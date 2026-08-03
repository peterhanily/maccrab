// QuarantineEnricher.swift
// MacCrabCore
//
// Enriches file events with download provenance from macOS's
// QuarantineEventsV2 SQLite database. When a file execution alert fires,
// adds the original download URL, downloading application, and timestamp.

import Foundation
import os.log
import CSQLCipher

/// Looks up file download origin from the QuarantineEventsV2 database.
///
/// macOS tracks every downloaded file's origin URL, downloading agent
/// (e.g., Safari, Chrome, curl), and timestamp. This enricher adds that
/// context to file-related alerts.
public actor QuarantineEnricher {

    private let logger = Logger(subsystem: "com.maccrab", category: "quarantine-enricher")

    /// Tests may pin one synthetic DB. Production resolves the database from
    /// the event/path's validated real-user home and never from /var/root.
    private let dbPathOverride: String?

    /// Cache of recent positive lookups to avoid repeated DB reads.
    private var cache: [String: QuarantineInfo] = [:]
    /// Sentinel cache of paths proven to have no quarantine record, so repeat
    /// lookups for the same path skip the xattr probe + DB entirely. Bounded
    /// and evicted with the same discipline as the positive cache above.
    private var negativeCache: Set<String> = []
    private let maxCacheSize = 1000

    // MARK: - Types

    public struct QuarantineInfo: Sendable {
        public let downloadURL: String
        public let downloadAgent: String // e.g., "com.apple.Safari", "curl"
        public let downloadTimestamp: Date
        public let originTitle: String? // Page title if downloaded from a browser
        /// Referring page / origin URL (LSQuarantineOriginURLString). Empty on
        /// Chrome-dominated boxes (Chromium keeps the referrer in its own
        /// History.downloads instead) — the delivery-provenance weld falls back
        /// to the Chromium History reader when this is nil.
        public let originURL: String?

        public init(
            downloadURL: String,
            downloadAgent: String,
            downloadTimestamp: Date,
            originTitle: String?,
            originURL: String? = nil
        ) {
            self.downloadURL = downloadURL
            self.downloadAgent = downloadAgent
            self.downloadTimestamp = downloadTimestamp
            self.originTitle = originTitle
            self.originURL = originURL
        }
    }

    // MARK: - Initialization

    public init() {
        self.dbPathOverride = nil
    }

    /// Test seam: point the enricher at an arbitrary QuarantineEventsV2-shaped
    /// SQLite DB. Not reachable in production, which always resolves the real
    /// per-user path via `init()`.
    init(dbPath: String) {
        self.dbPathOverride = dbPath
    }

    // MARK: - Public API

    /// Look up download provenance for a file path.
    /// Returns nil if the file has no quarantine record.
    ///
    /// Fast path: a file with no `com.apple.quarantine` xattr normally has no
    /// resolvable download provenance, so we return nil after a single size-only
    /// `getxattr` probe — without opening or full-table-scanning the external
    /// QuarantineEventsV2 DB. When the xattr *is* present we resolve by its event
    /// GUID (the deterministic key for this exact file's LSQuarantineEvent row)
    /// rather than a `LIKE %basename` scan of the download URL, which could
    /// otherwise match a *different* file's row by basename coincidence.
    ///
    /// v1.21.4 review NOTE (L3): this is a deliberate perf/provenance trade, NOT
    /// "detection-exact". If the xattr was STRIPPED (`xattr -c`, itself a
    /// Gatekeeper-bypass step that fires `quarantine_removed`) while the DB row
    /// persists, the old basename scan would still have attached the download URL
    /// here; the gate now returns nil. This loss is DISPLAY-ONLY: no rule,
    /// sequence, or graph rule reads `quarantine.*` (verified), and
    /// DeliveryProvenanceWeld resolves provenance through its event-bound GUID
    /// path. We accept it rather than re-introduce a per-file-event
    /// external-DB scan (the whole point of the gate) for the rare stripped-xattr
    /// case. The GUID join is strictly MORE precise for the common case.
    public func lookup(filePath: String) -> QuarantineInfo? {
        if let dbPathOverride {
            return lookup(filePath: filePath, databasePath: dbPathOverride, cacheScope: "override")
        }
        guard let home = RealUserHomeResolver.provenanceHome(forPath: filePath) else {
            return nil
        }
        return lookup(
            filePath: filePath,
            databasePath: Self.databasePath(for: home),
            cacheScope: String(home.userID)
        )
    }

    /// Event-aware lookup. The process/event uid is authoritative for paths
    /// outside a home (Applications, mounted images, temp); if the target lies
    /// under a user home, the path and uid must agree.
    public func lookup(filePath: String, userID: UInt32) -> QuarantineInfo? {
        if let dbPathOverride {
            return lookup(filePath: filePath, databasePath: dbPathOverride, cacheScope: "override")
        }
        guard let home = RealUserHomeResolver.provenanceHome(
            forPath: filePath,
            userID: userID
        ) else { return nil }
        return lookup(
            filePath: filePath,
            databasePath: Self.databasePath(for: home),
            cacheScope: String(home.userID)
        )
    }

    private func lookup(
        filePath: String,
        databasePath: String,
        cacheScope: String
    ) -> QuarantineInfo? {
        let pathKey = cacheScope + ":path:" + filePath
        // Positive cache.
        if let cached = cache[pathKey] { return cached }
        // Negative sentinel cache — repeat lookups of a record-less path skip
        // the xattr probe + DB entirely.
        if negativeCache.contains(pathKey) { return nil }

        // xattr gate: no com.apple.quarantine xattr -> provably no download
        // event for this file. `quarantineGUID` performs the size-only probe
        // and returns nil when the xattr is absent (or carries no GUID).
        guard let guid = Self.quarantineGUID(forPath: filePath) else {
            rememberNegative(pathKey)
            return nil
        }

        // Resolve by the deterministic event GUID rather than a basename scan.
        guard let info = lookupByGUID(
            guid,
            databasePath: databasePath,
            cacheScope: cacheScope
        ) else {
            rememberNegative(pathKey)
            return nil
        }

        // Cache the positive result under the path too, so a repeat lookup for
        // the same path avoids even the xattr probe.
        if cache.count >= maxCacheSize {
            cache.removeAll()
        }
        cache[pathKey] = info

        return info
    }

    /// Record a path as having no quarantine record, bounded with the same
    /// eviction discipline as the positive cache.
    private func rememberNegative(_ path: String) {
        if negativeCache.count >= maxCacheSize {
            negativeCache.removeAll()
        }
        negativeCache.insert(path)
    }

    /// Look up download provenance directly by the `com.apple.quarantine`
    /// event GUID (LSQuarantineEventIdentifier). This is the deterministic
    /// join the delivery-provenance weld uses: the running
    /// executable's quarantine xattr carries the GUID that keys its
    /// LSQuarantineEvent row (delivering agent + t0 + origin). Preview-made or
    /// non-downloaded files carry no GUID, so nothing is resolved for them.
    /// The xattr is user-controlled, so callers must also bind the lookup to
    /// the event uid and executable path before treating the result as
    /// provenance; the GUID alone is enrichment, not an authority boundary.
    /// Returns nil when the GUID has no matching row.
    public func lookupByGUID(_ guid: String) -> QuarantineInfo? {
        if let dbPathOverride {
            return lookupByGUID(guid, databasePath: dbPathOverride, cacheScope: "override")
        }
        // The legacy GUID-only API carries no path or uid. It is safe only on a
        // machine with exactly one validated real user; fast-user-switching or
        // multiple local accounts deliberately degrade to no provenance.
        guard let home = RealUserHomeResolver.uniqueHome() else { return nil }
        return lookupByGUID(
            guid,
            databasePath: Self.databasePath(for: home),
            cacheScope: String(home.userID)
        )
    }

    public func lookupByGUID(_ guid: String, userID: UInt32, executablePath: String) -> QuarantineInfo? {
        if let dbPathOverride {
            return lookupByGUID(guid, databasePath: dbPathOverride, cacheScope: "override")
        }
        guard let home = RealUserHomeResolver.provenanceHome(
            forPath: executablePath,
            userID: userID
        ) else { return nil }
        return lookupByGUID(
            guid,
            databasePath: Self.databasePath(for: home),
            cacheScope: String(home.userID)
        )
    }

    private func lookupByGUID(
        _ guid: String,
        databasePath: String,
        cacheScope: String
    ) -> QuarantineInfo? {
        let key = cacheScope + ":guid:" + guid.uppercased()
        if let cached = cache[key] { return cached }
        guard !guid.isEmpty, FileManager.default.fileExists(atPath: databasePath) else { return nil }

        var db: OpaquePointer?
        guard SQLiteOpenPathPolicy.open(
            databasePath,
            database: &db,
            flags: SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX
        ) == SQLITE_OK else {
            return nil
        }
        defer { sqlite3_close(db) }

        let sql = """
            SELECT LSQuarantineDataURLString, LSQuarantineAgentBundleIdentifier,
                   LSQuarantineTimeStamp, LSQuarantineOriginTitle, LSQuarantineOriginURLString
            FROM LSQuarantineEvent
            WHERE LSQuarantineEventIdentifier = ?
            LIMIT 1
            """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return nil }
        defer { sqlite3_finalize(stmt) }

        // GUIDs are stored uppercase; match both cases defensively.
        sqlite3_bind_text(stmt, 1, guid.uppercased(), -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self))

        guard let info = Self.rowToInfo(stmt) else { return nil }

        if cache.count >= maxCacheSize { cache.removeAll() }
        cache[key] = info
        return info
    }

    static func databasePath(for home: RealUserHome) -> String {
        home.appending("Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2")
    }

    /// Decode one LSQuarantineEvent row (columns in the fixed SELECT order used
    /// by both lookups) into a `QuarantineInfo`, or nil if there is no row.
    private static func rowToInfo(_ stmt: OpaquePointer?) -> QuarantineInfo? {
        guard sqlite3_step(stmt) == SQLITE_ROW else { return nil }
        let downloadURL = sqlite3_column_text(stmt, 0).map { String(cString: $0) } ?? ""
        let agent = sqlite3_column_text(stmt, 1).map { String(cString: $0) } ?? ""
        let timestamp = sqlite3_column_double(stmt, 2)
        let title = sqlite3_column_text(stmt, 3).map { String(cString: $0) }
        let originURL = sqlite3_column_text(stmt, 4).map { String(cString: $0) }
        // QuarantineTimeStamp is Core Data timestamp (seconds since 2001-01-01)
        let refDate = Date(timeIntervalSinceReferenceDate: timestamp)
        return QuarantineInfo(
            downloadURL: downloadURL,
            downloadAgent: agent,
            downloadTimestamp: refDate,
            originTitle: title,
            originURL: (originURL?.isEmpty == false) ? originURL : nil
        )
    }

    /// Read the `com.apple.quarantine` extended attribute of a file and return
    /// its event GUID (the 4th `;`-separated field, e.g.
    /// `0083;68a1...;Google Chrome;2853CF89-E284-42FC-84C8-013ECE017C50`).
    /// Returns nil when the file has no quarantine xattr (never downloaded, or
    /// Preview-made) or the value is malformed. Read-only stat — never mutates.
    public static func quarantineGUID(forPath path: String) -> String? {
        let value: String? = path.withCString { pathPtr in
            "com.apple.quarantine".withCString { namePtr -> String? in
                let size = getxattr(pathPtr, namePtr, nil, 0, 0, 0)
                guard size > 0 else { return nil }
                var buf = [UInt8](repeating: 0, count: size)
                let read = getxattr(pathPtr, namePtr, &buf, size, 0, 0)
                guard read > 0 else { return nil }
                return String(bytes: buf[0..<read], encoding: .utf8)
            }
        }
        guard let value else { return nil }
        // Format: flags;timestamp;agent;uuid — the uuid is LSQuarantineEventIdentifier.
        let parts = value.split(separator: ";", omittingEmptySubsequences: false)
        guard parts.count >= 4 else { return nil }
        let guid = parts[3].trimmingCharacters(in: .whitespaces)
        return guid.isEmpty ? nil : guid
    }

    /// Enrich an event's enrichments dict with quarantine provenance.
    public func enrich(_ enrichments: inout [String: String], forFile filePath: String) {
        guard let info = lookup(filePath: filePath) else { return }
        attach(info, to: &enrichments)
    }

    public func enrich(
        _ enrichments: inout [String: String],
        forFile filePath: String,
        userID: UInt32
    ) {
        guard let info = lookup(filePath: filePath, userID: userID) else { return }
        attach(info, to: &enrichments)
    }

    private func attach(_ info: QuarantineInfo, to enrichments: inout [String: String]) {
        enrichments["quarantine.download_url"] = info.downloadURL
        enrichments["quarantine.agent"] = info.downloadAgent
        enrichments["quarantine.timestamp"] = ISO8601DateFormatter().string(from: info.downloadTimestamp)
        if let title = info.originTitle {
            enrichments["quarantine.origin_title"] = title
        }
    }
}
