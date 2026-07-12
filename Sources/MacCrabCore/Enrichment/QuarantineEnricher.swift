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

    /// Path to the quarantine events database.
    private let dbPath: String

    /// Cache of recent lookups to avoid repeated DB reads.
    private var cache: [String: QuarantineInfo] = [:]
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
        self.dbPath = NSHomeDirectory() + "/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
    }

    // MARK: - Public API

    /// Look up download provenance for a file path.
    /// Returns nil if the file has no quarantine record.
    public func lookup(filePath: String) -> QuarantineInfo? {
        // Check cache
        if let cached = cache[filePath] { return cached }

        guard FileManager.default.fileExists(atPath: dbPath) else { return nil }

        // Query the quarantine database
        // The DB schema: LSQuarantineEvent table with columns:
        // LSQuarantineEventIdentifier, LSQuarantineTimeStamp, LSQuarantineAgentBundleIdentifier,
        // LSQuarantineAgentName, LSQuarantineDataURLString, LSQuarantineOriginURLString,
        // LSQuarantineOriginTitle, LSQuarantineTypeNumber
        var db: OpaquePointer?
        guard sqlite3_open_v2(dbPath, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nil) == SQLITE_OK else {
            return nil
        }
        defer { sqlite3_close(db) }

        // Try to match by filename in the data URL
        let filename = (filePath as NSString).lastPathComponent
        let sql = """
            SELECT LSQuarantineDataURLString, LSQuarantineAgentBundleIdentifier,
                   LSQuarantineTimeStamp, LSQuarantineOriginTitle, LSQuarantineOriginURLString
            FROM LSQuarantineEvent
            WHERE LSQuarantineDataURLString LIKE ?
            ORDER BY LSQuarantineTimeStamp DESC
            LIMIT 1
            """

        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return nil }
        defer { sqlite3_finalize(stmt) }

        let pattern = "%\(filename)"
        sqlite3_bind_text(stmt, 1, pattern, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self))

        guard let info = Self.rowToInfo(stmt) else { return nil }

        // Cache
        if cache.count >= maxCacheSize {
            cache.removeAll()
        }
        cache[filePath] = info

        return info
    }

    /// Look up download provenance directly by the `com.apple.quarantine`
    /// event GUID (LSQuarantineEventIdentifier). This is the deterministic,
    /// unforgeable join the delivery-provenance weld uses: the running
    /// executable's quarantine xattr carries the GUID that keys its
    /// LSQuarantineEvent row (delivering agent + t0 + origin). Preview-made or
    /// non-downloaded files carry no GUID, so nothing is resolved for them.
    /// Returns nil when the GUID has no matching row.
    public func lookupByGUID(_ guid: String) -> QuarantineInfo? {
        let key = "guid:" + guid
        if let cached = cache[key] { return cached }
        guard !guid.isEmpty, FileManager.default.fileExists(atPath: dbPath) else { return nil }

        var db: OpaquePointer?
        guard sqlite3_open_v2(dbPath, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nil) == SQLITE_OK else {
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
        enrichments["quarantine.download_url"] = info.downloadURL
        enrichments["quarantine.agent"] = info.downloadAgent
        enrichments["quarantine.timestamp"] = ISO8601DateFormatter().string(from: info.downloadTimestamp)
        if let title = info.originTitle {
            enrichments["quarantine.origin_title"] = title
        }
    }
}
