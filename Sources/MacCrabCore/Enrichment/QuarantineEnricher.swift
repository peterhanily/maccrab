// QuarantineEnricher.swift
// MacCrabCore
//
// Enriches file events with download provenance from macOS's
// QuarantineEventsV2 SQLite database. When a file execution alert fires,
// adds the original download URL, downloading application, and timestamp.

import Foundation
import os.log
import SQLite3

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
                   LSQuarantineTimeStamp, LSQuarantineOriginTitle
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

        guard sqlite3_step(stmt) == SQLITE_ROW else { return nil }

        let downloadURL = sqlite3_column_text(stmt, 0).map { String(cString: $0) } ?? ""
        let agent = sqlite3_column_text(stmt, 1).map { String(cString: $0) } ?? ""
        let timestamp = sqlite3_column_double(stmt, 2)
        let title = sqlite3_column_text(stmt, 3).map { String(cString: $0) }

        // QuarantineTimeStamp is Core Data timestamp (seconds since 2001-01-01)
        let refDate = Date(timeIntervalSinceReferenceDate: timestamp)

        let info = QuarantineInfo(
            downloadURL: downloadURL,
            downloadAgent: agent,
            downloadTimestamp: refDate,
            originTitle: title
        )

        // Cache
        if cache.count >= maxCacheSize {
            cache.removeAll()
        }
        cache[filePath] = info

        return info
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
