// StorageFlushStatus.swift
// MacCrabCore
//
// v1.9 hot-fix — feedback surface for the dashboard's "Reduce events.db
// now" button. The daemon writes this snapshot every time it runs an
// on-demand size-cap sweep (SIGUSR2); the dashboard reads it on its
// regular refresh tick to surface "last run, X MB → Y MB".
//
// Workaround for the v1.8.x events.db size-cap regression class
// (file growing unbounded despite the maxDatabaseSizeMB setting).
// Operator-triggered sweep gives a manual escape hatch while the
// underlying enforcer regression is being investigated.

import Foundation
import os.log

public struct StorageFlushStatus: Sendable, Codable, Equatable {
    public var inProgress: Bool
    public var lastRunAt: Date?
    public var bytesBefore: UInt64
    public var bytesAfter: UInt64
    public var note: String?

    public init(
        inProgress: Bool = false,
        lastRunAt: Date? = nil,
        bytesBefore: UInt64 = 0,
        bytesAfter: UInt64 = 0,
        note: String? = nil
    ) {
        self.inProgress = inProgress
        self.lastRunAt = lastRunAt
        self.bytesBefore = bytesBefore
        self.bytesAfter = bytesAfter
        self.note = note
    }

    public static let filename = "storage_flush_status.json"

    private static let logger = Logger(subsystem: "com.maccrab.storage", category: "flush-status")

    /// Atomic write — same temp+rename pattern used for the other
    /// daemon-published status snapshots.
    @discardableResult
    public static func write(_ status: StorageFlushStatus, to directory: String) -> Bool {
        let path = directory + "/" + filename
        let url = URL(fileURLWithPath: path)
        do {
            try FileManager.default.createDirectory(
                at: url.deletingLastPathComponent(),
                withIntermediateDirectories: true,
                attributes: nil
            )
            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .iso8601
            encoder.outputFormatting = [.sortedKeys, .prettyPrinted]
            let data = try encoder.encode(status)
            let tmpURL = url.appendingPathExtension("tmp")
            try data.write(to: tmpURL, options: .atomic)
            _ = try FileManager.default.replaceItemAt(url, withItemAt: tmpURL)
            chmod(path, 0o644)
            return true
        } catch {
            logger.error("status write failed: \(error.localizedDescription, privacy: .public)")
            return false
        }
    }

    public static func read(from directory: String) -> StorageFlushStatus? {
        let path = directory + "/" + filename
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
            return nil
        }
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .iso8601
        return try? dec.decode(StorageFlushStatus.self, from: data)
    }

    /// Sum of `events.db` + `-wal` + `-shm` byte sizes. Returns 0 on
    /// missing-file. Used by the daemon to capture before/after
    /// snapshots around the size-cap sweep.
    public static func fileSize(at path: String) -> UInt64 {
        var total: UInt64 = 0
        for suffix in ["", "-wal", "-shm"] {
            let p = path + suffix
            if let attrs = try? FileManager.default.attributesOfItem(atPath: p),
               let size = attrs[.size] as? UInt64 {
                total += size
            }
        }
        return total
    }
}
