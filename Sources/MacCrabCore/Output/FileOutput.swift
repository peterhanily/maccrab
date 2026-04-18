// FileOutput.swift
// MacCrabCore
//
// Writes one alert per line (NDJSON / JSON Lines) to a local file, with
// rotation on size + age. The default format is OCSF 1.3 Security
// Findings — pluggable via the Format enum for shops that prefer ECS
// or MacCrab's native envelope.
//
// Rotation scheme: `alerts.jsonl` → `alerts.jsonl.1` → `alerts.jsonl.2`
// ... up to `maxArchives`. Nothing is compressed here; operators wanting
// gzip can chain logrotate or a launchd plist. Compressed-in-place is
// deferred because Apple's Compression framework doesn't ship native
// gzip format and shelling out felt over-scoped for v1.

import Foundation
import os.log

public actor FileOutput: Output {

    // MARK: - Types

    public enum Format: String, Sendable, CaseIterable, Codable {
        /// OCSF 1.3 Security Finding JSON (default).
        case ocsf
        /// MacCrab-native envelope with alert + event dicts.
        case native
    }

    // MARK: - Config

    public nonisolated let name = "file"
    private let basePath: String
    private let format: Format
    private let maxBytes: Int64
    private let maxAgeSeconds: TimeInterval
    private let maxArchives: Int

    // MARK: - State

    private let logger = Logger(subsystem: "com.maccrab.output", category: "file")
    private var handle: FileHandle?
    private var currentBytes: Int64 = 0
    private var openedAt: Date = Date()
    private var stats = OutputStats()

    /// Encoder reused for each line. camelCase → snake_case conversion for
    /// the native format; OCSF goes through OCSFMapper which runs its own.
    private let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.outputFormatting = [.sortedKeys]
        e.dateEncodingStrategy = .iso8601
        e.keyEncodingStrategy = .convertToSnakeCase
        return e
    }()

    // MARK: - Init

    /// - Parameters:
    ///   - path: Full path to the live NDJSON file, e.g.
    ///     `/var/log/maccrab/alerts.jsonl`. Parent directory is created
    ///     on first write if missing.
    ///   - format: Serialization choice. Default `.ocsf`.
    ///   - maxBytes: Rotate when the live file reaches this size. Default
    ///     100 MB.
    ///   - maxAgeSeconds: Rotate when the live file becomes older than
    ///     this. Default 24h.
    ///   - maxArchives: Retain this many rotated files (oldest is
    ///     deleted). Default 10.
    public init(
        path: String,
        format: Format = .ocsf,
        maxBytes: Int64 = 100 * 1024 * 1024,
        maxAgeSeconds: TimeInterval = 86400,
        maxArchives: Int = 10
    ) {
        self.basePath = path
        self.format = format
        self.maxBytes = maxBytes
        self.maxAgeSeconds = maxAgeSeconds
        self.maxArchives = maxArchives
    }

    // MARK: - Output protocol

    public func send(alert: Alert, event: Event?) async {
        guard let line = renderLine(alert: alert, event: event) else {
            stats.dropped += 1
            return
        }
        await writeLine(line)
    }

    public func flush() async {
        try? handle?.synchronize()
    }

    public func outputStats() async -> OutputStats { stats }

    // MARK: - Rendering

    private func renderLine(alert: Alert, event: Event?) -> String? {
        switch format {
        case .ocsf:
            let finding = OCSFMapper.mapAlert(alert, event: event)
            return try? OCSFMapper.encodeJSON(finding)
        case .native:
            let envelope = NativeEnvelope(alert: alert, event: event)
            guard let data = try? encoder.encode(envelope),
                  let s = String(data: data, encoding: .utf8) else {
                return nil
            }
            return s
        }
    }

    // MARK: - Write + rotate

    private func writeLine(_ line: String) async {
        await openIfNeeded()

        if shouldRotate() {
            await rotate()
            await openIfNeeded()
        }

        let payload = line + "\n"
        guard let data = payload.data(using: .utf8), let handle else {
            stats.failed += 1
            return
        }
        do {
            try handle.write(contentsOf: data)
            currentBytes += Int64(data.count)
            stats.sent += 1
            stats.lastSentAt = Date()
        } catch {
            stats.failed += 1
            stats.lastError = error.localizedDescription
            logger.error("FileOutput write failed: \(error.localizedDescription)")
        }
    }

    private func openIfNeeded() async {
        guard handle == nil else { return }

        let dir = (basePath as NSString).deletingLastPathComponent
        try? FileManager.default.createDirectory(
            atPath: dir, withIntermediateDirectories: true
        )

        // Create the file if absent so FileHandle.forWritingTo can open it.
        if !FileManager.default.fileExists(atPath: basePath) {
            FileManager.default.createFile(atPath: basePath, contents: nil)
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o600], ofItemAtPath: basePath
            )
        }

        let url = URL(fileURLWithPath: basePath)
        do {
            let h = try FileHandle(forWritingTo: url)
            _ = try? h.seekToEnd()
            handle = h
            currentBytes = fileSize(at: basePath)
            openedAt = fileMtime(at: basePath) ?? Date()
        } catch {
            stats.failed += 1
            stats.lastError = error.localizedDescription
            logger.error("FileOutput open failed: \(error.localizedDescription)")
        }
    }

    private func shouldRotate() -> Bool {
        if currentBytes >= maxBytes { return true }
        let age = Date().timeIntervalSince(openedAt)
        if age >= maxAgeSeconds && currentBytes > 0 { return true }
        return false
    }

    private func rotate() async {
        try? handle?.close()
        handle = nil

        let fm = FileManager.default
        // Shift .N → .(N+1) starting from the oldest to avoid overwrite.
        for i in stride(from: maxArchives, to: 0, by: -1) {
            let src = "\(basePath).\(i)"
            let dst = "\(basePath).\(i + 1)"
            if fm.fileExists(atPath: src) {
                if i == maxArchives {
                    // Oldest retained → delete (falls off the end)
                    try? fm.removeItem(atPath: src)
                } else {
                    try? fm.moveItem(atPath: src, toPath: dst)
                }
            }
        }
        // Move live → .1
        if fm.fileExists(atPath: basePath) {
            try? fm.moveItem(atPath: basePath, toPath: "\(basePath).1")
        }
        currentBytes = 0
        openedAt = Date()
    }

    // MARK: - FS helpers

    private func fileSize(at path: String) -> Int64 {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: path) else {
            return 0
        }
        return (attrs[.size] as? NSNumber)?.int64Value ?? 0
    }

    private func fileMtime(at path: String) -> Date? {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: path) else {
            return nil
        }
        return attrs[.modificationDate] as? Date
    }

    // MARK: - Native envelope

    /// Shape used when `format == .native`. Mirrors the existing webhook
    /// payload so tooling that consumes webhooks can also tail the file.
    private struct NativeEnvelope: Codable {
        let schema: String
        let version: String
        let timestamp: Date
        let alert: AlertPayload
        let event: EventPayload?

        init(alert: Alert, event: Event?) {
            self.schema = "maccrab.alert.v1"
            self.version = "1.3.4"
            self.timestamp = Date()
            self.alert = AlertPayload(from: alert)
            self.event = event.map(EventPayload.init)
        }

        struct AlertPayload: Codable {
            let id: String
            let ruleId: String
            let ruleTitle: String
            let severity: String
            let description: String?
            let processPath: String?
            let processName: String?
            let mitreTactics: [String]
            let mitreTechniques: [String]
            let campaignId: String?

            init(from alert: Alert) {
                self.id = alert.id
                self.ruleId = alert.ruleId
                self.ruleTitle = alert.ruleTitle
                self.severity = alert.severity.rawValue
                self.description = alert.description
                self.processPath = alert.processPath
                self.processName = alert.processName
                self.mitreTactics = alert.mitreTacticsList
                self.mitreTechniques = alert.mitreTechniquesList
                self.campaignId = alert.campaignId
            }
        }

        struct EventPayload: Codable {
            let id: String
            let category: String
            let action: String
            let processPid: Int32
            let processPath: String
            let processCommandLine: String

            init(_ event: Event) {
                self.id = event.id.uuidString
                self.category = event.eventCategory.rawValue
                self.action = event.eventAction
                self.processPid = event.process.pid
                self.processPath = event.process.executable
                self.processCommandLine = CommandSanitizer.sanitize(event.process.commandLine)
            }
        }
    }
}
