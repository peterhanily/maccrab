// BTMSnapshotMonitor.swift
// MacCrabCore
//
// Periodic reconciliation source for BTM (Background Task Management)
// persistence — the "ghost login item" blind spot.
//
// The real-time ESCollector NOTIFY_BTM_LAUNCH_ITEM_ADD path is the PRIMARY
// sensor: it fires on the add itself and carries the responsible instigator.
// But it only observes adds that happen WHILE the daemon's ES client is live.
// This monitor closes the residual gap by enumerating current BTM state on an
// interval and flagging newly-seen, ENABLED launch items with weak inline
// attribution (no Team Identifier) — the narrow subset that could have been
// planted before install, while ES was down, or whose plist was deleted after
// registration. A modern SMAppService.register() item leaves no LaunchAgent
// plist and no write-time file event, so the write-time persistence rules never
// see it.
//
// STRICTLY READ-ONLY: `sfltool dumpbtm` only reads BTM state; nothing here
// mutates it. Discoveries are emitted as Alerts through the daemon's AlertSink
// (like the other poll-interval monitors); nothing auto-executes a response.
//
// HONEST LIMITS (dumpbtm output is undocumented / unstable — parsed
// defensively): app-scoped records may carry no Executable Path (only a bundle
// fragment / URL), so the on-disk path is resolved best-effort from the item
// URL; and the reported enable state reflects the snapshot, not the exact
// moment of registration.

import Foundation
import os.log

/// Enumerates Background Task Management launch items on an interval and reports
/// newly-seen, enabled items with weak attribution (no Team Identifier). Read-only.
public actor BTMSnapshotMonitor {

    private let logger = Logger(subsystem: "com.maccrab", category: "btm-snapshot-monitor")

    /// How often to reconcile BTM state (default: 300 seconds).
    private let pollInterval: TimeInterval

    /// AsyncStream continuation for emitting discoveries.
    private var continuation: AsyncStream<BTMSnapshotEvent>.Continuation?
    private let _events: AsyncStream<BTMSnapshotEvent>

    /// Items already reported this process lifetime (de-dup, keyed on BTM UUID).
    private var reportedItems: Set<String> = []

    /// Active scan task.
    private var scanTask: Task<Void, Never>?

    // MARK: - Types

    public struct BTMSnapshotEvent: Sendable {
        public let severity: Severity
        public let title: String
        public let description: String
        public let detail: String
        /// The item's launch identifier (or name), for alert attribution.
        public let identifier: String
        /// Best-effort on-disk executable / install path for the item.
        public let executablePath: String
        public let timestamp: Date

        public init(severity: Severity, title: String, description: String, detail: String,
                    identifier: String, executablePath: String) {
            self.severity = severity
            self.title = title
            self.description = description
            self.detail = detail
            self.identifier = identifier
            self.executablePath = executablePath
            self.timestamp = Date()
        }
    }

    /// A single parsed BTM record. Kept minimal — only the fields the
    /// discriminator and alert need. Parsed from `sfltool dumpbtm` text.
    public struct BTMRecord: Sendable, Equatable {
        public let uuid: String
        public let name: String
        /// nil when the item carries no Team Identifier (weak attribution).
        public let teamIdentifier: String?
        /// Lowercased `Type` line, e.g. "legacy daemon (0x10010)", "agent", "developer".
        public let type: String
        public let enabled: Bool
        public let executablePath: String?
        public let url: String?
        public let identifier: String?
    }

    // MARK: - Init

    public init(pollInterval: TimeInterval = 300) {
        self.pollInterval = pollInterval
        var capturedContinuation: AsyncStream<BTMSnapshotEvent>.Continuation!
        self._events = AsyncStream { c in
            capturedContinuation = c
        }
        self.continuation = capturedContinuation
    }

    // MARK: - Public API

    /// AsyncStream of BTM reconciliation discoveries.
    public nonisolated var events: AsyncStream<BTMSnapshotEvent> {
        _events
    }

    /// Start monitoring.
    public func start() {
        guard scanTask == nil else { return }
        logger.info("BTM snapshot monitor starting (dumpbtm reconcile every \(self.pollInterval)s)")
        scanTask = Task { [weak self] in
            // Initial scan establishes the reported set AND reports pre-existing
            // weakly-attributed items (they may have been planted before install
            // or while ES was down) — matching the reconciliation intent.
            await self?.scan()
            while !Task.isCancelled {
                let interval = PowerGate.adjustedInterval(base: self?.pollInterval ?? 300)
                try? await Task.sleep(nanoseconds: UInt64(interval * 1_000_000_000))
                guard !Task.isCancelled else { break }
                await self?.scan()
            }
        }
    }

    /// Stop monitoring.
    public func stop() {
        scanTask?.cancel()
        scanTask = nil
        continuation?.finish()
    }

    // MARK: - Scan

    private func scan() {
        guard let output = Self.runDumpBTM() else { return }
        let suspicious = Self.suspiciousRecords(Self.parseDumpBTM(output))
        for record in suspicious {
            let key = record.uuid.isEmpty ? (record.identifier ?? record.name) : record.uuid
            guard !reportedItems.contains(key) else { continue }
            reportedItems.insert(key)

            let path = Self.installPath(record)
            let event = BTMSnapshotEvent(
                severity: .medium,
                title: "Unattributed Background Launch Item Enabled: \(record.name)",
                description: """
                    A background launch item (\(record.type)) is registered and \
                    ENABLED in Background Task Management with no Team Identifier — \
                    weak attribution that the real-time BTM sensor did not witness \
                    being added (it may predate this session, or have been added \
                    while monitoring was offline). Modern SMAppService persistence \
                    leaves no LaunchAgent plist, so this reconciliation snapshot is \
                    the only view of it. Verify who installed it and whether it is \
                    expected before treating it as benign.
                    """,
                detail: "Type: \(record.type) · Path: \(path) · Identifier: \(record.identifier ?? "unknown") · UUID: \(record.uuid)",
                identifier: record.identifier ?? record.name,
                executablePath: path
            )
            continuation?.yield(event)
            logger.notice("BTM: unattributed enabled item — \(record.name, privacy: .public)")
        }
    }

    // MARK: - dumpbtm invocation (read-only)

    private nonisolated static func runDumpBTM() -> String? {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/sfltool")
        proc.arguments = ["dumpbtm"]
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = FileHandle.nullDevice

        do {
            try proc.run()
            // Drain BEFORE waiting: dumpbtm output can exceed the OS pipe buffer,
            // so waiting first would deadlock (child blocks on write, parent
            // blocks in waitUntilExit, neither drains). Same pattern as
            // SDRDeviceMonitor.getUSBDevices.
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            proc.waitUntilExit()
            guard proc.terminationStatus == 0 else { return nil }
            return String(data: data, encoding: .utf8)
        } catch {
            return nil
        }
    }

    // MARK: - Parsing (pure, unit-testable)

    /// Parse `sfltool dumpbtm` text into records. Defensive: the output format is
    /// undocumented and may drift, so unknown lines are ignored and missing
    /// fields default rather than throwing.
    public static func parseDumpBTM(_ output: String) -> [BTMRecord] {
        var records: [BTMRecord] = []
        var current: [String: String] = [:]

        func flush() {
            guard !current.isEmpty else { return }
            records.append(makeRecord(current))
            current = [:]
        }

        for rawLine in output.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)

            // Record boundary: a bare "#<n>:" on its own line (top-level item).
            // Embedded-item lines look like "#1: 16.com.foo" (value after the
            // colon) and are handled below — they never end in ':'.
            if line.hasPrefix("#"), line.hasSuffix(":"),
               line.dropFirst().dropLast().allSatisfy(\.isNumber),
               line.count > 2 {
                flush()
                continue
            }

            // "Key: value" — split on the FIRST ": ". Skip embedded-item lines
            // whose key begins with '#'.
            if let sep = line.range(of: ": ") {
                let key = String(line[line.startIndex..<sep.lowerBound]).trimmingCharacters(in: .whitespaces)
                let value = String(line[sep.upperBound...]).trimmingCharacters(in: .whitespaces)
                if !key.hasPrefix("#") {
                    current[key] = value
                }
            }
        }
        flush()
        return records
    }

    private static func makeRecord(_ f: [String: String]) -> BTMRecord {
        func clean(_ key: String) -> String? {
            guard let v = f[key], !v.isEmpty, v != "(null)" else { return nil }
            return v
        }
        let identifier = clean("Identifier")
        let name = clean("Name") ?? identifier ?? "unknown"
        // Disposition looks like "[enabled, allowed, notified] (0xb)" or
        // "[disabled, allowed, not notified] (0x2)". "disabled" does not contain
        // the substring "enabled", so a plain contains check is unambiguous.
        let disposition = (f["Disposition"] ?? "").lowercased()
        return BTMRecord(
            uuid: f["UUID"] ?? "",
            name: name,
            teamIdentifier: clean("Team Identifier"),
            type: (f["Type"] ?? "").lowercased(),
            enabled: disposition.contains("enabled"),
            executablePath: clean("Executable Path"),
            url: clean("URL"),
            identifier: identifier
        )
    }

    // MARK: - Discriminator (pure, unit-testable)

    /// True when the record's type is an actual launch item (login item / launch
    /// agent / launch daemon), NOT an app/"developer" container record.
    public static func isLaunchItem(_ type: String) -> Bool {
        return type.contains("daemon") || type.contains("agent") || type.contains("login item")
    }

    /// The reconciliation signal: an ENABLED launch item with NO Team Identifier
    /// (weak inline attribution). A signed app that adopts SMAppService carries a
    /// Team Identifier and is intentionally NOT flagged here — the wiki's honest
    /// limit that a signed .app in /Applications defeats a naive path test, so we
    /// gate on attribution, not a user-writable-path heuristic.
    public static func suspiciousRecords(_ records: [BTMRecord]) -> [BTMRecord] {
        records.filter { isLaunchItem($0.type) && $0.enabled && $0.teamIdentifier == nil }
    }

    /// Best-effort on-disk path for a record. App-scoped records may carry no
    /// Executable Path (only a bundle URL), so fall back to the item URL resolved
    /// to a filesystem path, then the identifier.
    public static func installPath(_ record: BTMRecord) -> String {
        if let exe = record.executablePath { return exe }
        if let url = record.url, let path = fileURLToPath(url) { return path }
        return record.identifier ?? record.uuid
    }

    private static func fileURLToPath(_ url: String) -> String? {
        guard url.hasPrefix("file://") else { return nil }
        return URL(string: url)?.path
    }
}
