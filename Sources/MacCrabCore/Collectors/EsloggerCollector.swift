// EsloggerCollector.swift
// MacCrabCore
//
// Collects Endpoint Security events by proxying through Apple's eslogger tool.
// This provides the same kernel-level events as ESCollector without requiring
// the com.apple.developer.endpoint-security.client entitlement.
// Requires root and macOS 13+ (Ventura).
//
// Follows the UnifiedLogCollector pattern:
//   1. Process + Pipe lifecycle management
//   2. Detached Task with blocking FileHandle.availableData loop
//   3. Manual line buffering: accumulate Data, split on 0x0A newline
//   4. Parse each line as JSON via JSONSerialization
//   5. Convert to Event via EsloggerParser
//   6. Yield via AsyncStream<Event>.Continuation
//   7. Watchdog restart on unexpected exit with exponential backoff

import Foundation
import os.log

// MARK: - EsloggerCollector

/// Collects Endpoint Security events by proxying through Apple's eslogger tool.
/// This provides the same kernel-level events as ESCollector without requiring
/// the com.apple.developer.endpoint-security.client entitlement.
/// Requires root and macOS 13+ (Ventura).
public actor EsloggerCollector {

    private let logger = Logger(subsystem: "com.maccrab", category: "eslogger-collector")

    public nonisolated let events: AsyncStream<Event>
    private var continuation: AsyncStream<Event>.Continuation?
    private var process: Process?
    private var readTask: Task<Void, Never>?
    private var watchdogTask: Task<Void, Never>?

    /// Event types to subscribe to — core 14 from ESCollector plus valuable extras.
    private static let eventTypes = [
        // Core 14 (matching ESCollector)
        "exec", "fork", "exit", "create", "write", "close",
        "rename", "unlink", "signal", "kextload",
        "mmap", "mprotect", "setowner", "setmode",
        // Extended (macOS 14+, gracefully ignored on older versions)
        "sudo", "su", "authentication",
        "tcc_modify",
        "btm_launch_item_add", "btm_launch_item_remove",
        "xp_malware_detected", "xp_malware_remediated",
        "gatekeeper_user_override",
        "remote_thread_create",
        "xpc_connect",
    ]

    /// Paths to skip BEFORE JSON parsing (fast-path muting).
    /// Scanning raw bytes avoids the cost of JSONSerialization for noisy system events.
    private static let mutedPathSubstrings: [Data] = {
        let strings = [
            "/System/",
            "/usr/libexec/xpcproxy",
            "/.Spotlight-V100",
            "/.MobileBackups",
            "/com.apple.TimeMachine",
            "/usr/sbin/mDNSResponder",
            "/usr/libexec/sandboxd",
        ]
        return strings.compactMap { $0.data(using: .utf8) }
    }()

    /// Track sequence numbers for gap detection.
    private var lastGlobalSeq: UInt64 = 0
    private var droppedEvents: UInt64 = 0

    /// Watchdog state.
    private var backoffSeconds: Double = 1.0
    private var lastSuccessfulStart: Date?

    /// Our own PID for self-muting.
    private let selfPid = Foundation.ProcessInfo.processInfo.processIdentifier

    // MARK: - Availability

    /// Check if eslogger is available on this system.
    public nonisolated static func isAvailable() -> Bool {
        FileManager.default.fileExists(atPath: "/usr/bin/eslogger")
    }

    /// Preflight check: verify eslogger can actually run (root + FDA).
    /// Returns nil on success, or a human-readable error string.
    public nonisolated static func preflightCheck() -> String? {
        guard getuid() == 0 else {
            return "MacCrab must run as root (sudo)"
        }
        guard isAvailable() else {
            return "eslogger not found (requires macOS 13+)"
        }
        // Try --list-events to verify TCC/FDA
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/eslogger")
        proc.arguments = ["--list-events"]
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = pipe
        try? proc.run()
        proc.waitUntilExit()
        if proc.terminationStatus != 0 {
            let output = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            if output.contains("TCC") || output.contains("Full Disk Access") || output.contains("FDA") {
                return "Terminal needs Full Disk Access. Open System Settings → Privacy & Security → Full Disk Access and add your terminal app."
            }
            return "eslogger failed with status \(proc.terminationStatus): \(output.prefix(200))"
        }
        return nil
    }

    // MARK: - Initialization

    public init() {
        var capturedContinuation: AsyncStream<Event>.Continuation!
        self.events = AsyncStream<Event>(bufferingPolicy: .bufferingNewest(4096)) { continuation in
            capturedContinuation = continuation
        }
        self.continuation = capturedContinuation
    }

    // MARK: - Start / Stop

    public func start() {
        guard process == nil else { return }
        launchEslogger()
    }

    public func stop() {
        watchdogTask?.cancel()
        watchdogTask = nil
        readTask?.cancel()
        readTask = nil
        if let proc = process, proc.isRunning {
            proc.terminate()
        }
        process = nil
        continuation?.finish()
        continuation = nil
    }

    // MARK: - Launch eslogger subprocess

    private func launchEslogger() {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/eslogger")
        proc.arguments = Self.eventTypes + ["--format", "json"]

        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = FileHandle.nullDevice

        do {
            try proc.run()
            self.process = proc
            logger.info("eslogger started (PID \(proc.processIdentifier))")
            self.lastSuccessfulStart = Date()

            // Start the read loop
            let fileHandle = pipe.fileHandleForReading
            let continuation = self.continuation
            let selfPid = Int32(self.selfPid)

            readTask = Task.detached { [weak self] in
                // Bind the weak capture to a `let` once. The nested `Task`s below
                // run concurrently; capturing the `[weak self]` var directly trips
                // Swift-6 strict concurrency ("reference to captured var 'self' in
                // concurrently-executing code"). A `let` actor reference is Sendable
                // and capture-safe.
                let weakSelf = self
                Self.readLoop(
                    fileHandle: fileHandle,
                    continuation: continuation,
                    selfPid: selfPid,
                    onGap: { dropped in
                        Task { await weakSelf?.recordDropped(dropped) }
                    }
                )
                // eslogger exited — trigger watchdog
                Task { await weakSelf?.handleEsloggerExit() }
            }
        } catch {
            logger.error("Failed to launch eslogger: \(error.localizedDescription)")
        }
    }

    // MARK: - Read Loop (static, runs in detached task)

    /// Reads stdout from the eslogger subprocess line-by-line, parsing JSON
    /// entries and yielding normalised `Event` values into the continuation.
    ///
    /// This is a static method so it can run in a detached Task without
    /// capturing `self` (the actor) directly.
    private static func readLoop(
        fileHandle: FileHandle,
        continuation: AsyncStream<Event>.Continuation?,
        selfPid: Int32,
        onGap: @Sendable @escaping (UInt64) -> Void
    ) {
        guard let continuation else { return }

        var residual = Data()
        var lastGlobalSeq: UInt64 = 0
        let newline = UInt8(0x0A)

        while true {
            // v1.7.9: outer autoreleasepool wraps the per-CHUNK body so
            // `fileHandle.availableData` (which returns an autoreleased
            // NSConcreteData of typically 16 KB) drains every iteration
            // instead of accumulating forever in the long-running Task's
            // pool.
            //
            // v1.7.7's fix only wrapped the inner per-LINE body, which
            // drained JSON-parser temporaries but missed the per-CHUNK
            // chunk Data itself. Field-reproduced on a v1.7.8 install:
            // heap dump showed 135,689 × 16 KB NSConcreteData = 2.22 GB
            // private heap (no JSON triplets — chunk-only leak shape).
            //
            // This pool wraps everything: the chunk read, the residual
            // append, the inner per-line loop. Inner autoreleasepool
            // remains as belt-and-suspenders for tighter peak memory
            // (drains JSON parsers per line, before the outer pool drains
            // the chunk at end of iteration).
            var outerEarlyReturn = false
            autoreleasepool {
                let chunk = fileHandle.availableData
                guard !chunk.isEmpty else {
                    outerEarlyReturn = true  // EOF
                    return
                }

                residual.append(chunk)

                // Process complete lines (inner pool: drains JSON parser
                // temporaries per line so peak memory stays low even on
                // chunks containing thousands of lines).
                var earlyReturn = false
                while let newlineIndex = residual.firstIndex(of: newline) {
                    autoreleasepool {
                    let lineData = residual[residual.startIndex..<newlineIndex]
                    residual = Data(residual[residual.index(after: newlineIndex)...])

                    guard !lineData.isEmpty else { return }

                    // Fast-path mute: check for system paths BEFORE JSON parsing
                    if shouldMute(lineData) { return }

                    // Parse JSON
                    guard let json = try? JSONSerialization.jsonObject(with: lineData) as? [String: Any] else {
                        return
                    }

                    // Self-mute: skip events from our own PID
                    if let proc = json["process"] as? [String: Any],
                       let auditToken = proc["audit_token"] as? [String: Any],
                       let pid = auditToken["pid"] as? Int,
                       pid == Int(selfPid) {
                        return
                    }

                    // Sequence gap detection (math lifted to Self.sequenceGap for testability)
                    if let globalSeq = json["global_seq_num"] as? UInt64 {
                        let gap = Self.sequenceGap(previous: lastGlobalSeq, current: globalSeq)
                        if gap > 0 { onGap(gap) }
                        lastGlobalSeq = globalSeq
                    }

                    // Parse into Event
                    guard let event = EsloggerParser.parse(json) else { return }

                    let result = continuation.yield(event)
                    if case .terminated = result { earlyReturn = true }
                }
                if earlyReturn { outerEarlyReturn = true; return }
            }
            }  // end outer autoreleasepool (drains the chunk Data)
            if outerEarlyReturn { break }
        }

        continuation.finish()
    }

    // MARK: - Fast-Path Mute Filter

    /// Check if a raw JSON line should be muted BEFORE parsing.
    /// Scans for known system path substrings in the raw bytes.
    private static func shouldMute(_ lineData: Data) -> Bool {
        for pattern in mutedPathSubstrings {
            if lineData.range(of: pattern) != nil {
                return true
            }
        }
        return false
    }

    // MARK: - Watchdog Restart

    private func handleEsloggerExit() {
        guard continuation != nil else { return }  // Intentional stop

        // Reset backoff if it ran for > 60 seconds
        if let lastStart = lastSuccessfulStart,
           Date().timeIntervalSince(lastStart) > 60 {
            backoffSeconds = 1.0
        }

        logger.warning("eslogger exited — restarting in \(self.backoffSeconds)s")

        watchdogTask = Task {
            try? await Task.sleep(nanoseconds: UInt64(backoffSeconds * 1_000_000_000))
            guard !Task.isCancelled else { return }

            // Exponential backoff capped at 30s
            self.backoffSeconds = min(self.backoffSeconds * 2, 30.0)
            self.launchEslogger()
        }
    }

    /// Pure sequence-gap math, lifted out of the FileHandle read loop so it is
    /// unit-testable. Given the previously-seen `global_seq_num` and the current
    /// one, returns the number of events dropped in between — 0 for the first
    /// observation, a contiguous step, a duplicate, or an out-of-order arrival
    /// (never a negative/underflowed count).
    static func sequenceGap(previous: UInt64, current: UInt64) -> UInt64 {
        guard previous > 0, current > previous + 1 else { return 0 }
        return current - previous - 1
    }

    private func recordDropped(_ count: UInt64) {
        droppedEvents += count
        logger.warning("eslogger sequence gap: \(count) events likely dropped (total: \(self.droppedEvents))")
    }

    /// Number of events dropped due to sequence gaps.
    public func getDroppedEventCount() -> UInt64 {
        droppedEvents
    }

    // MARK: - Deinit

    deinit {
        if let proc = process, proc.isRunning {
            proc.terminate()
        }
    }
}
