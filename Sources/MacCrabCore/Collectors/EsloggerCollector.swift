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

    /// Event types to subscribe to (matching ESCollector's 14 types).
    private static let eventTypes = [
        "exec", "fork", "exit", "create", "write", "close",
        "rename", "unlink", "signal", "kextload",
        "mmap", "mprotect", "setowner", "setmode",
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

    // MARK: - Initialization

    public init() {
        var capturedContinuation: AsyncStream<Event>.Continuation!
        self.events = AsyncStream<Event>(bufferingPolicy: .bufferingNewest(1024)) { continuation in
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
                Self.readLoop(
                    fileHandle: fileHandle,
                    continuation: continuation,
                    selfPid: selfPid,
                    onGap: { dropped in
                        Task { await self?.recordDropped(dropped) }
                    }
                )
                // eslogger exited — trigger watchdog
                Task { await self?.handleEsloggerExit() }
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
            let chunk = fileHandle.availableData
            guard !chunk.isEmpty else { break }  // EOF

            residual.append(chunk)

            // Process complete lines
            while let newlineIndex = residual.firstIndex(of: newline) {
                let lineData = residual[residual.startIndex..<newlineIndex]
                residual = Data(residual[residual.index(after: newlineIndex)...])

                guard !lineData.isEmpty else { continue }

                // Fast-path mute: check for system paths BEFORE JSON parsing
                if shouldMute(lineData) { continue }

                // Parse JSON
                guard let json = try? JSONSerialization.jsonObject(with: lineData) as? [String: Any] else {
                    continue
                }

                // Self-mute: skip events from our own PID
                if let proc = json["process"] as? [String: Any],
                   let auditToken = proc["audit_token"] as? [String: Any],
                   let pid = auditToken["pid"] as? Int,
                   pid == Int(selfPid) {
                    continue
                }

                // Sequence gap detection
                if let globalSeq = json["global_seq_num"] as? UInt64 {
                    if lastGlobalSeq > 0 && globalSeq > lastGlobalSeq + 1 {
                        let gap = globalSeq - lastGlobalSeq - 1
                        onGap(gap)
                    }
                    lastGlobalSeq = globalSeq
                }

                // Parse into Event
                guard let event = EsloggerParser.parse(json) else { continue }

                let result = continuation.yield(event)
                if case .terminated = result { return }
            }
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
