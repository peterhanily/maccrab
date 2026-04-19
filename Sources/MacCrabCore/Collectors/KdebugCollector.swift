// KdebugCollector.swift
// MacCrabCore
//
// Collects kernel events via macOS's kdebug tracing facility (fs_usage).
// Provides ES-equivalent NOTIFY event data as root without any entitlement,
// TCC permission, or Apple Developer Program membership.
//
// This is the third-tier fallback when both native ES and eslogger are unavailable:
//   ESCollector (entitlement) -> EsloggerCollector (FDA) -> KdebugCollector (root only)
//
// Follows the same subprocess pattern as EsloggerCollector:
//   1. Process + Pipe lifecycle management
//   2. Detached Task with blocking FileHandle.availableData loop
//   3. Manual line buffering: accumulate Data, split on 0x0A newline
//   4. Parse each fs_usage line into an Event
//   5. Yield via AsyncStream<Event>.Continuation
//   6. Watchdog restart on unexpected exit with exponential backoff

import Foundation
import os.log

// MARK: - KdebugCollector

/// Collects kernel events via macOS's kdebug tracing facility (fs_usage).
/// Provides ES-equivalent NOTIFY event data as root without any entitlement,
/// TCC permission, or Apple Developer Program membership.
///
/// This is the third-tier fallback when both native ES and eslogger are unavailable:
///   ESCollector (entitlement) -> EsloggerCollector (FDA) -> KdebugCollector (root only)
public actor KdebugCollector {

    private let logger = Logger(subsystem: "com.maccrab", category: "kdebug-collector")

    public nonisolated let events: AsyncStream<Event>
    private var continuation: AsyncStream<Event>.Continuation?
    private var process: Process?
    private var readTask: Task<Void, Never>?
    private var watchdogTask: Task<Void, Never>?

    /// Watchdog state.
    private var backoffSeconds: Double = 1.0
    private var lastSuccessfulStart: Date?

    /// Our own PID for self-muting.
    private let selfPid = Foundation.ProcessInfo.processInfo.processIdentifier

    /// Track event counts for stats.
    private var eventCount: UInt64 = 0

    /// Processes to ignore (system noise that produces huge volumes of events
    /// without security relevance).
    private static let noiseProcesses: Set<String> = [
        "mds", "mds_stores", "mdworker", "mdworker_shared",
        "fseventsd", "kernel_task", "launchd", "syslogd", "logd",
        "com.apple.WebK", "symptomsd", "rapportd",
        "notifyd", "distnoted", "cfprefsd", "containermanagerd",
        "UserEventAgent", "coreservicesd", "lsd",
    ]

    // MARK: - Availability

    /// Check if fs_usage is available on this system.
    public nonisolated static func isAvailable() -> Bool {
        FileManager.default.fileExists(atPath: "/usr/bin/fs_usage")
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
        launchFsUsage()
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

    /// Number of events emitted since start.
    public func getEventCount() -> UInt64 { eventCount }

    // MARK: - Launch fs_usage subprocess

    private func launchFsUsage() {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/fs_usage")
        // -w: wide output (full paths, no truncation)
        // -f: filter categories — filesys (file ops), exec (process), network
        proc.arguments = ["-w", "-f", "filesys,exec,network"]

        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = FileHandle.nullDevice

        do {
            try proc.run()
            self.process = proc
            logger.info("kdebug collector started via fs_usage (PID \(proc.processIdentifier))")
            self.lastSuccessfulStart = Date()

            let fileHandle = pipe.fileHandleForReading
            let continuation = self.continuation
            let selfPid = Int32(self.selfPid)

            readTask = Task.detached { [weak self] in
                Self.readLoop(
                    fileHandle: fileHandle,
                    continuation: continuation,
                    selfPid: selfPid
                )
                Task { [weak self] in await self?.handleExit() }
            }
        } catch {
            logger.error("Failed to launch fs_usage: \(error.localizedDescription)")
        }
    }

    private func incrementCount() { eventCount += 1 }

    // MARK: - Read Loop (static, runs in detached task)

    /// Reads stdout from the fs_usage subprocess line-by-line, parsing text
    /// entries and yielding normalised `Event` values into the continuation.
    ///
    /// This is a static method so it can run in a detached Task without
    /// capturing `self` (the actor) directly.
    private static func readLoop(
        fileHandle: FileHandle,
        continuation: AsyncStream<Event>.Continuation?,
        selfPid: Int32
    ) {
        guard let continuation else { return }

        var residual = Data()
        let newline = UInt8(0x0A)

        while true {
            let chunk = fileHandle.availableData
            guard !chunk.isEmpty else { break }  // EOF

            residual.append(chunk)

            // Process complete lines
            while let newlineIndex = residual.firstIndex(of: newline) {
                let lineData = residual[residual.startIndex..<newlineIndex]
                residual = Data(residual[residual.index(after: newlineIndex)...])

                guard let line = String(data: lineData, encoding: .utf8),
                      !line.isEmpty else { continue }

                // Parse the fs_usage line into an Event
                guard let event = parseFsUsageLine(line, selfPid: selfPid) else { continue }

                let result = continuation.yield(event)
                if case .terminated = result { return }
            }
        }

        continuation.finish()
    }

    // MARK: - fs_usage Line Parser

    /// Parses a single fs_usage output line into an `Event`.
    ///
    /// fs_usage output format (with -w flag):
    /// ```
    /// 10:30:45.123456  open              /path/to/file          0.000042 W  processName.12345
    /// 10:30:45.234567  write             /path/to/file          0.000015    processName.12345
    /// 10:30:45.345678  execve            /path/to/binary        0.000001    processName.12346
    /// 10:30:45.456789  connect           192.168.1.1:443        0.000234    processName.12347
    /// ```
    ///
    /// The last field is always `processName.PID`. The syscall name determines
    /// the event type. Fields are separated by variable whitespace.
    private static func parseFsUsageLine(_ line: String, selfPid: Int32) -> Event? {
        // fs_usage lines have variable whitespace. Split on whitespace runs.
        let parts = line.split(omittingEmptySubsequences: true, whereSeparator: { $0.isWhitespace })

        // Need at least: timestamp, syscall, processName.PID
        guard let lastPart = parts.last, parts.count >= 3 else { return nil }

        // Last field is processName.PID
        let procField = String(lastPart)
        guard let dotIdx = procField.lastIndex(of: "."),
              dotIdx > procField.startIndex,
              let pid = Int32(procField[procField.index(after: dotIdx)...]) else { return nil }

        // Self-mute: skip events from our own process
        guard pid != selfPid else { return nil }

        let processName = String(procField[procField.startIndex..<dotIdx])

        // Skip system noise
        guard !noiseProcesses.contains(processName) else { return nil }

        // Syscall is the second field
        let syscall = String(parts[1]).lowercased()

        // Path/destination is between syscall and the trailing duration+process fields.
        // We extract it as the third field if present. For lines with paths containing
        // spaces, fs_usage -w keeps them on a single field (no splitting needed in
        // practice for the fields we care about, but we do a best-effort extraction).
        let pathOrDest: String
        if parts.count > 3 {
            // The path is typically at index 2. In some lines there are extra
            // columns (e.g. flags like "W" or "R") between the path and the
            // duration. We take index 2 as the path/dest — this covers the
            // vast majority of fs_usage output patterns.
            pathOrDest = String(parts[2])
        } else {
            pathOrDest = ""
        }

        // Build a minimal ProcessInfo (fs_usage doesn't give full process metadata)
        let process = ProcessInfo(
            pid: pid,
            ppid: 0,
            rpid: 0,
            name: processName,
            executable: "",  // fs_usage doesn't provide the full executable path
            commandLine: "",
            args: [],
            workingDirectory: "",
            userId: 0,
            userName: "",
            groupId: 0,
            startTime: Date(),
            isPlatformBinary: false
        )

        // Map the syscall to an Event
        switch syscall {

        // -- Process events --

        case "execve", "posix_spawn", "exec":
            let executablePath = pathOrDest
            let execName = (executablePath as NSString).lastPathComponent
            let execProcess = ProcessInfo(
                pid: pid,
                ppid: 0,
                rpid: 0,
                name: execName.isEmpty ? processName : execName,
                executable: executablePath,
                commandLine: executablePath,
                args: executablePath.isEmpty ? [] : [executablePath],
                workingDirectory: "",
                userId: 0,
                userName: "",
                groupId: 0,
                startTime: Date(),
                isPlatformBinary: false
            )
            return Event(
                eventCategory: .process,
                eventType: .start,
                eventAction: "exec",
                process: execProcess,
                severity: .informational
            )

        case "fork":
            return Event(
                eventCategory: .process,
                eventType: .start,
                eventAction: "fork",
                process: process,
                severity: .informational
            )

        // -- File events --

        case "open", "open_nocancel":
            guard !pathOrDest.isEmpty else { return nil }
            return Event(
                eventCategory: .file,
                eventType: .creation,
                eventAction: "open",
                process: process,
                file: FileInfo(path: pathOrDest, action: .create),
                severity: .informational
            )

        case "write", "write_nocancel", "pwrite":
            guard !pathOrDest.isEmpty else { return nil }
            return Event(
                eventCategory: .file,
                eventType: .change,
                eventAction: "write",
                process: process,
                file: FileInfo(path: pathOrDest, action: .write),
                severity: .informational
            )

        case "close", "close_nocancel":
            guard !pathOrDest.isEmpty else { return nil }
            return Event(
                eventCategory: .file,
                eventType: .change,
                eventAction: "close_modified",
                process: process,
                file: FileInfo(path: pathOrDest, action: .close),
                severity: .informational
            )

        case "rename":
            guard !pathOrDest.isEmpty else { return nil }
            return Event(
                eventCategory: .file,
                eventType: .change,
                eventAction: "rename",
                process: process,
                file: FileInfo(path: pathOrDest, action: .rename),
                severity: .informational
            )

        case "unlink", "rmdir":
            guard !pathOrDest.isEmpty else { return nil }
            return Event(
                eventCategory: .file,
                eventType: .deletion,
                eventAction: "unlink",
                process: process,
                file: FileInfo(path: pathOrDest, action: .delete),
                severity: .informational
            )

        // -- Network events --

        case "connect", "connect_nocancel":
            // Parse IP:port from pathOrDest (e.g. "192.168.1.1:443")
            let netParts = pathOrDest.split(separator: ":")
            let ip = netParts.count > 0 ? String(netParts[0]) : pathOrDest
            let port = netParts.count > 1 ? (UInt16(netParts[1]) ?? 0) : 0
            return Event(
                eventCategory: .network,
                eventType: .start,
                eventAction: "connect",
                process: process,
                network: NetworkInfo(
                    sourceIp: "0.0.0.0",
                    sourcePort: 0,
                    destinationIp: ip,
                    destinationPort: port,
                    direction: .outbound,
                    transport: "tcp"
                ),
                severity: .informational
            )

        default:
            // Skip syscalls we don't map to events
            return nil
        }
    }

    // MARK: - Watchdog Restart

    private func handleExit() {
        guard continuation != nil else { return }  // Intentional stop

        // Reset backoff if it ran for > 60 seconds
        if let lastStart = lastSuccessfulStart,
           Date().timeIntervalSince(lastStart) > 60 {
            backoffSeconds = 1.0
        }

        logger.warning("fs_usage exited — restarting in \(self.backoffSeconds)s")

        watchdogTask = Task {
            try? await Task.sleep(nanoseconds: UInt64(backoffSeconds * 1_000_000_000))
            guard !Task.isCancelled else { return }

            // Exponential backoff capped at 30s
            self.backoffSeconds = min(self.backoffSeconds * 2, 30.0)
            self.launchFsUsage()
        }
    }

    // MARK: - Deinit

    deinit {
        if let proc = process, proc.isRunning {
            proc.terminate()
        }
    }
}
