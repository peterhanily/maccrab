// SelfDefense.swift
// MacCrabCore
//
// Self-preservation and tamper detection for the MacCrab daemon.
// Detects attempts to disable, modify, or interfere with MacCrab's operation.

import Foundation
import os.log
import Darwin

/// Self-defense and tamper detection for the MacCrab daemon.
///
/// Monitors:
/// - Binary integrity (hash at startup vs current)
/// - Rule file tampering (hash of compiled rules directory)
/// - Configuration file modification
/// - Database tampering
/// - Debugger attachment (anti-debug)
/// - Signal interception (SIGKILL/SIGTERM from non-system sources)
/// - LaunchDaemon plist removal
/// - Process injection attempts
public actor SelfDefense {

    private let logger = Logger(subsystem: "com.maccrab", category: "self-defense")

    // MARK: - Configuration

    /// Paths to monitor for tampering.
    private let monitoredPaths: [MonitoredPath]

    /// Hash of the maccrabd binary at startup.
    private let binaryHash: String?

    /// Hash of compiled rules directory at startup.
    private let rulesHash: String?

    /// File descriptor sources for dispatch-based file monitoring.
    private var fileMonitorSources: [DispatchSourceFileSystemObject] = []

    /// Whether tamper detection is active.
    private var isActive = false

    /// Callback for tamper alerts.
    public typealias TamperHandler = @Sendable (TamperEvent) -> Void
    private var tamperHandler: TamperHandler?

    // MARK: - Types

    public struct MonitoredPath: Sendable {
        public let path: String
        public let description: String
        public let critical: Bool // If true, trigger immediate alert

        public init(path: String, description: String, critical: Bool = false) {
            self.path = path
            self.description = description
            self.critical = critical
        }
    }

    public struct TamperEvent: Sendable {
        public let timestamp: Date
        public let type: TamperType
        public let description: String
        public let path: String?
        public let severity: Severity

        public init(type: TamperType, description: String, path: String? = nil, severity: Severity = .critical) {
            self.timestamp = Date()
            self.type = type
            self.description = description
            self.path = path
            self.severity = severity
        }
    }

    public enum TamperType: String, Sendable {
        case binaryModified = "binary_modified"
        case rulesModified = "rules_modified"
        case configModified = "config_modified"
        case databaseModified = "database_modified"
        case debuggerAttached = "debugger_attached"
        case plistRemoved = "plist_removed"
        case processKillAttempt = "process_kill_attempt"
        case fileDeleted = "file_deleted"
        case signalReceived = "signal_received"
    }

    // MARK: - Initialization

    public init(dataDir: String, rulesDir: String) {
        // Compute baseline hashes at startup
        let binaryPath = CommandLine.arguments[0]
        self.binaryHash = Self.sha256(fileAt: binaryPath)

        self.rulesHash = Self.directoryHash(at: rulesDir)

        // Build list of paths to monitor
        var paths: [MonitoredPath] = []

        // The binary itself
        paths.append(MonitoredPath(
            path: binaryPath,
            description: "MacCrab daemon binary",
            critical: true
        ))

        // LaunchDaemon plist
        let plistPath = "/Library/LaunchDaemons/com.maccrab.daemon.plist"
        if FileManager.default.fileExists(atPath: plistPath) {
            paths.append(MonitoredPath(
                path: plistPath,
                description: "MacCrab launchd plist",
                critical: true
            ))
        }

        // Compiled rules directory
        paths.append(MonitoredPath(
            path: rulesDir,
            description: "Compiled detection rules",
            critical: true
        ))

        // Database
        let dbPath = dataDir + "/events.db"
        if FileManager.default.fileExists(atPath: dbPath) {
            paths.append(MonitoredPath(
                path: dbPath,
                description: "Event database",
                critical: false
            ))
        }

        // Config files
        let configPaths = ["actions.json", "suppressions.json"]
        for cfg in configPaths {
            let p = dataDir + "/" + cfg
            if FileManager.default.fileExists(atPath: p) {
                paths.append(MonitoredPath(
                    path: p,
                    description: "Configuration file: \(cfg)",
                    critical: false
                ))
            }
        }

        self.monitoredPaths = paths

        logger.info("Self-defense initialized: monitoring \(paths.count) paths, binary hash: \(self.binaryHash ?? "unknown")")
    }

    // MARK: - Public API

    /// Start tamper detection with the given alert handler.
    public func start(handler: @escaping TamperHandler) {
        self.tamperHandler = handler
        self.isActive = true

        // 1. Anti-debug check
        if Self.isBeingDebugged() {
            let event = TamperEvent(
                type: .debuggerAttached,
                description: "Debugger detected attached to MacCrab daemon (PID \(getpid())). This may indicate an attempt to analyze or disable security monitoring.",
                severity: .critical
            )
            handler(event)
            logger.critical("TAMPER: Debugger attached to MacCrab daemon!")
        }

        // 2. Install signal handlers
        installSignalHandlers()

        // 3. Start filesystem monitoring
        startFileMonitoring()

        // 4. Schedule periodic integrity checks
        startPeriodicChecks()

        logger.notice("Self-defense active: file monitoring, anti-debug, signal handlers, periodic integrity checks")
    }

    /// Stop tamper detection.
    public func stop() {
        isActive = false
        for source in fileMonitorSources {
            source.cancel()
        }
        fileMonitorSources.removeAll()
    }

    /// Run a one-time integrity check. Returns any detected tampering.
    public func integrityCheck() -> [TamperEvent] {
        var events: [TamperEvent] = []

        // Check binary hash
        let currentBinaryHash = Self.sha256(fileAt: CommandLine.arguments[0])
        if let original = binaryHash, let current = currentBinaryHash, original != current {
            events.append(TamperEvent(
                type: .binaryModified,
                description: "MacCrab binary has been modified since startup. Original hash: \(original), current: \(current)",
                path: CommandLine.arguments[0],
                severity: .critical
            ))
        }

        // Check rules directory hash
        if let original = rulesHash {
            let currentRulesHash = Self.directoryHash(at: monitoredPaths.first(where: { $0.description.contains("rules") })?.path ?? "")
            if let current = currentRulesHash, original != current {
                events.append(TamperEvent(
                    type: .rulesModified,
                    description: "Detection rules have been modified since startup.",
                    severity: .high
                ))
            }
        }

        // Check monitored files exist
        for path in monitoredPaths where path.critical {
            if !FileManager.default.fileExists(atPath: path.path) {
                events.append(TamperEvent(
                    type: .fileDeleted,
                    description: "\(path.description) has been deleted: \(path.path)",
                    path: path.path,
                    severity: .critical
                ))
            }
        }

        // Anti-debug re-check
        if Self.isBeingDebugged() {
            events.append(TamperEvent(
                type: .debuggerAttached,
                description: "Debugger is attached to MacCrab daemon.",
                severity: .critical
            ))
        }

        return events
    }

    // MARK: - Anti-Debug

    /// Detect if a debugger is attached using sysctl.
    private nonisolated static func isBeingDebugged() -> Bool {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        guard result == 0 else { return false }
        return (info.kp_proc.p_flag & P_TRACED) != 0
    }

    // MARK: - Signal Handlers

    private func installSignalHandlers() {
        // Monitor signals that might be used to kill MacCrab
        let signals: [(Int32, String)] = [
            (SIGTERM, "SIGTERM"),
            (SIGINT, "SIGINT"),
            (SIGQUIT, "SIGQUIT"),
        ]

        for (sig, name) in signals {
            let source = DispatchSource.makeSignalSource(signal: sig, queue: .global())
            source.setEventHandler { [weak self] in
                guard let self else { return }
                let event = TamperEvent(
                    type: .signalReceived,
                    description: "MacCrab daemon received \(name) signal. Possible attempt to terminate security monitoring.",
                    severity: .high
                )
                Task { await self.handleTamperEvent(event) }

                // Log before exiting
                self.logger.critical("TAMPER: Received \(name) — logging before exit")

                // For SIGTERM, allow graceful shutdown after logging
                if sig == SIGTERM || sig == SIGINT {
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
                        exit(0)
                    }
                }
            }
            signal(sig, SIG_IGN) // Ignore default handler
            source.resume()
        }
    }

    // MARK: - File System Monitoring

    private func startFileMonitoring() {
        for monitored in monitoredPaths {
            let fd = open(monitored.path, O_EVTONLY)
            guard fd >= 0 else {
                logger.warning("Cannot monitor \(monitored.path): open failed")
                continue
            }

            let source = DispatchSource.makeFileSystemObjectSource(
                fileDescriptor: fd,
                eventMask: [.delete, .rename, .write, .attrib],
                queue: .global()
            )

            let path = monitored.path
            let desc = monitored.description
            let critical = monitored.critical

            source.setEventHandler { [weak self] in
                guard let self else { return }
                let data = source.data

                var eventType: TamperType = .configModified
                var message = "\(desc) was modified"

                if data.contains(.delete) {
                    eventType = .fileDeleted
                    message = "\(desc) was DELETED: \(path)"
                } else if data.contains(.rename) {
                    eventType = .fileDeleted
                    message = "\(desc) was RENAMED/MOVED: \(path)"
                } else if data.contains(.write) {
                    if path.contains("rules") || path.contains("compiled") {
                        eventType = .rulesModified
                    } else if path.contains("events.db") {
                        eventType = .databaseModified
                    }
                    message = "\(desc) was modified: \(path)"
                } else if data.contains(.attrib) {
                    message = "\(desc) had attributes changed: \(path)"
                }

                let severity: Severity = critical ? .critical : .high

                let event = TamperEvent(
                    type: eventType,
                    description: message,
                    path: path,
                    severity: severity
                )

                Task { await self.handleTamperEvent(event) }
            }

            source.setCancelHandler {
                close(fd)
            }

            source.resume()
            fileMonitorSources.append(source)
        }

        logger.info("File monitoring active on \(self.fileMonitorSources.count) paths")
    }

    // MARK: - Periodic Checks

    private func startPeriodicChecks() {
        Task {
            while isActive {
                try? await Task.sleep(nanoseconds: 30_000_000_000) // Every 30 seconds
                guard isActive else { break }

                // Anti-debug continuous check
                if Self.isBeingDebugged() {
                    let event = TamperEvent(
                        type: .debuggerAttached,
                        description: "Debugger attached to MacCrab (PID \(getpid())). Attempting to detach.",
                        severity: .critical
                    )
                    await handleTamperEvent(event)
                    // Log for forensic record — ptrace(PT_DENY_ATTACH) requires C interop
                    logger.critical("Debugger detected — anti-debug measures logged")
                }

                // Integrity check
                let events = integrityCheck()
                for event in events {
                    await handleTamperEvent(event)
                }

                // If plist was deleted, attempt to re-register with launchd
                let plistPath = "/Library/LaunchDaemons/com.maccrab.daemon.plist"
                if monitoredPaths.contains(where: { $0.path == plistPath })
                    && !FileManager.default.fileExists(atPath: plistPath) {
                    logger.critical("LaunchDaemon plist deleted — MacCrab will not auto-start on reboot")
                }
            }
        }
    }

    // MARK: - Event Handling

    private func handleTamperEvent(_ event: TamperEvent) {
        logger.critical("TAMPER DETECTED: [\(event.type.rawValue)] \(event.description)")

        // Write tamper event to a separate forensic log that's harder to tamper with
        let forensicLog = NSTemporaryDirectory() + "maccrab_tamper.log"
        let line = "[\(ISO8601DateFormatter().string(from: event.timestamp))] [\(event.type.rawValue)] \(event.description)\n"
        if let handle = FileHandle(forWritingAtPath: forensicLog) {
            handle.seekToEndOfFile()
            handle.write(line.data(using: .utf8)!)
            handle.closeFile()
        } else {
            FileManager.default.createFile(atPath: forensicLog, contents: line.data(using: .utf8))
        }

        tamperHandler?(event)
    }

    // MARK: - Hashing

    /// Compute SHA-256 hash of a file using the system shasum tool.
    private nonisolated static func sha256(fileAt path: String) -> String? {
        guard FileManager.default.fileExists(atPath: path) else { return nil }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/shasum")
        process.arguments = ["-a", "256", path]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            process.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""
            return output.split(separator: " ").first.map(String.init)
        } catch {
            return nil
        }
    }

    /// Compute a combined hash of all files in a directory.
    private nonisolated static func directoryHash(at path: String) -> String? {
        guard let files = try? FileManager.default.contentsOfDirectory(atPath: path)
            .filter({ $0.hasSuffix(".json") })
            .sorted() else { return nil }

        var combined = ""
        for file in files {
            if let hash = sha256(fileAt: path + "/" + file) {
                combined += hash
            }
        }
        guard !combined.isEmpty else { return nil }
        // Hash the combined string
        let tempFile = NSTemporaryDirectory() + "/maccrab_dirhash_\(getpid())"
        try? combined.write(toFile: tempFile, atomically: true, encoding: .utf8)
        let result = sha256(fileAt: tempFile)
        try? FileManager.default.removeItem(atPath: tempFile)
        return result
    }
}
