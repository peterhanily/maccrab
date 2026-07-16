// SelfDefense.swift
// MacCrabCore
//
// Self-preservation and tamper detection for the MacCrab daemon.
// Detects attempts to disable, modify, or interfere with MacCrab's operation.

import Foundation
import CryptoKit
import os.log
import Darwin

/// Self-defense and tamper detection for the MacCrab daemon.
///
/// Monitors:
/// - Binary integrity (hash at startup vs current)
/// - Rule file tampering (hash of compiled rules directory)
/// - Configuration file modification
/// - Evidence-database path presence (the `events.db` path is watched, but
///   in-place CONTENT tampering is deliberately NOT flagged here — the daemon
///   writes to it constantly, so a write is expected, not tamper. DB content
///   integrity is covered by field-level AES-GCM authentication
///   (`db_tamper_decrypt_failures`) and the trace continuity hash-chain, not
///   by this FSEvents monitor. The other evidence DBs are not path-watched
///   here for the same reason.)
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
    /// v1.12.0 RC24: computed lazily inside `start()` rather than in
    /// the constructor. Daemon boot path can't afford a synchronous
    /// SHA-256 on a 30 MB binary (3.5 s measured in RC22 timing).
    private var binaryHash: String?

    /// Resolved daemon-binary path. Retained for lazy hashing inside
    /// `start()` and integrity-check re-hashes.
    private let binaryPath: String

    /// Hash of compiled rules directory. Mutable because legitimate bundle
    /// syncs (fresh install, Sparkle-delivered rule updates, first-boot
    /// sequences subdir creation) re-baseline it so subsequent integrity
    /// checks don't keep firing on an already-observed legitimate change.
    private var rulesHash: String?

    /// Compiled rules directory path — retained so the write handler can
    /// recompute the hash on-demand when a file change is observed.
    private let rulesDir: String

    /// Wall-clock time the actor began monitoring. Writes to the rules
    /// directory within `startupGracePeriod` of this timestamp are treated
    /// as legitimate (install / upgrade bundle sync) and re-baseline the
    /// hash without firing a tamper alert. Without this, the sysext's
    /// SelfDefense watches an empty rules dir at first boot, then
    /// `RuleBundleInstaller` copies rules in, which fires a bogus
    /// "rules modified" critical alert on every fresh install.
    private var startupTime: Date?

    /// How long after `.start()` rules-directory writes are treated as
    /// legitimate bundle-sync churn. 60 seconds is comfortably above any
    /// observed install / Sparkle-upgrade copy duration.
    private let startupGracePeriod: TimeInterval = 60

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
        // Resolve the actual binary path using proc_pidpath (reliable even when
        // CommandLine.arguments[0] is just "maccrabd" without a full path).
        let resolvedBinary: String = {
            var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
            let result = proc_pidpath(getpid(), &buffer, UInt32(buffer.count))
            if result > 0 {
                return String(cString: buffer)
            }
            // Fallback: try resolving arguments[0]
            let raw = CommandLine.arguments[0]
            return (try? FileManager.default.destinationOfSymbolicLink(atPath: raw)) ?? raw
        }()
        self.binaryPath = resolvedBinary
        // v1.12.0 RC24: hashes deferred to `start()`. Synchronous
        // SHA-256 of the 30 MB daemon binary + 470-file rules dir
        // took 3.5 s on the boot critical path (RC22 timing). Leaving
        // them nil at construct time means the integrityCheck path
        // sees "no baseline yet" until start() runs — equivalent to
        // the pre-fix grace period.
        self.binaryHash = nil

        self.rulesDir = rulesDir
        self.rulesHash = nil

        // Build list of paths to monitor
        var paths: [MonitoredPath] = []

        // Binary monitoring is never critical — the running process is in memory
        // and file deletion doesn't affect it. Hash-based integrity checks (in
        // integrityCheck()) catch actual modifications. File existence checks
        // cause false positives on dev rebuilds, Homebrew upgrades, and path
        // resolution edge cases (sudo, symlinks).
        paths.append(MonitoredPath(
            path: resolvedBinary,
            description: "MacCrab daemon binary",
            critical: false
        ))

        // LaunchDaemon plist
        let plistPath = "/Library/LaunchDaemons/com.maccrab.agent.plist"
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

        logger.info("Self-defense initialized (hashes deferred to start()): monitoring \(paths.count) paths")
    }

    // MARK: - Public API

    /// Start tamper detection with the given alert handler.
    public func start(handler: @escaping TamperHandler) {
        self.tamperHandler = handler
        self.isActive = true
        self.startupTime = Date()

        // v1.12.0 RC24: lazy hashing. Constructor used to compute
        // SHA-256 of the daemon binary (~30 MB) + entire rules dir
        // (470 files) synchronously, costing ~3.5 s on the boot path.
        // Now both happen here — the SelfDefense actor is already on
        // a background Task by the time start() runs, so the boot
        // path doesn't wait.
        if self.binaryHash == nil {
            self.binaryHash = Self.sha256(fileAt: self.binaryPath)
        }
        if self.rulesHash == nil {
            self.rulesHash = Self.directoryHash(at: self.rulesDir)
        }
        logger.info("Self-defense baseline hashes computed: binary=\(self.binaryHash ?? "unknown")")

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

        // Check binary hash. v1.12.5 fix: use `self.binaryPath` (the
        // proc_pidpath-resolved absolute path set in `init`) instead of
        // `CommandLine.arguments[0]` — under sysextd, argv[0] is the
        // bundle-relative loader path which may not resolve to the
        // on-disk file after Sparkle/cask replaces the .app, making
        // sha256 + codesign verify silently miss or run against the
        // wrong file. The user-visible v1.12.4 regression was a real
        // signed binary swap firing `.binaryModified .critical`
        // because the signer-validity gate was probing the wrong path.
        let currentBinaryHash = Self.sha256(fileAt: self.binaryPath)
        if let original = binaryHash, let current = currentBinaryHash, original != current {
            if Self.isSignedByMacCrabTeam(at: self.binaryPath) {
                logger.notice("Binary hash changed but signature is valid MacCrab Developer ID — treating as legitimate update, rebaselining (path: \(self.binaryPath, privacy: .public))")
                self.binaryHash = current
            } else {
                events.append(TamperEvent(
                    type: .binaryModified,
                    description: "MacCrab binary has been modified since startup. Original hash: \(original), current: \(current)",
                    path: self.binaryPath,
                    severity: .critical
                ))
            }
        }

        // Check rules directory hash. v1.12.5 fix: apply the same
        // self-update gate that the DispatchSource path has — without
        // it, the periodic 15 s tick re-fires `.rulesModified .high`
        // every cycle once a Sparkle rule push lands past the startup
        // grace window. Hash-equal short-circuit at line below covers
        // benign no-op writes; sentinel check covers active sync.
        if let original = rulesHash, !Self.isSelfUpdateInProgress() {
            let currentRulesHash = Self.directoryHash(at: self.rulesDir)
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
                // v1.12.1 FP fix: same suppression as the DispatchSource
                // delete branch. The periodic 15 s integrity check would
                // otherwise re-fire the alert until the self-update
                // completes and the new tree is in place.
                if Self.isSelfUpdateInProgress() { continue }
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

        // Capture the grace deadline into a Sendable local. The signal-source
        // closure runs on a global queue and can't synchronously read the
        // actor-isolated `startupTime`; start() sets startupTime before
        // calling us, so this snapshot is valid for the whole process life.
        let graceDeadline = (startupTime ?? Date()).addingTimeInterval(startupGracePeriod)

        for (sig, name) in signals {
            let source = DispatchSource.makeSignalSource(signal: sig, queue: .global())
            source.setEventHandler { [weak self] in
                guard let self else { return }

                // v1.17.1 FP fix: gate the tamper ALERT the same way the file
                // monitor paths are (sentinel + startup grace). launchd/the
                // updater/`pkill -HUP`-adjacent stop signals MacCrab itself on
                // every legitimate stop, upgrade, and reload — firing a HIGH
                // "received SIGTERM" tamper event each time. A self-update
                // sentinel within its TTL, or the first `startupGracePeriod`
                // seconds (sysext (de)activation churn), is benign. The
                // graceful-exit behaviour below is UNCONDITIONAL — only the
                // alert is suppressed.
                let withinGrace = Date() < graceDeadline
                let benignSelfSignal = Self.isSelfUpdateInProgress() || withinGrace

                if benignSelfSignal {
                    self.logger.notice("Received \(name) during self-update/startup grace — graceful stop, no tamper alert")
                } else {
                    let event = TamperEvent(
                        type: .signalReceived,
                        description: "MacCrab daemon received \(name) signal. Possible attempt to terminate security monitoring.",
                        severity: .high
                    )
                    Task { await self.handleTamperEvent(event) }
                    self.logger.critical("TAMPER: Received \(name) — logging before exit")
                }

                // For SIGTERM/SIGINT, allow graceful shutdown after logging —
                // unconditional, regardless of whether we alerted.
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
        // Capture rulesDir out of actor isolation so the global-queue
        // DispatchSource closure can compute hashes without awaiting.
        let rulesDirForClosure = self.rulesDir

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
                    // Non-critical deletes are logged but don't fire tamper alerts
                    // (Homebrew upgrades routinely delete the old binary)
                    if !critical { return }
                    // v1.12.1 FP fix: RuleBundleInstaller's elevated
                    // `rm -rf <compiled_rules>` triggers this on every
                    // Sparkle/cask update. The installer drops a
                    // sentinel before the elevated session — when it's
                    // fresh, treat the delete as a legitimate self-
                    // update and schedule a re-baseline once the new
                    // dir exists.
                    if Self.isSelfUpdateInProgress() {
                        Task { await self.handleSelfUpdateDelete(path: path, desc: desc) }
                        return
                    }
                    eventType = .fileDeleted
                    message = "\(desc) was DELETED: \(path)"
                } else if data.contains(.rename) {
                    if !critical { return }
                    if Self.isSelfUpdateInProgress() {
                        Task { await self.handleSelfUpdateDelete(path: path, desc: desc) }
                        return
                    }
                    eventType = .fileDeleted
                    message = "\(desc) was RENAMED/MOVED: \(path)"
                } else if data.contains(.write) {
                    if path.contains("rules") || path.contains("compiled") {
                        // Rules-dir writes need hash comparison + startup-grace
                        // logic to suppress the bogus tamper alert on fresh
                        // install (RuleBundleInstaller copies rules INTO the
                        // monitored dir from the app bundle). Compute the new
                        // hash here on the global queue so the actor doesn't
                        // block on N shasum subprocess calls, then hand off.
                        let newHash = Self.directoryHash(at: rulesDirForClosure)
                        Task {
                            await self.handleRulesWriteEvent(
                                path: path,
                                desc: desc,
                                critical: critical,
                                newHash: newHash
                            )
                        }
                        return
                    } else if path.contains("events.db") {
                        // Honest scope (audit sec-storage-crypto): the daemon
                        // writes to events.db continuously, so an in-place
                        // `.write` is EXPECTED, not tampering. events.db is
                        // registered non-critical precisely so these writes are
                        // ignored here — meaning this FSEvents monitor does NOT
                        // detect in-place database CONTENT tampering. That
                        // coverage lives elsewhere: field-level AES-GCM
                        // authentication (surfaced as db_tamper_decrypt_failures)
                        // and the trace continuity hash-chain. The other evidence
                        // DBs are not path-monitored here for the same reason.
                        // Kept as an explicit branch (rather than falling through
                        // to the generic "modified" alert) so a hypothetical
                        // critical-flagged DB path can't silently FP on every
                        // write; today events.db is always non-critical, so the
                        // guard below always returns.
                        if !critical { return }
                        eventType = .databaseModified
                    } else if path.contains("/MacOS/") || path.contains("maccrabd") || path.contains("com.maccrab.agent") {
                        // v1.12.5 fix: a `.write` event on the daemon
                        // binary path fires under Sparkle/cask in-place
                        // upgrade. Apply both gates the integrityCheck
                        // path applies: sentinel-window suppression for
                        // explicit self-updates, signer-validity for
                        // anything else. A real tamper that's also
                        // validly signed by us is unreachable without
                        // our private key.
                        if Self.isSelfUpdateInProgress() {
                            return
                        }
                        if Self.isSignedByMacCrabTeam(at: path) {
                            return
                        }
                    }
                    message = "\(desc) was modified: \(path)"
                } else if data.contains(.attrib) {
                    // Attrib changes on non-critical paths are routine: sysextd
                    // stamps xattrs during activation, codesign staples the
                    // binary, Homebrew upgrades touch mtime, Time Machine
                    // tags nodes for exclusion. None of that is tampering.
                    // Only attribs on critical paths (LaunchDaemon plist,
                    // compiled rules) escalate; for everything else (binary,
                    // events.db, config files) silently ignore.
                    if !critical { return }
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

    /// Handle a write event on the rules directory with hash-aware baseline
    /// logic. Called from the DispatchSource closure via a Task so the
    /// `shasum` subprocess work happens on the global queue while the
    /// actor-isolated state mutation stays properly synchronized.
    ///
    /// Three outcomes:
    ///   1. Inside the startup grace window → rebaseline silently. This
    ///      covers the fresh-install and Sparkle-upgrade cases where
    ///      RuleBundleInstaller copies rules into the monitored dir just
    ///      after the sysext starts, plus DaemonSetup creating the
    ///      `sequences/` subdir at boot.
    ///   2. Past the grace window but hash unchanged → silent (benign
    ///      metadata write; no actual rule mutation happened).
    ///   3. Past the grace window, hash changed → rebaseline AND fire
    ///      the `.rulesModified` alert.
    private func handleRulesWriteEvent(
        path: String,
        desc: String,
        critical: Bool,
        newHash: String?
    ) {
        if let startupTime, Date().timeIntervalSince(startupTime) < startupGracePeriod {
            rulesHash = newHash
            logger.debug("Rules write during startup grace window — baseline updated, no alert")
            return
        }
        if let original = rulesHash, newHash == original {
            return // benign — no actual change to rule content
        }
        rulesHash = newHash
        let severity: Severity = critical ? .critical : .high
        let event = TamperEvent(
            type: .rulesModified,
            description: "\(desc) was modified: \(path)",
            path: path,
            severity: severity
        )
        handleTamperEvent(event)
    }

    /// Explicitly re-baseline the rules directory hash. Intended for callers
    /// that are about to perform a legitimate rules update outside the
    /// startup grace window — e.g., a future sentinel-based Sparkle upgrade
    /// hook. Not called anywhere today; kept public so the integration point
    /// exists when needed.
    public func snapshotRules() {
        rulesHash = Self.directoryHash(at: rulesDir)
        logger.info("Rules baseline re-snapshotted (intentional sync)")
    }

    // MARK: - Periodic Checks

    /// Tracks the last known PID for watchdog verification.
    private let startPID = getpid()
    private var lastParentPID = getppid()
    private var processStartTime = Date()
    private var consecutiveTamperCount = 0
    /// Tamper types we have already emitted an alert for this daemon
    /// lifetime. Without this the periodic check re-fires the same "binary
    /// modified" event every 15 seconds until the daemon restarts, which
    /// generates a flood of identical critical alerts (and OS notifications)
    /// after any local rebuild. One alert is enough — the operator already
    /// knows.
    private var alertedTamperTypes: Set<TamperType> = []
    /// Whether we've already emitted the "sustained tampering" escalation
    /// summary. Once fired, don't re-fire it every cycle.
    private var sustainedTamperAlerted = false

    private func startPeriodicChecks() {
        Task {
            while isActive {
                try? await Task.sleep(nanoseconds: 15_000_000_000) // Every 15 seconds
                guard isActive else { break }

                // 1. Anti-debug continuous check
                if Self.isBeingDebugged() {
                    let event = TamperEvent(
                        type: .debuggerAttached,
                        description: "Debugger attached to MacCrab (PID \(getpid())). This may indicate reverse engineering or tampering.",
                        severity: .critical
                    )
                    await handleTamperEvent(event)
                    logger.critical("Debugger detected — anti-debug measures logged")
                }

                // 2. Integrity check (binary hash, rules hash, file existence)
                let events = integrityCheck()
                for event in events {
                    await handleTamperEvent(event)
                }

                // 3. Process identity verification — are we still who we think we are?
                let currentPID = getpid()
                if currentPID != startPID {
                    await handleTamperEvent(TamperEvent(
                        type: .binaryModified,
                        description: "PID changed from \(startPID) to \(currentPID). Process may have been replaced.",
                        severity: .critical
                    ))
                }

                // 4. Parent process change detection (re-parenting attack)
                let currentParent = getppid()
                if currentParent != lastParentPID && lastParentPID != 1 {
                    // Parent changed and it wasn't orphan adoption by launchd
                    await handleTamperEvent(TamperEvent(
                        type: .processKillAttempt,
                        description: "Parent process changed from PID \(lastParentPID) to \(currentParent). Possible process manipulation.",
                        severity: .high
                    ))
                    lastParentPID = currentParent
                }

                // 5. LaunchDaemon plist restoration check
                let plistPath = "/Library/LaunchDaemons/com.maccrab.agent.plist"
                if monitoredPaths.contains(where: { $0.path == plistPath })
                    && !FileManager.default.fileExists(atPath: plistPath) {
                    await handleTamperEvent(TamperEvent(
                        type: .plistRemoved,
                        description: "LaunchDaemon plist deleted — MacCrab will not auto-start on reboot. Path: \(plistPath)",
                        path: plistPath,
                        severity: .critical
                    ))
                }

                // 6. Check if another process is impersonating MacCrab
                await checkForImpersonation()

                // 7. Verify environment hasn't been tampered with
                checkEnvironmentIntegrity()

                // 8. Escalate if we see repeated tampering. The summary
                // fires exactly once per daemon lifetime at the 3-failure
                // mark; beyond that the internal counter keeps climbing
                // (written to forensic log by handleTamperEvent) but we
                // don't re-emit a fresh critical alert every 15 seconds.
                if !events.isEmpty {
                    consecutiveTamperCount += 1
                    if consecutiveTamperCount >= 3 && !sustainedTamperAlerted {
                        sustainedTamperAlerted = true
                        await handleTamperEvent(TamperEvent(
                            type: .binaryModified,
                            description: "SUSTAINED TAMPERING DETECTED: \(consecutiveTamperCount) consecutive integrity failures. Active attack in progress.",
                            severity: .critical
                        ))
                    }
                } else {
                    consecutiveTamperCount = 0
                    sustainedTamperAlerted = false
                }
            }
        }
    }

    // MARK: - Impersonation Detection

    /// Track whether we've already alerted on duplicate processes (one-shot).
    private var duplicateAlerted = false

    /// Check if another process is running with our name (possible replacement attack).
    /// Only alerts once per daemon lifetime to avoid spam during upgrades/restarts.
    /// `pgrep -f` regex used by `checkForImpersonation` to spot OTHER live
    /// MacCrab instances (covers dev `maccrabd` + the release sysext
    /// `com.maccrab.agent`). Exposed so the D3 coverage-canary marker can be
    /// pinned disjoint from it: the canary spawns `/usr/bin/true` with a neutral
    /// "MCB-…" marker that must NEVER contain these tokens, or the health probe
    /// would self-report as an impersonator. See `CoverageCanary` + its safety
    /// test (`matchesImpersonationPattern`).
    nonisolated static let impersonationProcessPattern = "maccrabd|com\\.maccrab\\.agent"

    /// Pure mirror of the `pgrep -f` match `checkForImpersonation` performs:
    /// true when `commandLine` would be flagged as another MacCrab instance.
    /// Used by the canary self-trip safety test.
    nonisolated static func matchesImpersonationPattern(_ commandLine: String) -> Bool {
        commandLine.range(of: impersonationProcessPattern, options: .regularExpression) != nil
    }

    private func checkForImpersonation() async {
        guard !duplicateAlerted else { return }

        // v1.12.5 fix: the pre-fix probe used `pgrep -x maccrabd`
        // which never finds the running sysext in release builds —
        // the sysext executable name is `com.maccrab.agent`, not
        // `maccrabd`. Match either name with `-f` so impersonation
        // protection covers both the dev (`swift run maccrabd`) and
        // release (sysextd-activated) flavors.
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
        process.arguments = ["-f", Self.impersonationProcessPattern]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        try? process.run()
        process.waitUntilExit()

        let output = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let pids = output.split(separator: "\n").compactMap { Int32($0.trimmingCharacters(in: .whitespaces)) }

        // Filter out our own PID
        let otherPids = pids.filter { $0 != getpid() }
        if !otherPids.isEmpty {
            duplicateAlerted = true
            logger.warning("Another maccrabd process detected (PIDs: \(otherPids))")
        }
    }

    // MARK: - Environment Integrity

    /// Check for environment variable tampering that could affect security.
    private func checkEnvironmentIntegrity() {
        let suspiciousVars = [
            "DYLD_INSERT_LIBRARIES",
            "DYLD_FRAMEWORK_PATH",
            "DYLD_LIBRARY_PATH",
            "DYLD_FORCE_FLAT_NAMESPACE",
            "CFNETWORK_LIBRARY_PATH",
            "MallocStackLogging",
        ]

        let env = Foundation.ProcessInfo.processInfo.environment
        for varName in suspiciousVars {
            if let value = env[varName], !value.isEmpty {
                let event = TamperEvent(
                    type: .binaryModified,
                    description: "Suspicious environment variable set on MacCrab: \(varName)=\(value.prefix(100)). Possible library injection.",
                    severity: .critical
                )
                Task { await handleTamperEvent(event) }
            }
        }
    }

    // MARK: - Event Handling

    private func handleTamperEvent(_ event: TamperEvent) {
        // Dedup by tamper type: an integrity failure that persists across
        // poll cycles should alert exactly once, not every 15 seconds.
        // A periodic check that confirms the bad state on subsequent cycles
        // is useful internal signal (keeps `consecutiveTamperCount` accurate,
        // still writes to the forensic log) but it should not produce a
        // fresh operator alert / OS notification each time.
        if alertedTamperTypes.contains(event.type) {
            // Write to forensic logs only; skip the alert fan-out.
            writeForensicLog(event)
            return
        }
        alertedTamperTypes.insert(event.type)
        logger.critical("TAMPER DETECTED: [\(event.type.rawValue)] \(event.description)")

        writeForensicLog(event)
        tamperHandler?(event)
    }

    /// Append a tamper event to every writable forensic log location.
    /// Split out of `handleTamperEvent` so dedup-skipped events still get
    /// logged to disk (useful for post-incident forensics — confirms the
    /// condition persisted even though we stopped alerting).
    private func writeForensicLog(_ event: TamperEvent) {
        let logLocations = [
            NSTemporaryDirectory() + "maccrab_tamper.log",
            "/var/log/maccrab_tamper.log",  // May fail without root — that's OK
            NSHomeDirectory() + "/.maccrab_tamper.log",
        ]

        let line = "[\(ISO8601DateFormatter().string(from: event.timestamp))] [\(event.type.rawValue)] \(event.description)\n"
        let lineData = line.data(using: .utf8) ?? Data()

        for logPath in logLocations {
            let fd = open(logPath, O_WRONLY | O_CREAT | O_APPEND, 0o600)
            if fd >= 0 {
                lineData.withUnsafeBytes { ptr in
                    _ = write(fd, ptr.baseAddress!, ptr.count)
                }
                close(fd)
            }
        }
    }

    // MARK: - Hashing

    /// Compute SHA-256 hash of a file in-process via CryptoKit streaming.
    ///
    /// v1.12.6 fix: prior to this version, this method shelled out to
    /// `/usr/bin/shasum -a 256 <path>`. Because `/usr/bin/shasum` is a
    /// `#!/usr/bin/perl` script, every call forked + exec'd the perl
    /// interpreter. On a typical install with 425 compiled rule files,
    /// `directoryHash()` produced 426 perl subprocesses per call —
    /// roughly 28 perl spawns/second under the 15 s integrity-check
    /// cadence (~2.5 M/day per host). Routing through
    /// `FileHasher.computeSHA256(path:)` keeps the work entirely in
    /// process, eliminating that subprocess flood while producing a
    /// byte-identical hex digest.
    private nonisolated static func sha256(fileAt path: String) -> String? {
        guard FileManager.default.fileExists(atPath: path) else { return nil }
        return FileHasher.computeSHA256(path: path)
    }

    // MARK: - Self-update detection (v1.12.1 FP fix)

    /// Path of the sentinel file RuleBundleInstaller drops at the start
    /// of its elevated `rm -rf + cp -R` so SelfDefense can distinguish
    /// "MacCrab updating itself" from "attacker deleting MacCrab".
    private nonisolated static let selfUpdateSentinelPath =
        "/Library/Application Support/MacCrab/.maccrab_self_update_in_progress"

    /// Maximum age of the sentinel before we stop honoring it. The
    /// elevated rule sync usually completes in 1-2 s on warm disk;
    /// 90 s gives generous headroom for cold-cache + slow disks while
    /// keeping the suppression window short enough that a real
    /// post-update tamper still surfaces promptly.
    private nonisolated static let selfUpdateSentinelTTL: TimeInterval = 90

    /// Returns true if RuleBundleInstaller (dashboard side) is in the
    /// middle of an elevated rule sync. Checked before firing delete /
    /// rename / write alerts on paths inside the data dir.
    nonisolated static func isSelfUpdateInProgress() -> Bool {
        guard let attrs = try? FileManager.default.attributesOfItem(
                atPath: selfUpdateSentinelPath),
              let mtime = attrs[.modificationDate] as? Date else {
            return false
        }
        return Date().timeIntervalSince(mtime) < selfUpdateSentinelTTL
    }

    /// Verify that the binary at `path` is code-signed under MacCrab's
    /// Developer ID team (79S425CW99). Used to distinguish a legitimate
    /// Sparkle / cask in-place upgrade — which replaces the .app's
    /// binaries with a fresh validly-signed copy — from a real tamper
    /// where the binary is rewritten by an attacker. Shells to
    /// `/usr/bin/codesign -dvv --verify --` and matches against the
    /// expected TeamIdentifier; rejects on any non-zero exit so an
    /// unsigned or ad-hoc binary still trips the alert.
    nonisolated static func isSignedByMacCrabTeam(at path: String) -> Bool {
        guard FileManager.default.fileExists(atPath: path) else { return false }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        process.arguments = ["-dvv", "--verify", "--", path]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
            process.waitUntilExit()
            guard process.terminationStatus == 0 else { return false }
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""
            return output.contains("TeamIdentifier=79S425CW99")
        } catch {
            return false
        }
    }

    /// Called from the file-event handler when a delete/rename fires
    /// inside the self-update window. Logs at INFO (audit trail), tears
    /// down the stale DispatchSource fd, and schedules a delayed
    /// re-baseline once the new tree has been written.
    private func handleSelfUpdateDelete(path: String, desc: String) async {
        logger.notice("\(desc) DELETE during self-update window — suppressing alert + scheduling re-baseline (path: \(path, privacy: .public))")
        // Give the elevated cp -R time to finish before recomputing the
        // hash. Re-snapshotting before the new dir exists would baseline
        // to empty, which the next real tamper wouldn't detect.
        Task { [weak self] in
            try? await Task.sleep(nanoseconds: 5_000_000_000)
            await self?.rebaselineAfterSelfUpdate(path: path)
        }
    }

    /// Recompute hashes after a self-update completes. Only re-baselines
    /// if the sentinel has been cleared (success path) or the TTL has
    /// expired (failure path); in either case, the new tree on disk is
    /// what we want to baseline against.
    private func rebaselineAfterSelfUpdate(path: String) async {
        if path.contains("compiled_rules") || path.contains("rules") {
            self.rulesHash = Self.directoryHash(at: self.rulesDir)
            logger.info("Rules hash rebaselined after self-update (new hash: \(self.rulesHash ?? "unknown", privacy: .public))")
        }
    }

    /// Compute a combined hash of all `.json` rule files under a
    /// directory, recursing into subdirectories.
    ///
    /// v1.17: made recursive (`FileManager.enumerator`) so the
    /// `sequences/` and `graph/` subdirs (multi-step + TraceGraph rules)
    /// are covered by tamper detection — the prior top-level-only
    /// `contentsOfDirectory` walk silently omitted them. The
    /// `auto_generated/` subtree is excluded on purpose: those rules are
    /// written at runtime by the LLM rule-generation path and legitimately
    /// change, so hashing them would fire a self-inflicted false-positive
    /// `.rulesModified` alert.
    ///
    /// Sort order: files are hashed in ascending relative-path order.
    /// `FileManager.enumerator` does not guarantee a stable traversal
    /// order, so we sort the collected relative paths to keep the combined
    /// hash deterministic. For a flat (top-level-only) directory a file's
    /// relative path is just its filename, so the order is identical to
    /// the previous `contentsOfDirectory().sorted()` and the produced
    /// digest is byte-identical — no one-time false-positive on installs
    /// that don't yet have the subdirs populated.
    ///
    /// Combined-hash structure: concatenate per-file SHA-256 hex
    /// digests (no separators), then SHA-256 the UTF-8 bytes of that
    /// concatenation. Unchanged from the pre-v1.17 implementation.
    ///
    /// Error handling: fails closed on any unreadable file. Returns
    /// `nil` rather than partial-coverage hashes that might silently
    /// drop a file an attacker rendered unreadable. The caller treats
    /// `nil` as "couldn't verify this tick" (no alert, no baseline
    /// update); next tick will catch the real state.
    private nonisolated static func directoryHash(at path: String) -> String? {
        let rootURL = URL(fileURLWithPath: path, isDirectory: true).standardizedFileURL
        let rootPath = rootURL.path
        guard let enumerator = FileManager.default.enumerator(
            at: rootURL,
            includingPropertiesForKeys: [.isDirectoryKey],
            options: [.skipsHiddenFiles]
        ) else { return nil }

        var relPaths: [String] = []
        for case let url as URL in enumerator {
            let isDirectory = (try? url.resourceValues(
                forKeys: [.isDirectoryKey]))?.isDirectory ?? false
            if isDirectory {
                // Exclude runtime LLM-generated rules: they legitimately
                // change, so hashing them would self-FP. skipDescendants
                // prunes the whole subtree from the walk.
                if url.lastPathComponent == "auto_generated" {
                    enumerator.skipDescendants()
                }
                continue
            }
            guard url.pathExtension == "json" else { continue }
            let fullPath = url.standardizedFileURL.path
            guard fullPath.hasPrefix(rootPath + "/") else { continue }
            relPaths.append(String(fullPath.dropFirst(rootPath.count + 1)))
        }
        relPaths.sort()

        var combined = ""
        for rel in relPaths {
            guard let hash = sha256(fileAt: rootPath + "/" + rel) else {
                // Fail closed: any unreadable rule file means we
                // can't produce a trustworthy combined hash this
                // tick. Return nil so the caller skips alerting +
                // baseline-update this cycle instead of comparing
                // against a partial-coverage hash.
                return nil
            }
            combined += hash
        }
        guard !combined.isEmpty,
              let combinedBytes = combined.data(using: .utf8) else {
            return nil
        }
        let digest = SHA256.hash(data: combinedBytes)
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
