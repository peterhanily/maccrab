import Foundation
import Darwin
import MacCrabCore
import os.log

/// Creates and initializes all daemon components, returning a fully configured DaemonState.
enum DaemonSetup {

    private static let setupLogger = Logger(subsystem: "com.maccrab.agentkit", category: "daemon-setup")

    /// v1.7.6: write a startup marker to `<supportDir>/sysext_started.json`
    /// BEFORE any storage init runs. Synchronous, no actor hops, no
    /// dependencies. The dashboard compares this file's mtime with
    /// heartbeat.json to distinguish three failure modes:
    ///   - sysext_started.json missing → process never started (sysextd issue)
    ///   - sysext_started.json fresh, heartbeat.json stale → started, then
    ///     crashed in init / failed to write heartbeat (this v1.7.6 fixes)
    ///   - both fresh, then both stale → ran for a while, then died
    /// Each gets a different banner with a different remediation.
    public static func writeStartupMarker(supportDir: String, version: String) {
        let path = supportDir + "/sysext_started.json"
        let payload: [String: Any] = [
            "started_at_unix": Date().timeIntervalSince1970,
            "pid": getpid(),
            "version": version,
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]) else { return }
        try? FileManager.default.createDirectory(atPath: supportDir, withIntermediateDirectories: true)
        let tmp = path + ".tmp"
        try? data.write(to: URL(fileURLWithPath: tmp))
        try? FileManager.default.removeItem(atPath: path)
        try? FileManager.default.moveItem(atPath: tmp, toPath: path)
        try? FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: path)
    }

    /// v1.7.6: write a crash-report file when storage recovery exhausts
    /// retries. The dashboard reads this and surfaces a "Detection
    /// database failed to initialize" banner with the exact error +
    /// a "Recover" button.
    private static func writeCrashReport(supportDir: String, error: String, action: String) {
        let path = supportDir + "/last_crash.json"
        let payload: [String: Any] = [
            "occurred_at_unix": Date().timeIntervalSince1970,
            "error": error,
            "recovery_action": action,
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]) else { return }
        let tmp = path + ".tmp"
        try? data.write(to: URL(fileURLWithPath: tmp))
        try? FileManager.default.removeItem(atPath: path)
        try? FileManager.default.moveItem(atPath: tmp, toPath: path)
        try? FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: path)
    }

    /// Backup events.db / .wal / .shm to .corrupt-<timestamp> sibling files.
    /// Allows a fresh init to succeed; preserves the corrupted DB for forensics.
    private static func backupCorruptDatabase(directory: String, base: String) {
        let ts = Int(Date().timeIntervalSince1970)
        let suffixes = ["", "-wal", "-shm", "-journal"]
        for suffix in suffixes {
            let src = "\(directory)/\(base)\(suffix)"
            let dst = "\(directory)/\(base)\(suffix).corrupt-\(ts)"
            if FileManager.default.fileExists(atPath: src) {
                try? FileManager.default.moveItem(atPath: src, toPath: dst)
            }
        }
    }

    /// Recover from EventStore init failure. Captures the original error,
    /// backs up the corrupt files, retries init from a clean slate. If the
    /// recovery itself fails, writes last_crash.json and exits — but
    /// only after giving the dashboard a chance to surface the failure.
    static func recoverEventStore(supportDir: String, logger: Logger) -> EventStore {
        // First, capture the original error with public privacy so the
        // log shows what's wrong instead of "<private>".
        // v1.12.0 RC27 audit fix (Stab-B1): replace the `try!` second-
        // probe with a graceful return path. The prior code assumed
        // "unreachable" but a race or transient I/O hiccup between
        // the first failure and the second probe would crash the
        // daemon hard instead of running through the backup-and-retry
        // recovery path below.
        let originalError: String
        do {
            let store = try EventStore(directory: supportDir)
            // First attempt actually succeeded (transient failure
            // resolved itself). Return immediately; skip backup.
            logger.warning("EventStore: first init failed but a probe re-init succeeded — transient error; skipping backup")
            return store
        } catch {
            originalError = "\(error.localizedDescription) — \(error)"
        }
        logger.error("EventStore init failed: \(originalError, privacy: .public). Backing up corrupt files and retrying with a fresh database.")
        backupCorruptDatabase(directory: supportDir, base: "events.db")
        do {
            return try EventStore(directory: supportDir)
        } catch {
            let msg = "EventStore recovery failed: \(error.localizedDescription)"
            logger.error("\(msg, privacy: .public)")
            writeCrashReport(supportDir: supportDir, error: originalError, action: "EventStore recovery failed: \(error)")
            fputs("FATAL: \(msg)\n", stderr)
            exit(1)
        }
    }

    /// Same shape for AlertStore. v1.8.0 split alerts into their own
    /// `alerts.db` file, so EventStore recovery (which only touches
    /// events.db) doesn't help an AlertStore failure. If init fails,
    /// back up the corrupt alerts.db and retry once.
    static func recoverAlertStore(supportDir: String, logger: Logger) -> AlertStore {
        // v1.12.0 RC27 audit fix (Stab-B1): same pattern as recoverEventStore.
        let originalError: String
        do {
            let store = try AlertStore(directory: supportDir)
            logger.warning("AlertStore: first init failed but a probe re-init succeeded — transient error; skipping backup")
            return store
        } catch {
            originalError = "\(error.localizedDescription) — \(error)"
        }
        logger.error("AlertStore init failed: \(originalError, privacy: .public). Backing up corrupt alerts.db and retrying with a fresh database.")
        backupCorruptDatabase(directory: supportDir, base: "alerts.db")
        do {
            return try AlertStore(directory: supportDir)
        } catch {
            let msg = "AlertStore recovery failed: \(error.localizedDescription)"
            logger.error("\(msg, privacy: .public)")
            writeCrashReport(supportDir: supportDir, error: originalError, action: "AlertStore recovery failed: \(error)")
            fputs("FATAL: \(msg)\n", stderr)
            exit(1)
        }
    }

    /// Print a timing breadcrumb to the standard log. Used to find
    /// the actual daemon-boot bottleneck — v1.12.0 RC18 added these
    /// at major boot milestones so a `log show --predicate 'process ==
    /// "com.maccrab.agent"' | grep BOOT_TIMING` produces a single-pass
    /// breakdown of where the boot path spends time.
    fileprivate static func logBootStep(label: String, startedAt: Date) {
        let elapsed = Int(Date().timeIntervalSince(startedAt) * 1000)
        print("[BOOT_TIMING] \(label): +\(elapsed) ms")
        logger.notice("[BOOT_TIMING] \(label, privacy: .public): +\(elapsed, privacy: .public) ms")
    }

    /// Write a minimal boot-phase heartbeat so the dashboard can show
    /// "Daemon: Starting (loading rules)..." with real-time progress
    /// instead of "Not running" for 15-20 s while the daemon finishes
    /// initialising. Phase strings: "starting", "stores_ready",
    /// "rules_loaded", "collectors_started", "ready". Once `ready`, the
    /// regular livenessTimer takes over (`liveness: true` writes).
    /// Atomic via .tmp + rename, same as the livenessTimer pattern.
    fileprivate static func writeBootPhase(
        supportDir: String,
        phase: String,
        startedAt: Date
    ) {
        let payload: [String: Any] = [
            "written_at_unix": Date().timeIntervalSince1970,
            "started_at_unix": startedAt.timeIntervalSince1970,
            "uptime_seconds": Int(Date().timeIntervalSince(startedAt)),
            "boot_phase": phase,
            "liveness": false,
            "schema_version": 4,
        ]
        guard let data = try? JSONSerialization.data(
            withJSONObject: payload,
            options: [.sortedKeys]
        ) else { return }
        // Ensure the dir exists; on first daemon launch after install
        // the directory may be brand new.
        try? FileManager.default.createDirectory(
            atPath: supportDir,
            withIntermediateDirectories: true
        )
        let path = supportDir + "/heartbeat.json"
        let tmp = path + ".tmp"
        do {
            try data.write(to: URL(fileURLWithPath: tmp))
            try FileManager.default.moveItem(atPath: tmp, toPath: path)
        } catch {
            try? FileManager.default.removeItem(atPath: path)
            try? FileManager.default.moveItem(atPath: tmp, toPath: path)
        }
    }

    static func initialize() async -> DaemonState {
        let startupBegin = DispatchTime.now()
        let startedAt = Date()

        // Check if running as root (required for ES framework, optional for other sources)
        let isRoot = getuid() == 0
        if !isRoot {
            print("Note: Running without root. Endpoint Security events unavailable.")
            print("      Other sources (Unified Log, TCC, Network) will still work.")
            print("      For full coverage: run as root (dev) or install MacCrab.app and click Enable Protection (release).")
        }

        // Check Full Disk Access by probing a TCC-protected path.
        // Without FDA, ES events for protected file paths are silently dropped.
        if isRoot {
            let tccDB = "/Library/Application Support/com.apple.TCC/TCC.db"
            if FileManager.default.isReadableFile(atPath: tccDB) {
                print("Full Disk Access: granted (complete ES coverage)")
            } else {
                print("WARNING: Full Disk Access not granted — detection at ~70% coverage.")
                print("         Grant FDA to MacCrab.app (release) or your terminal emulator (dev)")
                print("         in System Settings > Privacy & Security > Full Disk Access, then restart.")
            }
        }

        // Paths -- root uses system location (shared with app), non-root uses user directory
        let supportDir: String
        if isRoot {
            supportDir = "/Library/Application Support/MacCrab"
        } else {
            let userAppSupport = FileManager.default.urls(
                for: .applicationSupportDirectory,
                in: .userDomainMask
            ).first.map { $0.appendingPathComponent("MacCrab").path }
                ?? NSHomeDirectory() + "/Library/Application Support/MacCrab"
            supportDir = userAppSupport
        }
        let compiledRulesDir = supportDir + "/compiled_rules"

        // v1.12.0 RC15: write an early "starting" heartbeat the moment
        // the support dir is known. Pre-fix, heartbeat.json didn't
        // appear until DaemonSetup.initialize() returned and the
        // livenessTimer fired (timer +0.5 s, dashboard poll every 10 s,
        // so steady-state "Daemon: starting…" appeared for up to 15-20 s
        // even though the process was up). With the boot_phase marker
        // here at T+~0 s, the dashboard can show real-time progress.
        writeBootPhase(supportDir: supportDir, phase: "starting", startedAt: startedAt)

        // Determine rules directory using a fixed, secure search order.
        // Environment variables are NOT used because a non-root user could
        // influence what the root daemon loads.
        let rulesDir: String
        let fm = FileManager.default

        /// Validate that a directory is safe to load rules from:
        /// it must not be a symlink, must be owned by root (or the current user),
        /// and must not be world-writable.
        func isSecureDirectory(_ path: String) -> Bool {
            // Reject symlinks: an attacker could point /Library/MacCrab/rules at
            // a world-writable directory they control. Use URL resource values
            // which operate on the path itself (lstat semantics) rather than
            // following the symlink (stat semantics).
            let url = URL(fileURLWithPath: path)
            if let resourceValues = try? url.resourceValues(forKeys: [.isSymbolicLinkKey]),
               resourceValues.isSymbolicLink == true {
                logger.warning("Rules directory \(path) is a symlink. Refusing to load rules to prevent symlink injection attacks.")
                return false
            }

            guard let attrs = try? fm.attributesOfItem(atPath: path) else {
                return false
            }
            let ownerUID = (attrs[.ownerAccountID] as? NSNumber)?.uint32Value ?? UInt32.max
            let currentUID = getuid()
            guard ownerUID == 0 || ownerUID == currentUID else {
                logger.warning("Rules directory \(path) is owned by uid \(ownerUID), expected 0 or \(currentUID). Skipping.")
                return false
            }
            if let posix = (attrs[.posixPermissions] as? NSNumber)?.intValue {
                // v1.17.2: reject GROUP- or world-writable (g+w|o+w = 0o022).
                // Detection rules govern what the EDR catches; a group-writable
                // rules dir (e.g. root:admin 0775) lets any admin-group member
                // drop a rule override that disables detection WITHOUT root —
                // a privilege-boundary hole. Rule dirs must be writable only by
                // their owner.
                if posix & 0o022 != 0 {
                    logger.warning("Rules directory \(path) is group/world-writable (mode \(String(posix, radix: 8))). Refusing to load rules to prevent non-root rule tampering.")
                    return false
                }
            }
            return true
        }

        // Fixed search order:
        // 1. /Library/MacCrab/rules/ (system-wide, root-owned)
        // 2. <executable_dir>/Rules/ (bundled with binary)
        // 3. ~/Library/Application Support/MacCrab/rules/ (user rules, only if not root)
        let systemRulesDir = "/Library/MacCrab/rules"
        let execDir = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent().path
        let bundledRulesDir = execDir + "/Rules"
        let userRulesDir = supportDir + "/rules"

        if fm.fileExists(atPath: systemRulesDir) && isSecureDirectory(systemRulesDir) {
            rulesDir = systemRulesDir
        } else if fm.fileExists(atPath: bundledRulesDir) && isSecureDirectory(bundledRulesDir) {
            rulesDir = bundledRulesDir
        } else if getuid() != 0 && fm.fileExists(atPath: userRulesDir) && isSecureDirectory(userRulesDir) {
            rulesDir = userRulesDir
        } else {
            // Fallback: use the system rules path even if it doesn't exist yet,
            // so the daemon can start and rules can be added later.
            rulesDir = systemRulesDir
        }

        logger.info("Rules directory: \(rulesDir)")
        logger.info("Support directory: \(supportDir)")

        // v1.6.14: quarantine orphan user-domain DBs left behind by a
        // pre-sysext dev daemon. Before the sysext ships, `swift run
        // maccrabd` writes to `~/<user>/Library/Application Support/
        // MacCrab/events.db`. After install, the sysext writes to
        // `/Library/Application Support/MacCrab/events.db`, but the
        // user-domain DB lingers — sometimes 100s of MB of stale data
        // the dashboard's most-recent-mtime picker confusingly
        // selects. Rename (don't delete) any such orphan that's been
        // idle >24h so the operator can inspect or purge it.
        if isRoot {
            reapOrphanUserDomainDBs(logger: logger)
        }

        // Load daemon configuration (optional JSON file with tuning overrides)
        let config = DaemonConfig.load(from: supportDir)

        // Create support directories with restrictive permissions
        try? fm.createDirectory(
            atPath: supportDir,
            withIntermediateDirectories: true
        )
        // Allow non-root GUI app to read the DB: rwxr-xr-x.
        // The DB file itself is 0o644 so the app can read it; the directory
        // needs at least r-x for traversal.
        try? fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: supportDir)

        try? fm.createDirectory(
            atPath: compiledRulesDir,
            withIntermediateDirectories: true
        )
        // Compiled rules are only read by the daemon — restrict to owner-only
        // to prevent attackers from reading detection logic for evasion.
        // rwxr-xr-x: non-root MacCrab.app needs to read rules for display
        try? fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: compiledRulesDir)

        // Initialize components
        let eventStore: EventStore
        let alertStore: AlertStore
        let enricher: EventEnricher
        let ruleEngine: RuleEngine
        var collector: ESCollector? = nil

        // v1.7.6: surface the actual SQLite error in the system log
        // (privacy: .public). The error message is a class-of-failure
        // description like "database disk image is malformed" — not
        // user data — so safe to expose. Pre-v1.7.6 the default
        // `\(value)` interpolation was redacted as `<private>` which
        // forced operators to enable private-data exposure system-wide
        // just to diagnose a daemon crash-loop.
        //
        // v1.7.6 also adds storage-recovery: if init fails, back up
        // the corrupt files and retry from a clean slate. Daemon
        // keeps running. Three retries max before exiting (and even
        // then we write last_crash.json so the dashboard can show a
        // specific "click to Recover" banner).
        eventStore = (try? EventStore(directory: supportDir))
            ?? Self.recoverEventStore(supportDir: supportDir, logger: logger)

        // v1.8.0 storage split: relocate `alerts` from events.db -> alerts.db
        // before AlertStore opens. Idempotent — no-op once migrated.
        // Best-effort: failure leaves both states present and AlertStore
        // initializes against an empty alerts.db. The next start retries.
        AlertsTableRelocator.relocate(directory: supportDir, logger: logger)

        alertStore = (try? AlertStore(directory: supportDir))
            ?? Self.recoverAlertStore(supportDir: supportDir, logger: logger)

        Self.writeBootPhase(supportDir: supportDir, phase: "stores_ready", startedAt: startedAt)
        Self.logBootStep(label: "stores_ready", startedAt: startedAt)

        // v1.12.0 RC23: quick_check entirely skipped on the daemon side.
        // RC15 deferred it to a background Task, but the actor model
        // means that Task still HELD eventStore for the duration of
        // PRAGMA quick_check (1-2 s on 962 MB DB) — so the very next
        // `await eventStore.setInsertFilter` call on the boot path
        // queued behind it for ~9 s (field-measured in RC22 timing
        // breadcrumbs). Real corruption surfaces immediately on actual
        // queries via SQLITE_CORRUPT, and `maccrabctl maintenance
        // check` exists for explicit operator-driven verification.

        // v1.8.0 Layer 1: install the pre-insert filter so noise events
        // never reach SQLite. Default filter drops the daemon's own self-
        // monitoring loop (own log/DB/support dir, /dev/null, /dev/ttys*)
        // — empirically 17% of event volume on field-measured hardware.
        // Operator-extended patterns from daemon_config can be merged in
        // here in a follow-up; the default alone closes the biggest gap.
        //
        // v1.10.0: this used to be a fire-and-forget Task — collectors
        // could (and did) start before the filter was in place, so
        // the first hundreds of events on every daemon startup
        // bypassed the filter. Await the actor call before any
        // collector is constructed below.
        await eventStore.setInsertFilter(
            EventInsertFilter.defaultFilter(supportDir: supportDir)
        )
        Self.logBootStep(label: "after_insert_filter", startedAt: startedAt)

        // ProcessHasher populates SHA-256 + CDHash on exec/fork events so
        // downstream rules and exports can match against threat-intel hashes.
        // Shared state across the daemon lifetime for cache reuse.
        let processHasher = ProcessHasher()

        // Deception tier (opt-in via MACCRAB_DECEPTION=1). Plants canary
        // credential files and exposes an isHoneyfile() lookup the enricher
        // uses to tag file events touching a canary.
        let honeyfileManager: HoneyfileManager?
        let honeyPromptManager: HoneyPromptManager?
        if ProcessInfo.processInfo.environment["MACCRAB_DECEPTION"] == "1" {
            let mgr = HoneyfileManager()
            honeyfileManager = mgr
            // v1.12.0 — pair the credential-shape bait (HoneyfileManager) with
            // AI-agent-context bait (HoneyPromptManager). Both deploy under
            // the same env-var gate so the operator's mental model stays
            // "deception on" / "deception off".
            let promptMgr = HoneyPromptManager()
            honeyPromptManager = promptMgr
            Task {
                do {
                    let deployed = try await mgr.deploy()
                    logger.info("Deployed \(deployed.count) honeyfiles (deception tier enabled)")
                } catch {
                    logger.warning("Honeyfile deploy failed: \(error.localizedDescription)")
                }
                do {
                    let deployedPrompts = try await promptMgr.deploy()
                    logger.info("Deployed \(deployedPrompts.count) honey-prompts (AI-agent context bait)")
                } catch {
                    logger.warning("Honey-prompt deploy failed: \(error.localizedDescription)")
                }
            }
        } else {
            honeyfileManager = nil
            honeyPromptManager = nil
        }

        // v1.12.0 — FileContent enricher reads first 64KB of close-write
        // events on a small allowlist (Info.plist, CHANGELOG, README,
        // .gitconfig, LaunchAgents plists, specific IOC filenames) so
        // detection rules can use `FileContent|contains: '...'` selectors.
        // Always on — the allowlist is tight enough that the cost is
        // negligible compared to the enrichment value.
        let fileContentEnricher = FileContentEnricher()

        // Env-var capture (opt-in). Reads DYLD_*, SSH_*, SUDO_*, AWS_PROFILE,
        // and a small set of context keys via sysctl on exec/fork. Secret-
        // bearing keys (AWS_SECRET_*, *_TOKEN, *_PASSWORD) are denied by
        // EnvCapture before allowlist resolution.
        let captureEnv = ProcessInfo.processInfo.environment["MACCRAB_CAPTURE_ENV"] == "1"
        if captureEnv {
            logger.info("Env var capture enabled (MACCRAB_CAPTURE_ENV=1)")
        }

        enricher = EventEnricher(
            processHasher: processHasher,
            honeyfileManager: honeyfileManager,
            honeyPromptManager: honeyPromptManager,
            fileContentEnricher: fileContentEnricher,
            captureEnv: captureEnv
        )
        ruleEngine = RuleEngine()
        Self.logBootStep(label: "after_enricher_engine", startedAt: startedAt)
        // v1.11.0 (audit functionality HIGH): read OS-notification
        // config from <supportDir>/alert_notifications.json instead
        // of hardcoding `.high`. Closes a wire-the-orphans gap —
        // SettingsView's notification toggle + severity picker have
        // existed since v1.0 but never reached the daemon. Falls
        // back to (enabled=true, .high) when the file is absent.
        // v1.11.0 RC2: pass `enabled` as its own flag (the previous
        // `.critical` sentinel didn't actually mute critical alerts).
        let notifConfig = loadAlertNotificationConfig(supportDir: supportDir)
        let notifier = NotificationOutput(minimumSeverity: notifConfig.minSeverity)
        await notifier.setEnabled(notifConfig.enabled)
        let responseEngine = ResponseEngine()

        Self.logBootStep(label: "after_response_engine", startedAt: startedAt)
        // Self-defense: tamper detection.
        // v1.12.0 RC21: the await selfDefense.start() pre-fix was on
        // the boot critical path. SelfDefense's startup does a baseline
        // scan of the rules dir + binary + WAL pages — easily multi-
        // second on first launch after install. Tamper detection
        // doesn't need to be ready by event #1; deferring .start() to
        // a Task gets the daemon serving events ~10× sooner while
        // losing only the tamper baseline for the first ~1 s.
        // (RC22 caught the constructor itself doing 3.6 s of binary
        // SHA-256 + rule dir hash — addressed in RC24 by lazy-hashing
        // inside SelfDefense rather than at-construct time. v1.12.1.)
        let selfDefense = SelfDefense(dataDir: supportDir, rulesDir: compiledRulesDir)
        Task.detached(priority: .utility) {
            await selfDefense.start { event in
            logger.critical("SELF-DEFENSE: [\(event.type.rawValue)] \(event.description)")
            print("[TAMPER] \(event.type.rawValue): \(event.description)")

            // Create an alert for tamper events
            let alert = Alert(
                ruleId: "maccrab.self-defense.\(event.type.rawValue)",
                ruleTitle: "MacCrab Tamper Detection: \(event.type.rawValue.replacingOccurrences(of: "_", with: " ").capitalized)",
                severity: event.severity,
                eventId: UUID().uuidString,
                processPath: event.path,
                processName: "maccrabd",
                description: event.description,
                mitreTactics: "attack.defense_evasion",
                mitreTechniques: "attack.t1562.001",
                suppressed: false
            )
            Task {
                // Audited AlertSink exception #1 of 2: SelfDefense alerts are
                // already debounced upstream (sustainedTamperAlerted in
                // SelfDefense.swift fires once per consecutive-tamper run) and
                // this closure is captured before DaemonState/AlertSink exist
                // in the setup order. Re-routing would force a major setup
                // reshuffle for zero dedup benefit.
                try? await alertStore.insert(alert: alert)
                await notifier.notify(alert: alert)
            }
        }
            print("Self-defense active (deferred — baseline forming in background)")
        }
        Self.logBootStep(label: "after_self_defense", startedAt: startedAt)

        // ES infrastructure health monitor.
        // v1.12.0 RC21 (TURBO): both await calls (start + currentStatus)
        // talk to xprotectd / syspolicyd / endpointsecurityd via private
        // OS APIs and can each block several seconds on a cold launch
        // (system services may be mid-init themselves). The status is
        // purely informational on the boot path — defer the whole probe
        // to a Task so the daemon doesn't wait on Apple's bootstrap.
        let esHealthMonitor = ESClientMonitor(pollInterval: config.esHealthPollInterval)
        Task.detached(priority: .utility) {
            await esHealthMonitor.start()
            let esHealth = await esHealthMonitor.currentStatus()
            if esHealth.isHealthy {
                print("ES infrastructure (deferred probe): healthy (xprotectd, syspolicyd, endpointsecurityd running)")
            } else {
                print("ES infrastructure (deferred probe): DEGRADED -- \(esHealth.issues.joined(separator: ", "))")
            }
        }
        Self.logBootStep(label: "after_es_health", startedAt: startedAt)

        // ES health monitoring task
        Task {
            for await healthEvent in esHealthMonitor.events {
                let alert = Alert(
                    ruleId: "maccrab.self-defense.\(healthEvent.type.rawValue)",
                    ruleTitle: "ES Infrastructure: \(healthEvent.type.rawValue.replacingOccurrences(of: "_", with: " ").capitalized)",
                    severity: healthEvent.severity,
                    eventId: UUID().uuidString,
                    processPath: nil,
                    processName: "maccrabd",
                    description: healthEvent.description,
                    mitreTactics: "attack.defense_evasion",
                    mitreTechniques: "attack.t1562.001",
                    suppressed: false
                )
                // Audited AlertSink exception #2 of 2: ESClientMonitor only
                // emits on state transitions (e.g. xprotectd died), so each
                // alert is already a one-shot. Same setup-order constraint as
                // exception #1 — closure captures alertStore before the
                // AlertSink instance is built.
                try? await alertStore.insert(alert: alert)
                await notifier.notify(alert: alert)
                print("[ES-HEALTH] \(healthEvent.type.rawValue): \(healthEvent.description)")
            }
        }

        // Threat intelligence feed. v1.12.0 RC16 (TURBO): construct
        // the actor immediately (cheap), but defer the `.start()`
        // refresh loop AND the bundled IOC load to a background Task.
        // Rules referencing threat-intel run against an empty index
        // for the first ~1-2 s of daemon life, then populate as the
        // background load completes — a tiny window of missed lookup
        // for a multi-second startup win.
        let threatIntel = ThreatIntelFeed(cacheDir: supportDir + "/threat_intel")
        Task.detached(priority: .utility) {
            await threatIntel.start()
            await BundledThreatIntel.loadInto(threatIntel)
            // v1.12.6 Wave 9F: write the cache file to disk RIGHT NOW
            // so a dashboard launched before the initial network fetch
            // completes (~14 min on a fresh install across all three
            // abuse.ch feeds) sees bundled IOCs immediately on first
            // Intelligence-tab mount. Pre-9F the cache file didn't
            // exist until updateAllFeeds() finished, so cold-start
            // dashboards saw an empty Threat Intel panel until the
            // user hit refresh. start() now awaits loadCachedFeeds()
            // inline, so on warm boot persistCacheNow() saves the
            // union (network IOCs from prior boots + bundled).
            await threatIntel.persistCacheNow()
            let bundledStats = BundledThreatIntel.stats
            print("Bundled threat intel loaded (deferred): \(bundledStats.hashes) hashes, \(bundledStats.ips) IPs, \(bundledStats.domains) domains")
            print("Threat intel feed active (abuse.ch Feodo, URLhaus, MalwareBazaar)")
        }

        Self.logBootStep(label: "threat_intel_init", startedAt: startedAt)
        // Behavioral scoring engine
        let behaviorScoring = BehaviorScoring(alertThreshold: config.behaviorAlertThreshold, criticalThreshold: config.behaviorCriticalThreshold)

        // Certificate Transparency monitor
        let ctMonitor = CertTransparency()

        // Incident grouper -- clusters related alerts into attack timelines
        let incidentGrouper = IncidentGrouper(correlationWindow: config.incidentCorrelationWindow, staleWindow: config.incidentStaleWindow)

        // Campaign detector -- meta-alert engine: chains alerts into kill chains,
        // alert storms, AI compromise patterns, and coordinated attacks
        let campaignDetector = CampaignDetector()

        // Persistent campaign store. Non-fatal if it fails to open — the
        // detector stays in-memory-only in that case and the daemon logs
        // the error rather than crashing.
        let campaignStore: CampaignStore?
        do {
            campaignStore = try CampaignStore(directory: supportDir)
        } catch {
            logger.warning("CampaignStore failed to open: \(error.localizedDescription) — campaigns will not persist across restarts")
            campaignStore = nil
        }
        Self.logBootStep(label: "after_campaign_store", startedAt: startedAt)

        // v1.10.0 TraceGraph wiring. Pre-fix the materializer + rolling
        // graph + event bridge shipped compiled but were never
        // instantiated by the daemon — only `maccrabctl trace demo`
        // produced traces. Now every Event flowing through the
        // EventLoop gets fed to the bridge, which materializes a Trace
        // when AnchorDetector decides the event is anchor-worthy.
        // Non-fatal on store failure (the rest of the daemon keeps
        // running without trace materialization).
        // v1.10.0 audit fix: build DatabaseEncryption here so it can
        // be passed into SQLiteCausalGraphStore. Pre-fix the store
        // was instantiated without the encryption param, and the
        // canonical `dbEncryption` was only constructed ~130 lines
        // below — tracegraph.db's `attributes_json`, `evidence_json`,
        // `summary_json`, `attack_json`, `policy_snapshot_json`
        // were written plaintext on disk despite the v1.9
        // "AES-GCM at rest" invariant. The canonical `dbEncryption`
        // below uses the same env-var gate so behaviour is identical;
        // this early instance just gates plumbing for stores that
        // need it before the canonical construction site.
        let earlyEncryptDbEnv = Foundation.ProcessInfo.processInfo.environment["MACCRAB_ENCRYPT_DB"]
        let earlyDbEncryption = DatabaseEncryption(enabled: earlyEncryptDbEnv != "0")

        let causalGraphBridge: EventToRollingCausalGraphBridge?
        // Hoisted out of the do-block so the daily retention timer in
        // DaemonTimers can call prune / size-cap on the same store.
        let causalStoreOuter: SQLiteCausalGraphStore?
        // v1.12.0 RC25 audit fix (Int-H3): retry with backup on corrupt
        // tracegraph.db. EventStore + AlertStore have recovery paths
        // (lines 73-122); SQLiteCausalGraphStore previously had none.
        // With this fix a 7GB corrupt tracegraph gets quarantined and
        // the daemon continues with a fresh empty store — the rest of
        // detection keeps working.
        func openCausalStore() async -> SQLiteCausalGraphStore? {
            let dbPath = supportDir + "/tracegraph.db"
            do {
                return try await SQLiteCausalGraphStore(
                    databasePath: dbPath, encryption: earlyDbEncryption
                )
            } catch {
                logger.error("TraceGraph init failed: \(error.localizedDescription, privacy: .public) — quarantining and retrying")
                let ts = Int(Date().timeIntervalSince1970)
                let quarantineDir = supportDir + "/quarantine"
                // v1.12.0 RC28 audit fix (Sec-M2): refuse to use a
                // symlinked quarantine dir. Without this an attacker
                // who can pre-create supportDir/quarantine as a link
                // to /Users/<them>/ would have us land sensitive
                // tracegraph.db content under their control on next
                // crash. lstat refuses to follow; URL resource-keys
                // .isSymbolicLink is the same check.
                let qURL = URL(fileURLWithPath: quarantineDir)
                let qIsSymlink = (try? qURL.resourceValues(forKeys: [.isSymbolicLinkKey]))?.isSymbolicLink == true
                if qIsSymlink {
                    logger.error("TraceGraph quarantine refused: \(quarantineDir, privacy: .public) is a symlink")
                    return nil
                }
                try? FileManager.default.createDirectory(
                    atPath: quarantineDir, withIntermediateDirectories: true
                )
                for ext in ["", "-wal", "-shm", "-journal"] {
                    let src = dbPath + ext
                    if FileManager.default.fileExists(atPath: src) {
                        let dst = "\(quarantineDir)/tracegraph.db.corrupt-\(ts)\(ext)"
                        try? FileManager.default.moveItem(atPath: src, toPath: dst)
                    }
                }
                return try? await SQLiteCausalGraphStore(
                    databasePath: dbPath, encryption: earlyDbEncryption
                )
            }
        }
        if let causalStore = await openCausalStore() {
            let materializer = TraceMaterializer(
                store: causalStore,
                daemonVersion: MacCrabVersion.current,
                rulesetVersion: MacCrabVersion.current
            )
            let rollingGraph = RollingCausalGraph(
                store: causalStore,
                materializer: materializer
            )
            // v1.17.4 (perf): gate graph ingest on the same default noise
            // filter the EventStore insert path uses (own instance — keeps
            // the EventStore drop counter clean). The graph was previously
            // fed EVERY event, churning on self-monitoring/dev-tool noise.
            causalGraphBridge = EventToRollingCausalGraphBridge(
                rollingGraph: rollingGraph,
                insertFilter: EventInsertFilter.defaultFilter(supportDir: supportDir)
            )
            causalStoreOuter = causalStore
            logger.info("TraceGraph materializer wired — events will now anchor traces in tracegraph.db")
        } else {
            logger.warning("TraceGraph init failed twice; trace materialization disabled this run")
            causalGraphBridge = nil
            causalStoreOuter = nil
        }

        // v1.12.0 — load graph rules from `<support-dir>/compiled_rules/graph`
        // (release builds) or `Rules/graph` (dev builds). Each rule is a
        // JSON file describing a multi-entity pattern that fires only
        // when a materialized Trace contains a matching constellation of
        // entities + edges. The evaluator runs in EventLoop right after
        // `EventToRollingCausalGraphBridge.process` returns its [Trace],
        // so every materialized trace gets one pass of graph rules.
        // Skipped when causalStoreOuter is nil — without traces there's
        // nothing to evaluate against.
        let graphEvaluator: GraphRuleEvaluator?
        if causalStoreOuter != nil {
            let compiledGraphDir = URL(fileURLWithPath: supportDir + "/compiled_rules/graph")
            var loaded = GraphRuleLoader.loadRules(from: compiledGraphDir)
            if loaded.isEmpty {
                // Dev fallback: pick up rules straight from the source tree.
                let cwd = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
                loaded = GraphRuleLoader.loadFromProjectSource(projectRoot: cwd)
            }
            if loaded.isEmpty {
                logger.info("TraceGraph rule evaluator: no graph rules found — multi-entity detection disabled this run")
                graphEvaluator = nil
            } else {
                graphEvaluator = GraphRuleEvaluator(rules: loaded)
                logger.info("TraceGraph rule evaluator: loaded \(loaded.count) graph rules")
            }
        } else {
            graphEvaluator = nil
        }
        Self.logBootStep(label: "after_graph_evaluator", startedAt: startedAt)

        // Load response action config if it exists
        let actionConfigPath = supportDir + "/actions.json"
        if FileManager.default.fileExists(atPath: actionConfigPath) {
            do {
                try await responseEngine.loadConfig(from: actionConfigPath)
                logger.info("Loaded response action config from \(actionConfigPath)")
                print("Response actions configured from: \(actionConfigPath)")
            } catch {
                logger.warning("Failed to load action config: \(error.localizedDescription)")
            }
        }

        // AI Guard: tool registry + process tracker
        let aiRegistry = AIToolRegistry()
        let lineageRef = await enricher.lineage
        let aiTracker = AIProcessTracker(lineage: lineageRef, registry: aiRegistry)
        let credentialFence = CredentialFence()
        let projectBoundary = ProjectBoundary()
        let injectionScanner = PromptInjectionScanner(confidenceThreshold: config.promptInjectionConfidence)
        let scannerStatus = await injectionScanner.isAvailable ? "active" : "unavailable (pip install forensicate)"
        print("AI Guard active (monitoring Claude Code, Codex, OpenClaw, Cursor)")
        print("  Credential fence: \(CredentialFence.defaultPaths.count) sensitive paths")
        print("  Prompt injection scanner: \(scannerStatus)")

        // Statistical anomaly detector
        let statisticalDetector = StatisticalAnomalyDetector(zThreshold: config.statisticalZThreshold, minSamples: config.statisticalMinSamples)

        // MCP server monitor -- watches AI tool configs for suspicious MCP server registrations
        let mcpMonitor = MCPMonitor()
        await mcpMonitor.start()
        print("MCP server monitor active (watching Claude, Cursor, Continue, VS Code, Windsurf configs)")

        // v1.7.0: MCP attribution + behavioral baseline.
        // MCPAttributor walks each AI-child event's ancestry to identify
        // the running MCP server (filesystem/github/fetch/...). Tags the
        // event so MCPBaselineService can build per-(tool,server)
        // fingerprints and emit deviation alerts when a server's
        // runtime behavior drifts from its learned baseline.
        let mcpAttributor = MCPAttributor(mcpMonitor: mcpMonitor, lineage: lineageRef)
        let mcpBaseline = MCPBaselineService()
        print("MCP attributor + behavioral baseline active")

        // v1.7.2: collector liveness registry. Pre-register the 16
        // known collectors so the dashboard sees the full set even
        // before any of them emits an event. `eventDriven: true` for
        // collectors that can be quiet for hours during normal idle
        // (USB hotplug, browser extension install, etc.).
        let collectorRegistry = CollectorRegistry()
        // ESCollector + NetworkCollector tick at fixed cadence so
        // they're genuinely non-event-driven — a missed tick is real
        // evidence of stall.
        await collectorRegistry.register(name: "ESCollector", expectedIntervalSeconds: 5, eventDriven: false)
        await collectorRegistry.register(name: "NetworkCollector", expectedIntervalSeconds: 10, eventDriven: false)
        // UnifiedLog / DNS (BPF) / FSEvents / SystemPolicy are real-
        // time event-driven streams that genuinely sit silent on a
        // quiet machine for minutes at a time. Pre-fix all four were
        // registered with `eventDriven: false`, which forced
        // `healthy=false` whenever `lastTick == nil` — so they
        // appeared "Stalled" in the dashboard the entire time their
        // event loops were running normally and just hadn't seen a
        // matching kernel event yet. v1.10.0 audit fix.
        await collectorRegistry.register(name: "UnifiedLogCollector", expectedIntervalSeconds: 30, eventDriven: true)
        await collectorRegistry.register(name: "DNSCollector", expectedIntervalSeconds: 30, eventDriven: true)
        await collectorRegistry.register(name: "FSEventsCollector", expectedIntervalSeconds: 30, eventDriven: true)
        await collectorRegistry.register(name: "TCCMonitor", expectedIntervalSeconds: 60, eventDriven: true)
        await collectorRegistry.register(name: "EDRMonitor", expectedIntervalSeconds: 120, eventDriven: true)
        await collectorRegistry.register(name: "USBMonitor", expectedIntervalSeconds: 10, eventDriven: true)
        await collectorRegistry.register(name: "ClipboardMonitor", expectedIntervalSeconds: 3, eventDriven: true)
        await collectorRegistry.register(name: "UltrasonicMonitor", expectedIntervalSeconds: 60, eventDriven: true)
        await collectorRegistry.register(name: "RootkitDetector", expectedIntervalSeconds: 120, eventDriven: true)
        await collectorRegistry.register(name: "EventTapMonitor", expectedIntervalSeconds: 60, eventDriven: true)
        await collectorRegistry.register(name: "SystemPolicyMonitor", expectedIntervalSeconds: 300, eventDriven: true)
        await collectorRegistry.register(name: "BrowserExtensionMonitor", expectedIntervalSeconds: 60, eventDriven: true)
        await collectorRegistry.register(name: "MCPMonitor", expectedIntervalSeconds: 60, eventDriven: true)
        await collectorRegistry.register(name: "TEMPESTMonitor", expectedIntervalSeconds: 60, eventDriven: true)
        print("Collector registry initialized — 16 collectors tracked")

        // Trust substrate -- ECDSA P-256 keypair for trace-bundle
        // signing. v1.10.0 audit fix: daemon was never instantiating
        // this, so the keypair only got generated lazily when an
        // operator ran `maccrabctl trace export` for the first time.
        // The dashboard's "Trust substrate: Not generated" badge sat
        // permanently red on a fresh sysext install. Now: bootstrap
        // here so `<dataDir>/keys/trace-signing.pub` is on disk by
        // the time the heartbeat first paints the System tab.
        let keysDir = URL(fileURLWithPath: supportDir + "/keys/")
        let trustStorage = FilesystemTrustSubstrateStorage(baseDirectory: keysDir)
        let trustSubstrate = TrustSubstrate(storage: trustStorage)
        do {
            _ = try await trustSubstrate.publicKey()
            print("Trust substrate: keypair available")
        } catch {
            print("Trust substrate: bootstrap failed — \(error). Trace-bundle signing will lazily retry on first export.")
        }

        // USB device monitor -- detects mass storage, HID keyboard emulation.
        // v1.12.0 RC21 (TURBO): IOKit polling startup is cheap on the
        // happy path but blocks if IOKit power-management is mid-state.
        // Defer to a Task.
        let usbMonitor = USBMonitor(pollInterval: config.usbPollInterval)
        Task.detached(priority: .utility) {
            await usbMonitor.start()
            print("USB device monitor active (deferred)")
        }

        // Database encryption -- AES-256 field encryption, key in Keychain.
        // v1.9.0 (audit Sec-H2): default ON to match the dashboard's
        // unconditional `enabled: true` and the release-notes claim of
        // "AES-GCM at rest". Pre-fix, the daemon gated on
        // `MACCRAB_ENCRYPT_DB=="1"`, so unless the operator set the env
        // var the daemon wrote plaintext while the dashboard's decrypt
        // path passed it through (no `ENC2:` prefix → no-op). The
        // claim was conditionally true; now it's unconditional.
        // `MACCRAB_ENCRYPT_DB=0` remains as an explicit escape hatch
        // for tests and bisects.
        let encryptDbEnv = Foundation.ProcessInfo.processInfo.environment["MACCRAB_ENCRYPT_DB"]
        let dbEncryptionEnabled = (encryptDbEnv != "0")
        let dbEncryption = DatabaseEncryption(enabled: dbEncryptionEnabled)
        if dbEncryption.isEnabled {
            print("Database encryption: active (AES-GCM, key in Keychain)")
        } else {
            print("Database encryption: disabled via MACCRAB_ENCRYPT_DB=0")
        }

        // Report generator -- HTML incident reports
        let reportGenerator = ReportGenerator()

        // Clipboard monitor -- detects sensitive data and injection on clipboard.
        // v1.12.0 RC21 (TURBO): polled monitor, defer .start().
        // v1.18: ClickFix detector, SHARED with the event loop via DaemonState.
        // The monitor records delivery-shaped clipboard payloads (curl|bash, etc.);
        // the exec path correlates a subsequent shell/Terminal exec against them.
        let clickFixDetector = ClickFixDetector()
        let clipboardMonitor = ClipboardMonitor(pollInterval: config.clipboardPollInterval, clickFix: clickFixDetector)
        Task.detached(priority: .utility) {
            await clipboardMonitor.start()
            print("Clipboard monitor active (deferred, sensitive data + injection detection)")
        }
        let clipboardInjectionDetector = ClipboardInjectionDetector()

        // Browser extension monitor -- scans Chrome/Firefox/Brave/Edge/Arc.
        // v1.12.0 RC21 (TURBO): startup scans 5 browser profile dirs +
        // enumerates each extension manifest — disk-heavy. Defer.
        let browserExtMonitor = BrowserExtensionMonitor(pollInterval: config.browserExtensionPollInterval)
        Task.detached(priority: .utility) {
            await browserExtMonitor.start()
            print("Browser extension monitor active (deferred)")
        }

        // Ultrasonic attack monitor -- FFT mic sampling for DolphinAttack/NUIT
        // Opt-in: requires microphone access which triggers a TCC permission popup.
        // Enable with "ultrasonicEnabled": true in daemon_config.json or MACCRAB_ULTRASONIC=1.
        let ultrasonicEnabled = config.ultrasonicEnabled || ProcessInfo.processInfo.environment["MACCRAB_ULTRASONIC"] == "1"
        let ultrasonicMonitor = UltrasonicMonitor(pollInterval: config.ultrasonicPollInterval)
        if ultrasonicEnabled {
            await ultrasonicMonitor.start()
            print("Ultrasonic attack monitor active (DolphinAttack, NUIT, SurfingAttack)")
        } else {
            print("Ultrasonic attack monitor: disabled (set MACCRAB_ULTRASONIC=1 to enable)")
        }

        // DoH evasion detector -- flags non-browser DoH usage
        let dohDetector = DoHDetector()

        // TLS fingerprinter -- C2 beacon detection via connection interval analysis
        let tlsFingerprinter = TLSFingerprinter()

        // Git security monitor -- credential theft, SSH agent hijack, malicious hooks
        let gitSecurityMonitor = GitSecurityMonitor()

        // File injection scanner -- scans files AI tools access for hidden prompt injection
        let fileInjectionScanner = FileInjectionScanner()
        if await fileInjectionScanner.isAvailable {
            print("File injection scanner active (forensicate + inline detection)")
        }

        // Natural language threat hunter
        let threatHunter = ThreatHunter(databasePath: supportDir + "/events.db")

        // Auto rule generator -- creates Sigma rules from observed campaigns
        let ruleGenerator = RuleGenerator(outputDir: supportDir + "/compiled_rules")

        // Rootkit detector — dual-API cross-reference of process tables.
        // v1.12.0 RC21 (TURBO): polled (120 s default) — defer .start().
        let rootkitDetector = RootkitDetector(pollInterval: config.rootkitPollInterval)
        Task.detached(priority: .utility) {
            await rootkitDetector.start()
            print("Rootkit detector active (deferred, dual-API cross-reference)")
        }

        // EDR/RMM tool monitor — scans for EDR, insider threat, MDM, and remote access tools.
        // v1.12.0 RC21 (TURBO): scans for 30+ tool signatures = disk +
        // code-signing churn. This was flagged by the RC18 perf agent;
        // already deferred for SecurityToolIntegrations, but EDRMonitor
        // is a SEPARATE actor doing similar work. Defer.
        let edrMonitor = EDRMonitor(pollInterval: 120)
        Task.detached(priority: .utility) {
            await edrMonitor.start()
            print("EDR/RMM monitor active (deferred — CrowdStrike, SentinelOne, ForcePoint, Jamf, TeamViewer + 25 more)")
        }

        // TEMPEST / Van Eck phreaking monitor — SDR device detection + display anomalies.
        // v1.12.0 RC21 (TURBO): IOKit enumeration + DRM display probe;
        // defer.
        let tempestMonitor = TEMPESTMonitor(pollInterval: 60)
        Task.detached(priority: .utility) {
            await tempestMonitor.start()
            print("TEMPEST monitor active (deferred, SDR device detection, display anomaly monitoring)")
        }

        // Library inventory -- scans for injected dylibs
        let libraryInventory = LibraryInventory()

        // CDHash extractor -- binary identity via undocumented flavor 17
        let cdhashExtractor = CDHashExtractor()

        // Crash report miner -- exploitation indicators in crash logs
        let crashReportMiner = CrashReportMiner()

        // Power anomaly detector -- crypto miners, C2 beacons via sleep prevention
        let powerAnomalyDetector = PowerAnomalyDetector()

        // === PREVENTION LAYER ===
        let preventionEnabled: Bool = {
            // Check env var first (backward compat)
            if Foundation.ProcessInfo.processInfo.environment["MACCRAB_PREVENTION"] == "1" { return true }
            // Check config file written by the dashboard app
            let configPath = supportDir + "/prevention_config.json"
            if let data = try? Data(contentsOf: URL(fileURLWithPath: configPath)),
               let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let enabled = json["enabled"] as? Bool {
                return enabled
            }
            return false
        }()

        // DNS Sinkhole -- redirect malicious domains to localhost
        let dnsSinkhole = DNSSinkhole()

        // Network Blocker -- PF table-based IP blocking
        let networkBlocker = NetworkBlocker()

        // Persistence Guard -- chflags on LaunchAgent/LaunchDaemon dirs
        let persistenceGuard = PersistenceGuard()

        // Sandbox Analyzer -- sandbox-exec suspicious binaries
        let sandboxAnalyzer = SandboxAnalyzer()

        // AI Containment -- lock credential files from AI tools
        let aiContainment = AIContainment()

        // Supply Chain Gate -- kill installers of fresh packages
        let supplyChainGate = SupplyChainGate()

        // TCC Revocation -- auto-revoke permissions for unsigned apps
        let tccRevocation = TCCRevocation()

        if preventionEnabled {
            // Register threat intel update callback to populate prevention modules
            await threatIntel.onUpdate { [dnsSinkhole, networkBlocker] ips, domains in
                await dnsSinkhole.enable(domains: domains)
                await networkBlocker.enable(ips: ips)
            }

            // Initial population from any cached threat intel
            let cachedIPs = await threatIntel.maliciousIPSet()
            let cachedDomains = await threatIntel.maliciousDomainSet()
            if !cachedDomains.isEmpty {
                await dnsSinkhole.enable(domains: cachedDomains)
            }
            if !cachedIPs.isEmpty {
                await networkBlocker.enable(ips: cachedIPs)
            }

            // Lock persistence directories
            await persistenceGuard.enable()

            // Lock credential files from AI tools
            await aiContainment.enable()

            // Enable supply chain gate
            await supplyChainGate.enable()

            // Enable TCC auto-revocation
            await tccRevocation.enable()

            print("Prevention layer: ACTIVE (DNS sinkhole, PF blocker, persistence guard, AI containment, supply chain gate, TCC revocation)")
        } else {
            print("Prevention layer: STANDBY (set MACCRAB_PREVENTION=1 to enable)")
        }

        Self.logBootStep(label: "before_user_security", startedAt: startedAt)
        // === USER SECURITY FEATURES ===

        // Security scorer -- 0-100 system security posture score.
        // v1.12.0 RC19 (TURBO): the calculate() pass enumerates 20+
        // posture signals (SIP/Gatekeeper/FileVault states, kext load
        // history, MDM enrolment, software update lag) — each a system
        // call. Defer to a Task; the dashboard's first read of the
        // score lands at first heartbeat tick (30 s) which is also
        // when the deferred calculation completes.
        let securityScorer = SecurityScorer()
        Task.detached(priority: .utility) {
            let initialScore = await securityScorer.calculate()
            print("Security score (deferred): \(initialScore.totalScore)/100 (\(initialScore.grade))\(initialScore.recommendations.isEmpty ? "" : " -- \(initialScore.recommendations.first ?? "")")")
        }

        // App privacy auditor -- tracks which apps phone home
        let appPrivacyAuditor = AppPrivacyAuditor()

        // Vulnerability scanner -- checks installed apps against CVE database
        let vulnScanner = VulnerabilityScanner()

        // PanicButton was instantiated here pre-v1.6.19 but had no production
        // caller (no UI surface invokes activate()). Removed from
        // DaemonState. Re-add when a Panic button ships in the dashboard.

        // Travel mode -- heightened security for untrusted networks
        let travelMode = TravelMode()

        // Daily security digest generator
        let securityDigest = SecurityDigest()

        // Notification integrations (Slack, Teams, Discord, PagerDuty)
        let notificationIntegrations = NotificationIntegrations(configPath: supportDir + "/notifications.json")
        let configuredNotifs = await notificationIntegrations.configuredServices()
        if !configuredNotifs.isEmpty {
            print("Notification integrations: \(configuredNotifs.joined(separator: ", "))")
        }

        // Alert exporter -- multi-format export (SARIF, CEF, CSV, JSON, STIX)
        let alertExporter = AlertExporter()

        // Scheduled reports -- daily digest + weekly HTML report
        let scheduledReports = ScheduledReports(supportDir: supportDir)
        let reportSchedule = await scheduledReports.getSchedule()
        if reportSchedule.dailyDigestEnabled || reportSchedule.weeklyReportEnabled {
            print("Scheduled reports: daily=\(reportSchedule.dailyDigestEnabled), weekly=\(reportSchedule.weeklyReportEnabled)")
        }

        // MISP threat intel integration.
        // v1.12.0 RC19 (TURBO): network call to MISP can block 10-30 s
        // on a slow/unreachable endpoint. Defer the whole fetch to a
        // background Task so the boot path isn't held hostage to a
        // remote service. Worst case: rules referencing MISP-sourced
        // IOCs miss matches for the first second of daemon life.
        let mispClient = MISPClient()
        Task.detached(priority: .utility) {
            if await mispClient.isConfigured {
                print("MISP integration: configured (deferred fetch)")
                let mispIOCs = await mispClient.fetchCategorized(lastDays: 7)
                if !mispIOCs.ips.isEmpty || !mispIOCs.domains.isEmpty || !mispIOCs.hashes.isEmpty {
                    await threatIntel.addCustomIOCs(hashes: mispIOCs.hashes, ips: mispIOCs.ips, domains: mispIOCs.domains)
                    print("  MISP import (deferred): \(mispIOCs.ips.count) IPs, \(mispIOCs.domains.count) domains, \(mispIOCs.hashes.count) hashes")
                }
            }
        }

        // Security tool integrations (read-only detection of other tools).
        // v1.12.0 RC19 (TURBO): the detection pass scans for 30+ EDR/
        // MDM/remote-access tool signatures, each involving filesystem
        // probes + code-signing checks. Field profiling (RC18 timing
        // breadcrumbs) showed this is the #1 single contributor to the
        // ~41 s pre-rules boot phase. Defer to a background Task; the
        // dashboard's IntegrationsView reads the snapshot once it's
        // written.
        let toolIntegrations = SecurityToolIntegrations()
        Task.detached(priority: .utility) {
            let installedTools = await toolIntegrations.detectInstalledTools()
            if !installedTools.isEmpty {
                let running = installedTools.filter(\.isRunning).map(\.name)
                print("Security tools detected (deferred): \(installedTools.map(\.name).joined(separator: ", "))\(running.isEmpty ? "" : " (running: \(running.joined(separator: ", ")))")")
            }
            await toolIntegrations.writeSnapshot(to: supportDir + "/integrations_snapshot.json")
        }

        // Notarization checker -- verifies notarization status of executed binaries
        let notarizationChecker = NotarizationChecker()

        // AI network sandbox -- monitors AI tool network connections against allowlist
        let aiNetworkSandbox = AINetworkSandbox(customConfigPath: supportDir + "/ai_network_allowlist.json")

        // Package freshness checker -- queries registries for package age
        let packageChecker = PackageFreshnessChecker()
        print("Package freshness checker active (npm, PyPI, Homebrew, Cargo)")

        // Cross-process correlator -- links events across unrelated process trees
        let crossProcessCorrelator = CrossProcessCorrelator()

        // Process tree ML -- Markov chain anomaly detection on parent-child transitions
        Self.logBootStep(label: "before_process_tree", startedAt: startedAt)
        let processTreeAnalyzer = ProcessTreeAnalyzer(modelPath: supportDir + "/process_tree_model.json")
        do {
            try await processTreeAnalyzer.load()
            let treeStats = await processTreeAnalyzer.stats()
            print("Process tree ML: \(treeStats.mode.rawValue) (\(treeStats.transitions) transitions, \(treeStats.uniqueParents) parents)")
        } catch {
            print("Process tree ML: starting fresh learning period")
        }

        // Topology anomaly detector -- complements ProcessTreeAnalyzer with
        // shape-based hard rules (launchd→shell, system→staged binary, fork
        // storm, deep descent). No persisted state; in-memory only.
        let topologyAnomalyDetector = TopologyAnomalyDetector()

        // Fleet telemetry (optional -- configure via MACCRAB_FLEET_URL env var)
        let fleetClient = FleetClient()
        if let fleet = fleetClient {
            await fleet.start { aggregation in
                // Feed fleet IOCs into local threat intel
                for ioc in aggregation.iocs where ioc.hostCount >= 2 {
                    if ioc.type == "ip" {
                        await threatIntel.addCustomIOCs(ips: [ioc.value])
                    } else if ioc.type == "domain" {
                        await threatIntel.addCustomIOCs(domains: [ioc.value])
                    } else if ioc.type == "hash" {
                        await threatIntel.addCustomIOCs(hashes: [ioc.value])
                    }
                }
            }
            print("Fleet client active")
        }

        // === LLM REASONING BACKEND (optional) ===
        // Config sources (in priority order): env vars > llm_config.json > daemon_config.json
        let llmService: LLMService? = await {
            var llmConfig = config.llm

            // Read dashboard-written llm_config.json (written by Settings > AI Backend)
            let llmConfigPath = supportDir + "/llm_config.json"
            if let data = try? Data(contentsOf: URL(fileURLWithPath: llmConfigPath)),
               let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                if let enabled = json["enabled"] as? Bool { llmConfig.enabled = enabled }
                if let provider = json["provider"] as? String {
                    llmConfig.provider = LLMProvider(rawValue: provider) ?? llmConfig.provider
                }
                if let v = json["ollama_url"] as? String { llmConfig.ollamaURL = v }
                if let v = json["ollama_model"] as? String { llmConfig.ollamaModel = v }
                if let v = json["ollama_api_key"] as? String { llmConfig.ollamaAPIKey = v }
                if let v = json["claude_api_key"] as? String { llmConfig.claudeAPIKey = v }
                if let v = json["claude_model"] as? String { llmConfig.claudeModel = v }
                if let v = json["openai_url"] as? String { llmConfig.openaiURL = v }
                if let v = json["openai_api_key"] as? String { llmConfig.openaiAPIKey = v }
                if let v = json["openai_model"] as? String { llmConfig.openaiModel = v }
                if let v = json["mistral_api_key"] as? String { llmConfig.mistralAPIKey = v }
                if let v = json["mistral_model"] as? String { llmConfig.mistralModel = v }
                if let v = json["gemini_api_key"] as? String { llmConfig.geminiAPIKey = v }
                if let v = json["gemini_model"] as? String { llmConfig.geminiModel = v }
            }

            // Env vars override everything (backward compat)
            let env = ProcessInfo.processInfo.environment
            if let p = env["MACCRAB_LLM_PROVIDER"] { llmConfig.provider = LLMProvider(rawValue: p) ?? llmConfig.provider }
            if let v = env["MACCRAB_LLM_OLLAMA_URL"] { llmConfig.ollamaURL = v }
            if let v = env["MACCRAB_LLM_OLLAMA_MODEL"] { llmConfig.ollamaModel = v }
            if let v = env["MACCRAB_LLM_CLAUDE_KEY"] { llmConfig.claudeAPIKey = v }
            if let v = env["MACCRAB_LLM_CLAUDE_MODEL"] { llmConfig.claudeModel = v }
            if let v = env["MACCRAB_LLM_OPENAI_URL"] { llmConfig.openaiURL = v }
            if let v = env["MACCRAB_LLM_OPENAI_KEY"] { llmConfig.openaiAPIKey = v }
            if let v = env["MACCRAB_LLM_OPENAI_MODEL"] { llmConfig.openaiModel = v }

            guard llmConfig.enabled else { return nil }

            let backend: any LLMBackend
            switch llmConfig.provider {
            case .ollama:
                let ollama = OllamaBackend(baseURL: llmConfig.ollamaURL, model: llmConfig.ollamaModel, apiKey: llmConfig.ollamaAPIKey)
                // v1.17.4: bounded (3s) model-presence probe. Pre-fix the
                // sysext defaulted to ollama/llama3.1:8b; if that model isn't
                // pulled (the live host has only qwen2.5:7b), every call 404s
                // and the circuit breaker thrashes forever with no signal.
                // Disable cleanly when the model is known-absent; stay
                // optimistic if /api/tags is unreachable (a transiently-down
                // Ollama at boot must not disable LLM until restart). 3s
                // mirrors makeFromConfig's bounded probe — no 60s blocking.
                let installed: Bool? = await withTaskGroup(of: Bool?.self) { group -> Bool? in
                    group.addTask { await ollama.modelIsInstalled() }
                    group.addTask {
                        try? await Task.sleep(nanoseconds: 3_000_000_000)
                        return nil  // timeout → undeterminable → optimistic
                    }
                    let result = await group.next() ?? nil
                    group.cancelAll()
                    return result
                }
                if installed == false {
                    print("LLM backend: configured Ollama model '\(llmConfig.ollamaModel)' not pulled — LLM disabled (pull it or pick an installed model in Settings → AI Backend)")
                    return nil
                }
                backend = ollama
            case .claude:
                guard let key = llmConfig.claudeAPIKey, !key.isEmpty else {
                    print("LLM backend: Claude requires API key")
                    return nil
                }
                backend = ClaudeBackend(apiKey: key, model: llmConfig.claudeModel)
            case .openai:
                guard let key = llmConfig.openaiAPIKey, !key.isEmpty else {
                    print("LLM backend: OpenAI requires API key")
                    return nil
                }
                backend = OpenAIBackend(baseURL: llmConfig.openaiURL, apiKey: key, model: llmConfig.openaiModel)
            case .mistral:
                guard let key = llmConfig.mistralAPIKey, !key.isEmpty else {
                    print("LLM backend: Mistral requires API key")
                    return nil
                }
                backend = MistralBackend(apiKey: key, model: llmConfig.mistralModel)
            case .gemini:
                guard let key = llmConfig.geminiAPIKey, !key.isEmpty else {
                    print("LLM backend: Gemini requires API key")
                    return nil
                }
                backend = GeminiBackend(apiKey: key, model: llmConfig.geminiModel)
            }

            // v1.12.0 RC19 (TURBO): the `isAvailable()` probe is a
            // network call. On an unreachable backend (Ollama down,
            // Claude API rate-limited, captive-portal network) the
            // default URLSession timeout is 60 s — a third of the
            // previous boot path. Optimistically return the service
            // without probing; LLMService's own circuit breaker
            // handles unreachable-at-call-time gracefully (3 failures
            // → 5 min cool-down) and triages all LLM features as
            // advisory-only.
            let service = LLMService(backend: backend, config: llmConfig)
            let model: String
            switch llmConfig.provider {
            case .ollama:  model = llmConfig.ollamaModel
            case .claude:  model = llmConfig.claudeModel
            case .openai:  model = llmConfig.openaiModel
            case .mistral: model = llmConfig.mistralModel
            case .gemini:  model = llmConfig.geminiModel
            }
            print("LLM backend: \(llmConfig.provider.rawValue) (\(model)) — availability checked lazily")
            return service
        }()

        // DNS collector (BPF capture or passive mode)
        Self.logBootStep(label: "before_dns_collector", startedAt: startedAt)
        let dnsCollector = DNSCollector()
        await dnsCollector.start()
        print("DNS collector active")

        // Event tap monitor (keylogger detection)
        let eventTapMonitor = EventTapMonitor(pollInterval: config.eventTapPollInterval)
        await eventTapMonitor.start()
        print("Event tap monitor active (keylogger detection)")

        // System policy monitor (SIP, auth plugins, quarantine, XProtect)
        let systemPolicyMonitor = SystemPolicyMonitor(pollInterval: config.systemPolicyPollInterval)
        await systemPolicyMonitor.start()
        print("System policy monitor active (SIP, plugins, quarantine, XProtect, XPC, MDM)")

        // FSEvents fallback file monitor (works without root)
        let fsEventsCollector = FSEventsCollector()
        if !isRoot {
            await fsEventsCollector.start()
            print("FSEvents file monitor active (non-root fallback for ES)")
        }

        // Quarantine provenance enricher
        let quarantineEnricher = QuarantineEnricher()

        Self.logBootStep(label: "before_sequence_engine", startedAt: startedAt)
        // Initialize sequence engine (Phase 2: temporal-causal detection)
        Self.logBootStep(label: "before_sequence_engine_construct", startedAt: startedAt)
        let sequenceEngine = await SequenceEngine(lineage: enricher.lineage)
        Self.logBootStep(label: "after_sequence_engine_construct", startedAt: startedAt)

        // Initialize baseline anomaly engine (Phase 3: learned detection).
        // v1.12.0 RC16 (TURBO): defer the on-disk model load to a
        // background Task. The actor is constructed synchronously
        // (cheap, no I/O), then `load()` happens in parallel with the
        // rest of boot. Events arriving in the first ~1 s after launch
        // see the engine in an "empty" state — equivalent to a fresh
        // learning period — which is benign: anomaly detection is
        // additive on top of the rule layer.
        let baselineEngine = BaselineEngine()
        Task.detached(priority: .utility) {
            do {
                try await baselineEngine.load()
                let status = await baselineEngine.status()
                logger.info("Baseline engine (deferred load): \(status.state.rawValue), \(status.totalEdges) edges")
                print("Baseline engine: \(status.state.rawValue) (\(status.totalEdges) edges learned)")
            } catch {
                logger.info("Baseline engine: starting fresh learning period")
                print("Baseline engine: starting 7-day learning period")
            }
        }

        // Initialize alert deduplicator (Phase 3)
        let deduplicator = AlertDeduplicator()

        // Load per-rule process suppressions (from maccrabctl suppress).
        // v1.12.0 RC16 (TURBO): defer load() — suppressions are an
        // additive filter (rule fires → suppression check → drop or
        // keep). Worst case for an event arriving in the boot window
        // is a small handful of alerts that would have been suppressed
        // get through. Acceptable for a multi-second boot win.
        // v1.12.0 RC25 audit fix (Int-H1): the prior deferral let
        // ESCollector start before .load() completed — events arriving
        // in the ~10-100 ms boot-finish window bypassed user-configured
        // suppressions and fired alerts the operator had explicitly
        // muted. Suppression load reads a single small JSON file
        // (typically <1 KB on a fresh install), so the cost is ~ms.
        // Switch back to a synchronous await before any collector
        // starts.
        let suppressionManager = SuppressionManager(dataDir: supportDir)
        await suppressionManager.load()
        let suppressionStats = await suppressionManager.stats()
        if suppressionStats.ruleCount > 0 {
            print("Suppressions loaded: \(suppressionStats.pathCount) paths across \(suppressionStats.ruleCount) rules")
        }

        // Initialize optional outputs (Phase 3)
        var webhookOutput: WebhookOutput? = nil
        if let webhookURLStr = Foundation.ProcessInfo.processInfo.environment["MACCRAB_WEBHOOK_URL"] {
            if let webhookURL = URL(string: webhookURLStr) {
                let allowPrivate = Foundation.ProcessInfo.processInfo.environment["MACCRAB_WEBHOOK_ALLOW_PRIVATE"] == "1"
                do {
                    try WebhookOutput.validate(url: webhookURL, allowPrivate: allowPrivate)
                    webhookOutput = WebhookOutput(url: webhookURL)
                    logger.info("Webhook output enabled: \(webhookURLStr)")
                    print("Webhook output: \(webhookURLStr)")
                } catch {
                    logger.error("Webhook URL rejected: \(error.localizedDescription)")
                    print("ERROR: MACCRAB_WEBHOOK_URL rejected: \(error)")
                    print("       Webhook output disabled. Fix MACCRAB_WEBHOOK_URL and restart.")
                }
            } else {
                logger.error("MACCRAB_WEBHOOK_URL is not a valid URL")
                print("ERROR: MACCRAB_WEBHOOK_URL is not a valid URL — webhook output disabled")
            }
        }

        var syslogOutput: SyslogOutput? = nil
        if let syslogHost = Foundation.ProcessInfo.processInfo.environment["MACCRAB_SYSLOG_HOST"] {
            let syslogPort = UInt16(Foundation.ProcessInfo.processInfo.environment["MACCRAB_SYSLOG_PORT"] ?? "514") ?? 514
            syslogOutput = SyslogOutput(host: syslogHost, port: syslogPort)
            do {
                try await syslogOutput?.connect()
                logger.info("Syslog output enabled: \(syslogHost):\(syslogPort)")
                print("Syslog output: \(syslogHost):\(syslogPort)")
            } catch {
                logger.error("Failed to connect syslog: \(error.localizedDescription)")
                syslogOutput = nil
            }
        }

        // Phase 7 outputs: FileOutput and StreamOutput (Splunk HEC /
        // Elastic Bulk / Datadog Logs) built from daemon_config.json.outputs[].
        var additionalOutputs: [any Output] = []
        for spec in config.outputs {
            if let out = Self.buildOutput(spec: spec, logger: logger) {
                additionalOutputs.append(out)
            }
        }
        if !additionalOutputs.isEmpty {
            logger.info("Configured \(additionalOutputs.count) additional output(s)")
            print("Additional outputs: \(additionalOutputs.map { $0.name }.joined(separator: ", "))")
        }

        // Initialize optional YARA enrichment (Phase 3)
        let yaraRulesPath = supportDir + "/yara_rules"
        let yaraEnricher = YARAEnricher(rulesPath: yaraRulesPath)
        if await yaraEnricher.isAvailable() {
            logger.info("YARA enrichment enabled")
            print("YARA enrichment: active (\(yaraRulesPath))")
        }

        // Initialize network collector (Phase 3)
        let networkCollector = NetworkCollector()
        Task { await networkCollector.start() }
        print("Network connection collector active (5s poll)")

        Self.logBootStep(label: "before_load_rules", startedAt: startedAt)
        // Load compiled rules (single-event)
        // Check both the system dir and the binary-local dir; prefer whichever has more
        // JSON files (the one with more rules is fresher from a recent build or install).
        let binaryDir = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent().path
        let localCompiledRules = binaryDir + "/compiled_rules"
        let effectiveRulesDir: String
        do {
            let systemFiles = (try? fm.contentsOfDirectory(atPath: compiledRulesDir))?.filter { $0.hasSuffix(".json") } ?? []
            let localFiles: [String]
            if fm.fileExists(atPath: localCompiledRules) {
                localFiles = (try? fm.contentsOfDirectory(atPath: localCompiledRules))?.filter { $0.hasSuffix(".json") } ?? []
            } else {
                localFiles = []
            }
            if !localFiles.isEmpty && localFiles.count >= systemFiles.count {
                effectiveRulesDir = localCompiledRules
                print("Using local compiled rules: \(localCompiledRules) (\(localFiles.count) files, system has \(systemFiles.count))")
            } else if !systemFiles.isEmpty {
                effectiveRulesDir = compiledRulesDir
                print("Using system compiled rules: \(compiledRulesDir) (\(systemFiles.count) files)")
            } else if !localFiles.isEmpty {
                effectiveRulesDir = localCompiledRules
                print("Using local compiled rules: \(localCompiledRules) (\(localFiles.count) files)")
            } else {
                effectiveRulesDir = compiledRulesDir
            }
        }
        let rulesURL = URL(fileURLWithPath: effectiveRulesDir)
        do {
            let count = try await ruleEngine.loadRules(from: rulesURL)
            logger.info("Loaded \(count) single-event detection rules")
            print("Loaded \(count) single-event detection rules")
        } catch {
            logger.warning("No compiled rules found at \(compiledRulesDir). Run compile_rules.py first.")
            print("Warning: No compiled rules found. Run: python3 Compiler/compile_rules.py --input-dir Rules/ --output-dir '\(compiledRulesDir)'")
        }

        // v1.12.0: overlay user-customised rules from
        // /Library/Application Support/MacCrab/user_rules/*.json. These
        // load AFTER bundled rules, so a user file with the same rule id
        // replaces the bundled definition (RuleEngine.loadRules uses
        // allRules[rule.id] = rule — last write wins). The dashboard
        // writes user_rules from V2DetectionWorkspace's Edit panel; the
        // dir itself is created lazily on first edit (root:admin 0775)
        // via osascript so subsequent saves don't need elevation. A
        // mtime watcher on `<dir>/.reload_tick` (installed below) gives
        // live reload without admin per save.
        let userOverridesDir = supportDir + "/user_rules"
        let userOverridesURL = URL(fileURLWithPath: userOverridesDir)
        // v1.17.2 security: gate the override overlay on the SAME secure-dir
        // check as the primary rules path. The overlay can DISABLE detection
        // (lower severity / turn rules off), so loading it from a group- or
        // world-writable or symlinked dir would let a non-root admin tamper
        // with what the root sysext detects. isSecureDirectory now also rejects
        // group-writable, so a legacy root:admin 0775 user_rules dir is refused
        // here — re-create it root-owned 0755 (follow-up: route override writes
        // through the privileged inbox IPC instead of a shared-writable dir).
        if fm.fileExists(atPath: userOverridesDir), isSecureDirectory(userOverridesDir) {
            do {
                let userCount = try await ruleEngine.loadRules(from: userOverridesURL)
                if userCount > 0 {
                    logger.info("Loaded \(userCount) user rule override(s) from \(userOverridesDir)")
                    print("Loaded \(userCount) user rule override(s)")
                }
            } catch {
                logger.warning("user_rules overlay skipped: \(error.localizedDescription)")
            }
        }

        // Load sequence rules (use same effective dir as single-event rules)
        let sequenceRulesDir = effectiveRulesDir + "/sequences"
        try? FileManager.default.createDirectory(atPath: sequenceRulesDir, withIntermediateDirectories: true)
        do {
            let seqCount = try await sequenceEngine.loadRules(from: URL(fileURLWithPath: sequenceRulesDir))
            logger.info("Loaded \(seqCount) sequence detection rules")
            print("Loaded \(seqCount) sequence detection rules")
        } catch {
            logger.info("No sequence rules loaded (this is fine for initial setup)")
        }

        Self.writeBootPhase(supportDir: supportDir, phase: "rules_loaded", startedAt: startedAt)
        Self.logBootStep(label: "rules_loaded", startedAt: startedAt)

        // v1.12.0: user-rules live-reload watcher. Dashboard's Edit Rule
        // panel writes overrides into <userOverridesDir>/<uuid>.json then
        // touches <userOverridesDir>/.reload_tick. We poll the tick file's
        // mtime every 5 s and rebuild the rule index when it changes.
        // 5 s is well under the typical edit→test cycle while keeping the
        // cost trivial (one stat() per poll). Avoids per-save admin
        // prompts that a SIGHUP path would force.
        let userOverridesDirForWatcher = userOverridesDir
        let tickPath = userOverridesDirForWatcher + "/.reload_tick"
        let liveCompiledRulesURL = rulesURL
        Task.detached(priority: .utility) {
            var lastSeen: Date = (try? FileManager.default
                .attributesOfItem(atPath: tickPath))?[.modificationDate] as? Date ?? .distantPast
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 5 * 1_000_000_000)
                let mtime = (try? FileManager.default
                    .attributesOfItem(atPath: tickPath))?[.modificationDate] as? Date
                guard let mtime, mtime != lastSeen else { continue }
                lastSeen = mtime
                logger.notice("user_rules .reload_tick fired — reloading rules")
                do {
                    let baseCount = try await ruleEngine.reloadRules(from: liveCompiledRulesURL)
                    var total = baseCount
                    // v1.17.2 security: same gate as the initial load — only
                    // overlay overrides from a non-symlinked, root/owner-owned,
                    // non-group/world-writable dir. Inlined because the
                    // isSecureDirectory closure isn't in this detached Task's
                    // scope. An override that can be written by a non-root admin
                    // could silently disable detection.
                    if FileManager.default.fileExists(atPath: userOverridesDirForWatcher),
                       isOverlayDirSecure(userOverridesDirForWatcher) {
                        if let overlayed = try? await ruleEngine.loadRules(from: URL(fileURLWithPath: userOverridesDirForWatcher)) {
                            total += overlayed
                        }
                    }
                    logger.notice("Rules reloaded after user-rules tick: \(total) active rule(s)")
                } catch {
                    logger.warning("Reload after user-rules tick failed: \(error.localizedDescription)")
                }
            }
        }

        // Start TCC monitor (Phase 2: permission change detection)
        let tccMonitor = TCCMonitor()
        Task { await tccMonitor.start() }
        logger.info("TCC permission monitor active")

        // Start Unified Log collector (Phase 2: system log events)
        var ulCollector: UnifiedLogCollector? = nil
        do {
            ulCollector = try UnifiedLogCollector()
            logger.info("Unified Log collector active")
            print("Unified Log collector active (12 subsystems)")
        } catch {
            logger.warning("Failed to start Unified Log collector: \(error.localizedDescription)")
            print("Warning: Unified Log collector unavailable")
        }

        // Start ES collector (optional -- requires root + ES entitlement)
        // Falls back to eslogger proxy if entitlement is missing.
        var esloggerCollector: EsloggerCollector? = nil
        var kdebugCollector: KdebugCollector? = nil
        var esMode = "unavailable"

        if isRoot {
            do {
                collector = try ESCollector(subscribeFileOpen: config.subscribeFileOpenEvents,
                                            subscribeIntrospection: config.subscribeIntrospectionEvents)
                logger.info("ES collector started successfully (native client)")
                esMode = "native client"
            } catch {
                logger.warning("ES entitlement unavailable: \(error)")
                // Fallback: use eslogger proxy (same kernel events, no entitlement)
                if let preflightError = EsloggerCollector.preflightCheck() {
                    logger.warning("eslogger preflight failed: \(preflightError)")
                    print("  eslogger: \(preflightError)")
                } else if EsloggerCollector.isAvailable() {
                    esloggerCollector = EsloggerCollector()
                    await esloggerCollector!.start()
                    logger.info("eslogger proxy collector started")
                    esMode = "eslogger proxy"
                } else if KdebugCollector.isAvailable() {
                    // Third fallback: kdebug via fs_usage (root only, no entitlement, no FDA)
                    let kdebug = KdebugCollector()
                    await kdebug.start()
                    kdebugCollector = kdebug
                    logger.info("kdebug collector started via fs_usage")
                    esMode = "kdebug (fs_usage)"
                } else {
                    logger.warning("No kernel event source available")
                    print("  To enable: sign binary with ES entitlement, or install macOS 13+ for eslogger")
                }
            }
        } else {
            // Non-root: try eslogger (needs root but fail gracefully)
            if EsloggerCollector.isAvailable() {
                esloggerCollector = EsloggerCollector()
                await esloggerCollector!.start()
                esMode = "eslogger proxy (may need root)"
            }
        }
        print("Endpoint Security: \(esMode)")

        let startupMs = Double(DispatchTime.now().uptimeNanoseconds - startupBegin.uptimeNanoseconds) / 1_000_000
        print(String(format: "Startup complete in %.0fms", startupMs))

        // v1.12.0 — Bayesian intent posterior + LLM-backed package
        // classifier. The Bayesian engine is fed Evidence values from
        // EventLoop and emits a posterior over attacker Goals per
        // process tree. The IntentClassifier is held here as a shared
        // singleton (MCP handlers + future PackageScanner call into it)
        // and does NOT run automatically on every event — its LLM cost
        // makes it suitable only for explicit package-install signals.
        let bayesianIntent = BayesianIntentEngine()
        let intentClassifier = IntentClassifier(llmService: llmService)

        // v1.12.0 post-audit (M-Int1): PromptIntentBridge needs an
        // AgentLineageService snapshot provider. Build one here so we
        // can bind the closure to it; assign to state.agentLineageService
        // post-construction so EventLoop's record() calls land in the
        // same instance the bridge queries.
        let agentLineageService = AgentLineageService()
        let promptIntentBridge = PromptIntentBridge(snapshotProvider: { aiPid in
            await agentLineageService.snapshot(aiPid: aiPid)
        })

        let state = DaemonState(
            isRoot: isRoot,
            supportDir: supportDir,
            compiledRulesDir: compiledRulesDir,
            rulesDir: rulesDir,
            rulesURL: rulesURL,
            sequenceRulesDir: sequenceRulesDir,
            effectiveRulesDir: effectiveRulesDir,
            eventStore: eventStore,
            alertStore: alertStore,
            enricher: enricher,
            ruleEngine: ruleEngine,
            sequenceEngine: sequenceEngine,
            baselineEngine: baselineEngine,
            behaviorScoring: behaviorScoring,
            deduplicator: deduplicator,
            suppressionManager: suppressionManager,
            statisticalDetector: statisticalDetector,
            crossProcessCorrelator: crossProcessCorrelator,
            processTreeAnalyzer: processTreeAnalyzer,
            topologyAnomalyDetector: topologyAnomalyDetector,
            notifier: notifier,
            responseEngine: responseEngine,
            webhookOutput: webhookOutput,
            syslogOutput: syslogOutput,
            additionalOutputs: additionalOutputs,
            notificationIntegrations: notificationIntegrations,
            selfDefense: selfDefense,
            esHealthMonitor: esHealthMonitor,
            threatIntel: threatIntel,
            ctMonitor: ctMonitor,
            mispClient: mispClient,
            aiRegistry: aiRegistry,
            aiTracker: aiTracker,
            credentialFence: credentialFence,
            projectBoundary: projectBoundary,
            injectionScanner: injectionScanner,
            aiNetworkSandbox: aiNetworkSandbox,
            fileInjectionScanner: fileInjectionScanner,
            mcpAttributor: mcpAttributor,
            mcpBaseline: mcpBaseline,
            collectorRegistry: collectorRegistry,
            mcpMonitor: mcpMonitor,
            usbMonitor: usbMonitor,
            clipboardMonitor: clipboardMonitor,
            clipboardInjectionDetector: clipboardInjectionDetector,
            browserExtMonitor: browserExtMonitor,
            ultrasonicMonitor: ultrasonicMonitor,
            eventTapMonitor: eventTapMonitor,
            systemPolicyMonitor: systemPolicyMonitor,
            rootkitDetector: rootkitDetector,
            tccMonitor: tccMonitor,
            edrMonitor: edrMonitor,
            tempestMonitor: tempestMonitor,
            fsEventsCollector: fsEventsCollector,
            collector: collector,
            esloggerCollector: esloggerCollector,
            kdebugCollector: kdebugCollector,
            ulCollector: ulCollector,
            networkCollector: networkCollector,
            dnsCollector: dnsCollector,
            esMode: esMode,
            dohDetector: dohDetector,
            tlsFingerprinter: tlsFingerprinter,
            crashReportMiner: crashReportMiner,
            powerAnomalyDetector: powerAnomalyDetector,
            libraryInventory: libraryInventory,
            cdhashExtractor: cdhashExtractor,
            quarantineEnricher: quarantineEnricher,
            yaraEnricher: yaraEnricher,
            dbEncryption: dbEncryption,
            preventionEnabled: preventionEnabled,
            dnsSinkhole: dnsSinkhole,
            networkBlocker: networkBlocker,
            persistenceGuard: persistenceGuard,
            sandboxAnalyzer: sandboxAnalyzer,
            aiContainment: aiContainment,
            supplyChainGate: supplyChainGate,
            tccRevocation: tccRevocation,
            securityScorer: securityScorer,
            appPrivacyAuditor: appPrivacyAuditor,
            vulnScanner: vulnScanner,
            travelMode: travelMode,
            securityDigest: securityDigest,
            alertExporter: alertExporter,
            scheduledReports: scheduledReports,
            incidentGrouper: incidentGrouper,
            campaignDetector: campaignDetector,
            campaignStore: campaignStore,
            ruleGenerator: ruleGenerator,
            causalGraphBridge: causalGraphBridge,
            causalStore: causalStoreOuter,
            graphEvaluator: graphEvaluator,
            bayesianIntent: bayesianIntent,
            intentClassifier: intentClassifier,
            promptIntentBridge: promptIntentBridge,
            packageChecker: packageChecker,
            notarizationChecker: notarizationChecker,
            gitSecurityMonitor: gitSecurityMonitor,
            reportGenerator: reportGenerator,
            threatHunter: threatHunter,
            toolIntegrations: toolIntegrations,
            fleetClient: fleetClient,
            llmService: llmService,
            clickFix: clickFixDetector
        )

        // v1.6.21: wire AlertSink into ResponseEngine so the
        // requireConfirmation skip path emits a synthetic informational
        // alert visible to the operator. Pre-fix the gate logged silently.
        await state.responseEngine.setAlertSinkForPending(state.alertSink)

        // Apply v1.8.0 per-tier storage budgets. DaemonTimers reads each
        // knob live so a SIGHUP-driven config reload is honored on the
        // next sweep without a daemon restart. Floors clamp hostile
        // values:
        //   - eventsHotTierMinutes: 15 min minimum. The longest sequence
        //     rule (ransomware_kill_chain.yml) needs a 10-min window;
        //     anything shorter risks dropping events mid-sequence.
        //   - retention days: 1 day minimum
        //   - size caps: 50 MB minimum
        var storage = config.storage
        storage.eventsHotTierMinutes  = max(15, storage.eventsHotTierMinutes)
        storage.eventsMaxSizeMB       = max(50, storage.eventsMaxSizeMB)
        storage.aggregateDays         = max(1, storage.aggregateDays)
        storage.alertsRetentionDays   = max(1, storage.alertsRetentionDays)
        storage.alertsMaxSizeMB       = max(50, storage.alertsMaxSizeMB)
        storage.campaignsRetentionDays = max(1, storage.campaignsRetentionDays)
        storage.campaignsMaxSizeMB    = max(50, storage.campaignsMaxSizeMB)
        state.storage = storage

        // v1.12.0 post-audit (M-Cfg1): wire intent thresholds from
        // daemon_config.json onto DaemonState. Clamp to sane ranges
        // so an operator typo can't make every install fire (threshold
        // 0) or kill the rule (threshold > 1).
        state.intentPosteriorThreshold = max(0.5, min(1.0, config.intentPosteriorThreshold))
        state.intentPosteriorMinDistinctEvidence = max(1, min(10, config.intentPosteriorMinDistinctEvidence))

        // v1.12.0 post-audit (M-Int1): bind state.agentLineageService
        // to the SAME instance the PromptIntentBridge captured above.
        // Otherwise EventLoop.record() calls would write into one
        // instance and the bridge.snapshot() would query a different
        // one — every install would see an empty snapshot.
        state.agentLineageService = agentLineageService

        // v1.9 Agent Traces (PR-2): if the operator opted in via
        // MACCRAB_AGENT_TRACES=1, allocate a TraceRegistry and spawn
        // the consumer Task that drains ESCollector.traceBindings into
        // it. The collector emits bind/evict signals only when the
        // same env var is set, so an unconfigured daemon pays nothing.
        if ESCollector.isAgentTracesEnabled {
            let registry = TraceRegistry()
            state.traceRegistry = registry
            if let collector = collector {
                let bindings = collector.traceBindings
                Task.detached(priority: .utility) { [weak registry] in
                    for await signal in bindings {
                        guard let registry else { return }
                        switch signal.kind {
                        case let .bind(identity, context, agentTool):
                            await registry.bind(
                                TraceRegistry.Binding(
                                    identity: identity,
                                    context: context,
                                    agentTool: agentTool,
                                    boundAt: signal.timestamp
                                )
                            )
                        case let .evict(pid):
                            await registry.evict(pid: pid)
                        }
                    }
                }
            }
        }

        // v1.9 PR-4: optional OTLP receiver + TraceStore. Allocated only
        // when both feature flags are present. The receiver listens on
        // 127.0.0.1:4318 and writes ingested spans into traces.db.
        // Bind failure surfaces via os.log .error and the receiver
        // remains nil — the rest of the daemon keeps running. PR-5
        // wires a Settings-driven start/stop; PR-4 is env-only.
        // v1.9 Phase-3.4: receiver enable now comes from EITHER the
        // env var (legacy) OR the user's agent_traces_config.json.
        // SIGHUP triggers a reload via SignalHandlers.
        let otlpEnvFlag = Foundation.ProcessInfo.processInfo
            .environment["MACCRAB_OTLP_RECEIVER"] == "1"
        let cfg = AgentTracesConfigStore.loadEffective()
        let otlpEnabled = otlpEnvFlag || cfg.receiverEnabled

        if ESCollector.isAgentTracesEnabled, otlpEnabled {
            do {
                // v1.9 Phase-2.3: pass the daemon's DatabaseEncryption
                // through so attributes_json is encrypted at rest with
                // the same shared key as events.db / alerts.db.
                let traceStore = try TraceStore(
                    directory: supportDir,
                    encryption: dbEncryption
                )
                state.traceStore = traceStore
                let receiver = OTLPReceiver(
                    port: cfg.port,
                    traceStore: traceStore
                )
                try await receiver.start()
                state.otlpReceiver = receiver
                AgentTracesStatusStore.write(
                    AgentTracesStatus(running: true, port: cfg.port),
                    to: supportDir
                )
                Logger(subsystem: "com.maccrab.agentkit", category: "agent-traces")
                    .notice("OTLPReceiver started on 127.0.0.1:\(cfg.port, privacy: .public) — traces.db at \(supportDir, privacy: .public)/traces.db")
                print("[agent-traces] OTLPReceiver listening on 127.0.0.1:\(cfg.port) — traces.db at \(supportDir)/traces.db")
            } catch {
                Logger(subsystem: "com.maccrab.agentkit", category: "agent-traces")
                    .error("OTLPReceiver failed to start: \(String(describing: error), privacy: .public)")
                print("[agent-traces] OTLPReceiver FAILED to start: \(error)")
                AgentTracesStatusStore.write(
                    AgentTracesStatus(
                        running: false,
                        port: cfg.port,
                        lastError: "\(error)",
                        lastErrorAt: Date()
                    ),
                    to: supportDir
                )
                state.traceStore = nil
            }
        } else if cfg.receiverEnabled || otlpEnvFlag {
            // Operator wanted it on but agent-traces master flag is off.
            // Surface the disagreement.
            AgentTracesStatusStore.write(
                AgentTracesStatus(
                    running: false,
                    port: cfg.port,
                    lastError: "Receiver enabled but MACCRAB_AGENT_TRACES is not set",
                    lastErrorAt: Date()
                ),
                to: supportDir
            )
        } else {
            // Neither config nor env asks for it — record stopped.
            AgentTracesStatusStore.write(
                AgentTracesStatus(running: false, port: cfg.port),
                to: supportDir
            )
        }

        // v1.12.0 RC15: boot complete — write the final "ready" phase
        // so the dashboard flips its banner from "Daemon: Starting…" to
        // "Daemon: Running ✓". The livenessTimer in DaemonTimers takes
        // over from here with `liveness: true` writes every 30 s.
        Self.writeBootPhase(supportDir: supportDir, phase: "ready", startedAt: startedAt)
        Self.logBootStep(label: "ready", startedAt: startedAt)

        return state
    }

    // MARK: - Phase-3.4: SIGHUP receiver lifecycle

    /// Apply the latest agent_traces_config.json to a running daemon.
    /// Called from SignalHandlers' SIGHUP handler. Idempotent: a
    /// no-op transition (already-running with the same port) does
    /// nothing.
    public static func applyAgentTracesConfig(
        state: DaemonState,
        supportDir: String,
        dbEncryption: DatabaseEncryption
    ) async {
        let cfg = AgentTracesConfigStore.loadEffective()
        let envFlag = Foundation.ProcessInfo.processInfo
            .environment["MACCRAB_OTLP_RECEIVER"] == "1"
        let shouldRun = ESCollector.isAgentTracesEnabled && (cfg.receiverEnabled || envFlag)
        let logger = Logger(subsystem: "com.maccrab.agentkit", category: "agent-traces")

        // Already running — stop and restart only if port changed.
        if let existing = state.otlpReceiver {
            let existingPort = await existing.currentPort()
            if !shouldRun {
                await existing.stop()
                state.otlpReceiver = nil
                state.traceStore = nil
                AgentTracesStatusStore.write(
                    AgentTracesStatus(running: false, port: existingPort),
                    to: supportDir
                )
                logger.notice("OTLPReceiver stopped via SIGHUP reload")
                print("[agent-traces] OTLPReceiver stopped (SIGHUP)")
                return
            }
            if existingPort == cfg.port {
                return // no change
            }
            await existing.stop()
            state.otlpReceiver = nil
            // fall through to start on new port
        }

        guard shouldRun else { return }
        do {
            let traceStore = try TraceStore(
                directory: supportDir,
                encryption: dbEncryption
            )
            state.traceStore = traceStore
            let receiver = OTLPReceiver(port: cfg.port, traceStore: traceStore)
            try await receiver.start()
            state.otlpReceiver = receiver
            AgentTracesStatusStore.write(
                AgentTracesStatus(running: true, port: cfg.port),
                to: supportDir
            )
            logger.notice("OTLPReceiver started via SIGHUP on 127.0.0.1:\(cfg.port, privacy: .public)")
            print("[agent-traces] OTLPReceiver started (SIGHUP) on 127.0.0.1:\(cfg.port)")
        } catch {
            AgentTracesStatusStore.write(
                AgentTracesStatus(
                    running: false,
                    port: cfg.port,
                    lastError: "\(error)",
                    lastErrorAt: Date()
                ),
                to: supportDir
            )
            logger.error("OTLPReceiver SIGHUP start failed: \(String(describing: error), privacy: .public)")
            print("[agent-traces] OTLPReceiver SIGHUP start FAILED: \(error)")
            state.traceStore = nil
        }
    }

    // MARK: - Phase 7 output factory

    /// Convert a `DaemonConfig.OutputSpec` into a concrete `any Output`.
    /// Returns nil for malformed specs; each failure is logged.
    static func buildOutput(spec: DaemonConfig.OutputSpec, logger: os.Logger) -> (any Output)? {
        switch spec.type {
        case "file":
            guard let path = spec.path else {
                logger.warning("FileOutput spec missing 'path'")
                return nil
            }
            let format = FileOutput.Format(rawValue: spec.format ?? "ocsf") ?? .ocsf
            let maxBytes = Int64((spec.maxMb ?? 100) * 1024 * 1024)
            let maxAge = (spec.maxAgeHours ?? 24) * 3600
            let maxArch = spec.maxArchives ?? 10
            return FileOutput(
                path: path,
                format: format,
                maxBytes: maxBytes,
                maxAgeSeconds: maxAge,
                maxArchives: maxArch
            )

        case "splunk_hec", "elastic_bulk", "datadog_logs", "wazuh_api":
            guard let urlStr = spec.url, let url = URL(string: urlStr) else {
                logger.warning("StreamOutput spec missing valid 'url'")
                return nil
            }
            guard let kind = StreamOutput.Kind(rawValue: spec.type) else {
                return nil
            }
            let token = resolveToken(spec: spec)
            return StreamOutput(
                kind: kind,
                url: url,
                token: token,
                indexName: spec.indexName,
                retryCount: spec.retryCount ?? 2,
                timeout: spec.timeoutSeconds ?? 10
            )

        case "s3":
            guard let bucket = spec.bucket, let region = spec.region else {
                logger.warning("S3Output spec missing 'bucket' or 'region'")
                return nil
            }
            guard let accessKey = resolveEnv(spec.accessKeyEnv),
                  let secretKey = resolveEnv(spec.secretKeyEnv) else {
                logger.warning("S3Output spec missing accessKeyEnv/secretKeyEnv values in environment")
                return nil
            }
            let endpoint = spec.endpoint.flatMap { URL(string: $0) }
            return S3Output(
                bucket: bucket,
                region: region,
                accessKey: accessKey,
                secretKey: secretKey,
                keyPrefix: spec.keyPrefix ?? "maccrab/alerts",
                endpoint: endpoint,
                sessionToken: resolveEnv(spec.sessionTokenEnv),
                maxBatchBytes: spec.maxBatchBytes ?? 1_048_576
            )

        case "sftp":
            guard let host = spec.host, let user = spec.user,
                  let keyPath = spec.keyPath,
                  let remotePath = spec.remotePath else {
                logger.warning("SFTPOutput spec missing host/user/keyPath/remotePath")
                return nil
            }
            return SFTPOutput(
                host: host,
                port: spec.port ?? 22,
                user: user,
                privateKeyPath: keyPath,
                remotePath: remotePath,
                flushIntervalSeconds: spec.flushIntervalSeconds ?? 300
            )

        default:
            logger.warning("Unknown output type '\(spec.type)'")
            return nil
        }
    }

    /// Resolve an env-var reference to its value, returning nil if the
    /// env name is missing or the variable isn't set.
    private static func resolveEnv(_ name: String?) -> String? {
        guard let name, !name.isEmpty else { return nil }
        let value = Foundation.ProcessInfo.processInfo.environment[name]
        return (value?.isEmpty == false) ? value : nil
    }

    /// Prefer tokenEnv lookup over a literal token — keeps secrets out
    /// of the on-disk config file.
    private static func resolveToken(spec: DaemonConfig.OutputSpec) -> String? {
        if let envVar = spec.tokenEnv,
           let value = Foundation.ProcessInfo.processInfo.environment[envVar],
           !value.isEmpty {
            return value
        }
        return spec.token
    }
}

// MARK: - Orphan user-domain DB reaper (v1.6.14)

/// Rename any stale `~<user>/Library/Application Support/MacCrab/events.db*`
/// files left over from a pre-sysext dev daemon. Preserves forensic
/// evidence (no delete) and stops the dashboard's most-recent-mtime
/// picker from selecting the orphan over the authoritative sysext DB.
///
/// Only invoked when the sysext runs as root. A user-space dev daemon
/// legitimately writes to this path and must not reap its own DB.
///
/// Criteria for quarantine:
///   • `events.db` exists
///   • Not modified in the last 24h (live dev DB is untouched)
///   • Rename to `events.db.orphan-<YYYYMMDD-HHMMSS>` so a later sweep
///     can distinguish repeated quarantines.
///
/// v1.11.0 (audit functionality HIGH): read OS-notification config
/// from `alert_notifications.json`. SettingsView writes the file
/// from the dashboard's notification toggle + severity picker.
/// Defaults to (enabled=true, .high) when the file is absent or
/// malformed, matching the historical hardcoded behaviour.
///
/// **v1.11.0 RC2 ship-blocker fix:** the dashboard runs as the user
/// and writes to `~/Library/Application Support/MacCrab/`, but the
/// sysext runs as root and reads `<supportDir>` =
/// `/Library/Application Support/MacCrab/`. Pre-fix the dashboard's
/// writes never reached the daemon's reads in production deployments
/// (RC1 audit BLOCKER). Mirrors the `NotificationIntegrations`
/// system+user-walker pattern (`loadEffectiveConfig`): system path
/// first, then walk `/Users/*` for a UID-validated user-home copy,
/// pick the most-recently-modified non-nil candidate. Same UID-
/// validation discipline (the file's owner must match the home dir's
/// owner) so a rogue process running as a different user can't
/// inject a config.
///
/// File schema:
///   { "enabled": true | false,
///     "min_severity": "critical" | "high" | "medium" | "low" | "informational" }
/// (The pre-v1.17 "allow_critical" key is ignored if present — criticals
/// always notify at critical severity now.)
func loadAlertNotificationConfig(supportDir: String) -> (enabled: Bool, minSeverity: Severity) {
    let systemPath = supportDir + "/alert_notifications.json"
    let userPath = _findUserHomeAlertNotificationConfigPath()

    let fm = FileManager.default
    let systemMtime = (try? fm.attributesOfItem(atPath: systemPath))?[.modificationDate] as? Date
    let userMtime = userPath.flatMap {
        (try? fm.attributesOfItem(atPath: $0))?[.modificationDate] as? Date
    }

    func decode(at path: String) -> (enabled: Bool, minSeverity: Severity)? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return nil }
        let enabled = json["enabled"] as? Bool ?? true
        let raw = (json["min_severity"] as? String ?? "critical").lowercased()
        let sev: Severity = {
            switch raw {
            case "critical":      return .critical
            case "high":          return .high
            case "medium":        return .medium
            case "low":           return .low
            case "informational": return .informational
            default:              return .critical
            }
        }()
        return (enabled, sev)
    }

    let systemConfig = decode(at: systemPath)
    let userConfig = userPath.flatMap(decode)

    switch (systemConfig, userConfig) {
    case (nil, nil):
        return (true, .critical)
    case (let sc?, nil):
        return sc
    case (nil, let uc?):
        return uc
    case (let sc?, let uc?):
        let sm = systemMtime ?? .distantPast
        let um = userMtime ?? .distantPast
        return um > sm ? uc : sc
    }
}

/// Walk `/Users/*` for an `alert_notifications.json` owned by the
/// home's uid. Returns the most-recently-modified validated
/// candidate's path, or nil. Same shape as
/// `NotificationIntegrations.findUserHomeConfigPath` — kept as a
/// sibling helper rather than generalising because the cross-target
/// abstraction would have to thread through MacCrabCore and the
/// path string is the only difference.
private func _findUserHomeAlertNotificationConfigPath() -> String? {
    let fm = FileManager.default
    guard let users = try? fm.contentsOfDirectory(atPath: "/Users") else { return nil }
    struct Candidate { let path: String; let mtime: Date }
    var candidates: [Candidate] = []
    for user in users where user != "Shared" && !user.hasPrefix(".") {
        let home = "/Users/\(user)"
        let path = home + "/Library/Application Support/MacCrab/alert_notifications.json"
        guard fm.fileExists(atPath: path) else { continue }
        guard let homeAttrs = try? fm.attributesOfItem(atPath: home),
              let fileAttrs = try? fm.attributesOfItem(atPath: path) else { continue }
        let homeUID = (homeAttrs[.ownerAccountID] as? NSNumber)?.uint32Value ?? UInt32.max
        let fileUID = (fileAttrs[.ownerAccountID] as? NSNumber)?.uint32Value ?? UInt32.max
        guard homeUID == fileUID, homeUID != UInt32.max else { continue }
        let mtime = (fileAttrs[.modificationDate] as? Date) ?? .distantPast
        candidates.append(Candidate(path: path, mtime: mtime))
    }
    return candidates.max(by: { $0.mtime < $1.mtime })?.path
}

/// WAL/SHM sidecars are renamed alongside the main file. Failures
/// are logged but don't abort daemon startup — a leftover orphan is
/// cosmetic, not a safety issue.
func reapOrphanUserDomainDBs(logger: os.Logger) {
    let fm = FileManager.default
    // Enumerate each real (non-system) user's home directory and
    // check for the MacCrab support dir. In a single-user setup this
    // is usually just the console user, but on a multi-user box the
    // orphan could live in any home — /Users/* excluding Shared.
    guard let homes = try? fm.contentsOfDirectory(atPath: "/Users") else { return }
    let formatter = DateFormatter()
    formatter.dateFormat = "yyyyMMdd-HHmmss"
    let stamp = formatter.string(from: Date())

    for user in homes where user != "Shared" && !user.hasPrefix(".") {
        let dbPath = "/Users/\(user)/Library/Application Support/MacCrab/events.db"
        guard fm.fileExists(atPath: dbPath) else { continue }
        let attrs = try? fm.attributesOfItem(atPath: dbPath)
        guard let mtime = attrs?[.modificationDate] as? Date else { continue }
        let ageSeconds = Date().timeIntervalSince(mtime)
        guard ageSeconds > 86_400 else {
            logger.info("Orphan-DB check: /Users/\(user) events.db modified <24h ago, leaving alone")
            continue
        }
        let size = (attrs?[.size] as? UInt64) ?? 0
        let sizeMB = Int(size / 1_000_000)
        logger.warning("Orphan-DB reaper: quarantining /Users/\(user)/Library/Application Support/MacCrab/events.db (\(sizeMB) MB, \(Int(ageSeconds / 86400))d stale)")
        for suffix in ["", "-wal", "-shm"] {
            let src = dbPath + suffix
            let dst = dbPath + ".orphan-" + stamp + suffix
            guard fm.fileExists(atPath: src) else { continue }
            do {
                try fm.moveItem(atPath: src, toPath: dst)
            } catch {
                logger.warning("Orphan-DB reaper: rename \(src) → \(dst) failed: \(error.localizedDescription)")
            }
        }
    }
}

/// Secure-directory check for the user_rules override overlay, usable from
/// detached Tasks (the per-setup `isSecureDirectory` closure isn't in their
/// scope). Rejects symlinks and any group- or world-writable dir; requires
/// owner uid 0 or the current uid. Mirrors the inline gate in `start()`.
/// A rule-override overlay can DISABLE detection, so it must not be writable
/// by a non-root admin. Top-level free function (like the orphan reaper above)
/// so detached Tasks can call it without capturing the per-setup closure.
func isOverlayDirSecure(_ path: String) -> Bool {
    let fm = FileManager.default
    let url = URL(fileURLWithPath: path)
    if let rv = try? url.resourceValues(forKeys: [.isSymbolicLinkKey]), rv.isSymbolicLink == true {
        return false
    }
    guard let attrs = try? fm.attributesOfItem(atPath: path) else { return false }
    let ownerUID = (attrs[.ownerAccountID] as? NSNumber)?.uint32Value ?? UInt32.max
    guard ownerUID == 0 || ownerUID == getuid() else { return false }
    if let posix = (attrs[.posixPermissions] as? NSNumber)?.intValue, posix & 0o022 != 0 {
        return false
    }
    return true
}
