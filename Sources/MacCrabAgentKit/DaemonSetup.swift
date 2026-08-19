import Foundation
import Darwin
import MacCrabCore
import os.log

/// Immutable identity for one running daemon process. Captured once on first
/// bootstrap access and copied into both heartbeat files so measurement tooling
/// can reject deltas that cross a crash/restart epoch. Values are bundle/process
/// metadata only; no event content enters the heartbeat labels.
struct DaemonProcessIdentity: Sendable, Equatable {
    let pid: Int
    let startedAtUnix: Double
    let version: String
    let build: String

    static let current = DaemonProcessIdentity(
        pid: Int(ProcessInfo.processInfo.processIdentifier),
        startedAtUnix: Date().timeIntervalSince1970,
        version: MacCrabVersion.current,
        build: (Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String)
            .flatMap { $0.isEmpty ? nil : $0 } ?? "unknown"
    )
}

/// OS-notification toggle records contain only two scalar fields. This is an
/// internal constant so tests can pin the root/user read boundary without
/// exposing it as product API.
let maximumAlertNotificationConfigBytes = 64 * 1024

/// Creates and initializes all daemon components, returning a fully configured DaemonState.
enum DaemonSetup {

    private static let setupLogger = Logger(subsystem: "com.maccrab.agentkit", category: "daemon-setup")

    /// Decoy files belong to the console user. A privileged engine may load
    /// their bounded manifest for matching, but must never mutate that user's
    /// namespace. Kept as a pure policy seam for the root-boundary guard test.
    static func shouldAutoDeployDeception(effectiveUID: uid_t = geteuid()) -> Bool {
        effectiveUID != 0
    }

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
        let identity = DaemonProcessIdentity.current
        let payload: [String: Any] = [
            "started_at_unix": identity.startedAtUnix,
            "pid": identity.pid,
            "version": version,
            "build": identity.build,
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

    enum DatabaseQuarantineAuthorizationError: Error, LocalizedError {
        case missingSQLiteFailureDetails(database: String)
        case notExplicitCorruption(database: String, details: SQLiteFailureDetails)

        var errorDescription: String? {
            switch self {
            case .missingSQLiteFailureDetails(let database):
                return "Refusing to quarantine \(database): the failure has no structured SQLite result codes"
            case .notExplicitCorruption(let database, let details):
                return "Refusing to quarantine \(database): SQLite rc=\(details.resultCode), extended=\(details.extendedResultCode), system_errno=\(details.systemErrno) is not explicit CORRUPT/NOTADB"
            }
        }
    }

    /// The sole startup authorization boundary for moving a SQLite evidence
    /// family aside. Error strings are never classification input: only typed
    /// SQLITE_CORRUPT / SQLITE_NOTADB metadata permits quarantine. The shared
    /// helper moves DB/WAL/SHM/journal as one rollback-capable operation and
    /// throws before a fresh database can be created if any move fails.
    @discardableResult
    static func quarantineExplicitSQLiteCorruption(
        directory: String,
        base: String,
        error: Error,
        timestamp: Int? = nil,
        moveOperation: CorruptDBBackup.MoveOperation? = nil
    ) throws -> CorruptDBBackupResult {
        guard let details = SQLiteFailureClassifier.details(from: error) else {
            throw DatabaseQuarantineAuthorizationError
                .missingSQLiteFailureDetails(database: base)
        }
        guard SQLiteFailureClassifier.disposition(
            resultCode: details.resultCode,
            extendedResultCode: details.extendedResultCode
        ) == .quarantineExplicitCorruption else {
            throw DatabaseQuarantineAuthorizationError.notExplicitCorruption(
                database: base,
                details: details
            )
        }
        return try CorruptDBBackup.quarantineAtomically(
            directory: directory,
            base: base,
            keep: corruptBackupRetention,
            timestamp: timestamp,
            moveOperation: moveOperation
        )
    }

    /// How many distinct corruption events to retain per database. Each event
    /// drops up to four sibling files (db + -wal / -shm / -journal), all sharing
    /// one `corrupt-<unix-ts>` stamp; we keep the newest `N` stamps' worth.
    static let corruptBackupRetention = CorruptDBBackup.defaultRetention

    /// v1.21.4 (C-03): bound the `*.corrupt-<ts>` quarantine backups that
    /// startup and mid-run corruption-quarantine paths leave behind.
    /// Nothing pruned them, so a machine that repeatedly boots against a corrupt
    /// DB accumulated them without bound. Thin forwarder to the shared
    /// `CorruptDBBackup.prune` (see C-04); kept so the tracegraph-quarantine
    /// call site and the existing tests keep the `DaemonSetup.pruneCorruptBackups`
    /// entry point.
    static func pruneCorruptBackups(directory: String, base: String, keep: Int = corruptBackupRetention) {
        CorruptDBBackup.prune(directory: directory, base: base, keep: keep)
    }

    private static func failRequiredStoreRecovery(
        supportDir: String,
        database: String,
        originalError: String,
        action: String,
        logger: Logger
    ) -> Never {
        let message = "\(database) recovery stopped: \(action)"
        logger.fault("\(message, privacy: .public). Existing database family was not replaced.")
        writeCrashReport(
            supportDir: supportDir,
            error: originalError,
            action: action
        )
        fputs("FATAL: \(message)\n", stderr)
        exit(1)
    }

    /// Recover from EventStore init failure. Captures the original error,
    /// backs up the corrupt files, retries init from a clean slate. If the
    /// recovery itself fails, writes last_crash.json and exits — but
    /// only after giving the dashboard a chance to surface the failure.
    static func recoverEventStore(
        supportDir: String,
        storagePolicy: SQLitePersistentStorePolicy,
        logger: Logger,
        initialFailure: Error
    ) -> EventStore {
        // First, capture the original error with public privacy so the
        // log shows what's wrong instead of "<private>".
        // v1.12.0 RC27 audit fix (Stab-B1): replace the `try!` second-
        // probe with a graceful return path. The prior code assumed
        // "unreachable" but a race or transient I/O hiccup between
        // the first failure and the second probe would crash the
        // daemon hard instead of running through the backup-and-retry
        // recovery path below.
        let retryFailure: Error
        do {
            let store = try EventStore(
                directory: supportDir,
                storagePolicy: storagePolicy,
                liveMemoryBudget: .processShared
            )
            // First attempt actually succeeded (transient failure
            // resolved itself). Return immediately; skip backup.
            logger.warning("EventStore: first init failed but a probe re-init succeeded — transient error; skipping backup")
            return store
        } catch {
            retryFailure = error
        }
        let originalError = "initial: \(initialFailure.localizedDescription) — \(initialFailure); retry: \(retryFailure.localizedDescription) — \(retryFailure)"
        do {
            try quarantineExplicitSQLiteCorruption(
                directory: supportDir,
                base: "events.db",
                error: retryFailure
            )
        } catch let authorization as DatabaseQuarantineAuthorizationError {
            failRequiredStoreRecovery(
                supportDir: supportDir,
                database: "EventStore",
                originalError: originalError,
                action: authorization.localizedDescription,
                logger: logger
            )
        } catch {
            failRequiredStoreRecovery(
                supportDir: supportDir,
                database: "EventStore",
                originalError: originalError,
                action: "atomic corruption quarantine failed: \(error.localizedDescription)",
                logger: logger
            )
        }
        logger.error("EventStore init failed with explicit SQLite corruption: \(originalError, privacy: .public). Atomic database-family quarantine succeeded; retrying with a fresh database.")
        do {
            return try EventStore(
                directory: supportDir,
                storagePolicy: storagePolicy,
                liveMemoryBudget: .processShared
            )
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
    static func recoverAlertStore(
        supportDir: String,
        storagePolicy: SQLitePersistentStorePolicy,
        logger: Logger,
        initialFailure: Error
    ) -> AlertStore {
        // v1.12.0 RC27 audit fix (Stab-B1): same pattern as recoverEventStore.
        let retryFailure: Error
        do {
            let store = try AlertStore(
                directory: supportDir,
                storagePolicy: storagePolicy
            )
            logger.warning("AlertStore: first init failed but a probe re-init succeeded — transient error; skipping backup")
            return store
        } catch {
            retryFailure = error
        }
        let originalError = "initial: \(initialFailure.localizedDescription) — \(initialFailure); retry: \(retryFailure.localizedDescription) — \(retryFailure)"
        do {
            try quarantineExplicitSQLiteCorruption(
                directory: supportDir,
                base: "alerts.db",
                error: retryFailure
            )
        } catch let authorization as DatabaseQuarantineAuthorizationError {
            failRequiredStoreRecovery(
                supportDir: supportDir,
                database: "AlertStore",
                originalError: originalError,
                action: authorization.localizedDescription,
                logger: logger
            )
        } catch {
            failRequiredStoreRecovery(
                supportDir: supportDir,
                database: "AlertStore",
                originalError: originalError,
                action: "atomic corruption quarantine failed: \(error.localizedDescription)",
                logger: logger
            )
        }
        logger.error("AlertStore init failed with explicit SQLite corruption: \(originalError, privacy: .public). Atomic database-family quarantine succeeded; retrying with a fresh database.")
        do {
            return try AlertStore(
                directory: supportDir,
                storagePolicy: storagePolicy
            )
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
    static func writeBootPhase(
        supportDir: String,
        phase: String,
        startedAt: Date
    ) {
        let identity = DaemonProcessIdentity.current
        let payload: [String: Any] = [
            "written_at_unix": Date().timeIntervalSince1970,
            "started_at_unix": startedAt.timeIntervalSince1970,
            "engine_pid": identity.pid,
            "engine_started_at_unix": identity.startedAtUnix,
            "engine_version": identity.version,
            "engine_build": identity.build,
            "uptime_seconds": Int(Date().timeIntervalSince(startedAt)),
            "boot_phase": phase,
            "liveness": false,
            // Independent schema from heartbeat_rich.json (which is at v5 with the
            // prevention block). This boot-phase liveness payload is intentionally
            // thinner; the dashboard reads schema_version informationally only.
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

    static func initialize() async throws -> DaemonState {
        let startupBegin = DispatchTime.now()
        let startedAt = Date()
        let startupWorkLifecycle = DaemonTimerLifecycle(
            maximumInFlightHandlers: 32
        )

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

        // v1.21.6 re-audit: automatic root cleanup of a user-domain DB is
        // retired. A user controls every ancestor below their home and could
        // replace the MacCrab directory with a symlink to the authoritative
        // system support directory; a path-based root rename would then move
        // live evidence. Cleanup must be an explicit user-context operation.

        // Load daemon configuration (optional JSON file with tuning overrides)
        let config = DaemonConfig.load(from: supportDir)
        // One clamped boot snapshot feeds BOTH buffer construction and the
        // TraceGraph hot-path storage admission below. Re-deriving selected
        // fields at each reader is how prior config fixes drifted.
        let bootStorage = config.storage.clampedToSafeFloors()
        // One policy value per persistent SQLite family. These exact values
        // must flow through startup migration, primary open, recovery probes,
        // and retry opens; falling back to store defaults at any one of those
        // sites silently defeats the operator's configured hard cap.
        let eventRelocationStoragePolicy = SQLitePersistentStorePolicy(
            maxFootprintBytes: SQLitePersistentStorePolicy.capBytes(
                // Startup must be safe before the legacy evidence table can be
                // measured. Retain the complete bounded transition reserve,
                // then narrow it immediately after EventStore opens.
                maxSizeMiB: bootStorage.effectiveEventsFamilyMaxSizeMB(
                    appliedLegacyEvidenceTransitionReserveMiB:
                        bootStorage.evidenceMaxSizeMB
                )
            ),
            freeSpaceFloorBytes: SQLitePersistentStorePolicy.freeSpaceFloorBytes,
            transactionReserveBytes: SQLitePersistentStorePolicy
                .eventTransactionReserveBytes,
            storageVolumePath: supportDir
        )
        let alertStoragePolicy = SQLitePersistentStorePolicy(
            maxFootprintBytes: AlertStore.combinedFamilyCapBytes(
                alertsMaxSizeMiB: bootStorage.alertsMaxSizeMB,
                evidenceMaxSizeMiB: bootStorage.evidenceMaxSizeMB
            ),
            freeSpaceFloorBytes: SQLitePersistentStorePolicy.freeSpaceFloorBytes,
            storageVolumePath: supportDir
        )
        let campaignStoragePolicy = SQLitePersistentStorePolicy(
            maxFootprintBytes: SQLitePersistentStorePolicy.capBytes(
                maxSizeMiB: bootStorage.campaignsMaxSizeMB
            ),
            freeSpaceFloorBytes: SQLitePersistentStorePolicy.freeSpaceFloorBytes,
            storageVolumePath: supportDir
        )

        // v1.19 (S1-T6): apply the self-test honeyfile-noise suppression flag
        // once at startup (config OR env). OFF in prod; the must-fire
        // `honeyfile_accessed` rule is unaffected.
        NoiseFilter.selfTestNoiseSuppressionEnabled = config.suppressSelftestNoise
            || ProcessInfo.processInfo.environment["MACCRAB_SUPPRESS_SELFTEST_NOISE"] == "1"

        // v1.21.4 (F2/A3): apply the split merged-stream buffer depths from
        // config before the streams are built in runEventLoop. Floored at 1000
        // so a fat-fingered tiny value can't make the pipeline drop everything.
        DaemonState.priorityStreamCap = bootStorage.mergedPriorityStreamCap
        DaemonState.fileStreamCap = bootStorage.mergedFileStreamCap

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
        // rwxr-xr-x (0o755): the non-root MacCrab.app (uid 501) reads
        // <support>/compiled_rules for rule display + integrity hashing
        // (AppState), so the dir must stay world-traversable / files world-
        // readable. Tradeoff: detection logic is world-READABLE — a minor
        // evasion-recon surface, accepted for the app read path. Do NOT set
        // 0o700 here: that breaks the app's read path (the v1.11.0 RC2 class
        // of "audit-driven tightening silently breaks the user-context read").
        // A future hardening could narrow to 0o750 root:admin IF every uid-501
        // reader is confirmed in the admin group — verify the read path first.
        try? fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: compiledRulesDir)

        // Refresh the installed corpus from the signed, sysextd-staged System
        // Extension before constructing any rule reader. This replaces the GUI
        // app's launch-time `osascript with administrator privileges` copy,
        // which produced a password dialog on every app update and trusted an
        // app-controlled path across a root boundary. The synchronizer verifies
        // the designated Developer ID requirement + resource seal in production,
        // then publishes an exact manifest-verified tree with an atomic swap.
        // Standalone/dev maccrabd runs deliberately skip this bundle-only path.
        let ruleSyncObservation = BundledRuleSynchronizer.synchronizeAtBoot(
            supportDirectory: supportDir
        )
        let ruleSyncOutcome = ruleSyncObservation.outcome
        if BundledRuleSynchronizer.shouldAbortBoot(after: ruleSyncOutcome) {
            let reason: String
            if case .failed(let detail, _, _, _) = ruleSyncOutcome {
                reason = detail
            } else {
                reason = "installed rule corpus is not verified"
            }
            logger.fault("Aborting before rule readers: no verified installed corpus after sync failure: \(reason, privacy: .public)")
            print("FATAL: detection rules could not be verified; engine stopped before loading rules.")
            writeBootPhase(
                supportDir: supportDir,
                phase: "rule_sync_failed",
                startedAt: startedAt
            )
            Darwin.exit(EXIT_FAILURE)
        }

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
        // v1.8.0 storage split: relocate `alerts` from events.db -> alerts.db
        // before either long-lived store opens. Idempotent — no-op once
        // migrated. Both raw migration connections use the same configured
        // family policies as the stores they precede.
        AlertsTableRelocator.relocate(
            directory: supportDir,
            eventStoragePolicy: eventRelocationStoragePolicy,
            alertStoragePolicy: alertStoragePolicy,
            logger: logger
        )

        // Establish the legacy-evidence reserve before EventStore performs its
        // first rc.13 schema/journal mutation. The probe uses the trusted Core
        // SQLite open path and may write only a fully admitted TRUNCATE
        // checkpoint. A pin or unprovable measurement stops boot as
        // storage_not_ready; it must never silently grant the old full reserve.
        let legacyEvidenceTransitionBudget = LegacyEvidenceTransitionBudget(
            storageConfig: bootStorage
        )
        let legacyEvidenceCapBytes = SQLitePersistentStorePolicy.capBytes(
            maxSizeMiB: bootStorage.evidenceMaxSizeMB
        )
        let legacyEvidenceTicket = legacyEvidenceTransitionBudget
            .measurementTicket()
        let legacyEvidenceMeasurement: LegacyAlertEvidenceTransitionMeasurement
        do {
            legacyEvidenceMeasurement = try EventStore
                .preopenLegacyAlertEvidenceTransitionMeasurement(
                    path: supportDir + "/events.db",
                    maxBytes: legacyEvidenceCapBytes,
                    checkpointPolicy: eventRelocationStoragePolicy
                )
        } catch {
            try DaemonBootstrap.failPreIngestionStorage(
                supportDir: supportDir,
                startedAt: startedAt,
                component: "EventStore",
                reason: "pre-open legacy-evidence measurement failed: \(error.localizedDescription)"
            )
        }
        var transition = legacyEvidenceTransitionBudget.update(
            measurement: legacyEvidenceMeasurement,
            ticket: legacyEvidenceTicket
        )
        // v1.21.6-rc.37: these three conditions are NOT equally fatal.
        //
        // `measurementFailed` and an undrained WAL are genuine unknown-state
        // cases: we cannot reason about the store, so refusing to start is
        // correct. A reserve that does not fit the hard boundary is different —
        // it means the retained family has outgrown the transition headroom,
        // which is a CAPACITY condition that retention is designed to relieve.
        //
        // Treating it as fatal created an unrecoverable loop. Retention,
        // checkpointing and compaction all run only AFTER a successful boot, so
        // a store that is merely too large can never be reduced: the engine
        // exits, sysextd relaunches it ~10s later, and it exits again. An
        // installed host logged 55 such relaunches in 90 minutes with protection
        // entirely off and no operator-free way back — the machine was
        // indistinguishable from "installed and healthy" to everything except
        // `maccrabctl status`.
        //
        // Booting with the already-proven applied reserve and letting the
        // ordinary retention path shrink the family is strictly better: the
        // engine protects the machine while it recovers, instead of protecting
        // nothing while it cannot.
        let bootDecision = transition.bootDecision
        if case .fail(let reason) = bootDecision {
            try DaemonBootstrap.failPreIngestionStorage(
                supportDir: supportDir,
                startedAt: startedAt,
                component: "EventStore",
                reason: reason
            )
        }
        if case .degrade(let reserve, let reason) = bootDecision {
            logger.fault(
                "Legacy-evidence transition degraded: \(reason, privacy: .public). Booting with the applied \(reserve) MiB reserve so retention can reduce the family. Detection and alerting start normally; retained event history may be trimmed."
            )
        }
        let policyReserve = bootDecision.reserveMiB
            ?? transition.appliedReserveMiB
        let measuredEventsFamilyCap = bootStorage
            .effectiveEventsFamilyMaxSizeMB(
                appliedLegacyEvidenceTransitionReserveMiB: policyReserve
            )
        let eventStoragePolicy = SQLitePersistentStorePolicy(
            maxFootprintBytes: SQLitePersistentStorePolicy.capBytes(
                maxSizeMiB: measuredEventsFamilyCap
            ),
            freeSpaceFloorBytes: SQLitePersistentStorePolicy
                .freeSpaceFloorBytes,
            transactionReserveBytes: SQLitePersistentStorePolicy
                .eventTransactionReserveBytes,
            storageVolumePath: supportDir
        )

        do {
            eventStore = try EventStore(
                directory: supportDir,
                storagePolicy: eventStoragePolicy,
                liveMemoryBudget: .processShared
            )
        } catch let error as EventStoreError {
            if case .storageNotReady(_) = error {
                try DaemonBootstrap.failPreIngestionStorage(
                    supportDir: supportDir,
                    startedAt: startedAt,
                    component: "EventStore",
                    reason: error.localizedDescription
                )
            }
            eventStore = Self.recoverEventStore(
                supportDir: supportDir,
                storagePolicy: eventStoragePolicy,
                logger: logger,
                initialFailure: error
            )
        } catch {
            eventStore = Self.recoverEventStore(
                supportDir: supportDir,
                storagePolicy: eventStoragePolicy,
                logger: logger,
                initialFailure: error
            )
        }
        if transition.pendingReserveFitsHardBoundary == true,
           let pending = transition.pendingReserveMiB {
            transition = legacyEvidenceTransitionBudget.commitPendingReserve(
                pending,
                ticket: legacyEvidenceTicket
            )
        }
        let liveCap = bootStorage.effectiveEventsFamilyMaxSizeMB(
            appliedLegacyEvidenceTransitionReserveMiB:
                transition.appliedReserveMiB
        )
        logger.notice("events.db upgrade budget established before journal transition: steady-state=\(bootStorage.effectiveEventsFamilyMaxSizeMB) MiB, applied legacy reserve=\(transition.appliedReserveMiB) MiB, live cap=\(liveCap) MiB, legacy rows=\(transition.rowCount ?? -1), WAL drained=\(transition.walCheckpointDrained ?? false)")

        do {
            alertStore = try AlertStore(
                directory: supportDir,
                storagePolicy: alertStoragePolicy
            )
        } catch {
            alertStore = Self.recoverAlertStore(
                supportDir: supportDir,
                storagePolicy: alertStoragePolicy,
                logger: logger,
                initialFailure: error
            )
        }

        // Recover and prove both primary persistence families before the first
        // collector/monitor is constructed or started. Several later
        // constructors activate their own bounded streams (Unified Log and
        // native ES), while fallback collectors, MCP/DNS/FSEvents, Fleet, and
        // OTLP explicitly start inside this function. A Bootstrap-only barrier
        // is therefore too late: those local buffers can fill and count drops
        // during a long inherited-family recovery.
        let eventRetentionBudgetHealth = EventRetentionBudgetHealth()
        let eventStartupBoundary = EventsSizeCapBoundary(
            maxSizeMiB: bootStorage.effectiveEventsFamilyMaxSizeMB(
                appliedLegacyEvidenceTransitionReserveMiB:
                    transition.appliedReserveMiB
            )
        )
        // The rc.12 wide table is the only source of truth until its rows are
        // checksummed into the rc.13 journal. Generic size-cap recovery may
        // prune non-process rows, so journal transcode/integrity/schema parity
        // must complete first, while the measured transition reserve is still
        // active and before any collector can produce a new Event.
        let journalRecovery: EventStore.EventJournalRecoverySnapshot
        do {
            journalRecovery = try await
                retryTransientEventStoreStartupOperation(
                    onRetry: { _ in
                        Self.writeBootPhase(
                            supportDir: supportDir,
                            phase: "starting",
                            startedAt: startedAt
                        )
                    },
                    operation: {
                        try await eventStore.recoverJournalBeforeProducers()
                    }
                )
        } catch {
            try DaemonBootstrap.failPreIngestionStorage(
                supportDir: supportDir,
                startedAt: startedAt,
                component: "EventStore",
                reason: "event journal pre-producer recovery failed: \(error.localizedDescription)"
            )
        }
        guard journalRecovery.complete,
              journalRecovery.remainingEvents == 0 else {
            try DaemonBootstrap.failPreIngestionStorage(
                supportDir: supportDir,
                startedAt: startedAt,
                component: "EventStore",
                reason: "event journal migration did not conserve to a complete boundary (source=\(journalRecovery.sourceEvents), migrated=\(journalRecovery.migratedEvents), expired=\(journalRecovery.rolledExpiredEvents), corrupt_preserved=\(journalRecovery.corruptPreservedEvents), remaining=\(journalRecovery.remainingEvents))"
            )
        }
        logger.notice("EventStore journal migration and integrity proved before generic cap recovery: source=\(journalRecovery.sourceEvents), migrated=\(journalRecovery.migratedEvents), expired=\(journalRecovery.rolledExpiredEvents), corrupt_preserved=\(journalRecovery.corruptPreservedEvents)")
        do {
            var expired = 0
            var batches = 0
            while true {
                let batch = try await
                    retryTransientEventStoreStartupOperation(
                        onRetry: { _ in
                            Self.writeBootPhase(
                                supportDir: supportDir,
                                phase: "starting",
                                startedAt: startedAt
                            )
                        },
                        operation: {
                            try await eventStore.expireJournalBlocks(
                                retainedThrough: Date(),
                                maximumBlocks: 1_024
                            )
                        }
                )
                expired += batch
                if batch == 0 { break }
                batches += 1
                if batches.isMultiple(of: 64) {
                    Self.writeBootPhase(
                        supportDir: supportDir,
                        phase: "starting",
                        startedAt: startedAt
                    )
                }
                await Task.yield()
            }
            if expired > 0 {
                logger.notice("EventStore expired and aggregate-rolled \(expired) authenticated journal events before generic cap recovery")
            }
        } catch {
            try DaemonBootstrap.failPreIngestionStorage(
                supportDir: supportDir,
                startedAt: startedAt,
                component: "EventStore",
                reason: "event journal expiry/rollup failed before producers: \(error.localizedDescription)"
            )
        }
        let eventStartupRecovery = await recoverEventStoreBeforeProducers(
            eventStore: eventStore,
            dbPath: supportDir + "/events.db",
            boundary: eventStartupBoundary,
            processFloorMinutes: bootStorage.processEventsFloorMinutes,
            retentionBudgetHealth: eventRetentionBudgetHealth,
            onTransientPinRetry: { _ in
                Self.writeBootPhase(
                    supportDir: supportDir,
                    phase: "starting",
                    startedAt: startedAt
                )
            }
        )
        guard eventStartupRecovery.writableBeforeProducers else {
            let detail = [
                "passes=\(eventStartupRecovery.passes)",
                "last_footprint=\(eventStartupRecovery.lastFootprintBytes ?? -1)",
                "probe_error=\(eventStartupRecovery.lastProbeError ?? "none")",
                "reason=\(eventStartupRecovery.reason)",
                "15-minute forensic floor preserved",
            ].joined(separator: ", ")
            try DaemonBootstrap.failPreIngestionStorage(
                supportDir: supportDir,
                startedAt: startedAt,
                component: "EventStore",
                reason: detail
            )
        }
        eventRetentionBudgetHealth.recordSweep(
            observedFootprintBytes:
                eventStartupRecovery.lastFootprintBytes,
            boundary: eventStartupBoundary
        )
        logger.notice("EventStore ordinary priority+file admission proved before collector construction after \(eventStartupRecovery.passes) bounded pass(es); footprint=\(eventStartupRecovery.lastFootprintBytes ?? -1), file_boundary=\(eventStartupBoundary.fileLaneAdmissionBoundaryBytes), target=\(eventStartupBoundary.targetBytes)")

        let alertStartupBoundary = AlertsSizeCapBoundary(
            nominalCapBytes: alertStoragePolicy.maxFootprintBytes,
            transactionReserveBytes:
                alertStoragePolicy.transactionReserveBytes
        )
        let alertStartupRecovery = await recoverAlertStoreBeforeProducers(
            alertStore: alertStore,
            dbPath: supportDir + "/alerts.db",
            alertCapBytes: SQLitePersistentStorePolicy.capBytes(
                maxSizeMiB: bootStorage.alertsMaxSizeMB
            ),
            evidenceCapBytes: legacyEvidenceCapBytes,
            boundary: alertStartupBoundary
        )
        guard alertStartupRecovery.writableBeforeProducers else {
            let detail = [
                "passes=\(alertStartupRecovery.passes)",
                "last_footprint=\(alertStartupRecovery.lastFootprintBytes ?? -1)",
                "probe_error=\(alertStartupRecovery.lastProbeError ?? "none")",
                "reason=\(alertStartupRecovery.reason)",
            ].joined(separator: ", ")
            try DaemonBootstrap.failPreIngestionStorage(
                supportDir: supportDir,
                startedAt: startedAt,
                component: "AlertStore",
                reason: detail
            )
        }
        logger.notice("AlertStore ordinary admission proved before collector construction after \(alertStartupRecovery.passes) bounded pass(es); footprint=\(alertStartupRecovery.lastFootprintBytes ?? -1), boundary=\(alertStartupBoundary.hardAdmissionBoundaryBytes), target=\(alertStartupBoundary.recoveryTargetBytes)")

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

        // Deception tier (opt-in). User-run maccrabctl plants the canaries; the
        // engine loads their bounded manifests and exposes an isHoneyfile()
        // lookup the enricher uses to tag file events touching a canary.
        //
        // v1.21.6 (audit DET-02): the gate was env-var-ONLY. sysextd launches the
        // System Extension, so an operator has no supported way to set that
        // variable — the tier (and with it the must-fire `honeyfile_accessed`
        // rule) was dead on every release install. Read `deception_enabled` from
        // daemon_config.json as well, mirroring the ultrasonic gate below.
        let honeyfileManager: HoneyfileManager?
        let honeyPromptManager: HoneyPromptManager?
        let deceptionStartupWork: (@Sendable () async -> Void)?
        if config.deceptionEnabled || ProcessInfo.processInfo.environment["MACCRAB_DECEPTION"] == "1" {
            let mgr = HoneyfileManager()
            honeyfileManager = mgr
            // v1.12.0 — pair the credential-shape bait (HoneyfileManager) with
            // AI-agent-context bait (HoneyPromptManager). Both deploy under
            // the same env-var gate so the operator's mental model stays
            // "deception on" / "deception off".
            let promptMgr = HoneyPromptManager()
            honeyPromptManager = promptMgr
            if !Self.shouldAutoDeployDeception() {
                // The System Extension runs as root while these decoys and
                // their manifests live below a user-controlled home. Root must
                // never create directories, age files, replace manifests, or
                // remove entries through that namespace: even no-follow leaf
                // opens leave intermediate-parent and follow-up path races.
                // Deployment/removal is therefore an explicit maccrabctl action
                // performed as the owning console user. The root engine only
                // loads the bounded manifest and activates event enrichment.
                logger.info("Deception detection enabled; decoy deployment is delegated to user-run maccrabctl")
                deceptionStartupWork = nil
            } else {
                deceptionStartupWork = {
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
            }
        } else {
            honeyfileManager = nil
            honeyPromptManager = nil
            deceptionStartupWork = nil
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
            captureEnv: captureEnv,
            telemetryGapSignal: TelemetryGapProbe(read: { collector?.esGlobalDropped() ?? 0 }).signal
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
        let responseEngine = ResponseEngine(supportDirectory: supportDir)

        Self.logBootStep(label: "after_response_engine", startedAt: startedAt)
        // Construct now; MonitorTasks starts and owns this only after
        // DaemonState/AlertSink exist, so there is one alert chokepoint and one
        // joinable shutdown owner.
        let selfDefense = SelfDefense(dataDir: supportDir, rulesDir: compiledRulesDir)
        Self.logBootStep(label: "after_self_defense", startedAt: startedAt)

        // ES infrastructure health monitor.
        // v1.12.0 RC21 (TURBO): both await calls (start + currentStatus)
        // talk to xprotectd / syspolicyd / endpointsecurityd via private
        // OS APIs and can each block several seconds on a cold launch
        // (system services may be mid-init themselves). The status is
        // purely informational. MonitorTasks owns the deferred probe, event
        // consumer, producer stop, and task join.
        let esHealthMonitor = ESClientMonitor(pollInterval: config.esHealthPollInterval)
        Self.logBootStep(label: "after_es_health", startedAt: startedAt)

        // Threat intelligence feed. v1.12.0 RC16 (TURBO): construct
        // the actor immediately (cheap), but defer the `.start()`
        // refresh loop AND the bundled IOC load to a background Task.
        // Rules referencing threat-intel run against an empty index
        // for the first ~1-2 s of daemon life, then populate as the
        // background load completes — a tiny window of missed lookup
        // for a multi-second startup win.
        let threatIntel = ThreatIntelFeed(cacheDir: supportDir + "/threat_intel")
        // v1.19.1: the abuse.ch network refresh is opt-in (off by default).
        // Local hydration + bundled IOCs still load; only the outbound fetch is
        // gated. Capture a Sendable Bool for the detached task.
        let threatIntelNetworkEnabled = config.threatIntelEnabled
        let threatIntelStartupWork: @Sendable () async -> Void = {
            let started = await threatIntel.start(
                networkRefresh: threatIntelNetworkEnabled
            )
            guard started, !Task.isCancelled else { return }
            await BundledThreatIntel.loadInto(threatIntel)
            guard !Task.isCancelled else { return }
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
            print("Threat intel: bundled IOCs loaded; abuse.ch network refresh \(threatIntelNetworkEnabled ? "ENABLED" : "OFF by default (opt-in)")")
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
            campaignStore = try CampaignStore(
                directory: supportDir,
                storagePolicy: campaignStoragePolicy
            )
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
        // Build the ONE process-wide DatabaseEncryption here so it can
        // be passed into SQLiteCausalGraphStore. Pre-fix the store
        // was instantiated without the encryption param, and the
        // encryption object used to be constructed again below —
        // tracegraph.db's `attributes_json`, `evidence_json`,
        // `summary_json`, `attack_json`, `policy_snapshot_json`
        // were written plaintext on disk despite the v1.9
        // "AES-GCM at rest" invariant. A single instance is also
        // security-critical: if Keychain access changes during boot,
        // constructing twice could give two stores different keys. An
        // unavailable persistent key disables encrypted evidence stores;
        // no ephemeral-key ciphertext is ever written.
        let encryptDbEnv = Foundation.ProcessInfo.processInfo.environment["MACCRAB_ENCRYPT_DB"]
        let dbEncryptionEnabled = (encryptDbEnv != "0")
        let dbEncryption = DatabaseEncryption(enabled: dbEncryptionEnabled)

        let causalGraphBridge: EventToRollingCausalGraphBridge?
        // Hoisted out of the do-block so the daily retention timer in
        // DaemonTimers can call prune / size-cap on the same store.
        let causalStoreOuter: SQLiteCausalGraphStore?
        var causalStoreStartupRecovery: CausalGraphStartupRecoveryResult
        // v1.12.0 RC25 audit fix (Int-H3): retry with backup on corrupt
        // tracegraph.db. EventStore + AlertStore have recovery paths
        // (lines 73-122); SQLiteCausalGraphStore previously had none.
        // With this fix a 7GB corrupt tracegraph gets quarantined and
        // the daemon continues with a fresh empty store — the rest of
        // detection keeps working.
        func openCausalStore() async -> (
            store: SQLiteCausalGraphStore?,
            startupAdmission: TraceGraphStartupAdmissionStatus?
        ) {
            let dbPath = supportDir + "/tracegraph.db"
            let tracegraphCapBytes = TraceGraphStoragePolicy.capBytes(
                maxSizeMiB: bootStorage.tracegraphMaxSizeMB)
            guard !dbEncryption.encryptionWasRequested || dbEncryption.isEnabled else {
                logger.fault("TraceGraph disabled: persistent DB-encryption key is unavailable (OSStatus \(dbEncryption.keyPersistenceFailureStatus ?? -1, privacy: .public)); preserving the existing store and refusing plaintext/ephemeral-key writes")
                return (nil, nil)
            }
            let storeEncryption = dbEncryption.isEnabled ? dbEncryption : nil
            do {
                let store = try await SQLiteCausalGraphStore(
                    databasePath: dbPath,
                    encryption: storeEncryption,
                    maxFootprintBytes: tracegraphCapBytes,
                    freeSpaceFloorBytes: TraceGraphStoragePolicy.freeSpaceFloorBytes,
                    storageVolumePath: supportDir
                )
                return (store, nil)
            } catch let admission as CausalGraphStorageAdmissionError {
                // A pre-migration max_page_count/low-disk failure is storage
                // pressure, not corruption. Never quarantine evidence for it;
                // keep the rest of detection online. Retain the typed reason so
                // the heartbeat/status/dashboard report a forensic-evidence gap
                // instead of the misleading generic `enabled: false` state.
                logger.fault("TraceGraph init paused by storage admission: \(admission.localizedDescription, privacy: .public). Existing tracegraph.db is preserved; trace materialization is disabled this run.")
                return (
                    nil,
                    TraceGraphStartupAdmissionStatus(
                        error: admission,
                        configuredMaxFootprintBytes: tracegraphCapBytes,
                        configuredFreeSpaceFloorBytes: TraceGraphStoragePolicy.freeSpaceFloorBytes
                    )
                )
            } catch {
                do {
                    try quarantineExplicitSQLiteCorruption(
                        directory: supportDir,
                        base: "tracegraph.db",
                        error: error
                    )
                } catch let authorization as DatabaseQuarantineAuthorizationError {
                    logger.fault("TraceGraph init failed without explicit SQLite corruption: \(authorization.localizedDescription, privacy: .public). Existing DB/WAL/SHM are preserved; trace materialization is disabled this run.")
                    return (nil, nil)
                } catch {
                    // Family-level rollback is attempted inside
                    // quarantineAtomically. Never retry against a newly-created
                    // database after a partial/failed evidence move.
                    logger.fault("TraceGraph atomic corruption quarantine failed: \(error.localizedDescription, privacy: .public). Existing DB/WAL/SHM were not deliberately replaced; trace materialization is disabled this run.")
                    return (nil, nil)
                }
                logger.error("TraceGraph init reported explicit SQLite corruption. Atomic database-family quarantine succeeded; retrying with a fresh tracegraph.db.")
                do {
                    let store = try await SQLiteCausalGraphStore(
                        databasePath: dbPath,
                        encryption: storeEncryption,
                        maxFootprintBytes: tracegraphCapBytes,
                        freeSpaceFloorBytes: TraceGraphStoragePolicy.freeSpaceFloorBytes,
                        storageVolumePath: supportDir
                    )
                    return (store, nil)
                } catch let admission as CausalGraphStorageAdmissionError {
                    logger.fault("TraceGraph retry paused by storage admission: \(admission.localizedDescription, privacy: .public). Trace materialization is disabled this run.")
                    return (
                        nil,
                        TraceGraphStartupAdmissionStatus(
                            error: admission,
                            configuredMaxFootprintBytes: tracegraphCapBytes,
                            configuredFreeSpaceFloorBytes: TraceGraphStoragePolicy.freeSpaceFloorBytes
                        )
                    )
                } catch {
                    logger.error("TraceGraph retry failed: \(error.localizedDescription, privacy: .public) — trace materialization is disabled this run")
                    return (nil, nil)
                }
            }
        }
        let causalStoreOpen = await openCausalStore()
        let causalStoreStartupAdmission = causalStoreOpen.startupAdmission
        if let causalStore = causalStoreOpen.store {
            // rc.11 can restart with no in-memory latch while the inherited
            // family is already at the proactive boundary. Recover here—not in
            // DaemonBootstrap—because every collector-local producer below
            // this point owns a bounded buffer that can fill/drop before the
            // merged EventLoop drivers attach. Success requires strict durable
            // headroom; the one-hour evidence floor is never crossed.
            let days = max(1, min(bootStorage.tracegraphRetentionDays, 3_650))
            let recovery = await causalStore.recoverStorageBeforeProducers(
                configuredRetentionHours: days * 24,
                cutoffRungs: DaemonTimers.tracegraphRecoveryCutoffHours,
                now: Date(),
                maximumPasses:
                    DaemonTimers.tracegraphStartupRecoveryMaximumPasses
            )
            guard recovery.writableBeforeProducers else {
                let admission = recovery.finalAdmission
                let disposition: String
                switch recovery.disposition {
                case .writable:
                    disposition = "inconsistent writable result"
                case .nonconverged(let reason):
                    disposition = reason.rawValue
                }
                let detail = [
                    "result=\(disposition)",
                    "passes=\(recovery.passes)",
                    "cutoffs=\(recovery.attemptedCutoffHours)",
                    "block=\(admission?.reason?.rawValue ?? "unavailable")",
                    "footprint=\(admission?.footprintBytes ?? -1)",
                    "target=\(admission?.resumeBelowBytes ?? -1)",
                    "detail=\(recovery.failureDetail ?? "none")",
                    "one-hour evidence floor preserved",
                ].joined(separator: ", ")
                try DaemonBootstrap.failPreIngestionStorage(
                    supportDir: supportDir,
                    startedAt: startedAt,
                    component: "TraceGraph",
                    reason: detail
                )
            }
            causalStoreStartupRecovery = recovery
            if recovery.normalWriteAdmissionRestored {
                logger.notice("TraceGraph startup recovery restored normal writable admission before collector construction after \(recovery.passes) bounded pass(es); cutoffs=\(recovery.attemptedCutoffHours)")
            } else if recovery.passes > 0 {
                logger.notice("TraceGraph startup recovery established durable headroom before collector construction in \(recovery.passes) bounded pass(es); cutoffs=\(recovery.attemptedCutoffHours)")
            } else {
                logger.info("TraceGraph startup admission confirmed below its proactive boundary before collector construction")
            }
            let materializer = TraceMaterializer(
                store: causalStore,
                daemonVersion: MacCrabVersion.current,
                rulesetVersion: MacCrabVersion.current
            )
            let rollingGraph = RollingCausalGraph(
                store: causalStore,
                materializer: materializer,
                // One event previously meant one SQLite transaction even when
                // hundreds of adjacent observations rewrote the same process /
                // file / edge rows. Novel anchors still force a synchronous
                // flush before materialization; non-anchor substrate writes are
                // coalesced behind strict time/event/row bounds.
                ingestionWritePolicy: .daemonCoalesced
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
            // v1.21.6-rc.36: DEGRADE, do not abort.
            //
            // This branch used to call failPreIngestionStorage, which writes
            // boot_phase=storage_not_ready and throws before any producer
            // starts — killing the whole daemon and leaving launchd to relaunch
            // it into the same failure forever, with no consecutive-failure
            // backoff anywhere in Sources.
            //
            // That is disproportionate and contradicts this code's own intent:
            // every non-corruption exit in openCausalStore logs "trace
            // materialization is disabled this run", i.e. it expects to degrade.
            // The key wired at the call below column-encrypts ONLY the trace and
            // causal-graph stores, so a Keychain or admission failure here kills
            // an engine whose events.db and alerts.db are entirely healthy —
            // trading all endpoint detection for one optional feature.
            //
            // The genuinely fail-closed case (writable convergence could not be
            // restored, above) still aborts. This one does not.
            let unavailable = CausalGraphStartupRecoveryResult.unavailable(
                reason: causalStoreStartupAdmission?.reason,
                detail: "TraceGraph store actor could not open before collector construction"
            )
            logger.fault(
                "TraceGraph unavailable: \(unavailable.failureDetail ?? "store unavailable", privacy: .public). Trace materialization is disabled this run; event detection, alerting and storage continue unaffected."
            )
            causalGraphBridge = nil
            causalStoreOuter = nil
            // Required now that this branch falls through instead of throwing:
            // the compiler previously proved the variable was only read on the
            // success path. Recording the unavailable result also keeps the
            // typed startup status flowing to the heartbeat, so a degraded run
            // is observable rather than merely quiet.
            causalStoreStartupRecovery = unavailable
        }

        // FINAL_PRE_INGESTION_STORAGE_ACTIVATION_BOUNDARY
        // Recovery above can be lengthy, and shared free space or SQLite
        // sidecars can change again while the remaining actors are built. Take
        // a no-maintenance, exact admission snapshot at the actual activation
        // edge. EventStore/AlertStore install their fresh ordinary-write probes
        // at this same marker; keep the graph reprobe last so no background
        // submission or collector can race the retained proof.
        let eventActivationProof: EventStoreActivationProof
        do {
            eventActivationProof = try await
                reprobeEventStoreAtActivationBoundary(
                    eventStore: eventStore,
                    dbPath: supportDir + "/events.db",
                    boundary: eventStartupBoundary,
                    retentionBudgetHealth: eventRetentionBudgetHealth
                )
        } catch {
            try DaemonBootstrap.failPreIngestionStorage(
                supportDir: supportDir,
                startedAt: startedAt,
                component: "EventStore",
                reason: "activation-boundary priority+file reprobe failed: \(error.localizedDescription)"
            )
        }
        logger.notice("EventStore activation-boundary proof refreshed immediately before producers; footprint=\(eventActivationProof.footprintBytes), target=\(eventStartupBoundary.targetBytes)")

        let alertActivationProof: AlertStoreActivationProof
        do {
            alertActivationProof = try await
                reprobeAlertStoreAtActivationBoundary(
                    alertStore: alertStore,
                    dbPath: supportDir + "/alerts.db",
                    boundary: alertStartupBoundary
                )
        } catch {
            try DaemonBootstrap.failPreIngestionStorage(
                supportDir: supportDir,
                startedAt: startedAt,
                component: "AlertStore",
                reason: "activation-boundary ordinary reprobe failed: \(error.localizedDescription)"
            )
        }
        logger.notice("AlertStore activation-boundary proof refreshed immediately before producers; footprint=\(alertActivationProof.footprintBytes), target=\(alertStartupBoundary.recoveryTargetBytes)")

        // rc.36: the activation-boundary proof only applies when TraceGraph is
        // actually running. When the store is unavailable this run, materialization
        // is already disabled and there is nothing to prove writable — so this
        // whole section is skipped rather than aborting a daemon whose events.db
        // and alerts.db are healthy. Previously the `guard let` below turned an
        // optional-feature outage into a permanent boot failure, defeating the
        // degrade decided above.
        if let activationCausalStore = causalStoreOuter {
            let activationAdmission = await activationCausalStore.storageAdmissionStatus()
            let activationProof = causalStoreStartupRecovery.refreshed(
                finalAdmission: activationAdmission
            )
            guard activationProof.writableBeforeProducers else {
                let detail = [
                    "activation-boundary reprobe failed",
                    "block=\(activationAdmission.reason?.rawValue ?? "none")",
                    "footprint=\(activationAdmission.footprintBytes ?? -1)",
                    "target=\(activationAdmission.resumeBelowBytes ?? -1)",
                    "deficit=\(activationAdmission.recoveryDeficitBytes ?? -1)",
                    "one-hour evidence floor preserved",
                ].joined(separator: ", ")
                try DaemonBootstrap.failPreIngestionStorage(
                    supportDir: supportDir,
                    startedAt: startedAt,
                    component: "TraceGraph",
                    reason: detail
                )
            }
            causalStoreStartupRecovery = activationProof
        } else {
            logger.warning(
                "TraceGraph activation-boundary proof skipped: materialization is disabled this run. Event detection, alerting and storage are unaffected."
            )
        }

        if let deceptionStartupWork {
            startupWorkLifecycle.submit(
                label: "deception-deploy",
                operation: deceptionStartupWork
            )
        }
        startupWorkLifecycle.submit(
            label: "threat-intel-hydration",
            operation: threatIntelStartupWork
        )

        // F-04: the daemon defaults to the "stable" rule profile — only the
        // curated stable tier ships enabled; "all" (daemon_config.json
        // rule_profile) restores every non-deprecated rule. Operator per-rule
        // overlays (user_rules, loaded below) are unaffected by the profile.
        // v1.21.5: resolved ONCE here, above the graph evaluator, because the
        // profile now gates all three rule families (single-event, sequence,
        // graph) — sequence + graph rules previously bypassed it entirely.
        // The mapping + corr-detection #273 unknown-value validation live in
        // DaemonConfig.enabledRuleStatuses (shared with the SIGHUP reload path).
        let ruleStatuses = DaemonConfig.enabledRuleStatuses(forProfile: config.ruleProfile)

        // v1.12.0 — load graph rules from `<support-dir>/compiled_rules/graph`
        // (release builds) or `Rules/graph` (dev builds). Each rule is a
        // JSON file describing a multi-entity pattern that fires only
        // when a materialized Trace contains a matching constellation of
        // entities + edges. The evaluator runs in EventLoop right after
        // `EventToRollingCausalGraphBridge.process` returns its [Trace],
        // so every materialized trace gets one pass of graph rules.
        // Skipped when causalStoreOuter is nil — without traces there's
        // nothing to evaluate against.
        // v1.21.5: gated by the rule profile. All 7 shipped graph rules are
        // curated `status: stable`, so default behavior is unchanged; a rule
        // file without the key is grandfathered as stable by the loader.
        let graphEvaluator: GraphRuleEvaluator?
        if causalStoreOuter != nil {
            let compiledGraphDir = URL(fileURLWithPath: supportDir + "/compiled_rules/graph")
            var loaded = GraphRuleLoader.loadRules(from: compiledGraphDir, enabledStatuses: ruleStatuses)
            if loaded.isEmpty {
                // Dev fallback: pick up rules straight from the source tree.
                let cwd = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
                loaded = GraphRuleLoader.loadFromProjectSource(projectRoot: cwd, enabledStatuses: ruleStatuses)
            }
            if loaded.isEmpty {
                logger.info("TraceGraph rule evaluator: no graph rules found — multi-entity detection disabled this run")
                graphEvaluator = nil
            } else {
                graphEvaluator = GraphRuleEvaluator(rules: loaded)
                logger.info("TraceGraph rule evaluator: loaded \(loaded.count) graph rules (rule_profile: \(config.ruleProfile))")
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
        let scannerStatus = "active (native)"
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
        // `expectsContinuousTraffic`: the unified log and DNS see traffic on any
        // active Mac, so prolonged silence means the sensor is dead rather than
        // idle. Both shipped broken and reported healthy for months precisely
        // because event-driven collectors were exempt from any liveness check.
        await collectorRegistry.register(
            name: "UnifiedLogCollector", expectedIntervalSeconds: 30,
            eventDriven: true, expectsContinuousTraffic: true)
        await collectorRegistry.register(
            name: "DNSCollector", expectedIntervalSeconds: 30,
            eventDriven: true, expectsContinuousTraffic: true)
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
        await collectorRegistry.register(name: "SDRDeviceMonitor", expectedIntervalSeconds: 60, eventDriven: true)
        await collectorRegistry.register(name: "BTMSnapshotMonitor", expectedIntervalSeconds: 300, eventDriven: true)
        print("Collector registry initialized — 17 collectors tracked")

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
        if dbEncryption.isEnabled {
            // v1.21.4 (audit A4-01): be precise about scope. This AES-GCM key
            // (in Keychain) column-encrypts only the trace + causal-graph stores
            // (TraceStore / SQLiteCausalGraphStore). The primary event / alert /
            // campaign stores (incl. alert_evidence) are NOT yet encrypted at
            // rest — that work is scheduled, not shipped.
            print("Database encryption: trace + causal-graph stores column-encrypted (AES-GCM, key in Keychain); event/alert/campaign stores not yet encrypted at rest (scheduled)")
        } else if dbEncryption.encryptionWasRequested {
            print("Database encryption: persistent Keychain key UNAVAILABLE (OSStatus \(dbEncryption.keyPersistenceFailureStatus ?? -1)); trace + causal-graph stores are disabled to prevent plaintext or ephemeral-key writes")
        } else {
            print("Database encryption: disabled via MACCRAB_ENCRYPT_DB=0 (trace + causal-graph stores plaintext; event/alert/campaign stores are not encrypted at rest either)")
        }

        // Report generator -- HTML incident reports
        let reportGenerator = ReportGenerator()

        // Clipboard monitor -- detects sensitive data and injection on clipboard.
        // v1.12.0 RC21 (TURBO): polled monitor, defer .start().
        // v1.18: ClickFix detector, SHARED with the event loop via DaemonState.
        // The monitor records delivery-shaped clipboard payloads (curl|bash, etc.);
        // the exec path correlates a subsequent shell/Terminal exec against them.
        let clickFixDetector = ClickFixDetector()

        // v1.21.4: per-user entity behaviour analytics. OFF unless the operator
        // opts in via `ueba_enabled`. Persistence has an explicit readiness
        // boundary: a corrupt/unreadable prior model disables UEBA for this boot
        // instead of racing new observations and later overwriting the evidence.
        // Periodic maintenance and the central finalizer own subsequent saves.
        let uebaPersistencePath = supportDir + "/ueba_profiles.json"
        let uebaEngine: UEBAEngine?
        var uebaLoadFailed = false
        if config.uebaEnabled {
            let candidate = UEBAEngine(persistencePath: uebaPersistencePath)
            if await candidate.loadPersistedProfiles() {
                uebaEngine = candidate
                print("UEBA enabled — bounded per-user behavioural baselining active (silent for first 100 obs/user)")
            } else {
                uebaEngine = nil
                uebaLoadFailed = true
                logger.fault("UEBA disabled for this boot because its persisted model failed validation: \(uebaPersistencePath, privacy: .public)")
                print("WARNING: UEBA is disabled for this boot; its persisted model is unreadable or invalid and was preserved for recovery")
            }
        } else {
            uebaEngine = nil
        }

        let clipboardMonitor = ClipboardMonitor(pollInterval: config.clipboardPollInterval, clickFix: clickFixDetector)
        let clipboardInjectionDetector = ClipboardInjectionDetector()

        // Browser extension monitor -- scans Chrome/Firefox/Brave/Edge/Arc.
        // v1.12.0 RC21 (TURBO): startup scans 5 browser profile dirs +
        // enumerates each extension manifest — disk-heavy. Defer.
        let browserExtMonitor = BrowserExtensionMonitor(pollInterval: config.browserExtensionPollInterval)

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
        // Unconditionally active since v1.21.6: the scanner is now pure native
        // structural analysis (invisible unicode / bidi overrides / tag-char
        // smuggling) with no external CLI to probe for.
        let fileInjectionScanner = FileInjectionScanner()
        print("File injection scanner active (native structural detection)")

        // Natural language threat hunter
        let threatHunter = ThreatHunter(
            eventsDatabasePath: supportDir + "/events.db",
            alertsDatabasePath: supportDir + "/alerts.db"
        )

        // Auto rule generator -- creates Sigma rules from observed campaigns
        let ruleGenerator = RuleGenerator(outputDir: supportDir + "/compiled_rules")

        // Rootkit detector — dual-API cross-reference of process tables.
        // v1.12.0 RC21 (TURBO): polled (120 s default) — defer .start().
        let rootkitDetector = RootkitDetector(pollInterval: config.rootkitPollInterval)

        // EDR/RMM tool monitor — scans for EDR, insider threat, MDM, and remote access tools.
        // v1.12.0 RC21 (TURBO): scans for 30+ tool signatures = disk +
        // code-signing churn. This was flagged by the RC18 perf agent;
        // already deferred for SecurityToolIntegrations, but EDRMonitor
        // is a SEPARATE actor doing similar work. Defer.
        let edrMonitor = EDRMonitor(pollInterval: 120)

        // SDR device + display-hotplug monitor (USB SDR enumeration + display
        // hotplug anomalies; no electromagnetic analysis).
        let sdrDeviceMonitor = SDRDeviceMonitor(pollInterval: 60)

        // BTM / SMAppService reconciliation monitor (read-only `sfltool dumpbtm`
        // snapshot; flags newly-seen enabled launch items with weak attribution —
        // the ghost-login-item persistence the real-time ES BTM sensor missed
        // because it predates this session or was added while ES was offline).
        let btmSnapshotMonitor = BTMSnapshotMonitor(pollInterval: config.btmPollInterval)

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
            if let data = BoundedRegularFileReader.read(
                   at: configPath,
                   maximumBytes: DaemonConfig.maximumConfigurationBytes
               ),
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

        // Retired API shell retained for state/source compatibility. Credential
        // reads remain detected; same-uid process blocking is not available.
        let aiContainment = AIContainment()

        // Supply Chain Gate -- kill installers of fresh packages
        let supplyChainGate = SupplyChainGate()

        // TCC Revocation -- auto-revoke permissions for unsigned apps
        let tccRevocation = TCCRevocation()

        if preventionEnabled {
            // The abuse.ch / threat-intel feeds drive the DNS sinkhole + PF
            // blocklist directly. Transport is already the hardened
            // SecureURLSession (TLS 1.2 floor + SSRF-redirect re-validation), and
            // DNSSinkhole/NetworkBlocker already exclude critical/protected
            // domains + IPs (Apple/OCSP/resolvers/RFC1918/gateway) so a poisoned
            // feed can't sever the host's own connectivity. These public feeds
            // can't be practically SPKI-pinned or content-signed, so add the
            // remaining guardrail: a sane per-refresh ceiling. A legitimate feed
            // set stays well under this; exceeding it is itself a poisoning /
            // MITM signal, so refuse to enforce that refresh (keeping the prior
            // smaller set) and log it. Detection/alerting still sees the IOCs —
            // this bounds ENFORCEMENT blast radius only.
            //
            // Content-integrity follow-up (tracked): a signed feed channel
            // (Ed25519, like the rave catalog / rules channels) would let us
            // authenticate abuse.ch content rather than sanity-bounding it.
            let maxFeedEnforcedDomains = 100_000
            let maxFeedEnforcedIPs = 100_000

            // Register threat intel update callback to populate prevention modules
            // `refreshFromFeed`, NOT `enable`: this callback fires on every feed
            // refresh and previously called `enable(...)` unconditionally, with
            // no consultation of the per-module toggle. A user who switched the
            // DNS sinkhole or network blocker off in the Prevention workspace
            // got a UI that said "off" while the daemon re-armed enforcement on
            // the next refresh — the user's *disable* silently ignored, with
            // unexpected DNS/PF blocking as the visible result.
            // `refreshFromFeed` honours the operator disable latch that
            // `disable()` sets; an explicit re-enable clears it.
            await threatIntel.onUpdate { [dnsSinkhole, networkBlocker, maxFeedEnforcedDomains, maxFeedEnforcedIPs] ips, domains in
                if domains.count > maxFeedEnforcedDomains {
                    print("Prevention: refusing to sinkhole \(domains.count) feed domains — exceeds \(maxFeedEnforcedDomains) sanity cap (possible feed poisoning); enforcement skipped this refresh")
                } else {
                    await dnsSinkhole.refreshFromFeed(domains: domains)
                }
                if ips.count > maxFeedEnforcedIPs {
                    print("Prevention: refusing to PF-block \(ips.count) feed IPs — exceeds \(maxFeedEnforcedIPs) sanity cap (possible feed poisoning); enforcement skipped this refresh")
                } else {
                    await networkBlocker.refreshFromFeed(ips: ips)
                }
            }

            // Initial population from any cached threat intel
            let cachedIPs = await threatIntel.maliciousIPSet()
            let cachedDomains = await threatIntel.maliciousDomainSet()
            if !cachedDomains.isEmpty {
                if cachedDomains.count > maxFeedEnforcedDomains {
                    print("Prevention: refusing to sinkhole \(cachedDomains.count) cached feed domains — exceeds \(maxFeedEnforcedDomains) sanity cap (possible feed poisoning); initial enforcement skipped")
                } else {
                    await dnsSinkhole.enable(domains: cachedDomains)
                }
            }
            if !cachedIPs.isEmpty {
                if cachedIPs.count > maxFeedEnforcedIPs {
                    print("Prevention: refusing to PF-block \(cachedIPs.count) cached feed IPs — exceeds \(maxFeedEnforcedIPs) sanity cap (possible feed poisoning); initial enforcement skipped")
                } else {
                    await networkBlocker.enable(ips: cachedIPs)
                }
            }

            // Lock persistence directories
            await persistenceGuard.enable()

            // Enable supply chain gate
            await supplyChainGate.enable()

            // Enable TCC auto-revocation
            await tccRevocation.enable()

            print("Prevention layer: ACTIVE (DNS sinkhole, PF blocker, persistence guard, supply chain gate, TCC revocation)")
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
        startupWorkLifecycle.submit(label: "initial-security-score") {
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
        startupWorkLifecycle.submit(label: "misp-hydration") {
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
        startupWorkLifecycle.submit(label: "security-tool-inventory") {
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
        print("Package freshness checker ready (npm, PyPI, Homebrew, Cargo) — registry lookups \(config.packageFreshnessEnabled ? "ENABLED" : "OFF by default (opt-in)")")

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
        // v1.21.5: fleet is outbound-only. Fleet-sourced IOCs must never
        // enter local threat intel — the prototype collector trusts
        // self-reported hostIds behind one shared bearer key, so a single
        // keyholder could feed poisoned "fleet-wide" IOCs to every endpoint.
        let fleetClient = FleetClient()
        if let fleet = fleetClient {
            if await fleet.start() {
                print("Fleet client active")
            } else {
                print("Warning: fleet client could not start")
            }
        } else if ProcessInfo.processInfo.environment["MACCRAB_FLEET_URL"] != nil {
            // v1.21.5: surface the transport refusal on stdout too — the
            // os.log warning inside FleetClient.init is easy to miss, and an
            // operator who set the env var deserves a loud answer at boot.
            print("Warning: MACCRAB_FLEET_URL refused: use https://, or http:// to a loopback host — fleet telemetry disabled")
        }

        // === LLM REASONING BACKEND (optional) ===
        // Config sources (in priority order): explicit env override > shared
        // Keychain secrets > non-secret llm_config.json > daemon_config.json.
        let llmService: LLMService? = await {
            var llmConfig = config.llm

            // Read and upgrade-scrub the root-owned, dashboard-bridged JSON.
            // API keys are never accepted from this file; old plaintext fields
            // are removed through a verified no-follow file descriptor at this
            // owner-context startup boundary.
            let llmConfigPath = supportDir + "/llm_config.json"
            if let json = try? LLMConfigFile.loadAndScrub(
                atPath: llmConfigPath,
                legacySecretMigration: .sharedKeychain(interaction: .disallowed),
                onScrubFailure: { error in
                    print("LLM config: legacy-secret scrub failed: \(error)")
                }
            ) {
                let trustedOllamaBaseline = llmConfig.ollamaURL
                LLMConfigFile.applyNonSecretValues(json, to: &llmConfig)
                // A URL that arrived over the uid-501 inbox is not a trusted
                // local endpoint. Keep sanitization enabled unless it exactly
                // matches the root-owned daemon-config baseline.
                if let value = json["ollama_url"] as? String,
                   value != trustedOllamaBaseline {
                    llmConfig.trustLocalEndpoint = false
                }
            }

            // Persistent provider credentials come only from the shared
            // Keychain. The sysext is background/root, so never allow an
            // authentication prompt; a denied/locked slot leaves that provider
            // unavailable without blocking engine startup.
            LLMSecretLoader.applyKeychainSecrets(
                to: &llmConfig,
                interaction: .disallowed,
                onError: { key, error in
                    print("LLM Keychain: \(key.displayName) unavailable: \(error)")
                }
            )

            // Env vars override everything (backward compatibility and an
            // explicit operator-controlled ephemeral override).
            let env = ProcessInfo.processInfo.environment
            LLMSecretLoader.applyEnvironmentOverrides(
                env,
                to: &llmConfig,
                trustEnvironmentOllamaURL: true
            )

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
        // RuleGenerator is constructed earlier with the deterministic engines.
        // Complete the optional dependency explicitly now; otherwise the
        // production "enhanced" path silently remains deterministic forever.
        // EventLoop invokes it only through the bounded advisory lifecycle.
        await ruleGenerator.configureLLMService(llmService)

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

        // Phase-5 delivery-provenance weld — enrichment on firing cred/exfil
        // alerts only (joins the quarantine GUID + Chromium referrer). Emits no
        // alerts of its own.
        let deliveryProvenanceWeld = DeliveryProvenanceWeld(
            source: QuarantineProvenanceSource(quarantine: quarantineEnricher)
        )

        // Phase-5 injection-evidence weld — retro-scans a firing agent-attributed
        // cred-read / read->egress trigger's session for a prior poisoned
        // agent-content read. Reads the session index (eventStore) and re-reads
        // file content on demand (fileContentEnricher). Enrichment-only.
        let injectionEvidenceWeld = InjectionEvidenceWeld(
            source: EventStoreInjectionSource(eventStore: eventStore, fileContent: fileContentEnricher)
        )

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
        let baselineEngine = BaselineEngine(
            persistPath: supportDir + "/baseline.json"
        )
        startupWorkLifecycle.submit(label: "baseline-hydration") {
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
            // F-04 stable-profile gate — `ruleStatuses` is resolved once above
            // the graph evaluator (v1.21.5), including the corr-detection #273
            // unknown-value validation, via DaemonConfig.enabledRuleStatuses.
            let count = try await ruleEngine.loadRules(from: rulesURL, enabledStatuses: ruleStatuses)
            logger.info("Loaded \(count) single-event detection rules (rule_profile: \(config.ruleProfile))")
            print("Loaded \(count) single-event detection rules (rule_profile: \(config.ruleProfile))")
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
                // v1.19.1 (audit): also gate per-FILE ownership — only files owned
                // by the daemon's own uid may shadow a bundled rule, so a legacy
                // non-daemon-owned file in the dir can't disable detection.
                let userCount = try await ruleEngine.loadRules(from: userOverridesURL, requireOwnerUID: geteuid())
                if userCount > 0 {
                    logger.info("Loaded \(userCount) user rule override(s) from \(userOverridesDir)")
                    print("Loaded \(userCount) user rule override(s)")
                }
            } catch {
                logger.warning("user_rules overlay skipped: \(error.localizedDescription)")
            }
        }

        // The out-of-band rule channel is release-disabled pending an
        // owner-approved offline key rotation and custody record. Preserve any
        // on-disk pushed corpus, but never read or evaluate it. Keep the response
        // gate empty because no `.pushed` rules can enter the live ruleset.
        await responseEngine.setDetectionOnlyRuleIDs([])

        // A boot with ZERO rules is total loss of tier 1, and it used to be a
        // `logger.warning` plus a stdout line — stdout being discarded for a
        // sysextd-launched System Extension. Meanwhile the RELOAD path is
        // rigorously fail-closed (last-known-good retention + the rule-count
        // regression guard), so boot was the weak end: delete, chmod or corrupt
        // `<supportDir>/compiled_rules` and the daemon ingests, enriches, stores
        // and heartbeats `liveness: true` while evaluating nothing. The
        // dashboard does catch it (AppState.isProtectionDegraded) but only if
        // the GUI is running. Raise it on the one channel every surface reads:
        // alerts.db → dashboard, `maccrabctl alerts`, MCP get_alerts.
        // Checked AFTER bundled + user-override loads. The release-disabled
        // pushed-rule channel is intentionally not a boot-time rule source.
        var bootstrapAlerts: [Alert] = []
        let bootRuleCount = await ruleEngine.ruleCount
        if bootRuleCount == 0 {
            logger.critical("No detection rules loaded from \(effectiveRulesDir) — tier-1 detection is INACTIVE")
            print("CRITICAL: 0 detection rules loaded from \(effectiveRulesDir) — MacCrab is collecting and storing events but evaluating none of them.")
            let noRulesAlert = Alert(
                // Synthetic self-defense ruleId, same convention as the
                // coverage-gap / sensor-degraded meta-alerts. NOT a Rules/ entry.
                ruleId: "maccrab.self-defense.no_rules_loaded",
                ruleTitle: "No Detection Rules Loaded",
                severity: .critical,
                eventId: UUID().uuidString,
                processPath: CommandLine.arguments[0],
                processName: "maccrabd",
                description: "MacCrab started with 0 single-event detection rules from \(effectiveRulesDir). Events are still collected and stored, but no rule is being evaluated — tier 1 of the detection stack is inactive. The compiled rules directory is missing, unreadable, or empty. Re-run the rule compiler or reinstall, then reload with SIGHUP.",
                mitreTactics: "attack.defense_evasion",
                mitreTechniques: "attack.t1562.001",
                suppressed: false
            )
            bootstrapAlerts.append(noRulesAlert)
        }
        if uebaLoadFailed {
            bootstrapAlerts.append(Alert(
                ruleId: "maccrab.self-defense.ueba_persistence_unavailable",
                ruleTitle: "UEBA Baseline Unavailable",
                severity: .medium,
                eventId: UUID().uuidString,
                processPath: CommandLine.arguments[0],
                processName: "maccrabd",
                description: "UEBA was enabled, but its persisted profile model failed bounded validation. Behavioural anomaly scoring is disabled for this boot; the original model was preserved at \(uebaPersistencePath) for recovery.",
                mitreTactics: "attack.defense_evasion",
                mitreTechniques: "attack.t1562.001",
                suppressed: false
            ))
        }

        // Load sequence rules (use same effective dir as single-event rules).
        // v1.21.5: pass the F-04 profile — sequence rules previously bypassed
        // rule_profile entirely, so the 36 experimental sequences ran on
        // default "stable" installs.
        let sequenceRulesDir = effectiveRulesDir + "/sequences"
        try? FileManager.default.createDirectory(atPath: sequenceRulesDir, withIntermediateDirectories: true)
        do {
            let seqCount = try await sequenceEngine.loadRules(from: URL(fileURLWithPath: sequenceRulesDir), enabledStatuses: ruleStatuses)
            logger.info("Loaded \(seqCount) sequence detection rules (rule_profile: \(config.ruleProfile))")
            print("Loaded \(seqCount) sequence detection rules (rule_profile: \(config.ruleProfile))")
        } catch {
            logger.info("No sequence rules loaded (this is fine for initial setup)")
        }

        // Restart continuity is part of sequence-engine correctness, not a
        // background convenience. Restore only after the complete active rule
        // corpus is known (the checkpoint is fingerprint-bound to it) and
        // before DaemonBootstrap starts either event consumer.
        let sequenceCheckpointCoordinator = SequenceCheckpointCoordinator(
            checkpointURL: URL(fileURLWithPath: supportDir, isDirectory: true)
                .appendingPathComponent(SequenceCheckpointCoordinator.defaultFileName)
        )
        let sequenceRestore = await sequenceCheckpointCoordinator.restore(
            into: sequenceEngine
        )
        switch sequenceRestore {
        case .absent:
            logger.info("No sequence checkpoint present; starting with empty in-flight state")
        case .restored(
            let partials,
            let pendingSteps,
            let expiredPartials,
            let expiredPendingSteps
        ):
            logger.notice("Restored sequence checkpoint: \(partials) partial(s), \(pendingSteps) pending step(s), \(expiredPartials) expired partial(s), \(expiredPendingSteps) expired pending step(s)")
        case .rejected(let detail):
            // Detection remains fail-open with empty in-flight state, but the
            // promised restart-continuity layer is degraded and must be loud.
            logger.fault("Sequence checkpoint rejected: \(detail, privacy: .public)")
            print("WARNING: sequence checkpoint rejected; restart continuity is degraded: \(detail)")
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
        startupWorkLifecycle.submit(label: "user-rule-watch") {
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
                        // v1.19.1 (audit): per-file ownership gate on the live-reload
                        // path too — only daemon-owned override files may shadow a
                        // bundled rule.
                        if let overlayed = try? await ruleEngine.loadRules(from: URL(fileURLWithPath: userOverridesDirForWatcher), requireOwnerUID: geteuid()) {
                            total += overlayed
                        }
                    }
                    // The release-disabled out-of-band channel leaves any pushed
                    // corpus on disk but never re-applies it after this base reload.
                    await responseEngine.setDetectionOnlyRuleIDs([])
                    // v1.21.6 (PERF-02) KNOWN GAP, documented not hidden: this
                    // detached watcher has no handle on the ESCollector (it is
                    // constructed later in this function), so it cannot re-run the
                    // demand gate. Enabling an introspection rule from the
                    // dashboard therefore needs a `pkill -HUP com.maccrab.agent`
                    // before ES starts delivering those events. SIGHUP does it.
                    logger.notice("Rules reloaded after user-rules tick: \(total) active rule(s)")
                } catch {
                    logger.warning("Reload after user-rules tick failed: \(error.localizedDescription)")
                }
            }
        }

        // Start TCC monitor (Phase 2: permission change detection)
        let tccMonitor = TCCMonitor()

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

        // v1.21.4 Phase-6 6A: fold the operator's agent_traces_config.json
        // master (agent_traces_enabled) into ESCollector's env-seeded gate
        // BEFORE the collector is constructed, so its ES handler block and
        // the registry / receiver gates below all observe the
        // config-reachable value. The shipped System Extension can't be
        // handed MACCRAB_AGENT_TRACES, so this file field is the only way
        // to reach the master on a release build. Loaded once here and
        // reused for the receiver gate below.
        let agentTracesCfg = AgentTracesConfigStore.loadEffective()
        ESCollector.applyConfigMaster(agentTracesCfg.enabled)

        // Start ES collector (optional -- requires root + ES entitlement)
        // Falls back to eslogger proxy if entitlement is missing.
        var esloggerCollector: EsloggerCollector? = nil
        var kdebugCollector: KdebugCollector? = nil
        var esMode = "unavailable"

        if isRoot {
            do {
                // v1.21.6 (PERF-02): subscribe the two high-rate / zero-yield ES
                // families ONLY when an ENABLED rule can consume them. Field-
                // measured: MPROTECT + MMAP + GET_TASK_READ were 24-31% of every
                // kernel message and produced ONE stored event and ZERO alerts —
                // their only rules are `experimental` (disabled under the default
                // stable profile) and nothing selects mprotect_wx/mmap_wx at all.
                // Rules are fully loaded by this point (base + user overlay), and
                // SIGHUP re-evaluates via applyOptionalSubscriptions, so
                // `rule_profile: "all"` still works without a restart.
                let esActionSelectors = await ruleEngine.enabledEventActionSelectors()
                let esDemand = ESCollector.optionalFamiliesDemanded(
                    selectors: esActionSelectors.values,
                    unanalyzable: esActionSelectors.hasUnanalyzableSelector)
                if !esDemand.introspection || !esDemand.memoryProtection {
                    // Never silent: an unsubscribed family is a deliberate coverage
                    // decision the operator must be able to see and reverse.
                    logger.notice("ES demand gate: introspection=\(esDemand.introspection), memory_protection=\(esDemand.memoryProtection) — an unsubscribed family means no ENABLED rule selects its event.action. Enable the rule (or set rule_profile: all), then `pkill -HUP com.maccrab.agent`.")
                    print("ES demand gate: introspection=\(esDemand.introspection), memory_protection=\(esDemand.memoryProtection)")
                }
                collector = try ESCollector(subscribeFileOpen: config.subscribeFileOpenEvents,
                                            subscribeIntrospection: config.subscribeIntrospectionEvents && esDemand.introspection,
                                            subscribeMemoryProtection: esDemand.memoryProtection,
                                            workerMaxInFlight: config.esWorkerMaxInFlight)
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
            bundledRuleSyncObservation: ruleSyncObservation,
            eventJournalRecovery: journalRecovery,
            eventStore: eventStore,
            legacyEvidenceTransitionBudget: legacyEvidenceTransitionBudget,
            eventRetentionBudgetHealth: eventRetentionBudgetHealth,
            alertStore: alertStore,
            evidenceBudgetBytes: SQLitePersistentStorePolicy.capBytes(
                maxSizeMiB: bootStorage.evidenceMaxSizeMB
            ),
            startupWorkLifecycle: startupWorkLifecycle,
            enricher: enricher,
            ruleEngine: ruleEngine,
            sequenceEngine: sequenceEngine,
            sequenceCheckpointCoordinator: sequenceCheckpointCoordinator,
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
            sdrDeviceMonitor: sdrDeviceMonitor,
            btmSnapshotMonitor: btmSnapshotMonitor,
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
            deliveryProvenanceWeld: deliveryProvenanceWeld,
            injectionEvidenceWeld: injectionEvidenceWeld,
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
            causalStoreStartupAdmission: causalStoreStartupAdmission,
            causalStoreStartupRecovery: causalStoreStartupRecovery,
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
            clickFix: clickFixDetector,
            uebaEngine: uebaEngine
        )

        // AlertSink does not exist until DaemonState construction. Flush the
        // bounded bootstrap queue through it immediately afterward rather than
        // maintaining a second raw AlertStore insertion path.
        for alert in bootstrapAlerts {
            do {
                _ = try await state.alertSink.submit(alert: alert)
            } catch {
                await StorageErrorTracker.shared.recordAlertError(error)
            }
        }

        // v1.6.21: wire AlertSink into ResponseEngine so the
        // requireConfirmation skip path emits a synthetic informational
        // alert visible to the operator. Pre-fix the gate logged silently.
        await state.responseEngine.setAlertSinkForPending(state.alertSink)

        // v1.21.5: remember the boot-time rule_profile so the SIGHUP handler
        // can warn when a config edit changed it — RuleEngine keeps applying
        // the boot profile on reload, only sequence/graph pick up the fresh one.
        state.bootRuleProfile = config.ruleProfile

        // Apply v1.8.0 per-tier storage budgets. DaemonTimers reads each knob
        // live so a SIGHUP-driven config reload is honored on the next sweep
        // without a daemon restart. Floors live on the type
        // (StorageConfig.clampedToSafeFloors) so this boot path and the SIGHUP
        // reload path cannot drift apart — they did, and eight tiers ended up
        // clamped at neither.
        state.storage = bootStorage

        // v1.19.1: seed the opt-in network-enrichment switches (off by default).
        // DaemonTimers (vuln scan) and EventLoop (package freshness) read these
        // live; the SIGHUP handler re-applies them so a dashboard toggle takes
        // effect without a restart.
        state.threatIntelEnabled     = config.threatIntelEnabled
        state.vulnScanEnabled        = config.vulnScanEnabled
        state.packageFreshnessEnabled = config.packageFreshnessEnabled
        state.certTransparencyEnabled = config.certTransparencyEnabled

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

        // v1.9 Agent Traces (PR-2): if the operator opted in (via
        // MACCRAB_AGENT_TRACES=1 on dev, OR agent_traces_enabled in
        // agent_traces_config.json on a release sysext — folded into the
        // gate by ESCollector.applyConfigMaster above), allocate a
        // TraceRegistry and spawn the consumer Task that drains
        // ESCollector.traceBindings into it. The collector emits
        // bind/evict signals only when the same master is on, so an
        // unconfigured daemon pays nothing.
        if ESCollector.isAgentTracesEnabled {
            let registry = TraceRegistry()
            state.traceRegistry = registry
            if let collector = collector {
                let bindings = collector.traceBindings
                startupWorkLifecycle.submit(label: "trace-binding-consumer") { [weak registry] in
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
        // v1.21.4 Phase-6 6A: reuse the config loaded above (its
        // `enabled` master was already folded into
        // ESCollector.isAgentTracesEnabled).
        let cfg = agentTracesCfg
        let otlpEnabled = otlpEnvFlag || cfg.receiverEnabled

        if ESCollector.isAgentTracesEnabled, otlpEnabled {
            do {
                guard !dbEncryption.encryptionWasRequested || dbEncryption.isEnabled else {
                    throw DatabaseEncryptionAvailabilityError.persistentKeyUnavailable(
                        dbEncryption.keyPersistenceFailureStatus)
                }
                // v1.9 Phase-2.3: pass the daemon's DatabaseEncryption
                // through so attributes_json is encrypted at rest with the
                // installation's Keychain-backed database-encryption key.
                let traceStore = try TraceStore(
                    directory: supportDir,
                    encryption: dbEncryption.isEnabled ? dbEncryption : nil,
                    maxFootprintBytes: TraceStoreStoragePolicy.capBytes(
                        maxSizeMiB: bootStorage.tracesMaxSizeMB),
                    freeSpaceFloorBytes: TraceStoreStoragePolicy.freeSpaceFloorBytes,
                    storageVolumePath: supportDir
                )
                state.traceStore = traceStore
                state.traceStoreStartupAdmission = nil
                // v1.21.6: rows written before the search-projection migration
                // carry a NULL `search_text` and would never be findable. The
                // migration is pure SQL and cannot decrypt, so backfill here.
                if let filled = try? await traceStore.backfillSearchProjection(), filled > 0 {
                    Logger(subsystem: "com.maccrab.agentkit", category: "agent-traces")
                        .notice("Backfilled search projection for \(filled, privacy: .public) pre-existing spans")
                }
                let receiver = makeOTLPReceiver(
                    port: cfg.port,
                    traceStore: traceStore,
                    supportDir: supportDir
                )
                try await receiver.start()
                state.otlpReceiver = receiver
                Logger(subsystem: "com.maccrab.agentkit", category: "agent-traces")
                    .notice("OTLPReceiver started on 127.0.0.1:\(cfg.port, privacy: .public) — traces.db at \(supportDir, privacy: .public)/traces.db")
                print("[agent-traces] OTLPReceiver listening on 127.0.0.1:\(cfg.port) — traces.db at \(supportDir)/traces.db")
            } catch let pressure as TraceStoreStorageAdmissionError {
                let cap = TraceStoreStoragePolicy.capBytes(
                    maxSizeMiB: bootStorage.tracesMaxSizeMB)
                state.traceStoreStartupAdmission = TraceStoreStartupAdmissionStatus(
                    error: pressure,
                    configuredMaxFootprintBytes: cap,
                    configuredFreeSpaceFloorBytes: TraceStoreStoragePolicy.freeSpaceFloorBytes
                )
                Logger(subsystem: "com.maccrab.agentkit", category: "agent-traces")
                    .fault("OTLP TraceStore startup blocked by storage pressure: \(pressure.localizedDescription, privacy: .public)")
                AgentTracesStatusStore.write(
                    AgentTracesStatus(
                        running: false,
                        port: cfg.port,
                        lastError: pressure.localizedDescription,
                        lastErrorAt: Date()
                    ),
                    to: supportDir
                )
                state.traceStore = nil
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
                state.traceStoreStartupAdmission = nil
            }
        } else {
            // v1.21.4 Phase-6 6A: the master is now config-reachable
            // (agent_traces_enabled), and the dashboard toggle writes the
            // master and receiverEnabled together — so the old
            // "receiver enabled but MACCRAB_AGENT_TRACES not set" mismatch
            // branch is no longer reachable from any supported path. Any
            // remaining off-state (master off, or receiver not requested)
            // simply records stopped.
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

    /// Both boot and SIGHUP must publish the same post-readiness failure state.
    /// `NWListener` can fail after a successful bind; without this callback the
    /// last on-disk snapshot remains `running: true` and a same-port reload used
    /// to return early without recreating the dead listener.
    private static func makeOTLPReceiver(
        port: UInt16,
        traceStore: TraceStore,
        supportDir: String
    ) -> OTLPReceiver {
        OTLPReceiver(
            port: port,
            traceStore: traceStore,
            onReady: {
                AgentTracesStatusStore.write(
                    AgentTracesStatus(running: true, port: port),
                    to: supportDir
                )
            },
            onTerminalFailure: { message in
                AgentTracesStatusStore.write(
                    AgentTracesStatus(
                        running: false,
                        port: port,
                        lastError: "listener failed after readiness: \(message)",
                        lastErrorAt: Date()
                    ),
                    to: supportDir
                )
            }
        )
    }

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
        // v1.21.4 Phase-6 6A: compute the master from the CURRENT config
        // (env seed OR agent_traces_enabled) rather than the boot-frozen
        // `ESCollector.isAgentTracesEnabled` static, so the dashboard can
        // start/stop the OTLP receiver live via SIGHUP. NOTE: this only
        // gates the *receiver* — the *producer* (TraceRegistry + the ES
        // emit gate) is allocated once at boot and can't be hot-toggled,
        // so enabling the master on a running daemon needs a restart to
        // start the producer. The receiver is independent (it ingests
        // external OTLP) so it can come up here regardless.
        let envMaster = Foundation.ProcessInfo.processInfo
            .environment["MACCRAB_AGENT_TRACES"] == "1"
        let master = ESCollector.agentTracesMasterEnabled(env: envMaster, config: cfg.enabled)
        let shouldRun = master && (cfg.receiverEnabled || envFlag)
        let logger = Logger(subsystem: "com.maccrab.agentkit", category: "agent-traces")
        // `state.storage` is the one clamped snapshot installed by boot/SIGHUP.
        // Do not re-read raw daemon config here: that is how cap readers drift.
        let tracesCapBytes = TraceStoreStoragePolicy.capBytes(
            maxSizeMiB: state.storage.tracesMaxSizeMB)

        // Already running — stop and restart only if port changed. Preserve
        // the actor-owned TraceStore across a port-only restart: the bounded
        // maintenance timer also resolves this same actor, so opening a second
        // writer handle here would break the single-writer lifecycle.
        var reusableTraceStore: TraceStore?
        if let existing = state.otlpReceiver {
            let existingPort = await existing.currentPort()
            if !shouldRun {
                let stopped = await existing.stop()
                guard stopped.cleanlyStopped else {
                    AgentTracesStatusStore.write(
                        AgentTracesStatus(
                            running: false,
                            port: existingPort,
                            lastError: "receiver shutdown did not drain owned work",
                            lastErrorAt: Date()
                        ),
                        to: supportDir
                    )
                    logger.error("Refusing to discard unclean OTLPReceiver owner during SIGHUP disable")
                    return
                }
                state.otlpReceiver = nil
                state.traceStore = nil
                state.traceStoreStartupAdmission = nil
                AgentTracesStatusStore.write(
                    AgentTracesStatus(running: false, port: existingPort),
                    to: supportDir
                )
                logger.notice("OTLPReceiver stopped via SIGHUP reload")
                print("[agent-traces] OTLPReceiver stopped (SIGHUP)")
                return
            }
            if let traceStore = state.traceStore {
                do {
                    let admission = try await traceStore.updateStorageAdmission(
                        maxFootprintBytes: tracesCapBytes,
                        freeSpaceFloorBytes: TraceStoreStoragePolicy.freeSpaceFloorBytes
                    )
                    if admission.blocked {
                        logger.warning("OTLP TraceStore remains pressure-blocked after SIGHUP: \(admission.reason?.rawValue ?? "unknown", privacy: .public)")
                    }
                    reusableTraceStore = traceStore
                } catch {
                    logger.error("OTLP TraceStore admission reload failed: \(error.localizedDescription, privacy: .public)")
                    // A same-port reload must not leave the receiver accepting
                    // after its cap/page backstop failed to reconfigure.
                    let stopped = await existing.stop()
                    if !stopped.cleanlyStopped {
                        logger.error("OTLPReceiver did not drain after storage-admission failure; retaining sealed owner")
                        return
                    }
                    state.otlpReceiver = nil
                    state.traceStore = nil
                    if let pressure = error as? TraceStoreStorageAdmissionError {
                        state.traceStoreStartupAdmission = TraceStoreStartupAdmissionStatus(
                            error: pressure,
                            configuredMaxFootprintBytes: tracesCapBytes,
                            configuredFreeSpaceFloorBytes: TraceStoreStoragePolicy.freeSpaceFloorBytes
                        )
                    } else {
                        state.traceStoreStartupAdmission = nil
                    }
                    AgentTracesStatusStore.write(
                        AgentTracesStatus(
                            running: false,
                            port: existingPort,
                            lastError: "storage admission reload failed: \(error.localizedDescription)",
                            lastErrorAt: Date()
                        ),
                        to: supportDir
                    )
                    return
                }
            }
            if existingPort == cfg.port {
                if await existing.isRunning {
                    return // healthy listener, no port change
                }
                // A post-readiness NWListener failure clears the receiver's
                // live listener and publishes running:false, but the owner
                // object remains in DaemonState. Drop that stale owner and
                // fall through so SIGHUP can recover on the same port.
                let stopped = await existing.stop()
                guard stopped.cleanlyStopped else {
                    logger.error("Refusing same-port OTLP restart because prior owned work did not drain")
                    return
                }
                state.otlpReceiver = nil
                logger.warning("OTLPReceiver is no longer running; retrying the same port via SIGHUP")
            } else {
                let stopped = await existing.stop()
                guard stopped.cleanlyStopped else {
                    logger.error("Refusing OTLP port change because prior receiver did not drain")
                    return
                }
                state.otlpReceiver = nil
            }
            // fall through to start on new port
        }

        guard shouldRun else { return }
        do {
            guard !dbEncryption.encryptionWasRequested || dbEncryption.isEnabled else {
                throw DatabaseEncryptionAvailabilityError.persistentKeyUnavailable(
                    dbEncryption.keyPersistenceFailureStatus)
            }
            let traceStore: TraceStore
            if let reusableTraceStore {
                traceStore = reusableTraceStore
            } else {
                traceStore = try TraceStore(
                    directory: supportDir,
                    encryption: dbEncryption.isEnabled ? dbEncryption : nil,
                    maxFootprintBytes: tracesCapBytes,
                    freeSpaceFloorBytes: TraceStoreStoragePolicy.freeSpaceFloorBytes,
                    storageVolumePath: supportDir
                )
            }
            state.traceStore = traceStore
            state.traceStoreStartupAdmission = nil
            let receiver = makeOTLPReceiver(
                port: cfg.port,
                traceStore: traceStore,
                supportDir: supportDir
            )
            try await receiver.start()
            state.otlpReceiver = receiver
            logger.notice("OTLPReceiver started via SIGHUP on 127.0.0.1:\(cfg.port, privacy: .public)")
            print("[agent-traces] OTLPReceiver started (SIGHUP) on 127.0.0.1:\(cfg.port)")
        } catch let pressure as TraceStoreStorageAdmissionError {
            state.traceStoreStartupAdmission = TraceStoreStartupAdmissionStatus(
                error: pressure,
                configuredMaxFootprintBytes: tracesCapBytes,
                configuredFreeSpaceFloorBytes: TraceStoreStoragePolicy.freeSpaceFloorBytes
            )
            AgentTracesStatusStore.write(
                AgentTracesStatus(
                    running: false,
                    port: cfg.port,
                    lastError: pressure.localizedDescription,
                    lastErrorAt: Date()
                ),
                to: supportDir
            )
            logger.error("OTLP TraceStore SIGHUP start blocked: \(pressure.localizedDescription, privacy: .public)")
            state.traceStore = nil
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
            state.traceStoreStartupAdmission = nil
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
/// system+user pattern (`loadEffectiveConfig`): system path first,
/// then inspect resolver-validated homes for a UID-bound user copy,
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
    let systemSnapshot: BoundedRegularFileReader.Snapshot? = {
        guard case .success(let snapshot) = BoundedRegularFileReader.readOutcome(
            at: systemPath,
            maximumBytes: maximumAlertNotificationConfigBytes
        ) else { return nil }
        return snapshot
    }()
    let userSnapshot = _findUserHomeAlertNotificationConfigSnapshot()

    func decode(
        _ snapshot: BoundedRegularFileReader.Snapshot
    ) -> (enabled: Bool, minSeverity: Severity)? {
        guard let json = try? JSONSerialization.jsonObject(
            with: snapshot.data
        ) as? [String: Any]
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

    let systemConfig = systemSnapshot.flatMap(decode)
    let userConfig = userSnapshot.flatMap(decode)

    switch (systemConfig, userConfig) {
    case (nil, nil):
        return (true, .critical)
    case (let sc?, nil):
        return sc
    case (nil, let uc?):
        return uc
    case (let sc?, let uc?):
        let sm = systemSnapshot?.modificationDate ?? .distantPast
        let um = userSnapshot?.modificationDate ?? .distantPast
        return um > sm ? uc : sc
    }
}

/// Inspect resolver-validated homes for an `alert_notifications.json` owned
/// by the home's uid. Returns the most-recently-modified descriptor snapshot,
/// or nil. Same shape as
/// `NotificationIntegrations.findUserHomeConfigSnapshot` — kept as a
/// sibling helper rather than generalising because the cross-target
/// abstraction would have to thread through MacCrabCore.
private func _findUserHomeAlertNotificationConfigSnapshot()
    -> BoundedRegularFileReader.Snapshot? {
    var candidates: [BoundedRegularFileReader.Snapshot] = []
    for home in RealUserHomeResolver.all() {
        let path = home.appending(
            "Library/Application Support/MacCrab/alert_notifications.json"
        )
        guard case .success(let snapshot) = BoundedRegularFileReader.readOutcome(
                  at: path,
                  maximumBytes: maximumAlertNotificationConfigBytes
              ) else { continue }
        guard home.userID == snapshot.ownerUID else { continue }
        // v1.21.4 (audit A2-02): this file toggles the operator's OS alert
        // notifications (enabled=false blinds them). Mirror the
        // ResponseAction.findUserHomeActionsPath gate — only honor a user-home
        // config owned by an ADMIN user, so a non-admin on a shared / managed
        // Mac can't suppress alerting via a self-owned file.
        guard DaemonTimers.isAdminUID(home.userID) else { continue }
        candidates.append(snapshot)
    }
    return candidates.max(by: { $0.modificationDate < $1.modificationDate })
}

/// Retired compatibility entry point. Root must never mutate a DB below a
/// user-controlled ancestor. Orphan cleanup is deliberately left to explicit
/// user-context tooling where the target is the caller's own data.
@available(*, deprecated, message: "Automatic root orphan-DB mutation is retired")
func reapOrphanUserDomainDBs(logger: os.Logger) {
    logger.notice("Automatic orphan user-domain DB mutation is retired; no files changed")
}

/// Secure-directory check for the user_rules override overlay, usable from
/// detached Tasks (the per-setup `isSecureDirectory` closure isn't in their
/// scope). Rejects symlinks and any group- or world-writable dir; requires
/// owner uid 0 or the current uid. Mirrors the inline gate in `start()`.
/// A rule-override overlay can DISABLE detection, so it must not be writable
/// by a non-root admin. A top-level free function lets detached Tasks call it
/// without capturing the per-setup closure.
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
