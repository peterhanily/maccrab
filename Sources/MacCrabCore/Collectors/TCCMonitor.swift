// TCCMonitor.swift
// MacCrabCore
//
// Monitors the macOS TCC (Transparency, Consent, and Control) databases
// for permission changes and emits security events when grants or
// revocations are detected.
//
// Watches both the system-wide and per-user TCC.db files using
// DispatchSource file-system watchers, diffs snapshots to identify
// changes, and reads the databases via the sqlite3 C API.

import Foundation
import CSQLCipher
import os.log

// MARK: - TCCMonitorError

/// Errors that can occur during TCC database monitoring.
public enum TCCMonitorError: Error, CustomStringConvertible {
    /// A TCC database could not be opened for reading.
    case databaseOpenFailed(path: String, reason: String)
    /// A SQL query against the TCC database failed.
    case queryFailed(String)
    /// Neither the system nor user TCC database could be found.
    case noDatabasesFound

    public var description: String {
        switch self {
        case .databaseOpenFailed(let path, let reason):
            return "Failed to open TCC database at \(path): \(reason)"
        case .queryFailed(let msg):
            return "TCC database query failed: \(msg)"
        case .noDatabasesFound:
            return "No TCC databases found at expected paths."
        }
    }
}

// MARK: - TCCEntry

/// A single row from the TCC `access` table, representing a permission
/// decision for one (service, client) pair.
struct TCCEntry: Hashable, Sendable, Codable {
    /// The TCC service identifier (e.g. `"kTCCServiceAccessibility"`).
    let service: String
    /// The client bundle identifier or executable path.
    let client: String
    /// Client type: 0 = bundle identifier, 1 = absolute path.
    let clientType: Int
    /// Authorization value: 0 = denied, 1 = unknown, 2 = allowed.
    let authValue: Int
    /// Authorization reason code.
    let authReason: Int
    /// The indirect object identifier, if any (e.g. a specific file path).
    let indirectObjectIdentifier: String
    /// Bit flags for the entry.
    let flags: Int
    /// Last modification time as Unix epoch seconds.
    let lastModified: Double
    /// Which database this entry came from (`"system"` or `"user"`).
    let source: String

    /// A stable identity key for diffing — two entries represent the same
    /// logical permission if they share (service, client, source).
    var identityKey: String {
        "\(source):\(service):\(client)"
    }
}

// MARK: - TCCMonitor

/// Monitors macOS TCC databases for permission changes and emits
/// `tcc_grant` / `tcc_revoke` events.
///
/// TCC databases live at:
/// - **System**: `/Library/Application Support/com.apple.TCC/TCC.db`
/// - **User**: `~/Library/Application Support/com.apple.TCC/TCC.db`
///
/// The monitor takes an initial snapshot on `start()`, then watches both
/// files for writes using `DispatchSource`. On each change it re-reads
/// the database, diffs against the previous snapshot, and emits events
/// for new grants and revocations.
///
/// Usage:
/// ```swift
/// let monitor = TCCMonitor()
/// Task {
///     await monitor.start()
/// }
/// for await event in monitor.events {
///     // handle event
/// }
/// ```
public actor TCCMonitor {

    public nonisolated static let eventStreamCapacity = 256

    /// App Info.plists are normally tens of KiB. Keep enough room for unusually
    /// rich bundles while bounding the root actor's scan of admin-writable
    /// `/Applications` entries.
    static let maxApplicationInfoPlistBytes = 1 * 1024 * 1024
    static let maxApplicationDirectoryEntries = 65_536

    // MARK: - Database Paths

    /// Path to the system-wide TCC database.
    private static let systemDBPath =
        "/Library/Application Support/com.apple.TCC/TCC.db"

    /// Paths to every real user's TCC database, paired with the `source` label
    /// their entries carry.
    ///
    /// v1.21.6 (audit DET-06): this was a single path built from
    /// `homeDirectoryForCurrentUser`. Inside the root System Extension that
    /// resolves to `/var/root`, which has no TCC.db — so on every release install
    /// the USER database was never opened. Verified on the field host: the
    /// daemon's own `tcc_snapshot.json` held 21 entries, ALL `source: "system"`,
    /// zero `user`. The per-user services (kTCCServiceMicrophone, Camera,
    /// Contacts, Calendar, Photos, AppleEvents) live only in the user DB, so any
    /// rule keyed on one of them was structurally incapable of firing —
    /// `Rules/collection/microphone_access_unsigned.yml` is `status: stable` and
    /// counts toward advertised coverage while being unable to match.
    ///
    /// Resolve homes through the shared uid/passwd/no-symlink contract and
    /// label each `user:<name>` so `identityKey` stays distinct on a multi-user
    /// Mac. The non-root dev daemon's own home is kept as a fallback so
    /// `swift run maccrabd` behaves exactly as before.
    private static func userDBPaths() -> [(path: String, source: String)] {
        let fm = FileManager.default
        var result: [(path: String, source: String)] = []
        for home in RealUserHomeResolver.all() {
            let path = home.appending("Library/Application Support/com.apple.TCC/TCC.db")
            if fm.fileExists(atPath: path) {
                result.append((path, "user:\(home.userName)"))
            }
        }
        return result
    }

    // MARK: - Properties

    private nonisolated let logger = Logger(subsystem: "com.maccrab.core", category: "TCCMonitor")
    private nonisolated let deliveryTelemetry = EventCollectorBufferTelemetry(
        capacity: eventStreamCapacity
    )
    private var continuation: AsyncStream<Event>.Continuation?
    private var lifecyclePhase: CollectorLifecyclePhase = .initialized
    private let callbackTasks = CollectorCallbackTaskLifecycle(maximumInFlight: 16)
    private let sourceCancellationGroup = DispatchGroup()

    /// Current snapshot of all TCC entries, keyed by identity.
    private var snapshot: [String: TCCEntry] = [:]

    /// File descriptors and dispatch sources for watching database files.
    private var watchSources: [DispatchSourceFileSystemObject] = []

    /// Resolves the code signature of the TCC client so SignerType is accurate.
    /// Before v1.18 the TCC event carried no codeSignature at all → SignerType
    /// resolved to nil → every "granted to unsigned" rule fired on signed apps.
    private let codeSigningCache = CodeSigningCache()
    private var watchFileDescriptors: [Int32] = []

    /// Debounce interval to coalesce rapid database writes (in seconds).
    private let debounceInterval: TimeInterval = 0.5

    /// Tracks the last time a change was processed to implement debouncing.
    private var lastChangeTime: Date = .distantPast
    private let snapshotWriter: CoalescingSnapshotWriter<PermissionSnapshot>

    /// The asynchronous stream of normalised events.
    public nonisolated let events: AsyncStream<Event>
    public nonisolated var deliveryCounters: EventCollectorBufferSnapshot {
        deliveryTelemetry.snapshot()
    }

    // MARK: - Auth Value / Reason Mapping

    /// Human-readable names for TCC authorization values.
    private static let authValueNames: [Int: String] = [
        0: "denied",
        1: "unknown",
        2: "allowed",
    ]

    /// Human-readable names for TCC authorization reasons.
    private static let authReasonNames: [Int: String] = [
        1: "user_consent",
        2: "user_set",
        3: "system_policy",
        4: "service_policy",
        5: "mdm_policy",
        6: "override_policy",
        7: "missing_usage_string",
        8: "prompt_timeout",
        9: "preflight_unknown",
        10: "entitled",
        11: "app_type_policy",
    ]

    // MARK: - Initialisation

    /// Creates a new `TCCMonitor`. Call `start()` to begin monitoring.
    public init() {
        self.snapshotWriter = CoalescingSnapshotWriter(
            category: "tcc-permission-snapshot",
            persistence: Self.persistPermissionSnapshot
        )
        var capturedContinuation: AsyncStream<Event>.Continuation!
        self.events = AsyncStream<Event>(
            bufferingPolicy: .bufferingNewest(Self.eventStreamCapacity)
        ) { continuation in
            capturedContinuation = continuation
        }
        self.continuation = capturedContinuation
    }

    // MARK: - Lifecycle

    /// Begins monitoring TCC databases.
    ///
    /// Takes an initial snapshot and installs file-system watchers on both
    /// the system and user TCC database files.
    public func start() async {
        guard lifecyclePhase == .initialized else {
            logger.warning("TCCMonitor.start() rejected after its one-shot lifecycle advanced.")
            return
        }
        guard callbackTasks.open() else {
            logger.error("TCCMonitor.start() rejected because prior callback work is still owned.")
            lifecyclePhase = .stopped
            continuation?.finish()
            continuation = nil
            return
        }
        lifecyclePhase = .running

        // SQLite busy waits and multi-user reads must not pin this actor: stop
        // has to be able to seal startup while the cold snapshot is in flight.
        let initialSnapshot = await Task.detached(priority: .utility) { [self] in
            readAllEntries()
        }.value
        guard lifecyclePhase == .running, !Task.isCancelled else { return }
        snapshot = initialSnapshot
        logger.info("TCCMonitor started — initial snapshot has \(self.snapshot.count) entries.")

        // Install file watchers
        installWatcher(path: Self.systemDBPath, label: "system")
        // v1.21.6 (audit DET-06): watch EVERY real user's TCC.db, not the
        // current process's home — as root that was /var/root and no user-DB
        // watcher was ever installed.
        for entry in Self.userDBPaths() {
            installWatcher(path: entry.path, label: entry.source)
        }
    }

    // MARK: - Cross-process snapshot (sysext → app, v1.7.1)

    /// Public, copy-by-value snapshot of one TCC entry. Same fields as the
    /// internal `TCCEntry` but exposed as `public` so MacCrabApp can decode
    /// it.
    public struct PublicEntry: Codable, Sendable, Hashable {
        public let service: String
        public let client: String
        public let clientType: Int
        public let authValue: Int
        public let authReason: Int
        public let indirectObjectIdentifier: String
        public let flags: Int
        public let lastModified: Double
        public let source: String
        public init(service: String, client: String, clientType: Int,
                    authValue: Int, authReason: Int,
                    indirectObjectIdentifier: String, flags: Int,
                    lastModified: Double, source: String) {
            self.service = service
            self.client = client
            self.clientType = clientType
            self.authValue = authValue
            self.authReason = authReason
            self.indirectObjectIdentifier = indirectObjectIdentifier
            self.flags = flags
            self.lastModified = lastModified
            self.source = source
        }
    }

    /// On-disk snapshot wrapper. The dashboard's rebuilt Permissions
    /// panel reads `<supportDir>/tcc_snapshot.json` for the current
    /// app × service permission matrix.
    public struct PermissionSnapshot: Codable, Sendable {
        public let writtenAt: Date
        public let entries: [PublicEntry]
        public init(writtenAt: Date, entries: [PublicEntry]) {
            self.writtenAt = writtenAt
            self.entries = entries
        }
    }

    /// Snapshot copy stays actor-isolated; encoding and publication use the
    /// shared bounded writer so a slow filesystem cannot stall TCC callbacks.
    public func writeSnapshot(to path: String) async {
        let pubEntries = snapshot.values.map {
            PublicEntry(
                service: $0.service,
                client: $0.client,
                clientType: $0.clientType,
                authValue: $0.authValue,
                authReason: $0.authReason,
                indirectObjectIdentifier: $0.indirectObjectIdentifier,
                flags: $0.flags,
                lastModified: $0.lastModified,
                source: $0.source
            )
        }
        let snap = PermissionSnapshot(writtenAt: Date(), entries: pubEntries)
        await snapshotWriter.publish(snap, to: path)
    }

    public func snapshotWriteTelemetry() async -> CoalescingSnapshotWriterTelemetry {
        await snapshotWriter.telemetry()
    }

    @Sendable
    private nonisolated static func persistPermissionSnapshot(
        _ snapshot: PermissionSnapshot,
        to path: String
    ) -> String? {
        do {
            let data = try JSONEncoder().encode(snapshot)
            try SecureFileIO.atomicReplace(at: path, data: data, mode: 0o640)
            // v1.21.5 (audit S-07): 0640, NOT 0644. This file is a verbatim copy of
            // the TCC grant map read from behind SIP/FDA — which client holds
            // Accessibility, Screen Recording, PostEvent, EndpointSecurityClient,
            // Full Disk Access. At 0644 MacCrab unilaterally downgraded an
            // OS-enforced confidentiality boundary: any local process, any uid, no
            // FDA and no admin, could enumerate the machine's highest-value
            // injection targets purely because we mirrored TCC.db to disk. 0640 in
            // the root:admin support dir matches alerts.db / events.db / traces.db,
            // which the dashboard already reads over that same group — so the
            // Permissions panel is unaffected for any user who can open the
            // dashboard at all.
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o640, .groupOwnerAccountID: 80],
                ofItemAtPath: path
            )
            return nil
        } catch {
            return String(error.localizedDescription.prefix(512))
        }
    }

    public nonisolated static func readSnapshot(at path: String) -> PermissionSnapshot? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else { return nil }
        return try? JSONDecoder().decode(PermissionSnapshot.self, from: data)
    }

    /// Stops monitoring and finishes the event stream.
    public func stop() {
        _ = beginStop()
    }

    /// Seal callback admission before cancelling file-system sources, then join
    /// both the exact accepted callback prefix and every source cancel handler.
    @discardableResult
    public func stopAndJoin(deadline: TimeInterval = 1.0) async -> Bool {
        let callbackPrefix = beginStop()
        async let callbacksJoined = CollectorBoundedTaskJoin.waitForAll(
            callbackPrefix,
            deadline: deadline
        )
        async let sourcesJoined = CollectorDispatchGroupJoin.wait(
            sourceCancellationGroup,
            deadline: deadline
        )
        let (callbackResult, sourceResult) = await (
            callbacksJoined,
            sourcesJoined
        )
        let clean = callbackResult && sourceResult
        if clean {
            lifecyclePhase = .stopped
            logger.info("TCCMonitor stopped cleanly.")
        } else {
            logger.error("TCCMonitor stop deadline expired with callback or source teardown active.")
        }
        return clean
    }

    private func beginStop() -> [Task<Void, Never>] {
        if lifecyclePhase == .stopped { return [] }
        lifecyclePhase = .stopping

        // Ordering is load-bearing: close task admission before source cancel,
        // because a callback already queued on its dispatch queue may run after
        // cancel() is requested.
        let callbackPrefix = callbackTasks.sealAndCancel()

        // Tear down dispatch sources. Each source's cancel handler closes
        // its own fd once GCD has stopped delivering events for it — closing
        // here would create a use-after-close window (the event handler can
        // still fire between this async cancel request and its completion).
        for source in watchSources {
            source.cancel()
        }
        watchSources.removeAll()
        watchFileDescriptors.removeAll()

        continuation?.finish()
        continuation = nil
        return callbackPrefix
    }

    deinit {
        _ = callbackTasks.sealAndCancel()
        for source in watchSources { source.cancel() }
        continuation?.finish()
    }

    // MARK: - File Watching

    /// Watchers installed by `start()`. The monitor is change-driven, so with
    /// none installed it would read healthy while unable to see any change.
    public var installedWatcherCount: Int { watchSources.count }

    /// Installs a `DispatchSource` file-system watcher on the given path.
    ///
    /// Watches for `.write` events and triggers a diff when the file changes.
    private func installWatcher(path: String, label: String) {
        let fd = Darwin.open(path, O_EVTONLY)
        guard fd >= 0 else {
            logger.warning("Cannot watch \(label) TCC database at \(path) — file not accessible (fd < 0).")
            return
        }

        watchFileDescriptors.append(fd)

        let source = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: fd,
            eventMask: [.write, .rename, .delete],
            queue: DispatchQueue(label: "com.maccrab.tccmonitor.\(label)")
        )

        let callbackTasks = self.callbackTasks

        source.setEventHandler { [weak self] in
            callbackTasks.submit { [weak self] in
                await self?.handleDatabaseChange()
            }
        }

        sourceCancellationGroup.enter()
        let sourceCancellationGroup = self.sourceCancellationGroup
        source.setCancelHandler {
            // Close the fd here — GCD guarantees the cancel handler runs once,
            // after the source has fully stopped delivering events, so there
            // is no use-after-close window.
            Darwin.close(fd)
            sourceCancellationGroup.leave()
        }

        source.resume()
        watchSources.append(source)

        logger.info("Installed file watcher on \(label) TCC database at \(path).")
    }

    // MARK: - Change Detection

    /// Called when a watched TCC database file changes on disk.
    ///
    /// Implements simple debouncing to coalesce rapid writes (tccd often
    /// writes multiple times for a single user action).
    private func handleDatabaseChange() async {
        guard lifecyclePhase == .running, !Task.isCancelled else { return }
        let now = Date()
        guard now.timeIntervalSince(lastChangeTime) >= debounceInterval else {
            return
        }
        lastChangeTime = now

        let currentEntries = await Task.detached(priority: .utility) { [self] in
            readAllEntries()
        }.value
        guard lifecyclePhase == .running, !Task.isCancelled else { return }
        let previousEntries = snapshot

        // Detect new or changed grants
        for (key, entry) in currentEntries {
            if let previous = previousEntries[key] {
                // Entry exists in both — check if the auth value changed
                if previous.authValue != entry.authValue {
                    await emitEvent(entry: entry, previousAuthValue: previous.authValue)
                    guard lifecyclePhase == .running, !Task.isCancelled else { return }
                }
            } else {
                // Brand new entry
                await emitEvent(entry: entry, previousAuthValue: nil)
                guard lifecyclePhase == .running, !Task.isCancelled else { return }
            }
        }

        // Detect revocations (entries that were removed entirely)
        for (key, previousEntry) in previousEntries {
            if currentEntries[key] == nil {
                await emitRevocationEvent(entry: previousEntry)
                guard lifecyclePhase == .running, !Task.isCancelled else { return }
            }
        }

        // Update the snapshot
        guard lifecyclePhase == .running, !Task.isCancelled else { return }
        snapshot = currentEntries
    }

    // MARK: - Event Emission

    /// Emits an event for a new or changed TCC entry.
    private func emitEvent(entry: TCCEntry, previousAuthValue: Int?) async {
        let allowed = entry.authValue == 2
        let eventAction: String
        let eventType: EventType

        if allowed {
            eventAction = "tcc_grant"
            eventType = .creation
        } else {
            eventAction = "tcc_revoke"
            eventType = .deletion
        }

        guard let event = await buildEvent(
            entry: entry,
            eventType: eventType,
            eventAction: eventAction,
            allowed: allowed,
            previousAuthValue: previousAuthValue
        ) else { return }

        guard lifecyclePhase == .running, !Task.isCancelled else { return }

        if let continuation {
            let result = continuation.yield(event)
            deliveryTelemetry.recordYield(offered: event, result: result)
        }

        let sourceLabel = entry.source
        logger.info(
            "TCC \(eventAction): service=\(entry.service) client=\(entry.client) source=\(sourceLabel)"
        )
    }

    /// Emits a revocation event for an entry that was removed from the database.
    private func emitRevocationEvent(entry: TCCEntry) async {
        guard let event = await buildEvent(
            entry: entry,
            eventType: .deletion,
            eventAction: "tcc_revoke",
            allowed: false,
            previousAuthValue: entry.authValue
        ) else { return }

        guard lifecyclePhase == .running, !Task.isCancelled else { return }

        if let continuation {
            let result = continuation.yield(event)
            deliveryTelemetry.recordYield(offered: event, result: result)
        }

        let sourceLabel = entry.source
        logger.info(
            "TCC tcc_revoke (entry removed): service=\(entry.service) client=\(entry.client) source=\(sourceLabel)"
        )
    }

    /// Builds a MacCrab `Event` from a TCC entry.
    private func buildEvent(
        entry: TCCEntry,
        eventType: EventType,
        eventAction: String,
        allowed: Bool,
        previousAuthValue: Int?
    ) async -> Event? {
        let authReasonString = Self.authReasonNames[entry.authReason] ?? "reason_\(entry.authReason)"

        // Resolve the client path if the client type indicates an absolute path
        let clientPath: String
        if entry.clientType == 1 {
            clientPath = entry.client
        } else {
            // Bundle identifier — attempt to resolve via Launch Services
            clientPath = await Task.detached(priority: .utility) { [self] in
                resolveBundlePath(bundleId: entry.client)
            }.value
        }

        guard lifecyclePhase == .running, !Task.isCancelled else {
            return nil
        }

        // Resolve the client's ACTUAL code signature so SignerType is accurate.
        // When the path is unresolvable the signature stays nil → SignerType
        // resolves to nil, which the (positive) `SignerType: unsigned` TCC rules
        // do NOT match — i.e. an unknown client is treated as "don't fire",
        // never as "unsigned". This is what fixes the whole TCC FP family.
        let clientSignature = clientPath.isEmpty
            ? nil
            : await codeSigningCache.evaluate(path: clientPath)
        guard lifecyclePhase == .running, !Task.isCancelled else { return nil }

        let tccInfo = TCCInfo(
            service: entry.service,
            client: entry.client,
            clientPath: clientPath,
            allowed: allowed,
            authReason: authReasonString
        )

        let processInfo = ProcessInfo(
            pid: 0,
            ppid: 0,
            rpid: 0,
            name: entry.client,
            executable: clientPath,
            commandLine: "",
            args: [],
            workingDirectory: "/",
            userId: 0,
            userName: "",
            groupId: 0,
            startTime: Date(timeIntervalSince1970: entry.lastModified),
            codeSignature: clientSignature
        )

        // Build enrichments with TCC-specific metadata
        var enrichments: [String: String] = [
            "tcc.source": entry.source,
            "tcc.clientType": entry.clientType == 0 ? "bundle_id" : "path",
            "tcc.authValue": Self.authValueNames[entry.authValue] ?? String(entry.authValue),
            "tcc.flags": String(entry.flags),
        ]
        if !entry.indirectObjectIdentifier.isEmpty {
            enrichments["tcc.indirectObject"] = entry.indirectObjectIdentifier
        }
        if let prev = previousAuthValue {
            enrichments["tcc.previousAuthValue"] = Self.authValueNames[prev] ?? String(prev)
        }

        // Severity: grants of sensitive services are more noteworthy
        let severity: Severity
        let sensitiveServices: Set<String> = [
            "kTCCServiceAccessibility",
            "kTCCServiceScreenCapture",
            "kTCCServiceSystemPolicyAllFiles",
            "kTCCServiceSystemPolicySysAdminFiles",
            "kTCCServiceListenEvent",
            "kTCCServicePostEvent",
        ]
        if allowed && sensitiveServices.contains(entry.service) {
            severity = .medium
        } else if allowed {
            severity = .low
        } else {
            severity = .informational
        }

        return Event(
            timestamp: Date(),
            eventCategory: .tcc,
            eventType: eventType,
            eventAction: eventAction,
            process: processInfo,
            tcc: tccInfo,
            enrichments: enrichments,
            severity: severity
        )
    }

    // MARK: - Database Reading

    /// Reads all TCC entries from both the system and user databases.
    ///
    /// Returns a dictionary keyed by identity (`"source:service:client"`).
    /// Silently skips databases that cannot be opened (e.g., insufficient
    /// permissions for the system database when not running as root).
    private nonisolated func readAllEntries() -> [String: TCCEntry] {
        var entries: [String: TCCEntry] = [:]

        for (path, source) in [(path: Self.systemDBPath, source: "system")] + Self.userDBPaths() {
            let dbEntries = readDatabase(path: path, source: source)
            for entry in dbEntries {
                entries[entry.identityKey] = entry
            }
        }

        return entries
    }

    /// Reads all entries from a single TCC database file.
    ///
    /// Opens the database in read-only mode with WAL journal to avoid
    /// interfering with the tccd daemon. Handles `SQLITE_BUSY` gracefully
    /// by retrying with a short timeout.
    private nonisolated func readDatabase(path: String, source: String) -> [TCCEntry] {
        guard FileManager.default.fileExists(atPath: path) else {
            logger.debug("TCC database not found at \(path) — skipping.")
            return []
        }

        var db: OpaquePointer?
        let flags = SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX
        let rc = SQLiteOpenPathPolicy.open(path, database: &db, flags: flags)
        guard rc == SQLITE_OK, let db else {
            let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
            logger.warning("Cannot open TCC database at \(path): \(msg)")
            if let db { sqlite3_close(db) }
            return []
        }

        defer { sqlite3_close(db) }

        // Set a busy timeout so we wait briefly if tccd holds a lock
        sqlite3_busy_timeout(db, 1000) // 1 second

        // Read the access table
        let sql = """
            SELECT service, client, client_type, auth_value, auth_reason,
                   indirect_object_identifier, flags, last_modified
            FROM access
            """

        var stmt: OpaquePointer?
        let prepareRC = sqlite3_prepare_v2(db, sql, -1, &stmt, nil)
        guard prepareRC == SQLITE_OK, let stmt else {
            let msg = String(cString: sqlite3_errmsg(db))
            logger.warning("Failed to prepare TCC query on \(path): \(msg)")
            return []
        }

        defer { sqlite3_finalize(stmt) }

        var entries: [TCCEntry] = []

        while true {
            let stepRC = sqlite3_step(stmt)
            if stepRC == SQLITE_ROW {
                let service = columnText(stmt, index: 0)
                let client = columnText(stmt, index: 1)
                let clientType = Int(sqlite3_column_int(stmt, 2))
                let authValue = Int(sqlite3_column_int(stmt, 3))
                let authReason = Int(sqlite3_column_int(stmt, 4))
                let indirectObject = columnText(stmt, index: 5)
                let flags = Int(sqlite3_column_int(stmt, 6))
                let lastModified = sqlite3_column_double(stmt, 7)

                let entry = TCCEntry(
                    service: service,
                    client: client,
                    clientType: clientType,
                    authValue: authValue,
                    authReason: authReason,
                    indirectObjectIdentifier: indirectObject,
                    flags: flags,
                    lastModified: lastModified,
                    source: source
                )
                entries.append(entry)

            } else if stepRC == SQLITE_DONE {
                break
            } else if stepRC == SQLITE_BUSY {
                // The database is locked by tccd — log and bail out;
                // we will retry on the next file-system notification.
                logger.info("TCC database at \(path) is busy — will retry on next change.")
                break
            } else {
                let msg = String(cString: sqlite3_errmsg(db))
                logger.warning("Unexpected step result on \(path): \(stepRC) — \(msg)")
                break
            }
        }

        return entries
    }

    /// Reads a text column from a prepared statement, returning an empty
    /// string if the column is NULL.
    private nonisolated func columnText(_ stmt: OpaquePointer, index: Int32) -> String {
        guard let cstr = sqlite3_column_text(stmt, index) else {
            return ""
        }
        return String(cString: cstr)
    }

    // MARK: - Bundle Resolution

    /// Attempts to resolve a bundle identifier to its on-disk path using
    /// `NSWorkspace` (via Launch Services).
    ///
    /// Returns an empty string if the bundle cannot be found.
    private nonisolated func resolveBundlePath(bundleId: String) -> String {
        // NSWorkspace.shared is main-actor-isolated on newer SDKs, so we
        // fall back to a file-system search of /Applications.
        if let url = findApplicationURL(bundleId: bundleId) {
            return url.path
        }
        return ""
    }

    /// Searches common application directories for a bundle matching the
    /// given identifier. This avoids requiring main-actor access.
    private nonisolated func findApplicationURL(bundleId: String) -> URL? {
        // `/Applications` is root:admin 0775 on supported macOS releases, so
        // local admins control its entries. Enumerate it through the same
        // descriptor-pinned bounded boundary as user homes. System application
        // roots are protected by SIP and remain separately classified.
        if let snapshot = Self.boundedApplicationEntries(
            at: "/Applications",
            maximumEntries: Self.maxApplicationDirectoryEntries,
            expectedDirectoryOwnerUID: 0
        ), let match = findApplicationURL(
            bundleId: bundleId,
            directory: "/Applications",
            names: snapshot.entries.compactMap {
                $0.kind == .directory ? $0.name : nil
            }
        ) {
            return match
        }

        let trustedSystemDirs = [
            "/System/Applications",
            "/System/Applications/Utilities",
        ]
        let fm = FileManager.default

        for dir in trustedSystemDirs {
            guard let contents = try? fm.contentsOfDirectory(
                at: URL(fileURLWithPath: dir),
                includingPropertiesForKeys: nil,
                options: [.skipsHiddenFiles]
            ) else {
                continue
            }

            if let match = findApplicationURL(
                bundleId: bundleId,
                directory: dir,
                names: contents.map(\.lastPathComponent)
            ) {
                return match
            }
        }

        return nil
    }

    static func boundedApplicationEntries(
        at path: String,
        maximumEntries: Int,
        expectedDirectoryOwnerUID: UInt32
    ) -> BoundedDirectoryLister.Snapshot? {
        BoundedDirectoryLister.list(
            at: path,
            maximumEntries: maximumEntries,
            expectedOwnerUID: expectedDirectoryOwnerUID
        )
    }

    private nonisolated func findApplicationURL(
        bundleId: String,
        directory: String,
        names: [String]
    ) -> URL? {
        for name in names where name.hasSuffix(".app") {
            let url = URL(fileURLWithPath: directory).appendingPathComponent(name)
            let plistURL = url.appendingPathComponent("Contents/Info.plist")
            guard let data = BoundedRegularFileReader.read(
                      at: plistURL.path,
                      maximumBytes: Self.maxApplicationInfoPlistBytes
                  ),
                  let plist = try? PropertyListSerialization.propertyList(
                    from: data, format: nil
                  ) as? [String: Any],
                  let cfBundleId = plist["CFBundleIdentifier"] as? String,
                  cfBundleId == bundleId else {
                continue
            }
            return url
        }
        return nil
    }
}
