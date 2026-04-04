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
import SQLite3
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
struct TCCEntry: Hashable, Sendable {
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

    // MARK: - Database Paths

    /// Path to the system-wide TCC database.
    private static let systemDBPath =
        "/Library/Application Support/com.apple.TCC/TCC.db"

    /// Path to the current user's TCC database.
    private static var userDBPath: String {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return "\(home)/Library/Application Support/com.apple.TCC/TCC.db"
    }

    // MARK: - Properties

    private let logger = Logger(subsystem: "com.maccrab.core", category: "TCCMonitor")
    private var continuation: AsyncStream<Event>.Continuation?
    private var isRunning = false

    /// Current snapshot of all TCC entries, keyed by identity.
    private var snapshot: [String: TCCEntry] = [:]

    /// File descriptors and dispatch sources for watching database files.
    private var watchSources: [DispatchSourceFileSystemObject] = []
    private var watchFileDescriptors: [Int32] = []

    /// Debounce interval to coalesce rapid database writes (in seconds).
    private let debounceInterval: TimeInterval = 0.5

    /// Tracks the last time a change was processed to implement debouncing.
    private var lastChangeTime: Date = .distantPast

    /// The asynchronous stream of normalised events.
    public nonisolated let events: AsyncStream<Event>

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
        var capturedContinuation: AsyncStream<Event>.Continuation!
        self.events = AsyncStream<Event>(bufferingPolicy: .bufferingNewest(256)) { continuation in
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
        guard !isRunning else {
            logger.warning("TCCMonitor.start() called but monitor is already running.")
            return
        }
        isRunning = true

        // Take the initial snapshot
        snapshot = readAllEntries()
        logger.info("TCCMonitor started — initial snapshot has \(self.snapshot.count) entries.")

        // Install file watchers
        installWatcher(path: Self.systemDBPath, label: "system")
        installWatcher(path: Self.userDBPath, label: "user")
    }

    /// Stops monitoring and finishes the event stream.
    public func stop() {
        guard isRunning else { return }
        isRunning = false

        // Tear down dispatch sources
        for source in watchSources {
            source.cancel()
        }
        watchSources.removeAll()

        for fd in watchFileDescriptors {
            Darwin.close(fd)
        }
        watchFileDescriptors.removeAll()

        continuation?.finish()
        continuation = nil

        logger.info("TCCMonitor stopped.")
    }

    // MARK: - File Watching

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

        source.setEventHandler { [weak self] in
            guard let self else { return }
            Task {
                await self.handleDatabaseChange()
            }
        }

        source.setCancelHandler {
            // File descriptor is closed in stop()
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
    private func handleDatabaseChange() {
        let now = Date()
        guard now.timeIntervalSince(lastChangeTime) >= debounceInterval else {
            return
        }
        lastChangeTime = now

        let currentEntries = readAllEntries()
        let previousEntries = snapshot

        // Detect new or changed grants
        for (key, entry) in currentEntries {
            if let previous = previousEntries[key] {
                // Entry exists in both — check if the auth value changed
                if previous.authValue != entry.authValue {
                    emitEvent(entry: entry, previousAuthValue: previous.authValue)
                }
            } else {
                // Brand new entry
                emitEvent(entry: entry, previousAuthValue: nil)
            }
        }

        // Detect revocations (entries that were removed entirely)
        for (key, previousEntry) in previousEntries {
            if currentEntries[key] == nil {
                emitRevocationEvent(entry: previousEntry)
            }
        }

        // Update the snapshot
        snapshot = currentEntries
    }

    // MARK: - Event Emission

    /// Emits an event for a new or changed TCC entry.
    private func emitEvent(entry: TCCEntry, previousAuthValue: Int?) {
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

        let event = buildEvent(
            entry: entry,
            eventType: eventType,
            eventAction: eventAction,
            allowed: allowed,
            previousAuthValue: previousAuthValue
        )

        continuation?.yield(event)

        let sourceLabel = entry.source
        logger.info(
            "TCC \(eventAction): service=\(entry.service) client=\(entry.client) source=\(sourceLabel)"
        )
    }

    /// Emits a revocation event for an entry that was removed from the database.
    private func emitRevocationEvent(entry: TCCEntry) {
        let event = buildEvent(
            entry: entry,
            eventType: .deletion,
            eventAction: "tcc_revoke",
            allowed: false,
            previousAuthValue: entry.authValue
        )

        continuation?.yield(event)

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
    ) -> Event {
        let authReasonString = Self.authReasonNames[entry.authReason] ?? "reason_\(entry.authReason)"

        // Resolve the client path if the client type indicates an absolute path
        let clientPath: String
        if entry.clientType == 1 {
            clientPath = entry.client
        } else {
            // Bundle identifier — attempt to resolve via Launch Services
            clientPath = resolveBundlePath(bundleId: entry.client)
        }

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
            startTime: Date(timeIntervalSince1970: entry.lastModified)
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
    private func readAllEntries() -> [String: TCCEntry] {
        var entries: [String: TCCEntry] = [:]

        for (path, source) in [(Self.systemDBPath, "system"), (Self.userDBPath, "user")] {
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
    private func readDatabase(path: String, source: String) -> [TCCEntry] {
        guard FileManager.default.fileExists(atPath: path) else {
            logger.debug("TCC database not found at \(path) — skipping.")
            return []
        }

        var db: OpaquePointer?
        let flags = SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX
        let rc = sqlite3_open_v2(path, &db, flags, nil)
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
    private func columnText(_ stmt: OpaquePointer, index: Int32) -> String {
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
    private func resolveBundlePath(bundleId: String) -> String {
        // NSWorkspace.shared is main-actor-isolated on newer SDKs, so we
        // fall back to a file-system search of /Applications.
        if let url = findApplicationURL(bundleId: bundleId) {
            return url.path
        }
        return ""
    }

    /// Searches common application directories for a bundle matching the
    /// given identifier. This avoids requiring main-actor access.
    private func findApplicationURL(bundleId: String) -> URL? {
        let searchDirs = [
            "/Applications",
            "/System/Applications",
            "/System/Applications/Utilities",
        ]
        let fm = FileManager.default

        for dir in searchDirs {
            guard let contents = try? fm.contentsOfDirectory(
                at: URL(fileURLWithPath: dir),
                includingPropertiesForKeys: nil,
                options: [.skipsHiddenFiles]
            ) else {
                continue
            }

            for url in contents where url.pathExtension == "app" {
                let plistURL = url.appendingPathComponent("Contents/Info.plist")
                guard let data = try? Data(contentsOf: plistURL),
                      let plist = try? PropertyListSerialization.propertyList(
                        from: data, format: nil
                      ) as? [String: Any],
                      let cfBundleId = plist["CFBundleIdentifier"] as? String,
                      cfBundleId == bundleId else {
                    continue
                }
                return url
            }
        }

        return nil
    }
}
