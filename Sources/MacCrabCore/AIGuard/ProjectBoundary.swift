// ProjectBoundary.swift
// MacCrabCore
//
// Enforces project directory boundaries for AI coding tool sessions.
// When an AI tool starts in a project directory, all file writes by its
// children should stay within that directory tree. Writes outside the
// boundary indicate scope creep, prompt injection, or misconfiguration.

import Foundation
import Darwin
import os.log

/// Enforces that AI tool file operations stay within the project directory.
///
/// Tracks the working directory where each AI tool session started and
/// alerts when child processes write files outside that boundary.
public actor ProjectBoundary {

    private let logger = Logger(subsystem: "com.maccrab", category: "project-boundary")
    private let monotonicNow: @Sendable () -> TimeInterval

    /// A boundary violation is returned to the detection pipeline on every
    /// occurrence. Unified-log emission is only diagnostic and must not become
    /// a second file-event firehose. The installed rc.5 run produced these at
    /// event rate; one global summary per interval preserves notice without
    /// spending CPU/disk on thousands of duplicate strings.
    private static let violationLogInterval: TimeInterval = 30
    private var lastViolationLogTick: TimeInterval?
    private var suppressedSinceLastViolationLog: UInt64 = 0

    private var checksTotal: UInt64 = 0
    private var allowedTotal: UInt64 = 0
    private var unboundTotal: UInt64 = 0
    private var violationsTotal: UInt64 = 0
    private var violationLogsEmittedTotal: UInt64 = 0
    private var violationLogsSuppressedTotal: UInt64 = 0

    /// Normalised file-event actions that can alter filesystem state and are
    /// therefore meaningful boundary inputs. OPEN is deliberately absent:
    /// ProjectBoundary enforces modification scope, not read scope. Callback
    /// demand and EventLoop both consume this owner-defined set so a newly
    /// supported mutation cannot land at only one layer.
    public nonisolated static let mutationEventActions: Set<String> = [
        "create", "write", "close_modified", "rename", "unlink", "link",
        "setmode", "setowner",
    ]

    /// Known safe directories that AI tools may write to outside the project.
    private static let globalExceptions: [String] = [
        "/tmp/",
        "/private/tmp/",
        "/var/folders/",              // macOS temp dirs
        "/.npm/",                     // npm cache
        "/.cache/",                   // General cache
        "/Library/Caches/",           // macOS caches
        "/.local/share/pnpm/",        // pnpm cache
        "/node_modules/.cache/",      // Build caches
        "/.cargo/registry/",          // Cargo cache
        "/.rustup/",                  // Rust toolchain
        "/.pyenv/",                   // Python version manager
        "/.nvm/",                     // Node version manager
        "/target/debug/",             // Rust build output
        "/build/",                    // Generic build dirs
        "/.build/",                   // Swift build dir
        "/dist/",                     // Distribution output
    ]

    /// Always-allowed exact device paths. Writes to `/dev/null`, `/dev/urandom`,
    /// and `/dev/random` are legitimate I/O sinks used by virtually every CLI
    /// tool an AI agent invokes (`cmd > /dev/null`, entropy reads). Exact-match
    /// to avoid widening the substring exception surface.
    private static let allowedDevicePaths: Set<String> = [
        "/dev/null",
        "/dev/urandom",
        "/dev/random",
        "/dev/zero",
    ]

    /// Pure owner-side exception contract shared with pre-callback dynamic
    /// demand. These paths can never produce a ProjectBoundary violation for
    /// any AI process, so unknown/stale PID state need not re-admit the build /
    /// temp firehose merely to remain fail-open elsewhere.
    public nonisolated static func isDefaultGloballyAllowed(filePath: String) -> Bool {
        let normalized = (filePath as NSString).standardizingPath
        if allowedDevicePaths.contains(normalized) { return true }
        return globalExceptions.contains { normalized.contains($0) }
    }

    /// Custom exception paths (user-configurable).
    private var customExceptions: [String] = []

    private struct BoundaryRecord: Sendable {
        var projectDirectory: String
        var sessionGeneration: UInt64?
        var processStartIdentity: UInt64?
    }

    /// Active project boundaries keyed by AI session PID. The optional tracker
    /// generation is attached after ordered root registration and makes
    /// maintenance removal a CAS rather than a PID-only delete.
    private var boundaries: [Int32: BoundaryRecord] = [:]

    /// Defense-in-depth bound. This leaves headroom above the tracker's shared
    /// root census for the boundary-first registration transaction while still
    /// preventing standalone callers or stale state from growing forever.
    private let maximumBoundaries: Int
    private static let hardMaximumBoundaries = 128
    private var registrationCapacityRejectionsTotal: UInt64 = 0
    private var generationCASMissesTotal: UInt64 = 0

    /// PIDs whose boundary registration has already been rejected, so the
    /// rejection is logged at most once per PID.
    ///
    /// `registerBoundary` is called from the event loop for EVERY event whose
    /// subject is an AI tool (EventLoop.swift:169) — not only on exec — and the
    /// shipping Endpoint Security path never populates
    /// `ProcessInfo.workingDirectory` (ESHelpers.swift:138 hardcodes ""), so a
    /// single long-lived `claude` process re-enters the reject path thousands
    /// of times an hour. Measured on a dev host: 34,719 warning-level
    /// unified-log records in one hour (9.6/s sustained, ~830K/day) from this
    /// one call site — polluting the persistent log store operators are told to
    /// read for diagnostics, and paying its own disk-write and CPU cost.
    private struct RejectedRegistration: Sendable {
        let processStartIdentity: UInt64?
    }
    private var rejectedPids: [Int32: RejectedRegistration] = [:]

    /// Upper bound on `rejectedPids` so a pid-churning workload cannot grow the
    /// memo without limit. On overflow the whole set is dropped; the worst case
    /// is one extra debug line per still-live rejected PID.
    private static let maxRejectedPids = 4096

    // MARK: - Initialization

    public init(
        customExceptions: [String] = [],
        maximumBoundaries: Int = 128
    ) {
        self.customExceptions = customExceptions
        self.maximumBoundaries = max(
            0,
            min(maximumBoundaries, Self.hardMaximumBoundaries)
        )
        self.monotonicNow = { Foundation.ProcessInfo.processInfo.systemUptime }
    }

    /// Deterministic clock seam for log-amplification tests.
    init(
        customExceptions: [String] = [],
        maximumBoundaries: Int = 128,
        monotonicNow: @escaping @Sendable () -> TimeInterval
    ) {
        self.customExceptions = customExceptions
        self.maximumBoundaries = max(
            0,
            min(maximumBoundaries, Self.hardMaximumBoundaries)
        )
        self.monotonicNow = monotonicNow
    }

    // MARK: - Public API

    /// Register a project boundary for an AI session.
    ///
    /// Returns `true` if the boundary was accepted, `false` if `projectDir`
    /// is invalid (empty, whitespace-only, or filesystem root). A boundary
    /// at `/` would make every write outside `//` (impossible) look like a
    /// violation — `hasPrefix("//")` never matches a real path — so the
    /// rule fired on every AI file write. Reject up-front instead.
    ///
    /// `resolveLiveCWDIfEmpty` covers the shipping Endpoint Security path,
    /// which never carries a working directory (ESHelpers.swift:138 hardcodes
    /// `""` because `es_process_t` has no cwd field). Without it EVERY
    /// registration from that source is rejected, and `checkWrite` treats "no
    /// boundary registered" as allowed — so the whole project-boundary control
    /// is inert on release builds, not merely for sessions that predate the
    /// daemon. Off by default so this stays a pure value check for callers that
    /// already hold a directory, and so tests do not depend on which PIDs
    /// happen to be alive on the host.
    @discardableResult
    public func registerBoundary(
        aiPid: Int32,
        projectDir: String,
        resolveLiveCWDIfEmpty: Bool = false,
        processStartIdentity: UInt64? = nil
    ) -> Bool {
        // A known new birth identity invalidates both a stale accepted root and
        // the once-per-PID rejection memo. Unknown evidence never does.
        if let processStartIdentity,
           let existingStart = boundaries[aiPid]?.processStartIdentity,
           processStartIdentity != existingStart {
            boundaries.removeValue(forKey: aiPid)
            rejectedPids.removeValue(forKey: aiPid)
        }
        if let processStartIdentity,
           let rejected = rejectedPids[aiPid],
           rejected.processStartIdentity != processStartIdentity {
            rejectedPids.removeValue(forKey: aiPid)
        }

        // One process lifetime owns one immutable project root. Repeated direct
        // root events may carry a different cwd after the tool itself `chdir`s;
        // accepting that value here would make enforcement disagree with the
        // tracker and callback snapshot. A proven path replacement is removed
        // by the lifecycle coordinator first, and a proven birth replacement
        // was removed above, so any record still present is the same lifetime.
        if boundaries[aiPid] != nil {
            if boundaries[aiPid]?.processStartIdentity == nil {
                boundaries[aiPid]?.processStartIdentity = processStartIdentity
            }
            rejectedPids.removeValue(forKey: aiPid)
            return true
        }

        var candidate = projectDir.trimmingCharacters(in: .whitespacesAndNewlines)
        if candidate.isEmpty {
            // A caller that supplies nothing and does not opt in is rejected
            // exactly as before — only the resolution path below is new.
            guard resolveLiveCWDIfEmpty else {
                logRejectionOnce(
                    aiPid,
                    "empty project boundary (this event source supplies no working directory)",
                    processStartIdentity: processStartIdentity
                )
                return false
            }
            // This runs from the event loop for EVERY event whose subject is an
            // AI tool, so neither a re-resolve nor a retry may land per event:
            // an already-registered PID is done, and a PID that failed to
            // resolve once (exited, or not readable by this uid) will not start
            // resolving later.
            if rejectedPids[aiPid] != nil { return false }
            candidate = Self.currentWorkingDirectory(ofPID: aiPid) ?? ""
        }
        guard !candidate.isEmpty else {
            logRejectionOnce(
                aiPid,
                "empty project boundary (no working directory on the event and the live process could not be read)",
                processStartIdentity: processStartIdentity
            )
            return false
        }
        // Reject filesystem root and bare `//`. Normalising via NSString here
        // (rather than later in checkWrite) keeps the rejection path cheap
        // and avoids storing a value we'll never accept matches against.
        let normalized = (candidate as NSString).standardizingPath
        if normalized == "/" || normalized.isEmpty {
            logRejectionOnce(
                aiPid,
                "filesystem-root project boundary (every write would appear outside the boundary)",
                processStartIdentity: processStartIdentity
            )
            return false
        }
        guard normalized.utf8.count < Int(MAXPATHLEN) else {
            logRejectionOnce(
                aiPid,
                "project boundary longer than the callback-safe macOS path bound",
                processStartIdentity: processStartIdentity
            )
            return false
        }
        guard boundaries.count < maximumBoundaries else {
            Self.incrementSaturating(&registrationCapacityRejectionsTotal)
            logRejectionOnce(
                aiPid,
                "project boundary because the fixed \(maximumBoundaries)-root capacity is full",
                processStartIdentity: processStartIdentity
            )
            return false
        }

        // Store the value that was actually validated: identical to the
        // argument apart from surrounding whitespace, plus the resolved cwd on
        // the ES path.
        boundaries[aiPid] = BoundaryRecord(
            projectDirectory: candidate,
            sessionGeneration: nil,
            processStartIdentity: processStartIdentity
        )
        // A PID that previously failed to register and now succeeds must be
        // able to log again if it later regresses.
        rejectedPids.removeValue(forKey: aiPid)
        logger.info("Project boundary set: PID \(aiPid) → \(candidate)")
        return true
    }

    /// Return the project directory accepted for this AI root.
    ///
    /// Endpoint Security does not provide a working directory, so
    /// `registerBoundary` may resolve the live process cwd instead of storing
    /// the caller's (empty) value. Downstream AI features must consume this
    /// accepted value rather than independently carrying the empty ES field;
    /// otherwise boundary enforcement, lineage, attribution, and callback
    /// demand disagree about which project the session owns.
    public func projectDirectory(aiPid: Int32) -> String? {
        boundaries[aiPid]?.projectDirectory
    }

    /// Attach the AIProcessTracker lifetime to the boundary-first registration.
    /// Returns false only when registration was rejected and no boundary exists.
    @discardableResult
    public func associateSession(
        aiPid: Int32,
        generation: UInt64,
        processStartIdentity: UInt64?
    ) -> Bool {
        guard boundaries[aiPid] != nil else { return false }
        boundaries[aiPid]?.sessionGeneration = generation
        if boundaries[aiPid]?.processStartIdentity == nil {
            boundaries[aiPid]?.processStartIdentity = processStartIdentity
        }
        return true
    }

    /// Working directory of a live process, or nil if it exited or this caller
    /// cannot read it. `PROC_PIDVNODEPATHINFO` needs root or a same-uid target:
    /// the shipping engine is root inside the System Extension, and the
    /// non-root dev daemon is same-uid with the AI tools it watches.
    private static func currentWorkingDirectory(ofPID pid: Int32) -> String? {
        var info = proc_vnodepathinfo()
        let size = Int32(MemoryLayout<proc_vnodepathinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &info, size) == size else { return nil }
        let path = withUnsafeBytes(of: &info.pvi_cdir.vip_path) { raw -> String in
            guard let base = raw.baseAddress?.assumingMemoryBound(to: CChar.self) else { return "" }
            return String(cString: base)
        }
        return path.isEmpty ? nil : path
    }

    /// Remove a boundary when the AI session ends.
    @discardableResult
    public func removeBoundary(
        aiPid: Int32,
        matchingSessionGeneration: UInt64? = nil
    ) -> Bool {
        guard let record = boundaries[aiPid] else {
            rejectedPids.removeValue(forKey: aiPid)
            return false
        }
        if let matchingSessionGeneration,
           record.sessionGeneration != matchingSessionGeneration {
            Self.incrementSaturating(&generationCASMissesTotal)
            return false
        }
        let removed = boundaries.removeValue(forKey: aiPid) != nil
        rejectedPids.removeValue(forKey: aiPid)
        return removed
    }

    /// Log a boundary rejection at most once per PID, at debug level.
    ///
    /// Debug rather than warning: on the shipping ES path an absent working
    /// directory is the STRUCTURAL norm for every event, not a per-event
    /// anomaly, and warning-level records are persisted in the unified log
    /// store. The once-per-PID memo also skips the string interpolation on the
    /// repeat path, which is where essentially all of these calls land.
    private func logRejectionOnce(
        _ aiPid: Int32,
        _ reason: String,
        processStartIdentity: UInt64? = nil
    ) {
        if rejectedPids.count >= Self.maxRejectedPids { rejectedPids.removeAll() }
        guard rejectedPids[aiPid] == nil else { return }
        rejectedPids[aiPid] = RejectedRegistration(
            processStartIdentity: processStartIdentity
        )
        logger.debug("Rejecting \(reason) for PID \(aiPid)")
    }

    /// Check if a file write is within the project boundary.
    /// Returns nil if within bounds, or a violation description if outside.
    public func checkWrite(
        filePath: String,
        aiSessionPid: Int32,
        aiToolName: String
    ) -> BoundaryViolation? {
        Self.incrementSaturating(&checksTotal)
        guard let projectDir = boundaries[aiSessionPid]?.projectDirectory else {
            Self.incrementSaturating(&unboundTotal)
            return nil // No boundary registered
        }

        // Normalize paths
        let normalizedFile = (filePath as NSString).standardizingPath
        let normalizedProject = (projectDir as NSString).standardizingPath

        // Canonical default exceptions are shared with callback demand so the
        // two boundaries cannot disagree about temp/build/cache paths.
        if Self.isDefaultGloballyAllowed(filePath: normalizedFile) {
            Self.incrementSaturating(&allowedTotal)
            return nil
        }

        // Check if within project boundary
        if normalizedFile.hasPrefix(normalizedProject + "/") || normalizedFile == normalizedProject {
            Self.incrementSaturating(&allowedTotal)
            return nil // Within bounds
        }

        // Check exceptions
        for exception in customExceptions {
            if normalizedFile.contains(exception) {
                Self.incrementSaturating(&allowedTotal)
                return nil // Matches an exception
            }
        }

        // This is a boundary violation
        let violation = BoundaryViolation(
            filePath: filePath,
            projectDir: projectDir,
            aiToolName: aiToolName,
            aiSessionPid: aiSessionPid,
            description: "\(aiToolName) child wrote file OUTSIDE project boundary. " +
                "File: \(filePath). Project: \(projectDir). " +
                "This may indicate prompt injection causing the AI to modify files " +
                "outside the intended project scope."
        )

        Self.incrementSaturating(&violationsTotal)
        let tick = monotonicNow()
        if lastViolationLogTick.map({ tick - $0 >= Self.violationLogInterval })
            ?? true {
            Self.incrementSaturating(&violationLogsEmittedTotal)
            let suppressed = suppressedSinceLastViolationLog
            suppressedSinceLastViolationLog = 0
            lastViolationLogTick = tick
            logger.warning("Boundary violation: \(filePath) outside \(projectDir); total=\(self.violationsTotal), duplicate_logs_suppressed=\(suppressed)")
        } else {
            Self.incrementSaturating(&violationLogsSuppressedTotal)
            Self.incrementSaturating(&suppressedSinceLastViolationLog)
        }
        return violation
    }

    /// Get active boundaries count.
    public var boundaryCount: Int { boundaries.count }

    public struct Telemetry: Sendable, Equatable {
        public let maximumBoundaries: Int
        public let activeBoundaries: Int
        public let checksTotal: UInt64
        public let allowedTotal: UInt64
        public let unboundTotal: UInt64
        public let violationsTotal: UInt64
        public let violationLogsEmittedTotal: UInt64
        public let violationLogsSuppressedTotal: UInt64
        public let registrationCapacityRejectionsTotal: UInt64
        public let generationCASMissesTotal: UInt64
    }

    /// Fixed-cardinality, content-free accounting. Conservation:
    /// `checks = allowed + unbound + violations`.
    public func telemetry() -> Telemetry {
        Telemetry(
            maximumBoundaries: maximumBoundaries,
            activeBoundaries: boundaries.count,
            checksTotal: checksTotal,
            allowedTotal: allowedTotal,
            unboundTotal: unboundTotal,
            violationsTotal: violationsTotal,
            violationLogsEmittedTotal: violationLogsEmittedTotal,
            violationLogsSuppressedTotal: violationLogsSuppressedTotal,
            registrationCapacityRejectionsTotal:
                registrationCapacityRejectionsTotal,
            generationCASMissesTotal: generationCASMissesTotal
        )
    }

    private nonisolated static func incrementSaturating(_ value: inout UInt64) {
        if value < UInt64.max { value += 1 }
    }

    // MARK: - Types

    public struct BoundaryViolation: Sendable {
        public let filePath: String
        public let projectDir: String
        public let aiToolName: String
        public let aiSessionPid: Int32
        public let description: String
    }
}
