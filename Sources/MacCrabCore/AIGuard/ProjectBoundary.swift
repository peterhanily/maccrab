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

    /// Custom exception paths (user-configurable).
    private var customExceptions: [String] = []

    /// Active project boundaries keyed by AI session PID.
    private var boundaries: [Int32: String] = [:]

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
    private var rejectedPids: Set<Int32> = []

    /// Upper bound on `rejectedPids` so a pid-churning workload cannot grow the
    /// memo without limit. On overflow the whole set is dropped; the worst case
    /// is one extra debug line per still-live rejected PID.
    private static let maxRejectedPids = 4096

    // MARK: - Initialization

    public init(customExceptions: [String] = []) {
        self.customExceptions = customExceptions
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
        resolveLiveCWDIfEmpty: Bool = false
    ) -> Bool {
        var candidate = projectDir.trimmingCharacters(in: .whitespacesAndNewlines)
        if candidate.isEmpty {
            // A caller that supplies nothing and does not opt in is rejected
            // exactly as before — only the resolution path below is new.
            guard resolveLiveCWDIfEmpty else {
                logRejectionOnce(aiPid, "empty project boundary (this event source supplies no working directory)")
                return false
            }
            // This runs from the event loop for EVERY event whose subject is an
            // AI tool, so neither a re-resolve nor a retry may land per event:
            // an already-registered PID is done, and a PID that failed to
            // resolve once (exited, or not readable by this uid) will not start
            // resolving later.
            if boundaries[aiPid] != nil { return true }
            if rejectedPids.contains(aiPid) { return false }
            candidate = Self.currentWorkingDirectory(ofPID: aiPid) ?? ""
        }
        guard !candidate.isEmpty else {
            logRejectionOnce(aiPid, "empty project boundary (no working directory on the event and the live process could not be read)")
            return false
        }
        // Reject filesystem root and bare `//`. Normalising via NSString here
        // (rather than later in checkWrite) keeps the rejection path cheap
        // and avoids storing a value we'll never accept matches against.
        let normalized = (candidate as NSString).standardizingPath
        if normalized == "/" || normalized.isEmpty {
            logRejectionOnce(aiPid, "filesystem-root project boundary (every write would appear outside the boundary)")
            return false
        }
        // Store the value that was actually validated: identical to the
        // argument apart from surrounding whitespace, plus the resolved cwd on
        // the ES path.
        boundaries[aiPid] = candidate
        // A PID that previously failed to register and now succeeds must be
        // able to log again if it later regresses.
        rejectedPids.remove(aiPid)
        logger.info("Project boundary set: PID \(aiPid) → \(candidate)")
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
    public func removeBoundary(aiPid: Int32) {
        boundaries.removeValue(forKey: aiPid)
        rejectedPids.remove(aiPid)
    }

    /// Log a boundary rejection at most once per PID, at debug level.
    ///
    /// Debug rather than warning: on the shipping ES path an absent working
    /// directory is the STRUCTURAL norm for every event, not a per-event
    /// anomaly, and warning-level records are persisted in the unified log
    /// store. The once-per-PID memo also skips the string interpolation on the
    /// repeat path, which is where essentially all of these calls land.
    private func logRejectionOnce(_ aiPid: Int32, _ reason: String) {
        if rejectedPids.count >= Self.maxRejectedPids { rejectedPids.removeAll() }
        guard rejectedPids.insert(aiPid).inserted else { return }
        logger.debug("Rejecting \(reason) for PID \(aiPid)")
    }

    /// Check if a file write is within the project boundary.
    /// Returns nil if within bounds, or a violation description if outside.
    public func checkWrite(
        filePath: String,
        aiSessionPid: Int32,
        aiToolName: String
    ) -> BoundaryViolation? {
        guard let projectDir = boundaries[aiSessionPid] else {
            return nil // No boundary registered
        }

        // Normalize paths
        let normalizedFile = (filePath as NSString).standardizingPath
        let normalizedProject = (projectDir as NSString).standardizingPath

        // Always-allowed device sinks (/dev/null etc.) — every CLI tool an AI
        // agent runs redirects to these; they are not "outside the project"
        // in any meaningful sense.
        if Self.allowedDevicePaths.contains(normalizedFile) {
            return nil
        }

        // Check if within project boundary
        if normalizedFile.hasPrefix(normalizedProject + "/") || normalizedFile == normalizedProject {
            return nil // Within bounds
        }

        // Check exceptions
        let allExceptions = Self.globalExceptions + customExceptions
        for exception in allExceptions {
            if normalizedFile.contains(exception) {
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

        logger.warning("Boundary violation: \(filePath) outside \(projectDir)")
        return violation
    }

    /// Get active boundaries count.
    public var boundaryCount: Int { boundaries.count }

    // MARK: - Types

    public struct BoundaryViolation: Sendable {
        public let filePath: String
        public let projectDir: String
        public let aiToolName: String
        public let aiSessionPid: Int32
        public let description: String
    }
}
