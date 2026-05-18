// ProjectBoundary.swift
// MacCrabCore
//
// Enforces project directory boundaries for AI coding tool sessions.
// When an AI tool starts in a project directory, all file writes by its
// children should stay within that directory tree. Writes outside the
// boundary indicate scope creep, prompt injection, or misconfiguration.

import Foundation
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
    @discardableResult
    public func registerBoundary(aiPid: Int32, projectDir: String) -> Bool {
        let trimmed = projectDir.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            logger.warning("Rejecting empty project boundary for PID \(aiPid)")
            return false
        }
        // Reject filesystem root and bare `//`. Normalising via NSString here
        // (rather than later in checkWrite) keeps the rejection path cheap
        // and avoids storing a value we'll never accept matches against.
        let normalized = (trimmed as NSString).standardizingPath
        if normalized == "/" || normalized.isEmpty {
            logger.warning("Rejecting filesystem-root project boundary for PID \(aiPid) (every write would appear outside the boundary)")
            return false
        }
        boundaries[aiPid] = projectDir
        logger.info("Project boundary set: PID \(aiPid) → \(projectDir)")
        return true
    }

    /// Remove a boundary when the AI session ends.
    public func removeBoundary(aiPid: Int32) {
        boundaries.removeValue(forKey: aiPid)
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
