// ProcessHasher.swift
// MacCrabCore
//
// Combines FileHasher (SHA-256 of the executable on disk) with
// CDHashExtractor (SHA-1 CDHash via proc_pidinfo) to produce the
// full hash fingerprint for a running process.

import Foundation
import os.log

/// Actor that fingerprints a process by combining its executable file hash
/// with the macOS code-signing CDHash.
///
/// SHA-256 identifies the on-disk bytes (useful for reputation lookups,
/// YARA-like matching, MISP IoC feeds). CDHash identifies the code signature
/// (useful for Apple's notarization + signing authority records). Both are
/// typically wanted in enrichment.
public actor ProcessHasher {

    /// Combined hash fingerprint for a process.
    public struct ProcessHash: Sendable, Equatable {
        public let sha256: String?
        public let cdhash: String?

        public init(sha256: String?, cdhash: String?) {
            self.sha256 = sha256
            self.cdhash = cdhash
        }

        /// True iff at least one hash was produced.
        public var hasAny: Bool { sha256 != nil || cdhash != nil }
    }

    private let logger = Logger(subsystem: "com.maccrab.enrichment", category: "process-hasher")
    private let fileHasher: FileHasher
    private let cdHashExtractor: CDHashExtractor

    // MARK: - Init

    /// Creates a ProcessHasher with the given dependencies.
    ///
    /// Defaults create fresh instances — callers that share enrichment state
    /// across collectors should pass in the shared instances.
    public init(
        fileHasher: FileHasher = FileHasher(),
        cdHashExtractor: CDHashExtractor = CDHashExtractor()
    ) {
        self.fileHasher = fileHasher
        self.cdHashExtractor = cdHashExtractor
    }

    // MARK: - Public API

    /// Fingerprint a process by PID + executable path.
    ///
    /// Runs the two hashes concurrently. Either can return `nil`:
    /// - SHA-256 nil → file missing, over size cap, on a network mount, or I/O error.
    /// - CDHash nil → process not running, not code-signed, or csops unavailable.
    public func hash(pid: Int32, executablePath: String) async -> ProcessHash {
        async let sha256 = fileHasher.hash(path: executablePath)
        async let cdhash = cdHashExtractor.extractCDHash(pid: pid)
        return ProcessHash(sha256: await sha256, cdhash: await cdhash)
    }

    /// Fingerprint an executable on disk only (no running process required).
    /// Useful for quarantine + offline analysis flows.
    public func hashFile(path: String) async -> String? {
        await fileHasher.hash(path: path)
    }

    /// Underlying FileHasher (for sharing across collectors).
    public func underlyingFileHasher() -> FileHasher { fileHasher }
}
