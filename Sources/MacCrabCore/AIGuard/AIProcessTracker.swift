// AIProcessTracker.swift
// MacCrabCore
//
// Tracks AI coding tool process trees. When an AI tool is detected,
// all its descendant processes are monitored with elevated scrutiny.

import Foundation
import os.log

/// Tracks active AI coding tool sessions and their subprocess trees.
///
/// When an AI tool (Claude Code, Codex, etc.) is identified, this tracker
/// records it as a "session" and marks all descendant processes as AI-spawned.
/// This enables MacCrab to apply AI-specific detection policies.
public actor AIProcessTracker {

    private let logger = Logger(subsystem: "com.maccrab", category: "ai-tracker")

    /// Active AI tool sessions.
    private var sessions: [Int32: AISession] = [:]

    /// Map from child PID → parent AI session PID (for fast lookup).
    private var childToSession: [Int32: Int32] = [:]

    /// Reference to process lineage for ancestry lookups.
    private let lineage: ProcessLineage

    /// The tool registry for identification.
    private let registry: AIToolRegistry

    // MARK: - Types

    /// An active AI coding tool session.
    public struct AISession: Sendable {
        public let aiPid: Int32
        public let toolType: AIToolType
        public let projectDir: String
        public let startTime: Date
        public var childPids: Set<Int32>
        public var filesWritten: [String]
        public var filesRead: [String]
        public var networkConnections: [(ip: String, port: UInt16)]
        public var alertCount: Int
    }

    // MARK: - Initialization

    public init(lineage: ProcessLineage, registry: AIToolRegistry = AIToolRegistry()) {
        self.lineage = lineage
        self.registry = registry
    }

    // MARK: - Public API

    /// Register an AI tool process.
    public func registerAIProcess(pid: Int32, type: AIToolType, projectDir: String) {
        guard sessions[pid] == nil else { return }

        sessions[pid] = AISession(
            aiPid: pid,
            toolType: type,
            projectDir: projectDir,
            startTime: Date(),
            childPids: [],
            filesWritten: [],
            filesRead: [],
            networkConnections: [],
            alertCount: 0
        )
        updateActiveSessionsFlag()

        logger.info("AI session started: \(type.rawValue) (PID \(pid)) in \(projectDir)")
    }

    /// SIP-protected / Apple-platform path prefixes. A binary running from one
    /// of these on a healthy system is Apple-shipped (SIP prevents writes), so
    /// it must NEVER be promoted to an AI-tool *root* — otherwise XProtect's
    /// `XProtectRemediatorMRTv3` and friends get mis-identified as "Claude Code"
    /// and every credential file they touch mints a false
    /// "Claude Code child process accessed credential" alert. Mirrors
    /// `NoiseFilter.isAppleSystemBinary`'s path arm (we only have the ancestor's
    /// path here, not a full `Event`).
    static func isApplePlatformPath(_ path: String) -> Bool {
        path.hasPrefix("/bin/") || path.hasPrefix("/sbin/")
            || path.hasPrefix("/usr/bin/") || path.hasPrefix("/usr/sbin/")
            || path.hasPrefix("/usr/libexec/")
            || path.hasPrefix("/System/")
            || path.hasPrefix("/Library/Apple/")
    }

    /// Check if a process is a child of an active AI session.
    /// Returns the tool type and project directory if it is.
    ///
    /// v1.19 (S1-T5): attribution now requires a GENUINE DIRECT-ANCESTOR
    /// lineage to the AI tool in the *passed* `ancestors` chain. Pre-fix this
    /// trusted any pid present in `childToSession` (a recycled pid reused by an
    /// unrelated process — e.g. an XProtect remediator — would inherit the AI
    /// attribution) and would promote ANY ancestor matching an AI pattern to a
    /// session root with no platform gate (so an Apple/SIP binary could become a
    /// fake "Claude Code" root). Both holes drove the false
    /// "Claude Code child process accessed credential" alerts the audit found.
    public func isAIChild(pid: Int32, ancestors: [ProcessAncestor]) -> (isChild: Bool, toolType: AIToolType?, projectDir: String?) {
        // (a) Cached attribution — only honored when the genuine ancestry STILL
        //     contains the recorded AI session pid. A recycled pid that landed
        //     in `childToSession` no longer descends from that session, so its
        //     ancestor chain won't contain `sessionPid`; we fall through and
        //     re-evaluate rather than returning a stale attribution.
        if let sessionPid = childToSession[pid],
           let session = sessions[sessionPid],
           ancestors.contains(where: { $0.pid == sessionPid }) {
            return (true, session.toolType, session.projectDir)
        }

        // Walk provided ancestry to find a registered AI-tool parent. This is a
        // genuine direct-lineage check by construction — the ancestor pid is in
        // THIS process's actual chain.
        for ancestor in ancestors {
            if let session = sessions[ancestor.pid] {
                // Register this child for fast future lookups
                childToSession[pid] = ancestor.pid
                sessions[ancestor.pid]?.childPids.insert(pid)
                return (true, session.toolType, session.projectDir)
            }
        }

        // Check if any ancestor matches AI tool patterns. (b) Skip Apple-
        // platform / SIP-path ancestors as ROOT candidates — XProtect, MRT, and
        // other Apple remediators must never be treated as an AI tool. Genuine
        // agent children (osascript/curl/bash spawned by a real agent) are NOT
        // affected: they are attributed via their non-Apple AI ANCESTOR, not by
        // being rejected here as children.
        if let aiAncestor = ancestors.first(where: {
            !Self.isApplePlatformPath($0.executable)
                && registry.isAITool(executablePath: $0.executable) != nil
        }), let tool = registry.isAITool(executablePath: aiAncestor.executable) {
            // Found a non-Apple AI ancestor not yet registered — register it.
            if sessions[aiAncestor.pid] == nil {
                sessions[aiAncestor.pid] = AISession(
                    aiPid: aiAncestor.pid, toolType: tool, projectDir: "",
                    startTime: Date(), childPids: [], filesWritten: [],
                    filesRead: [], networkConnections: [], alertCount: 0
                )
                updateActiveSessionsFlag()
            }
            childToSession[pid] = aiAncestor.pid
            sessions[aiAncestor.pid]?.childPids.insert(pid)
            return (true, tool, sessions[aiAncestor.pid]?.projectDir)
        }

        return (false, nil, nil)
    }

    /// v1.19 (S1-T5): evict a child→session mapping when the child process
    /// exits, so a later process that recycles the same pid can't inherit a
    /// stale AI attribution. Mirrors `MCPAttributor.processExited`. Also clears
    /// the entry from its parent session's `childPids` set. Cheap; safe to call
    /// on every ES exit event (no-op for unknown pids).
    public func processExited(pid: Int32) {
        if let sessionPid = childToSession.removeValue(forKey: pid) {
            sessions[sessionPid]?.childPids.remove(pid)
        }
        // If the exiting pid is itself an AI session root, tear the session down
        // (also clears its child mappings) — same effect as `removeSession`.
        if sessions[pid] != nil {
            removeSession(pid: pid)
        }
    }

    /// Record a file write by an AI session's child process.
    public func recordFileWrite(aiSessionPid: Int32, path: String) {
        sessions[aiSessionPid]?.filesWritten.append(path)
        // Cap at 1000 entries
        if let count = sessions[aiSessionPid]?.filesWritten.count, count > 1000 {
            sessions[aiSessionPid]?.filesWritten.removeFirst(500)
        }
    }

    /// Record a file read by an AI session's child process.
    public func recordFileRead(aiSessionPid: Int32, path: String) {
        sessions[aiSessionPid]?.filesRead.append(path)
        if let count = sessions[aiSessionPid]?.filesRead.count, count > 1000 {
            sessions[aiSessionPid]?.filesRead.removeFirst(500)
        }
    }

    /// Record a network connection from an AI session.
    public func recordConnection(aiSessionPid: Int32, ip: String, port: UInt16) {
        sessions[aiSessionPid]?.networkConnections.append((ip, port))
    }

    /// Increment alert count for a session.
    public func recordAlert(aiSessionPid: Int32) {
        sessions[aiSessionPid]?.alertCount += 1
    }

    /// Get all active AI sessions.
    public func activeSessions() -> [AISession] {
        Array(sessions.values)
    }

    /// Get a specific session.
    public func session(forPid pid: Int32) -> AISession? {
        sessions[pid]
    }

    /// Remove a session when the AI tool exits.
    public func removeSession(pid: Int32) {
        if let session = sessions[pid] {
            // Clean up child mappings
            for child in session.childPids {
                childToSession.removeValue(forKey: child)
            }
            sessions.removeValue(forKey: pid)
            updateActiveSessionsFlag()
            logger.info("AI session ended: \(session.toolType.rawValue) (PID \(pid)), \(session.alertCount) alerts")
        }
    }

    /// Prune sessions for processes that no longer exist.
    public func prune() async {
        for pid in sessions.keys {
            let exists = await lineage.contains(pid: pid)
            if !exists {
                removeSession(pid: pid)
            }
        }
    }

    /// Get session count.
    public var sessionCount: Int { sessions.count }

    // MARK: - v1.6.9 fast path
    //
    // `hasActiveSessionsHint` is a race-tolerant mirror of
    // `sessions.isEmpty` that the hot event loop can read WITHOUT
    // an actor hop. The event loop typically pays one actor hop per
    // event just to ask "is this process a child of an AI tool?";
    // when the answer is trivially no (no AI tools running —
    // majority of field installs), we want to short-circuit before
    // even making the hop. A stale read that's behind `sessions`
    // by one event is harmless — the next event will see the flag
    // true, and lineage bookkeeping continues correctly from there.
    //
    // Backed by `OSAllocatedUnfairLock<Bool>` so reads are lock-
    // protected without the overhead of full atomics. macOS 13.3+
    // API; MacCrab targets 13.0, but the lock is available as a
    // backport via the Combine runtime. For very old targets we'd
    // fall back to NSLock, but 13.3 has been the practical floor
    // across the v1.6.x run.
    public nonisolated var hasActiveSessionsHint: Bool {
        _hasActiveSessionsFlag.withLock { $0 }
    }

    private let _hasActiveSessionsFlag = OSAllocatedUnfairLock<Bool>(initialState: false)

    /// Called by the actor's own mutating methods after any change
    /// to `sessions`. Updates the nonisolated hint that
    /// `hasActiveSessionsHint` exposes.
    fileprivate func updateActiveSessionsFlag() {
        let nowEmpty = sessions.isEmpty
        _hasActiveSessionsFlag.withLock { $0 = !nowEmpty }
    }
}
