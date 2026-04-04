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

        logger.info("AI session started: \(type.rawValue) (PID \(pid)) in \(projectDir)")
    }

    /// Check if a process is a child of an active AI session.
    /// Returns the tool type and project directory if it is.
    public func isAIChild(pid: Int32, ancestors: [ProcessAncestor]) -> (isChild: Bool, toolType: AIToolType?, projectDir: String?) {
        // Direct lookup
        if let sessionPid = childToSession[pid], let session = sessions[sessionPid] {
            return (true, session.toolType, session.projectDir)
        }

        // Walk provided ancestry to find AI tool parent
        let ancestors = ancestors
        for ancestor in ancestors {
            if let session = sessions[ancestor.pid] {
                // Register this child for fast future lookups
                childToSession[pid] = ancestor.pid
                sessions[ancestor.pid]?.childPids.insert(pid)
                return (true, session.toolType, session.projectDir)
            }
        }

        // Check if any ancestor matches AI tool patterns
        let (isChild, toolType) = registry.isAIChildProcess(ancestors: ancestors)
        if isChild, let tool = toolType {
            // Found an AI ancestor not yet registered — register it
            if let aiAncestor = ancestors.first(where: { registry.isAITool(executablePath: $0.executable) != nil }) {
                // Register inline (same actor, no await needed)
                if sessions[aiAncestor.pid] == nil {
                    sessions[aiAncestor.pid] = AISession(
                        aiPid: aiAncestor.pid, toolType: tool, projectDir: "",
                        startTime: Date(), childPids: [], filesWritten: [],
                        filesRead: [], networkConnections: [], alertCount: 0
                    )
                }
                childToSession[pid] = aiAncestor.pid
                sessions[aiAncestor.pid]?.childPids.insert(pid)
            }
            return (true, toolType, sessions[childToSession[pid] ?? 0]?.projectDir)
        }

        return (false, nil, nil)
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
}
