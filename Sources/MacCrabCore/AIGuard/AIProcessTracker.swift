// AIProcessTracker.swift
// MacCrabCore
//
// Tracks AI coding tool process trees. When an AI tool is detected,
// all its descendant processes are monitored with elevated scrutiny.

import Foundation
import os.log

/// Tracks active AI coding tool sessions and their subprocess trees.
///
/// All retained collections have hard bounds. Root identity includes a
/// tracker generation plus the executable/start evidence production has, so a
/// missed EXIT cannot let a recycled PID inherit an old AI session forever.
public actor AIProcessTracker {

    private let logger = Logger(subsystem: "com.maccrab", category: "ai-tracker")

    /// One root census across tracker and timeline owner. A larger tracker cap
    /// would make AgentLineageService continually evict still-active sessions
    /// and then recreate them on the next root event.
    public nonisolated static let defaultMaximumSessions =
        AgentLineageService.defaultMaxSessions

    /// Keep the complete canonical callback snapshot below its own hard demand
    /// bound even when future AI consumers are added. The 512 ceiling also
    /// leaves pattern/byte headroom and bounds tracker memory independently.
    public nonisolated static let defaultMaximumAttributedProcesses = min(
        512,
        FileEventInterestPolicyLimits.default.maximumDynamicDemands
            / max(1, AIFileEventConsumer.allCases.count)
    )
    private nonisolated static let hardMaximumChildrenPerSession = 256
    private nonisolated static let hardMaximumFileHistoryPerSession = 1_000
    private nonisolated static let hardMaximumNetworkHistoryPerSession = 256

    public struct SessionIdentity: Sendable, Hashable {
        public let pid: Int32
        public let generation: UInt64
        public let executablePathHash: UInt64?
        /// Whole kernel start second when the event source carries a real
        /// process birth time. `nil` means unknown, never "now".
        public let processStartIdentity: UInt64?
    }

    public enum RegistrationDisposition: Sendable, Equatable {
        case inserted
        case existing
        case replaced
        case rejectedCapacity
    }

    public struct RegistrationResult: Sendable {
        public let disposition: RegistrationDisposition
        public let identity: SessionIdentity?
        public let replacedIdentity: SessionIdentity?
        /// True when a complete callback-interest snapshot must be republished.
        public let attributionChanged: Bool

        public var admitted: Bool { identity != nil }
        public var inserted: Bool {
            disposition == .inserted || disposition == .replaced
        }
    }

    /// An active AI coding tool session.
    public struct AISession: Sendable {
        public let aiPid: Int32
        public let toolType: AIToolType
        public var projectDir: String
        public let startTime: Date
        public var identity: SessionIdentity
        public var childPids: Set<Int32>
        public var filesWritten: [String]
        public var filesRead: [String]
        public var networkConnections: [(ip: String, port: UInt16)]
        public var alertCount: Int
    }

    public struct ProcessExitResult: Sendable {
        public let attributionChanged: Bool
        public let removedSession: AISession?
        public let ignoredStaleIdentity: Bool
    }

    public struct Telemetry: Sendable, Equatable {
        public let maximumSessions: Int
        public let maximumAttributedProcesses: Int
        public let maximumChildrenPerSession: Int
        public let maximumFileHistoryPerSession: Int
        public let maximumNetworkHistoryPerSession: Int
        public let activeSessions: Int
        public let attributedChildren: Int
        public let attributedProcesses: Int
        public let retainedFileWrites: Int
        public let retainedFileReads: Int
        public let retainedNetworkConnections: Int
        public let rootAdmissionsRejectedTotal: UInt64
        public let rootReplacementsTotal: UInt64
        public let childCapacityEvictionsTotal: UInt64
        public let childAdmissionsRejectedTotal: UInt64
        public let staleChildBindingsRemovedTotal: UInt64
        public let staleExitEventsIgnoredTotal: UInt64
        public let fileWritesDroppedTotal: UInt64
        public let fileReadsDroppedTotal: UInt64
        public let networkConnectionsDroppedTotal: UInt64
        public let sessionRemovalsTotal: UInt64

        public var withinConfiguredBounds: Bool {
            activeSessions <= maximumSessions
                && attributedProcesses <= maximumAttributedProcesses
                && attributedProcesses == activeSessions + attributedChildren
                && retainedFileWrites
                    <= activeSessions * maximumFileHistoryPerSession
                && retainedFileReads
                    <= activeSessions * maximumFileHistoryPerSession
                && retainedNetworkConnections
                    <= activeSessions * maximumNetworkHistoryPerSession
        }
    }

    private struct ChildBinding: Sendable {
        let rootPid: Int32
        let rootGeneration: UInt64
        var processStartIdentity: UInt64?
        var lastSeenSequence: UInt64
    }

    /// Active AI tool sessions, keyed by root PID.
    private var sessions: [Int32: AISession] = [:]

    /// Child attribution cache. The root generation prevents a binding from
    /// becoming valid again if its root PID is recycled into a new session.
    private var childBindings: [Int32: ChildBinding] = [:]

    /// Reference to process lineage for compatibility `prune()` calls. The
    /// production owner uses live libproc evidence in AgentKit instead.
    private let lineage: ProcessLineage

    /// The tool registry for identification.
    private let registry: AIToolRegistry

    private let maximumSessions: Int
    private let maximumAttributedProcesses: Int
    private let maximumChildrenPerSession: Int
    private let maximumFileHistoryPerSession: Int
    private let maximumNetworkHistoryPerSession: Int

    private var nextGeneration: UInt64 = 0
    private var nextActivitySequence: UInt64 = 0

    private var rootAdmissionsRejectedTotal: UInt64 = 0
    private var rootReplacementsTotal: UInt64 = 0
    private var childCapacityEvictionsTotal: UInt64 = 0
    private var childAdmissionsRejectedTotal: UInt64 = 0
    private var staleChildBindingsRemovedTotal: UInt64 = 0
    private var staleExitEventsIgnoredTotal: UInt64 = 0
    private var fileWritesDroppedTotal: UInt64 = 0
    private var fileReadsDroppedTotal: UInt64 = 0
    private var networkConnectionsDroppedTotal: UInt64 = 0
    private var sessionRemovalsTotal: UInt64 = 0

    // MARK: - Initialization

    public init(
        lineage: ProcessLineage,
        registry: AIToolRegistry = AIToolRegistry(),
        maximumSessions: Int = AIProcessTracker.defaultMaximumSessions,
        maximumAttributedProcesses: Int = AIProcessTracker
            .defaultMaximumAttributedProcesses,
        maximumChildrenPerSession: Int = 256,
        maximumFileHistoryPerSession: Int = 1_000,
        maximumNetworkHistoryPerSession: Int = 256
    ) {
        self.lineage = lineage
        self.registry = registry
        self.maximumSessions = max(
            0,
            min(maximumSessions, Self.defaultMaximumSessions)
        )
        self.maximumAttributedProcesses = max(
            0,
            min(
                maximumAttributedProcesses,
                Self.defaultMaximumAttributedProcesses
            )
        )
        self.maximumChildrenPerSession = max(
            0,
            min(
                maximumChildrenPerSession,
                Self.hardMaximumChildrenPerSession
            )
        )
        self.maximumFileHistoryPerSession = max(
            0,
            min(
                maximumFileHistoryPerSession,
                Self.hardMaximumFileHistoryPerSession
            )
        )
        self.maximumNetworkHistoryPerSession = max(
            0,
            min(
                maximumNetworkHistoryPerSession,
                Self.hardMaximumNetworkHistoryPerSession
            )
        )
    }

    /// Converts an authoritative process birth date into the identity used by
    /// the live libproc reconciler. Callers must pass nil when their collector
    /// synthesises `startTime` from event-processing time.
    public nonisolated static func processStartIdentity(_ startTime: Date) -> UInt64? {
        let seconds = startTime.timeIntervalSince1970
        guard seconds.isFinite, seconds > 0, seconds < Double(UInt64.max) else {
            return nil
        }
        return UInt64(seconds.rounded(.down))
    }

    // MARK: - Root lifecycle

    /// Compatibility registration surface. Production uses the identity-aware
    /// overload below; standalone callers retain the historical Bool contract.
    @discardableResult
    public func registerAIProcess(
        pid: Int32,
        type: AIToolType,
        projectDir: String
    ) -> Bool {
        registerAIProcessIdentity(
            pid: pid,
            type: type,
            projectDir: projectDir,
            executablePathHash: nil,
            processStartIdentity: nil,
            observedAt: Date()
        ).inserted
    }

    /// Register or reconcile one AI root. Same-PID replacement is proven only
    /// by conflicting known executable/start evidence. Unknown evidence never
    /// tears down a live session.
    public func registerAIProcessIdentity(
        pid: Int32,
        type: AIToolType,
        projectDir: String,
        executablePathHash: UInt64?,
        processStartIdentity: UInt64?,
        observedAt: Date = Date()
    ) -> RegistrationResult {
        if var existing = sessions[pid] {
            let pathReplaced = existing.identity.executablePathHash
                .flatMap { old in executablePathHash.map { old != $0 } } ?? false
            let startReplaced = existing.identity.processStartIdentity
                .flatMap { old in processStartIdentity.map { old != $0 } } ?? false

            if pathReplaced || startReplaced {
                let replaced = existing.identity
                _ = removeSessionInternal(pid: pid)
                Self.incrementSaturating(&rootReplacementsTotal)
                guard prepareRootAdmission(pid: pid) else {
                    Self.incrementSaturating(&rootAdmissionsRejectedTotal)
                    return RegistrationResult(
                        disposition: .rejectedCapacity,
                        identity: nil,
                        replacedIdentity: replaced,
                        attributionChanged: true
                    )
                }
                let identity = makeIdentity(
                    pid: pid,
                    executablePathHash: executablePathHash,
                    processStartIdentity: processStartIdentity
                )
                sessions[pid] = makeSession(
                    pid: pid,
                    type: type,
                    projectDir: projectDir,
                    observedAt: observedAt,
                    identity: identity
                )
                updateActiveSessionsFlag()
                logger.info("AI session replaced after PID identity changed: \(type.rawValue) (PID \(pid))")
                return RegistrationResult(
                    disposition: .replaced,
                    identity: identity,
                    replacedIdentity: replaced,
                    attributionChanged: true
                )
            }

            // Fill evidence that was unknown on daemon attach without treating
            // it as a new session. Initial project ownership stays stable, but
            // an initially-unresolved cwd may be healed once.
            let identity = SessionIdentity(
                pid: pid,
                generation: existing.identity.generation,
                executablePathHash: existing.identity.executablePathHash
                    ?? executablePathHash,
                processStartIdentity: existing.identity.processStartIdentity
                    ?? processStartIdentity
            )
            let projectHealed = existing.projectDir.isEmpty && !projectDir.isEmpty
            existing.identity = identity
            if projectHealed { existing.projectDir = projectDir }
            sessions[pid] = existing
            return RegistrationResult(
                disposition: .existing,
                identity: identity,
                replacedIdentity: nil,
                attributionChanged: projectHealed
            )
        }

        guard prepareRootAdmission(pid: pid) else {
            Self.incrementSaturating(&rootAdmissionsRejectedTotal)
            return RegistrationResult(
                disposition: .rejectedCapacity,
                identity: nil,
                replacedIdentity: nil,
                attributionChanged: false
            )
        }

        let identity = makeIdentity(
            pid: pid,
            executablePathHash: executablePathHash,
            processStartIdentity: processStartIdentity
        )
        sessions[pid] = makeSession(
            pid: pid,
            type: type,
            projectDir: projectDir,
            observedAt: observedAt,
            identity: identity
        )
        updateActiveSessionsFlag()
        logger.info("AI session started: \(type.rawValue) (PID \(pid)) in \(projectDir)")
        return RegistrationResult(
            disposition: .inserted,
            identity: identity,
            replacedIdentity: nil,
            attributionChanged: true
        )
    }

    /// Roots are authoritative; child bindings are a bounded attribution cache.
    /// When the aggregate census is full, a newly proven root evicts the oldest
    /// cached child instead of being rejected behind derivative state. Root-cap
    /// rejection is checked before mutation, so an already-attributed child is
    /// preserved when no root slot exists.
    private func prepareRootAdmission(pid: Int32) -> Bool {
        guard sessions.count < maximumSessions,
              sessions.count < maximumAttributedProcesses else {
            return false
        }

        // A process promoted from child to root must occupy one census slot,
        // not both. The complete callback snapshot is republished by every
        // successful root insertion, so this structural change is atomic there.
        if childBindings[pid] != nil { removeChildBinding(pid: pid) }

        while sessions.count + childBindings.count
                >= maximumAttributedProcesses,
              let victim = childBindings.min(by: {
                  $0.value.lastSeenSequence < $1.value.lastSeenSequence
              })?.key {
            removeChildBinding(pid: victim)
            Self.incrementSaturating(&childCapacityEvictionsTotal)
        }
        return sessions.count + childBindings.count
            < maximumAttributedProcesses
    }

    private func makeIdentity(
        pid: Int32,
        executablePathHash: UInt64?,
        processStartIdentity: UInt64?
    ) -> SessionIdentity {
        nextGeneration &+= 1
        if nextGeneration == 0 { nextGeneration = 1 }
        return SessionIdentity(
            pid: pid,
            generation: nextGeneration,
            executablePathHash: executablePathHash,
            processStartIdentity: processStartIdentity
        )
    }

    private func makeSession(
        pid: Int32,
        type: AIToolType,
        projectDir: String,
        observedAt: Date,
        identity: SessionIdentity
    ) -> AISession {
        AISession(
            aiPid: pid,
            toolType: type,
            projectDir: projectDir,
            startTime: observedAt,
            identity: identity,
            childPids: [],
            filesWritten: [],
            filesRead: [],
            networkConnections: [],
            alertCount: 0
        )
    }

    /// SIP-protected / Apple-platform path prefixes. A binary running from one
    /// of these is never promoted to an AI-tool root.
    public nonisolated static func isApplePlatformPath(_ path: String) -> Bool {
        path.hasPrefix("/bin/") || path.hasPrefix("/sbin/")
            || path.hasPrefix("/usr/bin/") || path.hasPrefix("/usr/sbin/")
            || path.hasPrefix("/usr/libexec/")
            || path.hasPrefix("/System/")
            || path.hasPrefix("/Library/Apple/")
    }

    // MARK: - Child attribution

    /// Check whether a process genuinely descends from an active AI session.
    /// Cached attribution is valid only while the root generation and the
    /// current ancestry still agree.
    public func isAIChild(
        pid: Int32,
        ancestors: [ProcessAncestor],
        promoteUnregisteredAncestors: Bool = true,
        processStartIdentity: UInt64? = nil
    ) -> (
        isChild: Bool,
        toolType: AIToolType?,
        projectDir: String?,
        rootPid: Int32?,
        attributionChanged: Bool
    ) {
        var attributionChanged = false
        if var binding = childBindings[pid] {
            let startReplaced = binding.processStartIdentity
                .flatMap { old in processStartIdentity.map { old != $0 } } ?? false
            let session = sessions[binding.rootPid]
            let valid = !startReplaced
                && session?.identity.generation == binding.rootGeneration
                && ancestors.contains(where: { $0.pid == binding.rootPid })
            if valid, let session {
                binding.processStartIdentity = binding.processStartIdentity
                    ?? processStartIdentity
                binding.lastSeenSequence = nextSequence()
                childBindings[pid] = binding
                return (
                    true, session.toolType, session.projectDir,
                    binding.rootPid, false
                )
            }
            removeChildBinding(pid: pid)
            Self.incrementSaturating(&staleChildBindingsRemovedTotal)
            attributionChanged = true
        }

        for ancestor in ancestors {
            guard let session = sessions[ancestor.pid] else { continue }
            let bound = bindChild(
                pid: pid,
                to: session.identity,
                processStartIdentity: processStartIdentity
            )
            return (
                true, session.toolType, session.projectDir, ancestor.pid,
                attributionChanged || bound.changed
            )
        }

        // Production performs ordered owner-side promotion through the shared
        // lifecycle coordinator. Preserve historical standalone behaviour.
        guard promoteUnregisteredAncestors else {
            return (false, nil, nil, nil, attributionChanged)
        }
        guard let aiAncestor = ancestors.first(where: {
            !Self.isApplePlatformPath($0.executable)
                && registry.isAITool(executablePath: $0.executable) != nil
        }), let tool = registry.isAITool(executablePath: aiAncestor.executable) else {
            return (false, nil, nil, nil, attributionChanged)
        }

        let registration = registerAIProcessIdentity(
            pid: aiAncestor.pid,
            type: tool,
            projectDir: "",
            executablePathHash: ProcessIdentity.fnv1a64(aiAncestor.executable),
            processStartIdentity: nil
        )
        guard let identity = registration.identity else {
            return (false, nil, nil, nil,
                    attributionChanged || registration.attributionChanged)
        }
        let bound = bindChild(
            pid: pid,
            to: identity,
            processStartIdentity: processStartIdentity
        )
        return (
            true, tool, sessions[aiAncestor.pid]?.projectDir,
            aiAncestor.pid,
            attributionChanged || registration.attributionChanged || bound.changed
        )
    }

    private func bindChild(
        pid: Int32,
        to root: SessionIdentity,
        processStartIdentity: UInt64?
    ) -> (bound: Bool, changed: Bool) {
        guard sessions[root.pid]?.identity.generation == root.generation else {
            return (false, false)
        }
        if let existing = childBindings[pid],
           existing.rootPid == root.pid,
           existing.rootGeneration == root.generation {
            return (true, false)
        }

        if childBindings[pid] != nil { removeChildBinding(pid: pid) }

        let rootChildCount = sessions[root.pid]?.childPids.count ?? 0
        if rootChildCount >= maximumChildrenPerSession {
            guard let victim = childBindings
                .filter({ $0.value.rootPid == root.pid })
                .min(by: { $0.value.lastSeenSequence < $1.value.lastSeenSequence })?
                .key else {
                Self.incrementSaturating(&childAdmissionsRejectedTotal)
                return (false, false)
            }
            removeChildBinding(pid: victim)
            Self.incrementSaturating(&childCapacityEvictionsTotal)
        }

        if sessions.count + childBindings.count >= maximumAttributedProcesses {
            guard let victim = childBindings.min(by: {
                $0.value.lastSeenSequence < $1.value.lastSeenSequence
            })?.key else {
                Self.incrementSaturating(&childAdmissionsRejectedTotal)
                return (false, false)
            }
            removeChildBinding(pid: victim)
            Self.incrementSaturating(&childCapacityEvictionsTotal)
        }

        guard maximumChildrenPerSession > 0,
              sessions.count + childBindings.count < maximumAttributedProcesses else {
            Self.incrementSaturating(&childAdmissionsRejectedTotal)
            return (false, false)
        }
        childBindings[pid] = ChildBinding(
            rootPid: root.pid,
            rootGeneration: root.generation,
            processStartIdentity: processStartIdentity,
            lastSeenSequence: nextSequence()
        )
        sessions[root.pid]?.childPids.insert(pid)
        return (true, true)
    }

    private func nextSequence() -> UInt64 {
        nextActivitySequence &+= 1
        if nextActivitySequence == 0 { nextActivitySequence = 1 }
        return nextActivitySequence
    }

    private func removeChildBinding(pid: Int32) {
        guard let binding = childBindings.removeValue(forKey: pid) else { return }
        if sessions[binding.rootPid]?.identity.generation == binding.rootGeneration {
            sessions[binding.rootPid]?.childPids.remove(pid)
        }
    }

    // MARK: - Exit / reconciliation CAS

    /// Compatibility EXIT surface.
    @discardableResult
    public func processExited(pid: Int32) -> Bool {
        processExited(pid: pid, expectedStartIdentity: nil).attributionChanged
    }

    /// Identity-aware EXIT. A delayed EXIT for an older same-PID process cannot
    /// tear down a newly-registered root/child with a conflicting known start.
    public func processExited(
        pid: Int32,
        expectedStartIdentity: UInt64?
    ) -> ProcessExitResult {
        if let binding = childBindings[pid],
           let expectedStartIdentity,
           let boundStart = binding.processStartIdentity,
           expectedStartIdentity != boundStart {
            Self.incrementSaturating(&staleExitEventsIgnoredTotal)
            return ProcessExitResult(
                attributionChanged: false,
                removedSession: nil,
                ignoredStaleIdentity: true
            )
        }
        if let session = sessions[pid],
           let expectedStartIdentity,
           let rootStart = session.identity.processStartIdentity,
           expectedStartIdentity != rootStart {
            Self.incrementSaturating(&staleExitEventsIgnoredTotal)
            return ProcessExitResult(
                attributionChanged: false,
                removedSession: nil,
                ignoredStaleIdentity: true
            )
        }

        var changed = false
        if childBindings[pid] != nil {
            removeChildBinding(pid: pid)
            changed = true
        }
        let removed = removeSessionInternal(pid: pid)
        changed = changed || removed != nil
        return ProcessExitResult(
            attributionChanged: changed,
            removedSession: removed,
            ignoredStaleIdentity: false
        )
    }

    /// Immutable generation tickets for a two-phase live-process probe.
    public func sessionIdentities() -> [SessionIdentity] {
        sessions.values.map(\.identity).sorted { $0.pid < $1.pid }
    }

    /// Generation/CAS removal. A prune decision made against an older PID
    /// lifetime cannot remove the replacement that arrived while it probed.
    public func removeSession(ifIdentityMatches identity: SessionIdentity) -> AISession? {
        guard sessions[identity.pid]?.identity == identity else { return nil }
        return removeSessionInternal(pid: identity.pid)
    }

    /// Explicit removal retained for existing callers.
    public func removeSession(pid: Int32) {
        _ = removeSessionInternal(pid: pid)
    }

    private func removeSessionInternal(pid: Int32) -> AISession? {
        guard let session = sessions[pid] else { return nil }
        for child in session.childPids { childBindings.removeValue(forKey: child) }
        sessions.removeValue(forKey: pid)
        Self.incrementSaturating(&sessionRemovalsTotal)
        updateActiveSessionsFlag()
        logger.info("AI session ended: \(session.toolType.rawValue) (PID \(pid)), \(session.alertCount) alerts")
        return session
    }

    /// Legacy lineage-only sweep. Production uses the live libproc reconciler,
    /// because absence from a bounded lineage cache alone is not proof of death.
    @available(*, deprecated, message: "Use the owned live-process reconciler")
    public func prune() async {
        // Deliberately retain everything: bounded ProcessLineage may evict a
        // live root, so cache absence is not proof of death. AgentKit's
        // reconciliation owner requires ESRCH or conflicting live process
        // identity before invoking the generation-CAS remover.
        _ = lineage
    }

    // MARK: - Bounded histories

    public func recordFileWrite(aiSessionPid: Int32, path: String) {
        guard var session = sessions[aiSessionPid] else { return }
        guard maximumFileHistoryPerSession > 0 else {
            Self.incrementSaturating(&fileWritesDroppedTotal)
            return
        }
        session.filesWritten.append(path)
        let overflow = max(
            0,
            session.filesWritten.count - maximumFileHistoryPerSession
        )
        if overflow > 0 {
            session.filesWritten.removeFirst(overflow)
            Self.addSaturating(UInt64(overflow), to: &fileWritesDroppedTotal)
        }
        sessions[aiSessionPid] = session
    }

    public func recordFileRead(aiSessionPid: Int32, path: String) {
        guard var session = sessions[aiSessionPid] else { return }
        guard maximumFileHistoryPerSession > 0 else {
            Self.incrementSaturating(&fileReadsDroppedTotal)
            return
        }
        session.filesRead.append(path)
        let overflow = max(
            0,
            session.filesRead.count - maximumFileHistoryPerSession
        )
        if overflow > 0 {
            session.filesRead.removeFirst(overflow)
            Self.addSaturating(UInt64(overflow), to: &fileReadsDroppedTotal)
        }
        sessions[aiSessionPid] = session
    }

    public func recordConnection(aiSessionPid: Int32, ip: String, port: UInt16) {
        guard var session = sessions[aiSessionPid] else { return }
        guard maximumNetworkHistoryPerSession > 0 else {
            Self.incrementSaturating(&networkConnectionsDroppedTotal)
            return
        }
        session.networkConnections.append((ip, port))
        let overflow = max(
            0,
            session.networkConnections.count - maximumNetworkHistoryPerSession
        )
        if overflow > 0 {
            session.networkConnections.removeFirst(overflow)
            Self.addSaturating(
                UInt64(overflow),
                to: &networkConnectionsDroppedTotal
            )
        }
        sessions[aiSessionPid] = session
    }

    public func recordAlert(aiSessionPid: Int32) {
        guard let current = sessions[aiSessionPid]?.alertCount else { return }
        sessions[aiSessionPid]?.alertCount = current == Int.max
            ? Int.max : current + 1
    }

    // MARK: - Queries / telemetry

    public func activeSessions() -> [AISession] {
        sessions.values.sorted { $0.aiPid < $1.aiPid }
    }

    public func session(forPid pid: Int32) -> AISession? { sessions[pid] }

    public var sessionCount: Int { sessions.count }

    public func telemetry() -> Telemetry {
        let values = sessions.values
        return Telemetry(
            maximumSessions: maximumSessions,
            maximumAttributedProcesses: maximumAttributedProcesses,
            maximumChildrenPerSession: maximumChildrenPerSession,
            maximumFileHistoryPerSession: maximumFileHistoryPerSession,
            maximumNetworkHistoryPerSession: maximumNetworkHistoryPerSession,
            activeSessions: sessions.count,
            attributedChildren: childBindings.count,
            attributedProcesses: sessions.count + childBindings.count,
            retainedFileWrites: values.reduce(0) { $0 + $1.filesWritten.count },
            retainedFileReads: values.reduce(0) { $0 + $1.filesRead.count },
            retainedNetworkConnections: values.reduce(0) {
                $0 + $1.networkConnections.count
            },
            rootAdmissionsRejectedTotal: rootAdmissionsRejectedTotal,
            rootReplacementsTotal: rootReplacementsTotal,
            childCapacityEvictionsTotal: childCapacityEvictionsTotal,
            childAdmissionsRejectedTotal: childAdmissionsRejectedTotal,
            staleChildBindingsRemovedTotal: staleChildBindingsRemovedTotal,
            staleExitEventsIgnoredTotal: staleExitEventsIgnoredTotal,
            fileWritesDroppedTotal: fileWritesDroppedTotal,
            fileReadsDroppedTotal: fileReadsDroppedTotal,
            networkConnectionsDroppedTotal: networkConnectionsDroppedTotal,
            sessionRemovalsTotal: sessionRemovalsTotal
        )
    }

    // MARK: - Fast-path hint

    public nonisolated var hasActiveSessionsHint: Bool {
        _hasActiveSessionsFlag.withLock { $0 }
    }

    private let _hasActiveSessionsFlag = OSAllocatedUnfairLock<Bool>(initialState: false)

    fileprivate func updateActiveSessionsFlag() {
        let nowEmpty = sessions.isEmpty
        _hasActiveSessionsFlag.withLock { $0 = !nowEmpty }
    }

    private nonisolated static func incrementSaturating(_ value: inout UInt64) {
        if value < UInt64.max { value += 1 }
    }

    private nonisolated static func addSaturating(
        _ amount: UInt64,
        to value: inout UInt64
    ) {
        if value > UInt64.max - amount { value = UInt64.max }
        else { value += amount }
    }
}
