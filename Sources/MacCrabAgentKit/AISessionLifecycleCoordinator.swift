import Darwin
import Foundation
import MacCrabCore
import os.log

/// Sole owner for multi-actor AI root lifecycle transitions.
///
/// AIProcessTracker is authoritative for attribution. ProjectBoundary,
/// AgentLineageService, AgentSessionRegistry, and the synchronous ES callback
/// snapshot are derivatives. This coordinator serializes root registration,
/// EXIT, and live-process reconciliation so those derivatives can never be
/// deleted from a fresh same-PID generation by an older prune decision.
actor AISessionLifecycleCoordinator {
    struct LiveProcessObservation: Sendable, Equatable {
        enum State: Sendable, Equatable { case alive, dead, unknown }

        let state: State
        let executablePathHash: UInt64?
        let processStartIdentity: UInt64?

        static let dead = Self(
            state: .dead,
            executablePathHash: nil,
            processStartIdentity: nil
        )
        static let unknown = Self(
            state: .unknown,
            executablePathHash: nil,
            processStartIdentity: nil
        )
        static func alive(
            executablePathHash: UInt64?,
            processStartIdentity: UInt64?
        ) -> Self {
            Self(
                state: .alive,
                executablePathHash: executablePathHash,
                processStartIdentity: processStartIdentity
            )
        }
    }

    struct RootRegistration: Sendable {
        let projectDirectory: String
        let trackerDisposition: AIProcessTracker.RegistrationDisposition
        let sessionID: String?
        let callbackSnapshotAccepted: Bool

        var admitted: Bool { sessionID != nil }
    }

    struct ReconciliationResult: Sendable, Equatable {
        let examined: Int
        let retainedAlive: Int
        let retainedUnknown: Int
        let removedDead: Int
        let removedReplaced: Int
        let generationCASMisses: Int
        let callbackSnapshotAccepted: Bool
    }

    struct Telemetry: Sendable, Equatable {
        let registrationsTotal: UInt64
        let exitsTotal: UInt64
        let reconciliationRunsTotal: UInt64
        let reconciliationSessionsExaminedTotal: UInt64
        let sessionsRemovedDeadTotal: UInt64
        let sessionsRemovedReplacedTotal: UInt64
        let generationCASMissesTotal: UInt64
        let staleExitEventsIgnoredTotal: UInt64
        let callbackPublicationsTotal: UInt64
        let callbackPublicationFailuresTotal: UInt64
    }

    typealias ProcessProbe = @Sendable (Int32) -> LiveProcessObservation
    typealias CallbackPublisher = @Sendable ([DynamicAIFileEventSession]) -> Bool
    typealias CallbackRevoker = @Sendable (Int32) -> Void

    private let logger = Logger(
        subsystem: "com.maccrab.agent",
        category: "ai-session-lifecycle"
    )
    private let processProbe: ProcessProbe
    private let callbackPublisher: CallbackPublisher
    private let callbackRevoker: CallbackRevoker

    /// An actor can re-enter at every downstream `await`. This small async gate
    /// deliberately spans those awaits, turning each root transition into one
    /// ownership transaction without blocking a cooperative-executor thread.
    private var ownershipHeld = false
    private var ownershipWaiters: [CheckedContinuation<Void, Never>] = []

    private var registrationsTotal: UInt64 = 0
    private var exitsTotal: UInt64 = 0
    private var reconciliationRunsTotal: UInt64 = 0
    private var reconciliationSessionsExaminedTotal: UInt64 = 0
    private var sessionsRemovedDeadTotal: UInt64 = 0
    private var sessionsRemovedReplacedTotal: UInt64 = 0
    private var generationCASMissesTotal: UInt64 = 0
    private var staleExitEventsIgnoredTotal: UInt64 = 0
    private var callbackPublicationsTotal: UInt64 = 0
    private var callbackPublicationFailuresTotal: UInt64 = 0

    init(
        processProbe: @escaping ProcessProbe = {
            AISessionLifecycleCoordinator.liveProcessObservation(pid: $0)
        },
        callbackPublisher: @escaping CallbackPublisher = {
            ESCollector.publishDynamicAIFileEventSessions($0)
        },
        callbackRevoker: @escaping CallbackRevoker = {
            ESCollector.revokeDynamicAIFileEventProcess($0)
        }
    ) {
        self.processProbe = processProbe
        self.callbackPublisher = callbackPublisher
        self.callbackRevoker = callbackRevoker
    }

    // MARK: - Ordered root ownership

    func registerRoot(
        tracker: AIProcessTracker,
        projectBoundary: ProjectBoundary,
        lineageService: AgentLineageService,
        sessionRegistry: AgentSessionRegistry,
        pid: Int32,
        executable: String,
        type: AIToolType,
        reportedProjectDirectory: String,
        observedAt: Date,
        processStartTime: Date,
        processStartIdentity: UInt64?
    ) async -> RootRegistration {
        await acquireOwnership()
        defer { releaseOwnership() }
        Self.incrementSaturating(&registrationsTotal)

        let executablePathHash = ProcessIdentity.fnv1a64(executable)
        let priorSession = await tracker.session(forPid: pid)
        let pathProvesReplacement = priorSession?.identity.executablePathHash
            .map { $0 != executablePathHash } ?? false
        if pathProvesReplacement, let priorSession {
            _ = await projectBoundary.removeBoundary(
                aiPid: pid,
                matchingSessionGeneration: priorSession.identity.generation
            )
        }

        // ProjectBoundary resolves the live cwd before every derivative stores
        // the project root. A new known birth identity clears a stale same-PID
        // rejection or boundary record.
        _ = await projectBoundary.registerBoundary(
            aiPid: pid,
            projectDir: reportedProjectDirectory,
            resolveLiveCWDIfEmpty: true,
            processStartIdentity: processStartIdentity
        )
        let acceptedProjectDirectory = await projectBoundary.projectDirectory(
            aiPid: pid
        ) ?? ""

        let registration = await tracker.registerAIProcessIdentity(
            pid: pid,
            type: type,
            projectDir: acceptedProjectDirectory,
            executablePathHash: executablePathHash,
            processStartIdentity: processStartIdentity,
            observedAt: observedAt
        )
        guard let identity = registration.identity else {
            // Boundary-first registration is rolled back when the root hard cap
            // refuses admission; no orphan derivative survives the rejection.
            _ = await projectBoundary.removeBoundary(aiPid: pid)
            if registration.replacedIdentity != nil, let priorSession {
                await lineageService.endSession(aiPid: pid)
                await sessionRegistry.end(rootPid: pid, now: observedAt)
                callbackRevoker(priorSession.aiPid)
                for child in priorSession.childPids { callbackRevoker(child) }
            }
            let accepted = registration.attributionChanged
                ? await publishCurrentSnapshot(tracker: tracker) : true
            return RootRegistration(
                projectDirectory: "",
                trackerDisposition: registration.disposition,
                sessionID: nil,
                callbackSnapshotAccepted: accepted
            )
        }

        _ = await projectBoundary.associateSession(
            aiPid: pid,
            generation: identity.generation,
            processStartIdentity: processStartIdentity
        )

        // Any inserted generation may have a same-PID record lingering in the
        // independent bounded stores. Force the durable registry entry beyond
        // grace before minting the new identity; otherwise same-executable PID
        // recycle revives the previous UUID because that store intentionally
        // cannot infer birth time from descendant events.
        if registration.inserted {
            await lineageService.endSession(aiPid: pid)
            await sessionRegistry.end(rootPid: pid, now: .distantPast)
            // Full publication below replaces root demand. Revoke every old
            // short-lived child grace entry as well so PID reuse cannot retain
            // over-admission until its monotonic expiry.
            if registration.disposition == .replaced, let priorSession {
                callbackRevoker(priorSession.aiPid)
                for child in priorSession.childPids { callbackRevoker(child) }
            }
        }
        await lineageService.startSession(
            aiPid: pid,
            toolType: type,
            projectDir: acceptedProjectDirectory,
            startTime: observedAt
        )
        let sessionID = await sessionRegistry.session(
            rootPid: pid,
            pathHash: executablePathHash,
            startTime: processStartTime,
            tool: type.rawValue,
            now: observedAt
        )
        let accepted = registration.attributionChanged
            ? await publishCurrentSnapshot(tracker: tracker) : true
        return RootRegistration(
            projectDirectory: acceptedProjectDirectory,
            trackerDisposition: registration.disposition,
            sessionID: sessionID,
            callbackSnapshotAccepted: accepted
        )
    }

    /// Publish after a child-attribution edge. Publication itself runs through
    /// the ownership gate, so a concurrent reconcile cannot publish empty and
    /// then be overwritten by a stale pre-prune session array.
    @discardableResult
    func publishCurrent(tracker: AIProcessTracker) async -> Bool {
        await acquireOwnership()
        defer { releaseOwnership() }
        return await publishCurrentSnapshot(tracker: tracker)
    }

    // MARK: - EXIT

    @discardableResult
    func processExited(
        tracker: AIProcessTracker,
        projectBoundary: ProjectBoundary,
        lineageService: AgentLineageService,
        sessionRegistry: AgentSessionRegistry,
        pid: Int32,
        expectedStartIdentity: UInt64?,
        now: Date
    ) async -> Bool {
        await acquireOwnership()
        defer { releaseOwnership() }
        Self.incrementSaturating(&exitsTotal)

        // A delayed EXIT can arrive after the PID has already been reused.
        // When both sides carry a birth identity, retain the new lifetime and
        // even its short callback grace entry.
        if let expectedStartIdentity {
            let live = processProbe(pid)
            if live.state == .alive,
               let liveStart = live.processStartIdentity,
               liveStart != expectedStartIdentity {
                Self.incrementSaturating(&staleExitEventsIgnoredTotal)
                return false
            }
        }

        let exit = await tracker.processExited(
            pid: pid,
            expectedStartIdentity: expectedStartIdentity
        )
        if exit.ignoredStaleIdentity {
            Self.incrementSaturating(&staleExitEventsIgnoredTotal)
            return false
        }

        callbackRevoker(pid)
        if let removed = exit.removedSession {
            await cleanDerivatives(
                removed,
                projectBoundary: projectBoundary,
                lineageService: lineageService,
                sessionRegistry: sessionRegistry,
                endedAt: now
            )
        }
        guard exit.attributionChanged else { return false }
        return await publishCurrentSnapshot(tracker: tracker)
    }

    // MARK: - Missed-EXIT reconciliation

    /// Reconcile only with proof: ESRCH means dead; a conflicting known live
    /// path/start identity means replaced. Permission/transient probe failure
    /// is unknown and therefore retained. Tracker removal is generation-CAS.
    func reconcile(
        tracker: AIProcessTracker,
        projectBoundary: ProjectBoundary,
        lineageService: AgentLineageService,
        sessionRegistry: AgentSessionRegistry,
        now: Date = Date()
    ) async -> ReconciliationResult {
        await acquireOwnership()
        defer { releaseOwnership() }
        Self.incrementSaturating(&reconciliationRunsTotal)

        let tickets = await tracker.sessionIdentities()
        Self.addSaturating(
            UInt64(tickets.count),
            to: &reconciliationSessionsExaminedTotal
        )
        var retainedAlive = 0
        var retainedUnknown = 0
        var removedDead = 0
        var removedReplaced = 0
        var generationCASMisses = 0

        for ticket in tickets {
            let observation = processProbe(ticket.pid)
            let reason: LiveRemovalReason?
            switch observation.state {
            case .dead:
                reason = .dead
            case .unknown:
                retainedUnknown += 1
                reason = nil
            case .alive:
                let pathChanged = ticket.executablePathHash.flatMap { expected in
                    observation.executablePathHash.map { expected != $0 }
                } ?? false
                let startChanged = ticket.processStartIdentity.flatMap { expected in
                    observation.processStartIdentity.map { expected != $0 }
                } ?? false
                if pathChanged || startChanged {
                    reason = .replaced
                } else {
                    retainedAlive += 1
                    reason = nil
                }
            }
            guard let reason else { continue }
            guard let removed = await tracker.removeSession(
                ifIdentityMatches: ticket
            ) else {
                generationCASMisses += 1
                Self.incrementSaturating(&generationCASMissesTotal)
                continue
            }
            switch reason {
            case .dead:
                removedDead += 1
                Self.incrementSaturating(&sessionsRemovedDeadTotal)
            case .replaced:
                removedReplaced += 1
                Self.incrementSaturating(&sessionsRemovedReplacedTotal)
            }
            await cleanDerivatives(
                removed,
                projectBoundary: projectBoundary,
                lineageService: lineageService,
                sessionRegistry: sessionRegistry,
                endedAt: now
            )
        }

        let changed = removedDead + removedReplaced > 0
        let accepted = changed
            ? await publishCurrentSnapshot(tracker: tracker) : true
        return ReconciliationResult(
            examined: tickets.count,
            retainedAlive: retainedAlive,
            retainedUnknown: retainedUnknown,
            removedDead: removedDead,
            removedReplaced: removedReplaced,
            generationCASMisses: generationCASMisses,
            callbackSnapshotAccepted: accepted
        )
    }

    func telemetry() -> Telemetry {
        Telemetry(
            registrationsTotal: registrationsTotal,
            exitsTotal: exitsTotal,
            reconciliationRunsTotal: reconciliationRunsTotal,
            reconciliationSessionsExaminedTotal:
                reconciliationSessionsExaminedTotal,
            sessionsRemovedDeadTotal: sessionsRemovedDeadTotal,
            sessionsRemovedReplacedTotal: sessionsRemovedReplacedTotal,
            generationCASMissesTotal: generationCASMissesTotal,
            staleExitEventsIgnoredTotal: staleExitEventsIgnoredTotal,
            callbackPublicationsTotal: callbackPublicationsTotal,
            callbackPublicationFailuresTotal: callbackPublicationFailuresTotal
        )
    }

    // MARK: - Transaction internals

    private enum LiveRemovalReason { case dead, replaced }

    private func acquireOwnership() async {
        if !ownershipHeld {
            ownershipHeld = true
            return
        }
        await withCheckedContinuation { continuation in
            ownershipWaiters.append(continuation)
        }
    }

    private func releaseOwnership() {
        if ownershipWaiters.isEmpty {
            ownershipHeld = false
            return
        }
        let next = ownershipWaiters.removeFirst()
        next.resume()
    }

    private func cleanDerivatives(
        _ removed: AIProcessTracker.AISession,
        projectBoundary: ProjectBoundary,
        lineageService: AgentLineageService,
        sessionRegistry: AgentSessionRegistry,
        endedAt: Date
    ) async {
        _ = await projectBoundary.removeBoundary(
            aiPid: removed.aiPid,
            matchingSessionGeneration: removed.identity.generation
        )
        await lineageService.endSession(aiPid: removed.aiPid)
        await sessionRegistry.end(rootPid: removed.aiPid, now: endedAt)
        callbackRevoker(removed.aiPid)
        for child in removed.childPids { callbackRevoker(child) }
    }

    private func publishCurrentSnapshot(tracker: AIProcessTracker) async -> Bool {
        let active = await tracker.activeSessions()
        let sessions = active.map { session in
            DynamicAIFileEventSession(
                rootProcessID: session.aiPid,
                childProcessIDs: session.childPids,
                projectRoots: session.projectDir.isEmpty
                    ? [] : [session.projectDir]
            )
        }
        Self.incrementSaturating(&callbackPublicationsTotal)
        let accepted = callbackPublisher(sessions)
        if !accepted {
            Self.incrementSaturating(&callbackPublicationFailuresTotal)
            logger.fault("Dynamic AI callback snapshot exceeded its fixed bound; callback admission is fail-open until the next accepted ownership snapshot")
        }
        return accepted
    }

    /// libproc/kill(0) proof used only off the callback path. `ESRCH` is the
    /// sole dead result. EPERM means alive. Every other failure is unknown.
    nonisolated static func liveProcessObservation(
        pid: Int32
    ) -> LiveProcessObservation {
        // `kill(0, 0)` addresses the caller's entire process group, so invalid
        // or sentinel PIDs must never reach the fallback probe.
        guard pid > 0 else { return .unknown }
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        if proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size {
            var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
            let length = proc_pidpath(pid, &buffer, UInt32(buffer.count))
            let pathHash: UInt64? = length > 0
                ? ProcessIdentity.fnv1a64(String(cString: buffer)) : nil
            let start = info.pbi_start_tvsec > 0
                ? UInt64(info.pbi_start_tvsec) : nil
            return .alive(
                executablePathHash: pathHash,
                processStartIdentity: start
            )
        }

        errno = 0
        let result = kill(pid, 0)
        if result == 0 || errno == EPERM {
            return .alive(
                executablePathHash: nil,
                processStartIdentity: nil
            )
        }
        return errno == ESRCH ? .dead : .unknown
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
