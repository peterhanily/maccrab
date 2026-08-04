import Foundation
import Testing
@testable import MacCrabCore
@testable import MacCrabAgentKit

private final class AISnapshotRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var snapshots: [[DynamicAIFileEventSession]] = []
    private var revoked: [Int32] = []

    func publish(_ sessions: [DynamicAIFileEventSession]) -> Bool {
        lock.withLock { snapshots.append(sessions) }
        return true
    }

    func revoke(_ pid: Int32) {
        lock.withLock { revoked.append(pid) }
    }

    var lastSnapshot: [DynamicAIFileEventSession]? {
        lock.withLock { snapshots.last }
    }

    var revokedPIDs: [Int32] { lock.withLock { revoked } }
}

private final class BlockingAIProcessProbe: @unchecked Sendable {
    private let condition = NSCondition()
    private var entered = false
    private var released = false

    func call(_ pid: Int32) -> AISessionLifecycleCoordinator.LiveProcessObservation {
        condition.lock()
        entered = true
        condition.broadcast()
        while !released { condition.wait() }
        condition.unlock()
        return .dead
    }

    func waitUntilEntered() async -> Bool {
        for _ in 0..<1_000 {
            if isEntered { return true }
            try? await Task.sleep(nanoseconds: 100_000)
        }
        return false
    }

    private var isEntered: Bool {
        condition.lock()
        defer { condition.unlock() }
        return entered
    }

    func release() {
        condition.lock()
        released = true
        condition.broadcast()
        condition.unlock()
    }
}

@Suite("AI session lifecycle ownership")
struct AISessionLifecycleCoordinatorTests {
    private let claudePath = "/Users/test/.local/bin/claude"

    private func ancestor(_ pid: Int32) -> ProcessAncestor {
        ProcessAncestor(pid: pid, executable: claudePath, name: "claude")
    }

    @Test("root, aggregate child, and per-root child bounds survive churn")
    func trackerHardBounds() async {
        #expect(
            AIProcessTracker.defaultMaximumSessions
                == AgentLineageService.defaultMaxSessions
        )
        let oneProcessDemand = DynamicAIFileEventDemandSnapshot.currentCanonical(
            validUntilUptimeNanoseconds: UInt64.max,
            sessions: [DynamicAIFileEventSession(
                rootProcessID: 1,
                projectRoots: ["/project"]
            )]
        )
        #expect(
            oneProcessDemand.demands.count
                == AIFileEventConsumer.allCases.count
        )
        #expect(
            AIProcessTracker.defaultMaximumAttributedProcesses
                * AIFileEventConsumer.allCases.count
                <= FileEventInterestPolicyLimits.default.maximumDynamicDemands
        )
        let tracker = AIProcessTracker(
            lineage: ProcessLineage(),
            maximumSessions: 2,
            maximumAttributedProcesses: 3,
            maximumChildrenPerSession: 2
        )
        #expect(await tracker.registerAIProcess(
            pid: 100, type: .claudeCode, projectDir: "/project"
        ))
        for pid in Int32(101)...Int32(112) {
            let result = await tracker.isAIChild(
                pid: pid,
                ancestors: [ancestor(100)],
                promoteUnregisteredAncestors: false,
                processStartIdentity: UInt64(pid)
            )
            #expect(result.isChild)
        }

        let telemetry = await tracker.telemetry()
        #expect(telemetry.activeSessions == 1)
        #expect(telemetry.attributedChildren == 2)
        #expect(telemetry.attributedProcesses == 3)
        #expect(telemetry.childCapacityEvictionsTotal == 10)
        #expect(telemetry.withinConfiguredBounds)
        #expect(await tracker.session(forPid: 100)?.childPids.count == 2)

        let recorder = AISnapshotRecorder()
        let coordinator = AISessionLifecycleCoordinator(
            processProbe: { _ in .unknown },
            callbackPublisher: { recorder.publish($0) },
            callbackRevoker: { recorder.revoke($0) }
        )
        #expect(await coordinator.publishCurrent(tracker: tracker))
        #expect(recorder.lastSnapshot?.count == 1)
        #expect(recorder.lastSnapshot?.first?.childProcessIDs.count == 2)

        #expect(await tracker.registerAIProcess(
            pid: 200, type: .codex, projectDir: "/other"
        ))
        let afterRootAdmission = await tracker.telemetry()
        #expect(afterRootAdmission.activeSessions == 2)
        #expect(afterRootAdmission.attributedChildren == 1)
        #expect(afterRootAdmission.attributedProcesses == 3)
        #expect(afterRootAdmission.childCapacityEvictionsTotal == 11)
        #expect(afterRootAdmission.withinConfiguredBounds)
        #expect(await coordinator.publishCurrent(tracker: tracker))
        #expect(recorder.lastSnapshot?.count == 2)
        #expect(
            recorder.lastSnapshot?.reduce(0) {
                $0 + 1 + $1.childProcessIDs.count
            } == 3
        )
        #expect(!(await tracker.registerAIProcess(
            pid: 300, type: .unknown, projectDir: "/third"
        )))
        #expect(await tracker.telemetry().rootAdmissionsRejectedTotal == 1)
    }

    @Test("file and network histories keep an exact hard suffix")
    func boundedHistories() async throws {
        let tracker = AIProcessTracker(
            lineage: ProcessLineage(),
            maximumFileHistoryPerSession: 3,
            maximumNetworkHistoryPerSession: 3
        )
        #expect(await tracker.registerAIProcess(
            pid: 400, type: .claudeCode, projectDir: "/project"
        ))
        for index in 0..<5 {
            await tracker.recordFileWrite(
                aiSessionPid: 400,
                path: "/project/f\(index)"
            )
            await tracker.recordFileRead(
                aiSessionPid: 400,
                path: "/project/r\(index)"
            )
            await tracker.recordConnection(
                aiSessionPid: 400,
                ip: "192.0.2.\(index)",
                port: 443
            )
        }
        let session = try #require(await tracker.session(forPid: 400))
        #expect(session.filesWritten == [
            "/project/f2", "/project/f3", "/project/f4",
        ])
        #expect(session.filesRead == [
            "/project/r2", "/project/r3", "/project/r4",
        ])
        #expect(session.networkConnections.map(\.ip) == [
            "192.0.2.2", "192.0.2.3", "192.0.2.4",
        ])
        let telemetry = await tracker.telemetry()
        #expect(telemetry.fileWritesDroppedTotal == 2)
        #expect(telemetry.fileReadsDroppedTotal == 2)
        #expect(telemetry.networkConnectionsDroppedTotal == 2)
    }

    @Test("same executable PID recycle mints a generation and defeats stale CAS")
    func pidRecycleGenerationCAS() async throws {
        let tracker = AIProcessTracker(lineage: ProcessLineage())
        let pathHash = ProcessIdentity.fnv1a64(claudePath)
        let first = await tracker.registerAIProcessIdentity(
            pid: 500,
            type: .claudeCode,
            projectDir: "/one",
            executablePathHash: pathHash,
            processStartIdentity: 100
        )
        let oldIdentity = try #require(first.identity)
        let second = await tracker.registerAIProcessIdentity(
            pid: 500,
            type: .claudeCode,
            projectDir: "/two",
            executablePathHash: pathHash,
            processStartIdentity: 101
        )
        let newIdentity = try #require(second.identity)
        #expect(second.disposition == .replaced)
        #expect(newIdentity.generation != oldIdentity.generation)
        #expect(await tracker.removeSession(ifIdentityMatches: oldIdentity) == nil)
        #expect(await tracker.session(forPid: 500)?.identity == newIdentity)
    }

    @Test("missed EXIT removes every derivative and publishes an empty callback snapshot")
    func missedExitReconciliation() async throws {
        let tracker = AIProcessTracker(lineage: ProcessLineage())
        let boundary = ProjectBoundary()
        let lineage = AgentLineageService()
        let registry = AgentSessionRegistry(graceWindow: 0)
        let recorder = AISnapshotRecorder()
        let coordinator = AISessionLifecycleCoordinator(
            processProbe: { _ in .dead },
            callbackPublisher: { recorder.publish($0) },
            callbackRevoker: { recorder.revoke($0) }
        )
        let start = Date(timeIntervalSince1970: 100)
        let registration = await coordinator.registerRoot(
            tracker: tracker,
            projectBoundary: boundary,
            lineageService: lineage,
            sessionRegistry: registry,
            pid: 600,
            executable: claudePath,
            type: .claudeCode,
            reportedProjectDirectory: "/project",
            observedAt: start,
            processStartTime: start,
            processStartIdentity: 100
        )
        #expect(registration.admitted)
        #expect(await boundary.boundaryCount == 1)
        #expect(await lineage.snapshot(aiPid: 600) != nil)

        let result = await coordinator.reconcile(
            tracker: tracker,
            projectBoundary: boundary,
            lineageService: lineage,
            sessionRegistry: registry,
            now: Date(timeIntervalSince1970: 200)
        )
        #expect(result.removedDead == 1)
        #expect(result.removedReplaced == 0)
        #expect(await tracker.sessionCount == 0)
        #expect(await boundary.boundaryCount == 0)
        #expect(await lineage.snapshot(aiPid: 600) == nil)
        #expect(await registry.sessionForRoot(
            pid: 600,
            pathHash: ProcessIdentity.fnv1a64(claudePath),
            now: Date(timeIntervalSince1970: 201)
        ) == nil)
        #expect(recorder.lastSnapshot?.isEmpty == true)
        #expect(recorder.revokedPIDs.contains(600))
    }

    @Test("live same-path start replacement is proven and reconciled")
    func livePIDReplacement() async {
        let tracker = AIProcessTracker(lineage: ProcessLineage())
        let boundary = ProjectBoundary()
        let lineage = AgentLineageService()
        let registry = AgentSessionRegistry()
        let recorder = AISnapshotRecorder()
        let pathHash = ProcessIdentity.fnv1a64(claudePath)
        let coordinator = AISessionLifecycleCoordinator(
            processProbe: { _ in
                .alive(
                    executablePathHash: pathHash,
                    processStartIdentity: 701
                )
            },
            callbackPublisher: { recorder.publish($0) },
            callbackRevoker: { recorder.revoke($0) }
        )
        let oldStart = Date(timeIntervalSince1970: 700)
        _ = await coordinator.registerRoot(
            tracker: tracker,
            projectBoundary: boundary,
            lineageService: lineage,
            sessionRegistry: registry,
            pid: 700,
            executable: claudePath,
            type: .claudeCode,
            reportedProjectDirectory: "/project",
            observedAt: oldStart,
            processStartTime: oldStart,
            processStartIdentity: 700
        )
        let result = await coordinator.reconcile(
            tracker: tracker,
            projectBoundary: boundary,
            lineageService: lineage,
            sessionRegistry: registry
        )
        #expect(result.removedReplaced == 1)
        #expect(await tracker.sessionCount == 0)
        #expect(recorder.lastSnapshot?.isEmpty == true)
    }

    @Test("unknown liveness is retained rather than guessed dead")
    func unknownProbeRetainsSession() async {
        let tracker = AIProcessTracker(lineage: ProcessLineage())
        let boundary = ProjectBoundary()
        let lineage = AgentLineageService()
        let registry = AgentSessionRegistry()
        let recorder = AISnapshotRecorder()
        let coordinator = AISessionLifecycleCoordinator(
            processProbe: { _ in .unknown },
            callbackPublisher: { recorder.publish($0) },
            callbackRevoker: { recorder.revoke($0) }
        )
        let start = Date(timeIntervalSince1970: 750)
        _ = await coordinator.registerRoot(
            tracker: tracker,
            projectBoundary: boundary,
            lineageService: lineage,
            sessionRegistry: registry,
            pid: 750,
            executable: claudePath,
            type: .claudeCode,
            reportedProjectDirectory: "/project",
            observedAt: start,
            processStartTime: start,
            processStartIdentity: 750
        )
        let result = await coordinator.reconcile(
            tracker: tracker,
            projectBoundary: boundary,
            lineageService: lineage,
            sessionRegistry: registry
        )
        #expect(result.retainedUnknown == 1)
        #expect(result.removedDead == 0)
        #expect(result.removedReplaced == 0)
        #expect(await tracker.sessionCount == 1)
        #expect(await boundary.boundaryCount == 1)
        #expect(recorder.lastSnapshot?.count == 1)
    }

    @Test("prune transaction cannot delete a queued same-PID registration")
    func pruneReregisterTransaction() async throws {
        let tracker = AIProcessTracker(lineage: ProcessLineage())
        let boundary = ProjectBoundary()
        let lineage = AgentLineageService()
        let registry = AgentSessionRegistry()
        let recorder = AISnapshotRecorder()
        let probe = BlockingAIProcessProbe()
        let coordinator = AISessionLifecycleCoordinator(
            processProbe: { probe.call($0) },
            callbackPublisher: { recorder.publish($0) },
            callbackRevoker: { recorder.revoke($0) }
        )
        let oldStart = Date(timeIntervalSince1970: 760)
        _ = await coordinator.registerRoot(
            tracker: tracker,
            projectBoundary: boundary,
            lineageService: lineage,
            sessionRegistry: registry,
            pid: 760,
            executable: claudePath,
            type: .claudeCode,
            reportedProjectDirectory: "/old",
            observedAt: oldStart,
            processStartTime: oldStart,
            processStartIdentity: 760
        )

        let reconciliation = Task {
            await coordinator.reconcile(
                tracker: tracker,
                projectBoundary: boundary,
                lineageService: lineage,
                sessionRegistry: registry,
                now: Date(timeIntervalSince1970: 761)
            )
        }
        #expect(await probe.waitUntilEntered())
        let newStart = Date(timeIntervalSince1970: 762)
        let registration = Task {
            await coordinator.registerRoot(
                tracker: tracker,
                projectBoundary: boundary,
                lineageService: lineage,
                sessionRegistry: registry,
                pid: 760,
                executable: claudePath,
                type: .claudeCode,
                reportedProjectDirectory: "/new",
                observedAt: newStart,
                processStartTime: newStart,
                processStartIdentity: 762
            )
        }
        probe.release()

        #expect(await reconciliation.value.removedDead == 1)
        #expect(await registration.value.admitted)
        let surviving = try #require(await tracker.session(forPid: 760))
        #expect(surviving.identity.processStartIdentity == 762)
        #expect(await boundary.projectDirectory(aiPid: 760) == "/new")
        #expect(recorder.lastSnapshot?.first?.rootProcessID == 760)
    }

    @Test("delayed old-generation EXIT cannot revoke a recycled PID")
    func staleExitCannotRemoveReplacement() async {
        let tracker = AIProcessTracker(lineage: ProcessLineage())
        let boundary = ProjectBoundary()
        let lineage = AgentLineageService()
        let registry = AgentSessionRegistry()
        let recorder = AISnapshotRecorder()
        let pathHash = ProcessIdentity.fnv1a64(claudePath)
        let coordinator = AISessionLifecycleCoordinator(
            processProbe: { _ in
                .alive(
                    executablePathHash: pathHash,
                    processStartIdentity: 801
                )
            },
            callbackPublisher: { recorder.publish($0) },
            callbackRevoker: { recorder.revoke($0) }
        )
        let start = Date(timeIntervalSince1970: 801)
        _ = await coordinator.registerRoot(
            tracker: tracker,
            projectBoundary: boundary,
            lineageService: lineage,
            sessionRegistry: registry,
            pid: 800,
            executable: claudePath,
            type: .claudeCode,
            reportedProjectDirectory: "/project",
            observedAt: start,
            processStartTime: start,
            processStartIdentity: 801
        )
        let changed = await coordinator.processExited(
            tracker: tracker,
            projectBoundary: boundary,
            lineageService: lineage,
            sessionRegistry: registry,
            pid: 800,
            expectedStartIdentity: 800,
            now: Date()
        )
        #expect(!changed)
        #expect(await tracker.sessionCount == 1)
        #expect(recorder.revokedPIDs.isEmpty)
        #expect(await coordinator.telemetry().staleExitEventsIgnoredTotal == 1)
    }

    @Test("boundary generation CAS preserves a newer lifetime")
    func boundaryGenerationCAS() async {
        let boundary = ProjectBoundary(maximumBoundaries: 1)
        #expect(await boundary.registerBoundary(
            aiPid: 900,
            projectDir: "/project",
            processStartIdentity: 90
        ))
        #expect(await boundary.associateSession(
            aiPid: 900,
            generation: 9,
            processStartIdentity: 90
        ))
        #expect(!(await boundary.removeBoundary(
            aiPid: 900,
            matchingSessionGeneration: 8
        )))
        #expect(await boundary.boundaryCount == 1)
        #expect(await boundary.removeBoundary(
            aiPid: 900,
            matchingSessionGeneration: 9
        ))
        #expect(await boundary.telemetry().generationCASMissesTotal == 1)
    }

    @Test("one process generation keeps one immutable project boundary")
    func boundaryDoesNotDriftWithCWD() async {
        let boundary = ProjectBoundary(maximumBoundaries: 1)
        #expect(await boundary.registerBoundary(
            aiPid: 901,
            projectDir: "/project/one",
            processStartIdentity: 90
        ))
        #expect(await boundary.associateSession(
            aiPid: 901,
            generation: 9,
            processStartIdentity: 90
        ))
        #expect(await boundary.registerBoundary(
            aiPid: 901,
            projectDir: "/project/two",
            processStartIdentity: 90
        ))
        #expect(await boundary.projectDirectory(aiPid: 901) == "/project/one")

        // Conflicting known birth evidence proves a new lifetime and permits a
        // new root even though the fixed one-boundary capacity is occupied.
        #expect(await boundary.registerBoundary(
            aiPid: 901,
            projectDir: "/project/two",
            processStartIdentity: 91
        ))
        #expect(await boundary.projectDirectory(aiPid: 901) == "/project/two")
    }
}

@Suite("AI session lifecycle source ownership")
struct AISessionLifecycleSourceWiringTests {
    private var repositoryRoot: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    private func source(_ relativePath: String) throws -> String {
        try String(
            contentsOf: repositoryRoot.appendingPathComponent(relativePath),
            encoding: .utf8
        )
    }

    @Test("registration EXIT and publication share one owner")
    func eventLoopUsesCoordinator() throws {
        let eventLoop = try source("Sources/MacCrabAgentKit/EventLoop.swift")
        #expect(eventLoop.contains(
            "state.aiSessionLifecycleCoordinator.registerRoot("
        ))
        #expect(eventLoop.contains(
            "state.aiSessionLifecycleCoordinator.processExited("
        ))
        #expect(eventLoop.contains(
            "state.aiSessionLifecycleCoordinator.publishCurrent("
        ))
        #expect(!eventLoop.contains("state.aiTracker.processExited("))
        #expect(!eventLoop.contains("state.projectBoundary.removeBoundary("))
        #expect(eventLoop.contains("case .endpointSecurity, .eslogger:"))
        #expect(eventLoop.contains(
            "processStartIdentity: eventProcessStartIdentity"
        ))
    }

    @Test("60-second reconciliation is owned and shutdown-joinable")
    func timerWiresReconciliation() throws {
        let timers = try source("Sources/MacCrabAgentKit/DaemonTimers.swift")
        let lifecycle = try source(
            "Sources/MacCrabAgentKit/AISessionLifecycleCoordinator.swift"
        )
        #expect(timers.contains(
            "timerLifecycle.submit(label: \"ai-session-reconcile\")"
        ))
        #expect(timers.contains(
            "state.aiSessionLifecycleCoordinator.reconcile("
        ))
        #expect(lifecycle.contains("removeSession(\n                ifIdentityMatches: ticket"))
        #expect(lifecycle.contains("matchingSessionGeneration:"))
        #expect(lifecycle.contains("await publishCurrentSnapshot(tracker: tracker)"))
    }
}
