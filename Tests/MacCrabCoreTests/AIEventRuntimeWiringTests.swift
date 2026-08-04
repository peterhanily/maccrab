import Foundation
import Testing

@Suite("AI event runtime wiring")
struct AIEventRuntimeWiringTests {
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

    private func occurrences(of needle: String, in text: String) -> Int {
        text.components(separatedBy: needle).count - 1
    }

    @Test("ProjectBoundary owns the root before tracker, lineage, and callback publication")
    func rootRegistrationOrderDoesNotDrift() throws {
        let eventLoop = try source("Sources/MacCrabAgentKit/EventLoop.swift")
        let coordinator = try source(
            "Sources/MacCrabAgentKit/AISessionLifecycleCoordinator.swift"
        )
        let helperStart = try #require(coordinator.range(of: "func registerRoot("))
        let helper = coordinator[helperStart.lowerBound...]
        let boundary = try #require(helper.range(of: "projectBoundary.registerBoundary("))
        let accepted = try #require(helper.range(of: "projectBoundary.projectDirectory("))
        let tracker = try #require(helper.range(of: "tracker.registerAIProcessIdentity("))
        let admittedAssociation = try #require(helper.range(of:
            "projectBoundary.associateSession("))
        let lineage = try #require(helper.range(
            of: "lineageService.startSession(",
            range: admittedAssociation.upperBound..<helper.endIndex
        ))
        let publication = try #require(helper.range(
            of: "publishCurrentSnapshot(tracker: tracker)",
            range: lineage.upperBound..<helper.endIndex
        ))

        #expect(boundary.lowerBound < accepted.lowerBound)
        #expect(accepted.lowerBound < tracker.lowerBound)
        #expect(tracker.lowerBound < admittedAssociation.lowerBound)
        #expect(admittedAssociation.lowerBound < lineage.lowerBound)
        #expect(lineage.lowerBound < publication.lowerBound)

        // A hard-cap rejection has no lineage/session derivative. It rolls the
        // boundary back and may publish the unchanged tracker snapshot before
        // returning; that distinct branch must not be mistaken for admitted
        // publication ordering.
        let rejectedBranch = helper[tracker.upperBound..<admittedAssociation.lowerBound]
        let rollback = try #require(rejectedBranch.range(of:
            "projectBoundary.removeBoundary(aiPid: pid)"))
        let rejectedPublication = try #require(rejectedBranch.range(of:
            "publishCurrentSnapshot(tracker: tracker)"))
        #expect(rollback.lowerBound < rejectedPublication.lowerBound)
        #expect(eventLoop.contains(
            "state.aiSessionLifecycleCoordinator.registerRoot("
        ))
        #expect(coordinator.contains("projectRoots: session.projectDir.isEmpty"))
    }

    @Test("active ancestry wins before direct AI root promotion")
    func nestedAgentAttributionOrderDoesNotDrift() throws {
        let eventLoop = try source("Sources/MacCrabAgentKit/EventLoop.swift")
        let childLookup = try #require(eventLoop.range(of:
            "childAttribution = await state.aiTracker.isAIChild("))
        let rootPromotion = try #require(eventLoop.range(of:
            "if !childAttribution.isChild, let aiType = directAIType"))
        #expect(childLookup.lowerBound < rootPromotion.lowerBound)
        #expect(eventLoop.contains("promoteUnregisteredAncestors: false"))
        #expect(eventLoop.contains("let rootPid = childAttribution.rootPid"))
        #expect(eventLoop.contains("enrichedEvent.enrichments[\"ai_root_pid\"]"))
    }

    @Test("AI root and child share one credential and boundary enforcement path")
    func rootChildFilesystemGuardParityDoesNotDrift() throws {
        let eventLoop = try source("Sources/MacCrabAgentKit/EventLoop.swift")
        #expect(occurrences(
            of: "resolvedAIAttribution = ResolvedAIAttribution(",
            in: eventLoop
        ) == 2, "root and child must each resolve the shared guard context")
        #expect(occurrences(
            of: "ruleId: \"maccrab.ai-guard.credential-access\"",
            in: eventLoop
        ) == 1, "credential enforcement must have one root/child alert path")
        #expect(occurrences(
            of: "ruleId: \"maccrab.ai-guard.boundary-violation\"",
            in: eventLoop
        ) == 1, "boundary enforcement must have one root/child alert path")
        #expect(occurrences(
            of: "await enforceAIFilesystemGuards(",
            in: eventLoop
        ) == 1)
        #expect(eventLoop.contains(
            "ProjectBoundary.mutationEventActions.contains(event.eventAction.lowercased())"
        ), "OPEN/read callbacks must not masquerade as boundary writes")
    }

    @Test("lineage materializes only exec spawns and canonical completed text events")
    func lineageVolumeGuardsDoNotDrift() throws {
        let eventLoop = try source("Sources/MacCrabAgentKit/EventLoop.swift")
        let execGate = try #require(eventLoop.range(of:
            "enrichedEvent.eventCategory == .process,"))
        let spawn = try #require(eventLoop.range(of: "kind: .processSpawn("))
        #expect(execGate.lowerBound < spawn.lowerBound)
        #expect(eventLoop.contains("enrichedEvent.eventAction == \"exec\""))
        #expect(eventLoop.contains("AgentLineageService.materializedFileEventKind("))
        #expect(!eventLoop.contains("isCredentialShapedPath"),
                "EventLoop must not grow a second private-path classifier")
    }

    @Test("dynamic AI OPEN demand precedes static discard while platform keychain stays final")
    func callbackAdmissionOrderDoesNotDrift() throws {
        let collector = try source("Sources/MacCrabCore/Collectors/ESCollector.swift")
        let helperStart = try #require(collector.range(of:
            "static func shouldDropBeforeWorker(\n        eventType: UInt32"))
        let helper = collector[helperStart.lowerBound...]
        let keychainGate = try #require(helper.range(of:
            "if isPlatformBinary && isKeychainPath(path) { return true }"))
        let dynamicDecision = try #require(helper.range(of:
            "dynamicAIRegistry.shouldAdmit(facts)"))
        #expect(keychainGate.lowerBound < dynamicDecision.lowerBound)
        #expect(collector.contains("processID: audit_token_to_pid(msg.process.pointee.audit_token)"))
        #expect(collector.contains("bridgeDynamicAIProcessStart(message: message)"))
        #expect(collector.contains("publishDynamicAIFileEventSessions("))
        #expect(collector.contains("revokeDynamicAIFileEventProcess("))
        #expect(!collector.contains(
            "guard Self.isCredentialReadPath(openPath) || Self.isAgentContentReadPath(openPath) else"
        ), "normalisation must not discard an OPEN retained by dynamic AI demand")
    }

    @Test("remote certificate enrichment cannot block the event consumer")
    func certificateTransparencyUsesAdvisoryLane() throws {
        let eventLoop = try source("Sources/MacCrabAgentKit/EventLoop.swift")
        #expect(eventLoop.contains("label: \"cert-transparency\""))
        #expect(eventLoop.contains("await ctMonitor"))
        #expect(!eventLoop.contains(
            "let ctResult = await state.ctMonitor.checkDomain"
        ))
    }

    @Test("package registry checks cannot block the event consumer")
    func packageFreshnessUsesProtectionLane() throws {
        let eventLoop = try source("Sources/MacCrabAgentKit/EventLoop.swift")
        #expect(eventLoop.contains("label: \"package-freshness\""))
        #expect(eventLoop.contains("state.detectionWorkLifecycle.submit("))
        #expect(eventLoop.contains("await packageChecker.checkPackages("))
        #expect(!eventLoop.contains(
            "await state.packageChecker.checkPackages("
        ))
    }

    @Test("bounded file-content scans cannot block the event consumer")
    func fileInjectionScanUsesProtectionLane() throws {
        let eventLoop = try source("Sources/MacCrabAgentKit/EventLoop.swift")
        #expect(eventLoop.contains("label: \"file-injection-scan\""))
        #expect(eventLoop.contains("await scanner.scanFile("))
        #expect(!eventLoop.contains(
            "await state.fileInjectionScanner.scanFile("
        ))
    }
}
