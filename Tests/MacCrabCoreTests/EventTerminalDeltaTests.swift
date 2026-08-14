import Foundation
import Testing
@testable import MacCrabCore

@Suite("Immutable event terminal delta")
struct EventTerminalDeltaTests {
    private final class LeaseBox: @unchecked Sendable {
        private let lock = NSLock()
        private var lease: EventPipelineMemoryLease?

        func store(_ value: EventPipelineMemoryLease?) {
            lock.lock()
            lease = value
            lock.unlock()
        }

        func release() {
            store(nil)
        }
    }

    private func tempDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(
            "maccrab-terminal-delta-\(UUID().uuidString)"
        )
        try FileManager.default.createDirectory(
            at: url,
            withIntermediateDirectories: true
        )
        return url
    }

    private func replacing(
        _ event: Event,
        commandLine: String? = nil,
        userName: String? = nil,
        enrichments: [String: String]? = nil,
        severity: Severity? = nil,
        ruleMatches: [RuleMatch]? = nil
    ) -> Event {
        let source = event.process
        let process = ProcessInfo(
            pid: source.pid,
            ppid: source.ppid,
            rpid: source.rpid,
            name: source.name,
            executable: source.executable,
            commandLine: commandLine ?? source.commandLine,
            args: source.args,
            workingDirectory: source.workingDirectory,
            userId: source.userId,
            userName: userName ?? source.userName,
            groupId: source.groupId,
            startTime: source.startTime,
            exitCode: source.exitCode,
            codeSignature: source.codeSignature,
            ancestors: source.ancestors,
            architecture: source.architecture,
            isPlatformBinary: source.isPlatformBinary,
            hashes: ProcessHashes(sha256: "aa", cdhash: "bb"),
            session: source.session,
            envVars: ["PATH": "/usr/bin"],
            auditIdentity: source.auditIdentity
        )
        return Event(
            id: event.id,
            timestamp: event.timestamp,
            eventCategory: event.eventCategory,
            eventType: event.eventType,
            eventAction: event.eventAction,
            process: process,
            file: event.file,
            network: event.network,
            tcc: event.tcc,
            enrichments: enrichments ?? event.enrichments,
            severity: severity ?? event.severity,
            ruleMatches: ruleMatches ?? event.ruleMatches
        )
    }

    @Test("delta reconstructs every allowed normal and deferred mutation")
    func reconstructsExactTerminal() throws {
        let base = makeEvent(commandLine: "/usr/bin/test --safe")
        let duplicate = RuleMatch(
            ruleId: "rule.delta",
            ruleName: "Delta",
            severity: .high,
            description: "reviewed",
            mitreTechniques: ["T1059", "T1059"],
            tags: ["z", "a", "z"]
        )
        let normalized = ReviewedRuleMatches.normalized([duplicate, duplicate])
        let terminal = replacing(
            base,
            userName: "operator",
            enrichments: [
                "FileContent": "evidence",
                "ai_tool_session_id": "session-1",
            ],
            severity: .high,
            ruleMatches: normalized
        )

        let delta = try EventTerminalDelta(base: base, terminal: terminal)
        #expect(delta.reviewedRuleMatches == .setValue(normalized))
        #expect(try delta.applying(to: base) == terminal)
        #expect(try delta.changes(base))

        let encoded = try JSONEncoder().encode(delta)
        let decoded = try JSONDecoder().decode(
            EventTerminalDelta.self,
            from: encoded
        )
        #expect(try decoded.applying(to: base) == terminal)
    }

    @Test("live ownership contention is retryable and never durable poison")
    func ownershipContentionIsTransient() async throws {
        let directory = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let budget = EventPipelineLiveMemoryBudget
            .isolatedProductionEquivalentForTesting()
        let store = try EventStore(
            directory: directory.path,
            liveMemoryBudget: budget
        )
        let basePrepared = try EventJournalAdmissionValidator.prepare(
            makeEvent()
        )
        try await store.insert(event: basePrepared.event)
        var terminal = basePrepared.event
        terminal.enrichments["reviewed"] = "after-pressure"
        let prepared = EventTerminalDeltaStoragePreparation(
            compacting: try EventTerminalDeltaValidator.prepare(
                base: basePrepared.event,
                terminal: terminal,
                baseCanonicalSHA256: basePrepared.canonicalSHA256,
                sourceIdentitySHA256: basePrepared.sourceIdentitySHA256
            )
        )
        let workspace = try #require(budget.tryAcquire(
            bytes: EventPipelineLiveMemoryBudget
                .productionEventStoreWorkspaceReserveBytes,
            owner: .eventStoreWorkspace
        ))
        let blocker = LeaseBox()
        await store.setTerminalDeltaOwnershipGrowthHookForTesting {
            let snapshot = budget.snapshot()
            blocker.store(budget.tryAcquire(
                bytes: snapshot.maximumBytes - snapshot.currentBytes,
                owner: .journalPrepared
            ))
        }

        do {
            _ = try await store.appendTerminalDeltas(
                preparedDeltas: [prepared],
                lane: .priority,
                workspaceLease: workspace
            )
            Issue.record("live ownership pressure unexpectedly persisted")
        } catch let error as EventStoreError {
            guard case .busy(let message, _) = error else {
                Issue.record("ownership pressure was not typed transient: \(error)")
                return
            }
            #expect(message.contains("base-and-delta ownership"))
        }
        #expect(try await store.payloadPoisonTotalSnapshot() == 0)

        blocker.release()
        await store.setTerminalDeltaOwnershipGrowthHookForTesting(nil)
        let retry = try await store.appendTerminalDeltas(
            preparedDeltas: [prepared],
            lane: .priority,
            workspaceLease: workspace
        )
        #expect(retry.outcomes.count == 1)
        #expect(retry.outcomes.first?.disposition == .inserted)
        #expect(try await store.payloadPoisonTotalSnapshot() == 0)
    }

    @Test("one late enrichment does not repeat a maximum-like base payload")
    func sparseOverlayIsProportionalToChange() throws {
        var base = makeEvent(commandLine: "/usr/bin/test --safe")
        base.enrichments = [
            "large_immutable_evidence": String(
                repeating: "forensic-payload-0123456789",
                count: 80_000
            ),
            "unchanged": "kept",
        ]
        var terminal = base
        terminal.enrichments["late_small_value"] = "resolved"

        let delta = try EventTerminalDelta(base: base, terminal: terminal)
        #expect(delta.enrichments.upserts == ["late_small_value": "resolved"])
        #expect(delta.enrichments.removals.isEmpty)
        #expect(try delta.applying(to: base) == terminal)

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let baseBytes = try encoder.encode(base).count
        let deltaBytes = try encoder.encode(delta).count
        #expect(baseBytes > 2_000_000)
        #expect(deltaBytes < 2_048)
        #expect(deltaBytes * 1_000 < baseBytes)
    }

    @Test("map removals and optional process nil are explicit")
    func exactSparseRemovalAndNil() throws {
        let base = replacing(
            makeEvent(commandLine: "/usr/bin/test --safe"),
            enrichments: ["remove": "old", "keep": "same"]
        )
        let source = base.process
        let process = ProcessInfo(
            pid: source.pid,
            ppid: source.ppid,
            rpid: source.rpid,
            name: source.name,
            executable: source.executable,
            commandLine: source.commandLine,
            args: source.args,
            workingDirectory: source.workingDirectory,
            userId: source.userId,
            userName: source.userName,
            groupId: source.groupId,
            startTime: source.startTime,
            exitCode: source.exitCode,
            codeSignature: nil,
            ancestors: source.ancestors,
            architecture: source.architecture,
            isPlatformBinary: source.isPlatformBinary,
            hashes: nil,
            session: source.session,
            envVars: nil,
            auditIdentity: source.auditIdentity
        )
        let terminal = Event(
            id: base.id,
            timestamp: base.timestamp,
            eventCategory: base.eventCategory,
            eventType: base.eventType,
            eventAction: base.eventAction,
            process: process,
            file: base.file,
            network: base.network,
            tcc: base.tcc,
            enrichments: ["keep": "same"],
            severity: base.severity,
            ruleMatches: base.ruleMatches
        )

        let delta = try EventTerminalDelta(base: base, terminal: terminal)
        #expect(delta.processHashes == .setNil)
        #expect(delta.processEnvironment == .setNil)
        #expect(delta.enrichments.removals == ["remove"])
        #expect(try delta.applying(to: base) == terminal)
    }

    @Test("delta rejects immutable source or process drift")
    func rejectsImmutableDrift() throws {
        let base = makeEvent(commandLine: "/usr/bin/test --safe")
        let processDrift = replacing(base, commandLine: "/bin/evil")
        #expect(throws: EventTerminalDeltaError.processIdentityChanged) {
            _ = try EventTerminalDelta(base: base, terminal: processDrift)
        }

        let eventDrift = Event(
            id: base.id,
            timestamp: base.timestamp,
            eventCategory: base.eventCategory,
            eventType: base.eventType,
            eventAction: "different-source-action",
            process: base.process,
            enrichments: base.enrichments,
            severity: base.severity,
            ruleMatches: base.ruleMatches
        )
        #expect(throws: EventTerminalDeltaError.eventIdentityChanged) {
            _ = try EventTerminalDelta(base: base, terminal: eventDrift)
        }
    }

    @Test("permuted deferred steps compose to the exact terminal value")
    func composedDeferredStepsAreExact() throws {
        let base = makeEvent(commandLine: "/usr/bin/test --safe")
        var enriched = base
        enriched.enrichments["late_hash"] = "abc123"
        var terminal = enriched
        terminal.severity = .high
        terminal.ruleMatches = [RuleMatch(
            ruleId: "rule.composed",
            ruleName: "Composed",
            severity: .high,
            description: "deferred"
        )]

        let first = try EventTerminalDelta(base: base, terminal: enriched)
        let second = try EventTerminalDelta(base: enriched, terminal: terminal)
        let composed = try EventTerminalDelta(eventID: base.id)
            .followed(by: first)
            .followed(by: second)
        #expect(try composed.applying(to: base) == terminal)

        let basePreparation = try EventJournalAdmissionValidator.prepare(base)
        let prepared = try EventTerminalDeltaValidator.prepare(
            delta: composed,
            baseCanonicalSHA256: basePreparation.canonicalSHA256,
            sourceIdentitySHA256: basePreparation.sourceIdentitySHA256
        )
        #expect(prepared.overflow == nil)
        #expect(prepared.canonicalDeltaJSON.count
            < EventTerminalDeltaValidator.maximumCanonicalDeltaBytes)
        #expect(try JSONDecoder().decode(
            EventTerminalDelta.self,
            from: prepared.canonicalDeltaJSON
        ) == composed)
    }
}
