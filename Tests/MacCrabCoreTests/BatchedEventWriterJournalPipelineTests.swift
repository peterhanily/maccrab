import CryptoKit
import Foundation
import Testing
@testable import MacCrabAgentKit
@testable import MacCrabCore

@Suite("BatchedEventWriter exact journal pipeline")
struct BatchedEventWriterJournalPipelineTests {
    private actor JournalStoreFake: EventBatchInserting,
        EventPreparedBatchInserting, EventJournalMutating {
        enum BaseMode: Sendable, Equatable { case durable, filtered, fail }

        let baseMode: BaseMode
        let ensureDelay: Duration?
        private var terminalDeltaBusy: Bool
        private var bases: [UUID: EventJournalIngressPreparation] = [:]
        private var terminals: [UUID: EventJournalIngressPreparation] = [:]
        private var terminalDeltas: [
            UUID: EventTerminalDeltaStoragePreparation
        ] = [:]
        private var promoted: [UUID: [RuleMatch]] = [:]
        private var mutationGeneration: UInt64 = 0
        private(set) var terminalAppendCalls = 0
        private(set) var terminalDeltaAppendCalls = 0
        private(set) var ensureCalls = 0
        private(set) var verifyCalls = 0

        init(
            baseMode: BaseMode = .durable,
            ensureDelay: Duration? = nil,
            terminalDeltaInitiallyBusy: Bool = false
        ) {
            self.baseMode = baseMode
            self.ensureDelay = ensureDelay
            terminalDeltaBusy = terminalDeltaInitiallyBusy
        }

        func insert(
            events: [Event],
            lane: EventPipelineLane
        ) async throws -> EventBatchInsertResult {
            try await insert(
                preparedEvents: events.map(
                    EventJournalAdmissionValidator.prepare
                ),
                lane: lane
            )
        }

        func insert(
            preparedEvents: [EventJournalIngressPreparation],
            lane _: EventPipelineLane
        ) async throws -> EventBatchInsertResult {
            if baseMode == .fail {
                throw EventStoreError.stepFailed("fixture permanent failure")
            }
            var dispositions: [EventJournalInsertDisposition] = []
            var durable = 0
            var filtered = 0
            for prepared in preparedEvents {
                if let overflow = prepared.overflow {
                    dispositions.append(.poisoned(overflow))
                } else if baseMode == .filtered {
                    filtered += 1
                    dispositions.append(.filtered(eventID: prepared.event.id))
                } else {
                    try storeBase(prepared)
                    durable += 1
                    dispositions.append(.durable(eventID: prepared.event.id))
                }
            }
            if durable > 0 || dispositions.contains(where: {
                if case .poisoned = $0 { return true }
                return false
            }) {
                mutationGeneration &+= 1
            }
            return EventBatchInsertResult(
                inputCount: preparedEvents.count,
                persistedCount: durable,
                filteredCount: filtered,
                committedTransactionCount: preparedEvents.isEmpty ? 0 : 1,
                inputDispositions: dispositions
            )
        }

        func ensureJournaled(
            _ prepared: EventJournalIngressPreparation,
            lane _: EventPipelineLane,
            reason: EventJournalEnsureReason
        ) async throws -> EventJournalEnsureOutcome {
            ensureCalls += 1
            if let ensureDelay {
                try await Task.sleep(for: ensureDelay)
            }
            if let overflow = prepared.overflow { return .poisoned(overflow) }
            if reason == .ordinary, baseMode == .filtered {
                return .filtered(eventID: prepared.event.id)
            }
            try storeBase(prepared)
            mutationGeneration &+= 1
            return .durable(eventID: prepared.event.id)
        }

        func appendTerminalRevisions(
            preparedEvents: [EventJournalIngressPreparation],
            lane _: EventPipelineLane
        ) async throws -> EventTerminalRevisionBatchResult {
            terminalAppendCalls += 1
            var outcomes: [EventTerminalRevisionOutcome] = []
            var durable: Set<UUID> = []
            var inserted: Set<UUID> = []
            var idempotent: Set<UUID> = []
            for prepared in preparedEvents {
                let id = prepared.event.id
                if let overflow = prepared.overflow {
                    outcomes.append(.poisoned(overflow))
                    mutationGeneration &+= 1
                    continue
                }
                guard let base = bases[id] else {
                    throw EventStoreError.stepFailed("terminal without base")
                }
                if base.canonicalSHA256 == prepared.canonicalSHA256 {
                    outcomes.append(.unchangedBase(eventID: id))
                    durable.insert(id)
                } else if let prior = terminals[id] {
                    guard prior.canonicalSHA256 == prepared.canonicalSHA256 else {
                        throw EventStoreError.immutableEventConflict(eventID: id)
                    }
                    outcomes.append(.alreadyDurable(eventID: id))
                    durable.insert(id)
                    idempotent.insert(id)
                } else {
                    terminals[id] = prepared
                    outcomes.append(.inserted(eventID: id))
                    durable.insert(id)
                    inserted.insert(id)
                    mutationGeneration &+= 1
                }
            }
            return EventTerminalRevisionBatchResult(
                inputCount: preparedEvents.count,
                outcomes: outcomes,
                durableEventIDs: durable,
                insertedEventIDs: inserted,
                idempotentEventIDs: idempotent,
                committedTransactionCount: preparedEvents.isEmpty ? 0 : 1,
                storageMutationGeneration: mutationGeneration
            )
        }

        func appendTerminalDeltas(
            preparedDeltas: [EventTerminalDeltaStoragePreparation],
            lane _: EventPipelineLane,
            workspaceLease: EventPipelineMemoryLease
        ) async throws -> EventTerminalDeltaBatchResult {
            #expect(workspaceLease.owner == .eventStoreWorkspace)
            #expect(
                workspaceLease.bytes
                    == EventPipelineLiveMemoryBudget
                        .productionEventStoreWorkspaceReserveBytes
            )
            terminalDeltaAppendCalls += 1
            if terminalDeltaBusy {
                throw EventStoreError.busy(
                    "fixture terminal ownership pressure"
                )
            }
            var outcomes: [EventTerminalDeltaOutcome] = []
            var committed = 0
            for prepared in preparedDeltas {
                guard let base = bases[prepared.eventID],
                      base.canonicalSHA256
                        == prepared.baseCanonicalSHA256,
                      base.sourceIdentitySHA256
                        == prepared.sourceIdentitySHA256 else {
                    throw EventStoreError.terminalRevisionRequiresBase(
                        eventID: prepared.eventID
                    )
                }
                if let overflow = prepared.overflow {
                    mutationGeneration &+= 1
                    committed += 1
                    outcomes.append(EventTerminalDeltaOutcome(
                        eventID: prepared.eventID,
                        disposition: .poisoned(overflow),
                        canonicalDeltaSHA256:
                            prepared.canonicalDeltaSHA256,
                        terminalCanonicalSHA256: nil,
                        terminalCanonicalByteCount: 0
                    ))
                    continue
                }
                let delta = try JSONDecoder().decode(
                    EventTerminalDelta.self,
                    from: prepared.canonicalDeltaJSON
                )
                let terminal = try delta.applying(to: base.event)
                let terminalPrepared = try EventJournalAdmissionValidator
                    .prepare(terminal)
                let disposition: EventTerminalDeltaOutcome.Disposition
                if delta.isEmpty {
                    disposition = .unchangedBase
                } else if let prior = terminalDeltas[prepared.eventID] {
                    guard prior.canonicalDeltaSHA256
                            == prepared.canonicalDeltaSHA256 else {
                        throw EventStoreError.immutableEventConflict(
                            eventID: prepared.eventID
                        )
                    }
                    disposition = .alreadyDurable
                } else {
                    terminalDeltas[prepared.eventID] = prepared
                    terminals[prepared.eventID] = terminalPrepared
                    mutationGeneration &+= 1
                    committed += 1
                    disposition = .inserted
                }
                outcomes.append(EventTerminalDeltaOutcome(
                    eventID: prepared.eventID,
                    disposition: disposition,
                    canonicalDeltaSHA256: prepared.canonicalDeltaSHA256,
                    terminalCanonicalSHA256:
                        terminalPrepared.canonicalSHA256,
                    terminalCanonicalByteCount:
                        terminalPrepared.canonicalJSON.count
                ))
            }
            return EventTerminalDeltaBatchResult(
                inputCount: preparedDeltas.count,
                outcomes: outcomes,
                committedTransactionCount: committed,
                storageMutationGeneration: mutationGeneration
            )
        }

        func promoteProjection(
            eventID: UUID,
            reviewedMatches: [RuleMatch]
        ) async throws -> ProjectionPromotionOutcome {
            let merged = ReviewedRuleMatches.merged(
                promoted[eventID] ?? [],
                reviewedMatches
            )
            let inserted = merged.count - (promoted[eventID]?.count ?? 0)
            promoted[eventID] = merged
            mutationGeneration &+= 1
            return ProjectionPromotionOutcome(
                eventID: eventID,
                insertedMatchCount: max(0, inserted),
                totalReviewedMatchCount: merged.count,
                projectionMaterialized: true,
                storageMutationGeneration: mutationGeneration
            )
        }

        func verifyJournaled(
            eventID: UUID,
            canonicalSHA256: Data
        ) async throws -> EventJournalVerification {
            verifyCalls += 1
            guard let base = bases[eventID] else {
                return EventJournalVerification(
                    disposition: .missing(eventID: eventID),
                    storageMutationGeneration: mutationGeneration
                )
            }
            guard base.canonicalSHA256 == canonicalSHA256 else {
                return EventJournalVerification(
                    disposition: .conflict(eventID: eventID),
                    storageMutationGeneration: mutationGeneration
                )
            }
            if let overflow = base.overflow {
                return EventJournalVerification(
                    disposition: .poisoned(overflow),
                    storageMutationGeneration: mutationGeneration
                )
            }
            return EventJournalVerification(
                disposition: .durable(eventID: eventID),
                storageMutationGeneration: mutationGeneration
            )
        }

        private func storeBase(
            _ prepared: EventJournalIngressPreparation
        ) throws {
            if let prior = bases[prepared.event.id] {
                guard prior.canonicalSHA256 == prepared.canonicalSHA256 else {
                    throw EventStoreError.immutableEventConflict(
                        eventID: prepared.event.id
                    )
                }
            } else {
                bases[prepared.event.id] = prepared
            }
        }

        func exactEvent(_ id: UUID) -> Event? {
            terminals[id]?.event ?? bases[id]?.event
        }

        func reviewedMatches(_ id: UUID) -> [RuleMatch] {
            promoted[id] ?? []
        }

        func releaseTerminalDeltaPressure() {
            terminalDeltaBusy = false
        }
    }

    private func event(
        _ index: Int,
        id: UUID = UUID(),
        args: [String] = [],
        action: String = "exec"
    ) -> Event {
        let timestamp = Date(timeIntervalSince1970: 1_800_000_000 + Double(index))
        return Event(
            id: id,
            timestamp: timestamp,
            eventCategory: .process,
            eventType: .start,
            eventAction: action,
            process: ProcessInfo(
                pid: Int32(10_000 + index),
                ppid: 1,
                rpid: Int32(10_000 + index),
                name: "fixture-\(index)",
                executable: "/usr/bin/fixture-\(index)",
                commandLine: "/usr/bin/fixture-\(index)",
                args: args,
                workingDirectory: "/private/tmp",
                userId: 501,
                userName: "tester",
                groupId: 20,
                startTime: timestamp,
                ancestors: [],
                architecture: "arm64",
                isPlatformBinary: false
            )
        )
    }

    @Test("terminal-only work after a drained base is joined exactly once")
    func terminalOnlyDrain() async throws {
        let store = JournalStoreFake()
        let writer = BatchedEventWriter(
            store: store,
            flushThreshold: 10_000,
            hardCap: 100
        )
        let base = event(1)
        let basePrepared = try EventJournalAdmissionValidator.prepare(base)
        let receipt = try #require(await writer.enqueuePrepared(basePrepared))
        await writer.shutdown()

        var terminal = base
        terminal.enrichments["heavy.sha256"] = String(repeating: "ab", count: 32)
        let terminalPrepared = try EventJournalAdmissionValidator.prepare(terminal)
        #expect(await writer.enqueueTerminalRevision(
            terminalPrepared,
            admission: receipt
        ) == .queued)
        #expect((await writer.telemetrySnapshot()).terminalRevisionBufferDepth == 1)

        await writer.shutdown()
        #expect(await store.terminalAppendCalls == 1)
        #expect(await store.exactEvent(base.id) == terminalPrepared.event)
        let snapshot = await writer.telemetrySnapshot()
        #expect(snapshot.terminalRevisionOfferedCount == 1)
        #expect(snapshot.terminalRevisionDurableCount == 1)
        #expect(snapshot.terminalRevisionBufferDepth == 0)
        #expect(snapshot.terminalRevisionInFlightDepth == 0)
        #expect(snapshot.terminalRevisionConservationHolds)
        #expect(snapshot.terminalStorageMutationGeneration > 0)
    }

    @Test("settled terminal receipt is digest-bound and storage-durable")
    func settledTerminalReceipt() async throws {
        let store = JournalStoreFake()
        let writer = BatchedEventWriter(
            store: store,
            flushThreshold: 10_000,
            hardCap: 100
        )
        let base = event(20)
        let receipt = try #require(await writer.enqueuePrepared(
            EventJournalAdmissionValidator.prepare(base)
        ))
        var terminal = base
        terminal.enrichments["reviewed"] = "true"
        terminal.severity = .high

        let proof = await writer.prepareAndSettleTerminalDelta(
            base: base,
            terminal: terminal,
            admission: receipt,
            timeout: .seconds(1)
        )
        let expected = try EventJournalAdmissionValidator.prepare(terminal)
        #expect(proof.eventID == terminal.id)
        #expect(proof.baseGeneration == receipt.generation)
        #expect(proof.baseCanonicalSHA256 == receipt.canonicalSHA256)
        #expect(proof.terminalCanonicalSHA256 == expected.canonicalSHA256)
        #expect(proof.terminalCanonicalByteCount
            == expected.canonicalJSON.count)
        #expect(proof.status == .verified)
        #expect(proof.storageMutationGeneration > 0)
        #expect(await store.exactEvent(base.id) == expected.event,
                "returning verified must follow terminal durability")
        #expect(await store.terminalDeltaAppendCalls == 1)

        let snapshot = await writer.telemetrySnapshot()
        #expect(snapshot.terminalRevisionBufferDepth == 0)
        #expect(snapshot.terminalRevisionInFlightDepth == 0)
        #expect(snapshot.terminalRevisionDurableCount == 1)
        #expect(snapshot.terminalRevisionConservationHolds)
    }

    @Test("terminal delta outlives transient storage pressure without poisoning")
    func terminalDeltaRetriesTransientPressureLosslessly() async throws {
        let store = JournalStoreFake(terminalDeltaInitiallyBusy: true)
        let writer = BatchedEventWriter(
            store: store,
            flushThreshold: 10_000,
            hardCap: 100
        )
        let base = event(21)
        let receipt = try #require(await writer.enqueuePrepared(
            EventJournalAdmissionValidator.prepare(base)
        ))
        var terminal = base
        terminal.enrichments["reviewed"] = "after-pressure"

        let release = Task {
            // Exceeds the former five-second sparse-settlement deadline.
            try await Task.sleep(for: .milliseconds(5_250))
            await store.releaseTerminalDeltaPressure()
        }
        let proof = await writer.prepareAndSettleTerminalDelta(
            base: base,
            terminal: terminal,
            admission: receipt,
            timeout: .seconds(1)
        )
        _ = try await release.value

        #expect(proof.status == .verified)
        #expect(await store.terminalDeltaAppendCalls > 1)
        let snapshot = await writer.telemetrySnapshot()
        #expect(snapshot.terminalRevisionRetriedCount > 0)
        #expect(snapshot.terminalRevisionPoisonedCount == 0)
        #expect(snapshot.terminalRevisionDroppedCount == 0)
        #expect(snapshot.terminalRevisionConservationHolds)
    }

    @Test("wrong or missing receipt digest cannot append a terminal revision")
    func wrongDigestRejected() async throws {
        let store = JournalStoreFake()
        let writer = BatchedEventWriter(store: store, flushThreshold: 10_000)
        let base = event(2)
        let receipt = try #require(await writer.enqueuePrepared(
            EventJournalAdmissionValidator.prepare(base)
        ))
        var terminal = base
        terminal.enrichments["reviewed"] = "true"
        let prepared = try EventJournalAdmissionValidator.prepare(terminal)
        let forged = EventJournalAdmission(
            eventID: receipt.eventID,
            generation: receipt.generation,
            canonicalSHA256: Data(repeating: 0xA5, count: 32),
            canonicalByteCount: receipt.canonicalByteCount
        )
        #expect(await writer.enqueueTerminalRevision(
            prepared,
            admission: forged
        ) == .rejected)
        #expect(await writer.awaitJournalAdmission(forged) == .mismatchedReceipt)
        let missing = EventJournalAdmission(
            eventID: receipt.eventID,
            generation: receipt.generation
        )
        #expect(await writer.awaitJournalAdmission(missing) == .mismatchedReceipt)
    }

    @Test("terminal preparation must bind the immutable base source identity")
    func terminalSourceIdentityMismatchRejected() async throws {
        let store = JournalStoreFake()
        let writer = BatchedEventWriter(store: store, flushThreshold: 10_000)
        let base = event(21)
        let receipt = try #require(await writer.enqueuePrepared(
            EventJournalAdmissionValidator.prepare(base)
        ))
        await writer.shutdown()

        var differentSource = event(21, id: base.id, action: "fork")
        differentSource.enrichments["late"] = "value"
        let prepared = try EventJournalAdmissionValidator.prepare(
            differentSource
        )
        #expect(await writer.enqueueTerminalRevision(
            prepared,
            admission: receipt
        ) == .rejected)
        #expect(await store.terminalAppendCalls == 0)
    }

    @Test("terminal poison is settled, conserved, and never durable")
    func terminalPoisonConserved() async throws {
        let store = JournalStoreFake()
        let writer = BatchedEventWriter(store: store, flushThreshold: 10_000)
        let base = event(3)
        let receipt = try #require(await writer.enqueuePrepared(
            EventJournalAdmissionValidator.prepare(base)
        ))
        await writer.shutdown()

        var replacement = base
        replacement.enrichments["journal_overflow"] = "poison"
        let canonical = try EventPrivacySanitizer.sanitize(replacement)
        let overflow = EventJournalOverflowEvidence(
            originalEventID: base.id,
            originalBytes: EventJournalAdmissionValidator
                .maximumCanonicalRecordBytes + 1,
            originalSHA256: Data(repeating: 0x11, count: 32),
            digestKind: .canonicalJSON,
            sourceIdentitySHA256: Data(repeating: 0x22, count: 32)
        )
        let poisoned = EventJournalIngressPreparation(
            event: canonical.event,
            canonicalJSON: canonical.canonicalJSON,
            canonicalSHA256: Data(SHA256.hash(data: canonical.canonicalJSON)),
            overflow: overflow,
            retainedByteEstimate: canonical.canonicalJSON.count
        )
        #expect(await writer.enqueueTerminalRevision(
            poisoned,
            admission: receipt
        ) == .queued)
        await writer.shutdown()

        let snapshot = await writer.telemetrySnapshot()
        #expect(snapshot.terminalRevisionPoisonedCount == 1)
        #expect(snapshot.terminalRevisionDurableCount == 0)
        #expect(snapshot.terminalRevisionDroppedCount == 0)
        #expect(snapshot.terminalRevisionConservationHolds)
        #expect(snapshot.terminalRevisionEvidencePoisoned)
    }

    @Test("aged internal handle revalidates while public lookalike is rejected")
    func delayedHandlePastReceiptHistory() async throws {
        let store = JournalStoreFake()
        let writer = BatchedEventWriter(
            store: store,
            flushThreshold: 10_000,
            hardCap: 100,
            admissionResolutionCapacity: 2
        )
        let first = event(10)
        let firstReceipt = try #require(await writer.enqueuePrepared(
            EventJournalAdmissionValidator.prepare(first)
        ))
        for index in 11..<15 {
            _ = await writer.enqueuePrepared(
                try EventJournalAdmissionValidator.prepare(event(index))
            )
        }
        await writer.shutdown()

        #expect(await writer.awaitJournalAdmission(firstReceipt) == .verified)
        #expect(await store.verifyCalls == 1,
                "aged compact receipt must exact-revalidate through storage")
        let publicLookalike = EventJournalAdmission(
            eventID: firstReceipt.eventID,
            generation: firstReceipt.generation,
            canonicalSHA256: firstReceipt.canonicalSHA256,
            canonicalByteCount: firstReceipt.canonicalByteCount
        )
        #expect(await writer.awaitJournalAdmission(publicLookalike)
            == .mismatchedReceipt)
    }

    @Test("sustained permanent failure keeps repair metadata bounded")
    func sustainedFailureGapStateIsBounded() async throws {
        let store = JournalStoreFake(baseMode: .fail)
        let writer = BatchedEventWriter(
            store: store,
            flushThreshold: 10_000,
            hardCap: 100,
            admissionResolutionCapacity: 3
        )
        for index in 100..<120 {
            _ = await writer.enqueuePrepared(
                try EventJournalAdmissionValidator.prepare(event(index))
            )
        }
        await writer.shutdown()

        let snapshot = await writer.telemetrySnapshot()
        #expect(snapshot.droppedCount == 20)
        #expect(snapshot.repairableJournalGapCount <= 3)
        #expect(snapshot.earliestJournalGapGeneration == 1)
    }

    @Test("failed repair payload expires to a permanent identity-bound gap")
    func failedRepairPayloadExpires() async throws {
        let store = JournalStoreFake(baseMode: .fail)
        let writer = BatchedEventWriter(
            store: store,
            flushThreshold: 10_000,
            repairPayloadLeaseDuration: .milliseconds(2)
        )
        let receipt = try #require(await writer.enqueuePrepared(
            EventJournalAdmissionValidator.prepare(event(150))
        ))
        await writer.shutdown()

        try await Task.sleep(for: .milliseconds(10))
        #expect(await writer.awaitJournalAdmission(receipt) == .repairExpired)
        let snapshot = await writer.telemetrySnapshot()
        #expect(snapshot.repairPayloadExpiredTotal == 1)
        #expect(snapshot.repairPayloadLeaseCount == 0)
        #expect(snapshot.earliestJournalGapGeneration == receipt.generation)
        #expect(receipt.preparedHandle?.availablePreparation == nil)
    }

    @Test("filtered payload expiry does not poison later conserved exclusions")
    func filteredRepairPayloadExpiryIsNotPrefixGap() async throws {
        let store = JournalStoreFake(baseMode: .filtered)
        let writer = BatchedEventWriter(
            store: store,
            flushThreshold: 10_000,
            repairPayloadLeaseDuration: .milliseconds(2)
        )
        let receipt = try #require(await writer.enqueuePrepared(
            EventJournalAdmissionValidator.prepare(event(151))
        ))
        await writer.shutdown()

        try await Task.sleep(for: .milliseconds(10))
        #expect(await writer.awaitJournalAdmission(receipt) == .repairExpired)
        let snapshot = await writer.telemetrySnapshot()
        #expect(snapshot.repairPayloadExpiredTotal == 1)
        #expect(snapshot.earliestJournalGapGeneration == nil)
    }

    @Test("repair expiry keeps prepared bytes charged through an in-flight call")
    func repairExpiryWhileEnsureIsSuspended() async throws {
        let store = JournalStoreFake(
            baseMode: .filtered,
            ensureDelay: .milliseconds(200)
        )
        let writer = BatchedEventWriter(
            store: store,
            flushThreshold: 10_000,
            repairPayloadLeaseDuration: .milliseconds(50)
        )
        let receipt = try #require(await writer.enqueuePrepared(
            EventJournalAdmissionValidator.prepare(
                event(175, args: Array(repeating: "payload", count: 20_000))
            )
        ))
        await writer.shutdown()
        let fullCharge = (await writer.telemetrySnapshot())
            .preparedOwnershipBytes

        let repair = Task { await writer.awaitJournalAdmission(receipt) }
        for _ in 0..<100 {
            if await store.ensureCalls > 0 { break }
            try await Task.sleep(for: .milliseconds(1))
        }
        #expect(await store.ensureCalls == 1)
        try await Task.sleep(for: .milliseconds(60))
        let suspended = await writer.telemetrySnapshot()
        #expect(suspended.repairPayloadExpiredTotal == 1)
        #expect(suspended.preparedOwnershipBytes == fullCharge,
                "expiry must not release credit while EventStore owns the value")

        #expect(await repair.value == .repairExpired,
                "a completion past the repair deadline cannot become verified")
        let compacted = await writer.telemetrySnapshot()
        #expect(compacted.preparedOwnershipBytes
            == EventJournalPreparedOwnershipBudget.compactReceiptByteCharge)
        #expect(compacted.earliestJournalGapGeneration == nil,
                "an intentional filtered exclusion is not a prior-prefix gap")
    }

    @Test("container-heavy handles obey one shared base and terminal byte cap")
    func sharedPreparedOwnershipByteCap() async throws {
        let prepared = try EventJournalAdmissionValidator.prepare(
            event(200, args: Array(repeating: "", count: 20_000))
        )
        let probe = EventJournalPreparedOwnershipBudget(
            maximumCount: 10,
            maximumBytes: Int.max
        )
        var probeHandle: EventJournalPreparedHandle? = try #require(
            probe.acquire(prepared)
        )
        let charge = probe.snapshot().retainedBytes
        #expect(charge >= prepared.retainedByteEstimate
            + prepared.canonicalJSON.count,
            "container backing and canonical bytes must both be charged")
        probeHandle = nil
        #expect(probe.snapshot().retainedBytes == 0)

        let store = JournalStoreFake()
        let writer = BatchedEventWriter(
            store: store,
            flushThreshold: 10_000,
            hardCap: 10,
            hardByteCap: charge
        )
        let first = try #require(await writer.enqueuePrepared(prepared))
        let secondEvent = event(201, args: Array(repeating: "", count: 20_000))
        #expect(await writer.enqueuePrepared(
            try EventJournalAdmissionValidator.prepare(secondEvent)
        ) == nil)
        let snapshot = await writer.telemetrySnapshot()
        #expect(snapshot.preparedOwnershipCount == 1)
        #expect(snapshot.preparedOwnershipBytes == charge)
        #expect(snapshot.preparedOwnershipBytes
            <= snapshot.preparedOwnershipMaximumBytes)
        _ = first
    }

    @Test("durable base compacts shared receipt ownership to fixed metadata")
    func durableBaseCompactsPreparedOwnership() async throws {
        let store = JournalStoreFake()
        let writer = BatchedEventWriter(
            store: store,
            flushThreshold: 10_000,
            hardCap: 10,
            hardByteCap: 64 * 1_024 * 1_024
        )
        var receipt: EventJournalAdmission? = try #require(
            await writer.enqueuePrepared(
                EventJournalAdmissionValidator.prepare(
                    event(250, args: Array(repeating: "payload", count: 20_000))
                )
            )
        )
        let before = await writer.telemetrySnapshot()
        #expect(before.preparedOwnershipBytes
            > EventJournalPreparedOwnershipBudget.compactReceiptByteCharge)

        await writer.shutdown()
        let compacted = await writer.telemetrySnapshot()
        #expect(compacted.preparedOwnershipCount == 0,
                "compact receipts no longer consume a full-preparation slot")
        #expect(compacted.preparedOwnershipCompactReceiptCount == 1)
        #expect(compacted.preparedOwnershipLiveHandleCount == 1)
        #expect(compacted.preparedOwnershipBytes
            == EventJournalPreparedOwnershipBudget.compactReceiptByteCharge)
        #expect(await writer.awaitJournalAdmission(try #require(receipt))
            == .verified)

        receipt = nil
        let released = await writer.telemetrySnapshot()
        #expect(released.preparedOwnershipBytes == 0)
        #expect(released.preparedOwnershipCompactReceiptCount == 0)
        #expect(released.preparedOwnershipLiveHandleCount == 0)
    }

    @Test("compact receipts consume the bounded live-handle slot")
    func compactReceiptCountIsBounded() async throws {
        let budget = EventJournalPreparedOwnershipBudget(
            maximumCount: 1,
            maximumBytes: 64 * 1_024 * 1_024
        )
        var first: EventJournalPreparedHandle? = try #require(
            budget.acquire(
                try EventJournalAdmissionValidator.prepare(event(275))
            )
        )
        first?.compactAfterDurableVerification()
        var snapshot = budget.snapshot()
        #expect(snapshot.retainedCount == 0)
        #expect(snapshot.compactReceiptCount == 1)
        #expect(snapshot.liveHandleCount == 1)

        #expect(budget.acquire(
            try EventJournalAdmissionValidator.prepare(event(276))
        ) == nil)
        first = nil
        snapshot = budget.snapshot()
        #expect(snapshot.compactReceiptCount == 0)
        #expect(snapshot.liveHandleCount == 0)
        var second: EventJournalPreparedHandle? = try #require(budget.acquire(
            try EventJournalAdmissionValidator.prepare(event(276))
        ))
        second = nil
        #expect(budget.snapshot().liveHandleCount == 0)
    }

    @Test("1,274 unchanged completions create no terminal storage work")
    func unchangedBurstIsStorageOChanged() async throws {
        let store = JournalStoreFake()
        let writer = BatchedEventWriter(
            store: store,
            flushThreshold: 10_000,
            hardCap: 2_000
        )
        var receipts: [EventJournalAdmission] = []
        receipts.reserveCapacity(1_274)
        for index in 0..<1_274 {
            let prepared = try EventJournalAdmissionValidator.prepare(
                event(1_000 + index)
            )
            let receipt = try #require(await writer.enqueuePrepared(prepared))
            receipts.append(receipt)
            #expect(await writer.enqueueTerminalRevision(
                prepared,
                admission: receipt
            ) == .unchanged)
        }
        let queued = await writer.telemetrySnapshot()
        #expect(queued.terminalRevisionOfferedCount == 1_274)
        #expect(queued.terminalRevisionUnchangedCount == 1_274)
        #expect(queued.terminalRevisionBufferDepth == 0)
        #expect(queued.terminalRevisionConservationHolds)
        await writer.shutdown()
        #expect(await store.terminalAppendCalls == 0)
        _ = receipts
    }

    @Test("filtered base becomes exact and promotions union independent of order")
    func filteredBaseSecurityPromotionAndMatchUnion() async throws {
        let store = JournalStoreFake(baseMode: .filtered)
        let writer = BatchedEventWriter(store: store, flushThreshold: 10_000)
        let base = event(300)
        let receipt = try #require(await writer.enqueuePrepared(
            EventJournalAdmissionValidator.prepare(base)
        ))
        await writer.shutdown()

        let low = RuleMatch(
            ruleId: "rule.low",
            ruleName: "Low",
            severity: .low,
            description: "low",
            mitreTechniques: ["T1001", "T1001"],
            tags: ["z", "a"]
        )
        let high = RuleMatch(
            ruleId: "rule.high",
            ruleName: "High",
            severity: .high,
            description: "high",
            mitreTechniques: ["T2002"],
            tags: ["b"]
        )
        #expect(await writer.promoteProjection(
            event: base,
            reviewedMatches: [high, low, high],
            admission: receipt
        ))
        #expect(await writer.promoteProjection(
            event: base,
            reviewedMatches: [low, high],
            admission: receipt
        ))
        #expect(await writer.awaitJournalAdmission(receipt) == .verified)

        let expected = ReviewedRuleMatches.normalized([low, high])
        #expect(await store.reviewedMatches(base.id) == expected)
        var terminal = base
        terminal.ruleMatches = ReviewedRuleMatches.merged(
            terminal.ruleMatches,
            [low, high, high]
        )
        terminal.severity = .high
        #expect(await writer.enqueueTerminalRevision(
            try EventJournalAdmissionValidator.prepare(terminal),
            admission: receipt
        ) == .queued)
        await writer.shutdown()
        #expect(await store.exactEvent(base.id)?.ruleMatches == expected)
    }
}
