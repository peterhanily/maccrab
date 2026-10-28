// AlertSinkTests.swift
// MacCrabCoreTests
//
// Pin the v1.6.19 AlertSink contract: every alert reaches AlertStore through
// AlertSink (single chokepoint) and AlertSink applies AlertDeduplicator
// before insertion. These tests are the regression net for the v1.6.9
// NoiseFilter-layering bug class — if a future change re-introduces a
// direct AlertStore.insert outside the sink, these tests will not catch
// it (that's the job of pre-release-audit.sh in task #10), but they DO
// catch silent breakage of dedup ordering, missing await chains, and
// double-counting bugs.

import Testing
import Foundation
import CSQLCipher
@testable import MacCrabCore

@Suite("AlertSink contract")
struct AlertSinkTests {

    // MARK: - Helpers

    private func makeSink() async throws -> (sink: AlertSink, store: AlertStore, dir: URL) {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-alertsink-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        let store = try AlertStore(directory: tempDir.path)
        let dedup = AlertDeduplicator(suppressionWindow: 60)
        let sink = AlertSink(alertStore: store, deduplicator: dedup)
        return (sink, store, tempDir)
    }

    private func makeAlert(
        ruleId: String = "test.rule",
        processPath: String? = "/usr/bin/example",
        severity: Severity = .medium
    ) -> Alert {
        Alert(
            ruleId: ruleId,
            ruleTitle: "Test rule",
            severity: severity,
            eventId: UUID().uuidString,
            processPath: processPath,
            processName: processPath.map { ($0 as NSString).lastPathComponent },
            description: "test description",
            mitreTactics: nil, mitreTechniques: nil,
            suppressed: false
        )
    }

    /// Reuses the global `makeEvent(...)` helper from MacCrabCoreTests.swift.
    private func event(executable: String = "/usr/bin/example", pid: Int32 = 1234) -> Event {
        makeEvent(processName: (executable as NSString).lastPathComponent,
                  processPath: executable,
                  commandLine: executable,
                  pid: pid)
    }

    // MARK: - Tests

    @Test("enrichWithAttribution derives D3FEND defenses + remediation from ATT&CK tactics")
    func enrichDerivesD3FEND() {
        // C2 tactic → outbound filtering + DNS blackholing (FIQ-3).
        let c2 = Alert(
            ruleId: "r", ruleTitle: "t", severity: .high, eventId: "e",
            processPath: "/bin/x", processName: "x", description: "d",
            mitreTactics: "attack.command_and_control", mitreTechniques: nil,
            suppressed: false
        )
        let enriched = AlertSink.enrichWithAttribution(alert: c2, event: event())
        #expect(enriched.d3fendTechniques == ["D3-OTF", "D3-DNSBA"])
        #expect(enriched.remediationHint?.contains("D3-OTF") == true)

        // A tactic with no clean preventive twin → nil (no fabricated hint).
        let disc = Alert(
            ruleId: "r", ruleTitle: "t", severity: .low, eventId: "e",
            processPath: "/bin/x", processName: "x", description: "d",
            mitreTactics: "attack.discovery", mitreTechniques: nil, suppressed: false
        )
        let enrichedDisc = AlertSink.enrichWithAttribution(alert: disc, event: event())
        #expect(enrichedDisc.d3fendTechniques == nil)
        #expect(enrichedDisc.remediationHint == nil)

        // Caller-supplied values are preserved, never overwritten.
        let preset = Alert(
            ruleId: "r", ruleTitle: "t", severity: .high, eventId: "e",
            processPath: "/bin/x", processName: "x", description: "d",
            mitreTactics: "attack.command_and_control", mitreTechniques: nil,
            suppressed: false,
            d3fendTechniques: ["D3-CUSTOM"], remediationHint: "operator note"
        )
        let enrichedPreset = AlertSink.enrichWithAttribution(alert: preset, event: event())
        #expect(enrichedPreset.d3fendTechniques == ["D3-CUSTOM"])
        #expect(enrichedPreset.remediationHint == "operator note")
    }

    @Test("a graph alert and a rule alert on one event and tactic both persist, in either order")
    func graphAndRuleAlertOnOneEventBothPersist() async throws {
        for graphFirst in [true, false] {
            let (sink, store, dir) = try await makeSink()
            defer { try? FileManager.default.removeItem(at: dir) }
            let ev = event(executable: "/Users/x/.claude/tools/run.sh", pid: 4321)
            let lane = Alert(
                ruleId: "launch_agent_written", ruleTitle: "LaunchAgent Written", severity: .high,
                eventId: ev.id.uuidString, processPath: ev.process.executable, processName: "run.sh",
                description: "rule", mitreTactics: "attack.persistence", mitreTechniques: "attack.t1543.001"
            )
            let graph = Alert(
                ruleId: "maccrab_agent_associated_shell_writes_to_login_item",
                ruleTitle: "AI-associated shell wrote to a login item", severity: .high,
                eventId: ev.id.uuidString, processPath: ev.process.executable, processName: "run.sh",
                description: "graph", mitreTactics: "attack.persistence", mitreTechniques: "T1543.001,T1547"
            )
            // The graph lane's own submission (see the source pin in the
            // recalibration suite).
            func submitGraph() async throws {
                _ = try await sink.submit(alert: graph, event: ev, mustFire: true, collapseSameEvidence: false)
            }
            func submitRule() async throws {
                _ = try await sink.insertEngineBatch(alerts: [lane], event: ev)
            }
            if graphFirst {
                try await submitGraph(); try await submitRule()
            } else {
                try await submitRule(); try await submitGraph()
            }
            let stored = try await store.alerts(forEventId: ev.id.uuidString)
            #expect(Set(stored.map(\.ruleId)) == [lane.ruleId, graph.ruleId], "graph first: \(graphFirst)")
        }
    }

    @Test("submit(alert:event:) inserts the alert into AlertStore on first call")
    func submitInsertsFirst() async throws {
        let (sink, store, dir) = try await makeSink()
        defer { try? FileManager.default.removeItem(at: dir) }

        let inserted = try await sink.submit(alert: makeAlert(), event: event())
        #expect(inserted == true)

        let count = try await store.count()
        #expect(count == 1)
    }

    @Test("submit(alert:event:) suppresses duplicate within the dedup window")
    func submitSuppressesDuplicate() async throws {
        let (sink, store, dir) = try await makeSink()
        defer { try? FileManager.default.removeItem(at: dir) }

        let ev = event()
        let first = try await sink.submit(alert: makeAlert(), event: ev)
        let second = try await sink.submit(alert: makeAlert(), event: ev)
        #expect(first == true)
        #expect(second == false)

        let count = try await store.count()
        #expect(count == 1)

        let stats = await sink.stats()
        #expect(stats.inserted == 1)
        #expect(stats.suppressed == 1)
    }

    @Test("submit(alert:event:) does not dedup across different processPaths")
    func submitDistinguishesProcesses() async throws {
        let (sink, store, dir) = try await makeSink()
        defer { try? FileManager.default.removeItem(at: dir) }

        let eventA = event(executable: "/usr/bin/a")
        let eventB = event(executable: "/usr/bin/b")
        let a = try await sink.submit(alert: makeAlert(), event: eventA)
        let b = try await sink.submit(alert: makeAlert(), event: eventB)
        #expect(a == true)
        #expect(b == true)

        let count = try await store.count()
        #expect(count == 2)
    }

    @Test("submit can transactionally dedup correlator alerts on shared evidence")
    func submitUsesCustomDedupIdentity() async throws {
        let (sink, store, dir) = try await makeSink()
        defer { try? FileManager.default.removeItem(at: dir) }

        let first = try await sink.submit(
            alert: makeAlert(ruleId: "test.convergence"),
            event: event(executable: "/usr/bin/a"),
            dedupProcessPath: "api.example.test"
        )
        let second = try await sink.submit(
            alert: makeAlert(ruleId: "test.convergence"),
            event: event(executable: "/usr/bin/b"),
            dedupProcessPath: "api.example.test"
        )

        #expect(first)
        #expect(!second)
        #expect(try await store.count() == 1)
    }

    @Test("submit(alert:) without event uses alert.processPath as dedup key")
    func submitNoEventUsesProcessPath() async throws {
        let (sink, store, dir) = try await makeSink()
        defer { try? FileManager.default.removeItem(at: dir) }

        let first = try await sink.submit(alert: makeAlert(processPath: "/Applications/Foo.app/Contents/MacOS/Foo"))
        let second = try await sink.submit(alert: makeAlert(processPath: "/Applications/Foo.app/Contents/MacOS/Foo"))
        #expect(first == true)
        #expect(second == false)

        let count = try await store.count()
        #expect(count == 1)
    }

    @Test("submit(alert:) falls back to ruleId when processPath is nil")
    func submitNoEventFallsBackToRuleId() async throws {
        let (sink, store, dir) = try await makeSink()
        defer { try? FileManager.default.removeItem(at: dir) }

        let first = try await sink.submit(alert: makeAlert(processPath: nil))
        let second = try await sink.submit(alert: makeAlert(processPath: nil))
        #expect(first == true)
        #expect(second == false)

        let count = try await store.count()
        #expect(count == 1)
    }

    @Test("insertEngineBatch passes through without re-dedup")
    func insertEngineBatchPassthrough() async throws {
        let (sink, store, dir) = try await makeSink()
        defer { try? FileManager.default.removeItem(at: dir) }

        // Event-less harness path has no evidence/process context. Sink inserts
        // the batch as-is; production EventLoop always supplies an Event and
        // therefore uses transactional per-rule + same-evidence reservations.
        let alerts = [
            makeAlert(ruleId: "a"),
            makeAlert(ruleId: "b"),
            makeAlert(ruleId: "c"),
        ]
        let persisted = try await sink.insertEngineBatch(alerts: alerts)

        let count = try await store.count()
        #expect(count == 3)
        #expect(persisted.map(\.id) == alerts.map(\.id))

        // After a passthrough batch, follow-up direct submits with the SAME
        // ruleId should still go through dedup against their (ruleId, path)
        // tuple — this event-less harness insertion doesn't pollute the table.
        let extra = try await sink.submit(alert: makeAlert(ruleId: "a"), event: event())
        #expect(extra == true)
    }

    @Test("insertEngineBatch with empty array is a no-op")
    func insertEngineBatchEmpty() async throws {
        let (sink, store, dir) = try await makeSink()
        defer { try? FileManager.default.removeItem(at: dir) }

        let persisted = try await sink.insertEngineBatch(alerts: [])
        let count = try await store.count()
        #expect(count == 0)
        #expect(persisted.isEmpty)
    }

    @Test("insertEngineBatch returns only the exact post-collapse stored alerts")
    func insertEngineBatchReturnsPersistedSurvivors() async throws {
        let (sink, store, dir) = try await makeSink()
        defer { try? FileManager.default.removeItem(at: dir) }

        let ev = event(executable: "/private/tmp/untrusted-tool")
        func alert(id: String, severity: Severity) -> Alert {
            Alert(
                id: id,
                timestamp: Date(timeIntervalSince1970: 100),
                ruleId: "rule.\(id)",
                ruleTitle: id,
                severity: severity,
                eventId: ev.id.uuidString,
                processPath: ev.process.executable,
                processName: ev.process.name,
                description: "same evidence",
                mitreTactics: "attack.execution",
                mitreTechniques: "attack.t1059",
                suppressed: false
            )
        }

        let persisted = try await sink.insertEngineBatch(
            alerts: [
                alert(id: "low", severity: .low),
                alert(id: "critical", severity: .critical),
                alert(id: "high", severity: .high),
            ],
            event: ev
        )

        #expect(persisted.count == 1)
        #expect(persisted.first?.id == "critical")
        #expect(try await store.count() == 1)
        #expect(try await store.alert(id: "critical") != nil)
    }

    @Test("A failed engine batch rolls back rule and evidence reservations")
    func failedEngineBatchDoesNotPoisonDedup() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-alertsink-rollback-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: dir,
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("alerts.db").path
        let reserve = 16 * SQLitePersistentStorePolicy.bytesPerMiB
        let roomy = SQLitePersistentStorePolicy(
            maxFootprintBytes: 128 * SQLitePersistentStorePolicy.bytesPerMiB,
            freeSpaceFloorBytes: 0,
            transactionReserveBytes: reserve,
            storageVolumePath: dir.path
        )
        _ = try AlertStore(
            path: path,
            storagePolicy: roomy
        )

        let blocked = SQLitePersistentStorePolicy(
            maxFootprintBytes: roomy.maxFootprintBytes,
            freeSpaceFloorBytes: Int64.max,
            transactionReserveBytes: reserve,
            storageVolumePath: dir.path
        )
        let store = try AlertStore(path: path, storagePolicy: blocked)
        let sink = AlertSink(
            alertStore: store,
            deduplicator: AlertDeduplicator(suppressionWindow: 60)
        )
        let ev = event(executable: "/private/tmp/untrusted-tool")
        let candidate = Alert(
            id: "retry-after-store-failure",
            ruleId: "test.rollback",
            ruleTitle: "Reservation rollback",
            severity: .high,
            eventId: ev.id.uuidString,
            processPath: ev.process.executable,
            processName: ev.process.name,
            description: "same candidate is retried",
            mitreTactics: "attack.execution",
            mitreTechniques: "attack.t1059"
        )

        await #expect(throws: SQLitePersistentStoreAdmissionError.self) {
            try await sink.insertEngineBatch(alerts: [candidate], event: ev)
        }
        #expect(try await store.count() == 0)

        let recovered = try await store.updateStorageAdmission(roomy)
        #expect(recovered?.latchedFailure == nil)
        let retry = try await sink.insertEngineBatch(
            alerts: [candidate],
            event: ev
        )
        #expect(retry.map(\.id) == [candidate.id])
        #expect(try await store.count() == 1)
        let stats = await sink.stats()
        #expect(stats.inserted == 1)
        #expect(stats.suppressed == 0)
    }

    @Test("A later chunk failure settles only the durable prefix")
    func partialEngineBatchSettlesCommittedPrefixOnly() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-alertsink-partial-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: dir,
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: dir) }

        let path = dir.appendingPathComponent("alerts.db").path
        let roomy = SQLitePersistentStorePolicy(
            maxFootprintBytes: 128 * SQLitePersistentStorePolicy.bytesPerMiB,
            freeSpaceFloorBytes: 0,
            transactionReserveBytes: 8 * SQLitePersistentStorePolicy.bytesPerMiB,
            storageVolumePath: dir.path
        )
        let store = try AlertStore(path: path, storagePolicy: roomy)
        let deduplicator = AlertDeduplicator(suppressionWindow: 60)
        let sink = AlertSink(alertStore: store, deduplicator: deduplicator)
        let ev = event(executable: "/private/tmp/partial-batch-tool")

        func candidate(id: String, severity: Severity) -> Alert {
            Alert(
                id: id,
                ruleId: "test.partial.\(id)",
                ruleTitle: "Partial batch \(id)",
                severity: severity,
                eventId: ev.id.uuidString,
                processPath: ev.process.executable,
                processName: ev.process.name,
                description: "distinct rule with no same-evidence tactic",
                mitreTactics: nil,
                mitreTechniques: nil
            )
        }
        let candidates = [
            candidate(id: "medium", severity: .medium),
            candidate(id: "critical", severity: .critical),
            candidate(id: "high", severity: .high),
        ]

        // Match AlertSink's exact stored representation and severity ordering,
        // then choose a reserve which fits any one row but never two. Truncating
        // the WAL and leaving two reserves admits the first chunk while
        // preserving the next transaction's headroom. A real reader pin then
        // prevents recovery from clearing that chunk's WAL before the second
        // chunk. Merely filling the WAL would now recover and finish the batch.
        // This sink intentionally has no journal verifier/ensure closure, so
        // production persists the bounded trigger plus an `.unavailable`
        // journal-context marker. Use that exact representation seam: the old
        // raw EventSnapshot estimate was 218 bytes below the row actually
        // handed to AlertStore.
        let eventSnapshot = EventSnapshot.prepare(ev).snapshotJSON(
            journalContext: .unavailable
        )
        let insertionOrder = candidates
            .map {
                AlertSink.enrichWithAttribution(
                    alert: $0,
                    event: ev,
                    precomputedSnapshot: eventSnapshot
                )
            }
            .sorted { $0.severity > $1.severity }
        let pageSize: Int64 = 4_096
        let singleTransactionEstimates = try insertionOrder.map {
            let alertMutation = try AlertStore.estimatedAlertMutationBytes(
                $0,
                pageSizeBytes: pageSize
            )
            // Every alert transaction now durably initializes its evidence-
            // context row. Mirror that second table/PK mutation so this fixture
            // still chooses a reserve that fits exactly one complete alert.
            let contextMutation = SQLitePersistentStoreAdmission
                .conservativeEncodedRowMutationBytes(
                    logicalRepresentationBytes: Int64($0.id.utf8.count + 128),
                    pageSizeBytes: pageSize,
                    maximumLeafPageTouches: 2
                )
            return SQLitePersistentStoreAdmission.conservativeTransactionBytes(
                rowMutationBytes: SQLitePersistentStoreAdmission.saturatingAdd(
                    alertMutation,
                    contextMutation
                ),
                pageSizeBytes: pageSize,
                maximumTreePathPageTouches: 32
            )
        }
        let oneRowReserve = try #require(singleTransactionEstimates.max())
        #expect(await store.walCheckpointTruncate())
        let familyBefore = try SQLitePersistentStoreAdmission.measureFamily(path)
        let tight = SQLitePersistentStorePolicy(
            maxFootprintBytes: familyBefore + 2 * oneRowReserve,
            freeSpaceFloorBytes: 0,
            transactionReserveBytes: oneRowReserve,
            storageVolumePath: dir.path
        )
        let tightened = try await store.updateStorageAdmission(tight)
        #expect(tightened?.latchedFailure == nil)

        var reader: OpaquePointer?
        let openResult = sqlite3_open_v2(
            path, &reader, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nil
        )
        defer { sqlite3_close(reader) }
        try #require(openResult == SQLITE_OK)
        let pinnedReader = try #require(reader)
        try #require(sqlite3_exec(pinnedReader, "BEGIN", nil, nil, nil) == SQLITE_OK)
        try #require(sqlite3_exec(
            pinnedReader, "SELECT COUNT(*) FROM alerts", nil, nil, nil
        ) == SQLITE_OK)

        let partial: AlertBatchInsertFailure
        do {
            _ = try await sink.insertEngineBatch(alerts: candidates, event: ev)
            Issue.record("expected the second reserve-bounded chunk to fail")
            return
        } catch let failure as AlertBatchInsertFailure {
            partial = failure
        }
        // Release immediately so the prefix's queued evidence capture and the
        // later ordinary retry can proceed. Closing also releases it on error.
        try #require(sqlite3_exec(pinnedReader, "ROLLBACK", nil, nil, nil) == SQLITE_OK)
        let failureCode = partial.sqliteFailureDetails?.primaryResultCode
        #expect(failureCode == SQLITE_BUSY || failureCode == SQLITE_LOCKED)

        #expect(partial.committedAlerts.map(\.id) == ["critical"])
        #expect(partial.uncommittedAlerts.map(\.id) == ["high", "medium"])
        #expect(try await store.count() == 1)
        let partialStats = await sink.stats()
        #expect(partialStats.inserted == 1)
        #expect(partialStats.suppressed == 0)

        // Restoring headroom and retrying the original candidate set proves the
        // committed prefix kept its dedup window while only the suffix was rolled
        // back: critical suppresses, high+medium persist, and no row duplicates.
        let recovered = try await store.updateStorageAdmission(roomy)
        #expect(recovered?.latchedFailure == nil)
        let retry = try await sink.insertEngineBatch(
            alerts: candidates,
            event: ev
        )
        #expect(retry.map(\.id) == ["high", "medium"])
        #expect(try await store.count() == 3)
        let finalStats = await sink.stats()
        #expect(finalStats.inserted == 3)
        #expect(finalStats.suppressed == 1)
    }

    @Test("Concurrent submits with the same key insert exactly one (TOCTOU pin)")
    func concurrentSubmitsAtomic() async throws {
        // Pre-fix, AlertSink called shouldSuppress and recordAlert as two
        // separate actor hops — a TOCTOU window between them allowed two
        // concurrent submits with the same key to both observe "not
        // suppressed" and both insert. Post-fix, shouldSuppressAndRecord is
        // a single atomic actor method. This test pins that behavior:
        // emit 50 concurrent submits with the same key and verify exactly
        // one inserts.
        let (sink, store, dir) = try await makeSink()
        defer { try? FileManager.default.removeItem(at: dir) }

        let ev = event()
        await withTaskGroup(of: Bool.self) { group in
            for _ in 0..<50 {
                group.addTask {
                    (try? await sink.submit(alert: self.makeAlert(), event: ev)) ?? false
                }
            }
            var insertedCount = 0
            for await wasInserted in group where wasInserted {
                insertedCount += 1
            }
            #expect(insertedCount == 1)
        }

        let count = try await store.count()
        #expect(count == 1)

        let stats = await sink.stats()
        #expect(stats.inserted == 1)
        #expect(stats.suppressed == 49)
    }

    @Test("stats() reflects inserted and suppressed counts after mixed traffic")
    func statsAccumulate() async throws {
        let (sink, _, dir) = try await makeSink()
        defer { try? FileManager.default.removeItem(at: dir) }

        let ev = event()
        // 1st insert: new
        _ = try await sink.submit(alert: makeAlert(ruleId: "x"), event: ev)
        // 2nd insert: same key → suppressed
        _ = try await sink.submit(alert: makeAlert(ruleId: "x"), event: ev)
        // 3rd insert: different rule → new
        _ = try await sink.submit(alert: makeAlert(ruleId: "y"), event: ev)
        // 4th insert: different processPath fallback (no event) → new
        _ = try await sink.submit(alert: makeAlert(ruleId: "z", processPath: "/bin/z"))

        let stats = await sink.stats()
        #expect(stats.inserted == 3)
        #expect(stats.suppressed == 1)
    }

    // MARK: - Shared alerts-emitted counter (audit #211)

    @Test("shared alert counter increments once per emitted alert across all submit paths (post-dedup)")
    func sharedCounterCountsEveryEmissionPath() async throws {
        // Regression net for the ~16x HEARTBEAT alerts_emitted / Prometheus
        // alerts_total undercount: pre-fix only the single-event rule-match
        // site incremented the counter, so the ~59 direct-emission paths
        // (graph/intent/sequence/campaign/AI-guard/meta) that flow through
        // AlertSink.submit were invisible. The daemon injects the SAME
        // LockedCounter the heartbeat reads; the sink must increment it once
        // per successfully-inserted (post-dedup) alert on EVERY path.
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-alertsink-counter-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let store = try AlertStore(directory: tempDir.path)
        let counter = LockedCounter()
        let sink = AlertSink(
            alertStore: store,
            deduplicator: AlertDeduplicator(suppressionWindow: 60),
            alertCounter: counter
        )
        let ev = event()

        // Three distinct direct emissions (the non-rule-match submit path that
        // used to bypass the counter entirely).
        _ = try await sink.submit(alert: makeAlert(ruleId: "graph"), event: ev)
        _ = try await sink.submit(alert: makeAlert(ruleId: "intent"), event: ev)
        _ = try await sink.submit(alert: makeAlert(ruleId: "campaign"), event: ev)
        #expect(counter.get() == 3)

        // A dedup-suppressed submit must NOT count (post-dedup semantics).
        let dup = try await sink.submit(alert: makeAlert(ruleId: "graph"), event: ev)
        #expect(dup == false)
        #expect(counter.get() == 3)

        // The event-less submit path also counts.
        _ = try await sink.submit(alert: makeAlert(ruleId: "selfdefense", processPath: "/bin/z"))
        #expect(counter.get() == 4)

        // The engine batch path counts once per inserted alert (this is the
        // rule-match path — the old EventLoop per-match increment was removed,
        // so exactly the batch size is added, no double-count).
        try await sink.insertEngineBatch(alerts: [
            makeAlert(ruleId: "rule.a"),
            makeAlert(ruleId: "rule.b"),
        ])
        #expect(counter.get() == 6)

        // The shared counter agrees with the sink's own inserted tally.
        let stats = await sink.stats()
        #expect(counter.get() == stats.inserted)
    }
}

// MARK: - FP recalibration (v1.19.3)

/// Pin the dev-tooling / self-noise down-weight applied at the AlertSink
/// chokepoint. Contract: noisy attack-chain alerts on trusted dev-tooling
/// lineage (or MacCrab's own processes) are DOWN-WEIGHTED to informational —
/// never dropped — while must-fire credential-theft / honeyfile detections are
/// PRESERVED at full severity. Exercised through `submit(alert:)` and read back
/// from the store so the test covers the real emission path.
@Suite("AlertSink FP recalibration")
struct AlertSinkRecalibrationTests {

    private func storedSeverity(after alert: Alert, mustFire: Bool = false) async throws -> Severity {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-recal-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let store = try AlertStore(directory: tempDir.path)
        let sink = AlertSink(alertStore: store, deduplicator: AlertDeduplicator(suppressionWindow: 60))
        _ = try await sink.submit(alert: alert, mustFire: mustFire)
        let stored = try await store.alerts(forEventId: alert.eventId)
        return stored.first?.severity ?? alert.severity
    }

    /// The row the sink stored, with the severity it recalibrated.
    private func storedAlert(after alert: Alert, mustFire: Bool = false) async throws -> Alert? {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-recal-row-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let store = try AlertStore(directory: tempDir.path)
        let sink = AlertSink(alertStore: store, deduplicator: AlertDeduplicator(suppressionWindow: 60))
        _ = try await sink.submit(alert: alert, mustFire: mustFire)
        return try await store.alerts(forEventId: alert.eventId).first
    }

    private var repositoryRoot: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    }

    private func alert(
        ruleId: String = "test.rule",
        ruleTitle: String = "Test rule",
        severity: Severity,
        processPath: String?,
        mitreTactics: String? = nil,
        parentExecutable: String? = nil
    ) -> Alert {
        Alert(
            ruleId: ruleId, ruleTitle: ruleTitle, severity: severity,
            eventId: UUID().uuidString, processPath: processPath,
            processName: processPath.map { ($0 as NSString).lastPathComponent },
            description: "d", mitreTactics: mitreTactics, mitreTechniques: nil,
            suppressed: false, parentExecutable: parentExecutable
        )
    }

    @Test("a must-fire rule under a dev-tooling path keeps its severity")
    func mustFirePreservedOnDevToolingPath() async throws {
        let a = alert(
            ruleId: "d1a2b3c4-0042-4000-a000-000000000042", ruleTitle: "Reverse Shell Command Detected",
            severity: .high,
            processPath: "/Users/x/proj/node_modules/.bin/postinstall",
            mitreTactics: "attack.execution,attack.command_and_control"
        )
        #expect(try await storedSeverity(after: a, mustFire: true) == .high)
        // A medium match keeps its severity on a dev-tooling path, whether or
        // not its rule is must-fire.
        let medium = alert(
            ruleId: "d1a2b3c4-0101", ruleTitle: "Environment Variable Enumeration",
            severity: .medium,
            processPath: "/Users/x/proj/node_modules/.bin/postinstall",
            mitreTactics: "attack.discovery"
        )
        #expect(try await storedSeverity(after: medium, mustFire: true) == .medium)
        #expect(try await storedSeverity(after: medium) == .medium)
    }

    @Test("the engine batch keeps every alert's severity on a dev-tooling path")
    func batchKeepsMustFire() async throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-recal-batch-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let store = try AlertStore(directory: tempDir.path)
        let sink = AlertSink(alertStore: store, deduplicator: AlertDeduplicator(suppressionWindow: 60))
        let path = "/Users/x/proj/node_modules/.bin/esbuild"
        let event = makeEvent(processName: "esbuild", processPath: path, commandLine: path, pid: 4242)
        let mustFire = alert(ruleId: "must.fire", ruleTitle: "Must fire", severity: .high,
                             processPath: path, mitreTactics: "attack.execution")
        let quiet = alert(ruleId: "quiet.rule", ruleTitle: "Environment Variable Enumeration", severity: .medium,
                          processPath: path, mitreTactics: "attack.discovery")
        let inserted = try await sink.insertEngineBatch(
            alerts: [mustFire, quiet], event: event, mustFireRuleIds: ["must.fire"])
        let severities = Dictionary(uniqueKeysWithValues: inserted.map { ($0.ruleId, $0.severity) })
        #expect(severities["must.fire"] == .high)
        #expect(severities["quiet.rule"] == .medium)
    }

    @Test("a critical under a dev-tooling path is never lowered")
    func criticalPreservedOnDevToolingPath() async throws {
        // A reverse shell from a package's postinstall, run by node from the
        // user's version manager: the supply-chain scenario itself.
        let a = alert(
            ruleId: "d1a2b3c4-0042-4000-a000-000000000042", ruleTitle: "Reverse Shell Command Detected",
            severity: .critical,
            processPath: "/Users/x/proj/node_modules/left-pad/postinstall.sh",
            mitreTactics: "attack.execution,attack.command_and_control",
            parentExecutable: "/Users/x/.nvm/versions/node/v20.0.0/bin/node"
        )
        let stored = try #require(try await storedAlert(after: a))
        #expect(stored.severity == .critical)
        // The stored row, not the input, clears the default notification floor.
        var gate = NotificationGate()
        guard case .deliver = gate.evaluate(alert: stored) else {
            Issue.record("a critical reverse shell must notify at the default floor")
            return
        }
        // And it counts toward a campaign: only sub-critical dev-tooling
        // alerts are kept out of tactic counting.
        let detector = CampaignDetector()
        let summary = CampaignDetector.AlertSummary(
            ruleId: stored.ruleId, ruleTitle: stored.ruleTitle, severity: stored.severity,
            processPath: stored.processPath, pid: 4242,
            tactics: ["attack.execution", "attack.command_and_control"])
        #expect(await detector.isTacticContributor(summary))
    }

    @Test("a graph rule's techniques name its tactics")
    func graphRuleTactics() {
        func match(_ attack: [String]) -> GraphRuleMatch {
            GraphRuleMatch(ruleId: "r", ruleTitle: "r", severity: "high", attack: attack, bindings: [:], matchedEdgeIds: [])
        }
        #expect(match(["T1543.001", "T1547"]).tactics == ["attack.persistence"])
        #expect(match(["T1059", "T1555", "T1041"]).tactics == ["attack.execution", "attack.credential_access", "attack.exfiltration"])
        #expect(match(["T1195.001", "T1555", "T1567", "T1098"]).tactics ==
                ["attack.initial_access", "attack.credential_access", "attack.exfiltration", "attack.persistence"])
        #expect(match(["T9999"]).tactics.isEmpty)
        #expect(match([]).tactics.isEmpty)
    }

    @Test("a MEDIUM alert on a dev-tooling path keeps its severity")
    func devToolingMediumKept() async throws {
        let a = alert(
            ruleId: "d1a2b3c4-0101", ruleTitle: "Environment Variable Enumeration",
            severity: .medium,
            processPath: "/Users/x/proj/node_modules/.bin/esbuild",
            mitreTactics: "attack.discovery"
        )
        #expect(try await storedSeverity(after: a) == .medium)
    }

    @Test("an AI-safety MEDIUM under an agent's dev-tooling path keeps its severity")
    func agentAISafetyMediumKept() async throws {
        // ai_tool_downloads_script: an agent's shell piping a download into sh.
        let a = alert(
            ruleId: "d1a2b3c4-2004-4000-a000-000000002004",
            ruleTitle: "AI Coding Tool Downloads and Executes Script",
            severity: .medium,
            processPath: "/bin/zsh",
            mitreTactics: "attack.execution",
            parentExecutable: "/Users/x/.local/share/claude/versions/2.1.0"
        )
        #expect(try await storedSeverity(after: a) == .medium)
    }

    @Test("a HIGH suppressible alert is never lowered on a dev-tooling path")
    func devToolingHighIsNeverLowered() async throws {
        let a = alert(
            ruleId: "keylogger_event_tap_active", ruleTitle: "Keylogger Event Tap Active",
            severity: .high,
            processPath: "/opt/homebrew/Cellar/tool/1.0/bin/tool",
            mitreTactics: "attack.collection"
        )
        #expect(try await storedSeverity(after: a) == .high)
    }

    @Test("a command-and-control match keeps its severity on a dev-tooling path")
    func devToolingCommandAndControlPreserved() async throws {
        let high = alert(
            ruleId: "package_manager_downloads_and_executes", ruleTitle: "Package Manager Downloads And Executes",
            severity: .high,
            processPath: "/Users/x/proj/node_modules/.bin/postinstall",
            mitreTactics: "attack.execution,attack.command_and_control",
            parentExecutable: "/Users/x/.nvm/versions/node/v20.0.0/bin/node"
        )
        #expect(try await storedSeverity(after: high) == .high)
        let medium = alert(
            ruleId: "osascript_download_execute", ruleTitle: "osascript Download Execute",
            severity: .medium,
            processPath: "/Users/x/proj/node_modules/.bin/postinstall",
            mitreTactics: "attack.execution,attack.command_and_control",
            parentExecutable: "/Users/x/.nvm/versions/node/v20.0.0/bin/node"
        )
        #expect(try await storedSeverity(after: medium) == .medium)
    }

    @Test("a graph rule's alert keeps its severity under an agent or dev-tooling path")
    func graphAlertKeepsSeverityUnderAgentPath() async throws {
        let path = "/Users/x/.claude/tools/run.sh"
        let node = "/Users/x/.nvm/versions/node/v20.0.0/bin/node"
        let persistence = alert(
            ruleId: "maccrab_agent_associated_shell_writes_to_login_item",
            ruleTitle: "AI-associated shell wrote to a login item", severity: .high,
            processPath: path, mitreTactics: "attack.persistence", parentExecutable: node
        )
        #expect(try await storedSeverity(after: persistence, mustFire: true) == .high)
        // A medium graph alert keeps its severity under an agent's path, and
        // so would an ordinary medium match.
        let execution = alert(
            ruleId: "maccrab_graph_fixture", ruleTitle: "Graph fixture", severity: .medium,
            processPath: path, mitreTactics: "attack.execution", parentExecutable: node
        )
        #expect(try await storedSeverity(after: execution, mustFire: true) == .medium)
        #expect(try await storedSeverity(after: execution) == .medium)
        // The lane submits every graph alert that way, with its tactics.
        let eventLoop = try String(
            contentsOf: repositoryRoot.appendingPathComponent("Sources/MacCrabAgentKit/EventLoop.swift"),
            encoding: .utf8)
        #expect(eventLoop.contains(
            "_ = try await alertSink.submit(alert: alert, event: anchorEvent, mustFire: true, collapseSameEvidence: false)"))
        #expect(eventLoop.contains("mitreTactics: match.tactics.isEmpty ? nil : match.tactics.joined(separator: \",\")"))
    }

    @Test("a must-fire alert from a trusted browser or agent bundle keeps its severity")
    func mustFireSurvivesTheBrowserStep() async throws {
        // An agent bundled as an Electron app runs under the trusted-browser
        // prefixes, and the lethal-trifecta graph rule carries a credential
        // tactic, so the browser step took it for credential sync.
        let cursor = "/Applications/Cursor.app/Contents/Frameworks/Cursor Helper (Plugin).app/Contents/MacOS/Cursor Helper (Plugin)"
        func stored(mustFire: Bool) async throws -> Severity? {
            let tempDir = FileManager.default.temporaryDirectory
                .appendingPathComponent("maccrab-recal-browser-\(UUID().uuidString)")
            try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: tempDir) }
            let store = try AlertStore(directory: tempDir.path)
            let sink = AlertSink(alertStore: store, deduplicator: AlertDeduplicator(suppressionWindow: 60))
            let event = makeEvent(category: .network, type: .connection, action: "connect",
                                  processName: "Cursor Helper (Plugin)", processPath: cursor,
                                  commandLine: cursor, pid: 4244)
            let a = alert(
                ruleId: "maccrab_ai_agent_lethal_trifecta", ruleTitle: "AI agent lethal trifecta",
                severity: .critical, processPath: cursor,
                mitreTactics: "attack.execution,attack.credential_access,attack.exfiltration"
            )
            _ = try await sink.submit(alert: a, event: event, mustFire: mustFire)
            return try await store.alerts(forEventId: a.eventId).first?.severity
        }
        #expect(try await stored(mustFire: true) == .critical)
        // A suppressible alert of the same shape is still the step's
        // credential-sync class.
        #expect(try await stored(mustFire: false) == .low)
    }

    @Test("a must-fire rule match keeps its severity through the engine batch, and so does a suppressible one on a dev-tooling path")
    func mustFireMatchSurvivesTheEngineBatch() async throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-recal-pipeline-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let store = try AlertStore(directory: tempDir.path)
        let sink = AlertSink(alertStore: store, deduplicator: AlertDeduplicator(suppressionWindow: 60))
        let path = "/Users/x/proj/node_modules/.bin/esbuild"
        let event = makeEvent(processName: "esbuild", processPath: path, commandLine: path, pid: 4243)
        let matches = [
            RuleMatch(ruleId: "must.high", ruleName: "Must fire high", severity: .high, description: "",
                      mitreTechniques: ["attack.t1059.004"], tags: ["attack.execution", "attack.t1059.004"],
                      suppressible: false),
            RuleMatch(ruleId: "must.medium", ruleName: "Must fire medium", severity: .medium, description: "",
                      mitreTechniques: [], tags: ["attack.discovery"], suppressible: false),
            // A distinct tactic, so same-evidence dedup does not fold it into
            // the must-fire medium above.
            RuleMatch(ruleId: "quiet.medium", ruleName: "Suppressible medium", severity: .medium, description: "",
                      mitreTechniques: [], tags: ["attack.collection"], suppressible: true),
        ]
        // The same transformation the lane applies to a reviewed match.
        let alerts = matches.map { match in
            Alert(ruleId: match.ruleId, ruleTitle: match.ruleName, severity: match.severity,
                  eventId: event.id.uuidString, processPath: path, processName: "esbuild",
                  description: match.description,
                  mitreTactics: match.tags.filter { $0.hasPrefix("attack.") && !$0.contains("t1") }.joined(separator: ","),
                  mitreTechniques: match.tags.filter { $0.contains("t1") }.joined(separator: ","))
        }
        let inserted = try await sink.insertEngineBatch(
            alerts: alerts, event: event,
            mustFireRuleIds: Set(matches.filter { !$0.suppressible }.map(\.ruleId)))
        let severities = Dictionary(uniqueKeysWithValues: inserted.map { ($0.ruleId, $0.severity) })
        #expect(severities["must.high"] == .high)
        #expect(severities["must.medium"] == .medium)
        #expect(severities["quiet.medium"] == .medium)
        let eventLoop = try String(
            contentsOf: repositoryRoot.appendingPathComponent("Sources/MacCrabAgentKit/EventLoop.swift"),
            encoding: .utf8)
        #expect(eventLoop.contains("if !match.suppressible { batchMustFire.insert(match.ruleId) }"))
        #expect(eventLoop.contains("mustFireRuleIds: batchMustFire"))
    }

    @Test("dev-tooling critical credential-access PRESERVED (must-fire)")
    func devToolingCredentialPreserved() async throws {
        let a = alert(
            ruleTitle: "AI Tool Reads Credentials Then Network",
            severity: .critical,
            processPath: "/Users/x/proj/node_modules/.bin/tool",
            mitreTactics: "attack.credential_access"
        )
        #expect(try await storedSeverity(after: a) == .critical)
    }

    @Test("dev-tooling honeyfile PRESERVED (must-fire)")
    func devToolingHoneyfilePreserved() async throws {
        let a = alert(
            ruleTitle: "Honeyfile Accessed", severity: .high,
            processPath: "/opt/homebrew/bin/something",
            mitreTactics: "attack.collection"
        )
        #expect(try await storedSeverity(after: a) == .high)
    }

    @Test("gh reading its own GitHub token keeps its medium severity, as in v1.22.5")
    func ghGitHubTokenKeepsMedium() async throws {
        let a = alert(
            ruleTitle: "🦀 AI Tool Accessed GitHub Token", severity: .medium,
            processPath: "/opt/homebrew/Cellar/gh/2.86.0/bin/gh",
            mitreTactics: "attack.credential_access"
        )
        #expect(try await storedSeverity(after: a) == .medium)
    }

    @Test("non-dev-tooling high is UNCHANGED")
    func nonDevToolingUnchanged() async throws {
        let a = alert(
            ruleTitle: "Suspicious Exec", severity: .high,
            processPath: "/Applications/Evil.app/Contents/MacOS/Evil",
            mitreTactics: "attack.execution"
        )
        #expect(try await storedSeverity(after: a) == .high)
    }

    @Test("MacCrab self-process noise → low")
    func selfNoiseDownweighted() async throws {
        let a = alert(
            ruleTitle: "Cross-Process Attack Chain", severity: .high,
            processPath: "/Library/SystemExtensions/ABC/com.maccrab.agent.systemextension/Contents/MacOS/com.maccrab.agent",
            mitreTactics: "attack.execution"
        )
        #expect(try await storedSeverity(after: a) == .low)
    }

    @Test("MacCrab's own integrity alerts keep their severity at the sysext path")
    func selfDefenseVictimAlertsKeepSeverity() async throws {
        // These name MacCrab as the victim, not the actor.
        let sysext = "/Library/SystemExtensions/ABC/com.maccrab.agent.systemextension/Contents/MacOS/com.maccrab.agent"
        let tamper = alert(
            ruleId: "maccrab.self-defense.binary_modified", ruleTitle: "MacCrab Tamper Detection: Binary Modified",
            severity: .critical, processPath: sysext, mitreTactics: "attack.defense_evasion"
        )
        #expect(try await storedSeverity(after: tamper) == .critical)
        let injected = alert(
            ruleId: "maccrab.forensic.injected-library", ruleTitle: "Injected Library: com.maccrab.agent loaded x.dylib",
            severity: .high, processPath: sysext, mitreTactics: "attack.defense_evasion"
        )
        #expect(try await storedSeverity(after: injected) == .high)
    }

    @Test("A user-writable MacCrab path is not self-noise by path alone in a release engine")
    func userWritableSelfPathNeedsIdentity() async throws {
        // Without the event there is no signature to check. The app bundle and
        // the Tier-B staging directory are writable by the user who owns them.
        for (path, severity) in [
            ("/Applications/MacCrab.app/Contents/Resources/bin/maccrab-mcp", Severity.high),
            ("/private/var/folders/hf/X/T/maccrab-tier-b-verified-4F4CCE5E", Severity.medium),
        ] {
            let a = alert(
                ruleTitle: "Cross-Process Attack Chain", severity: severity,
                processPath: path, mitreTactics: "attack.execution"
            )
            let expected = NoiseFilter.engineIsDevelopmentBuild ? Severity.low : severity
            #expect(try await storedSeverity(after: a) == expected, "\(path)")
        }
    }

    @Test("a dev-tooling PARENT executable does not lower a medium")
    func parentLineageDevToolingKeepsMedium() async throws {
        let a = alert(
            ruleTitle: "Environment Variable Enumeration", severity: .medium,
            processPath: "/usr/bin/env",
            mitreTactics: "attack.discovery",
            parentExecutable: "/Users/x/proj/node_modules/.bin/esbuild"
        )
        #expect(try await storedSeverity(after: a) == .medium)
    }

    @Test("non-dev-tooling credential theft (real infostealer) is UNCHANGED")
    func realCredentialTheftUnchanged() async throws {
        // A *different* process (not gh) reading credentials, off any dev path —
        // exactly what must keep escalating.
        let a = alert(
            ruleTitle: "🦀 AI Tool Accessed GitHub Token", severity: .critical,
            processPath: "/tmp/.hidden/stealer",
            mitreTactics: "attack.credential_access"
        )
        #expect(try await storedSeverity(after: a) == .critical)
    }

    // MARK: - Must-fire classes preserved on dev paths (v1.19.3 adversarial review)

    @Test("dev-tooling IMPACT (ransomware / disk wipe) PRESERVED")
    func devToolingImpactPreserved() async throws {
        let a = alert(
            ruleTitle: "Disk Wipe or Overwrite Command", severity: .critical,
            processPath: "/opt/homebrew/lib/node_modules/evil/bin/wipe",
            mitreTactics: "attack.impact"
        )
        #expect(try await storedSeverity(after: a) == .critical)
    }

    @Test("dev-tooling DEFENSE-EVASION (SIP / Gatekeeper disable) PRESERVED")
    func devToolingDefenseEvasionPreserved() async throws {
        let a = alert(
            ruleTitle: "SIP Disabled", severity: .critical,
            processPath: "/opt/homebrew/bin/installer",
            mitreTactics: "attack.defense_evasion"
        )
        #expect(try await storedSeverity(after: a) == .critical)
    }

    @Test("dev-tooling PERSISTENCE (launchd) PRESERVED")
    func devToolingPersistencePreserved() async throws {
        let a = alert(
            ruleTitle: "LaunchAgent Created by Unsigned Process", severity: .high,
            processPath: "/Users/x/proj/node_modules/.bin/postinstall",
            mitreTactics: "attack.persistence"
        )
        #expect(try await storedSeverity(after: a) == .high)
    }

    @Test("dev-tooling EXFILTRATION PRESERVED")
    func devToolingExfiltrationPreserved() async throws {
        let a = alert(
            ruleTitle: "Archive Created and Uploaded", severity: .high,
            processPath: "/Users/x/.local/share/claude/bin/agent",
            mitreTactics: "attack.exfiltration"
        )
        #expect(try await storedSeverity(after: a) == .high)
    }

    // MARK: - Campaign meta-alerts skip dev-tooling recalibration

    @Test("campaign meta-alert on a dev-tool contributor is NOT down-weighted")
    func campaignMetaAlertPreserved() async throws {
        let a = alert(
            ruleId: "maccrab.campaign.kill_chain", ruleTitle: "Kill Chain Detected",
            severity: .critical,
            processPath: "/opt/homebrew/bin/workerd",
            mitreTactics: "attack.execution"
        )
        #expect(try await storedSeverity(after: a) == .critical)
    }

    // MARK: - Anti-spoofing (P0): self-noise gate must be path-anchored

    @Test("spoofed /tmp/maccrabd is NOT treated as self-noise")
    func spoofedMaccrabdNotSelfNoise() async throws {
        // An attacker drops a binary literally named maccrabd in a world-writable
        // dir. It is NOT on a dev-tooling path and NOT a real install location, so
        // it must keep its full severity (the pre-anchoring code wrongly hid it).
        #expect(AlertSink.isMacCrabSelfNoise("/tmp/maccrabd") == false)
        #expect(AlertSink.isMacCrabSelfNoise("/var/tmp/maccrab-mcp") == false)
        #expect(AlertSink.isMacCrabSelfNoise("/Users/x/Downloads/maccrabctl") == false)
        let a = alert(
            ruleTitle: "Unsigned Binary Execution from /tmp", severity: .high,
            processPath: "/tmp/maccrabd",
            mitreTactics: "attack.execution"
        )
        #expect(try await storedSeverity(after: a) == .high)
    }

    @Test("spoofed /tmp tier-B path is NOT treated as self-noise")
    func spoofedTierBNotSelfNoise() async throws {
        #expect(AlertSink.isMacCrabSelfNoise("/tmp/maccrab-tier-b-verified-FAKE/payload") == false)
        // Legitimate per-user temp path still matches.
        #expect(AlertSink.isMacCrabSelfNoise("/private/var/folders/hf/X/T/maccrab-tier-b-verified-REAL/bin") == true)
    }

    @Test("real install + dev-build self-noise paths still match")
    func realSelfNoisePathsMatch() async throws {
        #expect(AlertSink.isMacCrabSelfNoise("/Applications/MacCrab.app/Contents/Resources/bin/maccrabd") == true)
        #expect(AlertSink.isMacCrabSelfNoise("/Users/x/maccrab/.build/arm64-apple-macosx/debug/maccrabctl") == true)
        #expect(AlertSink.isMacCrabSelfNoise("/Library/SystemExtensions/ABC/com.maccrab.agent.systemextension/Contents/MacOS/com.maccrab.agent") == true)
    }

    // MARK: - Parent lineage lifted from the EVENT (production reorder fix)

    /// The alert's own path is benign (/usr/bin/env) and the dev-tool lineage
    /// lives only on the triggering event's parent. That lineage lowers
    /// nothing: the medium is stored as a medium.
    @Test("a dev-tooling parent from the triggering event lowers nothing")
    func parentFromEventKeepsMedium() async throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-recal-evt-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let store = try AlertStore(directory: tempDir.path)
        let sink = AlertSink(alertStore: store, deduplicator: AlertDeduplicator(suppressionWindow: 60))
        let a = alert(
            ruleTitle: "Environment Variable Enumeration", severity: .medium,
            processPath: "/usr/bin/env",
            mitreTactics: "attack.discovery"
        )
        let ev = makeEvent(processName: "env", processPath: "/usr/bin/env",
                           commandLine: "env",
                           parentPath: "/Users/x/proj/node_modules/.bin/esbuild")
        _ = try await sink.submit(alert: a, event: ev)
        let stored = try await store.alerts(forEventId: a.eventId)
        #expect(stored.first?.severity == .medium)
    }

    // MARK: - Browser self-credential (narrow self-access; system keychain stays loud)

    @Test("trusted browser reading its OWN credential store → low")
    func browserOwnCredentialStoreDownweighted() async throws {
        let a = alert(
            ruleTitle: "🦀 AI Tool Accessed Browser Credential Store", severity: .high,
            processPath: "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/149/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper",
            mitreTactics: "attack.credential_access"
        )
        #expect(try await storedSeverity(after: a) == .low)
    }

    @Test("browser credential-file access then upload (own-store sync) → low")
    func browserCredFileUploadDownweighted() async throws {
        let a = alert(
            ruleTitle: "Credential File Access Followed by Network Upload", severity: .high,
            processPath: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            mitreTactics: "attack.credential_access,attack.exfiltration"
        )
        #expect(try await storedSeverity(after: a) == .low)
    }

    /// Submits through the event path, so the triggering file is known.
    private func storedSeverity(after alert: Alert, readingFile path: String) async throws -> Severity {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-recal-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let store = try AlertStore(directory: tempDir.path)
        let sink = AlertSink(alertStore: store, deduplicator: AlertDeduplicator(suppressionWindow: 60))
        let process = MacCrabCore.ProcessInfo(
            pid: 4_242, ppid: 1, rpid: 1, name: alert.processName ?? "p",
            executable: alert.processPath ?? "/p", commandLine: "p", args: [],
            workingDirectory: "/", userId: 501, userName: "u", groupId: 20, startTime: Date())
        let event = Event(timestamp: Date(), eventCategory: .file, eventType: .info,
                          eventAction: "open", process: process,
                          file: FileInfo(path: path, action: .open))
        _ = try await sink.submit(alert: alert, event: event)
        return try await store.alerts(forEventId: alert.eventId).first?.severity ?? alert.severity
    }

    @Test("an Electron helper reading ANOTHER browser's credential store stays LOUD")
    func foreignBrowserStoreStaysLoud() async throws {
        let loginData = "/Users/x/Library/Application Support/Google/Chrome/Default/Login Data"
        let vscode = alert(
            ruleTitle: "Browser Credential Store Accessed", severity: .high,
            processPath: "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper.app/Contents/MacOS/Code Helper",
            mitreTactics: "attack.credential_access")
        #expect(NoiseFilter.isTrustedBrowserHelper(path: vscode.processPath!))
        #expect(try await storedSeverity(after: vscode, readingFile: loginData) == .high)
        let chrome = alert(
            ruleTitle: "Browser Credential Store Accessed", severity: .high,
            processPath: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            mitreTactics: "attack.credential_access")
        #expect(try await storedSeverity(after: chrome, readingFile: loginData) == .low)
    }

    @Test("browser touching the SYSTEM login.keychain stays LOUD")
    func browserSystemKeychainPreserved() async throws {
        let a = alert(
            ruleTitle: "login.keychain or System.keychain Database Opened by Non-Apple Process",
            severity: .high,
            processPath: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            mitreTactics: "attack.credential_access"
        )
        #expect(try await storedSeverity(after: a) == .high)
    }

    @Test("browser 'Keychain Database' access stays LOUD")
    func browserKeychainDatabasePreserved() async throws {
        let a = alert(
            ruleTitle: "🦀 AI Tool Accessed Keychain Database", severity: .high,
            processPath: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            mitreTactics: "attack.credential_access"
        )
        #expect(try await storedSeverity(after: a) == .high)
    }

    @Test("non-browser AI tool (claude CLI) reading creds then network stays LOUD")
    func claudeCliCredentialPreserved() async throws {
        // ~/.local/share/claude is a dev-tooling path but NOT a browser; the
        // dev-tooling must-fire carve-out preserves credential-access. This is
        // the AIGuard's core detection and must keep escalating.
        let a = alert(
            ruleTitle: "AI Tool Reads Credentials Then Makes Network Connection",
            severity: .high,
            processPath: "/Users/x/.local/share/claude/versions/2.1.186/bin/claude",
            mitreTactics: "attack.credential_access"
        )
        #expect(try await storedSeverity(after: a) == .high)
    }
}
