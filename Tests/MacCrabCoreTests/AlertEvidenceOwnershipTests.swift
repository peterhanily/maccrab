import Foundation
import Testing
import CSQLCipher
@testable import MacCrabCore
@testable import MacCrabAgentKit

@Suite("Alert-owned evidence budget split")
struct AlertEvidenceOwnershipTests {
    private actor LeaseHolder {
        private var lease: EventPipelineMemoryLease?

        init(_ lease: EventPipelineMemoryLease) {
            self.lease = lease
        }

        func release() {
            lease = nil
        }
    }

    private func tempDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-alert-evidence-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: url, withIntermediateDirectories: true
        )
        return url
    }

    private func event(
        id: UUID = UUID(),
        timestamp: Date,
        severity: Severity = .informational,
        padding: Int = 0
    ) -> Event {
        let command = "/usr/bin/tool " + String(repeating: "x", count: padding)
        let process = ProcessInfo(
            pid: 123,
            ppid: 1,
            rpid: 1,
            name: "tool",
            executable: "/usr/bin/tool",
            commandLine: command,
            args: [command],
            workingDirectory: "/tmp",
            userId: 501,
            userName: "tester",
            groupId: 20,
            startTime: timestamp,
            exitCode: nil,
            codeSignature: nil,
            ancestors: [],
            architecture: "arm64",
            isPlatformBinary: false
        )
        return Event(
            id: id,
            timestamp: timestamp,
            eventCategory: .process,
            eventType: .creation,
            eventAction: "exec",
            process: process,
            enrichments: [:],
            severity: severity
        )
    }

    private func candidate(_ event: Event) throws -> AlertEvidenceCandidate {
        let data = try JSONEncoder().encode(event)
        return AlertEvidenceCandidate(
            eventId: event.id.uuidString,
            timestamp: event.timestamp,
            rawJSON: String(decoding: data, as: UTF8.self)
        )
    }

    private func admission(
        for event: Event,
        generation: UInt64
    ) throws -> EventJournalAdmission {
        let prepared = try EventJournalAdmissionValidator.prepare(event)
        return EventJournalAdmission(
            eventID: event.id,
            generation: generation,
            canonicalSHA256: prepared.canonicalSHA256,
            canonicalByteCount: prepared.canonicalJSON.count
        )
    }

    private func alert(id: String, event: Event) -> Alert {
        Alert(
            id: id,
            timestamp: event.timestamp,
            ruleId: "test.alert-evidence",
            ruleTitle: "Evidence test",
            severity: .high,
            eventId: event.id.uuidString
        )
    }

    @Test("candidate selection is backward-only, bounded, deterministic, and chronological")
    func boundedSelection() async throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = try EventStore(directory: dir.path)
        let alertTime = Date(timeIntervalSince1970: 10_000)
        for index in 0..<80 {
            let e = event(
                timestamp: alertTime.addingTimeInterval(
                    Double(index - 60) / 2
                ),
                severity: index % 11 == 0 ? .critical : .informational
            )
            try await store.insert(event: e)
        }
        let candidates = try await store.alertEvidenceCandidates(
            alertTimestamp: alertTime,
            windowSeconds: 10_000,
            maxRows: 10_000
        )
        #expect(candidates.count == AlertEvidencePolicy.maximumEventsPerAlert)
        #expect(candidates.allSatisfy {
            $0.timestamp <= alertTime
                && $0.timestamp >= alertTime.addingTimeInterval(-30)
        })
        #expect(candidates.map(\.timestamp) == candidates.map(\.timestamp).sorted())
        let second = try await store.alertEvidenceCandidates(
            alertTimestamp: alertTime,
            windowSeconds: 30,
            maxRows: 50
        )
        #expect(second == candidates)
    }

    @Test("capture is idempotent, capped per alert, and cascades on delete")
    func idempotentCascade() async throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = try AlertStore(directory: dir.path)
        let base = Date(timeIntervalSince1970: 20_000)
        let events = (0..<70).map {
            event(timestamp: base.addingTimeInterval(Double($0) * 0.4))
        }
        let parent = alert(id: "alert-1", event: events.last!)
        try await store.insert(alert: parent)
        let candidates = try events.map(candidate)
        let first = try await store.captureEvidence(
            alertId: parent.id,
            candidates: candidates,
            maxBytes: 10 * 1_048_576
        )
        let second = try await store.captureEvidence(
            alertId: parent.id,
            candidates: candidates,
            maxBytes: 10 * 1_048_576
        )
        #expect(first.insertedRows == AlertEvidencePolicy.maximumEventsPerAlert)
        #expect(second.insertedRows == 0)
        #expect(try await store.evidenceFor(alertId: parent.id).count == 50)

        // UPSERT must not invoke the delete cascade on a harmless retry.
        try await store.insert(alert: parent)
        #expect(try await store.evidenceFor(alertId: parent.id).count == 50)
        #expect(try await store.delete(alertId: parent.id))
        #expect(try await store.evidenceFor(alertId: parent.id).isEmpty)
    }

    @Test("exact-window context gaps persist monotonically and cascade")
    func contextGapPersistence() async throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = try AlertStore(directory: dir.path)
        let trigger = event(timestamp: Date(timeIntervalSince1970: 20_500))
        let parent = alert(id: "context-gap", event: trigger)
        try await store.insert(alert: parent)
        let pending = try #require(await store.evidenceContext(
            alertId: parent.id
        ))
        #expect(pending.status == .pending,
                "alert commit must atomically install crash-visible context")
        #expect(!pending.isComplete)
        #expect(try await store.pendingEvidenceContextCount() == 1)
        var counts = try await store.evidenceContextCounts()
        #expect(counts.pending == 1 && counts.unhealthy == 1)
        #expect(counts.legacyUnverified == 0 && counts.reconciles)
        try await store.recordEvidenceContext(AlertEvidenceContextRecord(
            alertId: parent.id,
            status: .incomplete,
            sourceMutationGeneration: 7,
            poisonRecordCount: 2,
            corruptRecordCount: 1,
            inheritedLossCount: 3,
            resourceLimitedCount: 4,
            journalAdmissionGapCount: 5
        ))
        // A later clean retry may advance generation but must not erase the
        // gap observed by the original capture epoch.
        try await store.recordEvidenceContext(AlertEvidenceContextRecord(
            alertId: parent.id,
            status: .complete,
            sourceMutationGeneration: 9,
            poisonRecordCount: 0,
            corruptRecordCount: 0
        ))
        let context = try #require(await store.evidenceContext(
            alertId: parent.id
        ))
        #expect(context.status == .incomplete)
        #expect(context.sourceMutationGeneration == 9)
        #expect(context.poisonRecordCount == 2)
        #expect(context.corruptRecordCount == 1)
        #expect(context.inheritedLossCount == 3)
        #expect(context.resourceLimitedCount == 4)
        #expect(context.journalAdmissionGapCount == 5)
        #expect(!context.isComplete)
        #expect(try await store.pendingEvidenceContextCount() == 0)
        counts = try await store.evidenceContextCounts()
        #expect(counts.incomplete == 1 && counts.unhealthy == 1)
        #expect(counts.poisonRecords == 2)
        #expect(counts.corruptRecords == 1)
        #expect(counts.inheritedLossRecords == 3)
        #expect(counts.resourceLimitedRecords == 4)
        #expect(counts.journalAdmissionGapRecords == 5)
        #expect(counts.legacyUnverified == 0 && counts.reconciles)

        #expect(try await store.delete(alertId: parent.id))
        #expect(try await store.evidenceContext(alertId: parent.id) == nil)
        #expect(try await store.pendingEvidenceContextCount() == 0)
    }

    @Test("single and batch alert commits atomically own pending context rows")
    func committedAlertsOwnPendingContext() async throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = try AlertStore(directory: dir.path)
        let base = Date(timeIntervalSince1970: 20_750)
        let first = alert(id: "pending-single", event: event(timestamp: base))
        try await store.insert(alert: first)

        let second = alert(
            id: "pending-batch-1",
            event: event(timestamp: base.addingTimeInterval(1))
        )
        let third = alert(
            id: "pending-batch-2",
            event: event(timestamp: base.addingTimeInterval(2))
        )
        let committed = try await store.insert(alerts: [second, third])
        #expect(committed.map(\.id) == [second.id, third.id])
        let counts = try await store.evidenceContextCounts()
        #expect(counts.pending == 3)
        for id in [first.id, second.id, third.id] {
            #expect(try await store.evidenceContext(alertId: id)?.status
                == .pending)
        }
    }

    @Test("oldest evidence is evicted until the charged physical budget fits")
    func totalEvidenceCap() async throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = try AlertStore(directory: dir.path)
        let base = Date(timeIntervalSince1970: 30_000)
        let events = (0..<20).map {
            event(timestamp: base.addingTimeInterval(Double($0)), padding: 3_000)
        }
        let parent = alert(id: "budgeted", event: events.last!)
        try await store.insert(alert: parent)
        let budget: Int64 = 32 * 1024
        _ = try await store.captureEvidence(
            alertId: parent.id,
            candidates: try events.map(candidate),
            maxBytes: budget
        )
        let snapshot = try await store.evidenceBudgetSnapshot(maxBytes: budget)
        #expect(snapshot.chargedBytes <= budget)
        let retained = try await store.evidenceFor(alertId: parent.id)
        #expect(retained.count < events.count)
        if let first = retained.first {
            #expect(first.timestamp > events.first!.timestamp)
        }
    }

    @Test("destination revalidates the fixed preceding window instead of trusting candidates")
    func destinationWindowValidation() async throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = try AlertStore(directory: dir.path)
        let timestamp = Date(timeIntervalSince1970: 25_000)
        let parentEvent = event(timestamp: timestamp)
        let parent = alert(id: "window-guard", event: parentEvent)
        try await store.insert(alert: parent)
        let valid = event(timestamp: timestamp.addingTimeInterval(-1))
        let tooOld = event(timestamp: timestamp.addingTimeInterval(-31))
        let future = event(timestamp: timestamp.addingTimeInterval(0.001))
        let result = try await store.captureEvidence(
            alertId: parent.id,
            candidates: try [valid, tooOld, future].map(candidate),
            maxBytes: 1_048_576
        )
        #expect(result.insertedRows == 1)
        #expect(try await store.evidenceFor(alertId: parent.id).map(\.id) == [valid.id])
    }

    @Test("DBSTAT proves the slim table avoids projected-column duplication")
    func slimSchemaFootprint() async throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = try AlertStore(directory: dir.path)
        let base = Date(timeIntervalSince1970: 35_000)
        let events = (0..<20).map {
            // Make duplicated projected payload dominate SQLite's fixed page
            // and index overhead so the ratio remains meaningful across page
            // layouts and SQLCipher/SQLite versions.
            event(timestamp: base.addingTimeInterval(Double($0)), padding: 30_000)
        }
        let parent = alert(id: "slim", event: events.last!)
        try await store.insert(alert: parent)
        _ = try await store.captureEvidence(
            alertId: parent.id,
            candidates: try events.map(candidate),
            maxBytes: 10 * 1_048_576
        )
        let slim = try await store.refreshEvidenceBudgetSnapshot(
            maxBytes: 10 * 1_048_576
        ).allocatedBytes

        let legacyPath = dir.appendingPathComponent("legacy.db").path
        var db: OpaquePointer?
        #expect(sqlite3_open(legacyPath, &db) == SQLITE_OK)
        guard let db else { return }
        defer { sqlite3_close(db) }
        let schema = """
            CREATE TABLE alert_evidence (
              alert_id TEXT NOT NULL, id TEXT NOT NULL, timestamp REAL NOT NULL,
              event_category TEXT NOT NULL, event_type TEXT NOT NULL,
              event_action TEXT NOT NULL, severity TEXT NOT NULL,
              process_pid INTEGER, process_name TEXT, process_path TEXT,
              process_commandline TEXT, process_ppid INTEGER,
              process_signer TEXT, process_team_id TEXT, process_signing_id TEXT,
              file_path TEXT, file_action TEXT, network_dest_ip TEXT,
              network_dest_port INTEGER, tcc_service TEXT, tcc_client TEXT,
              raw_json TEXT NOT NULL, mcp_server_name TEXT,
              mcp_server_category TEXT, ai_tool_session_id TEXT,
              PRIMARY KEY(alert_id,id)
            );
            CREATE INDEX idx_evidence_alert_ts ON alert_evidence(alert_id,timestamp);
            CREATE INDEX idx_evidence_event ON alert_evidence(id);
            """
        #expect(sqlite3_exec(db, schema, nil, nil, nil) == SQLITE_OK)
        var insert: OpaquePointer?
        let sql = """
            INSERT INTO alert_evidence(
              alert_id,id,timestamp,event_category,event_type,event_action,
              severity,process_name,process_path,process_commandline,raw_json
            ) VALUES(?1,?2,?3,'process','creation','exec','informational',
                     'tool','/usr/bin/tool',?4,?5)
            """
        #expect(sqlite3_prepare_v2(db, sql, -1, &insert, nil) == SQLITE_OK)
        guard let insert else { return }
        defer { sqlite3_finalize(insert) }
        func bind(_ value: String, _ index: Int32) {
            _ = value.withCString {
                sqlite3_bind_text(
                    insert, index, $0, -1,
                    unsafeBitCast(-1, to: sqlite3_destructor_type.self)
                )
            }
        }
        for event in events {
            sqlite3_reset(insert)
            sqlite3_clear_bindings(insert)
            let raw = String(decoding: try JSONEncoder().encode(event), as: UTF8.self)
            bind("slim", 1)
            bind(event.id.uuidString, 2)
            sqlite3_bind_double(insert, 3, event.timestamp.timeIntervalSince1970)
            bind(event.process.commandLine, 4)
            bind(raw, 5)
            #expect(sqlite3_step(insert) == SQLITE_DONE)
        }
        var stat: OpaquePointer?
        #expect(sqlite3_prepare_v2(
            db,
            "SELECT COALESCE(SUM(pgsize),0) FROM dbstat WHERE name='alert_evidence' OR name IN ('sqlite_autoindex_alert_evidence_1','idx_evidence_alert_ts','idx_evidence_event')",
            -1, &stat, nil
        ) == SQLITE_OK)
        guard let stat else { return }
        defer { sqlite3_finalize(stat) }
        #expect(sqlite3_step(stat) == SQLITE_ROW)
        let legacy = sqlite3_column_int64(stat, 0)
        #expect(legacy > slim)
        #expect(Double(slim) / Double(legacy) < 0.75)
    }

    @Test("new evidence wins; absent new evidence falls back to legacy without migration")
    func legacyFallback() async throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let events = try EventStore(directory: dir.path)
        let alerts = try AlertStore(directory: dir.path)
        let legacy = event(timestamp: Date(timeIntervalSince1970: 40_000))
        try await events.insert(event: legacy)
        try await events.recordAlertEvidence(
            alertId: "legacy-alert",
            alertTimestamp: legacy.timestamp
        )
        let fallback = await AlertEvidenceResolver.evidenceFor(
            alertId: "legacy-alert",
            alertStore: alerts,
            legacyEventStore: events
        )
        #expect(fallback.map(\.id) == [legacy.id])

        let current = event(timestamp: legacy.timestamp.addingTimeInterval(1))
        try await alerts.insert(alert: alert(id: "legacy-alert", event: current))
        _ = try await alerts.captureEvidence(
            alertId: "legacy-alert",
            candidates: [try candidate(current)],
            maxBytes: 1_048_576
        )
        let preferred = await AlertEvidenceResolver.evidenceFor(
            alertId: "legacy-alert",
            alertStore: alerts,
            legacyEventStore: events
        )
        #expect(preferred.map(\.id) == [current.id])
    }

    @Test("evidence failure after commit does not roll back the alert")
    func postCommitFailure() async throws {
        enum SyntheticFailure: Error { case expected }
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = try AlertStore(directory: dir.path)
        let sink = AlertSink(
            alertStore: store,
            deduplicator: AlertDeduplicator(suppressionWindow: 60),
            evidenceCaptureOverride: { _, _ in throw SyntheticFailure.expected }
        )
        let submittedAlert = makeAlert()
        #expect(try await sink.submit(alert: submittedAlert))
        #expect(try await store.count() == 1)
        await sink.flushEvidenceCapture()
        #expect(await sink.evidenceStats().failures == 1)
        let context = try #require(await store.evidenceContext(
            alertId: submittedAlert.id
        ))
        #expect(context.status == .captureFailed)
        #expect(try await store.pendingEvidenceContextCount() == 0)
    }

    @Test("decode ownership pressure is transient rather than corruption")
    func decodeOwnershipPressureIsTransient() async throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let budget = EventPipelineLiveMemoryBudget
            .isolatedProductionEquivalentForTesting()
        let events = try EventStore(
            directory: dir.path,
            liveMemoryBudget: budget
        )
        let timestamp = Date(timeIntervalSince1970: 44_500)
        try await events.insert(event: event(timestamp: timestamp))

        var blocker: EventPipelineMemoryLease? = budget.tryAcquire(
            bytes: 50 * 1_048_576,
            owner: .journalPrepared
        )
        _ = try #require(blocker)
        do {
            _ = try await events.exactAlertEvidenceSnapshot(
                alertTimestamp: timestamp
            )
            Issue.record("expected bounded decode ownership pressure")
        } catch let error as EventStoreError {
            // rc.32: bounded decode ownership pressure is in-process credit
            // exhaustion, so it surfaces as `memoryLeaseUnavailable`.
            guard case .memoryLeaseUnavailable = error else {
                Issue.record("pressure was misclassified as \(error)")
                return
            }
        }
        // A transient exact-read throw must close every incremental blob,
        // finalize every statement, and roll back its deferred transaction.
        // Otherwise this connection pins its own WAL and retention can never
        // recover even after the memory pressure has passed.
        #expect(await events.walCheckpointTruncate())
        blocker = nil

        let recovered = try await events.exactAlertEvidenceSnapshot(
            alertTimestamp: timestamp
        )
        #expect(recovered.candidates.count == 1)
    }

    @Test("malformed terminal evidence cannot leave a WAL-pinning statement")
    func malformedTerminalEvidenceReleasesReader() async throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let events = try EventStore(directory: dir.path)
        let timestamp = Date(timeIntervalSince1970: 44_550)
        let base = event(timestamp: timestamp)
        try await events.insert(event: base)
        var terminal = base
        terminal.enrichments["reviewed"] = "true"
        _ = try await events.appendTerminalRevision(
            terminal,
            lane: EventPipelineLane.finalLane(for: terminal)
        )

        let path = dir.appendingPathComponent("events.db").path
        var raw: OpaquePointer?
        try #require(sqlite3_open_v2(
            path,
            &raw,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX,
            nil
        ) == SQLITE_OK)
        let database = try #require(raw)
        #expect(sqlite3_exec(
            database,
            "PRAGMA ignore_check_constraints=ON",
            nil,
            nil,
            nil
        ) == SQLITE_OK)
        #expect(sqlite3_exec(
            database,
            "UPDATE event_journal_terminal_revisions SET event_id=X'00'",
            nil,
            nil,
            nil
        ) == SQLITE_OK)
        sqlite3_close(database)
        raw = nil

        do {
            _ = try await events.exactAlertEvidenceSnapshot(
                alertTimestamp: timestamp
            )
            Issue.record("expected malformed terminal evidence to be rejected")
        } catch let error as EventStoreError {
            guard case .decodingFailed = error else {
                Issue.record("terminal evidence was misclassified as \(error)")
                return
            }
        }
        #expect(await events.walCheckpointTruncate())
    }

    @Test("evidence worker outlives sustained transient decode ownership pressure")
    func evidenceRetriesDecodeOwnershipPressure() async throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let budget = EventPipelineLiveMemoryBudget
            .isolatedProductionEquivalentForTesting()
        let events = try EventStore(
            directory: dir.path,
            liveMemoryBudget: budget
        )
        let alerts = try AlertStore(directory: dir.path)
        let timestamp = Date(timeIntervalSince1970: 44_600)
        let trigger = event(timestamp: timestamp)
        try await events.insert(event: trigger)

        var blocker: EventPipelineMemoryLease? = budget.tryAcquire(
            bytes: 50 * 1_048_576,
            owner: .journalPrepared
        )
        let holder = LeaseHolder(try #require(blocker))
        blocker = nil
        let release = Task {
            // This deliberately exceeds the former five-second cutoff. A
            // pressure interval is not a terminal evidence result merely
            // because it crosses an arbitrary wall-clock boundary.
            try await Task.sleep(for: .milliseconds(5_250))
            await holder.release()
        }
        let sink = AlertSink(
            alertStore: alerts,
            deduplicator: AlertDeduplicator(suppressionWindow: 60),
            eventStore: events,
            liveMemoryBudget: budget
        )
        #expect(try await sink.submit(alert: alert(
            id: "transient-decode-pressure",
            event: trigger
        )))
        await sink.flushEvidenceCapture()
        try await release.value

        let stats = await sink.evidenceStats()
        #expect(stats.failures == 0)
        #expect(stats.exactContextQueryFailures == 0)
        #expect(try await alerts.evidenceFor(
            alertId: "transient-decode-pressure"
        ).map(\.id) == [trigger.id])
        let context = try #require(await alerts.evidenceContext(
            alertId: "transient-decode-pressure"
        ))
        #expect(context.status != .captureFailed)
    }

    @Test("shutdown preserves transiently blocked evidence as pending")
    func shutdownPreservesTransientEvidencePending() async throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let budget = EventPipelineLiveMemoryBudget
            .isolatedProductionEquivalentForTesting()
        let events = try EventStore(
            directory: dir.path,
            liveMemoryBudget: budget
        )
        let alerts = try AlertStore(directory: dir.path)
        let timestamp = Date(timeIntervalSince1970: 44_700)
        let trigger = event(timestamp: timestamp)
        try await events.insert(event: trigger)

        var blocker: EventPipelineMemoryLease? = budget.tryAcquire(
            bytes: 50 * 1_048_576,
            owner: .journalPrepared
        )
        let holder = LeaseHolder(try #require(blocker))
        blocker = nil
        let sink = AlertSink(
            alertStore: alerts,
            deduplicator: AlertDeduplicator(suppressionWindow: 60),
            eventStore: events,
            liveMemoryBudget: budget
        )
        #expect(try await sink.submit(alert: alert(
            id: "shutdown-transient-pressure",
            event: trigger
        )))

        let shutdown = await sink.shutdownEvidenceCapture(
            timeout: .milliseconds(50)
        )
        await holder.release()
        await sink.flushEvidenceCapture()

        #expect(shutdown.deadlineExpired)
        #expect(shutdown.durablePendingContexts >= 1)
        let stats = await sink.evidenceStats()
        #expect(stats.failures == 0)
        #expect(stats.exactContextQueryFailures == 0)
        let context = try #require(await alerts.evidenceContext(
            alertId: "shutdown-transient-pressure"
        ))
        #expect(context.status == .pending)
    }

    @Test("post-commit evidence uses a bounded single-worker conservation lane")
    func boundedCaptureLane() async throws {
        actor Gate {
            var released = false
            var waiters: [CheckedContinuation<Void, Never>] = []

            func capture() async -> AlertEvidenceCaptureResult {
                if !released {
                    await withCheckedContinuation { continuation in
                        waiters.append(continuation)
                    }
                }
                return AlertEvidenceCaptureResult(
                    insertedRows: 0,
                    duplicateRows: 0,
                    prunedRows: 0
                )
            }

            func release() {
                released = true
                let pending = waiters
                waiters.removeAll()
                for waiter in pending { waiter.resume() }
            }
        }

        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = try AlertStore(directory: dir.path)
        let gate = Gate()
        let sink = AlertSink(
            alertStore: store,
            deduplicator: AlertDeduplicator(suppressionWindow: 60),
            evidenceQueueCapacity: 2,
            evidenceCaptureOverride: { _, _ in await gate.capture() }
        )
        let base = Date(timeIntervalSince1970: 45_000)
        let trigger = event(timestamp: base)
        let alerts = (0..<6).map {
            alert(id: "queued-\($0)", event: trigger)
        }

        // This returns while the capture gate is closed; evidence work is no
        // longer serialized into the alert commit path.
        #expect(try await sink.insertEngineBatch(alerts: alerts).count == 6)
        let blocked = await sink.evidenceStats()
        #expect(blocked.offered == 6)
        #expect(blocked.shed == 4)
        #expect(blocked.pending + blocked.inFlight == 2)
        #expect(blocked.conserved)

        await gate.release()
        await sink.flushEvidenceCapture()
        let drained = await sink.evidenceStats()
        #expect(drained.completed == 2)
        #expect(drained.shed == 4)
        #expect(drained.pending == 0)
        #expect(drained.inFlight == 0)
        #expect(drained.conserved)

        let shutdown = await sink.shutdownEvidenceCapture()
        #expect(!shutdown.clean)
        #expect(shutdown.durablePendingContexts == 6,
                "override captures and intentional queue sheds must remain durable pending truth")
        let late = try await sink.insertEngineBatch(
            alerts: [alert(id: "after-shutdown", event: trigger)]
        )
        #expect(late.isEmpty)
        #expect(try await store.count() == 6)
        let sealed = await sink.evidenceStats()
        #expect(sealed.offered == 6)
        #expect(sealed.shed == 4)
        #expect(!sealed.accepting)
        #expect(sealed.alertsRejectedAfterSeal == 1)
        #expect(sealed.conserved)
    }

    @Test("evidence waits for the admitted batched-writer prefix on a real store")
    func writerPrefixBarrier() async throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let events = try EventStore(directory: dir.path)
        let alerts = try AlertStore(directory: dir.path)
        let writer = BatchedEventWriter(
            store: events,
            flushThreshold: 10_000,
            hardCap: 10_000
        )
        let sink = AlertSink(
            alertStore: alerts,
            deduplicator: AlertDeduplicator(suppressionWindow: 60),
            eventStore: events,
            journalAdmissionVerifier: { receipt in
                await writer.awaitJournalAdmission(
                    receipt,
                    timeout: .seconds(1)
                )
            }
        )
        let trigger = event(timestamp: Date(timeIntervalSince1970: 45_500))
        let generation = try #require(await writer.enqueue(trigger))
        #expect(writer.persistedCount == 0)

        #expect(try await sink.submit(
            alert: alert(id: "writer-prefix", event: trigger),
            event: trigger,
            journalAdmission: try admission(
                for: trigger,
                generation: generation
            )
        ))
        await sink.flushEvidenceCapture()

        let captured = try await alerts.evidenceFor(alertId: "writer-prefix")
        #expect(captured.map(\.id) == [trigger.id])
        #expect(writer.persistedCount == 1)
        #expect(await sink.evidenceStats().prefixBarrierTimeouts == 0)
        _ = await sink.shutdownEvidenceCapture()
        await writer.shutdown()
    }

    @Test("trigger snapshot survives a bounded writer-prefix timeout")
    func writerPrefixTimeoutFallback() async throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let events = try EventStore(directory: dir.path)
        let alerts = try AlertStore(directory: dir.path)
        let sink = AlertSink(
            alertStore: alerts,
            deduplicator: AlertDeduplicator(suppressionWindow: 60),
            eventStore: events,
            journalAdmissionVerifier: { _ in .timedOut }
        )
        let trigger = event(timestamp: Date(timeIntervalSince1970: 45_600))
        #expect(try await sink.submit(
            alert: alert(id: "prefix-timeout", event: trigger),
            event: trigger,
            journalAdmission: try admission(for: trigger, generation: 7)
        ))
        await sink.flushEvidenceCapture()

        let captured = try await alerts.evidenceFor(alertId: "prefix-timeout")
        #expect(captured.map(\.id) == [trigger.id])
        #expect(await sink.evidenceStats().prefixBarrierTimeouts == 1)
        _ = await sink.shutdownEvidenceCapture()
    }

    @Test("bounded shutdown sheds queued evidence and reports an uncooperative job")
    func boundedShutdownDeadline() async throws {
        actor Gate {
            var waiter: CheckedContinuation<Void, Never>?

            func capture() async -> AlertEvidenceCaptureResult {
                await withCheckedContinuation { waiter = $0 }
                return AlertEvidenceCaptureResult(
                    insertedRows: 0,
                    duplicateRows: 0,
                    prunedRows: 0
                )
            }

            func release() {
                waiter?.resume()
                waiter = nil
            }
        }

        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = try AlertStore(directory: dir.path)
        let gate = Gate()
        let sink = AlertSink(
            alertStore: store,
            deduplicator: AlertDeduplicator(suppressionWindow: 60),
            evidenceQueueCapacity: 2,
            evidenceCaptureOverride: { _, _ in await gate.capture() }
        )
        let trigger = event(timestamp: Date(timeIntervalSince1970: 45_750))
        #expect(try await sink.insertEngineBatch(alerts: [
            alert(id: "deadline-1", event: trigger),
            alert(id: "deadline-2", event: trigger),
        ]).count == 2)

        // Let the worker move one job into the uncooperative capture call.
        for _ in 0..<100 {
            if await sink.evidenceStats().inFlight == 1 { break }
            try? await Task.sleep(for: .milliseconds(1))
        }
        let shutdown = await sink.shutdownEvidenceCapture(
            timeout: .milliseconds(20)
        )
        #expect(shutdown.deadlineExpired)
        #expect(shutdown.shedAtDeadline == 1)
        #expect(shutdown.pending == 1)
        #expect(!shutdown.clean)

        let late = try await sink.submit(alert: alert(
            id: "deadline-late",
            event: trigger
        ))
        #expect(!late)
        #expect(await sink.evidenceStats().alertsRejectedAfterSeal == 1)

        await gate.release()
        await sink.flushEvidenceCapture()
        let settled = await sink.evidenceStats()
        #expect(settled.completed == 1)
        #expect(settled.shedAtShutdownDeadline == 1)
        #expect(settled.pending == 0)
        #expect(settled.inFlight == 0)
        #expect(settled.conserved)
    }

    @Test("capture accounting is incremental between explicit DBSTAT refreshes")
    func incrementalAccounting() async throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = try AlertStore(directory: dir.path)
        let base = Date(timeIntervalSince1970: 46_000)
        for index in 0..<2 {
            let trigger = event(timestamp: base.addingTimeInterval(Double(index)))
            let parent = alert(id: "accounting-\(index)", event: trigger)
            try await store.insert(alert: parent)
            _ = try await store.captureEvidence(
                alertId: parent.id,
                candidates: [try candidate(trigger)],
                maxBytes: 100 * 1_048_576
            )
        }
        let cached = try await store.evidenceBudgetSnapshot(
            maxBytes: 100 * 1_048_576
        )
        #expect(cached.rowCount == 2)
        #expect(cached.fullRefreshesTotal == 1)
        #expect(!cached.allocatedBytesExact)

        let exact = try await store.refreshEvidenceBudgetSnapshot(
            maxBytes: 100 * 1_048_576
        )
        #expect(exact.rowCount == 2)
        #expect(exact.fullRefreshesTotal == 2)
        #expect(exact.allocatedBytesExact)
        #expect(exact.chargedBytes == max(exact.logicalBytes, exact.allocatedBytes))
    }

    @Test("max-payload cascades remain reserve-bounded for delete and both pruners")
    func cascadeReserveAccounting() async throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = try AlertStore(directory: dir.path)
        let base = Date(timeIntervalSince1970: 47_000)
        var parents: [Alert] = []

        for parentIndex in 0..<3 {
            let parentTime = base.addingTimeInterval(Double(parentIndex) * 100)
            let evidenceEvents = (0..<AlertEvidencePolicy.maximumEventsPerAlert)
                .map { row in
                    event(
                        timestamp: parentTime.addingTimeInterval(
                            -25 + Double(row) * 0.5
                        ),
                        padding: 20_000
                    )
                }
            let parent = alert(
                id: "cascade-\(parentIndex)",
                event: event(timestamp: parentTime)
            )
            parents.append(parent)
            try await store.insert(alert: parent)
            let candidates = try evidenceEvents.map(candidate)
            #expect(candidates.allSatisfy {
                $0.rawJSON.utf8.count <= AlertEvidencePolicy.maximumRawPayloadBytes
            })
            let result = try await store.captureEvidence(
                alertId: parent.id,
                candidates: candidates,
                maxBytes: 100 * 1_048_576
            )
            #expect(result.insertedRows == AlertEvidencePolicy.maximumEventsPerAlert)
        }

        // Lower the reserve only after schema/capture. Each parent cascade is
        // larger than this, so deletion must drain children through admitted
        // chunks rather than issue one under-estimated FK transaction.
        _ = try await store.updateStorageAdmission(
            SQLitePersistentStorePolicy(
                maxFootprintBytes: 200 * 1_048_576,
                freeSpaceFloorBytes: 0,
                transactionReserveBytes: 512 * 1_024,
                storageVolumePath: dir.path
            )
        )

        #expect(try await store.delete(alertId: parents[0].id))
        #expect(try await store.evidenceFor(alertId: parents[0].id).isEmpty)
        #expect(try await store.prune(
            olderThan: base.addingTimeInterval(150)
        ) == 1)
        #expect(try await store.evidenceFor(alertId: parents[1].id).isEmpty)
        #expect(try await store.pruneOldest(count: 1) == 1)
        #expect(try await store.evidenceFor(alertId: parents[2].id).isEmpty)
        #expect(try await store.count() == 0)
    }

    @Test("default, low, and extreme config caps conserve the historical total")
    func capConservation() {
        func assertConserved(_ storage: DaemonConfig.StorageConfig) {
            let clamped = storage.clampedToSafeFloors()
            #expect(clamped.effectiveEventsFamilyMaxSizeMB >= 112)
            #expect(
                clamped.effectiveEventsFamilyMaxSizeMB
                    + clamped.effectiveAlertsFamilyMaxSizeMB
                    == clamped.configuredEventsAndAlertsTotalMaxSizeMB
            )
        }
        let defaults = DaemonConfig.StorageConfig().clampedToSafeFloors()
        #expect(defaults.effectiveEventsFamilyMaxSizeMB == 376)
        #expect(defaults.effectiveAlertsFamilyMaxSizeMB == 200)
        #expect(defaults.configuredEventsAndAlertsTotalMaxSizeMB == 576)
        assertConserved(defaults)

        var low = DaemonConfig.StorageConfig()
        low.eventsMaxSizeMB = 0
        low.evidenceMaxSizeMB = .max
        assertConserved(low)
        let lowClamped = low.clampedToSafeFloors()
        #expect(lowClamped.eventsMaxSizeMB == 162)
        #expect(lowClamped.evidenceMaxSizeMB == 50)

        var extreme = DaemonConfig.StorageConfig()
        extreme.eventsMaxSizeMB = .max
        extreme.alertsMaxSizeMB = .max
        extreme.evidenceMaxSizeMB = .max
        assertConserved(extreme)
        #expect(extreme.clampedToSafeFloors().effectiveEventsFamilyMaxSizeMB == 112)
    }

    @Test("heartbeat decodes effective caps rather than relabeling the envelope")
    func heartbeatCaps() throws {
        let data = Data(#"{"schema_version":5,"alert_evidence_budget":{"events_family_effective_cap_bytes":356515840,"events_legacy_envelope_bytes":461373440,"alerts_family_combined_cap_bytes":209715200,"events_and_alerts_total_cap_bytes":566231040,"over_budget":false}}"#.utf8)
        let heartbeat = try JSONDecoder().decode(HeartbeatSnapshot.self, from: data)
        #expect(heartbeat.alertEvidenceBudget?.eventsFamilyEffectiveCapBytes == Int64(340) * 1_048_576)
        #expect(heartbeat.alertEvidenceBudget?.eventsLegacyEnvelopeBytes == Int64(440) * 1_048_576)
        #expect(heartbeat.alertEvidenceBudget?.eventsAndAlertsTotalCapBytes == Int64(540) * 1_048_576)
    }

    @Test("production capture and boot/reload cap wiring cannot drift to legacy paths")
    func sourceDriftGuards() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent()
        func source(_ relative: String) throws -> String {
            try String(contentsOf: root.appendingPathComponent(relative), encoding: .utf8)
        }
        let sink = try source("Sources/MacCrabCore/Detection/AlertSink.swift")
        #expect(!sink.contains("recordAlertEvidence("))
        #expect(sink.contains("exactAlertEvidenceSnapshot("))
        #expect(sink.contains("recordEvidenceContext("))
        #expect(sink.contains("alertStore.captureEvidence("))

        let setup = try source("Sources/MacCrabAgentKit/DaemonSetup.swift")
        #expect(setup.contains("bootStorage.effectiveEventsFamilyMaxSizeMB"))
        #expect(setup.contains("AlertStore.combinedFamilyCapBytes("))
        #expect(setup.contains(
            "preopenLegacyAlertEvidenceTransitionMeasurement("
        ))
        #expect(setup.contains("measurementTicket()"))
        #expect(setup.contains("commitPendingReserve("))
        #expect(!setup.contains("legacyEvidenceTransitionReserveMiB:"))
        let reload = try source("Sources/MacCrabAgentKit/SignalHandlers.swift")
        #expect(reload.contains("newStorage.effectiveEventsFamilyMaxSizeMB"))
        #expect(reload.contains("newStorage.effectiveAlertsFamilyMaxSizeMB"))
        #expect(reload.contains("installStorageConfig(newStorage)"))
        #expect(reload.contains("legacyAlertEvidenceTransitionMeasurement("))
        #expect(reload.contains("commitPendingReserve("))
        #expect(reload.contains(
            "appliedLegacyEvidenceTransitionReserveMiB:"
        ))
        #expect(!reload.contains("legacyEvidenceTransitionReserveMiB:"))
        #expect(!reload.contains("maxSizeMiB: newStorage.eventsMaxSizeMB,"))

        let timers = try source("Sources/MacCrabAgentKit/DaemonTimers.swift")
        #expect(timers.contains("legacyAlertEvidenceTransitionMeasurement("))
        #expect(timers.contains("ticket: ticket"))
        #expect(timers.contains("commitPendingReserve(pending, ticket: ticket)"))
        #expect(timers.contains(
            "after.configurationGeneration"
        ))
        #expect(timers.contains(
            "ticket.configurationGeneration"
        ))
        #expect(!timers.contains("legacyEvidenceTransitionReserveMiB:"))

        let bootPolicy = try #require(
            setup.range(of: "storagePolicy: eventStoragePolicy")
        )
        let bootCommit = try #require(
            setup.range(of: "commitPendingReserve(")
        )
        #expect(bootPolicy.lowerBound < bootCommit.lowerBound)

        for transitionSource in [reload, timers] {
            let policy = try #require(
                transitionSource.range(of: "updateStorageAdmission(")
            )
            let commit = try #require(
                transitionSource.range(of: "commitPendingReserve(")
            )
            #expect(policy.lowerBound < commit.lowerBound)
        }
    }

    // The tier-rollup sweep used to run the FTS optimize only when ALREADY over
    // cap. That let events_fts accumulate tombstones untouched on a host sitting
    // under cap, until the index itself forced the crossing — a measured 180.6 MB
    // in ~81 days, at which point it was 44% of the store. Compaction must be
    // governed by its own rate limit, not by waiting for the damage.
    @Test("FTS compaction is not gated on already being over cap")
    func ftsCompactionIsNotGatedOnOverCap() throws {
        let timers = try String(
            contentsOf: URL(fileURLWithPath: #filePath)
                .deletingLastPathComponent().deletingLastPathComponent()
                .deletingLastPathComponent()
                .appendingPathComponent("Sources/MacCrabAgentKit/DaemonTimers.swift"),
            encoding: .utf8
        )
        guard let gate = timers.range(of: "before FTS optimize") else {
            Issue.record("the FTS optimize call site is missing")
            return
        }
        // Inspect the `if` immediately preceding the optimize block.
        let head = String(timers[..<gate.lowerBound].suffix(400))
        guard let condition = head.range(of: "if ", options: .backwards) else {
            Issue.record("could not locate the optimize gate condition")
            return
        }
        let text = String(head[condition.lowerBound...])
        #expect(!text.contains("overCap &&"),
                "compaction must not wait for the store to be over cap before running")
        #expect(text.contains("!walPinned") && text.contains("!underPowerPressure"),
                "the reader-pin and power-pressure guards must remain")
    }
}
