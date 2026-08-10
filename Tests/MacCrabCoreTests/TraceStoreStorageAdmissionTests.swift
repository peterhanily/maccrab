import Testing
import Foundation
import Darwin
import CSQLCipher
@testable import MacCrabCore
@testable import MacCrabAgentKit

@Suite("TraceStore: authoritative disk admission + untrusted provenance")
struct TraceStoreStorageAdmissionTests {
    private static let mib: Int64 = 1_048_576

    private final class ProbeBox: @unchecked Sendable {
        private let lock = NSLock()
        private var value: Int64?
        private var scriptedValues: [Int64?] = []
        private var scriptedReadCount = 0

        init(_ value: Int64?) { self.value = value }

        func get() -> Int64? {
            lock.lock()
            defer { lock.unlock() }
            if !scriptedValues.isEmpty {
                scriptedReadCount += 1
                return scriptedValues.removeFirst()
            }
            if scriptedReadCount > 0 { scriptedReadCount += 1 }
            return value
        }

        func set(_ newValue: Int64?) {
            lock.lock()
            value = newValue
            scriptedValues = []
            scriptedReadCount = 0
            lock.unlock()
        }

        func script(_ values: [Int64?], then fallback: Int64?) {
            lock.lock()
            scriptedValues = values
            value = fallback
            scriptedReadCount = 0
            lock.unlock()
        }

        func readsSinceScript() -> Int {
            lock.lock()
            defer { lock.unlock() }
            return scriptedReadCount
        }
    }

    private static func tempPath(_ label: String) -> String {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("traces-admission-\(label)-\(UUID().uuidString).db")
            .path
    }

    private static func cleanup(_ path: String) {
        for suffix in ["", "-wal", "-shm", "-journal"] {
            try? FileManager.default.removeItem(atPath: path + suffix)
        }
    }

    private static func executeSQLite(_ sql: String, at path: String) throws {
        var db: OpaquePointer?
        guard sqlite3_open(path, &db) == SQLITE_OK, let db else {
            throw TraceStoreError.databaseOpenFailed("test fixture open failed")
        }
        defer { sqlite3_close(db) }
        let rc = sqlite3_exec(db, sql, nil, nil, nil)
        guard rc == SQLITE_OK else {
            throw TraceStoreError.databaseOpenFailed(
                String(cString: sqlite3_errmsg(db))
            )
        }
    }

    private static func span(
        trace: String = "4bf92f3577b34da6a3ce929d0e0e4736",
        id: String = "00f067aa0ba902b7",
        payloadBytes: Int = 0,
        start: UInt64 = 1_700_000_000_000_000_000
    ) -> SpanRecord {
        SpanRecord(
            traceId: trace,
            spanId: id,
            parentSpanId: nil,
            startNs: start,
            endNs: start + 1_000,
            serviceName: "claude-code",
            spanName: "claude_code.tool.execution",
            agentTool: .claudeCode,
            providerName: "anthropic",
            legacyGenAiSystem: nil,
            attributesJson: #"{"payload":"\#(String(repeating: "x", count: payloadBytes))"}"#,
            trust: .unauthenticatedSelfReported
        )
    }

    @Test("Exact footprint sums DB, WAL, SHM, and journal and rejects non-regular members")
    func exactFootprint() throws {
        let path = Self.tempPath("sum")
        defer { Self.cleanup(path) }
        try Data(repeating: 1, count: 11).write(to: URL(fileURLWithPath: path))
        try Data(repeating: 2, count: 13).write(to: URL(fileURLWithPath: path + "-wal"))
        try Data(repeating: 3, count: 17).write(to: URL(fileURLWithPath: path + "-shm"))
        try Data(repeating: 4, count: 19).write(to: URL(fileURLWithPath: path + "-journal"))
        #expect(TraceStore.exactSQLiteFootprintBytes(databasePath: path) == 60)

        try FileManager.default.removeItem(atPath: path + "-shm")
        try FileManager.default.createSymbolicLink(
            atPath: path + "-shm",
            withDestinationPath: path
        )
        #expect(TraceStore.exactSQLiteFootprintBytes(databasePath: path) == nil)

        // The final DB component remains no-follow even though ordinary macOS
        // temp paths traverse /var -> /private/var. TraceStore's explicit
        // lstat check and the vendored Unix VFS O_NOFOLLOW both reject it.
        let linkPath = Self.tempPath("db-link")
        defer { Self.cleanup(linkPath) }
        try FileManager.default.createSymbolicLink(
            atPath: linkPath,
            withDestinationPath: path
        )
        #expect(throws: TraceStoreError.self) {
            _ = try TraceStore(path: linkPath)
        }
    }

    @Test("Configured cap/floor probes fail closed, unconfigured probes do not")
    func probesFailClosedOnlyWhenConfigured() async throws {
        let path = Self.tempPath("probes")
        defer { Self.cleanup(path) }
        let unconfigured = try TraceStore(
            path: path,
            footprintProbe: { _ in nil },
            freeSpaceProbe: { _ in nil }
        )
        try await unconfigured.insertSpan(Self.span())
        #expect(try await unconfigured.count() == 1)

        let blockedPath = Self.tempPath("probe-block")
        defer { Self.cleanup(blockedPath) }
        _ = try TraceStore(path: blockedPath)
        #expect(throws: TraceStoreStorageAdmissionError.self) {
            _ = try TraceStore(
                path: blockedPath,
                maxFootprintBytes: 16 * Self.mib,
                transactionReserveBytes: 4 * Self.mib,
                footprintProbe: { _ in nil }
            )
        }
        let footprint = ProbeBox(Self.mib)
        let blocked = try TraceStore(
            path: blockedPath,
            maxFootprintBytes: 16 * Self.mib,
            transactionReserveBytes: 4 * Self.mib,
            footprintProbe: { _ in footprint.get() }
        )
        footprint.set(nil)
        await #expect(throws: TraceStoreStorageAdmissionError.self) {
            try await blocked.insertSpan(Self.span(id: "1111111111111111"))
        }
        #expect(try await blocked.count() == 0)
        #expect(await blocked.storageAdmissionStatus().reason == .probeFailure)

        let maskedPath = Self.tempPath("masked-free-probe")
        defer { Self.cleanup(maskedPath) }
        do {
            let maskedBootstrap = try TraceStore(path: maskedPath)
            _ = maskedBootstrap
        }
        do {
            _ = try TraceStore(
                path: maskedPath,
                maxFootprintBytes: 16 * Self.mib,
                freeSpaceFloorBytes: Self.mib,
                transactionReserveBytes: 4 * Self.mib,
                footprintProbe: { _ in 13 * Self.mib },
                freeSpaceProbe: { _ in nil }
            )
            Issue.record("footprint pressure must not mask a failed free-space probe")
        } catch let error as TraceStoreStorageAdmissionError {
            guard case .probeFailed = error else {
                Issue.record("expected probeFailed, got \(error)")
                return
            }
        }

        let lowPath = Self.tempPath("low-floor")
        defer { Self.cleanup(lowPath) }
        _ = try TraceStore(path: lowPath)
        let freeSpace = ProbeBox(1_024 * Self.mib - 1)
        let low = try TraceStore(
            path: lowPath,
            freeSpaceFloorBytes: 1_024 * Self.mib,
            freeSpaceProbe: { _ in freeSpace.get() }
        )
        #expect(await low.storageAdmissionStatus().reason == .lowFreeSpace)
        await #expect(throws: TraceStoreStorageAdmissionError.self) {
            try await low.insertSpan(Self.span(id: "2222222222222222"))
        }
        #expect(try await low.count() == 0)
        #expect(await low.storageAdmissionStatus().reason == .lowFreeSpace)
        freeSpace.set(2_048 * Self.mib)
        try await low.insertSpan(Self.span(id: "3333333333333333"))
        #expect(try await low.count() == 1,
                "an existing pressure-opened store must resume without SIGHUP")
    }

    @Test(
        "An inherited at/over-cap store recovers and restores the full writer",
        arguments: [16, 20]
    )
    func startupPressureCanRecover(footprintMiB: Int) async throws {
        let path = Self.tempPath("startup-recovery-\(footprintMiB)")
        defer { Self.cleanup(path) }
        var bootstrap: TraceStore? = try TraceStore(path: path)
        try await bootstrap?.insertSpan(Self.span(id: "aaaaaaaaaaaaaaaa"))
        try await bootstrap?.insertSpan(Self.span(
            trace: "5bf92f3577b34da6a3ce929d0e0e4736",
            id: "bbbbbbbbbbbbbbbb",
            start: 1_700_000_000_000_001_000
        ))
        bootstrap = nil

        let footprint = ProbeBox(Int64(footprintMiB) * Self.mib)
        let store = try TraceStore(
            path: path,
            maxFootprintBytes: 16 * Self.mib,
            transactionReserveBytes: 4 * Self.mib,
            footprintProbe: { _ in footprint.get() }
        )
        let blocked = await store.storageAdmissionStatus()
        #expect(blocked.blocked)
        #expect(blocked.reason == .footprintLimit)
        #expect(try await store.writerConfigurationDiagnostics().recoveryOnly)
        await #expect(throws: TraceStoreStorageAdmissionError.self) {
            try await store.insertSpan(Self.span(id: "cccccccccccccccc"))
        }

        let recovery = try await store.recoverStorageBudget(
            retentionCutoff: Date(),
            maxDeleteRows: 1,
            maxVacuumPages: 0
        )
        #expect(recovery.spansDeleted == 1,
                "startup pressure must not strand the bounded recovery actor")
        #expect(try await store.count() == 1)
        #expect((await store.storageAdmissionStatus()).blocked,
                "synthetic at/over-cap pressure remains latched after one bounded delete")

        footprint.set(Self.mib)
        #expect((await store.storageAdmissionStatus()).blocked,
                "healthy probes alone must not expose the under-configured recovery handle")
        try await store.insertSpan(Self.span(id: "dddddddddddddddd"))
        #expect(try await store.count() == 2)
        let configured = try await store.writerConfigurationDiagnostics()
        #expect(!configured.recoveryOnly)
        #expect(configured.maxPageCount == 3_072,
                "12 MiB main-file threshold / 4 KiB SQLite pages")
        #expect(configured.journalSizeLimit == 12 * Self.mib)
        #expect(configured.journalMode.lowercased() == "wal")
        #expect(!(await store.storageAdmissionStatus().blocked))
    }

    @Test("Recovery-only open rejects a current-version schema with a wrong-shaped index")
    func recoveryRequiresCompleteCurrentSchema() async throws {
        let path = Self.tempPath("recovery-schema")
        defer { Self.cleanup(path) }
        var bootstrap: TraceStore? = try TraceStore(path: path)
        try await bootstrap?.insertSpan(Self.span())
        bootstrap = nil
        try Self.executeSQLite(
            "DROP INDEX idx_spans_start; CREATE INDEX idx_spans_start ON spans(trace_id)",
            at: path
        )

        #expect(throws: TraceStoreError.self) {
            _ = try TraceStore(
                path: path,
                maxFootprintBytes: 16 * Self.mib,
                transactionReserveBytes: 4 * Self.mib,
                footprintProbe: { _ in 13 * Self.mib }
            )
        }
    }

    @Test("Recovery-only open rejects a UNIQUE index that changes replacement identity")
    func recoveryRejectsNonPrimaryUniqueIdentity() async throws {
        let path = Self.tempPath("recovery-unique-index")
        defer { Self.cleanup(path) }
        var bootstrap: TraceStore? = try TraceStore(path: path)
        try await bootstrap?.insertSpan(Self.span())
        bootstrap = nil
        try Self.executeSQLite(
            "DROP INDEX idx_spans_trace; CREATE UNIQUE INDEX idx_spans_trace ON spans(trace_id)",
            at: path
        )

        #expect(throws: TraceStoreError.self) {
            _ = try TraceStore(
                path: path,
                maxFootprintBytes: 16 * Self.mib,
                transactionReserveBytes: 4 * Self.mib,
                footprintProbe: { _ in 13 * Self.mib }
            )
        }
        let reader = try TraceStore(path: path, forceReadOnly: true)
        #expect(try await reader.count() == 1)
    }

    @Test("Recovery-only open rejects a current-version spans table without its identity key")
    func recoveryRequiresCompositeSpanIdentityBeforeDelete() async throws {
        let path = Self.tempPath("recovery-no-primary-key")
        defer { Self.cleanup(path) }
        try Self.executeSQLite(
            """
            PRAGMA journal_mode = WAL;
            CREATE TABLE spans (
                trace_id TEXT NOT NULL,
                span_id TEXT NOT NULL,
                parent_span_id TEXT,
                start_ns INTEGER NOT NULL,
                end_ns INTEGER NOT NULL,
                service_name TEXT,
                span_name TEXT NOT NULL,
                agent_tool TEXT,
                provider_name TEXT,
                legacy_gen_ai_system TEXT,
                attributes_json TEXT,
                search_text TEXT,
                trust_label TEXT NOT NULL DEFAULT 'unauthenticated_self_reported'
            );
            CREATE INDEX idx_spans_trace ON spans(trace_id);
            CREATE INDEX idx_spans_start ON spans(start_ns);
            CREATE INDEX idx_spans_search ON spans(search_text);
            INSERT INTO spans (
                trace_id, span_id, start_ns, end_ns, span_name, trust_label
            ) VALUES (
                '4bf92f3577b34da6a3ce929d0e0e4736',
                '00f067aa0ba902b7', 1, 2, 'preserve',
                'unauthenticated_self_reported'
            );
            PRAGMA user_version = 3;
            """,
            at: path
        )

        #expect(throws: TraceStoreError.self) {
            _ = try TraceStore(
                path: path,
                maxFootprintBytes: 16 * Self.mib,
                transactionReserveBytes: 4 * Self.mib,
                footprintProbe: { _ in 13 * Self.mib }
            )
        }

        let reader = try TraceStore(path: path, forceReadOnly: true)
        #expect(try await reader.count() == 1,
                "schema refusal must precede every pressure-recovery DELETE")
    }

    @Test("Recovery-only open preserves a future-version store untouched")
    func recoveryRejectsFutureSchemaBeforeDelete() async throws {
        let path = Self.tempPath("recovery-future-schema")
        defer { Self.cleanup(path) }
        var bootstrap: TraceStore? = try TraceStore(path: path)
        try await bootstrap?.insertSpan(Self.span())
        bootstrap = nil
        try Self.executeSQLite("PRAGMA user_version = 99", at: path)

        #expect(throws: TraceStoreError.self) {
            _ = try TraceStore(
                path: path,
                maxFootprintBytes: 16 * Self.mib,
                transactionReserveBytes: 4 * Self.mib,
                footprintProbe: { _ in 13 * Self.mib }
            )
        }
        let reader = try TraceStore(path: path, forceReadOnly: true)
        #expect(try await reader.count() == 1,
                "an older recovery writer must not mutate a future schema")
    }

    @Test("Recovery-only open rejects malformed retention and writer columns")
    func recoveryRequiresExactCriticalColumnShape() async throws {
        let path = Self.tempPath("recovery-critical-column-shape")
        defer { Self.cleanup(path) }
        try Self.executeSQLite(
            """
            PRAGMA journal_mode = WAL;
            CREATE TABLE spans (
                trace_id TEXT NOT NULL,
                span_id TEXT NOT NULL,
                parent_span_id TEXT,
                start_ns TEXT NOT NULL,
                end_ns INTEGER NOT NULL,
                service_name TEXT,
                span_name TEXT NOT NULL,
                agent_tool TEXT,
                provider_name TEXT,
                legacy_gen_ai_system TEXT,
                attributes_json TEXT,
                search_text TEXT,
                trust_label TEXT,
                PRIMARY KEY (trace_id, span_id)
            );
            CREATE INDEX idx_spans_trace ON spans(trace_id);
            CREATE INDEX idx_spans_start ON spans(start_ns);
            CREATE INDEX idx_spans_search ON spans(search_text);
            INSERT INTO spans (
                trace_id, span_id, start_ns, end_ns, span_name, trust_label
            ) VALUES (
                '4bf92f3577b34da6a3ce929d0e0e4736',
                '00f067aa0ba902b7', '1', 2, 'preserve',
                'unauthenticated_self_reported'
            );
            PRAGMA user_version = 3;
            """,
            at: path
        )

        #expect(throws: TraceStoreError.self) {
            _ = try TraceStore(
                path: path,
                maxFootprintBytes: 16 * Self.mib,
                transactionReserveBytes: 4 * Self.mib,
                footprintProbe: { _ in 13 * Self.mib }
            )
        }
        let reader = try TraceStore(path: path, forceReadOnly: true)
        #expect(try await reader.count() == 1,
                "malformed retention columns must be refused before DELETE")
    }

    @Test("Recovery-only open rejects unsupported span CHECK constraints")
    func recoveryRejectsUnsupportedTableConstraint() async throws {
        let path = Self.tempPath("recovery-check-constraint")
        defer { Self.cleanup(path) }
        try Self.executeSQLite(
            """
            PRAGMA journal_mode = WAL;
            CREATE TABLE spans (
                trace_id TEXT NOT NULL,
                span_id TEXT NOT NULL,
                parent_span_id TEXT,
                start_ns INTEGER NOT NULL,
                end_ns INTEGER NOT NULL,
                service_name TEXT,
                span_name TEXT NOT NULL,
                agent_tool TEXT,
                provider_name TEXT,
                legacy_gen_ai_system TEXT,
                attributes_json TEXT,
                search_text TEXT,
                trust_label TEXT NOT NULL DEFAULT 'unauthenticated_self_reported',
                PRIMARY KEY (trace_id, span_id),
                CHECK (start_ns <= end_ns)
            );
            CREATE INDEX idx_spans_trace ON spans(trace_id);
            CREATE INDEX idx_spans_start ON spans(start_ns);
            CREATE INDEX idx_spans_search ON spans(search_text);
            INSERT INTO spans (
                trace_id, span_id, start_ns, end_ns, span_name, trust_label
            ) VALUES (
                '4bf92f3577b34da6a3ce929d0e0e4736',
                '00f067aa0ba902b7', 1, 2, 'preserve',
                'unauthenticated_self_reported'
            );
            PRAGMA user_version = 3;
            """,
            at: path
        )

        #expect(throws: TraceStoreError.self) {
            _ = try TraceStore(
                path: path,
                maxFootprintBytes: 16 * Self.mib,
                transactionReserveBytes: 4 * Self.mib,
                footprintProbe: { _ in 13 * Self.mib }
            )
        }
        let reader = try TraceStore(path: path, forceReadOnly: true)
        #expect(try await reader.count() == 1,
                "unknown table constraints must be refused before DELETE")
    }

    @Test("Recovery-only open rejects inbound foreign-key delete side effects")
    func recoveryRejectsInboundSpanForeignKey() async throws {
        let path = Self.tempPath("recovery-inbound-foreign-key")
        defer { Self.cleanup(path) }
        var bootstrap: TraceStore? = try TraceStore(path: path)
        try await bootstrap?.insertSpan(Self.span())
        bootstrap = nil
        try Self.executeSQLite(
            """
            CREATE TABLE span_dependents (
                trace_id TEXT NOT NULL,
                span_id TEXT NOT NULL,
                FOREIGN KEY (trace_id, span_id)
                    REFERENCES spans(trace_id, span_id)
                    ON DELETE CASCADE
            );
            INSERT INTO span_dependents(trace_id, span_id) VALUES (
                '4bf92f3577b34da6a3ce929d0e0e4736',
                '00f067aa0ba902b7'
            );
            """,
            at: path
        )

        #expect(throws: TraceStoreError.self) {
            _ = try TraceStore(
                path: path,
                maxFootprintBytes: 16 * Self.mib,
                transactionReserveBytes: 4 * Self.mib,
                footprintProbe: { _ in 13 * Self.mib }
            )
        }
        let reader = try TraceStore(path: path, forceReadOnly: true)
        #expect(try await reader.count() == 1,
                "foreign-key refusal must precede every pressure DELETE")
    }

    @Test("Search backfill reacquires the full writer after recovery-only open")
    func backfillReacquiresWriterAfterRecovery() async throws {
        let path = Self.tempPath("recovery-backfill")
        defer { Self.cleanup(path) }
        var bootstrap: TraceStore? = try TraceStore(path: path)
        try await bootstrap?.insertSpan(Self.span())
        bootstrap = nil
        try Self.executeSQLite("UPDATE spans SET search_text = NULL", at: path)

        let footprint = ProbeBox(13 * Self.mib)
        let store = try TraceStore(
            path: path,
            maxFootprintBytes: 16 * Self.mib,
            transactionReserveBytes: 4 * Self.mib,
            footprintProbe: { _ in footprint.get() }
        )
        #expect(try await store.writerConfigurationDiagnostics().recoveryOnly)

        footprint.set(Self.mib)
        #expect((await store.storageAdmissionStatus()).blocked)
        #expect(try await store.backfillSearchProjection() == 1)
        #expect(!(try await store.writerConfigurationDiagnostics().recoveryOnly))
        #expect(try await store.searchSpans(matching: "claude-code").count == 1)
    }

    @Test("Failed full-writer finalization leaves bounded recovery available")
    func recoveryFinalizationFailureStaysFailClosed() async throws {
        let path = Self.tempPath("recovery-finalize-failure")
        defer { Self.cleanup(path) }
        var bootstrap: TraceStore? = try TraceStore(path: path)
        try await bootstrap?.insertSpan(Self.span())
        bootstrap = nil

        let footprint = ProbeBox(13 * Self.mib)
        let store = try TraceStore(
            path: path,
            maxFootprintBytes: 16 * Self.mib,
            transactionReserveBytes: 4 * Self.mib,
            footprintProbe: { _ in footprint.get() },
            pragmaFailureProbe: { operation in
                operation == .journalSizeLimitStep
                    ? TraceStoreInjectedSQLiteFailure(resultCode: SQLITE_FULL)
                    : nil
            }
        )
        footprint.set(Self.mib)
        do {
            try await store.insertSpan(Self.span(id: "bbbbbbbbbbbbbbbb"))
            Issue.record("expected full-writer finalization to fail closed")
        } catch let error as TraceStoreStorageAdmissionError {
            guard case .sqliteFull = error else {
                Issue.record("expected sqliteFull, got \(error)")
                return
            }
        }
        #expect(try await store.count() == 1)
        #expect(try await store.writerConfigurationDiagnostics().recoveryOnly)
        let status = await store.storageAdmissionStatus()
        #expect(status.blocked)
        #expect(status.reason == .sqliteFull)
    }

    @Test("Production directory open clamps inherited recovery-family permissions")
    func recoveryOpenClampsPermissions() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("traces-recovery-perms-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        var bootstrap: TraceStore? = try TraceStore(directory: directory.path)
        try await bootstrap?.insertSpan(Self.span())
        bootstrap = nil
        let path = directory.appendingPathComponent("traces.db").path
        #expect(chmod(path, 0o660) == 0)

        let store = try TraceStore(
            directory: directory.path,
            maxFootprintBytes: 16 * Self.mib,
            transactionReserveBytes: 4 * Self.mib,
            footprintProbe: { _ in 13 * Self.mib }
        )
        #expect(try await store.writerConfigurationDiagnostics().recoveryOnly)
        let attributes = try FileManager.default.attributesOfItem(atPath: path)
        let permissions = attributes[.posixPermissions] as? NSNumber
        #expect(permissions?.intValue == 0o640)
    }

    @Test("Direct single and batch writers cannot bypass footprint admission")
    func directWriterBypassClosed() async throws {
        let path = Self.tempPath("direct")
        defer { Self.cleanup(path) }
        let bootstrap = try TraceStore(path: path)
        try await bootstrap.insertSpan(Self.span(id: "aaaaaaaaaaaaaaaa"))

        let footprint = ProbeBox(Self.mib)
        let store = try TraceStore(
            path: path,
            maxFootprintBytes: 16 * Self.mib,
            transactionReserveBytes: 4 * Self.mib,
            footprintProbe: { _ in footprint.get() }
        )
        footprint.set(13 * Self.mib)
        await #expect(throws: TraceStoreStorageAdmissionError.self) {
            try await store.insertSpan(Self.span(id: "bbbbbbbbbbbbbbbb"))
        }
        await #expect(throws: TraceStoreStorageAdmissionError.self) {
            try await store.insertSpans([
                Self.span(id: "cccccccccccccccc"),
                Self.span(id: "dddddddddddddddd"),
            ])
        }
        #expect(try await store.count() == 1, "genuine seeded evidence survives the flood gate")
    }

    @Test("Decoded batch larger than transaction reserve is rejected before BEGIN")
    func oversizedDecodedBatch() async throws {
        let path = Self.tempPath("oversized")
        defer { Self.cleanup(path) }
        _ = try TraceStore(path: path)
        let store = try TraceStore(
            path: path,
            maxFootprintBytes: 16 * Self.mib,
            transactionReserveBytes: 2 * Self.mib,
            footprintProbe: { _ in 64 * 1024 }
        )
        let huge = Self.span(payloadBytes: 1_000_000)
        #expect(await store.estimatedInsertUpperBoundBytes([huge]) > 2 * Self.mib)
        await #expect(throws: TraceStoreStorageAdmissionError.self) {
            try await store.insertSpans([huge])
        }
        #expect(try await store.count() == 0)
    }

    @Test("Decoded admission charges the expanded encrypted attributes envelope")
    func encryptedEnvelopeCannotExceedRecoverableReserve() async throws {
        let path = Self.tempPath("encrypted-envelope-bound")
        defer { Self.cleanup(path) }
        let encryption = DatabaseEncryption(
            enabled: true,
            keyLoader: { Data(repeating: 0x33, count: 32) },
            keySaver: { _ in 0 },
            keyGenerator: { Data(repeating: 0x44, count: 32) }
        )
        let store = try TraceStore(
            path: path,
            encryption: encryption,
            maxFootprintBytes:
                TraceStoreStoragePolicy.capBytes(maxSizeMiB: 50)
        )
        let record = Self.span(payloadBytes: 5_000_000)
        let status = await store.storageAdmissionStatus()
        let reserve = try #require(status.transactionReserveBytes)
        #expect(reserve == 25 * Self.mib / 2)
        #expect(await store.estimatedInsertUpperBoundBytes([record]) > reserve,
                "AES-GCM nonce/tag/base64 expansion must be charged before BEGIN")
        await #expect(throws: TraceStoreStorageAdmissionError.self) {
            try await store.insertSpan(record)
        }
        #expect(try await store.count() == 0)
    }

    @Test("Span ingest ledger conserves committed rows and whole-batch throws exactly")
    func ingestConservationCountsWholeBatchFailure() async throws {
        let path = Self.tempPath("ingest-conservation")
        defer { Self.cleanup(path) }
        let store = try TraceStore(
            path: path,
            maxFootprintBytes: 64 * Self.mib,
            transactionReserveBytes: 2 * Self.mib
        )
        let committed = try await store.insertSpans([
            Self.span(id: "1111111111111111"),
            Self.span(
                trace: "5bf92f3577b34da6a3ce929d0e0e4736",
                id: "2222222222222222"
            ),
        ])
        #expect(committed.succeeded == 2)
        #expect(committed.failed == 0)

        let refused = (0..<3).map { index in
            Self.span(
                trace: String(format: "%032llx", UInt64(index + 100)),
                id: String(format: "%016llx", UInt64(index + 100)),
                payloadBytes: 400_000
            )
        }
        await #expect(throws: TraceStoreStorageAdmissionError.self) {
            _ = try await store.insertSpans(refused)
        }

        let status = await store.storageAdmissionStatus()
        let ingest = status.ingestConservation
        #expect(ingest.offered == 5)
        #expect(ingest.completed == 2)
        #expect(ingest.queued == 0)
        #expect(ingest.inFlight == 0)
        #expect(ingest.explicitlyShed == 3,
                "a thrown transaction sheds every row, not one mutation call")
        #expect(ingest.conservationMaintained)
        #expect(try await store.count() == 2)
    }

    @Test("Failed BEGIN and COMMIT preserve typed FULL/ENOSPC and never report rows")
    func checkedTransactionControl() async throws {
        let beginPath = Self.tempPath("begin-full")
        defer { Self.cleanup(beginPath) }
        _ = try TraceStore(path: beginPath)
        let beginStore = try TraceStore(
            path: beginPath,
            transactionFailureProbe: { operation in
                operation == .begin
                    ? TraceStoreInjectedSQLiteFailure(resultCode: SQLITE_FULL)
                    : nil
            }
        )
        await #expect(throws: TraceStoreStorageAdmissionError.self) {
            try await beginStore.insertSpan(Self.span())
        }
        #expect(try await beginStore.count() == 0)
        let beginIngest = await beginStore.storageAdmissionStatus()
            .ingestConservation
        #expect(beginIngest.offered == 1)
        #expect(beginIngest.completed == 0)
        #expect(beginIngest.explicitlyShed == 1)
        #expect(beginIngest.conservationMaintained)

        let commitPath = Self.tempPath("commit-full")
        defer { Self.cleanup(commitPath) }
        let seed = try TraceStore(path: commitPath)
        try await seed.insertSpan(Self.span(id: "aaaaaaaaaaaaaaaa"))
        let commitStore = try TraceStore(
            path: commitPath,
            transactionFailureProbe: { operation in
                operation == .commit
                    ? TraceStoreInjectedSQLiteFailure(resultCode: SQLITE_FULL)
                    : nil
            }
        )
        await #expect(throws: TraceStoreStorageAdmissionError.self) {
            try await commitStore.insertSpan(
                Self.span(id: "bbbbbbbbbbbbbbbb")
            )
        }
        #expect(try await commitStore.count() == 1,
                "failed COMMIT must roll back and expose no successful-row count")
        let commitIngest = await commitStore.storageAdmissionStatus()
            .ingestConservation
        #expect(commitIngest.offered == 1)
        #expect(commitIngest.completed == 0)
        #expect(commitIngest.explicitlyShed == 1)
        #expect(commitIngest.conservationMaintained)

        let ioPath = Self.tempPath("commit-enospc")
        defer { Self.cleanup(ioPath) }
        _ = try TraceStore(path: ioPath)
        let ioStore = try TraceStore(
            path: ioPath,
            transactionFailureProbe: { operation in
                operation == .commit
                    ? TraceStoreInjectedSQLiteFailure(
                        resultCode: SQLITE_IOERR,
                        extendedResultCode: SQLITE_IOERR | Int32(3 << 8),
                        systemErrno: ENOSPC
                    )
                    : nil
            }
        )
        do {
            _ = try await ioStore.insertSpans([Self.span()])
            Issue.record("expected typed filesystem-full failure")
        } catch let error as TraceStoreStorageAdmissionError {
            guard case .filesystemFull(_, _, _, let systemErrno) = error else {
                Issue.record("expected filesystemFull, got \(error)")
                return
            }
            #expect(systemErrno == ENOSPC)
        }
        #expect(try await ioStore.count() == 0)
        let ioIngest = await ioStore.storageAdmissionStatus()
            .ingestConservation
        #expect(ioIngest.offered == 1)
        #expect(ioIngest.completed == 0)
        #expect(ioIngest.explicitlyShed == 1)
        #expect(ioIngest.conservationMaintained)
    }

    @Test("SQLite FULL remains latched until an explicit recovery boundary")
    func sqliteFailureRemainsLatched() async throws {
        let path = Self.tempPath("sticky-full")
        defer { Self.cleanup(path) }
        _ = try TraceStore(path: path)
        let store = try TraceStore(
            path: path,
            maxFootprintBytes: 64 * Self.mib,
            freeSpaceFloorBytes: nil,
            transactionReserveBytes: 8 * Self.mib,
            footprintProbe: { _ in Self.mib },
            transactionFailureProbe: { operation in
                operation == .commit
                    ? TraceStoreInjectedSQLiteFailure(resultCode: SQLITE_FULL)
                    : nil
            }
        )
        await #expect(throws: TraceStoreStorageAdmissionError.self) {
            try await store.insertSpans([Self.span()])
        }
        #expect(await store.storageAdmissionStatus().reason == .sqliteFull)
        await #expect(throws: TraceStoreStorageAdmissionError.self) {
            try await store.preflightStorageAdmission(estimatedGrowthBytes: 1)
        }

        let reset = try await store.updateStorageAdmission(
            maxFootprintBytes: 64 * Self.mib,
            freeSpaceFloorBytes: nil,
            transactionReserveBytes: 8 * Self.mib
        )
        #expect(!reset.blocked)
        try await store.preflightStorageAdmission(estimatedGrowthBytes: 1)
    }

    @Test("Admission backstop pragma read/write failures remain typed and close the open handle")
    func pragmaFailuresRemainTyped() throws {
        for (index, operation) in TraceStorePragmaOperation.allCases.enumerated() {
            let path = Self.tempPath("pragma-\(operation.rawValue)")
            defer { Self.cleanup(path) }
            _ = try TraceStore(path: path)
            let expectFilesystemFull = index.isMultiple(of: 2) == false
            let injected = expectFilesystemFull
                ? TraceStoreInjectedSQLiteFailure(
                    resultCode: SQLITE_IOERR,
                    extendedResultCode: SQLITE_IOERR | Int32(3 << 8),
                    systemErrno: ENOSPC
                )
                : TraceStoreInjectedSQLiteFailure(resultCode: SQLITE_FULL)
            do {
                _ = try TraceStore(
                    path: path,
                    maxFootprintBytes: 16 * Self.mib,
                    transactionReserveBytes: 4 * Self.mib,
                    pragmaFailureProbe: { candidate in
                        candidate == operation ? injected : nil
                    }
                )
                Issue.record("expected typed pragma failure for \(operation)")
            } catch let error as TraceStoreStorageAdmissionError {
                if expectFilesystemFull {
                    guard case .filesystemFull = error else {
                        Issue.record("expected filesystemFull, got \(error)")
                        continue
                    }
                } else {
                    guard case .sqliteFull = error else {
                        Issue.record("expected sqliteFull, got \(error)")
                        continue
                    }
                }
            }

            // If the post-open failure leaked its handle, this exclusive
            // transaction would remain vulnerable to a hidden lock owner.
            var db: OpaquePointer?
            #expect(sqlite3_open(path, &db) == SQLITE_OK)
            #expect(sqlite3_exec(db, "BEGIN EXCLUSIVE; ROLLBACK", nil, nil, nil) == SQLITE_OK)
            sqlite3_close(db)
        }
    }

    @Test("Blocked store returns 507 before attempting malformed protobuf decode")
    func predecodeStorageResponse() async throws {
        let path = Self.tempPath("predecode")
        defer { Self.cleanup(path) }
        _ = try TraceStore(path: path)
        let footprint = ProbeBox(Self.mib)
        let store = try TraceStore(
            path: path,
            maxFootprintBytes: 8 * Self.mib,
            transactionReserveBytes: 2 * Self.mib,
            footprintProbe: { _ in footprint.get() }
        )
        footprint.set(7 * Self.mib)
        let receiver = OTLPReceiver(port: 4318, traceStore: store)
        let response = await receiver.ingestBodyForTesting(Data([0xff, 0xff]))
        #expect(response.status == 507)
        let metrics = await receiver.metricsSnapshot()
        #expect(metrics.bodyDecodeErrors == 0,
                "pressure gate must run before malformed protobuf is decoded")
        #expect(try await store.count() == 0)
    }

    @Test("Runtime cap lowering blocks immediately and raising resumes")
    func liveCapUpdate() async throws {
        let path = Self.tempPath("reload")
        defer { Self.cleanup(path) }
        let footprint = ProbeBox(5 * Self.mib)
        let store = try TraceStore(
            path: path,
            maxFootprintBytes: 12 * Self.mib,
            transactionReserveBytes: 2 * Self.mib,
            footprintProbe: { _ in footprint.get() }
        )
        try await store.insertSpan(Self.span(id: "aaaaaaaaaaaaaaaa"))
        let lowered = try await store.updateStorageAdmission(
            maxFootprintBytes: 6 * Self.mib,
            freeSpaceFloorBytes: nil,
            transactionReserveBytes: 2 * Self.mib
        )
        #expect(lowered.blocked)
        await #expect(throws: TraceStoreStorageAdmissionError.self) {
            try await store.insertSpan(Self.span(id: "bbbbbbbbbbbbbbbb"))
        }
        let raised = try await store.updateStorageAdmission(
            maxFootprintBytes: 12 * Self.mib,
            freeSpaceFloorBytes: nil,
            transactionReserveBytes: 2 * Self.mib
        )
        #expect(!raised.blocked)
        try await store.insertSpan(Self.span(id: "cccccccccccccccc"))
        #expect(try await store.count() == 2)
    }

    @Test("Actual flood remains under cap and preserves pre-existing evidence")
    func boundedFloodPreservesSeed() async throws {
        let path = Self.tempPath("flood")
        defer { Self.cleanup(path) }
        let writer = try TraceStore(path: path)
        let seed = Self.span(id: "aaaaaaaaaaaaaaaa")
        try await writer.insertSpan(seed)

        let cap = 4 * Self.mib
        let store = try TraceStore(
            path: path,
            maxFootprintBytes: cap,
            freeSpaceFloorBytes: nil,
            transactionReserveBytes: 2 * Self.mib
        )
        var blocked = false
        for index in 0..<1_000 {
            let id = String(format: "%016llx", UInt64(index + 1))
            do {
                try await store.insertSpan(Self.span(
                    trace: String(format: "%032llx", UInt64(index + 1)),
                    id: id,
                    payloadBytes: 2_048,
                    start: seed.startNs + UInt64(index + 1)
                ))
            } catch is TraceStoreStorageAdmissionError {
                blocked = true
                break
            }
        }
        #expect(blocked, "flood must reach admission rather than grow forever")
        #expect(try await store.spansForTrace(seed.traceId).first?.spanId == seed.spanId)
        let footprint = try #require(await store.storageFootprintBytes())
        #expect(footprint <= cap, "the SQLite family must stay within the absolute cap")
    }

    @Test("Configured stores refuse legacy unbounded maintenance entry points")
    func configuredMaintenanceIsBounded() async throws {
        let path = Self.tempPath("configured-maintenance")
        defer { Self.cleanup(path) }
        let store = try TraceStore(
            path: path,
            maxFootprintBytes: 64 * Self.mib,
            freeSpaceFloorBytes: nil,
            transactionReserveBytes: 8 * Self.mib
        )
        await #expect(throws: TraceStoreError.self) {
            try await store.prune(olderThan: Date())
        }
        await #expect(throws: TraceStoreError.self) {
            try await store.pruneOldest(count: 1)
        }
        await #expect(throws: TraceStoreError.self) {
            _ = try await store.incrementalVacuum(maxPages: Int.max)
        }
        await #expect(throws: TraceStoreError.self) {
            try await store.vacuum()
        }
    }

    @Test("Every WAL checkpoint preserves the floor plus the full sidecar family")
    func checkpointHeadroomUsesFreshSidecarBytes() async throws {
        let path = Self.tempPath("checkpoint-headroom")
        defer { Self.cleanup(path) }
        var bootstrap: TraceStore? = try TraceStore(path: path)
        bootstrap = nil

        let footprint = ProbeBox(
            TraceStore.exactSQLiteFootprintBytes(databasePath: path)
        )
        let free = ProbeBox(Int64.max)
        let floor: Int64 = 10_000
        let store = try TraceStore(
            path: path,
            freeSpaceFloorBytes: floor,
            footprintProbe: { _ in footprint.get() },
            freeSpaceProbe: { _ in free.get() }
        )

        let sidecars: Int64 = 4_096
        let main = try SQLitePersistentStoreAdmission.measureMainFile(path)
        footprint.set(main + sidecars)
        free.set(floor + sidecars)
        #expect(await store.walCheckpoint(),
                "the exact floor+sidecar boundary must be admitted")

        let mainAfter = try SQLitePersistentStoreAdmission.measureMainFile(path)
        footprint.set(mainAfter + sidecars)
        free.set(floor + sidecars - 1)
        #expect(!(await store.walCheckpointTruncate()),
                "checkpoint must not consume one byte below the hard floor")
        let blocked = await store.storageAdmissionStatus()
        #expect(blocked.reason == .lowFreeSpace)
        #expect(blocked.freeSpaceBytes == floor + sidecars - 1)
        #expect(blocked.shedMutationsTotal == 0,
                "deferring maintenance is not a shed ingest mutation")
    }

    @Test("Reader-pinned WAL prevents bounded recovery deletion")
    func pinnedReaderRecoveryDoesNotDelete() async throws {
        let path = Self.tempPath("pinned-reader")
        defer { Self.cleanup(path) }
        let store = try TraceStore(path: path)
        let expired = Self.span(id: "aaaaaaaaaaaaaaaa", start: 1)
        try await store.insertSpan(expired)
        _ = await store.walCheckpoint()

        var reader: OpaquePointer?
        #expect(sqlite3_open_v2(
            path, &reader, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nil
        ) == SQLITE_OK)
        defer { if let reader { sqlite3_close(reader) } }
        let openedReader = try #require(reader)
        #expect(sqlite3_exec(openedReader, "BEGIN", nil, nil, nil) == SQLITE_OK)
        var statement: OpaquePointer?
        #expect(sqlite3_prepare_v2(
            openedReader, "SELECT COUNT(*) FROM spans", -1, &statement, nil
        ) == SQLITE_OK)
        #expect(sqlite3_step(statement) == SQLITE_ROW)
        sqlite3_finalize(statement)

        try await store.insertSpan(Self.span(
            id: "bbbbbbbbbbbbbbbb", start: 2
        ))
        let pinned = try await store.recoverStorageBudget(
            retentionCutoff: Date(), maxDeleteRows: 1, maxVacuumPages: 0
        )
        #expect(pinned.pinnedReader)
        #expect(pinned.spansDeleted == 0)
        #expect(try await store.count() == 2)

        #expect(sqlite3_exec(openedReader, "COMMIT", nil, nil, nil) == SQLITE_OK)
        sqlite3_close(openedReader)
        reader = nil

        let recovered = try await store.recoverStorageBudget(
            retentionCutoff: Date(), maxDeleteRows: 1, maxVacuumPages: 0
        )
        #expect(!recovered.pinnedReader)
        #expect(recovered.spansDeleted == 1)
        #expect(try await store.count() == 1)
    }

    @Test("Repeated production-sized recovery batches converge a real SQLite family")
    func multiBatchRecoveryConvergesRealFamily() async throws {
        let path = Self.tempPath("multi-batch-convergence")
        defer { Self.cleanup(path) }
        let cutoff = Date(timeIntervalSince1970: 1_750_000_000)
        let expiredStart: UInt64 = 1_600_000_000_000_000_000
        let retainedStart: UInt64 = 1_800_000_000_000_000_000

        var bootstrap: TraceStore? = try TraceStore(path: path)
        #expect(await bootstrap?.autoVacuumMode() == 2)
        for batchStart in stride(from: 0, to: 900, by: 75) {
            let batchEnd = min(batchStart + 75, 900)
            var records: [SpanRecord] = []
            records.reserveCapacity(batchEnd - batchStart)
            for index in batchStart..<batchEnd {
                let ordinal = UInt64(index + 1)
                let traceID = String(format: "%032llx", ordinal)
                let spanID = String(format: "%016llx", ordinal)
                records.append(Self.span(
                    trace: traceID,
                    id: spanID,
                    payloadBytes: 4_096,
                    start: expiredStart + UInt64(index)
                ))
            }
            _ = try await bootstrap?.insertSpans(records)
        }
        let retainedTraceIDs = (0..<4).map { index in
            String(format: "%032llx", UInt64(10_000 + index))
        }
        _ = try await bootstrap?.insertSpans(
            retainedTraceIDs.enumerated().map { index, traceID in
                Self.span(
                    trace: traceID,
                    id: String(format: "%016llx", UInt64(10_000 + index)),
                    payloadBytes: 1_024,
                    start: retainedStart + UInt64(index)
                )
            }
        )
        #expect(await bootstrap?.walCheckpointTruncate() == true)
        bootstrap = nil

        let initialFootprint = try #require(
            TraceStore.exactSQLiteFootprintBytes(databasePath: path)
        )
        let threshold = max(512 * 1_024, initialFootprint * 55 / 100)
        #expect(threshold < initialFootprint)
        let reserve = 16 * Self.mib
        let store = try TraceStore(
            path: path,
            maxFootprintBytes: threshold + reserve,
            transactionReserveBytes: reserve
        )
        #expect((await store.storageAdmissionStatus()).blocked)
        #expect(try await store.writerConfigurationDiagnostics().recoveryOnly)

        var passes = 0
        var deleted = 0
        while (await store.storageAdmissionStatus()).blocked, passes < 12 {
            let result = try await store.recoverStorageBudget(
                retentionCutoff: cutoff
            )
            #expect(!result.pinnedReader)
            deleted += result.spansDeleted
            passes += 1
        }

        let recovered = await store.storageAdmissionStatus()
        #expect(passes > 1,
                "a one-shot 256-row pass must not be mistaken for convergence")
        #expect(deleted > 256)
        #expect(!recovered.blocked)
        #expect(try #require(recovered.footprintBytes) < threshold)
        #expect(!(try await store.writerConfigurationDiagnostics().recoveryOnly))
        for traceID in retainedTraceIDs {
            #expect(try await store.spansForTrace(traceID).count == 1,
                    "pressure recovery must retain evidence newer than the cutoff")
        }
    }

    @Test("One encrypted span larger than the nominal delete batch cannot wedge recovery")
    func oversizedOldestSpanUsesBoundedSingleRowRecovery() async throws {
        let path = Self.tempPath("oversized-oldest-recovery")
        defer { Self.cleanup(path) }
        let footprint = ProbeBox(64 * 1_024)
        let free = ProbeBox(Int64.max)
        let encryption = DatabaseEncryption(
            enabled: true,
            keyLoader: { Data(repeating: 0x5A, count: 32) },
            keySaver: { _ in 0 },
            keyGenerator: { Data(repeating: 0xA5, count: 32) }
        )
        let productionCap = TraceStoreStoragePolicy.capBytes(maxSizeMiB: 50)
        let productionFloor = TraceStoreStoragePolicy.freeSpaceFloorBytes
        let store = try TraceStore(
            path: path,
            encryption: encryption,
            maxFootprintBytes: productionCap,
            freeSpaceFloorBytes: productionFloor,
            footprintProbe: { _ in footprint.get() },
            freeSpaceProbe: { _ in free.get() }
        )
        let large = Self.span(payloadBytes: 4_300_000, start: 1)
        let estimate = await store.estimatedInsertUpperBoundBytes([large])
        let initial = await store.storageAdmissionStatus()
        let reserve = 25 * Self.mib / 2
        #expect(initial.transactionReserveBytes == reserve)
        #expect(estimate < reserve,
                "the >4 MiB production-legal span must reach persistence")
        try await store.insertSpan(large)
        #expect(try await store.count() == 1)
        let exactFamily = TraceStore.exactSQLiteFootprintBytes(
            databasePath: path
        )
        guard let exactFamily else {
            Issue.record("exact family probe failed before checkpoint")
            return
        }
        footprint.set(exactFamily)
        #expect(await store.walCheckpointTruncate())

        // Default 50 MiB policy admits below 37.5 MiB. The encrypted row's
        // recovery charge is above the ordinary 8 MiB delete batch but below
        // the explicit one-row ceiling.
        footprint.set(38 * Self.mib)
        #expect((await store.storageAdmissionStatus()).blocked)

        // The checkpoint headroom is small after the explicit truncate, but
        // the fresh operation-sized floor proof still refuses this DELETE.
        let operationStarvedFree = productionFloor + 2 * Self.mib
        // Recovery's PASSIVE and TRUNCATE checkpoints each see ample space.
        // Space drops before the DELETE boundary; only a fresh per-operation
        // floor probe can observe and refuse that transition.
        free.script([Int64.max, Int64.max], then: operationStarvedFree)
        await #expect(throws: TraceStoreStorageAdmissionError.self) {
            _ = try await store.recoverStorageBudget(
                retentionCutoff: Date(),
                maxDeleteRows: 256,
                maxVacuumPages: 0
            )
        }
        #expect(try await store.count() == 1,
                "an oversized recovery may not spend through the fresh floor")
        #expect(free.readsSinceScript() >= 4,
                "the DELETE must re-probe after both checkpoint gates")

        free.set(Int64.max)
        let recovery = try await store.recoverStorageBudget(
            retentionCutoff: Date(),
            maxDeleteRows: 256,
            maxVacuumPages: 0
        )
        #expect(recovery.spansDeleted == 1)
        #expect(!recovery.retentionBacklogRemaining)
        #expect(try await store.count() == 0)

        footprint.set(64 * 1_024)
        #expect(!(await store.storageAdmissionStatus()).blocked,
                "one bounded pass must let the writer converge after pressure clears")
    }

    @Test("Single-row recovery refuses payloads no production admission could create")
    func oversizedRecoveryIsCappedAtFormerProductionAdmission() async throws {
        let path = Self.tempPath("oversized-recovery-ceiling")
        defer { Self.cleanup(path) }
        var bootstrap: TraceStore? = try TraceStore(path: path)
        try await bootstrap?.insertSpan(Self.span(start: 1))
        #expect(await bootstrap?.walCheckpointTruncate() == true)
        bootstrap = nil

        // Under the 50 MiB production policy the 12.5 MiB reserve could admit
        // at most ~8.03 MB of ENC2/base64 attributes under the former plaintext
        // estimate. This 8.2 MiB stored payload is therefore not a legacy-legal
        // row and must not broaden the emergency DELETE operation indefinitely.
        try Self.executeSQLite(
            "UPDATE spans SET attributes_json = zeroblob(8200000); PRAGMA wal_checkpoint(TRUNCATE)",
            at: path
        )
        let productionCap = TraceStoreStoragePolicy.capBytes(maxSizeMiB: 50)
        let store = try TraceStore(
            path: path,
            maxFootprintBytes: productionCap,
            freeSpaceFloorBytes: TraceStoreStoragePolicy.freeSpaceFloorBytes,
            footprintProbe: { _ in 38 * Self.mib },
            freeSpaceProbe: { _ in Int64.max }
        )

        await #expect(throws: TraceStoreStorageAdmissionError.self) {
            _ = try await store.recoverStorageBudget(
                retentionCutoff: Date(),
                maxDeleteRows: 256,
                maxVacuumPages: 0
            )
        }
        #expect(try await store.count() == 1,
                "an impossible oversized row must fail visibly and remain intact")
    }

    @Test("Pressured populated mode-0 store converts once and recovers physically")
    func legacyModeZeroRecoveryConvertsAndPreservesRecentEvidence() async throws {
        let path = Self.tempPath("legacy-mode-zero")
        defer { Self.cleanup(path) }
        try Self.executeSQLite(
            "PRAGMA auto_vacuum = NONE; CREATE TABLE legacy_seed(value TEXT); INSERT INTO legacy_seed VALUES ('preserve');",
            at: path
        )

        let cutoff = Date(timeIntervalSince1970: 1_750_000_000)
        let expiredStart: UInt64 = 1_600_000_000_000_000_000
        let retainedStart: UInt64 = 1_800_000_000_000_000_000
        var bootstrap: TraceStore? = try TraceStore(path: path)
        #expect(await bootstrap?.autoVacuumMode() == 0,
                "a populated NONE header cannot change without full VACUUM")
        for batchStart in stride(from: 0, to: 700, by: 50) {
            let batchEnd = min(batchStart + 50, 700)
            var records: [SpanRecord] = []
            records.reserveCapacity(batchEnd - batchStart)
            for index in batchStart..<batchEnd {
                let ordinal = UInt64(index + 1)
                let traceID = String(format: "%032llx", ordinal)
                let spanID = String(format: "%016llx", ordinal)
                records.append(Self.span(
                    trace: traceID,
                    id: spanID,
                    payloadBytes: 8_192,
                    start: expiredStart + UInt64(index)
                ))
            }
            _ = try await bootstrap?.insertSpans(records)
        }
        let retainedTraceIDs = (0..<3).map { index in
            String(format: "%032llx", UInt64(20_000 + index))
        }
        _ = try await bootstrap?.insertSpans(
            retainedTraceIDs.enumerated().map { index, traceID in
                Self.span(
                    trace: traceID,
                    id: String(format: "%016llx", UInt64(20_000 + index)),
                    payloadBytes: 1_024,
                    start: retainedStart + UInt64(index)
                )
            }
        )
        #expect(await bootstrap?.walCheckpointTruncate() == true)
        bootstrap = nil

        let initialFootprint = try #require(
            TraceStore.exactSQLiteFootprintBytes(databasePath: path)
        )
        let threshold = max(512 * 1_024, initialFootprint * 55 / 100)
        let reserve = 16 * Self.mib
        let store = try TraceStore(
            path: path,
            maxFootprintBytes: threshold + reserve,
            freeSpaceFloorBytes: 64 * 1_024,
            transactionReserveBytes: reserve
        )
        let initialStatus = await store.storageAdmissionStatus()
        #expect(initialStatus.blocked)
        #expect(try #require(initialStatus.footprintBytes) >= threshold)
        #expect(try await store.writerConfigurationDiagnostics().recoveryOnly)

        var passes = 0
        var deleted = 0
        var observedModeTwo = false
        while (await store.storageAdmissionStatus()).blocked, passes < 12 {
            let result = try await store.recoverStorageBudget(
                retentionCutoff: cutoff
            )
            #expect(!result.pinnedReader)
            observedModeTwo = observedModeTwo || result.autoVacuumMode == 2
            deleted += result.spansDeleted
            passes += 1
        }

        let recovered = await store.storageAdmissionStatus()
        #expect(observedModeTwo)
        #expect(await store.autoVacuumMode() == 2)
        #expect(deleted > 0)
        #expect(!recovered.blocked)
        #expect(try #require(recovered.footprintBytes) < threshold)
        #expect(!(try await store.writerConfigurationDiagnostics().recoveryOnly),
                "physical recovery must restore the fully configured writer")
        for traceID in retainedTraceIDs {
            #expect(try await store.spansForTrace(traceID).count == 1,
                    "full conversion and bounded pruning must retain recent evidence")
        }
    }

    @Test("Mode-0 conversion preserves the configured floor before deleting evidence")
    func legacyConversionHeadroomFailsBeforeDelete() async throws {
        let path = Self.tempPath("legacy-mode-zero-headroom")
        defer { Self.cleanup(path) }
        try Self.executeSQLite(
            "PRAGMA auto_vacuum = NONE; CREATE TABLE legacy_seed(value TEXT); INSERT INTO legacy_seed VALUES ('seed');",
            at: path
        )
        var bootstrap: TraceStore? = try TraceStore(path: path)
        try await bootstrap?.insertSpan(Self.span(id: "aaaaaaaaaaaaaaaa", start: 1))
        #expect(await bootstrap?.autoVacuumMode() == 0)
        #expect(await bootstrap?.walCheckpointTruncate() == true)
        bootstrap = nil

        let initialFootprint = try #require(
            TraceStore.exactSQLiteFootprintBytes(databasePath: path)
        )
        let mainBytes = try SQLitePersistentStoreAdmission.measureMainFile(path)
        let reserve: Int64 = 4_096
        let floor: Int64 = 64 * 1_024
        let free = ProbeBox(Int64.max)
        let store = try TraceStore(
            path: path,
            maxFootprintBytes: initialFootprint + reserve,
            freeSpaceFloorBytes: floor,
            transactionReserveBytes: reserve,
            freeSpaceProbe: { _ in free.get() }
        )
        #expect((await store.storageAdmissionStatus()).blocked)

        let family = try #require(
            TraceStore.exactSQLiteFootprintBytes(databasePath: path)
        )
        let checkpointRequired = floor + max(0, family - mainBytes)
        let fullVacuumRequired = SQLitePersistentStoreAdmission
            .fullVacuumRequiredFreeBytes(
                mainFileBytes: mainBytes,
                freeSpaceFloorBytes: floor
            )
        let oneByteShort = fullVacuumRequired - 1
        #expect(oneByteShort >= checkpointRequired,
                "fixture must admit the reader check but refuse full VACUUM")
        free.set(oneByteShort)

        do {
            _ = try await store.recoverStorageBudget(
                retentionCutoff: Date(),
                maxDeleteRows: 1,
                maxVacuumPages: 0
            )
            Issue.record("expected configured full-VACUUM headroom refusal")
        } catch let error as TraceStoreStorageAdmissionError {
            guard case .lowFreeSpace(
                let freeBytes, let floorBytes, let requiredFreeBytes
            ) = error else {
                Issue.record("expected lowFreeSpace, got \(error)")
                return
            }
            #expect(freeBytes == oneByteShort)
            #expect(floorBytes == floor)
            #expect(requiredFreeBytes == fullVacuumRequired)
        }
        #expect(try await store.count() == 1,
                "no DELETE may precede a refused mode-0 conversion")
        #expect(await store.autoVacuumMode() == 0)
        #expect((await store.storageAdmissionStatus()).blocked)
    }

    @Test("Force-read-only v2 schema defaults trust and cannot mutate")
    func legacyReadOnlyTrustMigration() async throws {
        let path = Self.tempPath("legacy-v2")
        defer { Self.cleanup(path) }
        var db: OpaquePointer?
        #expect(sqlite3_open(path, &db) == SQLITE_OK)
        let schema = """
            CREATE TABLE spans (
                trace_id TEXT NOT NULL, span_id TEXT NOT NULL,
                parent_span_id TEXT, start_ns INTEGER NOT NULL,
                end_ns INTEGER NOT NULL, service_name TEXT,
                span_name TEXT NOT NULL, agent_tool TEXT,
                provider_name TEXT, legacy_gen_ai_system TEXT,
                attributes_json TEXT, search_text TEXT,
                PRIMARY KEY(trace_id, span_id)
            );
            INSERT INTO spans VALUES (
                '4bf92f3577b34da6a3ce929d0e0e4736', '00f067aa0ba902b7',
                NULL, 1, 2, 'claude-code', 'legacy', 'claude_code',
                'anthropic', NULL, NULL, 'legacy'
            );
            PRAGMA user_version = 2;
            """
        #expect(sqlite3_exec(db, schema, nil, nil, nil) == SQLITE_OK)
        sqlite3_close(db)

        let reader = try TraceStore(path: path, forceReadOnly: true)
        #expect(await reader.hasTrustLabel() == false)
        let rows = try await reader.spansForTrace(
            "4bf92f3577b34da6a3ce929d0e0e4736"
        )
        #expect(rows.first?.trust == .unauthenticatedSelfReported)
        #expect(try await reader.searchSpans(matching: "legacy").count == 1,
                "v2 RO search synthesizes a structural search projection")
        await #expect(throws: (any Error).self) {
            try await reader.insertSpan(Self.span(id: "ffffffffffffffff"))
        }
        #expect(try await reader.count() == 1)
    }

    @Test("Writable v1 database migrates through search projection before its index")
    func writableV1Migration() async throws {
        let path = Self.tempPath("legacy-v1-writable")
        defer { Self.cleanup(path) }
        var db: OpaquePointer?
        #expect(sqlite3_open(path, &db) == SQLITE_OK)
        let schema = """
            CREATE TABLE spans (
                trace_id TEXT NOT NULL, span_id TEXT NOT NULL,
                parent_span_id TEXT, start_ns INTEGER NOT NULL,
                end_ns INTEGER NOT NULL, service_name TEXT,
                span_name TEXT NOT NULL, agent_tool TEXT,
                provider_name TEXT, legacy_gen_ai_system TEXT,
                attributes_json TEXT,
                PRIMARY KEY(trace_id, span_id)
            );
            INSERT INTO spans VALUES (
                '4bf92f3577b34da6a3ce929d0e0e4736', '00f067aa0ba902b7',
                NULL, 1, 2, 'claude-code', 'legacy-v1', 'claude_code',
                'anthropic', NULL, NULL
            );
            PRAGMA user_version = 1;
            """
        #expect(sqlite3_exec(db, schema, nil, nil, nil) == SQLITE_OK)
        sqlite3_close(db)

        let migrated = try TraceStore(path: path)
        #expect(await migrated.hasSearchProjection())
        #expect(await migrated.hasTrustLabel())
        let rows = try await migrated.spansForTrace(
            "4bf92f3577b34da6a3ce929d0e0e4736"
        )
        #expect(rows.first?.trust == .unauthenticatedSelfReported)
        try await migrated.insertSpan(Self.span(id: "ffffffffffffffff"))
        #expect(try await migrated.count() == 2)
    }

    @Test("Legacy SpanRecord JSON defaults to unauthenticated self-report")
    func legacyModelDecode() throws {
        let json = #"{"traceId":"t","spanId":"s","startNs":1,"endNs":2,"spanName":"n"}"#
        let decoded = try JSONDecoder().decode(SpanRecord.self, from: Data(json.utf8))
        #expect(decoded.trust == .unauthenticatedSelfReported)
    }

    @Test("Trace recovery retries pressure every tick but retains daily healthy cadence")
    func productionRecoveryCadenceGate() {
        #expect(TraceStoreRecoveryCadenceGate.initialDelaySeconds == 180)
        #expect(TraceStoreRecoveryCadenceGate.pressureIntervalSeconds == 300)
        #expect(TraceStoreRecoveryCadenceGate.healthyIntervalSeconds == 86_400)

        let gate = TraceStoreRecoveryCadenceGate()
        let start = Date(timeIntervalSince1970: 1_700_000_000)
        #expect(gate.shouldRun(blocked: false, now: start),
                "the first post-boot retention pass must run")
        #expect(!gate.shouldRun(blocked: false, now: start.addingTimeInterval(300)),
                "healthy five-minute ticks must not replace daily retention")
        gate.recordRecoveryOutcome(retentionBacklogRemaining: true)
        #expect(gate.shouldRun(blocked: false, now: start.addingTimeInterval(600)),
                "an explicitly reported healthy backlog must use the five-minute drain cadence")
        gate.recordRecoveryOutcome(retentionBacklogRemaining: false)
        #expect(!gate.shouldRun(blocked: false, now: start.addingTimeInterval(900)),
                "an empty retention backlog returns to the daily deadline")
        #expect(gate.shouldRun(blocked: true, now: start.addingTimeInterval(600)))
        #expect(gate.shouldRun(blocked: true, now: start.addingTimeInterval(900)),
                "a blocked store needs consecutive bounded recovery batches")
        #expect(!gate.shouldRun(blocked: false, now: start.addingTimeInterval(1_200)),
                "recovery completion resets the daily healthy deadline")
        #expect(gate.shouldRun(
            blocked: false,
            now: start.addingTimeInterval(900 + 86_400)
        ))
    }

    @Test("Healthy retention drains more than one bounded batch before returning daily")
    func healthyRetentionBacklogDrainsAtPressureCadence() async throws {
        let path = Self.tempPath("healthy-retention-drain")
        defer { Self.cleanup(path) }
        let store = try TraceStore(
            path: path,
            maxFootprintBytes:
                TraceStoreStoragePolicy.capBytes(maxSizeMiB: 100)
        )
        var records: [SpanRecord] = []
        records.reserveCapacity(600)
        for index in 0..<600 {
            let ordinal = UInt64(index + 1)
            records.append(Self.span(
                trace: String(format: "%032llx", ordinal),
                id: String(format: "%016llx", ordinal),
                start: ordinal
            ))
        }
        _ = try await store.insertSpans(records)
        #expect(!(await store.storageAdmissionStatus()).blocked)

        let gate = TraceStoreRecoveryCadenceGate()
        let start = Date(timeIntervalSince1970: 1_700_000_000)
        var now = start
        var passCounts: [Int] = []
        while gate.shouldRun(blocked: false, now: now) {
            let result = try await store.recoverStorageBudget(
                retentionCutoff: Date(),
                maxDeleteRows: 256,
                maxVacuumPages: 0
            )
            passCounts.append(result.spansDeleted)
            gate.recordRecoveryOutcome(
                retentionBacklogRemaining:
                    result.retentionBacklogRemaining
            )
            now = now.addingTimeInterval(
                TraceStoreRecoveryCadenceGate.pressureIntervalSeconds
            )
            if passCounts.count > 4 {
                Issue.record("healthy retention did not converge in bounded passes")
                break
            }
        }

        #expect(passCounts == [256, 256, 88])
        #expect(try await store.count() == 0)
        #expect(!gate.shouldRun(blocked: false, now: now),
                "an empty backlog must remain on daily cadence")
    }

    @Test("Production TraceStore wiring cannot drift around admission or trust")
    func productionWiringGuard() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        func source(_ relativePath: String) throws -> String {
            try String(
                contentsOf: root.appendingPathComponent(relativePath),
                encoding: .utf8
            )
        }
        func constructorCalls(in text: String, marker: String) -> [String] {
            var calls: [String] = []
            var searchStart = text.startIndex
            while let found = text.range(
                of: marker, range: searchStart..<text.endIndex
            ) {
                var depth = 1
                var cursor = found.upperBound
                while cursor < text.endIndex, depth > 0 {
                    switch text[cursor] {
                    case "(": depth += 1
                    case ")": depth -= 1
                    default: break
                    }
                    cursor = text.index(after: cursor)
                }
                guard depth == 0 else { break }
                calls.append(String(text[found.lowerBound..<cursor]))
                searchStart = cursor
            }
            return calls
        }

        let setup = try source("Sources/MacCrabAgentKit/DaemonSetup.swift")
        let setupCalls = constructorCalls(in: setup, marker: "TraceStore(")
        #expect(setupCalls.count == 2,
                "classify each new daemon TraceStore construction")
        #expect(setupCalls.allSatisfy {
            $0.contains("maxFootprintBytes:")
                && $0.contains("freeSpaceFloorBytes: TraceStoreStoragePolicy.freeSpaceFloorBytes")
                && $0.contains("storageVolumePath: supportDir")
        }, "boot and SIGHUP must share the cap, floor, and filesystem volume")

        let reloadStart = try #require(setup.range(
            of: "if let existing = state.otlpReceiver"))
        let reloadEnd = try #require(setup.range(
            of: "guard shouldRun else { return }",
            range: reloadStart.lowerBound..<setup.endIndex
        ))
        let reload = String(setup[reloadStart.lowerBound..<reloadEnd.lowerBound])
        let update = try #require(reload.range(of: "updateStorageAdmission("))
        let samePort = try #require(reload.range(of: "if existingPort == cfg.port"))
        #expect(update.lowerBound < samePort.lowerBound,
                "same-port SIGHUP must apply the new cap before returning")
        #expect(reload.contains("await existing.stop()"))
        #expect(reload.contains("storage admission reload failed"),
                "a failed page/cap reload must stop the accepting receiver visibly")
        #expect(reload.contains("reusableTraceStore = traceStore"))
        #expect(setup.contains("if let reusableTraceStore"))
        #expect(setup.contains("traceStore = reusableTraceStore"),
                "a port-only SIGHUP restart must not open a second traces.db writer actor")

        let timers = try source("Sources/MacCrabAgentKit/DaemonTimers.swift")
        let traceGraphTimer = try #require(timers.range(
            of: "tracegraphPruneTimer = nil"))
        let timerStart = try #require(timers.range(
            of: "let tracesPruneTimer",
            range: traceGraphTimer.upperBound..<timers.endIndex
        ))
        let timerEnd = try #require(timers.range(
            of: "let artifactsPruneTimer",
            range: timerStart.lowerBound..<timers.endIndex
        ))
        let traceTimer = String(timers[timerStart.lowerBound..<timerEnd.lowerBound])
        #expect(traceTimer.contains("recoverStorageBudget("))
        #expect(traceTimer.contains(
            "TraceStoreRecoveryCadenceGate.pressureIntervalSeconds"
        ), "the live timer must wake at the bounded pressure cadence")
        #expect(traceTimer.contains("shouldRun("))
        #expect(traceTimer.contains("blocked: admissionBefore.blocked"),
                "storage pressure must bypass the daily retention gate")
        #expect(traceTimer.contains("recordRecoveryOutcome("))
        #expect(traceTimer.contains("result.retentionBacklogRemaining"),
                "a healthy bounded pass must keep draining an expired backlog")
        #expect(traceTimer.contains(
            "timerLifecycle.submit(label: \"traces-recovery\")"
        ), "label coalescing prevents overlapping recovery passes")
        #expect(!traceTimer.contains(".prune("))
        #expect(!traceTimer.contains(".pruneOldest("))
        #expect(!traceTimer.contains(".vacuum("),
                "the timer must delegate to actor-owned recovery, never call the unrestricted VACUUM entry point")
        let timerHandler = try #require(traceTimer.range(of: "t.setEventHandler"))
        let liveStoreLookup = try #require(traceTimer.range(
            of: "guard let traceStore = state.traceStore",
            range: timerHandler.upperBound..<traceTimer.endIndex
        ))
        #expect(timerHandler.lowerBound < liveStoreLookup.lowerBound,
                "SIGHUP lifecycle requires the timer to resolve the current TraceStore actor on each tick")
        #expect(timers.contains("\"traces_storage_admission\": traceStoreStorageDict"))
        #expect(timers.contains("d[\"ingest_conservation\"]"))
        for key in ["offered", "completed", "queued", "in_flight", "explicitly_shed"] {
            #expect(timers.contains("\"\(key)\""),
                    "TraceStore heartbeat is missing ingest ledger key \(key)")
        }

        let readOnlyClients = [
            "Sources/MacCrabApp/AppState.swift",
            "Sources/maccrabctl/AgentSpansCommand.swift",
            "Sources/maccrabctl/StatusCommand.swift",
            "Sources/maccrab-mcp/main.swift",
        ]
        for path in readOnlyClients {
            let calls = constructorCalls(in: try source(path), marker: "TraceStore(")
            #expect(!calls.isEmpty, "expected a classified TraceStore reader in \(path)")
            #expect(calls.allSatisfy { $0.contains("forceReadOnly: true") },
                    "query-only TraceStore client gained write capability: \(path)")
        }

        let detectionDirectory = root.appendingPathComponent(
            "Sources/MacCrabCore/Detection", isDirectory: true
        )
        let detectionFiles = (try FileManager.default.contentsOfDirectory(
            at: detectionDirectory,
            includingPropertiesForKeys: nil
        )).filter { $0.pathExtension == "swift" }
        for file in detectionFiles {
            let text = try String(contentsOf: file, encoding: .utf8)
            #expect(!text.contains("TraceStore("))
            #expect(!text.contains("AgentTraceTrust"))
            #expect(!text.contains("SpanRecord"),
                    "unauthenticated OTLP records must not become detection authentication")
        }

        let v2 = try source("Sources/MacCrabApp/V2/Data/V2HeartbeatSnapshot.swift")
        #expect(v2.contains("raw[\"traces_storage_admission\"]"))
        let dashboard = try source("Sources/MacCrabApp/V2/Workspaces/V2SystemWorkspace.swift")
        #expect(dashboard.contains("traceStoreStorageBanner"))
        let cli = try source("Sources/maccrabctl/StatusCommand.swift")
        #expect(cli.contains("traceStoreStorageStatusLines"))
        let mcp = try source("Sources/maccrab-mcp/main.swift")
        #expect(mcp.contains("Agent Trace DB:"))
        #expect(mcp.contains("unauthenticated/self-reported"))
        let view = try source("Sources/MacCrabApp/Views/AgentTracesView.swift")
        #expect(view.contains("span.trust.displayLabel"))
        #expect(view.contains("Loopback is not authentication"))
    }
}
