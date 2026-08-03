import Testing
import Foundation
import Darwin
import CSQLCipher
@testable import MacCrabCore

@Suite("TraceStore: authoritative disk admission + untrusted provenance")
struct TraceStoreStorageAdmissionTests {
    private static let mib: Int64 = 1_048_576

    private final class ProbeBox: @unchecked Sendable {
        private let lock = NSLock()
        private var value: Int64?

        init(_ value: Int64?) { self.value = value }

        func get() -> Int64? {
            lock.lock()
            defer { lock.unlock() }
            return value
        }

        func set(_ newValue: Int64?) {
            lock.lock()
            value = newValue
            lock.unlock()
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

        let lowPath = Self.tempPath("low-floor")
        defer { Self.cleanup(lowPath) }
        _ = try TraceStore(path: lowPath)
        #expect(throws: TraceStoreStorageAdmissionError.self) {
            _ = try TraceStore(
                path: lowPath,
                freeSpaceFloorBytes: 1_024 * Self.mib,
                freeSpaceProbe: { _ in 1_024 * Self.mib - 1 }
            )
        }
        let freeSpace = ProbeBox(2_048 * Self.mib)
        let low = try TraceStore(
            path: lowPath,
            freeSpaceFloorBytes: 1_024 * Self.mib,
            freeSpaceProbe: { _ in freeSpace.get() }
        )
        freeSpace.set(1_024 * Self.mib - 1)
        await #expect(throws: TraceStoreStorageAdmissionError.self) {
            try await low.insertSpan(Self.span(id: "2222222222222222"))
        }
        #expect(try await low.count() == 0)
        #expect(await low.storageAdmissionStatus().reason == .lowFreeSpace)
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
        #expect(!traceTimer.contains(".prune("))
        #expect(!traceTimer.contains(".pruneOldest("))
        #expect(!traceTimer.contains(".vacuum("),
                "the online timer must never issue a full-file VACUUM")
        let timerHandler = try #require(traceTimer.range(of: "t.setEventHandler"))
        let liveStoreLookup = try #require(traceTimer.range(
            of: "guard let traceStore = state.traceStore",
            range: timerHandler.upperBound..<traceTimer.endIndex
        ))
        #expect(timerHandler.lowerBound < liveStoreLookup.lowerBound,
                "SIGHUP lifecycle requires the timer to resolve the current TraceStore actor on each tick")
        #expect(timers.contains("\"traces_storage_admission\": traceStoreStorageDict"))

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
