import Testing
import Foundation
import Darwin
import CSQLCipher
@testable import MacCrabCore

@Suite("Persistent SQLite store admission")
struct SQLitePersistentStoreAdmissionTests {
    private final class Int64Box: @unchecked Sendable {
        private let lock = NSLock()
        private var value: Int64

        init(_ value: Int64) { self.value = value }

        func get() -> Int64 {
            lock.lock()
            defer { lock.unlock() }
            return value
        }

        func set(_ value: Int64) {
            lock.lock()
            self.value = value
            lock.unlock()
        }
    }

    private func tempDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("persistent-admission-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: url,
            withIntermediateDirectories: true
        )
        return url
    }

    private var repositoryRoot: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    private func repositoryText(_ relativePath: String) throws -> String {
        try String(
            contentsOf: repositoryRoot.appendingPathComponent(relativePath),
            encoding: .utf8
        )
    }

    private func sourceSwiftFiles() throws -> [String: String] {
        let sources = repositoryRoot.appendingPathComponent(
            "Sources",
            isDirectory: true
        )
        guard let enumerator = FileManager.default.enumerator(
            at: sources,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: [.skipsHiddenFiles]
        ) else { return [:] }
        var result: [String: String] = [:]
        for case let url as URL in enumerator where url.pathExtension == "swift" {
            let values = try url.resourceValues(forKeys: [.isRegularFileKey])
            guard values.isRegularFile == true else { continue }
            let relative = String(url.path.dropFirst(sources.path.count + 1))
            result[relative] = try String(contentsOf: url, encoding: .utf8)
        }
        return result
    }

    private func occurrences(of needle: String, in text: String) -> Int {
        text.components(separatedBy: needle).count - 1
    }

    private func policy(
        directory: URL,
        max: Int64 = 1_048_576,
        floor: Int64 = 0,
        reserve: Int64 = 65_536
    ) -> SQLitePersistentStorePolicy {
        SQLitePersistentStorePolicy(
            maxFootprintBytes: max,
            freeSpaceFloorBytes: floor,
            transactionReserveBytes: reserve,
            storageVolumePath: directory.path
        )
    }

    private func event() -> Event {
        Event(
            timestamp: Date(),
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: ProcessInfo(
                pid: 42,
                ppid: 1,
                rpid: 1,
                name: "admission-test",
                executable: "/usr/bin/true",
                commandLine: "/usr/bin/true",
                args: ["/usr/bin/true"],
                workingDirectory: "/",
                userId: 501,
                userName: "tester",
                groupId: 20,
                startTime: Date(),
                ancestors: [],
                isPlatformBinary: true
            )
        )
    }

    private func alert() -> Alert {
        Alert(
            id: UUID().uuidString,
            timestamp: Date(),
            ruleId: "storage-admission-test",
            ruleTitle: "Storage admission test",
            severity: .low,
            eventId: UUID().uuidString
        )
    }

    private func campaign() -> CampaignStore.Record {
        CampaignStore.Record(
            id: UUID().uuidString,
            type: "test",
            severity: .low,
            title: "Storage admission test",
            description: "test",
            tactics: [],
            timeSpanSeconds: 1,
            detectedAt: Date()
        )
    }

    /// Adopt a ceiling one byte below the store's current footprint+reserve.
    /// updateStorageAdmission therefore latches pressure while preserving the
    /// already-prepared writer; maintenance can then shrink the family so the
    /// next ordinary admission takes the reopen-after-recovery path.
    private func pressureLatchPolicy(
        directory: URL,
        databasePath: String,
        reserveBytes: Int64
    ) throws -> SQLitePersistentStorePolicy {
        let footprint = try SQLitePersistentStoreAdmission.measureFamily(
            databasePath
        )
        return policy(
            directory: directory,
            max: footprint + reserveBytes - 1,
            reserve: reserveBytes
        )
    }

    @Test("Family accounting is exact and rejects partial, symlinked, or hard-linked families")
    func familyAccounting() throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("store.db").path
        try Data(repeating: 1, count: 11).write(to: URL(fileURLWithPath: path))
        try Data(repeating: 2, count: 13).write(to: URL(fileURLWithPath: path + "-wal"))
        try Data(repeating: 3, count: 17).write(to: URL(fileURLWithPath: path + "-shm"))
        #expect(try SQLitePersistentStoreAdmission.measureFamily(path) == 41)

        try FileManager.default.removeItem(atPath: path)
        #expect(throws: SQLitePersistentStoreAdmissionError.self) {
            _ = try SQLitePersistentStoreAdmission.measureFamily(path)
        }

        try Data().write(to: URL(fileURLWithPath: path))
        try FileManager.default.removeItem(atPath: path + "-shm")
        try FileManager.default.createSymbolicLink(
            atPath: path + "-shm",
            withDestinationPath: path
        )
        #expect(throws: SQLitePersistentStoreAdmissionError.self) {
            _ = try SQLitePersistentStoreAdmission.measureFamily(path)
        }

        try FileManager.default.removeItem(atPath: path + "-shm")
        try FileManager.default.removeItem(atPath: path + "-wal")
        let hardSource = dir.appendingPathComponent("hard-source")
        try Data([4]).write(to: hardSource)
        try FileManager.default.linkItem(
            atPath: hardSource.path,
            toPath: path + "-wal"
        )
        #expect(throws: SQLitePersistentStoreAdmissionError.self) {
            _ = try SQLitePersistentStoreAdmission.measureFamily(path)
        }
        try FileManager.default.removeItem(atPath: path + "-wal")
        try FileManager.default.removeItem(at: hardSource)

        let secondMainLink = dir.appendingPathComponent("second-main-link.db")
        try FileManager.default.linkItem(
            atPath: path,
            toPath: secondMainLink.path
        )
        #expect(throws: SQLitePersistentStoreAdmissionError.self) {
            _ = try SQLitePersistentStoreAdmission.mainFileExists(path)
        }
    }

    @Test("All production SQLite opens share alias normalization and NOFOLLOW")
    func sqliteOpenBoundaryCannotDrift() throws {
        let files = try sourceSwiftFiles()
        let directOpeners = Set(files.compactMap { path, text in
            text.contains("sqlite3_open_v2(") ? path : nil
        })
        #expect(directOpeners == [
            "MacCrabCore/Storage/SQLiteOpenPathPolicy.swift",
        ], "production path opens must stay behind the shared NOFOLLOW boundary")

        let helper = try #require(
            files["MacCrabCore/Storage/SQLiteOpenPathPolicy.swift"]
        )
        #expect(occurrences(of: "sqlite3_open_v2(", in: helper) == 1)
        #expect(helper.contains("flags | SQLITE_OPEN_NOFOLLOW"))
        #expect(helper.contains("normalizedPath(displayPath)"))
        #expect(helper.contains("displayPath.first == \"/\""),
                "relative, URI, and special SQLite filenames must fail closed")

        let wrapperUsers = Set(files.compactMap { path, text in
            text.contains("SQLiteOpenPathPolicy.open(") ? path : nil
        })
        let expectedUsers: Set<String> = [
            "MacCrabAgentKit/DaemonTimers.swift",
            "MacCrabApp/AppState.swift",
            "MacCrabCore/Collectors/TCCMonitor.swift",
            "MacCrabCore/Detection/ThreatHunter.swift",
            "MacCrabCore/Enrichment/DeliveryProvenanceWeld.swift",
            "MacCrabCore/Enrichment/QuarantineEnricher.swift",
            "MacCrabCore/Storage/AlertStore.swift",
            "MacCrabCore/Storage/AlertsTableRelocator.swift",
            "MacCrabCore/Storage/AttributionOverrideStore.swift",
            "MacCrabCore/Storage/CampaignStore.swift",
            "MacCrabCore/Storage/EventStore.swift",
            "MacCrabCore/Storage/SQLiteCausalGraphStore.swift",
            "MacCrabCore/Storage/TraceStore.swift",
            "MacCrabForensics/Plugins/Analyzers/PostureAnalyzer.swift",
            "MacCrabForensics/Plugins/Collectors/ChromiumLite/ChromiumLitePlugin.swift",
            "MacCrabForensics/Plugins/Collectors/FaceTime/FaceTimePlugin.swift",
            "MacCrabForensics/Plugins/Collectors/KnowledgeC/KnowledgeCPlugin.swift",
            "MacCrabForensics/Plugins/Collectors/MailLite/MailLitePlugin.swift",
            "MacCrabForensics/Plugins/Collectors/Quarantine/QuarantinePlugin.swift",
            "MacCrabForensics/Plugins/Collectors/SafariLite/SafariLitePlugin.swift",
            "MacCrabForensics/Plugins/Collectors/TCCLite/TCCLitePlugin.swift",
            "MacCrabForensics/Plugins/Collectors/iMessageBodies/iMessageBodiesPlugin.swift",
            "MacCrabForensics/Plugins/Collectors/iMessageMetadata/iMessageMetadataPlugin.swift",
            "MacCrabForensics/Snapshots/LiveDBSnapshot.swift",
            "MacCrabForensics/Storage/ArtifactStore.swift",
        ]
        #expect(wrapperUsers == expectedUsers,
                "the production SQLite opener census changed; review path trust before updating it")
        for path in wrapperUsers {
            let text = try #require(files[path])
            #expect(!text.contains("\"/etc/"),
                    "\(path) introduced the unsupported /etc symlink alias")
            #expect(!text.contains("\":memory:\""))
            #expect(!text.contains("\"file:"),
                    "\(path) introduced a SQLite URI filename")
        }
    }

    @Test("macOS /var and /tmp aliases open, while other parent symlinks fail")
    func sqliteOpenAliasRuntime() throws {
        #expect(SQLiteOpenPathPolicy.normalizedPath("/var") == "/private/var")
        #expect(SQLiteOpenPathPolicy.normalizedPath("/var/db/test.db")
            == "/private/var/db/test.db")
        #expect(SQLiteOpenPathPolicy.normalizedPath("/tmp") == "/private/tmp")
        #expect(SQLiteOpenPathPolicy.normalizedPath("/tmp/test.db")
            == "/private/tmp/test.db")
        #expect(SQLiteOpenPathPolicy.normalizedPath("/variable/test.db")
            == "/variable/test.db")
        #expect(SQLiteOpenPathPolicy.normalizedPath("/tmp-owned/test.db")
            == "/tmp-owned/test.db")
        #expect(SQLiteOpenPathPolicy.normalizedPath("/etc/test.db")
            == "/etc/test.db")

        for refused in [
            "relative.db",
            ":memory:",
            "file:/tmp/uri.db?mode=memory",
            "/tmp/truncated.db\0ignored",
        ] {
            var refusedDB: OpaquePointer?
            #expect(SQLiteOpenPathPolicy.open(
                refused,
                database: &refusedDB,
                flags: SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE
            ) == SQLITE_CANTOPEN)
            #expect(refusedDB == nil)
        }

        func createDatabase(at displayPath: String) throws {
            var db: OpaquePointer?
            let rc = SQLiteOpenPathPolicy.open(
                displayPath,
                database: &db,
                flags: SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE
                    | SQLITE_OPEN_FULLMUTEX
            )
            defer { if let db { sqlite3_close(db) } }
            #expect(rc == SQLITE_OK)
            _ = try #require(db)
        }

        let tmpPath = "/tmp/maccrab-sqlite-open-\(UUID().uuidString).db"
        defer {
            try? FileManager.default.removeItem(
                atPath: SQLiteOpenPathPolicy.normalizedPath(tmpPath)
            )
        }
        try createDatabase(at: tmpPath)
        #expect(FileManager.default.fileExists(
            atPath: SQLiteOpenPathPolicy.normalizedPath(tmpPath)
        ))

        let varDirectory = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: varDirectory) }
        let canonicalVarPath = SQLiteOpenPathPolicy.normalizedPath(
            varDirectory.appendingPathComponent("var-alias.db").path
        )
        guard canonicalVarPath.hasPrefix("/private/var/") else {
            Issue.record("Foundation temporaryDirectory is not on /private/var")
            return
        }
        let varAliasPath = String(canonicalVarPath.dropFirst("/private".count))
        try createDatabase(at: varAliasPath)
        #expect(FileManager.default.fileExists(atPath: canonicalVarPath))

        let realParent = varDirectory.appendingPathComponent("real-parent")
        let linkedParent = varDirectory.appendingPathComponent("linked-parent")
        try FileManager.default.createDirectory(
            at: realParent,
            withIntermediateDirectories: false
        )
        try FileManager.default.createSymbolicLink(
            at: linkedParent,
            withDestinationURL: realParent
        )
        let blockedPath = linkedParent.appendingPathComponent("blocked.db").path
        var blockedDB: OpaquePointer?
        let blockedRC = SQLiteOpenPathPolicy.open(
            blockedPath,
            database: &blockedDB,
            flags: SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE
                | SQLITE_OPEN_FULLMUTEX
        )
        if let blockedDB { sqlite3_close(blockedDB) }
        #expect(blockedRC != SQLITE_OK)
        #expect(!FileManager.default.fileExists(
            atPath: realParent.appendingPathComponent("blocked.db").path
        ))
    }

    @Test("Every primary store rejects hard links before read-write or forced read-only open")
    func primaryStoreHardLinkRuntime() throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }

        func plantHardLinkedDatabase(named name: String) throws -> String {
            let path = dir.appendingPathComponent(name).path
            try Data().write(to: URL(fileURLWithPath: path))
            try FileManager.default.linkItem(
                atPath: path,
                toPath: path + ".second-link"
            )
            return path
        }

        for forceReadOnly in [false, true] {
            let eventPath = try plantHardLinkedDatabase(
                named: "events-\(forceReadOnly).db"
            )
            #expect(throws: SQLitePersistentStoreAdmissionError.self) {
                _ = try EventStore(
                    path: eventPath,
                    forceReadOnly: forceReadOnly
                )
            }

            let alertPath = try plantHardLinkedDatabase(
                named: "alerts-\(forceReadOnly).db"
            )
            #expect(throws: SQLitePersistentStoreAdmissionError.self) {
                _ = try AlertStore(
                    path: alertPath,
                    forceReadOnly: forceReadOnly
                )
            }

            let campaignPath = try plantHardLinkedDatabase(
                named: "campaigns-\(forceReadOnly).db"
            )
            #expect(throws: SQLitePersistentStoreAdmissionError.self) {
                _ = try CampaignStore(
                    path: campaignPath,
                    forceReadOnly: forceReadOnly
                )
            }
        }

        let overridePath = try plantHardLinkedDatabase(named: "overrides.db")
        #expect(throws: SQLitePersistentStoreAdmissionError.self) {
            _ = try AttributionOverrideStore(
                path: overridePath,
                storagePolicy: policy(directory: dir)
            )
        }
    }

    @Test("MiB conversion is overflow-safe and the common floor cannot drift")
    func policyConversion() {
        #expect(SQLitePersistentStorePolicy.capBytes(maxSizeMiB: -1) == 0)
        #expect(SQLitePersistentStorePolicy.capBytes(maxSizeMiB: 0) == 0)
        #expect(SQLitePersistentStorePolicy.capBytes(maxSizeMiB: 1) == 1_048_576)
        #expect(SQLitePersistentStorePolicy.capBytes(maxSizeMiB: Int.max) == Int64.max)
        #expect(SQLitePersistentStorePolicy.freeSpaceFloorBytes == 1_073_741_824)
        #expect(SQLitePersistentStorePolicy.eventTransactionReserveBytes
            == 32 * 1_048_576)
    }

    @Test("Transaction estimates are page-aware, amortized, and hard-limited by reserve")
    func transactionEstimateContract() throws {
        let pageSize: Int64 = 4_096
        let row = SQLitePersistentStoreAdmission
            .conservativeEncodedRowMutationBytes(
                logicalRepresentationBytes: 1_500,
                pageSizeBytes: pageSize,
                maximumLeafPageTouches: 20
            )
        #expect(row == 84_920)
        let fixed = SQLitePersistentStoreAdmission
            .transactionFixedOverheadBytes(
                pageSizeBytes: pageSize,
                maximumTreePathPageTouches: 48
            )
        #expect(fixed == 212_992)
        let reserve = SQLitePersistentStorePolicy.eventTransactionReserveBytes
        #expect((reserve - fixed) / row == 392,
                "ordinary events must amortize fixed tree slack across a useful batch")

        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        var admission = try SQLitePersistentStoreAdmission(
            databasePath: dir.appendingPathComponent("estimate.db").path,
            policy: policy(
                directory: dir,
                max: 128 * 1_048_576,
                reserve: reserve
            ),
            footprintProbe: { _ in 0 },
            freeSpaceProbe: { _ in Int64.max }
        )
        #expect(throws: SQLitePersistentStoreAdmissionError.self) {
            try admission.admitWrite(
                estimatedTransactionBytes: reserve + 1
            )
        }
        try admission.admitWrite(estimatedTransactionBytes: reserve)
    }

    @Test("Page-counted maintenance reserves fixed paths and bounded overshoot")
    func boundedPageOperationContract() {
        let plan = SQLitePersistentStoreAdmission.boundedPageOperationPlan(
            requestedPages: 100,
            reserveBytes: 1_000_000,
            pageSizeBytes: 4_096,
            copiesPerPage: 2,
            fixedTreePageTouches: 8,
            overshootPages: 64
        )
        // 12 fixed pages + 64 possible overshoot pages leave room for exactly
        // 52 requested 8-KiB page images inside the one-million-byte reserve.
        #expect(plan.pages == 52)
        #expect(plan.estimatedTransactionBytes == 999_424)

        let noRoom = SQLitePersistentStoreAdmission.boundedPageOperationPlan(
            requestedPages: 1,
            reserveBytes: 573_440,
            pageSizeBytes: 4_096,
            copiesPerPage: 2,
            fixedTreePageTouches: 8,
            overshootPages: 64
        )
        #expect(noRoom.pages == 0)
        #expect(noRoom.estimatedTransactionBytes == Int64.max)

        let overflow = SQLitePersistentStoreAdmission.boundedPageOperationPlan(
            requestedPages: Int.max,
            reserveBytes: Int64.max,
            pageSizeBytes: 65_536,
            copiesPerPage: Int64.max
        )
        #expect(overflow.pages == 0)
        #expect(overflow.estimatedTransactionBytes == Int64.max)
    }

    @Test("Whole-file VACUUM admission is exactly floor plus twice the main file")
    func fullVacuumHeadroomBoundary() throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("vacuum.db").path
        try Data(repeating: 0, count: 10).write(to: URL(fileURLWithPath: path))
        let free = Int64Box(25)
        var admission = try SQLitePersistentStoreAdmission(
            databasePath: path,
            policy: policy(directory: dir, max: 1_000, floor: 5, reserve: 1),
            footprintProbe: { _ in 10 },
            freeSpaceProbe: { _ in free.get() }
        )

        let admitted = try admission.admitFullVacuum()
        #expect(admitted.mainFileBytes == 10)
        #expect(admitted.scratchBytes == 20)
        #expect(admitted.requiredFreeBytes == 25)
        #expect(admitted.admitted)

        free.set(24)
        #expect(throws: SQLitePersistentStoreAdmissionError.self) {
            _ = try admission.admitFullVacuum()
        }
        #expect(SQLitePersistentStoreAdmission.fullVacuumRequiredFreeBytes(
            mainFileBytes: Int64.max,
            freeSpaceFloorBytes: 1
        ) == Int64.max)
    }

    @Test("Checkpoint admission preserves the floor plus all allocated sidecars")
    func checkpointHeadroomBoundary() throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("checkpoint.db").path
        try Data(repeating: 0, count: 10).write(to: URL(fileURLWithPath: path))
        let free = Int64Box(36)
        var admission = try SQLitePersistentStoreAdmission(
            databasePath: path,
            policy: policy(directory: dir, max: 1_000, floor: 5, reserve: 1),
            footprintProbe: { _ in 41 },
            freeSpaceProbe: { _ in free.get() }
        )

        let admitted = try admission.admitCheckpoint()
        #expect(admitted.mainFileBytes == 10)
        #expect(admitted.familyFootprintBytes == 41)
        #expect(admitted.sidecarBytes == 31)
        #expect(admitted.requiredFreeBytes == 36)
        #expect(admitted.admitted)

        free.set(35)
        #expect(throws: SQLitePersistentStoreAdmissionError.self) {
            _ = try admission.admitCheckpoint()
        }

        var overflowing = try SQLitePersistentStoreAdmission(
            databasePath: path,
            policy: policy(
                directory: dir,
                max: Int64.max,
                floor: Int64.max,
                reserve: 1
            ),
            maintenance: true,
            footprintProbe: { _ in 11 },
            freeSpaceProbe: { _ in Int64.max }
        )
        #expect(throws: SQLitePersistentStoreAdmissionError.self) {
            _ = try overflowing.admitCheckpoint()
        }

        let inconsistent = SQLitePersistentStoreAdmission
            .checkpointAdmissionSnapshot(
                mainFileBytes: 11,
                familyFootprintBytes: 10,
                freeSpaceBytes: Int64.max,
                freeSpaceFloorBytes: 0
            )
        #expect(!inconsistent.admitted)
        #expect(inconsistent.requirementOverflowed)
    }

    @Test("Schema rebuild headroom uses fresh whole-store growth and scratch bounds")
    func schemaRebuildHeadroomBoundary() throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("schema.db").path
        try Data(repeating: 0, count: 100).write(to: URL(fileURLWithPath: path))
        let free = Int64Box(1_000)
        var admission = try SQLitePersistentStoreAdmission(
            databasePath: path,
            policy: policy(directory: dir, max: 1_000, floor: 10, reserve: 10),
            footprintProbe: { _ in 120 },
            freeSpaceProbe: { _ in free.get() }
        )

        let twoIndexes = try admission.admitSchemaRebuild(operationCount: 2)
        #expect(twoIndexes.mainFileBytes == 100)
        #expect(twoIndexes.projectedGrowthBytes == 200)
        #expect(twoIndexes.scratchBytes == 300)
        #expect(twoIndexes.projectedFootprintBytes == 320)
        #expect(twoIndexes.requiredFreeBytes == 310)

        let bulkCopy = try admission.admitSchemaRebuild(
            operationCount: 1,
            minimumProjectedGrowthBytes: 500
        )
        #expect(bulkCopy.projectedGrowthBytes == 500)
        #expect(bulkCopy.scratchBytes == 600)
        #expect(bulkCopy.projectedFootprintBytes == 620)
        #expect(bulkCopy.requiredFreeBytes == 610)

        free.set(609)
        #expect(throws: SQLitePersistentStoreAdmissionError.self) {
            _ = try admission.admitSchemaRebuild(
                operationCount: 1,
                minimumProjectedGrowthBytes: 500
            )
        }
    }

    @Test("Schema classifier distinguishes repairs, no-ops, metadata, and rebuilds")
    func schemaWorkClassifier() throws {
        var db: OpaquePointer?
        #expect(sqlite3_open(":memory:", &db) == SQLITE_OK)
        let handle = try #require(db)
        defer { sqlite3_close(handle) }
        #expect(sqlite3_exec(
            handle,
            "CREATE TABLE sample (id INTEGER PRIMARY KEY, value TEXT); CREATE INDEX idx_sample_value ON sample(value); CREATE TRIGGER trg_sample AFTER INSERT ON sample BEGIN SELECT 1; END;",
            nil,
            nil,
            nil
        ) == SQLITE_OK)

        let work = SchemaMigrator.pendingStorageWork(
            on: handle,
            statements: [
                "CREATE INDEX IF NOT EXISTS idx_sample_value ON sample(value)",
                "CREATE INDEX IF NOT EXISTS idx_sample_id ON sample(id)",
                "CREATE TRIGGER IF NOT EXISTS trg_sample AFTER INSERT ON sample BEGIN SELECT 1; END",
                "CREATE TRIGGER IF NOT EXISTS trg_sample_new AFTER UPDATE ON sample BEGIN SELECT 1; END",
                "ALTER TABLE sample ADD COLUMN added TEXT",
                "DROP INDEX IF EXISTS idx_sample_value",
                "DROP INDEX IF EXISTS idx_absent",
                "CREATE VIRTUAL TABLE IF NOT EXISTS sample_fts USING fts5(value)",
            ]
        )
        #expect(work.rebuildStatementCount == 3)
        #expect(work.boundedMetadataStatementCount == 2)

        #expect(sqlite3_exec(
            handle,
            "ALTER TABLE sample ADD COLUMN added TEXT",
            nil,
            nil,
            nil
        ) == SQLITE_OK)
        #expect(SchemaMigrator.pendingStorageWork(
            on: handle,
            statements: ["ALTER TABLE sample ADD COLUMN added TEXT"]
        ).isEmpty)
    }

    @Test("Vendored Unix VFS exhaustion classification matches admission")
    func vendoredVFSExhaustionDriftGuard() throws {
        let header = try repositoryText("Sources/CSQLCipher/include/sqlite3.h")
        let amalgamation = try repositoryText("Sources/CSQLCipher/sqlite3.c")
        let admission = try repositoryText(
            "Sources/MacCrabCore/Storage/SQLitePersistentStoreAdmission.swift"
        )

        #expect(header.contains(
            "#define SQLITE_IOERR_ACCESS            (SQLITE_IOERR | (13<<8))"
        ))
        #expect(!header.contains("SQLITE_IOERR_NOSPC"),
                "the vendored SQLite API has no SQLITE_IOERR_NOSPC code")
        #expect(amalgamation.contains(
            "if( wrote<0 && pFile->lastErrno!=ENOSPC )"
        ))
        #expect(amalgamation.contains(
            "storeLastErrno(pFile, 0); /* not a system error */\n      return SQLITE_FULL;"
        ), "the Unix VFS is expected to map ENOSPC writes to primary SQLITE_FULL")
        #expect(admission.contains("primary == SQLITE_FULL"))
        #expect(admission.contains("details.systemErrno == ENOSPC"))
        #expect(admission.contains("details.systemErrno == EDQUOT"))
        #expect(!admission.contains("SQLITE_IOERR_NOSPC"))
    }

    @Test("Boot, recovery, maintenance, and live reload share exact policies")
    func daemonPolicyWiringDriftGuard() throws {
        let setup = try repositoryText("Sources/MacCrabAgentKit/DaemonSetup.swift")
        let timers = try repositoryText("Sources/MacCrabAgentKit/DaemonTimers.swift")
        let signals = try repositoryText("Sources/MacCrabAgentKit/SignalHandlers.swift")

        #expect(setup.contains(
            "maxSizeMiB: bootStorage.effectiveEventsFamilyMaxSizeMB"
        ))
        #expect(setup.contains("AlertStore.combinedFamilyCapBytes("))
        #expect(setup.contains(
            "maxSizeMiB: bootStorage.campaignsMaxSizeMB"
        ))
        #expect(occurrences(of: "eventStoragePolicy: eventStoragePolicy", in: setup) == 1)
        #expect(occurrences(of: "alertStoragePolicy: alertStoragePolicy", in: setup) == 1)
        #expect(occurrences(of: "storagePolicy: eventStoragePolicy", in: setup) == 2)
        #expect(occurrences(of: "storagePolicy: alertStoragePolicy", in: setup) == 2)
        #expect(occurrences(of: "storagePolicy: campaignStoragePolicy", in: setup) == 1)
        #expect(occurrences(of: "storagePolicy: storagePolicy", in: setup) == 4,
                "Event/Alert recovery probes and retry opens must retain the boot policy")

        #expect(!timers.contains("EventStore.vacuumOnDedicatedConnection("),
                "a detached VACUUM can race ingestion after its headroom probe")
        #expect(occurrences(of: "try await eventStore.vacuum()", in: timers) == 2,
                "both cap enforcers must serialize VACUUM on the writer actor")

        #expect(signals.contains(
            "state.eventStore.updateStorageAdmission("
        ))
        #expect(signals.contains(
            "state.alertStore.updateStorageAdmission("
        ))
        #expect(signals.contains(
            "campaignStore.updateStorageAdmission("
        ))
        #expect(signals.contains(
            "persistentPolicy(maxSizeMiB: newAlertsFamilyCap)"
        ))
        #expect(signals.contains(
            "persistentPolicy(maxSizeMiB: newStorage.campaignsMaxSizeMB)"
        ))
        #expect(signals.contains("maxSizeMiB: newEventsFamilyCap"),
                "event live reload lost the effective family cap")
        #expect(signals.contains(
            "freeSpaceFloorBytes: SQLitePersistentStorePolicy.freeSpaceFloorBytes"
        ))
        #expect(signals.contains("storageVolumePath: state.supportDir"))
        #expect(setup.contains(".eventTransactionReserveBytes"),
                "boot event policy lost the throughput-safe bounded reserve")
        #expect(signals.contains(".eventTransactionReserveBytes"),
                "SIGHUP event policy drifted from the boot reserve")
        #expect(!timers.contains("storagePolicy: SQLitePersistentStorePolicy("),
                "maintenance must use the policy already owned by EventStore")

        let eventStore = try repositoryText(
            "Sources/MacCrabCore/Storage/EventStore.swift"
        )
        #expect(eventStore.contains(".eventTransactionReserveBytes"),
                "direct EventStore opens drifted from daemon policy")
    }

    @Test("Every persistent writer retains the shared admission contract")
    func persistentWriterSurfaceDriftGuard() throws {
        let primaryStores = [
            "Sources/MacCrabCore/Storage/EventStore.swift",
            "Sources/MacCrabCore/Storage/AlertStore.swift",
            "Sources/MacCrabCore/Storage/CampaignStore.swift",
        ]
        for path in primaryStores {
            let source = try repositoryText(path)
            #expect(source.contains("storagePolicy ?? Self.defaultStoragePolicy"),
                    "\(path) lets a nil RW policy disable the shipping boundary")
            #expect(source.contains("let effectiveStoragePolicy = forceReadOnly\n            ? nil"),
                    "\(path) must reserve nil admission for explicit read-only opens")
            #expect(source.contains("latchOperationalPressure: existingDatabase"),
                    "\(path) must open an existing pressure-bound DB shed-only")
            #expect(source.contains("installPageLimit(on:"),
                    "\(path) lost its SQLite page ceiling")
            #expect(source.contains("private func admitStorageWrite("),
                    "\(path) has no normal pre-write admission")
            #expect(source.contains("private func admitStorageMaintenanceWrite("),
                    "\(path) has no bounded reclaim route")
            #expect(source.contains("estimatedTransactionBytes:"),
                    "\(path) stopped supplying explicit transaction estimates")
            #expect(source.contains("SchemaMigrator.pendingStorageWork("),
                    "\(path) baseline/migration repair lost schema work classification")
            #expect(source.contains("latchSQLitePressure(resultCode:"),
                    "\(path) no longer latches native disk exhaustion")
            #expect(source.contains("updateStorageAdmission("),
                    "\(path) cannot atomically adopt a live cap")
            #expect(source.contains("reopenAfterStorageRecovery()"),
                    "\(path) may recover admission without restoring skipped writer setup")
            #expect(source.contains("where error.isOperationalPressure"),
                    "\(path) must not turn structural/open failures into shed mode")
        }

        let overrides = try repositoryText(
            "Sources/MacCrabCore/Storage/AttributionOverrideStore.swift"
        )
        for required in [
            "latchOperationalPressure: existingDatabase",
            "installPageLimit(on:",
            "private func admitStorageWrite(",
            "estimatedTransactionBytes:",
            "SchemaMigrator.pendingStorageWork(",
            "latchSQLitePressure(resultCode:",
            "reopenAfterStorageRecovery()",
            "where error.isOperationalPressure",
        ] {
            #expect(overrides.contains(required),
                    "AttributionOverrideStore drifted from shared admission: \(required)")
        }

        let relocator = try repositoryText(
            "Sources/MacCrabCore/Storage/AlertsTableRelocator.swift"
        )
        #expect(relocator.contains("maintenance: true"))
        #expect(relocator.contains("installPageLimit(on: src, schema: \"new\")"))
        #expect(relocator.contains("alertAdmission.admitSchemaRebuild("))
        #expect(relocator.contains("minimumProjectedGrowthBytes:"))
        #expect(relocator.contains("copiedRowsAreEquivalent("),
                "OR IGNORE copy must be proven equivalent before source draining")
        #expect(relocator.contains("deleteLegacyAlertsInBoundedTransactions("))
        #expect(relocator.contains("eventAdmission.admitMaintenanceWrite("))

        let eventStore = try repositoryText(
            "Sources/MacCrabCore/Storage/EventStore.swift"
        )
        #expect(eventStore.contains(
            "vacuumOnDedicatedConnection(\n        at path: String,\n        storagePolicy suppliedPolicy: SQLitePersistentStorePolicy? = nil"
        ))
        #expect(eventStore.contains(
            "concurrent dedicated VACUUM is disabled; use EventStore.vacuum()"
        ))
        #expect(eventStore.contains("try admission.admitFullVacuum()"),
                "the actor-serialized VACUUM writer lost its whole-file gate")
        for path in primaryStores {
            let source = try repositoryText(path)
            #expect(source.contains("try admission.admitCheckpoint()"),
                    "\(path) lost its fresh sidecar-aware checkpoint gate")
        }
    }

    @Test("Cached insert statements are acquired only after reopening admission")
    func cachedInsertStatementOrderingDriftGuard() throws {
        func assertAcquireAfterAdmission(
            path: String,
            functionStart: String,
            functionEnd: String,
            admissionCall: String
        ) throws {
            let source = try repositoryText(path)
            let start = try #require(source.range(of: functionStart))
            let end = try #require(
                source.range(of: functionEnd, range: start.upperBound..<source.endIndex)
            )
            let body = String(source[start.lowerBound..<end.lowerBound])
            let admission = try #require(body.range(of: admissionCall))
            let acquireNeedle = "let stmt = insertStmt"
            let acquire = try #require(body.range(of: acquireNeedle))
            let reset = try #require(body.range(of: "sqlite3_reset(stmt)"))

            #expect(occurrences(of: acquireNeedle, in: body) == 1)
            #expect(admission.lowerBound < acquire.lowerBound)
            #expect(acquire.lowerBound < reset.lowerBound)
        }

        try assertAcquireAfterAdmission(
            path: "Sources/MacCrabCore/Storage/EventStore.swift",
            functionStart: "private func insert(\n        event: Event,",
            functionEnd: "static func estimatedEventMutationBytes(",
            admissionCall: "try beforeWrite(mutationBytes)"
        )
        try assertAcquireAfterAdmission(
            path: "Sources/MacCrabCore/Storage/AlertStore.swift",
            functionStart: "private func insert(\n        alert: Alert,",
            functionEnd: "static func estimatedAlertMutationBytes(",
            admissionCall: "try beforeWrite(rowBytes)"
        )
        try assertAcquireAfterAdmission(
            path: "Sources/MacCrabCore/Storage/CampaignStore.swift",
            functionStart: "public func insert(_ r: Record) throws {",
            functionEnd: "private func existingCampaignMutationBytes(",
            admissionCall: "try admitStorageWrite("
        )
        try assertAcquireAfterAdmission(
            path: "Sources/MacCrabCore/Storage/AttributionOverrideStore.swift",
            functionStart: "public func record(_ override: AttributionOverride) throws {",
            functionEnd: "private func existingOverrideMutationBytes(",
            admissionCall: "try admitStorageWrite("
        )
    }

    @Test("Every persistent SQLite checkpoint surface has the fresh sidecar gate")
    func checkpointSurfaceDriftGuard() throws {
        let primaryStores = [
            "Sources/MacCrabCore/Storage/EventStore.swift",
            "Sources/MacCrabCore/Storage/AlertStore.swift",
            "Sources/MacCrabCore/Storage/CampaignStore.swift",
        ]
        for path in primaryStores {
            let source = try repositoryText(path)
            #expect(source.contains("private func admitStorageCheckpoint()"))
            #expect(source.contains("try admission.admitCheckpoint()"))
            #expect(occurrences(of: "sqlite3_wal_checkpoint_v2", in: source) == 3,
                    "new checkpoint calls must route through the existing gated surfaces")
        }

        let pragmas = try repositoryText(
            "Sources/MacCrabCore/Storage/StoragePragmas.swift"
        )
        #expect(!pragmas.contains("sqlite3_wal_checkpoint_v2"),
                "path-agnostic helpers cannot prove floor-plus-sidecar headroom")

        let traces = try repositoryText(
            "Sources/MacCrabCore/Storage/TraceStore.swift"
        )
        #expect(traces.contains("private func admitCheckpointHeadroom()"))
        #expect(traces.contains("try admitCheckpointHeadroom()"))
        #expect(occurrences(of: "sqlite3_wal_checkpoint_v2", in: traces) == 1,
                "TraceStore checkpoints must stay centralized behind one fresh gate")
        #expect(!traces.contains("PRAGMA wal_checkpoint"))

        let graph = try repositoryText(
            "Sources/MacCrabCore/Storage/SQLiteCausalGraphStore.swift"
        )
        #expect(graph.contains("private func checkpointHeadroomAdmitted()"))
        #expect(graph.contains(
            "guard let db, checkpointHeadroomAdmitted() else"
        ))
        #expect(occurrences(of: "sqlite3_wal_checkpoint_v2", in: graph) == 1,
                "TraceGraph checkpoints must stay centralized behind one fresh gate")
        #expect(!graph.contains("PRAGMA wal_checkpoint"))

        let allSwift = try sourceSwiftFiles()
        for (path, source) in allSwift {
            #expect(!source.localizedCaseInsensitiveContains(
                "PRAGMA wal_autocheckpoint"
            ), "\(path) restored SQLite's ungated automatic checkpoint")
            #expect(!source.contains("sqlite3_wal_autocheckpoint"),
                    "\(path) bypasses controlled checkpoint ownership")
        }

        let hookOwners = Set(allSwift.compactMap { path, source in
            source.contains("sqlite3_wal_hook(") ? path : nil
        })
        #expect(hookOwners == [
            "MacCrabCore/Storage/SQLiteControlledCheckpoint.swift",
        ], "a second WAL hook can silently replace the checkpoint controller")

        let controller = try repositoryText(
            "Sources/MacCrabCore/Storage/SQLiteControlledCheckpoint.swift"
        )
        #expect(occurrences(
            of: "sqlite3_wal_checkpoint_v2",
            in: controller
        ) == 1)
        #expect(controller.contains("Int32(SQLITE_CHECKPOINT_PASSIVE)"))
        #expect(controller.contains("return SQLITE_OK"),
                "post-COMMIT maintenance must never false-fail a durable write")
        #expect(controller.contains("maximumRetryBackoffCommits: UInt32 = 64"))
        #expect(controller.contains("saturatingIncrement("))
        #expect(!controller.contains("&+="),
                "lifetime checkpoint counters must saturate, not wrap")
        #expect(!controller.contains("preexistingWalHook"),
                "SQLite cannot truthfully query an arbitrary prior WAL hook")

        let controlledWriters = [
            "MacCrabCore/Storage/EventStore.swift",
            "MacCrabCore/Storage/AlertStore.swift",
            "MacCrabCore/Storage/CampaignStore.swift",
            "MacCrabCore/Storage/AttributionOverrideStore.swift",
            "MacCrabCore/Storage/TraceStore.swift",
            "MacCrabCore/Storage/SQLiteCausalGraphStore.swift",
            "MacCrabForensics/Storage/ArtifactStore.swift",
        ]
        for path in controlledWriters {
            let source = try #require(allSwift[path])
            #expect(source.contains("try .install("),
                    "\(path) lost controlled ownership on its RW handle")
            #expect(source.contains(".detach(from:"),
                    "\(path) can close while its unretained WAL hook is live")
        }

        let shim = try repositoryText(
            "Sources/CSQLCipher/MacCrabSQLiteControl.c"
        )
        #expect(occurrences(of: "sqlite3_wal_autocheckpoint(db, 0)", in: shim) == 1)
        #expect(occurrences(
            of: "SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE",
            in: shim
        ) == 2)
        let shimHeader = try repositoryText(
            "Sources/CSQLCipher/include/MacCrabSQLiteControl.h"
        )
        #expect(shimHeader.contains("maccrab_sqlite_take_checkpoint_ownership"))
        #expect(shimHeader.contains("maccrab_sqlite_no_checkpoint_on_close"))
        let moduleMap = try repositoryText(
            "Sources/CSQLCipher/include/module.modulemap"
        )
        #expect(moduleMap.contains("header \"MacCrabSQLiteControl.h\""))
        let package = try repositoryText("Package.swift")
        #expect(package.contains(
            "sources: [\"sqlite3.c\", \"MacCrabSQLiteControl.c\"]"
        ))

        let artifact = try #require(
            allSwift["MacCrabForensics/Storage/ArtifactStore.swift"]
        )
        let artifactInstall = try #require(artifact.range(
            of: "checkpointController = try .install("
        ))
        let artifactKey = try #require(artifact.range(
            of: "try applyDEK(handle: h, dek: dek)"
        ))
        #expect(artifactInstall.lowerBound < artifactKey.lowerBound,
                "ArtifactStore must suppress hidden checkpoints before key/schema IO")

        let relocator = try repositoryText(
            "Sources/MacCrabCore/Storage/AlertsTableRelocator.swift"
        )
        #expect(relocator.contains("checkpointController = try .install("))
        #expect(relocator.contains("checkpointController.detach(from: src)"))
        #expect(relocator.contains("schema: \"new\""))
        #expect(relocator.contains("databasePath: alertsDB"))
        let relocatorInstall = try #require(relocator.range(
            of: "checkpointController = try .install("
        ))
        let relocatorPragma = try #require(relocator.range(
            of: "PRAGMA busy_timeout = 5000"
        ))
        #expect(relocatorInstall.lowerBound < relocatorPragma.lowerBound,
                "relocator source ownership must precede all connection IO")
    }

    @Test("Pressure is sticky until authoritative probes demonstrate recovery")
    func stickyRecovery() throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("store.db").path
        let footprint = Int64Box(10)
        let free = Int64Box(1_000)
        var admission = try SQLitePersistentStoreAdmission(
            databasePath: path,
            policy: policy(directory: dir, max: 100, floor: 100, reserve: 10),
            footprintProbe: { _ in footprint.get() },
            freeSpaceProbe: { _ in free.get() }
        )

        footprint.set(91)
        #expect(throws: SQLitePersistentStoreAdmissionError.self) {
            try admission.admitWrite(estimatedTransactionBytes: 0)
        }
        #expect(admission.snapshot().latchedFailure != nil)

        footprint.set(10)
        free.set(1_000)
        try admission.admitWrite(estimatedTransactionBytes: 0)
        #expect(admission.snapshot().latchedFailure == nil)

        for details in [
            SQLiteFailureDetails(
                resultCode: SQLITE_FULL,
                extendedResultCode: SQLITE_FULL,
                systemErrno: 0
            ),
            SQLiteFailureDetails(
                resultCode: SQLITE_IOERR,
                extendedResultCode: SQLITE_IOERR,
                systemErrno: ENOSPC
            ),
            SQLiteFailureDetails(
                resultCode: SQLITE_IOERR,
                extendedResultCode: SQLITE_IOERR,
                systemErrno: EDQUOT
            ),
        ] {
            #expect(admission.latchSQLitePressure(details: details) != nil)
            #expect(admission.snapshot().latchedFailure != nil)
            try admission.admitWrite(estimatedTransactionBytes: 0)
            #expect(admission.snapshot().latchedFailure == nil)
        }
    }

    @Test("Every direct read-write store gets safe defaults; read-only stays observational")
    func defaultReadWriteAdmission() async throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let eventPath = dir.appendingPathComponent("events.db").path
        let alertPath = dir.appendingPathComponent("alerts.db").path
        let campaignPath = dir.appendingPathComponent("campaigns.db").path

        var events: EventStore? = try EventStore(path: eventPath)
        var alerts: AlertStore? = try AlertStore(path: alertPath)
        var campaigns: CampaignStore? = try CampaignStore(path: campaignPath)
        let eventSnapshot = try #require(await events?.storageAdmissionSnapshot())
        let alertSnapshot = try #require(await alerts?.storageAdmissionSnapshot())
        let campaignSnapshot = try #require(await campaigns?.storageAdmissionSnapshot())
        #expect(eventSnapshot.maxFootprintBytes
            == Int64(320) * SQLitePersistentStorePolicy.bytesPerMiB)
        #expect(alertSnapshot.maxFootprintBytes
            == Int64(200) * SQLitePersistentStorePolicy.bytesPerMiB)
        #expect(campaignSnapshot.maxFootprintBytes
            == Int64(50) * SQLitePersistentStorePolicy.bytesPerMiB)
        #expect(eventSnapshot.freeSpaceFloorBytes
            == SQLitePersistentStorePolicy.freeSpaceFloorBytes)
        #expect(alertSnapshot.freeSpaceFloorBytes
            == SQLitePersistentStorePolicy.freeSpaceFloorBytes)
        #expect(campaignSnapshot.freeSpaceFloorBytes
            == SQLitePersistentStorePolicy.freeSpaceFloorBytes)
        events = nil
        alerts = nil
        campaigns = nil

        let readOnly = try EventStore(path: eventPath, forceReadOnly: true)
        #expect(await readOnly.storageAdmissionSnapshot() == nil)
    }

    @Test("A lowered live cap latches, then retries its page ceiling after recovery")
    func livePolicyRecovery() throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("store.db").path
        let footprint = Int64Box(10)
        let free = Int64Box(100_000)
        var admission = try SQLitePersistentStoreAdmission(
            databasePath: path,
            policy: policy(directory: dir, max: 1_048_576, reserve: 65_536),
            footprintProbe: { _ in footprint.get() },
            freeSpaceProbe: { _ in free.get() }
        )
        var db: OpaquePointer?
        #expect(sqlite3_open_v2(
            path,
            &db,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
            nil
        ) == SQLITE_OK)
        let handle = try #require(db)
        defer { sqlite3_close(handle) }
        try admission.installPageLimit(on: handle)

        footprint.set(91)
        let lowered = policy(directory: dir, max: 100, floor: 10, reserve: 10)
        let blocked = try admission.updatePolicy(lowered, on: handle)
        #expect(blocked.latchedFailure != nil)
        #expect(blocked.pageLimitPending)
        #expect(admission.policy == lowered)

        // Maintenance gets a smaller reserve-only gate and deliberately does
        // not clear the growth latch.
        free.set(9)
        #expect(throws: SQLitePersistentStoreAdmissionError.self) {
            try admission.admitMaintenanceWrite(estimatedTransactionBytes: 0)
        }
        free.set(10)
        try admission.admitMaintenanceWrite(estimatedTransactionBytes: 0)
        #expect(admission.snapshot().latchedFailure != nil)

        footprint.set(10)
        free.set(1_000)
        try admission.admitWrite(estimatedTransactionBytes: 0, on: handle)
        let recovered = admission.snapshot()
        #expect(recovered.latchedFailure == nil)
        #expect(!recovered.pageLimitPending)
    }

    @Test("max_page_count is installed and verified on the writer connection")
    func pageCeiling() throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("store.db").path
        let configured = policy(
            directory: dir,
            max: 1_048_576,
            reserve: 65_536
        )
        var admission = try SQLitePersistentStoreAdmission(
            databasePath: path,
            policy: configured
        )
        var db: OpaquePointer?
        #expect(sqlite3_open_v2(
            path,
            &db,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
            nil
        ) == SQLITE_OK)
        let handle = try #require(db)
        defer { sqlite3_close(handle) }
        try admission.installPageLimit(on: handle)

        func pragma(_ name: String) throws -> Int64 {
            var statement: OpaquePointer?
            defer { sqlite3_finalize(statement) }
            #expect(sqlite3_prepare_v2(
                handle,
                "PRAGMA \(name)",
                -1,
                &statement,
                nil
            ) == SQLITE_OK)
            let statementHandle = try #require(statement)
            #expect(sqlite3_step(statementHandle) == SQLITE_ROW)
            return sqlite3_column_int64(statementHandle, 0)
        }

        let pageSize = try pragma("page_size")
        let maximumPages = try pragma("max_page_count")
        #expect(maximumPages <= (configured.maxFootprintBytes
            - configured.transactionReserveBytes) / pageSize)
    }

    @Test("Existing over-cap stores open shed-only; maintenance and live recovery remain available")
    func storeShedModeAndLiveReload() async throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let eventPath = dir.appendingPathComponent("events.db").path
        let alertPath = dir.appendingPathComponent("alerts.db").path
        let campaignPath = dir.appendingPathComponent("campaigns.db").path
        let overridePath = dir.appendingPathComponent("attribution_overrides.db").path

        var eventBootstrap: EventStore? = try EventStore(path: eventPath)
        var alertBootstrap: AlertStore? = try AlertStore(path: alertPath)
        var campaignBootstrap: CampaignStore? = try CampaignStore(path: campaignPath)
        var overrideBootstrap: AttributionOverrideStore? = try AttributionOverrideStore(
            path: overridePath,
            storagePolicy: policy(
                directory: dir,
                max: 8 * 1_048_576,
                reserve: SQLitePersistentStorePolicy.bytesPerMiB
            )
        )
        eventBootstrap = nil
        alertBootstrap = nil
        campaignBootstrap = nil
        overrideBootstrap = nil

        func loweredPolicy(_ path: String) throws -> SQLitePersistentStorePolicy {
            let reserve = SQLitePersistentStorePolicy.bytesPerMiB
            let footprint = try SQLitePersistentStoreAdmission.measureFamily(path)
            return policy(
                directory: dir,
                max: max(reserve + 1, footprint + reserve - 1),
                reserve: reserve
            )
        }
        func raisedPolicy(_ path: String) throws -> SQLitePersistentStorePolicy {
            let reserve = SQLitePersistentStorePolicy.bytesPerMiB
            let footprint = try SQLitePersistentStoreAdmission.measureFamily(path)
            return policy(
                directory: dir,
                max: footprint + reserve + 1_048_576,
                reserve: reserve
            )
        }

        let events = try EventStore(
            path: eventPath,
            storagePolicy: try loweredPolicy(eventPath)
        )
        let alerts = try AlertStore(
            path: alertPath,
            storagePolicy: try loweredPolicy(alertPath)
        )
        let campaigns = try CampaignStore(
            path: campaignPath,
            storagePolicy: try loweredPolicy(campaignPath)
        )
        let overrides = try AttributionOverrideStore(
            path: overridePath,
            storagePolicy: try loweredPolicy(overridePath)
        )

        #expect((await events.storageAdmissionSnapshot())?.latchedFailure != nil)
        #expect((await alerts.storageAdmissionSnapshot())?.latchedFailure != nil)
        #expect((await campaigns.storageAdmissionSnapshot())?.latchedFailure != nil)
        #expect((await overrides.storageAdmissionSnapshot())?.latchedFailure != nil)

        await #expect(throws: SQLitePersistentStoreAdmissionError.self) {
            try await events.insert(event: event())
        }
        await #expect(throws: SQLitePersistentStoreAdmissionError.self) {
            try await alerts.insert(alert: alert())
        }
        await #expect(throws: SQLitePersistentStoreAdmissionError.self) {
            try await campaigns.insert(campaign())
        }
        await #expect(throws: SQLitePersistentStoreAdmissionError.self) {
            try await overrides.record(AttributionOverride(
                eventId: UUID().uuidString,
                machineConfidence: "test",
                verdict: .confirmed
            ))
        }

        // Shed-mode maintenance is available even though normal growth is not.
        #expect(try await events.pruneOldest(count: 1) == 0)
        #expect(try await alerts.pruneOldest(count: 1) == 0)
        #expect(try await campaigns.pruneOldest(count: 1) == 0)

        let eventRaised = try await events.updateStorageAdmission(
            raisedPolicy(eventPath)
        )
        let alertRaised = try await alerts.updateStorageAdmission(
            raisedPolicy(alertPath)
        )
        let campaignRaised = try await campaigns.updateStorageAdmission(
            raisedPolicy(campaignPath)
        )
        #expect(eventRaised?.latchedFailure == nil)
        #expect(alertRaised?.latchedFailure == nil)
        #expect(campaignRaised?.latchedFailure == nil)

        try await events.insert(event: event())
        try await alerts.insert(alert: alert())
        try await campaigns.insert(campaign())
    }

    @Test("Fresh schema creation fails before touching disk under the free-space floor")
    func freshLowFloorDoesNotCreate() throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("fresh.db").path
        let impossible = policy(
            directory: dir,
            max: 16 * 1_048_576,
            floor: Int64.max,
            reserve: 4_096
        )
        #expect(throws: SQLitePersistentStoreAdmissionError.self) {
            _ = try EventStore(path: path, storagePolicy: impossible)
        }
        #expect(!FileManager.default.fileExists(atPath: path))
    }

    @Test("An existing low-free-space store opens shed-only and can recover live")
    func existingLowFloorShedMode() async throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("events.db").path
        var bootstrap: EventStore? = try EventStore(path: path)
        bootstrap = nil

        let reserve = SQLitePersistentStorePolicy.bytesPerMiB
        let lowFloor = policy(
            directory: dir,
            max: 16 * 1_048_576,
            floor: Int64.max,
            reserve: reserve
        )
        let store = try EventStore(path: path, storagePolicy: lowFloor)
        #expect((await store.storageAdmissionSnapshot())?.latchedFailure != nil)
        await #expect(throws: SQLitePersistentStoreAdmissionError.self) {
            try await store.insert(event: event())
        }
        #expect(try await store.pruneOldest(count: 1) == 0)

        let recovered = try await store.updateStorageAdmission(policy(
            directory: dir,
            max: 16 * 1_048_576,
            floor: 0,
            reserve: reserve
        ))
        #expect(recovered?.latchedFailure == nil)
        try await store.insert(event: event())
    }

    @Test("Event batches survive repeated pressure-recovery connection reopens")
    func eventBatchReacquiresStatementAfterRecovery() async throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("events.db").path
        // EventStore's page-aware transaction estimate intentionally includes
        // fixed commit/WAL headroom; keep the reserve above that estimate while
        // the independently-derived footprint ceiling supplies the pressure.
        // Use page-size-independent headroom: at SQLite's supported 64 KiB
        // maximum, the event row plus fixed tree/WAL estimate is about 5 MiB.
        let reserve = 16 * SQLitePersistentStorePolicy.bytesPerMiB
        let store = try EventStore(
            path: path,
            storagePolicy: policy(
                directory: dir,
                max: 128 * SQLitePersistentStorePolicy.bytesPerMiB,
                reserve: reserve
            )
        )

        // RC.4 crashed at sqlite3_reset on the first batch after the 60-second
        // size-cap sweep. Repeat the exact state transition enough times to make
        // a one-shot/lifetime accident visible under sanitizers as well.
        for cycle in 0..<8 {
            if try await store.count() == 0 {
                let seed = try await store.insert(events: (0..<8).map { _ in event() })
                #expect(seed.persistedCount == 8)
            }

            let tight = try pressureLatchPolicy(
                directory: dir,
                databasePath: path,
                reserveBytes: reserve
            )
            let blocked = try await store.updateStorageAdmission(tight)
            #expect(blocked?.latchedFailure != nil, "cycle \(cycle) did not latch")

            let rows = try await store.count()
            #expect(try await store.pruneOldest(count: rows) == rows)
            try await store.vacuum()
            let compacted = try SQLitePersistentStoreAdmission.measureFamily(path)
            #expect(compacted + reserve <= tight.maxFootprintBytes)

            let batch = (0..<16).map { _ in event() }
            let recovered = try await store.insert(events: batch)
            #expect(recovered.persistedCount == batch.count)
            #expect(recovered.filteredCount == 0)
            #expect((await store.storageAdmissionSnapshot())?.latchedFailure == nil)
            #expect(try await store.count() == batch.count)
        }
    }

    @Test("Alert and Campaign writers reacquire cached statements after recovery")
    func alertAndCampaignReacquireStatementsAfterRecovery() async throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let alertPath = dir.appendingPathComponent("alerts.db").path
        let campaignPath = dir.appendingPathComponent("campaigns.db").path
        // One alert transaction's current conservative estimate is slightly
        // above 2 MiB. This test exercises statement reacquisition, not reserve
        // rejection, so provision a valid bounded transaction reserve.
        let reserve = 4 * SQLitePersistentStorePolicy.bytesPerMiB
        let roomy = policy(
            directory: dir,
            max: 128 * SQLitePersistentStorePolicy.bytesPerMiB,
            reserve: reserve
        )
        let alerts = try AlertStore(path: alertPath, storagePolicy: roomy)
        let campaigns = try CampaignStore(path: campaignPath, storagePolicy: roomy)

        for cycle in 0..<4 {
            if try await alerts.count() == 0 {
                try await alerts.insert(alerts: (0..<8).map { _ in alert() })
            }
            if try await campaigns.count() == 0 {
                for _ in 0..<8 { try await campaigns.insert(campaign()) }
            }

            let alertPolicy = try pressureLatchPolicy(
                directory: dir,
                databasePath: alertPath,
                reserveBytes: reserve
            )
            let campaignPolicy = try pressureLatchPolicy(
                directory: dir,
                databasePath: campaignPath,
                reserveBytes: reserve
            )
            #expect(
                (try await alerts.updateStorageAdmission(alertPolicy))?
                    .latchedFailure != nil,
                "alert cycle \(cycle) did not latch"
            )
            #expect(
                (try await campaigns.updateStorageAdmission(campaignPolicy))?
                    .latchedFailure != nil,
                "campaign cycle \(cycle) did not latch"
            )

            let alertRows = try await alerts.count()
            let campaignRows = try await campaigns.count()
            #expect(try await alerts.pruneOldest(count: alertRows) == alertRows)
            #expect(
                try await campaigns.pruneOldest(count: campaignRows)
                    == campaignRows
            )
            try await alerts.vacuum()
            try await campaigns.vacuum()
            #expect(
                try SQLitePersistentStoreAdmission.measureFamily(alertPath)
                    + reserve <= alertPolicy.maxFootprintBytes
            )
            #expect(
                try SQLitePersistentStoreAdmission.measureFamily(campaignPath)
                    + reserve <= campaignPolicy.maxFootprintBytes
            )

            // One post-recovery write is sufficient to exercise the stale
            // statement edge. Keeping the recovered store below its deliberately
            // tight ceiling lets the transition repeat on the next cycle.
            let newAlerts = [alert()]
            try await alerts.insert(alerts: newAlerts)
            try await campaigns.insert(campaign())
            #expect((await alerts.storageAdmissionSnapshot())?.latchedFailure == nil)
            #expect((await campaigns.storageAdmissionSnapshot())?.latchedFailure == nil)
            #expect(try await alerts.count() == newAlerts.count)
            #expect(try await campaigns.count() == 1)
        }
    }

    @Test("Attribution override writer restores its skipped statement after recovery")
    func attributionOverrideReacquiresStatementAfterRecovery() async throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("attribution_overrides.db").path
        let reserve = 4 * SQLitePersistentStorePolicy.bytesPerMiB
        let roomy = policy(
            directory: dir,
            max: 128 * SQLitePersistentStorePolicy.bytesPerMiB,
            reserve: reserve
        )

        // Grow a real store, close its writer, then reopen it one byte beyond
        // the configured footprint boundary. That open deliberately skips
        // preparing insertStmt while retaining a maintenance-capable handle.
        var bootstrap: AttributionOverrideStore? = try AttributionOverrideStore(
            path: path,
            storagePolicy: roomy
        )
        let note = String(repeating: "x", count: 64 * 1_024)
        for index in 0..<32 {
            try await bootstrap?.record(AttributionOverride(
                eventId: "recovery-seed-\(index)",
                machineConfidence: "test",
                verdict: .confirmed,
                userNote: note
            ))
        }
        #expect(try await bootstrap?.count() == 32)
        bootstrap = nil

        let tight = try pressureLatchPolicy(
            directory: dir,
            databasePath: path,
            reserveBytes: reserve
        )
        let store = try AttributionOverrideStore(
            path: path,
            storagePolicy: tight
        )
        #expect((await store.storageAdmissionSnapshot())?.latchedFailure != nil)

        // AttributionOverrideStore has no public retention surface. Use a
        // sibling SQLite connection only in this fixture to model an operator
        // reclaiming the tiny database while the shed-only reader remains open.
        // The following successful record is itself a direct reopen assertion:
        // the store began with insertStmt == nil, so it cannot write unless
        // admitStorageWrite reopens and prepares a new statement first.
        do {
            var maintenanceDB: OpaquePointer?
            let openRC = SQLiteOpenPathPolicy.open(
                path,
                database: &maintenanceDB,
                flags: SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX
            )
            #expect(openRC == SQLITE_OK)
            let handle = try #require(maintenanceDB)
            defer { sqlite3_close(handle) }
            sqlite3_busy_timeout(handle, 5_000)
            for sql in [
                "DELETE FROM attribution_overrides",
                "PRAGMA wal_checkpoint(TRUNCATE)",
                "VACUUM",
                "PRAGMA wal_checkpoint(TRUNCATE)",
            ] {
                let rc = sqlite3_exec(handle, sql, nil, nil, nil)
                try #require(rc == SQLITE_OK)
            }
        }

        let compacted = try SQLitePersistentStoreAdmission.measureFamily(path)
        #expect(compacted + reserve <= tight.maxFootprintBytes)
        let recoveredID = "post-recovery"
        try await store.record(AttributionOverride(
            eventId: recoveredID,
            machineConfidence: "test",
            verdict: .confirmed
        ))
        #expect((await store.storageAdmissionSnapshot())?.latchedFailure == nil)
        #expect(try await store.count() == 1)
        #expect(try await store.fetch(eventId: recoveredID)?.verdict == .confirmed)
    }

    @Test("REPLACE admission charges the authoritative old Alert and Campaign rows")
    func replacementChargesOldRows() async throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let alertPath = dir.appendingPathComponent("alerts.db").path
        let campaignPath = dir.appendingPathComponent("campaigns.db").path
        let roomy = policy(
            directory: dir,
            max: 64 * 1_048_576,
            floor: 0,
            reserve: 16 * 1_048_576
        )
        let constrained = policy(
            directory: dir,
            max: 64 * 1_048_576,
            floor: 0,
            reserve: 1_048_576
        )
        let large = String(repeating: "x", count: 2 * 1_048_576)

        let alertID = "replace-large-alert"
        var alertBootstrap: AlertStore? = try AlertStore(
            path: alertPath,
            storagePolicy: roomy
        )
        try await alertBootstrap?.insert(alert: Alert(
            id: alertID,
            ruleId: "old.rule",
            ruleTitle: "large old alert",
            severity: .high,
            eventId: "event-old",
            description: large
        ))
        alertBootstrap = nil

        let alerts = try AlertStore(
            path: alertPath,
            storagePolicy: constrained
        )
        await #expect(throws: SQLitePersistentStoreAdmissionError.self) {
            try await alerts.insert(alert: Alert(
                id: alertID,
                ruleId: "new.rule",
                ruleTitle: "small replacement",
                severity: .low,
                eventId: "event-new"
            ))
        }
        let retainedAlert = try #require(await alerts.alert(id: alertID))
        #expect(retainedAlert.ruleId == "old.rule")
        #expect(retainedAlert.description?.utf8.count == large.utf8.count)

        let campaignID = "replace-large-campaign"
        var campaignBootstrap: CampaignStore? = try CampaignStore(
            path: campaignPath,
            storagePolicy: roomy
        )
        try await campaignBootstrap?.insert(CampaignStore.Record(
            id: campaignID,
            type: "old",
            severity: .high,
            title: "large old campaign",
            description: large,
            tactics: ["TA0001"],
            timeSpanSeconds: 1,
            detectedAt: Date()
        ))
        campaignBootstrap = nil

        let campaigns = try CampaignStore(
            path: campaignPath,
            storagePolicy: constrained
        )
        await #expect(throws: SQLitePersistentStoreAdmissionError.self) {
            try await campaigns.insert(CampaignStore.Record(
                id: campaignID,
                type: "new",
                severity: .low,
                title: "small replacement",
                description: "small",
                tactics: [],
                timeSpanSeconds: 1,
                detectedAt: Date()
            ))
        }
        let retainedCampaign = try #require(
            await campaigns.get(id: campaignID)
        )
        #expect(retainedCampaign.type == "old")
        #expect(retainedCampaign.description.utf8.count == large.utf8.count)
    }

    @Test("Alert evidence sizes every projected source field before INSERT SELECT")
    func alertEvidenceChargesLargeLegacyProjection() async throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("events.db").path
        let roomy = policy(
            directory: dir,
            max: 64 * 1_048_576,
            floor: 0,
            reserve: 16 * 1_048_576
        )
        let constrained = policy(
            directory: dir,
            max: 64 * 1_048_576,
            floor: 0,
            reserve: 1_048_576
        )
        let timestamp = Date(timeIntervalSince1970: 1_700_123_456)
        let base = event()
        let oversizedAction = String(
            repeating: "a",
            count: 2 * 1_048_576
        )
        let legacy = Event(
            id: base.id,
            timestamp: timestamp,
            eventCategory: base.eventCategory,
            eventType: base.eventType,
            eventAction: oversizedAction,
            process: base.process
        )

        var bootstrap: EventStore? = try EventStore(
            path: path,
            storagePolicy: roomy
        )
        try await bootstrap?.insert(event: legacy)
        bootstrap = nil

        let store = try EventStore(
            path: path,
            storagePolicy: constrained
        )
        await #expect(throws: SQLitePersistentStoreAdmissionError.self) {
            try await store.recordAlertEvidence(
                alertId: "oversized-evidence",
                alertTimestamp: timestamp,
                windowSeconds: 1
            )
        }
        #expect(try await store.evidenceFor(alertId: "oversized-evidence").isEmpty)
    }

    @Test("Representative 1000-event batch remains transaction-amortized")
    func representativeBatchTransactionCount() async throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("events.db").path
        let store = try EventStore(
            path: path,
            storagePolicy: policy(
                directory: dir,
                max: 128 * 1_048_576,
                floor: 0,
                reserve: SQLitePersistentStorePolicy
                    .eventTransactionReserveBytes
            )
        )
        let events = (0..<1_000).map { index in
            Event(
                timestamp: Date(timeIntervalSince1970: 1_700_000_000 + Double(index)),
                eventCategory: .process,
                eventType: .start,
                eventAction: "exec",
                process: ProcessInfo(
                    pid: Int32(index + 100),
                    ppid: 1,
                    rpid: 1,
                    name: "representative-tool",
                    executable: "/usr/bin/representative-tool",
                    commandLine: "/usr/bin/representative-tool --scan",
                    args: ["/usr/bin/representative-tool", "--scan"],
                    workingDirectory: "/tmp",
                    userId: 501,
                    userName: "tester",
                    groupId: 20,
                    startTime: Date(timeIntervalSince1970: 1_700_000_000),
                    ancestors: [],
                    isPlatformBinary: false
                )
            )
        }

        let before = await store.batchInsertTransactionCount()
        let result = try await store.insert(events: events)
        let after = await store.batchInsertTransactionCount()
        #expect(result.persistedCount == 1_000)
        #expect(result.filteredCount == 0)
        #expect(result.committedTransactionCount == Int(after - before))
        #expect(result.committedTransactionCount > 1,
                "the reserve guard must actually split a large batch")
        #expect(result.committedTransactionCount <= 4,
                "ordinary rows regressed toward per-event commits")
        #expect(try await store.count() == 1_000)
    }

    @Test("One event larger than the reserve is refused before SQLite and keeps typed cause")
    func oversizedEventRefusalRetainsCause() async throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = try EventStore(
            path: dir.appendingPathComponent("events.db").path,
            storagePolicy: policy(
                directory: dir,
                max: 64 * 1_048_576,
                floor: 0,
                reserve: SQLitePersistentStorePolicy
                    .eventTransactionReserveBytes
            )
        )
        let oversized = Event(
            timestamp: Date(timeIntervalSince1970: 1_700_000_000),
            eventCategory: .process,
            eventType: .start,
            eventAction: String(repeating: "x", count: 9 * 1_048_576),
            process: event().process
        )

        do {
            _ = try await store.insert(events: [oversized])
            Issue.record("oversized event unexpectedly passed transaction admission")
        } catch let failure as EventBatchInsertFailure {
            #expect(failure.progress.persistedCount == 0)
            #expect(failure.uncommittedEvents.map(\.id) == [oversized.id])
            let cause = try #require(
                failure.underlyingError as? SQLitePersistentStoreAdmissionError
            )
            guard case .transactionEstimateExceedsReserve(
                let estimated,
                let reserve
            ) = cause else {
                Issue.record("unexpected admission cause: \(cause)")
                return
            }
            #expect(estimated > reserve)
            #expect(failure.sqliteFailureDetails == nil)
        }
        #expect(try await store.count() == 0)

        let details = SQLiteFailureDetails(
            resultCode: SQLITE_BUSY,
            extendedResultCode: SQLITE_BUSY,
            systemErrno: 0
        )
        let wrappedSQLite = EventBatchInsertFailure(
            progress: EventBatchInsertResult(
                inputCount: 1,
                persistedCount: 0,
                filteredCount: 0,
                committedTransactionCount: 0
            ),
            uncommittedEvents: [oversized],
            underlyingError: EventStoreError.busy("injected", failure: details)
        )
        #expect(SQLiteFailureClassifier.details(from: wrappedSQLite) == details)
    }

    @Test("Latest EventStore reopen repairs baseline, post-migration, and trigger objects")
    func latestVersionSchemaRepair() async throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("events.db").path
        let configured = policy(
            directory: dir,
            max: 64 * 1_048_576,
            floor: 0,
            reserve: SQLitePersistentStorePolicy
                .eventTransactionReserveBytes
        )
        var bootstrap: EventStore? = try EventStore(
            path: path,
            storagePolicy: configured
        )
        _ = try await bootstrap?.insert(events: [event()])
        bootstrap = nil

        var raw: OpaquePointer?
        #expect(SQLiteOpenPathPolicy.open(
            path,
            database: &raw,
            flags: SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX
        ) == SQLITE_OK)
        let handle = try #require(raw)
        #expect(sqlite3_exec(
            handle,
            "DROP INDEX idx_events_timestamp; "
                + "DROP INDEX idx_events_ai_session; "
                + "DROP TRIGGER events_ai;",
            nil,
            nil,
            nil
        ) == SQLITE_OK)
        sqlite3_close(handle)

        var reopened: EventStore? = try EventStore(
            path: path,
            storagePolicy: configured
        )
        reopened = nil

        var verify: OpaquePointer?
        #expect(SQLiteOpenPathPolicy.open(
            path,
            database: &verify,
            flags: SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX
        ) == SQLITE_OK)
        let verifyHandle = try #require(verify)
        defer { sqlite3_close(verifyHandle) }
        var stmt: OpaquePointer?
        #expect(sqlite3_prepare_v2(
            verifyHandle,
            "SELECT type, name FROM sqlite_master WHERE name IN "
                + "('idx_events_timestamp', 'idx_events_ai_session', 'events_ai') "
                + "ORDER BY name",
            -1,
            &stmt,
            nil
        ) == SQLITE_OK)
        let schemaStmt = try #require(stmt)
        defer { sqlite3_finalize(schemaStmt) }
        var repaired: [String: String] = [:]
        while sqlite3_step(schemaStmt) == SQLITE_ROW {
            repaired[String(cString: sqlite3_column_text(schemaStmt, 1))]
                = String(cString: sqlite3_column_text(schemaStmt, 0))
        }
        #expect(repaired == [
            "events_ai": "trigger",
            "idx_events_ai_session": "index",
            "idx_events_timestamp": "index",
        ])
    }

    @Test("Latest Alert and Campaign reopen repairs baseline and migration indexes")
    func lowVolumeLatestVersionSchemaRepair() async throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let alertPath = dir.appendingPathComponent("alerts.db").path
        let campaignPath = dir.appendingPathComponent("campaigns.db").path
        let configured = policy(
            directory: dir,
            max: 64 * 1_048_576,
            floor: 0,
            reserve: 8 * 1_048_576
        )

        var alerts: AlertStore? = try AlertStore(
            path: alertPath,
            storagePolicy: configured
        )
        try await alerts?.insert(alert: alert())
        alerts = nil
        var campaigns: CampaignStore? = try CampaignStore(
            path: campaignPath,
            storagePolicy: configured
        )
        try await campaigns?.insert(campaign())
        campaigns = nil

        func mutateSchema(path: String, sql: String) throws {
            var raw: OpaquePointer?
            #expect(SQLiteOpenPathPolicy.open(
                path,
                database: &raw,
                flags: SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX
            ) == SQLITE_OK)
            let handle = try #require(raw)
            defer { sqlite3_close(handle) }
            #expect(sqlite3_exec(handle, sql, nil, nil, nil) == SQLITE_OK)
        }
        try mutateSchema(
            path: alertPath,
            sql: "DROP INDEX idx_alerts_timestamp; DROP INDEX idx_alerts_user_id;"
        )
        try mutateSchema(
            path: campaignPath,
            sql: "DROP INDEX idx_campaigns_detected_at; DROP INDEX idx_campaigns_first_seen;"
        )

        var reopenedAlerts: AlertStore? = try AlertStore(
            path: alertPath,
            storagePolicy: configured
        )
        reopenedAlerts = nil
        var reopenedCampaigns: CampaignStore? = try CampaignStore(
            path: campaignPath,
            storagePolicy: configured
        )
        reopenedCampaigns = nil

        func indexNames(path: String) throws -> Set<String> {
            var raw: OpaquePointer?
            #expect(SQLiteOpenPathPolicy.open(
                path,
                database: &raw,
                flags: SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX
            ) == SQLITE_OK)
            let handle = try #require(raw)
            defer { sqlite3_close(handle) }
            var statement: OpaquePointer?
            #expect(sqlite3_prepare_v2(
                handle,
                "SELECT name FROM sqlite_master WHERE type = 'index'",
                -1,
                &statement,
                nil
            ) == SQLITE_OK)
            let statementHandle = try #require(statement)
            defer { sqlite3_finalize(statementHandle) }
            var names: Set<String> = []
            while sqlite3_step(statementHandle) == SQLITE_ROW {
                names.insert(String(cString: sqlite3_column_text(statementHandle, 0)))
            }
            return names
        }
        let alertIndexes = try indexNames(path: alertPath)
        #expect(alertIndexes.contains("idx_alerts_timestamp"))
        #expect(alertIndexes.contains("idx_alerts_user_id"))
        let campaignIndexes = try indexNames(path: campaignPath)
        #expect(campaignIndexes.contains("idx_campaigns_detected_at"))
        #expect(campaignIndexes.contains("idx_campaigns_first_seen"))
    }

    @Test("Batched writer is the sole production batch caller and consumes exact partial progress")
    func eventBatchCallerCensus() throws {
        let files = try sourceSwiftFiles()
        let callers = Set(files.compactMap { path, source in
            source.contains(".insert(events:") ? path : nil
        })
        #expect(callers == ["MacCrabAgentKit/BatchedEventWriter.swift"])
        let writer = try #require(files["MacCrabAgentKit/BatchedEventWriter.swift"])
        #expect(writer.contains("catch let partial as EventBatchInsertFailure"))
        #expect(writer.contains("partial.progress.persistedCount"))
        #expect(writer.contains("partial.uncommittedEvents"))
        #expect(writer.contains("partial.underlyingError"))
        #expect(writer.contains("partial.replacementReadyForRetry"))

        let eventStore = try #require(
            files["MacCrabCore/Storage/EventStore.swift"]
        )
        #expect(eventStore.contains("private var activeDatabaseGeneration"))
        #expect(eventStore.contains("activeDatabaseGeneration &+= 1"))
        #expect(eventStore.contains("let databaseWasReplaced = activeDatabaseGeneration"))
        #expect(eventStore.contains("replacementReadyForRetry: databaseWasReplaced"))
    }

    @Test("Every index and trigger repair surface has classified storage admission")
    func schemaRepairAdmissionCensus() throws {
        let files = try sourceSwiftFiles()
        let migrationUsers = Set(files.compactMap { path, source in
            path != "MacCrabCore/Storage/SchemaMigrator.swift"
                && source.contains("SchemaMigrator.run(") ? path : nil
        })
        let expectedMigrationUsers: Set<String> = [
            "MacCrabCore/Storage/AlertStore.swift",
            "MacCrabCore/Storage/AttributionOverrideStore.swift",
            "MacCrabCore/Storage/CampaignStore.swift",
            "MacCrabCore/Storage/EventStore.swift",
            "MacCrabCore/Storage/SQLiteCausalGraphStore.swift",
            "MacCrabCore/Storage/TraceStore.swift",
        ]
        #expect(migrationUsers == expectedMigrationUsers,
                "migration caller census changed; review schema write admission")
        for path in migrationUsers {
            let source = try #require(files[path])
            #expect(source.contains("beforeStorageWork:"),
                    "\(path) can execute an unclassified migration index/trigger repair")
        }

        for path in [
            "MacCrabCore/Storage/AlertStore.swift",
            "MacCrabCore/Storage/AttributionOverrideStore.swift",
            "MacCrabCore/Storage/CampaignStore.swift",
            "MacCrabCore/Storage/EventStore.swift",
            "MacCrabCore/Storage/TraceStore.swift",
        ] {
            let source = try #require(files[path])
            #expect(source.contains("SchemaMigrator.pendingStorageWork("),
                    "\(path) baseline repair bypasses pending-work classification")
        }

        let artifact = try #require(
            files["MacCrabForensics/Storage/ArtifactStore.swift"]
        )
        #expect(artifact.contains("SchemaMigrator.pendingStorageWork("))
        #expect(artifact.contains("admitSchemaRebuild("))
        #expect(artifact.contains("needsVersionBump"),
                "latest-version ArtifactStore reopen must still repair missing indexes")

        let event = try #require(files["MacCrabCore/Storage/EventStore.swift"])
        #expect(event.contains("CREATE TRIGGER IF NOT EXISTS events_ai"))
        #expect(event.contains("CREATE TRIGGER IF NOT EXISTS events_au"))
        let graph = try #require(
            files["MacCrabCore/Storage/SQLiteCausalGraphStore.swift"]
        )
        #expect(graph.contains(
            "CREATE TRIGGER IF NOT EXISTS trg_hash_chain_global_sequence_unique"
        ))
        #expect(graph.contains("admitSchemaStorageWork(work)"))
    }

    @Test("Primary stores retry shed-only reopens once with the full write estimate")
    func secondaryRecoveryUsesFullEstimateDriftGuard() throws {
        for path in [
            "Sources/MacCrabCore/Storage/EventStore.swift",
            "Sources/MacCrabCore/Storage/AlertStore.swift",
            "Sources/MacCrabCore/Storage/CampaignStore.swift",
        ] {
            let source = try repositoryText(path)
            let start = try #require(source.range(
                of: "private func admitStorageWrite("
            ))
            let end = try #require(source.range(
                of: "private func admitStorageMaintenanceWrite(",
                range: start.upperBound..<source.endIndex
            ))
            let method = String(source[start.lowerBound..<end.lowerBound])

            #expect(
                occurrences(
                    of: "estimatedTransactionBytes: estimatedTransactionBytes",
                    in: method
                ) == 2,
                "\(path) must charge the same full estimate on primary and secondary admission"
            )
            #expect(
                occurrences(of: "try reopenAfterStorageRecovery()", in: method) == 2,
                "\(path) must reopen once after each successful recovery admission"
            )
            #expect(method.contains("if !isReadOnly, insertStmt == nil"))
            #expect(method.contains("storageAdmission?.latchedFailure"))
            #expect(!method.contains("estimatedTransactionBytes: 0"))

            // Statement acquisition lives in the insert path after admission;
            // no cached SQLite pointer is carried across either possible reopen.
            let admission = try #require(source.range(
                of: path.contains("CampaignStore")
                    ? "try admitStorageWrite("
                    : "try beforeWrite("
            ))
            let statement = try #require(source.range(
                of: "guard let stmt = insertStmt",
                range: admission.lowerBound..<source.endIndex
            ))
            #expect(admission.lowerBound < statement.lowerBound)
        }
    }
}
