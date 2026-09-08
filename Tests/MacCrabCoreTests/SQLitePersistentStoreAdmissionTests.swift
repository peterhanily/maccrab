import Testing
import os
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

    /// Grow the main file, then leave those pages on SQLite's freelist. A
    /// later full VACUUM can physically reclaim them while the store remains
    /// in shed mode, reproducing the startup maintenance -> normal admission
    /// transition without manufacturing application rows.
    private func addFreelistPadding(
        databasePath: String,
        bytes: Int
    ) throws {
        var handle: OpaquePointer?
        guard sqlite3_open_v2(
            databasePath,
            &handle,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX,
            nil
        ) == SQLITE_OK, let db = handle else {
            sqlite3_close(handle)
            throw FixtureError.sqlite
        }
        defer { sqlite3_close(db) }

        for sql in [
            "PRAGMA busy_timeout = 5000",
            "CREATE TABLE admission_reprobe_padding (payload BLOB NOT NULL)",
            "INSERT INTO admission_reprobe_padding VALUES (zeroblob(\(bytes)))",
            "DROP TABLE admission_reprobe_padding",
            "PRAGMA wal_checkpoint(TRUNCATE)",
        ] {
            guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else {
                throw FixtureError.sqlite
            }
        }
    }

    private enum FixtureError: Error {
        case sqlite
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
            "MacCrabCore/Storage/SQLiteIntegrityDiagnostic.swift",
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

    // v1.21.7. `optimizeFTS` — the only thing that reclaims FTS5 tombstones —
    // was admitted through `admitSchemaRebuild`, which projects
    // `family + growth + scratch` and refuses unless that stays under the cap.
    // `family` is the CURRENT footprint, and the call site only ever fires when
    // the store is already over cap, so the guard could never pass. It threw
    // every sweep and `optimizeFTS` returned false SILENTLY.
    //
    // Measured on an installed rc.9 host after 25 h uptime: events_fts_data at
    // 188 MB — 44% of a 383 MB store, against 62 MB of actual events spanning
    // 16 minutes — from tombstones left by ~4.5M insert/delete cycles. Zero "FTS
    // optimize compacted" lines in 8 h while the sweep ran 218 times and
    // reported the cap unreachable. The store was over cap BECAUSE of the index,
    // and being over cap is what blocked the only thing that shrinks it.
    @Test("compaction is admissible while over cap; growth is not")
    func reclaimAdmissionDoesNotDeadlockOnTheFootprintCap() throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let cap: Int64 = 128 * 1_048_576
        // The state that actually occurs: footprint ABOVE the cap, plenty of
        // disk. This is the only state optimizeFTS is ever invoked in.
        // The store opens HEALTHY and only later grows over cap — the real
        // sequence. A probe that is over cap at init cannot even be constructed.
        let grew = OSAllocatedUnfairLock(initialState: false)
        let overCapPath = dir.appendingPathComponent("overcap.db").path
        FileManager.default.createFile(atPath: overCapPath, contents: Data(count: 4_096))
        var overCap = try SQLitePersistentStoreAdmission(
            databasePath: overCapPath,
            policy: policy(directory: dir, max: cap, reserve: 8 * 1_048_576),
            footprintProbe: { _ in
                grew.withLock { $0 } ? cap + 64 * 1_048_576 : 0
            },
            freeSpaceProbe: { _ in Int64.max }
        )
        grew.withLock { $0 = true }   // now over cap, as on the live host

        // GROWTH admission must still refuse — the cap is real for new data.
        #expect(throws: SQLitePersistentStoreAdmissionError.self) {
            _ = try overCap.admitSchemaRebuild(operationCount: 1)
        }

        // RECLAIM admission must NOT, or the store can never get back under cap.
        #expect(throws: Never.self) {
            _ = try overCap.admitFullVacuum()
        }
    }

    @Test("reclaim still refuses when the volume itself is short")
    func reclaimStillRespectsFreeSpace() throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let cap: Int64 = 128 * 1_048_576
        // Ignoring the footprint cap must not mean ignoring the disk: compaction
        // needs transient scratch, and exhausting the boot volume mid-rewrite is
        // the failure this project has already had once.
        let grewND = OSAllocatedUnfairLock(initialState: false)
        let noDiskPath = dir.appendingPathComponent("nodisk.db").path
        FileManager.default.createFile(atPath: noDiskPath, contents: Data(count: 4_096))
        var noDisk = try SQLitePersistentStoreAdmission(
            databasePath: noDiskPath,
            policy: policy(directory: dir, max: cap, reserve: 8 * 1_048_576),
            footprintProbe: { _ in
                grewND.withLock { $0 } ? cap + 64 * 1_048_576 : 0
            },
            freeSpaceProbe: { _ in
                grewND.withLock { $0 } ? 2_048 : Int64.max   // below 2x the 4 KiB main file
            }
        )
        grewND.withLock { $0 = true }   // disk fills AFTER the store opened
        #expect(throws: SQLitePersistentStoreAdmissionError.self) {
            _ = try noDisk.admitFullVacuum()
        }
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
        #expect(occurrences(of: "eventStoragePolicy: eventStoragePolicy", in: setup) == 0)
        #expect(occurrences(of: "alertStoragePolicy: alertStoragePolicy", in: setup) == 1)
        #expect(occurrences(of: "storagePolicy: eventStoragePolicy", in: setup) == 3)
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
            "Sources/MacCrabCore/Storage/EventStore.swift": 5,
            "Sources/MacCrabCore/Storage/AlertStore.swift": 3,
            "Sources/MacCrabCore/Storage/CampaignStore.swift": 3,
        ]
        for (path, expectedCheckpointCalls) in primaryStores {
            let source = try repositoryText(path)
            #expect(source.contains("private func admitStorageCheckpoint()"))
            #expect(source.contains("try admission.admitCheckpoint()"))
            #expect(occurrences(of: "sqlite3_wal_checkpoint_v2", in: source)
                    == expectedCheckpointCalls,
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

    @Test("post-reopen growth is rejected at the exact alert reserve boundary")
    func postReopenGrowthConsumesRecoveredHeadroom() throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let footprint = Int64Box(90)
        var admission = try SQLitePersistentStoreAdmission(
            databasePath: dir.appendingPathComponent("alert.db").path,
            policy: policy(directory: dir, max: 100, reserve: 10),
            footprintProbe: { _ in footprint.get() },
            freeSpaceProbe: { _ in Int64.max }
        )

        // Equality is the last admissible point. This is the successful
        // pre-reopen probe cached by the old AlertStore path.
        try admission.admitWrite(estimatedTransactionBytes: 10)
        #expect(admission.snapshot().footprintBytes == 90)

        // Schema/statement setup during reopen consumes one byte. A fresh
        // post-reopen revalidation must latch and reject before any INSERT.
        footprint.set(91)
        #expect(throws: SQLitePersistentStoreAdmissionError.self) {
            try admission.admitWrite(estimatedTransactionBytes: 10)
        }
        let blocked = admission.snapshot()
        #expect(blocked.footprintBytes == 91)
        #expect(blocked.latchedFailure != nil)
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
            == Int64(376) * SQLitePersistentStorePolicy.bytesPerMiB)
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
        _ = try await eventBootstrap?.recoverJournalBeforeProducers()
        eventBootstrap = nil
        alertBootstrap = nil
        campaignBootstrap = nil
        overrideBootstrap = nil

        func loweredPolicy(
            _ path: String,
            reserve: Int64
        ) throws -> SQLitePersistentStorePolicy {
            let footprint = try SQLitePersistentStoreAdmission.measureFamily(path)
            return policy(
                directory: dir,
                max: max(reserve + 1, footprint + reserve - 1),
                reserve: reserve
            )
        }
        func raisedPolicy(
            _ path: String,
            reserve: Int64
        ) throws -> SQLitePersistentStorePolicy {
            let footprint = try SQLitePersistentStoreAdmission.measureFamily(path)
            return policy(
                directory: dir,
                max: max(128 * 1_048_576, footprint + reserve + 8 * 1_048_576),
                reserve: reserve
            )
        }

        let events = try EventStore(
            path: eventPath,
            storagePolicy: try loweredPolicy(
                eventPath,
                reserve: SQLitePersistentStorePolicy.eventTransactionReserveBytes
            )
        )
        let alerts = try AlertStore(
            path: alertPath,
            storagePolicy: try loweredPolicy(alertPath, reserve: 8 * 1_048_576)
        )
        let campaigns = try CampaignStore(
            path: campaignPath,
            storagePolicy: try loweredPolicy(campaignPath, reserve: 8 * 1_048_576)
        )
        let overrides = try AttributionOverrideStore(
            path: overridePath,
            storagePolicy: try loweredPolicy(overridePath, reserve: 4 * 1_048_576)
        )

        #expect((await events.storageAdmissionSnapshot())?.latchedFailure != nil)
        #expect((await alerts.storageAdmissionSnapshot())?.latchedFailure != nil)
        #expect((await campaigns.storageAdmissionSnapshot())?.latchedFailure != nil)
        #expect((await overrides.storageAdmissionSnapshot())?.latchedFailure != nil)

        do {
            try await events.insert(event: event())
            Issue.record("shed-mode EventStore insert unexpectedly succeeded")
        } catch let failure as EventBatchInsertFailure {
            #expect(failure.underlyingError is SQLitePersistentStoreAdmissionError)
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
            raisedPolicy(
                eventPath,
                reserve: SQLitePersistentStorePolicy.eventTransactionReserveBytes
            )
        )
        let alertRaised = try await alerts.updateStorageAdmission(
            raisedPolicy(alertPath, reserve: 8 * 1_048_576)
        )
        let campaignRaised = try await campaigns.updateStorageAdmission(
            raisedPolicy(campaignPath, reserve: 8 * 1_048_576)
        )
        #expect(eventRaised?.latchedFailure == nil)
        #expect(alertRaised?.latchedFailure == nil)
        #expect(campaignRaised?.latchedFailure == nil)

        try await events.insert(event: event())
        try await alerts.insert(alert: alert())
        try await campaigns.insert(campaign())
    }

    @Test("Maintenance recovery is proven by normal no-write alert and event lane reprobes")
    func recoveredStoresReprobeWithoutSacrificialWrites() async throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let eventPath = dir.appendingPathComponent("events-reprobe.db").path
        let alertPath = dir.appendingPathComponent("alerts-reprobe.db").path
        let mib = SQLitePersistentStorePolicy.bytesPerMiB
        let eventReserve = SQLitePersistentStorePolicy.eventTransactionReserveBytes
        let alertReserve = 4 * mib

        let events = try EventStore(
            path: eventPath,
            storagePolicy: policy(
                directory: dir,
                max: 128 * mib,
                reserve: eventReserve
            )
        )
        let alerts = try AlertStore(
            path: alertPath,
            storagePolicy: policy(
                directory: dir,
                max: 64 * mib,
                reserve: alertReserve
            )
        )

        // The lowered cap is paddedFootprint + R - 1. Reclaim enough padding
        // to leave both producer reserves and the file-priority reserve after
        // VACUUM, with one MiB for ordinary page/sidecar rounding.
        let eventPadding = eventReserve
            + EventStore.priorityLaneReserveBytes(maxFootprintBytes: 128 * mib)
            + mib
        try addFreelistPadding(
            databasePath: eventPath,
            bytes: Int(eventPadding)
        )
        try addFreelistPadding(
            databasePath: alertPath,
            bytes: 8 * Int(mib)
        )

        let eventPolicy = try pressureLatchPolicy(
            directory: dir,
            databasePath: eventPath,
            reserveBytes: eventReserve
        )
        let alertPolicy = try pressureLatchPolicy(
            directory: dir,
            databasePath: alertPath,
            reserveBytes: alertReserve
        )
        #expect(
            (try await events.updateStorageAdmission(eventPolicy))?
                .latchedFailure != nil
        )
        #expect(
            (try await alerts.updateStorageAdmission(alertPolicy))?
                .latchedFailure != nil
        )

        let eventRows = try await events.count()
        let alertRows = try await alerts.count()
        try await events.vacuum()
        try await alerts.vacuum()

        let compactedEvents = try SQLitePersistentStoreAdmission.measureFamily(
            eventPath
        )
        #expect(
            compactedEvents
                + 2 * eventReserve
                + EventStore.priorityLaneReserveBytes(
                    maxFootprintBytes: eventPolicy.maxFootprintBytes
                )
                <= eventPolicy.maxFootprintBytes
        )
        let compactedAlerts = try SQLitePersistentStoreAdmission.measureFamily(
            alertPath
        )
        #expect(
            compactedAlerts + alertReserve <= alertPolicy.maxFootprintBytes
        )

        // These probes clear the maintenance-preserved latch and reopen the
        // writer. Event probes check both reserves plus file-priority space
        // inside an empty BEGIN/ROLLBACK transaction, without sacrificial DML.
        let priority = try await events.reprobeStorageAdmissionForWrite(
            lane: .priority
        )
        let file = try await events.reprobeStorageAdmissionForWrite(lane: .file)
        let alert = try await alerts.reprobeStorageAdmissionForWrite()

        for snapshot in [priority, file, alert] {
            #expect(snapshot.latchedFailure == nil)
            #expect(!snapshot.pageLimitPending)
        }
        #expect(try await events.count() == eventRows)
        #expect(try await alerts.count() == alertRows)
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
        _ = try await bootstrap?.recoverJournalBeforeProducers()
        bootstrap = nil

        let reserve = SQLitePersistentStorePolicy.eventTransactionReserveBytes
        let lowFloor = policy(
            directory: dir,
            max: 128 * 1_048_576,
            floor: Int64.max,
            reserve: reserve
        )
        let store = try EventStore(path: path, storagePolicy: lowFloor)
        #expect((await store.storageAdmissionSnapshot())?.latchedFailure != nil)
        do {
            try await store.insert(event: event())
            Issue.record("low-floor EventStore insert unexpectedly succeeded")
        } catch let failure as EventBatchInsertFailure {
            #expect(failure.underlyingError is SQLitePersistentStoreAdmissionError)
        }
        #expect(try await store.pruneOldest(count: 1) == 0)

        let recovered = try await store.updateStorageAdmission(policy(
            directory: dir,
            max: 128 * 1_048_576,
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
        let reserve = SQLitePersistentStorePolicy.eventTransactionReserveBytes
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
                let seed = try await store.insert(
                    events: (0..<8).map { _ in event() },
                    lane: .priority
                )
                #expect(seed.persistedCount == 8)
            }

            try addFreelistPadding(
                databasePath: path,
                bytes: 8 * Int(SQLitePersistentStorePolicy.bytesPerMiB)
            )

            let tight = try pressureLatchPolicy(
                directory: dir,
                databasePath: path,
                reserveBytes: reserve
            )
            let blocked = try await store.updateStorageAdmission(tight)
            #expect(blocked?.latchedFailure != nil, "cycle \(cycle) did not latch")

            let rows = try await store.count()
            let reopened = try await store.updateStorageAdmission(policy(
                directory: dir,
                max: 128 * SQLitePersistentStorePolicy.bytesPerMiB,
                reserve: reserve
            ))
            #expect(reopened?.latchedFailure == nil)
            #expect(try await store.pruneOldest(count: rows) == 0,
                    "generic pressure recovery must preserve fresh journal evidence")
            try await store.vacuum()
            let compacted = try SQLitePersistentStoreAdmission.measureFamily(path)
            #expect(compacted + reserve <= 128 * SQLitePersistentStorePolicy.bytesPerMiB)

            let batch = (0..<16).map { _ in event() }
            let recovered = try await store.insert(
                events: batch,
                lane: .priority
            )
            #expect(recovered.persistedCount == batch.count)
            #expect(recovered.filteredCount == 0)
            #expect((await store.storageAdmissionSnapshot())?.latchedFailure == nil)
            #expect(try await store.count() == rows + batch.count)
        }
    }

    @Test("Alert and Campaign writers reacquire cached statements after recovery")
    func alertAndCampaignReacquireStatementsAfterRecovery() async throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let alertPath = dir.appendingPathComponent("alerts.db").path
        let campaignPath = dir.appendingPathComponent("campaigns.db").path
        // Alert batches reserve both their current chunk and the next ordinary
        // transaction. The pressure ceiling must therefore still fit two
        // reserves after maintenance compacts the actual seeded alert rows.
        let reserve = 4 * SQLitePersistentStorePolicy.bytesPerMiB
        let roomy = policy(
            directory: dir,
            max: 128 * SQLitePersistentStorePolicy.bytesPerMiB,
            reserve: reserve
        )
        let alerts = try AlertStore(path: alertPath, storagePolicy: roomy)
        let campaigns = try CampaignStore(path: campaignPath, storagePolicy: roomy)
        let seedDescription = String(repeating: "x", count: 64 * 1_024)

        for cycle in 0..<4 {
            // Prepare the next real pressure episode only after the previous
            // cycle's recovered write proved its unchanged tight cap. Raising
            // this bootstrap cap never participates in a blocked→write proof.
            _ = try await alerts.updateStorageAdmission(roomy)
            for _ in 0..<96 {
                try await alerts.insert(alert: Alert(
                    ruleId: "storage-reacquisition-seed",
                    ruleTitle: "Statement recovery fixture",
                    severity: .low,
                    eventId: UUID().uuidString,
                    description: seedDescription
                ))
            }
            #expect(await alerts.walCheckpointTruncate())
            let seededAlertBytes = try SQLitePersistentStoreAdmission.measureFamily(alertPath)
            #expect(seededAlertBytes > reserve,
                    "Actual seeded pages must make the derived cap larger than two alert reserves")
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
            #expect(alertPolicy.maxFootprintBytes > 2 * reserve)
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
                    + 2 * reserve <= alertPolicy.maxFootprintBytes
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
            #expect((await alerts.storageAdmissionSnapshot())?.maxFootprintBytes == alertPolicy.maxFootprintBytes,
                    "Alert statement recovery must succeed under the same cap that latched pressure")
            #expect((await campaigns.storageAdmissionSnapshot())?.maxFootprintBytes == campaignPolicy.maxFootprintBytes)
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

    @Test("Alert evidence copies a bounded projection while the journal remains exact")
    func alertEvidenceChargesLargeLegacyProjection() async throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("events.db").path
        let roomy = policy(
            directory: dir,
            max: 64 * 1_048_576,
            floor: 0,
            reserve: SQLitePersistentStorePolicy.eventTransactionReserveBytes
        )
        let constrained = policy(
            directory: dir,
            max: 64 * 1_048_576,
            floor: 0,
            reserve: SQLitePersistentStorePolicy.eventTransactionReserveBytes
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
        try await store.recordAlertEvidence(
            alertId: "bounded-evidence",
            alertTimestamp: timestamp,
            windowSeconds: 1
        )
        let evidence = try await store.evidenceFor(alertId: "bounded-evidence")
        #expect(evidence.count == 1)
        #expect(evidence.first?.eventAction.utf8.count == 2_048,
                "legacy alert evidence copies the bounded sparse projection")
        let exact = try await store.exactEventSnapshot(id: legacy.id)
        #expect(exact.event?.eventAction.utf8.count == oversizedAction.utf8.count,
                "the canonical journal must retain the complete event")
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
        let result = try await store.insert(events: events, lane: .priority)
        let after = await store.batchInsertTransactionCount()
        #expect(result.persistedCount == 1_000)
        #expect(result.filteredCount == 0)
        #expect(result.committedTransactionCount == Int(after - before))
        #expect(result.committedTransactionCount > 1,
                "the reserve guard must actually split a large batch")
        let expectedBlocks = (
            events.count + EventJournalCodec.maximumEventsPerBlock - 1
        ) / EventJournalCodec.maximumEventsPerBlock
        #expect(result.committedTransactionCount == expectedBlocks,
                "ordinary rows must commit one bounded journal block per transaction")
        #expect(try await store.count() == 1_000)
    }

    @Test("A structural ingress overflow becomes durable qualification poison")
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

        let result = try await store.insert(
            events: [oversized],
            lane: .priority
        )
        #expect(result.persistedCount == 0)
        #expect(result.inputDispositions.count == 1)
        if case .poisoned(let evidence) = try #require(
            result.inputDispositions.first
        ) {
            #expect(evidence.originalEventID == oversized.id)
            #expect(evidence.digestKind == .structuralPreflight)
        } else {
            Issue.record("structural ingress overflow was not durably poisoned")
        }
        #expect(try await store.payloadPoisonTotalSnapshot() == 1)
        let snapshot = try await store.exactEventsSnapshot(
            since: .distantPast,
            limit: 10
        )
        #expect(snapshot.events.isEmpty)
        #expect(snapshot.poisonRecords.map(\.eventID) == [oversized.id])
        #expect(!snapshot.isComplete)

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
        _ = try await bootstrap?.insert(events: [event()], lane: .priority)
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
            "DROP VIEW idx_events_timestamp; "
                + "DROP INDEX idx_event_projection_timestamp; "
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
                + "('idx_events_timestamp', 'idx_event_projection_timestamp', "
                + "'idx_events_ai_session', 'events_ai') "
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
            "idx_event_projection_timestamp": "index",
            "idx_events_timestamp": "view",
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
        #expect(writer.contains("partitionPartialFailure("),
                "partial retries must map EventStore identities back to writer generations")
        #expect(!writer.contains("batch.suffix("),
                "arbitrarily-positioned filtered rows make count-based suffix mapping unsafe")
        #expect(!writer.contains("batch.dropLast("),
                "terminal generations must come from exact partial dispositions")

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

            let fullEstimateForwards = occurrences(
                of: "estimatedTransactionBytes: estimatedTransactionBytes",
                in: method
            )
            if path.hasSuffix("EventStore.swift") {
                // EventStore additionally carries the lane through a fresh-probe
                // helper and through both post-reopen revalidations. Pin the
                // complete forwarding chain rather than the old two-call shape.
                #expect(fullEstimateForwards == 6,
                        "EventStore must preserve the full estimate through every fresh lane check")
                #expect(occurrences(
                    of: "try admitFreshStorageWrite(",
                    in: method
                ) == 2, "primary and revalidation admission must share the fresh gate")
                #expect(occurrences(
                    of: "try revalidateStorageWriteAfterReopen(",
                    in: method
                ) == 2, "both bounded recovery reopens must receive the full estimate")
            } else if path.hasSuffix("AlertStore.swift") {
                #expect(
                    fullEstimateForwards == 4,
                    "AlertStore must preserve the full estimate through both post-reopen probes"
                )
                #expect(occurrences(
                    of: "try revalidateStorageWriteAfterReopen(",
                    in: method
                ) == 2, "AlertStore must freshly revalidate after every recovery reopen")
            } else {
                #expect(
                    fullEstimateForwards == 2,
                    "\(path) must charge the same full estimate on primary and secondary admission"
                )
            }
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

    // v1.21.7. Storage admission was lane-blind: at the footprint threshold it
    // refused whatever arrived next, so a process exec and a routine chmod were
    // treated identically. Measured on an installed rc.7 host: ~890 events/min
    // refused with `footprint_limit` while 1,400/s of temp-file churn filled the
    // store — process and network telemetry lost to make room for chmod. It is
    // also an evasion primitive: flood cheap file events and the attacker's OWN
    // process events stop being recorded.
    //
    // The reserve is what makes the file lane yield first. These pin its shape;
    // the end-to-end ordering is exercised by the store-level tests above.
    @Test("the priority reserve is always meaningful and always bounded")
    func priorityLaneReserveIsSanelyBounded() {
        // Floor holds for a small budget: 15 minutes of priority-lane events is
        // a few MiB, so even the floor keeps that guarantee satisfiable.
        #expect(EventStore.priorityLaneReserveBytes(maxFootprintBytes: 50 * 1_048_576)
                == 16 * 1_048_576)
        // Ceiling holds for a large one — the reserve must never become the
        // dominant consumer of the budget it is protecting.
        #expect(EventStore.priorityLaneReserveBytes(maxFootprintBytes: 4_096 * 1_048_576)
                == 64 * 1_048_576)

        // Across every plausible cap: non-zero, never a majority of the budget,
        // and monotonic in the budget.
        var previous: Int64 = 0
        for mib in stride(from: 50, through: 2_048, by: 50) {
            let cap = Int64(mib) * 1_048_576
            let reserve = EventStore.priorityLaneReserveBytes(maxFootprintBytes: cap)
            #expect(reserve > 0, "reserve must never vanish (cap \(mib) MiB)")
            #expect(reserve < cap / 2, "reserve must never dominate the budget (cap \(mib) MiB)")
            #expect(reserve >= previous, "reserve must not decrease as the budget grows")
            previous = reserve
        }
    }

    @Test("the shipped events budget reserves headroom the file lane cannot take")
    func shippedBudgetReservesPriorityHeadroom() {
        // The shipped default is events_max_size_mb 476 with a 100 MiB evidence
        // subtraction, so the events family cap is 376 MiB.
        let familyCap: Int64 = 376 * 1_048_576
        let reserve = EventStore.priorityLaneReserveBytes(maxFootprintBytes: familyCap)
        #expect(reserve == 39_426_457, "expected the 10% reserve at the shipped cap, got \(reserve)")
        // A file-lane write must additionally leave the reserve free; a priority
        // write is charged only its own cost and stays admissible below that
        // point.
        #expect(reserve > 0 && reserve < familyCap)
    }

    // The first implementation of the lane reserve got the mechanism wrong in
    // two ways that the suite caught, and both are worth pinning so they cannot
    // come back.
    @Test("the lane reserve is small enough to never trip the per-transaction bound")
    func laneReserveDoesNotExceedTheTransactionBound() {
        // ATTEMPT 1 inflated `estimatedTransactionBytes` by the reserve. That
        // parameter feeds a per-TRANSACTION sanity bound, not the footprint
        // comparison, so every file-lane insert failed with
        // `transactionEstimateExceedsReserve` instead of being admitted —
        // 9 suite failures, and in production it would have dropped 100% of
        // file events rather than shedding them under pressure.
        //
        // The reserve therefore must never be expressible as part of a
        // transaction estimate. It is a FOOTPRINT quantity: comparable to the
        // store cap, far larger than any single transaction's reserve.
        for mib in [50, 340, 440, 2_048] {
            let cap = Int64(mib) * 1_048_576
            let reserve = EventStore.priorityLaneReserveBytes(maxFootprintBytes: cap)
            #expect(reserve > SQLitePersistentStoreAdmission.conservativeRowMutationBytes,
                    "the reserve is a footprint quantity, not a per-row one (cap \(mib) MiB)")
        }
    }

    @Test("a file-lane refusal must not latch the store closed against the priority lane")
    func fileLaneRefusalIsNonLatching() throws {
        // ATTEMPT 2 would have routed the lane test through `admitWrite`, whose
        // failure latches into `latchedFailure` — shared state every later
        // writer consults. A file-lane refusal would then have blocked the
        // PRIORITY lane too, which is exactly the outcome the reserve exists to
        // prevent: the cheap events would have shut the door on the valuable
        // ones by a different route.
        //
        // Guard the property structurally: the shared gate probes first so the
        // lane check consumes its fresh footprint, but the lane check still
        // throws directly rather than feeding an adjusted value back through
        // `admitWrite` and poisoning the shared latch.
        let source = try String(
            contentsOf: URL(fileURLWithPath: #filePath)
                .deletingLastPathComponent()          // MacCrabCoreTests
                .deletingLastPathComponent()          // Tests
                .deletingLastPathComponent()          // repo root
                .appendingPathComponent("Sources/MacCrabCore/Storage/EventStore.swift"),
            encoding: .utf8
        )
        let freshStart = try #require(source.range(
            of: "private func admitFreshStorageWrite("
        ))
        let freshEnd = try #require(source.range(
            of: "private func revalidateStorageWriteAfterReopen(",
            range: freshStart.upperBound..<source.endIndex
        ))
        let freshBody = String(
            source[freshStart.lowerBound..<freshEnd.lowerBound]
        )
        let sharedGate = try #require(freshBody.range(
            of: "try admission.admitWrite("
        ))
        let laneGate = try #require(freshBody.range(
            of: "try enforceFileLaneReserve("
        ))
        #expect(sharedGate.lowerBound < laneGate.lowerBound,
                "the lane check must consume admitWrite's fresh footprint")

        let laneStart = try #require(source.range(
            of: "private func enforceFileLaneReserve("
        ))
        let laneEnd = try #require(source.range(
            of: "private func admitStorageMaintenanceWrite(",
            range: laneStart.upperBound..<source.endIndex
        ))
        let laneBody = String(source[laneStart.lowerBound..<laneEnd.lowerBound])
        #expect(laneBody.contains("throw SQLitePersistentStoreAdmissionError.footprintLimit"),
                "the lane check must throw directly after the shared fresh probe")
        #expect(!laneBody.contains("admitWrite("),
                "the lane check must not route through admitWrite, whose failure latches shared state")
        #expect(occurrences(
            of: "try revalidateStorageWriteAfterReopen(",
            in: source
        ) == 2, "every bounded recovery reopen must receive a fresh lane check")
    }
}

// MARK: - rc.36: retention must be able to write its way back under the cap
//
// The family footprint cap was enforced against EVERY write, including the
// maintenance writes whose entire purpose is to shrink the family. A delete or
// rollup appends to the WAL before a checkpoint can reclaim anything, so once
// the family exceeded its cap the only work capable of fixing that was the
// first thing refused — a closed loop with no exit.
//
// Observed on an installed host: ingestion paused at 289.7 MiB of a 320 MiB
// cap, "Adaptive rollup at cutoff 15m failed: SQLite writes paused", and
// 906,509 events dropped while the store sat unable to prune itself.
@Suite("rc.36 maintenance admission headroom", .serialized)
struct MaintenanceAdmissionHeadroomTests {

    private func tempDirectory() throws -> URL {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-admit-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: dir, withIntermediateDirectories: true
        )
        return dir
    }

    /// A live, mutable footprint so the admission can be CONSTRUCTED healthy and
    /// then pushed over cap — the initializer probes and refuses to build an
    /// already-over-cap instance, which is exactly the state under test.
    private final class FootprintBox: @unchecked Sendable {
        private let lock = NSLock()
        private var value: Int64
        init(_ value: Int64) { self.value = value }
        var current: Int64 {
            get { lock.lock(); defer { lock.unlock() }; return value }
            set { lock.lock(); value = newValue; lock.unlock() }
        }
    }

    private func admission(
        directory: URL, max: Int64, reserve: Int64, footprint: FootprintBox
    ) throws -> SQLitePersistentStoreAdmission {
        try SQLitePersistentStoreAdmission(
            databasePath: directory.appendingPathComponent("admit.db").path,
            policy: SQLitePersistentStorePolicy(
                maxFootprintBytes: max,
                freeSpaceFloorBytes: 0,
                transactionReserveBytes: reserve,
                storageVolumePath: directory.path
            ),
            footprintProbe: { _ in footprint.current },
            freeSpaceProbe: { _ in Int64.max }
        )
    }

    @Test("Ingestion is still refused when the family is over cap")
    func ingestionRefusedOverCap() throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let max: Int64 = 128 * 1_048_576
        let reserve: Int64 = 1_048_576
        let footprint = FootprintBox(0)
        var admission = try admission(
            directory: dir, max: max, reserve: reserve, footprint: footprint
        )
        footprint.current = max + 1
        // The cap must keep meaning what it says for ordinary writes.
        #expect(throws: SQLitePersistentStoreAdmissionError.self) {
            try admission.admitWrite(estimatedTransactionBytes: 4_096)
        }
    }

    @Test("Maintenance may write one reserve above the cap to make progress")
    func maintenanceAdmittedOverCap() throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let max: Int64 = 128 * 1_048_576
        let reserve: Int64 = 1_048_576
        let footprint = FootprintBox(0)
        var admission = try admission(
            directory: dir, max: max, reserve: reserve, footprint: footprint
        )
        footprint.current = max + 1
        // Retention/rollup/prune must be able to run here. Refusing this is the
        // deadlock: the store can never shrink back under its own cap.
        try admission.admitSerializedWrite(
            estimatedTransactionBytes: 4_096,
            maintenance: true
        )
    }

    @Test("Maintenance headroom is bounded, not a blank cheque")
    func maintenanceHeadroomIsBounded() throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let max: Int64 = 128 * 1_048_576
        let reserve: Int64 = 1_048_576
        let footprint = FootprintBox(0)
        var admission = try admission(
            directory: dir, max: max, reserve: reserve, footprint: footprint
        )
        footprint.current = max + 1
        // One transaction reserve of overshoot, and no more — otherwise
        // "maintenance" becomes an unbounded exemption from the family budget.
        #expect(throws: SQLitePersistentStoreAdmissionError.self) {
            try admission.admitSerializedWrite(
                estimatedTransactionBytes: reserve + 1,
                maintenance: true
            )
        }
    }
}
