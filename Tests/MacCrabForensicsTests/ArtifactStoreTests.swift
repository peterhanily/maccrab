// ArtifactStore behavioral tests covering open, schema migration,
// case CRUD, artifact commit, plugin invocations, queries, and the
// Pass 2026-D invariant (plaintext cases reject non-metadata at
// INSERT).

import Foundation
import CSQLCipher
import Testing
@testable import MacCrabCore
@testable import MacCrabForensics

@Suite("ArtifactStore: schema + case CRUD")
struct ArtifactStoreSchemaCaseCRUDTests {

    private func tempPath() -> String {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-forensics-test-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("case.sqlite").path
    }

    @Test("Fresh encrypted store opens and schema migrates to v1")
    func freshEncryptedStoreMigrates() async throws {
        let dek = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let path = tempPath()
        let store = try await ArtifactStore(
            path: path,
            dek: dek,
            encryptionState: .encryptedKeychain
        )
        // Round-trip a case to confirm the schema actually exists.
        let row = CaseRecord(
            id: UUID().uuidString,
            name: "schema test",
            createdAt: Date(),
            encryptionState: .encryptedKeychain
        )
        try await store.insertCase(row)
        let fetched = try await store.fetchCase(id: row.id)
        #expect(fetched?.name == "schema test")
    }

    @Test("Plaintext store opens without a DEK")
    func plaintextStoreOpensWithoutDEK() async throws {
        let path = tempPath()
        let store = try await ArtifactStore(
            path: path,
            dek: nil,
            encryptionState: .plaintext
        )
        let row = CaseRecord(
            id: "test-1",
            name: "plaintext",
            createdAt: Date(),
            encryptionState: .plaintext
        )
        try await store.insertCase(row)
        let list = try await store.listCases()
        #expect(list.count == 1)
        #expect(list.first?.encryptionState == .plaintext)
    }

    @Test("Declared encryption state must match key presence")
    func encryptionStateAndKeyMustAgree() async {
        let path = tempPath()
        await #expect(throws: ArtifactStoreError.self) {
            _ = try await ArtifactStore(
                path: path,
                dek: nil,
                encryptionState: .encryptedKeychain
            )
        }
        await #expect(throws: ArtifactStoreError.self) {
            _ = try await ArtifactStore(
                path: path,
                dek: Data(repeating: 7, count: 32),
                encryptionState: .plaintext
            )
        }
        #expect(!FileManager.default.fileExists(atPath: path),
                "a key/state mismatch must fail before SQLite creates a file")
    }

    @Test("SQLite family symlinks, hard links, and orphan sidecars fail closed")
    func unsafeSQLiteFamilyRejected() async throws {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-artifact-path-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let target = dir.appendingPathComponent("target.sqlite")
        try Data("sentinel".utf8).write(to: target)
        let linked = dir.appendingPathComponent("case.sqlite")
        try FileManager.default.createSymbolicLink(at: linked, withDestinationURL: target)

        await #expect(throws: ArtifactStoreError.self) {
            _ = try await ArtifactStore(
                path: linked.path,
                dek: nil,
                encryptionState: .plaintext
            )
        }
        #expect(try Data(contentsOf: target) == Data("sentinel".utf8))

        try FileManager.default.removeItem(at: linked)
        try FileManager.default.linkItem(at: target, to: linked)
        await #expect(throws: ArtifactStoreError.self) {
            _ = try await ArtifactStore(
                path: linked.path,
                dek: nil,
                encryptionState: .plaintext
            )
        }
        #expect(try Data(contentsOf: target) == Data("sentinel".utf8))

        try FileManager.default.removeItem(at: linked)
        try Data("orphan".utf8).write(to: URL(fileURLWithPath: linked.path + "-wal"))
        await #expect(throws: ArtifactStoreError.self) {
            _ = try await ArtifactStore(
                path: linked.path,
                dek: nil,
                encryptionState: .plaintext
            )
        }
        #expect(!FileManager.default.fileExists(atPath: linked.path))
    }

    @Test("A database from a newer schema is never silently opened or downgraded")
    func futureSchemaRejected() async throws {
        let path = tempPath()
        try CSQLCipherInitGate.withLock {
            var db: OpaquePointer?
            #expect(sqlite3_open_v2(
                path,
                &db,
                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                nil
            ) == SQLITE_OK)
            guard let db else { return }
            #expect(sqlite3_exec(db, "PRAGMA user_version = 99", nil, nil, nil) == SQLITE_OK)
            sqlite3_close(db)
        }

        await #expect(throws: ArtifactStoreError.self) {
            _ = try await ArtifactStore(
                path: path,
                dek: nil,
                encryptionState: .plaintext
            )
        }

        let version = try CSQLCipherInitGate.withLock { () -> Int32 in
            var db: OpaquePointer?
            guard sqlite3_open_v2(
                path,
                &db,
                SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX,
                nil
            ) == SQLITE_OK, let db else { return -1 }
            defer { sqlite3_close(db) }
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, "PRAGMA user_version", -1, &stmt, nil) == SQLITE_OK,
                  let stmt else { return -1 }
            defer { sqlite3_finalize(stmt) }
            guard sqlite3_step(stmt) == SQLITE_ROW else { return -1 }
            return sqlite3_column_int(stmt, 0)
        }
        #expect(version == 99)
    }

    @Test("Latest-version reopen repairs a deleted production index")
    func latestVersionIndexRepair() async throws {
        let path = tempPath()
        var store: ArtifactStore? = try await ArtifactStore(
            path: path,
            dek: nil,
            encryptionState: .plaintext
        )
        store = nil

        try CSQLCipherInitGate.withLock {
            var db: OpaquePointer?
            #expect(SQLiteOpenPathPolicy.open(
                path,
                database: &db,
                flags: SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX
            ) == SQLITE_OK)
            let handle = try #require(db)
            defer { sqlite3_close(handle) }
            #expect(sqlite3_exec(
                handle,
                "DROP INDEX idx_artifacts_observed",
                nil,
                nil,
                nil
            ) == SQLITE_OK)
        }

        var reopened: ArtifactStore? = try await ArtifactStore(
            path: path,
            dek: nil,
            encryptionState: .plaintext
        )
        reopened = nil

        let repaired = try CSQLCipherInitGate.withLock { () -> Bool in
            var db: OpaquePointer?
            guard SQLiteOpenPathPolicy.open(
                path,
                database: &db,
                flags: SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX
            ) == SQLITE_OK, let db else { return false }
            defer { sqlite3_close(db) }
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(
                db,
                "SELECT 1 FROM sqlite_master WHERE type='index' AND name='idx_artifacts_observed'",
                -1,
                &stmt,
                nil
            ) == SQLITE_OK, let stmt else { return false }
            defer { sqlite3_finalize(stmt) }
            return sqlite3_step(stmt) == SQLITE_ROW
        }
        #expect(repaired)
    }

    @Test("ArtifactStore shares the package-wide SQLCipher initialization gate")
    func sharedSQLCipherGateDriftGuard() throws {
        let source = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("Sources/MacCrabForensics/Storage/ArtifactStore.swift")
        let text = try String(contentsOf: source, encoding: .utf8)
        #expect(text.contains("CSQLCipherInitGate.withLock"))
        #expect(!text.contains("static let initLock"),
                "a private gate does not serialize ArtifactStore against LiveDBSnapshot")
        #expect(text.contains("operation: \"commit begin savepoint\""))
        #expect(text.contains("operation: \"commit release savepoint\""),
                "commit must surface transaction-boundary failures")
    }

    @Test("A shed-only legacy store initializes before its first recovered write")
    func shedModeRecoveryRunsSkippedMigration() async throws {
        let path = tempPath()
        try CSQLCipherInitGate.withLock {
            var db: OpaquePointer?
            #expect(sqlite3_open_v2(
                path,
                &db,
                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                nil
            ) == SQLITE_OK)
            let handle = try #require(db)
            defer { sqlite3_close(handle) }
            #expect(sqlite3_exec(
                handle,
                "CREATE TABLE legacy_padding(payload BLOB); "
                    + "INSERT INTO legacy_padding VALUES (zeroblob(2097152)); "
                    + "PRAGMA user_version = 0",
                nil,
                nil,
                nil
            ) == SQLITE_OK)
        }

        let directory = (path as NSString).deletingLastPathComponent
        let constrained = SQLitePersistentStorePolicy(
            maxFootprintBytes: 3 * 1_048_576,
            freeSpaceFloorBytes: 0,
            transactionReserveBytes: 2 * 1_048_576,
            storageVolumePath: directory
        )
        let store = try await ArtifactStore(
            path: path,
            dek: nil,
            encryptionState: .plaintext,
            storagePolicy: constrained
        )
        #expect((await store.storageAdmissionSnapshot()).latchedFailure != nil)

        // Simulate a retention/reclaim owner shrinking the existing legacy DB
        // while ArtifactStore remains open for inspection in shed mode.
        try CSQLCipherInitGate.withLock {
            var db: OpaquePointer?
            #expect(sqlite3_open_v2(
                path,
                &db,
                SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX,
                nil
            ) == SQLITE_OK)
            let handle = try #require(db)
            defer { sqlite3_close(handle) }
            #expect(sqlite3_exec(
                handle,
                "DROP TABLE legacy_padding; VACUUM",
                nil,
                nil,
                nil
            ) == SQLITE_OK)
        }

        let row = CaseRecord(
            id: "shed-recovery",
            name: "recovered",
            createdAt: Date(),
            encryptionState: .plaintext
        )
        try await store.insertCase(row)
        #expect(try await store.fetchCase(id: row.id)?.name == "recovered")
        #expect((await store.storageAdmissionSnapshot()).latchedFailure == nil)
    }

    @Test("setAIContentAllowed flips the case flag")
    func aiContentAllowedFlip() async throws {
        let path = tempPath()
        let store = try await ArtifactStore(
            path: path,
            dek: nil,
            encryptionState: .plaintext
        )
        let row = CaseRecord(
            id: "test-ai",
            name: "ai test",
            createdAt: Date(),
            encryptionState: .plaintext
        )
        try await store.insertCase(row)
        try await store.setAIContentAllowed(caseID: "test-ai", allowed: true)
        let fetched = try await store.fetchCase(id: "test-ai")
        #expect(fetched?.aiContentAllowed == true)
    }

    @Test("setScheduledTrusted flips the case flag")
    func scheduledTrustedFlip() async throws {
        let path = tempPath()
        let store = try await ArtifactStore(
            path: path,
            dek: nil,
            encryptionState: .plaintext
        )
        let row = CaseRecord(
            id: "test-sched",
            name: "sched test",
            createdAt: Date(),
            encryptionState: .plaintext
        )
        try await store.insertCase(row)
        try await store.setScheduledTrusted(caseID: "test-sched", trusted: true)
        let fetched = try await store.fetchCase(id: "test-sched")
        #expect(fetched?.scheduledTrusted == true)
    }
}

@Suite("ArtifactStore: SQLCipher key correctness")
struct ArtifactStoreSQLCipherTests {

    private func tempPath() -> String {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-forensics-test-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("case.sqlite").path
    }

    @Test("Encrypted store survives close/reopen with the same key")
    func reopenWithSameKey() async throws {
        let dek = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let path = tempPath()

        // Open + insert + close.
        do {
            let store = try await ArtifactStore(
                path: path, dek: dek, encryptionState: .encryptedKeychain
            )
            try await store.insertCase(CaseRecord(
                id: "round-trip",
                name: "round trip",
                createdAt: Date(),
                encryptionState: .encryptedKeychain
            ))
            _ = store  // keep alive
        }

        // Reopen with same key.
        let reopened = try await ArtifactStore(
            path: path, dek: dek, encryptionState: .encryptedKeychain
        )
        let fetched = try await reopened.fetchCase(id: "round-trip")
        #expect(fetched?.name == "round trip")
    }

    @Test("Encrypted store with wrong key fails to open")
    func wrongKeyRejected() async throws {
        let correctKey = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        var wrongKey = correctKey
        wrongKey[0] = wrongKey[0] ^ 0xFF
        let path = tempPath()

        // Create with correct key.
        do {
            let store = try await ArtifactStore(
                path: path, dek: correctKey, encryptionState: .encryptedKeychain
            )
            try await store.insertCase(CaseRecord(
                id: "key-test",
                name: "key test",
                createdAt: Date(),
                encryptionState: .encryptedKeychain
            ))
            _ = store
        }

        // Reopen with wrong key — must throw.
        await #expect(throws: ArtifactStoreError.self) {
            _ = try await ArtifactStore(
                path: path, dek: wrongKey, encryptionState: .encryptedKeychain
            )
        }
    }
}

@Suite("ArtifactStore: artifact commit + query")
struct ArtifactStoreCommitQueryTests {

    private func tempPath() -> String {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-forensics-test-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("case.sqlite").path
    }

    private func openStore(plaintext: Bool = false) async throws -> (ArtifactStore, String) {
        let path = tempPath()
        let dek = plaintext ? nil : Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let state: CaseEncryptionState = plaintext ? .plaintext : .encryptedKeychain
        let store = try await ArtifactStore(
            path: path, dek: dek, encryptionState: state
        )
        let caseID = "case-\(UUID().uuidString.prefix(8))"
        try await store.insertCase(CaseRecord(
            id: caseID,
            name: "commit test",
            createdAt: Date(),
            encryptionState: state
        ))
        return (store, caseID)
    }

    @Test("commit returns a positive id and the artifact round-trips via query")
    func commitAndQuery() async throws {
        let (store, caseID) = try await openStore()
        let observed = Date()
        let record = ArtifactRecord(
            caseID: caseID,
            pluginID: "com.maccrab.forensics.fixture",
            pluginVersion: "1.0.0",
            schemaVersion: 1,
            contentType: "fixture.heartbeat",
            sha256: "0000000000000000000000000000000000000000000000000000000000000000",
            observedAt: observed,
            summary: "test heartbeat",
            confidence: .observed,
            privacyClass: .metadata,
            data: [
                "tick": .integer(1),
                "label": .string("alpha"),
            ]
        )
        let id = try await store.commit(record)
        #expect(id > 0)

        let q = ArtifactQuery(caseID: caseID, contentType: "fixture.heartbeat", limit: 10)
        let rows = try await store.query(q)
        #expect(rows.count == 1)
        #expect(rows.first?.id == id)
        #expect(rows.first?.record.summary == "test heartbeat")
        #expect(rows.first?.record.data["tick"] == .integer(1))
        #expect(rows.first?.record.data["label"] == .string("alpha"))
    }
    // Regression guard for the MCP forensics-01 fix: the granted MCP
    // read ceiling is .content, NOT .secret. A query capped at
    // privacyClassAtMost: .content must return metadata + content but
    // exclude personalComms, credentialAdjacent, and secret — so a
    // single `allow-ai --content` grant can never expose those classes
    // to an AI agent.
    @Test("privacyClassAtMost .content excludes personalComms/credentialAdjacent/secret")
    func contentCeilingExcludesHigherClasses() async throws {
        // Encrypted store so non-metadata classes pass the Pass 2026-D
        // INSERT invariant.
        let (store, caseID) = try await openStore()
        let classes: [PrivacyClass] = [.metadata, .content, .personalComms, .credentialAdjacent, .secret]
        for (i, cls) in classes.enumerated() {
            try await store.commit(ArtifactRecord(
                caseID: caseID,
                pluginID: "com.maccrab.forensics.fixture",
                pluginVersion: "1.0.0",
                schemaVersion: 1,
                contentType: "fixture.class.\(cls.rawValue)",
                sha256: String(i).padding(toLength: 64, withPad: "0", startingAt: 0),
                observedAt: Date(),
                privacyClass: cls
            ))
        }
        let rows = try await store.query(
            ArtifactQuery(caseID: caseID, privacyClassAtMost: .content, limit: 100)
        )
        let returned = Set(rows.map { $0.record.privacyClass })
        #expect(returned == [.metadata, .content])
        #expect(!returned.contains(.personalComms))
        #expect(!returned.contains(.credentialAdjacent))
        #expect(!returned.contains(.secret))
    }
    // Regression guard for cli-mcp-02: get_artifact's miss path must be
    // able to distinguish "genuinely absent" from "present but above the
    // ceiling". That disambiguation rests entirely on the store: a row
    // above the ceiling is excluded under a capped query but visible
    // under an unfiltered (privacyClassAtMost: nil) query. If this ever
    // regressed (e.g. nil started filtering), the MCP handler could no
    // longer surface aiContentBlockedError vs a true not-found.
    @Test("unfiltered query finds a higher-class artifact that the ceiling hides")
    func unfilteredLookupRevealsBlockedArtifact() async throws {
        let (store, caseID) = try await openStore()
        // Commit a single secret-class artifact. The default MCP ceiling
        // (no grant) is .metadata, which must exclude it.
        let secretID = try await store.commit(ArtifactRecord(
            caseID: caseID,
            pluginID: "com.maccrab.forensics.fixture",
            pluginVersion: "1.0.0",
            schemaVersion: 1,
            contentType: "fixture.secret",
            sha256: String(repeating: "a", count: 64),
            observedAt: Date(),
            privacyClass: .secret
        ))
        #expect(secretID > 0)

        // Capped at the metadata ceiling: the id is invisible (the
        // handler's first query misses).
        let ceilingRows = try await store.query(
            ArtifactQuery(caseID: caseID, privacyClassAtMost: .metadata, limit: 10_000)
        )
        #expect(!ceilingRows.contains(where: { $0.id == secretID }))

        // Unfiltered: the id is present, and its class is reported as
        // .secret — exactly what the handler passes to aiContentBlockedError.
        let unfiltered = try await store.query(
            ArtifactQuery(caseID: caseID, privacyClassAtMost: nil, limit: 10_000)
        )
        let blocked = unfiltered.first(where: { $0.id == secretID })
        #expect(blocked != nil)
        #expect(blocked?.record.privacyClass == .secret)

        // A nonexistent id is absent in BOTH queries — the genuine
        // not-found case the handler must keep distinct.
        #expect(!unfiltered.contains(where: { $0.id == secretID + 999_999 }))
    }

    @Test("query orders by observed_at DESC")
    func queryOrderDesc() async throws {
        let (store, caseID) = try await openStore()
        let base = Date()
        for i in 0..<5 {
            try await store.commit(ArtifactRecord(
                caseID: caseID,
                pluginID: "com.maccrab.forensics.fixture",
                pluginVersion: "1.0.0",
                schemaVersion: 1,
                contentType: "fixture.heartbeat",
                sha256: String(repeating: "\(i)", count: 64).padding(toLength: 64, withPad: "0", startingAt: 0),
                observedAt: base.addingTimeInterval(TimeInterval(i)),
                privacyClass: .metadata,
                data: ["tick": .integer(Int64(i))]
            ))
        }
        let rows = try await store.query(ArtifactQuery(caseID: caseID, limit: 10))
        #expect(rows.count == 5)
        // Latest observed_at first.
        #expect(rows.first?.record.data["tick"] == .integer(4))
        #expect(rows.last?.record.data["tick"] == .integer(0))
    }

    @Test("query honors --type filter")
    func queryByContentType() async throws {
        let (store, caseID) = try await openStore()
        try await store.commit(ArtifactRecord(
            caseID: caseID,
            pluginID: "com.maccrab.forensics.fixture",
            pluginVersion: "1.0.0",
            schemaVersion: 1,
            contentType: "fixture.heartbeat",
            sha256: "1".padding(toLength: 64, withPad: "0", startingAt: 0),
            observedAt: Date(),
            privacyClass: .metadata
        ))
        try await store.commit(ArtifactRecord(
            caseID: caseID,
            pluginID: "com.maccrab.forensics.fixture",
            pluginVersion: "1.0.0",
            schemaVersion: 1,
            contentType: "fixture.summary",
            sha256: "2".padding(toLength: 64, withPad: "0", startingAt: 0),
            observedAt: Date(),
            privacyClass: .metadata
        ))
        let beats = try await store.query(
            ArtifactQuery(caseID: caseID, contentType: "fixture.heartbeat", limit: 10)
        )
        #expect(beats.count == 1)
        #expect(beats.first?.record.contentType == "fixture.heartbeat")
    }

    @Test("Plugin invocation start + end records counts")
    func invocationRoundTrip() async throws {
        let (store, caseID) = try await openStore()
        let id = try await store.recordInvocationStart(
            caseID: caseID,
            pluginID: "com.maccrab.forensics.fixture",
            pluginVersion: "1.0.0",
            inputsJSON: "{}"
        )
        #expect(id > 0)
        try await store.recordInvocationEnd(
            id: id,
            exitStatus: "ok",
            artifactsCommitted: 3,
            artifactsRejected: 0,
            errorMessage: nil,
            snapshotHash: "deadbeef"
        )
    }
}

@Suite("ArtifactStore: Pass 2026-D plaintext-rejects-non-metadata")
struct ArtifactStorePass2026DTests {

    private func tempPath() -> String {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-forensics-test-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("case.sqlite").path
    }

    @Test("Plaintext case accepts metadata artifacts")
    func plaintextAcceptsMetadata() async throws {
        let store = try await ArtifactStore(
            path: tempPath(), dek: nil, encryptionState: .plaintext
        )
        let caseID = "plaintext-test"
        try await store.insertCase(CaseRecord(
            id: caseID,
            name: "plain",
            createdAt: Date(),
            encryptionState: .plaintext
        ))
        let id = try await store.commit(ArtifactRecord(
            caseID: caseID,
            pluginID: "com.maccrab.forensics.fixture",
            pluginVersion: "1.0.0",
            schemaVersion: 1,
            contentType: "fixture.heartbeat",
            sha256: "1".padding(toLength: 64, withPad: "0", startingAt: 0),
            observedAt: Date(),
            privacyClass: .metadata
        ))
        #expect(id > 0)
    }

    @Test("Plaintext case rejects content-class artifacts at INSERT")
    func plaintextRejectsContent() async throws {
        let store = try await ArtifactStore(
            path: tempPath(), dek: nil, encryptionState: .plaintext
        )
        let caseID = "plaintext-content"
        try await store.insertCase(CaseRecord(
            id: caseID,
            name: "plain",
            createdAt: Date(),
            encryptionState: .plaintext
        ))
        await #expect(throws: ArtifactStoreError.self) {
            try await store.commit(ArtifactRecord(
                caseID: caseID,
                pluginID: "com.maccrab.forensics.fixture",
                pluginVersion: "1.0.0",
                schemaVersion: 1,
                contentType: "fixture.body",
                sha256: "1".padding(toLength: 64, withPad: "0", startingAt: 0),
                observedAt: Date(),
                privacyClass: .content
            ))
        }
    }

    @Test("Plaintext case rejects personalComms artifacts at INSERT")
    func plaintextRejectsPersonalComms() async throws {
        let store = try await ArtifactStore(
            path: tempPath(), dek: nil, encryptionState: .plaintext
        )
        let caseID = "plaintext-pc"
        try await store.insertCase(CaseRecord(
            id: caseID,
            name: "plain",
            createdAt: Date(),
            encryptionState: .plaintext
        ))
        await #expect(throws: ArtifactStoreError.self) {
            try await store.commit(ArtifactRecord(
                caseID: caseID,
                pluginID: "com.maccrab.forensics.fixture",
                pluginVersion: "1.0.0",
                schemaVersion: 1,
                contentType: "fixture.message",
                sha256: "1".padding(toLength: 64, withPad: "0", startingAt: 0),
                observedAt: Date(),
                privacyClass: .personalComms
            ))
        }
    }

    @Test("Plaintext case rejects credentialAdjacent artifacts at INSERT")
    func plaintextRejectsCredentialAdjacent() async throws {
        let store = try await ArtifactStore(
            path: tempPath(), dek: nil, encryptionState: .plaintext
        )
        let caseID = "plaintext-ca"
        try await store.insertCase(CaseRecord(
            id: caseID,
            name: "plain",
            createdAt: Date(),
            encryptionState: .plaintext
        ))
        await #expect(throws: ArtifactStoreError.self) {
            try await store.commit(ArtifactRecord(
                caseID: caseID,
                pluginID: "com.maccrab.forensics.fixture",
                pluginVersion: "1.0.0",
                schemaVersion: 1,
                contentType: "fixture.cred",
                sha256: "1".padding(toLength: 64, withPad: "0", startingAt: 0),
                observedAt: Date(),
                privacyClass: .credentialAdjacent
            ))
        }
    }

    @Test("Plaintext case rejects secret artifacts at INSERT")
    func plaintextRejectsSecret() async throws {
        let store = try await ArtifactStore(
            path: tempPath(), dek: nil, encryptionState: .plaintext
        )
        let caseID = "plaintext-s"
        try await store.insertCase(CaseRecord(
            id: caseID,
            name: "plain",
            createdAt: Date(),
            encryptionState: .plaintext
        ))
        await #expect(throws: ArtifactStoreError.self) {
            try await store.commit(ArtifactRecord(
                caseID: caseID,
                pluginID: "com.maccrab.forensics.fixture",
                pluginVersion: "1.0.0",
                schemaVersion: 1,
                contentType: "fixture.secret",
                sha256: "1".padding(toLength: 64, withPad: "0", startingAt: 0),
                observedAt: Date(),
                privacyClass: .secret
            ))
        }
    }

    @Test("Encrypted case accepts content-class artifacts")
    func encryptedAcceptsContent() async throws {
        let dek = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let store = try await ArtifactStore(
            path: tempPath(),
            dek: dek,
            encryptionState: .encryptedKeychain
        )
        let caseID = "enc-content"
        try await store.insertCase(CaseRecord(
            id: caseID,
            name: "encrypted",
            createdAt: Date(),
            encryptionState: .encryptedKeychain
        ))
        let id = try await store.commit(ArtifactRecord(
            caseID: caseID,
            pluginID: "com.maccrab.forensics.fixture",
            pluginVersion: "1.0.0",
            schemaVersion: 1,
            contentType: "fixture.body",
            sha256: "1".padding(toLength: 64, withPad: "0", startingAt: 0),
            observedAt: Date(),
            privacyClass: .content
        ))
        #expect(id > 0)
    }
}
