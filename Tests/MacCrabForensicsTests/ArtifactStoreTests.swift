// ArtifactStore behavioral tests covering open, schema migration,
// case CRUD, artifact commit, plugin invocations, queries, and the
// Pass 2026-D invariant (plaintext cases reject non-metadata at
// INSERT).

import Foundation
import Testing
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
