import Foundation
import Testing
@testable import MacCrabCore

@Suite("TraceGraph encrypted presentation boundary")
struct CausalGraphEncryptionPresentationTests {
    private func encryption(_ byte: UInt8) -> DatabaseEncryption {
        let key = Data(repeating: byte, count: 32)
        return DatabaseEncryption(
            enabled: true,
            keyLoader: { key },
            keySaver: { _ in 0 },
            keyGenerator: { key }
        )
    }

    private func entity() -> TraceEntity {
        TraceEntity(
            id: "entity-1",
            entityType: "process",
            stableKey: "process:/bin/zsh",
            displayName: "zsh",
            firstSeen: Date(timeIntervalSince1970: 1),
            lastSeen: Date(timeIntervalSince1970: 2),
            attributesJson: #"{"path":"/bin/zsh","tool":"Bash"}"#,
            source: "test"
        )
    }

    @Test("Authenticated reader receives plaintext graph attributes")
    func authenticatedReader() async throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracegraph-enc-\(UUID().uuidString).db")
        defer { try? FileManager.default.removeItem(at: path) }
        let key = encryption(0x7C)
        do {
            let writer = try await SQLiteCausalGraphStore(
                databasePath: path.path,
                encryption: key
            )
            try await writer.upsertEntity(entity())
            await writer.close()
        }
        let reader = try await SQLiteCausalGraphStore(
            databasePath: path.path,
            encryption: key,
            forceReadOnly: true
        )
        let loaded = try await reader.entity(id: "entity-1")
        #expect(loaded?.attributesJson.contains("/bin/zsh") == true)
        #expect(loaded?.attributesJson.hasPrefix("ENC2:") == false)
        await reader.close()
    }

    @Test("Missing graph key fails closed instead of returning ENC2")
    func missingKeyFailsClosed() async throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracegraph-enc-\(UUID().uuidString).db")
        defer { try? FileManager.default.removeItem(at: path) }
        do {
            let writer = try await SQLiteCausalGraphStore(
                databasePath: path.path,
                encryption: encryption(0x51)
            )
            try await writer.upsertEntity(entity())
            await writer.close()
        }
        let keyless = try await SQLiteCausalGraphStore(
            databasePath: path.path,
            forceReadOnly: true
        )
        await #expect(throws: (any Error).self) {
            _ = try await keyless.entity(id: "entity-1")
        }
        await keyless.close()
    }
}
