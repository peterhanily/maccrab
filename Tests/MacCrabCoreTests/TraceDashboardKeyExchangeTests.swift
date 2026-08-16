import CryptoKit
import Foundation
import Testing
@testable import MacCrabCore

@Suite("Root-to-dashboard trace key exchange")
struct TraceDashboardKeyExchangeTests {
    private func rootEncryption(key: Data) -> DatabaseEncryption {
        DatabaseEncryption(
            enabled: true,
            keyLoader: { key },
            keySaver: { _ in errSecSuccess },
            keyGenerator: { key }
        )
    }

    @Test("Dashboard recipient is stable for one process session")
    func sessionRecipientIsStable() throws {
        let first = try TraceDashboardKeyExchange
            .dashboardPrivateKeyForCurrentSession()
        let second = try TraceDashboardKeyExchange
            .dashboardPrivateKeyForCurrentSession()

        #expect(first.rawRepresentation == second.rawRepresentation)
    }

    @Test("Root wraps its established key only to the dashboard recipient")
    func roundTrip() throws {
        let rootKey = Data((0..<32).map(UInt8.init))
        let root = rootEncryption(key: rootKey)
        let dashboard = Curve25519.KeyAgreement.PrivateKey()

        let envelope = try root.dashboardKeyEnvelope(
            for: dashboard.publicKey.rawRepresentation
        )
        let unwrapped = try TraceDashboardKeyExchange.unwrap(
            envelope,
            with: dashboard
        )

        #expect(unwrapped == rootKey)
        #expect(envelope.recipientKeyID == TraceDashboardKeyExchange.keyID(
            for: dashboard.publicKey.rawRepresentation
        ))
        #expect(!envelope.sealedDatabaseKey.contains(rootKey.base64EncodedString()))
    }

    @Test("A different dashboard private key cannot unwrap the envelope")
    func wrongRecipientRejected() throws {
        let root = rootEncryption(key: Data(repeating: 0xA5, count: 32))
        let intended = Curve25519.KeyAgreement.PrivateKey()
        let attacker = Curve25519.KeyAgreement.PrivateKey()
        let envelope = try root.dashboardKeyEnvelope(
            for: intended.publicKey.rawRepresentation
        )

        #expect(throws: TraceDashboardKeyExchangeError.self) {
            _ = try TraceDashboardKeyExchange.unwrap(envelope, with: attacker)
        }
    }

    @Test("Tampering with the wrapped database key fails authentication")
    func tamperedEnvelopeRejected() throws {
        let root = rootEncryption(key: Data(repeating: 0x3C, count: 32))
        let dashboard = Curve25519.KeyAgreement.PrivateKey()
        let original = try root.dashboardKeyEnvelope(
            for: dashboard.publicKey.rawRepresentation
        )
        var sealed = try #require(Data(base64Encoded: original.sealedDatabaseKey))
        sealed[sealed.index(before: sealed.endIndex)] ^= 0x01
        let tampered = TraceDashboardKeyEnvelope(
            recipientKeyID: original.recipientKeyID,
            ephemeralPublicKey: original.ephemeralPublicKey,
            sealedDatabaseKey: sealed.base64EncodedString()
        )

        #expect(throws: (any Error).self) {
            _ = try TraceDashboardKeyExchange.unwrap(tampered, with: dashboard)
        }
    }

    @Test("Unwrapped key decrypts ciphertext produced by the root instance")
    func sharedDecryptionBehavior() throws {
        let root = rootEncryption(key: Data(repeating: 0x6D, count: 32))
        let dashboard = Curve25519.KeyAgreement.PrivateKey()
        let envelope = try root.dashboardKeyEnvelope(
            for: dashboard.publicKey.rawRepresentation
        )
        let key = try TraceDashboardKeyExchange.unwrap(envelope, with: dashboard)
        let reader = try #require(DatabaseEncryption(establishedKey: key))

        let plaintext = #"{"tool_name":"Bash","path":"/tmp/example"}"#
        let ciphertext = root.encrypt(plaintext)
        #expect(ciphertext.hasPrefix("ENC2:"))
        #expect(reader.decrypt(ciphertext, expectingEncrypted: true) == plaintext)
    }
}
