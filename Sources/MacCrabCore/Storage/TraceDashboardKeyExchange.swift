import CryptoKit
import Foundation

/// A public, non-secret envelope carrying the root daemon's trace-database key
/// to one dashboard-held Curve25519 recipient key. Only the corresponding
/// private key can unwrap `sealedDatabaseKey`.
public struct TraceDashboardKeyEnvelope: Codable, Equatable, Sendable {
    public static let currentSchema = "com.maccrab.trace-dashboard-key-envelope.v1"

    public let schema: String
    public let recipientKeyID: String
    public let ephemeralPublicKey: String
    public let sealedDatabaseKey: String

    public init(
        schema: String = Self.currentSchema,
        recipientKeyID: String,
        ephemeralPublicKey: String,
        sealedDatabaseKey: String
    ) {
        self.schema = schema
        self.recipientKeyID = recipientKeyID
        self.ephemeralPublicKey = ephemeralPublicKey
        self.sealedDatabaseKey = sealedDatabaseKey
    }
}

public enum TraceDashboardKeyExchangeError: Error, LocalizedError {
    case encryptionUnavailable
    case invalidRecipientKey
    case invalidEnvelope
    case recipientMismatch

    public var errorDescription: String? {
        switch self {
        case .encryptionUnavailable:
            return "The trace database encryption key is unavailable."
        case .invalidRecipientKey:
            return "The dashboard key-agreement public key is invalid."
        case .invalidEnvelope:
            return "The dashboard trace-key envelope is malformed."
        case .recipientMismatch:
            return "The trace-key envelope was issued to a different dashboard key."
        }
    }
}

public enum TraceDashboardKeyExchange {
    private static let derivationSalt = Data("MacCrab trace dashboard key envelope v1".utf8)

    /// One recipient per dashboard process. This key only authenticates the
    /// daemon-to-dashboard handoff; it does not encrypt data at rest and does
    /// not need to survive an app restart. Keeping it in memory avoids login
    /// Keychain ACL/authentication UI while narrowing the lifetime of a key
    /// that can unwrap the root daemon's response.
    private static let dashboardSessionPrivateKey =
        Curve25519.KeyAgreement.PrivateKey()

    public static func keyID(for publicKey: Data) -> String {
        SHA256.hash(data: publicKey).map { String(format: "%02x", $0) }.joined()
    }

    static func wrappingKey(
        sharedSecret: SharedSecret,
        recipientPublicKey: Data
    ) -> SymmetricKey {
        sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: derivationSalt,
            sharedInfo: recipientPublicKey,
            outputByteCount: 32
        )
    }

    /// Return this dashboard process's X25519 recipient key. The raw private
    /// bytes remain in process memory and never enter the Keychain, an inbox
    /// request, or a root-owned response file.
    public static func dashboardPrivateKeyForCurrentSession() throws
        -> Curve25519.KeyAgreement.PrivateKey
    {
        dashboardSessionPrivateKey
    }

    public static func unwrap(
        _ envelope: TraceDashboardKeyEnvelope,
        with recipientPrivateKey: Curve25519.KeyAgreement.PrivateKey
    ) throws -> Data {
        guard envelope.schema == TraceDashboardKeyEnvelope.currentSchema,
              let ephemeralRaw = Data(base64Encoded: envelope.ephemeralPublicKey),
              let sealedRaw = Data(base64Encoded: envelope.sealedDatabaseKey),
              let ephemeral = try? Curve25519.KeyAgreement.PublicKey(
                rawRepresentation: ephemeralRaw
              ),
              let sealed = try? AES.GCM.SealedBox(combined: sealedRaw)
        else { throw TraceDashboardKeyExchangeError.invalidEnvelope }

        let recipientRaw = recipientPrivateKey.publicKey.rawRepresentation
        guard envelope.recipientKeyID == keyID(for: recipientRaw) else {
            throw TraceDashboardKeyExchangeError.recipientMismatch
        }
        let secret = try recipientPrivateKey.sharedSecretFromKeyAgreement(with: ephemeral)
        let wrappingKey = wrappingKey(
            sharedSecret: secret,
            recipientPublicKey: recipientRaw
        )
        return try AES.GCM.open(
            sealed,
            using: wrappingKey,
            authenticating: recipientRaw
        )
    }

    /// Resolve a root-issued envelope using this process's session recipient
    /// key and return a read-side DatabaseEncryption.
    public static func dashboardEncryption(from envelopeData: Data) throws
        -> DatabaseEncryption
    {
        guard envelopeData.count <= 16 * 1024,
              let envelope = try? JSONDecoder().decode(
                TraceDashboardKeyEnvelope.self,
                from: envelopeData
              ) else { throw TraceDashboardKeyExchangeError.invalidEnvelope }
        let recipient = try dashboardPrivateKeyForCurrentSession()
        let key = try unwrap(envelope, with: recipient)
        guard let encryption = DatabaseEncryption(establishedKey: key) else {
            throw TraceDashboardKeyExchangeError.invalidEnvelope
        }
        return encryption
    }
}

extension DatabaseEncryption {
    /// Wrap this process's persistent AES key to a dashboard public key. This is
    /// called only by the root daemon after the existing UID/admin inbox gate.
    public func dashboardKeyEnvelope(
        for recipientPublicKeyRaw: Data
    ) throws -> TraceDashboardKeyEnvelope {
        let databaseKey = establishedKeyMaterial
        guard isEnabled, databaseKey.count == 32 else {
            throw TraceDashboardKeyExchangeError.encryptionUnavailable
        }
        guard let recipient = try? Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: recipientPublicKeyRaw
        ) else { throw TraceDashboardKeyExchangeError.invalidRecipientKey }

        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        let secret = try ephemeral.sharedSecretFromKeyAgreement(with: recipient)
        let wrappingKey = TraceDashboardKeyExchange.wrappingKey(
            sharedSecret: secret,
            recipientPublicKey: recipientPublicKeyRaw
        )
        let sealed = try AES.GCM.seal(
            databaseKey,
            using: wrappingKey,
            authenticating: recipientPublicKeyRaw
        )
        guard let combined = sealed.combined else {
            throw TraceDashboardKeyExchangeError.invalidEnvelope
        }
        return TraceDashboardKeyEnvelope(
            recipientKeyID: TraceDashboardKeyExchange.keyID(for: recipientPublicKeyRaw),
            ephemeralPublicKey: ephemeral.publicKey.rawRepresentation.base64EncodedString(),
            sealedDatabaseKey: combined.base64EncodedString()
        )
    }

    /// Construct a read-side encryption instance from an authenticated key
    /// envelope. No Keychain lookup or key generation is performed here.
    public convenience init?(establishedKey: Data) {
        guard establishedKey.count == 32 else { return nil }
        self.init(
            enabled: true,
            keyLoader: { establishedKey },
            keySaver: { _ in 0 },
            keyGenerator: { establishedKey }
        )
    }
}
