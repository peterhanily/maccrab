import CryptoKit
import Foundation
import Security

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
    case keychain(OSStatus)

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
        case .keychain(let status):
            return "The dashboard key-agreement private key is unavailable (OSStatus \(status))."
        }
    }
}

public enum TraceDashboardKeyExchange {
    private static let keychainService = "com.maccrab.trace-dashboard-key-agreement"
    private static let keychainAccount = "dashboard-x25519-v1"
    private static let keychainAccessGroup = "79S425CW99.com.maccrab.shared"
    private static let derivationSalt = Data("MacCrab trace dashboard key envelope v1".utf8)

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

    /// Load the dashboard's persistent X25519 private key, creating it in the
    /// login user's Keychain on first use. The raw private bytes never enter an
    /// inbox request or a root-owned response file.
    public static func loadOrCreateDashboardPrivateKey() throws
        -> Curve25519.KeyAgreement.PrivateKey
    {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecAttrAccessGroup as String: keychainAccessGroup,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: AnyObject?
        let loadStatus = SecItemCopyMatching(query as CFDictionary, &result)
        if loadStatus == errSecSuccess {
            guard let bytes = result as? Data,
                  let key = try? Curve25519.KeyAgreement.PrivateKey(
                    rawRepresentation: bytes
                  ) else {
                // A malformed dashboard recipient key can be replaced safely:
                // it never encrypted database rows, and the daemon can issue a
                // fresh envelope to the replacement public key.
                let generated = Curve25519.KeyAgreement.PrivateKey()
                var base = query
                base.removeValue(forKey: kSecReturnData as String)
                base.removeValue(forKey: kSecMatchLimit as String)
                let update = SecItemUpdate(
                    base as CFDictionary,
                    [kSecValueData as String: generated.rawRepresentation]
                        as CFDictionary
                )
                guard update == errSecSuccess else {
                    throw TraceDashboardKeyExchangeError.keychain(update)
                }
                return generated
            }
            return key
        }
        if loadStatus != errSecItemNotFound && loadStatus != errSecSuccess {
            throw TraceDashboardKeyExchangeError.keychain(loadStatus)
        }

        let generated = Curve25519.KeyAgreement.PrivateKey()
        query.removeValue(forKey: kSecReturnData as String)
        query.removeValue(forKey: kSecMatchLimit as String)
        query[kSecValueData as String] = generated.rawRepresentation
        query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let addStatus = SecItemAdd(query as CFDictionary, nil)
        if addStatus == errSecSuccess { return generated }

        // A second dashboard process may have won the create race. Perform one
        // bounded reload and adopt the persisted winner; never recurse on a
        // malformed/unauthorised duplicate.
        if addStatus == errSecDuplicateItem {
            var raced: AnyObject?
            var reload = query
            reload.removeValue(forKey: kSecValueData as String)
            reload.removeValue(forKey: kSecAttrAccessible as String)
            reload[kSecReturnData as String] = true
            reload[kSecMatchLimit as String] = kSecMatchLimitOne
            let status = SecItemCopyMatching(reload as CFDictionary, &raced)
            guard status == errSecSuccess,
                  let bytes = raced as? Data,
                  let winner = try? Curve25519.KeyAgreement.PrivateKey(
                    rawRepresentation: bytes
                  ) else {
                throw TraceDashboardKeyExchangeError.keychain(status)
            }
            return winner
        }
        throw TraceDashboardKeyExchangeError.keychain(addStatus)
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

    /// Resolve a root-issued envelope using the login user's persistent
    /// dashboard private key and return a read-side DatabaseEncryption.
    public static func dashboardEncryption(from envelopeData: Data) throws
        -> DatabaseEncryption
    {
        guard envelopeData.count <= 16 * 1024,
              let envelope = try? JSONDecoder().decode(
                TraceDashboardKeyEnvelope.self,
                from: envelopeData
              ) else { throw TraceDashboardKeyExchangeError.invalidEnvelope }
        let recipient = try loadOrCreateDashboardPrivateKey()
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
            keySaver: { _ in errSecSuccess },
            keyGenerator: { establishedKey }
        )
    }
}
