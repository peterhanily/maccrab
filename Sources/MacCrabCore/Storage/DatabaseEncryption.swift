// DatabaseEncryption.swift
// MacCrabCore
//
// Field-level encryption for sensitive database columns. The encryption
// key is auto-generated on first use, stored in the macOS Keychain
// under a shared access group both bundles can read (v1.8.1).
//
// v1 format (legacy, decrypt-only): "ENC:" + base64( [IV (16)] [AES-256-CBC + PKCS7] )
//   Confidentiality only — a tampered ciphertext decrypts to garbage with
//   no signal.
//
// v2 format (current, encrypt + decrypt): "ENC2:" + base64( SealedBox.combined )
//   AES-256-GCM via CryptoKit. SealedBox.combined = nonce (12) + ciphertext
//   + tag (16). Authenticated — tamper produces a decrypt failure, which
//   the daemon logs and reports as a tamper alert.
//
// Migration is transparent: v1.8.1+ writes v2; reads dispatch on prefix
// and accept both. Old rows stay v1 until naturally rewritten or migrated
// in bulk via a one-shot sweep (not yet implemented — graceful, not
// forced).

import Foundation
import CommonCrypto
import CryptoKit
import os.log
import Security

/// Provides field-level encryption for sensitive database columns.
///
/// Key management:
/// - AES-256 key is stored in the macOS Keychain under `com.maccrab.db-encryption`
///   with a shared access group so both the .app and the sysext can read it
/// - Key is auto-generated on first use (32 bytes from SecRandomCopyBytes)
/// - Key persists across daemon restarts via Keychain
///
/// Encryption format:
/// - v2 (current, AES-GCM, authenticated): `"ENC2:"` + base64(SealedBox.combined)
///   SealedBox.combined = nonce (12) + ciphertext + tag (16). Tamper-detecting.
/// - v1 (legacy, AES-CBC, decrypt-only): `"ENC:"` + base64([IV (16)][CBC + PKCS7])
///   Confidentiality only. Pre-v1.8.1 writes are still readable.
///
/// `decrypt(_:)` accepts either prefix; `encrypt(_:)` always emits v2.
///
/// If `enabled` is false, `encrypt`/`decrypt` are no-ops (passthrough).
public final class DatabaseEncryption: Sendable {

    private let logger = Logger(subsystem: "com.maccrab.storage", category: "encryption")

    /// The AES-256 encryption key (32 bytes).
    private let key: Data

    /// Whether encryption is enabled.
    public let isEnabled: Bool

    /// v1 prefix — legacy AES-CBC + PKCS7. Decrypt-only going forward.
    private static let encryptedPrefixV1 = "ENC:"
    /// v2 prefix — AES-GCM via CryptoKit. Authenticated. v1.8.1+.
    private static let encryptedPrefixV2 = "ENC2:"

    /// Keychain service name for the encryption key.
    private static let keychainService = "com.maccrab.db-encryption"
    private static let keychainAccount = "events-db-key"

    // MARK: - Initialization

    /// Initialize with auto-generated or Keychain-stored key.
    /// If `enabled` is false, encrypt/decrypt are no-ops (passthrough).
    public init(enabled: Bool = true) {
        guard enabled else {
            self.key = Data()
            self.isEnabled = false
            return
        }

        if let existingKey = Self.loadKeyFromKeychain() {
            self.key = existingKey
        } else {
            let newKey = Self.generateKey()
            Self.saveKeyToKeychain(newKey)
            self.key = newKey
        }
        self.isEnabled = true
    }

    // MARK: - Encrypt / Decrypt

    /// Encrypt a string value with AES-256-GCM (authenticated).
    /// Returns `"ENC2:"` + base64(`SealedBox.combined`) where combined =
    /// nonce (12 bytes) + ciphertext + tag (16 bytes).
    /// Returns the original string if encryption is disabled or the
    /// input is empty.
    public func encrypt(_ plaintext: String) -> String {
        guard isEnabled, !plaintext.isEmpty else { return plaintext }
        guard let data = plaintext.data(using: .utf8) else { return plaintext }

        let symKey = SymmetricKey(data: key)
        do {
            let sealed = try AES.GCM.seal(data, using: symKey)
            guard let combined = sealed.combined else { return plaintext }
            return Self.encryptedPrefixV2 + combined.base64EncodedString()
        } catch {
            logger.error("AES-GCM seal failed: \(error.localizedDescription, privacy: .public)")
            return plaintext
        }
    }

    /// Decrypt a value produced by any version of `encrypt(_:)`. Dispatches
    /// on prefix: ENC2: -> AES-GCM (current), ENC: -> AES-CBC (legacy).
    /// Returns the original string if decryption fails or the value was
    /// not encrypted.
    public func decrypt(_ encrypted: String) -> String {
        guard isEnabled else { return encrypted }
        if encrypted.hasPrefix(Self.encryptedPrefixV2) {
            return decryptV2(encrypted)
        }
        if encrypted.hasPrefix(Self.encryptedPrefixV1) {
            return decryptV1(encrypted)
        }
        return encrypted
    }

    /// AES-GCM decrypt. Tamper detection lives here: a modified
    /// ciphertext / tag throws, and the caller falls through to the
    /// passthrough return — making tamper visible as garbage in the UI
    /// and a logged error in the unified log.
    private func decryptV2(_ encrypted: String) -> String {
        let base64 = String(encrypted.dropFirst(Self.encryptedPrefixV2.count))
        guard let combined = Data(base64Encoded: base64) else { return encrypted }
        let symKey = SymmetricKey(data: key)
        do {
            let sealed = try AES.GCM.SealedBox(combined: combined)
            let plain = try AES.GCM.open(sealed, using: symKey)
            return String(data: plain, encoding: .utf8) ?? encrypted
        } catch {
            // Authenticated decryption failure — explicitly logged so a
            // tamper attempt against events.db produces a visible signal.
            logger.warning("AES-GCM open failed (possible tamper): \(error.localizedDescription, privacy: .public)")
            return encrypted
        }
    }

    /// AES-CBC + PKCS7 decrypt for v1 ciphertexts written before v1.8.1.
    /// Decrypt-only path; new writes always go through `encrypt(_:)` which
    /// emits v2. Once the row gets touched by an UPDATE that re-encrypts,
    /// it migrates naturally to v2.
    private func decryptV1(_ encrypted: String) -> String {
        let base64 = String(encrypted.dropFirst(Self.encryptedPrefixV1.count))
        guard let data = Data(base64Encoded: base64),
              data.count > kCCBlockSizeAES128 else {
            return encrypted
        }

        let iv = data.prefix(kCCBlockSizeAES128)
        let ciphertext = data.dropFirst(kCCBlockSizeAES128)

        let bufferSize = ciphertext.count + kCCBlockSizeAES128
        var plaintext = Data(count: bufferSize)
        var numBytesDecrypted: size_t = 0

        let status = key.withUnsafeBytes { keyBytes in
            iv.withUnsafeBytes { ivBytes in
                ciphertext.withUnsafeBytes { cipherBytes in
                    plaintext.withUnsafeMutableBytes { plainBytes in
                        CCCrypt(
                            CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionPKCS7Padding),
                            keyBytes.baseAddress, key.count,
                            ivBytes.baseAddress,
                            cipherBytes.baseAddress, ciphertext.count,
                            plainBytes.baseAddress, bufferSize,
                            &numBytesDecrypted
                        )
                    }
                }
            }
        }

        guard status == kCCSuccess else { return encrypted }
        plaintext.count = numBytesDecrypted
        return String(data: plaintext, encoding: .utf8) ?? encrypted
    }

    // MARK: - Keychain

    /// Generate a cryptographically random 32-byte AES-256 key.
    private static func generateKey() -> Data {
        var key = Data(count: kCCKeySizeAES256)
        _ = key.withUnsafeMutableBytes { keyPtr -> OSStatus in
            guard let base = keyPtr.baseAddress else { return errSecParam }
            return SecRandomCopyBytes(kSecRandomDefault, kCCKeySizeAES256, base)
        }
        return key
    }

    /// v1.8.1: shared keychain access group between the dashboard and
    /// the System Extension. Pre-fix the sysext couldn't read a key
    /// the dashboard wrote, so the daemon ended up generating its own
    /// (and the encrypted DB the dashboard could read became
    /// dashboard-only). With both bundles claiming this group, both
    /// can decrypt the same events.db.
    private static let keychainAccessGroup = "79S425CW99.com.maccrab.shared"

    /// Load the encryption key from the macOS Keychain.
    ///
    /// v1.8.1 migration: try with-group first, fall back to without-
    /// group; if found via the legacy path, rewrite with-group so the
    /// next read finds it directly.
    private static func loadKeyFromKeychain() -> Data? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecAttrAccessGroup as String: keychainAccessGroup,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: AnyObject?
        if SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
           let data = result as? Data {
            return data
        }

        // v1.8.1 access-group migration: pre-v1.8.1 items have no
        // group attribute. Look them up, return the value, and rewrite
        // with-group so subsequent reads hit the fast path.
        query.removeValue(forKey: kSecAttrAccessGroup as String)
        result = nil
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let legacyData = result as? Data else {
            return nil
        }
        saveKeyToKeychain(legacyData)
        // Best-effort delete the legacy without-group entry.
        var deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
        ]
        deleteQuery.removeValue(forKey: kSecAttrAccessGroup as String)
        SecItemDelete(deleteQuery as CFDictionary)
        return legacyData
    }

    /// Save the encryption key to the macOS Keychain with the shared
    /// access group attached so the sysext (signed by the same team)
    /// can read it.
    private static func saveKeyToKeychain(_ key: Data) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecAttrAccessGroup as String: keychainAccessGroup,
            kSecValueData as String: key,
            // v1.8.0: ThisDeviceOnly stops iCloud Keychain from syncing
            // the DB encryption key off-device. Local-only forensic data
            // should never roam — and `…AfterFirstUnlock` (the previous
            // value) is iCloud-Keychain-syncable. Matches SecretsStore.swift.
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        // Remove old key if it exists (ignore result)
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecAttrAccessGroup as String: keychainAccessGroup,
        ]
        SecItemDelete(deleteQuery as CFDictionary)
        SecItemAdd(query as CFDictionary, nil)
    }
}
