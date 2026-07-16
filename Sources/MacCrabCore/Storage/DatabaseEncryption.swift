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
//   + tag (16). Authenticated — tamper produces an authentication failure,
//   which increments a tamper counter (`authenticatedDecryptFailures`) and
//   logs at fault level so the daemon can raise a tamper alert.
//
// Fail-closed contract: `encrypt` never returns plaintext on a crypto
// failure while encryption is enabled, and key generation never accepts an
// RNG failure — both terminate the process rather than silently persist
// plaintext or a weak key. See `failClosed`.
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

    /// Count of AES-GCM authenticated-decryption failures since process
    /// start. For GCM an authentication failure means the stored ciphertext
    /// or tag was modified — i.e. tamper against an encrypted DB column — so
    /// a non-zero value is a tamper signal, not a benign decode miss.
    private let tamperCounter = LockedCounter()

    /// Number of authenticated-decryption (tamper) failures observed so far.
    /// 0 under normal operation; any increase means a modified ciphertext /
    /// tag in one of the encrypted DB columns. The daemon should poll this
    /// to raise a (rate-limited) tamper alert.
    public var authenticatedDecryptFailures: Int { tamperCounter.get() }

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
        // Fail CLOSED past this point: with encryption enabled we must never
        // return plaintext on a crypto failure, or the caller would persist
        // sensitive columns unencrypted while believing they are encrypted.
        // Every branch below is unreachable under a well-formed 32-byte key
        // (a Swift String is always valid UTF-8; AES-GCM.seal with a valid
        // key does not fail and always yields a non-nil combined box), so
        // reaching one means a broken key/CryptoKit invariant.
        guard let data = plaintext.data(using: .utf8) else {
            Self.failClosed("UTF-8 encoding of plaintext failed")
        }

        let symKey = SymmetricKey(data: key)
        do {
            let sealed = try AES.GCM.seal(data, using: symKey)
            guard let combined = sealed.combined else {
                Self.failClosed("AES-GCM SealedBox.combined was nil")
            }
            return Self.encryptedPrefixV2 + combined.base64EncodedString()
        } catch {
            Self.failClosed("AES-GCM seal failed: \(error.localizedDescription)")
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

    /// AES-GCM decrypt. Tamper detection lives here: a modified ciphertext
    /// / tag fails authentication, which increments `tamperCounter` and logs
    /// at fault level (distinct from a benign non-encrypted value) so the
    /// daemon can raise a tamper alert; the value then falls through to the
    /// passthrough return (visible as garbage in the UI).
    ///
    /// Follow-up (needs a daemon/store hook, not in this file): poll
    /// `authenticatedDecryptFailures` from the maintenance timer and emit a
    /// structured, rate-limited tamper Alert/Event.
    private func decryptV2(_ encrypted: String) -> String {
        let base64 = String(encrypted.dropFirst(Self.encryptedPrefixV2.count))
        guard let combined = Data(base64Encoded: base64) else { return encrypted }
        let symKey = SymmetricKey(data: key)
        do {
            let sealed = try AES.GCM.SealedBox(combined: combined)
            let plain = try AES.GCM.open(sealed, using: symKey)
            return String(data: plain, encoding: .utf8) ?? encrypted
        } catch {
            // AES-GCM authentication failure == tamper: the stored ciphertext
            // or tag was modified. Record it distinctly (tamper counter +
            // fault log) so it surfaces as a security signal the daemon can
            // alert on, rather than being swallowed as a benign warning.
            let count = tamperCounter.increment()
            logger.fault("DB tamper detected: AES-GCM authentication failed (tamper_count=\(count, privacy: .public)): \(error.localizedDescription, privacy: .public)")
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
        let status = key.withUnsafeMutableBytes { keyPtr -> OSStatus in
            guard let base = keyPtr.baseAddress else { return errSecParam }
            return SecRandomCopyBytes(kSecRandomDefault, kCCKeySizeAES256, base)
        }
        // Fail CLOSED on RNG failure: proceeding would persist the all-zero
        // `Data(count:)` buffer as an AES-256 key to the Keychain — a
        // catastrophic, silent key-generation failure. A key-generation path
        // must never accept an RNG error.
        guard status == errSecSuccess else {
            failClosed("SecRandomCopyBytes failed (OSStatus \(status)) — refusing to persist a weak key")
        }
        return key
    }

    /// Fail CLOSED. A security product's at-rest encryption must never fall
    /// back to persisting plaintext, nor accept a weak key, on a crypto
    /// failure. Callers reach here only on a broken key/RNG/CryptoKit
    /// invariant; we log at fault level (unified log) and terminate rather
    /// than silently leak plaintext or write with a possibly-weak key.
    private static func failClosed(_ reason: String) -> Never {
        Logger(subsystem: "com.maccrab.storage", category: "encryption")
            .fault("DatabaseEncryption failed closed: \(reason, privacy: .public)")
        fatalError("DatabaseEncryption failed closed: \(reason)")
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
