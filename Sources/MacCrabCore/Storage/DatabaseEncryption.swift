// DatabaseEncryption.swift
// MacCrabCore
//
// Provides field-level AES-256 encryption for sensitive database columns.
// Uses CommonCrypto (built into macOS) for AES-256-CBC encryption with
// PKCS7 padding and random IVs. The encryption key is stored in the
// macOS Keychain and auto-generated on first use.

import Foundation
import CommonCrypto
import os.log
import Security

/// Provides field-level AES-256 encryption for sensitive database columns.
///
/// Key management:
/// - AES-256 key is stored in the macOS Keychain under `com.maccrab.db-encryption`
/// - Key is auto-generated on first use (32 bytes from SecRandomCopyBytes)
/// - Key persists across daemon restarts via Keychain
///
/// Encryption format:
/// - Ciphertext is prefixed with `"ENC:"` for identification
/// - Binary layout: `[IV (16 bytes)][AES-256-CBC ciphertext with PKCS7 padding]`
/// - Stored as base64 after the `"ENC:"` prefix
///
/// If `enabled` is false, `encrypt`/`decrypt` are no-ops (passthrough).
public final class DatabaseEncryption: Sendable {

    private let logger = Logger(subsystem: "com.maccrab.storage", category: "encryption")

    /// The AES-256 encryption key (32 bytes).
    private let key: Data

    /// Whether encryption is enabled.
    public let isEnabled: Bool

    /// Prefix used to identify encrypted values.
    private static let encryptedPrefix = "ENC:"

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

    /// Encrypt a string value. Returns `"ENC:"` + base64-encoded `[IV][ciphertext]`.
    /// Returns the original string if encryption is disabled or the input is empty.
    public func encrypt(_ plaintext: String) -> String {
        guard isEnabled, !plaintext.isEmpty else { return plaintext }
        guard let data = plaintext.data(using: .utf8) else { return plaintext }

        // Generate random IV (16 bytes for AES block size)
        var iv = Data(count: kCCBlockSizeAES128)
        let ivStatus = iv.withUnsafeMutableBytes { ivPtr -> OSStatus in
            guard let base = ivPtr.baseAddress else { return errSecParam }
            return SecRandomCopyBytes(kSecRandomDefault, kCCBlockSizeAES128, base)
        }
        guard ivStatus == errSecSuccess else { return plaintext }

        // Buffer needs room for data + up to one extra block of padding
        let bufferSize = data.count + kCCBlockSizeAES128
        var ciphertext = Data(count: bufferSize)
        var numBytesEncrypted: size_t = 0

        let status = key.withUnsafeBytes { keyBytes in
            iv.withUnsafeBytes { ivBytes in
                data.withUnsafeBytes { dataBytes in
                    ciphertext.withUnsafeMutableBytes { cipherBytes in
                        CCCrypt(
                            CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionPKCS7Padding),
                            keyBytes.baseAddress, key.count,
                            ivBytes.baseAddress,
                            dataBytes.baseAddress, data.count,
                            cipherBytes.baseAddress, bufferSize,
                            &numBytesEncrypted
                        )
                    }
                }
            }
        }

        guard status == kCCSuccess else { return plaintext }
        ciphertext.count = numBytesEncrypted

        // Prepend IV to ciphertext: [IV (16 bytes)][ciphertext]
        var result = iv
        result.append(ciphertext)
        return Self.encryptedPrefix + result.base64EncodedString()
    }

    /// Decrypt a base64-encoded ciphertext previously produced by `encrypt(_:)`.
    /// Returns the original string if decryption fails or the value was not encrypted.
    public func decrypt(_ encrypted: String) -> String {
        guard isEnabled, encrypted.hasPrefix(Self.encryptedPrefix) else { return encrypted }

        let base64 = String(encrypted.dropFirst(Self.encryptedPrefix.count))
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

    /// Load the encryption key from the macOS Keychain.
    private static func loadKeyFromKeychain() -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else { return nil }
        return result as? Data
    }

    /// Save the encryption key to the macOS Keychain.
    private static func saveKeyToKeychain(_ key: Data) {
        // Build the query used for both delete (cleanup) and add
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecValueData as String: key,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
        ]
        // Remove old key if it exists (ignore result)
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
        ]
        SecItemDelete(deleteQuery as CFDictionary)
        SecItemAdd(query as CFDictionary, nil)
    }
}
