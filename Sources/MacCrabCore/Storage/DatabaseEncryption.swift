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

public enum DatabaseEncryptionAvailabilityError: Error, LocalizedError, Equatable {
    case persistentKeyUnavailable(OSStatus?)

    public var errorDescription: String? {
        switch self {
        case .persistentKeyUnavailable(let status):
            if let status {
                return "persistent database-encryption key unavailable (OSStatus \(status))"
            }
            return "persistent database-encryption key unavailable"
        }
    }
}

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

    /// Module-internal access for the authenticated dashboard-key wrapping
    /// protocol. Never expose this as public raw key material.
    var establishedKeyMaterial: Data { key }

    /// Whether encryption is enabled.
    public let isEnabled: Bool

    /// True when the caller requested encryption (as opposed to the explicit
    /// MACCRAB_ENCRYPT_DB=0/test passthrough mode). If this is true while
    /// `isEnabled` is false, no persistent Keychain key was available and
    /// encrypted writers must remain offline rather than write plaintext or
    /// ciphertext under an ephemeral key.
    public let encryptionWasRequested: Bool

    /// Keychain status from a failed persist attempt. Nil for a healthy loaded
    /// or newly-persisted key and for explicitly disabled encryption.
    public let keyPersistenceFailureStatus: OSStatus?

    /// Count of invalid authenticated-encryption envelopes since process
    /// start. This includes both malformed `ENC2:` encodings that cannot reach
    /// CryptoKit and AES-GCM authentication failures. Every value written by
    /// `encrypt(_:)` is a valid base64 AES-GCM sealed box, so either condition
    /// means the stored encrypted value was corrupted or modified.
    private let tamperCounter = LockedCounter()

    /// Number of authenticated-envelope (tamper) failures observed so far.
    /// The legacy name is retained because it is already published in the
    /// heartbeat schema. 0 is normal; any increase means a malformed envelope
    /// or failed GCM authentication in an encrypted DB column.
    public var authenticatedDecryptFailures: Int { tamperCounter.get() }

    /// Count of UNENCRYPTED values seen in an encryption-enabled column (#19).
    /// This is a LOWER-confidence signal than an AES-GCM auth failure: a plaintext
    /// value there is EITHER a ciphertext→plaintext substitution OR a legitimate
    /// legacy row written while `MACCRAB_ENCRYPT_DB=0` before encryption was later
    /// enabled. Because the two are indistinguishable from the value alone, this
    /// is tracked + logged separately and does NOT drive the CRITICAL self-defense
    /// tamper alert (which stays AES-GCM-only, unambiguous) — the rc.3-verify FP
    /// fix. Exposed for an advisory surface / migration tooling.
    private let substitutionCounter = LockedCounter()

    /// Unencrypted values seen in an encryption-enabled column since start.
    public var plaintextInEncryptedColumnCount: Int { substitutionCounter.get() }

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
    public convenience init(enabled: Bool = true) {
        self.init(
            enabled: enabled,
            keyLoader: Self.loadKeyFromKeychain,
            keySaver: Self.saveKeyToKeychain,
            keyGenerator: Self.generateKey
        )
    }

    /// Injectable Keychain seam for persistence/restart tests. Production uses
    /// the public convenience initializer above.
    init(
        enabled: Bool,
        keyLoader: () -> Data?,
        keySaver: (Data) -> OSStatus,
        keyGenerator: () -> Data
    ) {
        guard enabled else {
            self.key = Data()
            self.isEnabled = false
            self.encryptionWasRequested = false
            self.keyPersistenceFailureStatus = nil
            return
        }

        self.encryptionWasRequested = true
        if let existingKey = keyLoader() {
            self.key = existingKey
            self.isEnabled = true
            self.keyPersistenceFailureStatus = nil
        } else {
            let newKey = keyGenerator()
            guard newKey.count == kCCKeySizeAES256 else {
                Self.failClosed("injected/generated DB key was \(newKey.count) bytes, expected \(kCCKeySizeAES256)")
            }
            let saveStatus = keySaver(newKey)
            if saveStatus == errSecSuccess {
                self.key = newKey
                self.isEnabled = true
                self.keyPersistenceFailureStatus = nil
            } else if let raced = keyLoader() {
                // A concurrent writer (the other bundle — the .app and the
                // sysext share this item) persisted first. Adopt the PERSISTED
                // key, never our ephemeral one, or the two processes encrypt
                // the same events.db under two different keys.
                self.key = raced
                self.isEnabled = true
                self.keyPersistenceFailureStatus = nil
            } else {
                // Never encrypt with an in-memory-only key. That ciphertext is
                // guaranteed to become unreadable on restart and was previously
                // misreported as tampering. Keep an unavailable sentinel; the
                // daemon refuses the encrypted stores while the rest of
                // detection remains online. encrypt(_:) also fails closed if a
                // caller violates that wiring contract.
                Logger(subsystem: "com.maccrab.storage", category: "encryption")
                    .fault("DB encryption key could NOT be persisted to or reloaded from the Keychain (OSStatus \(saveStatus, privacy: .public)) — encrypted stores are UNAVAILABLE; refusing ephemeral-key writes")
                self.key = Data()
                self.isEnabled = false
                self.keyPersistenceFailureStatus = saveStatus
            }
        }
    }

    // MARK: - Encrypt / Decrypt

    /// Encrypt a string value with AES-256-GCM (authenticated).
    /// Returns `"ENC2:"` + base64(`SealedBox.combined`) where combined =
    /// nonce (12 bytes) + ciphertext + tag (16 bytes).
    /// Returns the original string if encryption is disabled or the
    /// input is empty.
    public func encrypt(_ plaintext: String) -> String {
        guard encryptionWasRequested else { return plaintext }
        guard isEnabled else {
            Self.failClosed("encrypted write attempted without a persistent Keychain key")
        }
        guard !plaintext.isEmpty else { return plaintext }
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
    /// - Parameter expectingEncrypted: pass `true` from a column that is ALWAYS
    ///   written encrypted when encryption is enabled. A value there with no
    ///   encryption prefix is not a benign never-encrypted value — a real write
    ///   always emits an ENC2: blob — so bare plaintext is a ciphertext→plaintext
    ///   SUBSTITUTION (#19). Without this signal `decrypt` cannot tell the two
    ///   apart and would return the attacker's plaintext as trusted, never
    ///   touching the tamper counter. (AES-GCM already catches ciphertext/tag
    ///   MODIFICATION; this closes the substitution/downgrade gap.)
    public func decrypt(_ encrypted: String, expectingEncrypted: Bool = false) -> String {
        guard isEnabled else { return encrypted }
        if encrypted.hasPrefix(Self.encryptedPrefixV2) {
            return decryptV2(encrypted)
        }
        if encrypted.hasPrefix(Self.encryptedPrefixV1) {
            return decryptV1(encrypted)
        }
        // #19: no encryption prefix in an encryption-enabled column is either a
        // plaintext substitution OR a legacy row from before encryption was
        // enabled (MACCRAB_ENCRYPT_DB toggled on over an existing DB). Ambiguous,
        // so record it on the DISTINCT, lower-confidence counter and log at notice
        // — do NOT touch the AES-GCM tamper counter that drives the CRITICAL alert
        // (rc.3-verify: firing CRITICAL here false-alarmed on legit legacy rows).
        if expectingEncrypted {
            let count = substitutionCounter.increment()
            logger.notice("DB advisory: unencrypted value in an encryption-enabled column — possible ciphertext substitution OR a pre-encryption legacy row (substitution_count=\(count, privacy: .public))")
        }
        return encrypted
    }

    /// AES-GCM decrypt. Tamper detection lives here: a malformed `ENC2:`
    /// envelope or a modified ciphertext/tag increments `tamperCounter` and
    /// logs at fault level (distinct from a benign non-encrypted value) so the
    /// daemon can raise a tamper alert; the value then falls through to the
    /// passthrough return (visible as garbage in the UI).
    ///
    /// Follow-up (needs a daemon/store hook, not in this file): poll
    /// `authenticatedDecryptFailures` from the maintenance timer and emit a
    /// structured, rate-limited tamper Alert/Event.
    private func decryptV2(_ encrypted: String) -> String {
        let base64 = String(encrypted.dropFirst(Self.encryptedPrefixV2.count))
        guard let combined = Data(base64Encoded: base64) else {
            recordTamperFailure("malformed ENC2 base64 envelope")
            return encrypted
        }
        let symKey = SymmetricKey(data: key)
        do {
            let sealed = try AES.GCM.SealedBox(combined: combined)
            let plain = try AES.GCM.open(sealed, using: symKey)
            return String(data: plain, encoding: .utf8) ?? encrypted
        } catch {
            recordTamperFailure("AES-GCM envelope/authentication failed: \(error.localizedDescription)")
            return encrypted
        }
    }

    /// One accounting path for every invalid `ENC2:` representation. Keeping
    /// malformed base64 on the same monotonic counter is load-bearing: an
    /// attacker must not evade the daemon's rising-edge alert merely by making
    /// the ciphertext fail before `AES.GCM.open` is reached.
    private func recordTamperFailure(_ reason: String) {
        let count = tamperCounter.increment()
        logger.fault("DB tamper detected: authenticated encryption envelope invalid (tamper_count=\(count, privacy: .public)): \(reason, privacy: .public)")
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

    /// Reject a Keychain payload that is not a well-formed AES-256 key.
    ///
    /// `SymmetricKey(data:)` accepts ANY length, but `AES.GCM.seal` then throws
    /// `incorrectKeySize` — which lands in `encrypt`'s catch, calls
    /// `failClosed`, and hits the process-terminating `fatalError`. That is on
    /// the event-ingestion hot path, so a single wrong-length item at this
    /// (service, account) kills the ROOT System Extension on the first event
    /// carrying an encrypted column: a deterministic crash loop seconds after
    /// every launch, until macOS stops relaunching it. The bytes are not ours
    /// to trust — `generateKey()` only ever emits 32 — and realistic sources of
    /// a malformed item (partial Migration Assistant / Time Machine restore, a
    /// truncated item, a hand-rolled `security add-generic-password`) are all
    /// outside our control.
    ///
    /// Returning nil makes the caller fall through to the legacy lookup and
    /// ultimately to `generateKey()`; `saveKeyToKeychain` deletes before it
    /// adds, so the malformed item is replaced rather than left to re-trigger.
    /// Nothing is lost that was not already lost: a key of the wrong length
    /// cannot decrypt anything we ever wrote.
    private static func validatedKeyBytes(_ data: Data, source: String) -> Data? {
        guard data.count == kCCKeySizeAES256 else {
            Logger(subsystem: "com.maccrab.storage", category: "encryption")
                .fault("Keychain DB key (\(source, privacy: .public)) is \(data.count, privacy: .public) bytes, expected \(kCCKeySizeAES256, privacy: .public) — ignoring it and generating a fresh key rather than terminating the daemon on the first encrypted write")
            return nil
        }
        return data
    }

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
           let data = result as? Data,
           let valid = validatedKeyBytes(data, source: "access-group item") {
            return valid
        }

        // v1.8.1 access-group migration: pre-v1.8.1 items have no
        // group attribute. Look them up, return the value, and rewrite
        // with-group so subsequent reads hit the fast path.
        query.removeValue(forKey: kSecAttrAccessGroup as String)
        result = nil
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let legacyRaw = result as? Data,
              let legacyData = validatedKeyBytes(legacyRaw, source: "legacy no-group item") else {
            return nil
        }
        saveKeyToKeychain(legacyData)
        // The legacy without-group entry is deliberately LEFT IN PLACE.
        //
        // The delete that used to live here queried on (class, service,
        // account) — the exact tuple `saveKeyToKeychain` had just written — and
        // on macOS's file-based keychain `kSecAttrAccessGroup` does not
        // participate in matching, so the delete removed the item that had just
        // been stored. (The `removeValue(forKey: kSecAttrAccessGroup)` line was
        // itself a no-op: the key was never added to that dictionary.) The
        // in-memory key survived the current run, but the next launch found
        // nothing, fell through to `generateKey()` at init, and persisted a
        // BRAND-NEW key — permanently orphaning every prior `ENC2:` blob in
        // events.db / traces.db and re-diverging the root sysext from the
        // uid-501 app.
        //
        // A duplicate key item is harmless (identical bytes, and the with-group
        // lookup above is tried first). A deleted key is not. Removing the
        // delete is safe under either reading of how the access group is
        // matched on this platform; the underlying access-group inertness is a
        // separate, migration-bearing fix.
        return legacyData
    }

    /// Save the encryption key to the macOS Keychain with the shared
    /// access group attached so the sysext (signed by the same team)
    /// can read it. Returns the OSStatus so the caller can distinguish a
    /// key that is actually PERSISTED from an in-memory-only one.
    @discardableResult
    private static func saveKeyToKeychain(_ key: Data) -> OSStatus {
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecAttrAccessGroup as String: keychainAccessGroup,
        ]
        // v1.8.0: ThisDeviceOnly stops iCloud Keychain from syncing
        // the DB encryption key off-device. Local-only forensic data
        // should never roam — and `…AfterFirstUnlock` (the previous
        // value) is iCloud-Keychain-syncable. Matches SecretsStore.swift.
        // Passed on BOTH update and add so an item written by an older
        // build with weaker accessibility gets tightened on next write.
        let attributes: [String: Any] = [
            kSecValueData as String: key,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        // Update-first, add-only-when-absent — the pattern SecretsStore.save
        // already uses correctly. The previous delete-then-add DESTROYED the
        // stored key BEFORE the add, and the add's OSStatus was discarded, so
        // any add failure (locked keychain at boot → errSecInteractionNotAllowed,
        // errSecDuplicateItem from a racing writer, an entitlement error) left
        // the process running on an in-memory-only key while believing the key
        // had persisted. Everything written that session then failed AES-GCM
        // authentication after the next restart — i.e. it surfaced as a FALSE
        // tamper signal on `authenticatedDecryptFailures`. SecItemUpdate never
        // leaves the key absent.
        let updateStatus = SecItemUpdate(base as CFDictionary, attributes as CFDictionary)
        if updateStatus != errSecItemNotFound { return updateStatus }
        var addQuery = base
        addQuery[kSecValueData as String] = key
        addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        return SecItemAdd(addQuery as CFDictionary, nil)
    }
}
