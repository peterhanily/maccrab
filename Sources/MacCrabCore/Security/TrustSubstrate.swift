// TrustSubstrate.swift
// MacCrabCore
//
// v1.10 TraceGraph (PR-5) — per-install signing primitive used by the
// EvidenceBundleExporter (PR-10c) to sign the canonical bundle Merkle
// root, and by the policy loader (§15.10.2) to verify policy signatures
// against the install trust anchor.
//
// Two key modes ship per §19.1 of the v1.10.0 spec:
//
//   - secureEnclave: P-256 ECDSA keypair generated with
//     kSecAttrTokenIDSecureEnclave. Private key is non-exportable and
//     pinned to the daemon's keychain. Preferred mode.
//
//   - filesystemDegraded: P-256 ECDSA keypair generated with CryptoKit
//     and persisted to disk at strict 0o600 ownership. Used when SE
//     is unavailable (CI, virtualised hosts, older hardware). Honest
//     tamper-evidence against post-hoc bundle modification by
//     non-root attackers; explicitly does not claim root-resistant
//     authenticity.
//
// Mode selection is automatic at first launch (§19.1):
//   1. Try SE keypair generation. Success → secureEnclave mode.
//   2. SE rejection (errSecParam or other) → filesystemDegraded mode.
//   3. Persist the chosen mode for subsequent launches.
//
// Both modes produce ECDSA-over-P256 signatures with SHA-256 digests
// in DER format so a third-party validator's verification path is
// identical regardless of which mode signed.
//
// Public key surface: third-party validators consume the public key
// from `<base>/trace-signing.pub` (DER bytes). The public key is
// always extractable and persisted regardless of mode — it must be
// since the dashboard, CLI, and external validators verify by
// reading it from disk rather than calling back into the daemon.
//
// A3-02: the SE private key is now created with a usage ACL
// (SecAccessControl, `.privateKeyUsage`) pinned at key CREATION so the
// key material can only be exercised for signing. Combined with the
// keychain's default ACL — a keychain item is, by default, reachable
// only by the code identity that created it — this ties invocation of
// the signing key to the daemon's own signed code rather than leaving it
// open to any process. This RAISES THE BAR against a *non-daemon* root
// process trying to forge trace signatures with our key.
//
// It is explicitly NOT a defense against local ROOT / a kernel-level
// attacker: per docs/THREAT_MODEL.md, local root is out of scope for
// tamper protection — with root (or SIP disabled) an attacker can rewrite
// the daemon binary, dump keychain items, or drive the Secure Enclave
// directly. The ACL is defense-in-depth, not a root boundary.
//
// The filesystemDegraded fallback keeps its weaker guarantee: the private
// key is an on-disk DER blob at 0o600 under a 0o700 dir (see
// TrustSubstrateStorage). There is no SE/keychain ACL in that mode — any
// process able to read the file (root, or a misconfiguration) can sign.
// That mode is chosen only when SE is unavailable (CI, VMs, older HW) and
// is documented above as NOT root-resistant.

import Foundation
import CryptoKit
import Security
import os.log

public actor TrustSubstrate {

    // MARK: - Types

    public enum KeyMode: String, Sendable, Codable, Equatable, CaseIterable {
        case secureEnclave = "secure_enclave"
        case filesystemDegraded = "filesystem_degraded"
    }

    public enum SubstrateError: Swift.Error, Equatable {
        case keyGenerationFailed(status: OSStatus, message: String)
        case secureEnclaveUnavailable(reason: String)
        case keyMaterialUnavailable
        case signatureFailed(status: OSStatus, message: String)
        case verificationFailed(reason: String)
        case publicKeyExtractionFailed(message: String)
        case signatureFormatInvalid
        case storageError(String)
    }

    public struct PublicKeyMaterial: Sendable, Equatable {
        public let mode: KeyMode
        public let derBytes: Data
        public let pemString: String
        public let fingerprint: String  // sha256 hex of DER bytes

        public init(mode: KeyMode, derBytes: Data) {
            self.mode = mode
            self.derBytes = derBytes
            self.pemString = Self.encodePEM(derBytes)
            self.fingerprint = Self.fingerprint(derBytes)
        }

        private static func encodePEM(_ der: Data) -> String {
            let b64 = der.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
            return "-----BEGIN PUBLIC KEY-----\n\(b64)\n-----END PUBLIC KEY-----\n"
        }

        private static func fingerprint(_ der: Data) -> String {
            SHA256.hash(data: der).map { String(format: "%02x", $0) }.joined()
        }
    }

    // MARK: - Configuration

    /// Storage backend. Owns persistence of the mode, private key (in
    /// filesystem mode), public key, and SE keychain tag.
    private let storage: TrustSubstrateStorage

    /// When set, forces TrustSubstrate to skip SE detection and use
    /// the requested mode unconditionally. Test-only — production
    /// callers leave this nil so automatic detection runs.
    private let modeOverride: KeyMode?

    /// SE keychain lookup tag for this install. Generated once at first
    /// launch in SE mode and persisted via storage so subsequent launches
    /// find the same key.
    private static let defaultKeyTagPrefix = "com.maccrab.tracegraph.trace-signing."

    private let logger = Logger(subsystem: "com.maccrab.tracegraph", category: "trust-substrate")

    // MARK: - Cached state

    private var resolvedMode: KeyMode?
    private var cachedPublicKey: PublicKeyMaterial?
    private var cachedFilesystemPrivateKey: P256.Signing.PrivateKey?
    private var cachedSEKey: SecKey?

    // MARK: - Lifecycle

    public init(storage: TrustSubstrateStorage, modeOverride: KeyMode? = nil) {
        self.storage = storage
        self.modeOverride = modeOverride
    }

    // MARK: - Public API

    public func activeMode() async throws -> KeyMode {
        if let resolvedMode { return resolvedMode }
        let mode = try await selectMode()
        resolvedMode = mode
        return mode
    }

    public func sign(_ data: Data) async throws -> Data {
        let mode = try await activeMode()
        switch mode {
        case .filesystemDegraded:
            let key = try await loadOrGenerateFilesystemKey()
            let signature = try key.signature(for: data)
            // CryptoKit P256 signature → DER for wire compatibility
            // with SecKey (.ecdsaSignatureMessageX962SHA256 emits DER).
            return signature.derRepresentation
        case .secureEnclave:
            let key = try await loadOrGenerateSecureEnclaveKey()
            var error: Unmanaged<CFError>?
            let dataRef = data as CFData
            guard let signatureRef = SecKeyCreateSignature(
                key,
                .ecdsaSignatureMessageX962SHA256,
                dataRef,
                &error
            ) else {
                let cfError = error?.takeRetainedValue()
                let message = cfError.map { CFErrorCopyDescription($0) as String } ?? "<nil>"
                throw SubstrateError.signatureFailed(status: errSecInvalidSignature, message: message)
            }
            return signatureRef as Data
        }
    }

    public func verify(_ data: Data, signature: Data) async throws -> Bool {
        // Both modes produce DER ECDSA-P256-SHA256 signatures, so the
        // verification path is the same — pull the public key, parse it
        // back, and verify against the data.
        let publicKey = try await publicKey()
        // Use CryptoKit for verification regardless of the signing mode;
        // it handles DER ECDSA P-256 SHA-256 signatures and gives the
        // same answer SecKey would.
        let p256Key: P256.Signing.PublicKey
        do {
            p256Key = try P256.Signing.PublicKey(derRepresentation: publicKey.derBytes)
        } catch {
            throw SubstrateError.verificationFailed(
                reason: "public key DER could not be parsed: \(error)"
            )
        }
        let p256Signature: P256.Signing.ECDSASignature
        do {
            p256Signature = try P256.Signing.ECDSASignature(derRepresentation: signature)
        } catch {
            throw SubstrateError.signatureFormatInvalid
        }
        return p256Key.isValidSignature(p256Signature, for: data)
    }

    public func publicKey() async throws -> PublicKeyMaterial {
        if let cachedPublicKey { return cachedPublicKey }
        // Generate mode + key if needed; that path also persists the
        // public key to storage, so a subsequent load() will succeed.
        _ = try await activeMode()
        if let stored = try await storage.loadPublicKey() {
            let material = PublicKeyMaterial(mode: resolvedMode ?? .filesystemDegraded, derBytes: stored)
            cachedPublicKey = material
            return material
        }
        // Cold path: generate keypair, persist, return.
        switch try await activeMode() {
        case .filesystemDegraded:
            _ = try await loadOrGenerateFilesystemKey()
        case .secureEnclave:
            _ = try await loadOrGenerateSecureEnclaveKey()
        }
        guard let stored = try await storage.loadPublicKey() else {
            throw SubstrateError.keyMaterialUnavailable
        }
        let material = PublicKeyMaterial(mode: resolvedMode ?? .filesystemDegraded, derBytes: stored)
        cachedPublicKey = material
        return material
    }

    public func publicKeyFingerprint() async throws -> String {
        try await publicKey().fingerprint
    }

    // MARK: - Mode selection

    private func selectMode() async throws -> KeyMode {
        if let modeOverride {
            try await persistModeIfNew(modeOverride)
            return modeOverride
        }
        if let stored = try await storage.loadKeyMode() {
            return stored
        }
        // First launch — try SE, fall back to filesystem.
        if (try? await probeSecureEnclave()) == true {
            try await storage.saveKeyMode(.secureEnclave)
            logger.info("trust substrate selected mode: secure_enclave")
            return .secureEnclave
        }
        try await storage.saveKeyMode(.filesystemDegraded)
        logger.info("trust substrate selected mode: filesystem_degraded (SE unavailable)")
        return .filesystemDegraded
    }

    private func persistModeIfNew(_ mode: KeyMode) async throws {
        if try await storage.loadKeyMode() != mode {
            try await storage.saveKeyMode(mode)
        }
    }

    /// Returns true iff a SE-bound EC keypair can be created on this
    /// host. The probe key is created with kSecAttrIsPermanent: false
    /// so we don't pollute the keychain.
    private func probeSecureEnclave() async throws -> Bool {
        var attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrIsPermanent as String: false,
        ]
        // Suppress unused-mutability warnings; attrs is intentionally var
        // for future extension (access control, label) without restructure.
        _ = attrs.removeValue(forKey: "__placeholder__")
        attrs["__placeholder__"] = nil

        var error: Unmanaged<CFError>?
        guard let _ = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else {
            return false
        }
        return true
    }

    // MARK: - Filesystem mode

    private func loadOrGenerateFilesystemKey() async throws -> P256.Signing.PrivateKey {
        if let cachedFilesystemPrivateKey { return cachedFilesystemPrivateKey }
        if let der = try await storage.loadFilesystemPrivateKey() {
            do {
                let key = try P256.Signing.PrivateKey(derRepresentation: der)
                cachedFilesystemPrivateKey = key
                return key
            } catch {
                throw SubstrateError.keyMaterialUnavailable
            }
        }
        // Generate fresh keypair, persist private + public.
        let key = P256.Signing.PrivateKey()
        try await storage.saveFilesystemPrivateKey(key.derRepresentation)
        try await storage.savePublicKey(key.publicKey.derRepresentation)
        cachedFilesystemPrivateKey = key
        cachedPublicKey = PublicKeyMaterial(mode: .filesystemDegraded, derBytes: key.publicKey.derRepresentation)
        logger.info("trust substrate generated filesystem keypair")
        return key
    }

    // MARK: - Secure Enclave mode

    /// A3-02: build the usage ACL pinned to the SE signing key at creation.
    ///
    /// `.privateKeyUsage` marks the key usable only for signing operations
    /// (no export, no decrypt). We deliberately do NOT add `.userPresence`
    /// or biometry flags — the daemon signs headless, so an interactive
    /// prompt is neither possible nor wanted. The protection class is
    /// `…AfterFirstUnlockThisDeviceOnly`: device-bound (never syncs, never
    /// leaves this Mac) and available to the background daemon after the
    /// first unlock following boot.
    ///
    /// The code-identity binding ("only the daemon's signed code may
    /// invoke it") comes from the keychain ACL, not from a flag here: a
    /// keychain item is by default reachable only by the identity that
    /// created it. This helper is `internal` so tests can assert the ACL
    /// is constructed even on hosts without a Secure Enclave (the policy
    /// object is built in software and does not touch SE hardware).
    static func makeSigningKeyAccessControl() throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            [.privateKeyUsage],
            &error
        ) else {
            let cfError = error?.takeRetainedValue()
            let message = cfError.map { CFErrorCopyDescription($0) as String } ?? "<unknown>"
            throw SubstrateError.keyGenerationFailed(
                status: errSecParam,
                message: "SecAccessControl creation failed: \(message)"
            )
        }
        return access
    }

    private func loadOrGenerateSecureEnclaveKey() async throws -> SecKey {
        if let cachedSEKey { return cachedSEKey }
        // Try to load by tag.
        if let tag = try await storage.loadSecureEnclaveKeyTag() {
            if let key = try seKeyByTag(tag) {
                cachedSEKey = key
                return key
            }
            // Tag exists but key is gone (keychain wipe?). Fall through
            // to regenerate; we'll overwrite the tag.
            logger.warning("SE key tag persisted but key not found in keychain — regenerating")
        }

        let tag = (Self.defaultKeyTagPrefix + UUID().uuidString)
            .data(using: .utf8)!

        // A3-02: pin a usage ACL to the private key at CREATION so it can
        // only be used for signing operations. See makeSigningKeyAccessControl.
        let access = try Self.makeSigningKeyAccessControl()

        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrLabel as String: "MacCrab TraceGraph Signing Key",
                kSecAttrAccessControl as String: access,
            ],
        ]

        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else {
            let cfError = error?.takeRetainedValue()
            let message = cfError.map { CFErrorCopyDescription($0) as String } ?? "<unknown>"
            throw SubstrateError.keyGenerationFailed(status: errSecParam, message: message)
        }

        // Persist tag first so a successful key is always reachable.
        try await storage.saveSecureEnclaveKeyTag(tag)

        // Extract + persist public key DER.
        let pubKey = SecKeyCopyPublicKey(key)
        guard let pubKey else {
            throw SubstrateError.publicKeyExtractionFailed(message: "SecKeyCopyPublicKey returned nil")
        }
        var pubError: Unmanaged<CFError>?
        guard let pubRef = SecKeyCopyExternalRepresentation(pubKey, &pubError) else {
            let cfError = pubError?.takeRetainedValue()
            let message = cfError.map { CFErrorCopyDescription($0) as String } ?? "<unknown>"
            throw SubstrateError.publicKeyExtractionFailed(message: message)
        }
        // SecKeyCopyExternalRepresentation for EC keys returns the raw
        // X9.63 representation (04 || X || Y), not a SubjectPublicKeyInfo
        // DER. Convert to DER so verifiers using CryptoKit's
        // P256.Signing.PublicKey(derRepresentation:) can parse it.
        let rawX963 = pubRef as Data
        let der = try Self.x963ToDER(rawX963)
        try await storage.savePublicKey(der)
        cachedSEKey = key
        cachedPublicKey = PublicKeyMaterial(mode: .secureEnclave, derBytes: der)
        logger.info("trust substrate generated SE keypair")
        return key
    }

    private func seKeyByTag(_ tag: Data) throws -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else {
            throw SubstrateError.storageError("SecItemCopyMatching failed: \(status)")
        }
        // swiftlint:disable:next force_cast
        return (item as! SecKey)
    }

    /// Wrap a raw X9.63 EC public key (04 || X || Y) into a
    /// SubjectPublicKeyInfo DER blob compatible with CryptoKit's
    /// P256.Signing.PublicKey(derRepresentation:).
    ///
    /// SPKI for P-256 is a fixed-shape DER:
    ///   SEQUENCE {
    ///     SEQUENCE {
    ///       OID id-ecPublicKey (1.2.840.10045.2.1)
    ///       OID secp256r1 (1.2.840.10045.3.1.7)
    ///     }
    ///     BIT STRING { 0x00 || X9.63 (65 bytes for P-256) }
    ///   }
    private static func x963ToDER(_ x963: Data) throws -> Data {
        guard x963.count == 65, x963.first == 0x04 else {
            throw SubstrateError.publicKeyExtractionFailed(
                message: "expected 65-byte uncompressed X9.63 public key, got \(x963.count) bytes"
            )
        }
        // Pre-built SPKI prefix for P-256: 26 bytes through end-of-inner-SEQUENCE.
        // SEQUENCE (0x30) total length 0x59 (89) →
        //   SEQUENCE (0x30) length 0x13 (19) →
        //     OID id-ecPublicKey  06 07 2A 86 48 CE 3D 02 01
        //     OID secp256r1       06 08 2A 86 48 CE 3D 03 01 07
        //   BIT STRING (0x03) length 0x42 (66) → 00 || X9.63 (65 bytes)
        let prefix: [UInt8] = [
            0x30, 0x59,
                0x30, 0x13,
                    0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
                    0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
                0x03, 0x42, 0x00,
        ]
        var out = Data()
        out.reserveCapacity(prefix.count + x963.count)
        out.append(contentsOf: prefix)
        out.append(x963)
        return out
    }
}
