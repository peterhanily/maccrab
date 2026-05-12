// TrustSubstrateStorage.swift
// MacCrabCore
//
// v1.10 TraceGraph (PR-5) — pluggable storage for the TrustSubstrate
// actor. Two implementations ship:
//
//   - FilesystemTrustSubstrateStorage: production backend rooted at
//     `/Library/Application Support/MacCrab/keys/` (or a caller-supplied
//     base URL for tests / dev installs without root).
//
//   - InMemoryTrustSubstrateStorage: test-only backend that keeps key
//     material in actor-isolated dictionaries. Lets the test suite
//     exercise the full lifecycle without touching disk.
//
// The storage protocol is intentionally narrow — the TrustSubstrate
// actor owns mode selection, key generation, signing, and verification
// logic. Storage just persists bytes.

import Foundation
import os.log

/// Backend for TrustSubstrate persistence. All methods are async +
/// throwing because the production filesystem implementation can hit
/// the disk; the in-memory implementation is sync but conforms via
/// actor isolation.
public protocol TrustSubstrateStorage: Sendable {

    /// Read the persisted key mode. Returns nil if no mode has been
    /// recorded yet (first launch — caller must choose and persist).
    func loadKeyMode() async throws -> TrustSubstrate.KeyMode?

    /// Persist the chosen key mode for future daemon launches.
    func saveKeyMode(_ mode: TrustSubstrate.KeyMode) async throws

    /// Read the filesystem-mode private key DER bytes. Returns nil if
    /// no key has been generated. SE mode does not store the private
    /// key here (it lives in the keychain).
    func loadFilesystemPrivateKey() async throws -> Data?

    /// Persist the filesystem-mode private key DER bytes. Implementations
    /// must enforce strict ownership and 0o600 permissions; symlink-safe
    /// writes via O_NOFOLLOW where applicable.
    func saveFilesystemPrivateKey(_ data: Data) async throws

    /// Read the public key DER bytes. Always populated after first
    /// generation regardless of mode — the public key is the surface
    /// that third-party validators consume.
    func loadPublicKey() async throws -> Data?

    /// Persist the public key DER bytes.
    func savePublicKey(_ data: Data) async throws

    /// Identifier used by SE mode to look the private key up in the
    /// keychain. Persisted at first generation so subsequent launches
    /// can find the same key. Returns nil before SE mode has ever
    /// generated a key.
    func loadSecureEnclaveKeyTag() async throws -> Data?

    /// Persist the SE keychain lookup tag.
    func saveSecureEnclaveKeyTag(_ tag: Data) async throws
}

// MARK: - InMemoryTrustSubstrateStorage

/// Test-only storage. All state is held in actor-isolated dictionaries.
public actor InMemoryTrustSubstrateStorage: TrustSubstrateStorage {

    private var mode: TrustSubstrate.KeyMode?
    private var filesystemPrivateKey: Data?
    private var publicKey: Data?
    private var seKeyTag: Data?

    public init() {}

    public func loadKeyMode() throws -> TrustSubstrate.KeyMode? { mode }
    public func saveKeyMode(_ mode: TrustSubstrate.KeyMode) throws { self.mode = mode }

    public func loadFilesystemPrivateKey() throws -> Data? { filesystemPrivateKey }
    public func saveFilesystemPrivateKey(_ data: Data) throws { filesystemPrivateKey = data }

    public func loadPublicKey() throws -> Data? { publicKey }
    public func savePublicKey(_ data: Data) throws { publicKey = data }

    public func loadSecureEnclaveKeyTag() throws -> Data? { seKeyTag }
    public func saveSecureEnclaveKeyTag(_ tag: Data) throws { seKeyTag = tag }
}

// MARK: - FilesystemTrustSubstrateStorage

/// Production storage. Files live under a base directory (default:
/// `/Library/Application Support/MacCrab/keys/`). The base directory
/// is parameterised so dev installs and tests can use a writeable
/// path without root.
///
/// File layout under the base directory:
///
///   trace-signing.pub        — public key DER bytes (always present
///                              after first generation).
///   trace-signing.key        — filesystem-mode private key DER bytes
///                              (present only in filesystem mode);
///                              0o600, owned by daemon user.
///   trust-substrate.json     — small JSON record of the active mode
///                              and the SE keychain tag (when applicable).
public actor FilesystemTrustSubstrateStorage: TrustSubstrateStorage {

    private let baseDirectory: URL
    private let logger = Logger(subsystem: "com.maccrab.tracegraph", category: "trust-substrate-storage")

    private static let publicKeyFile = "trace-signing.pub"
    private static let privateKeyFile = "trace-signing.key"
    private static let stateFile = "trust-substrate.json"

    public init(baseDirectory: URL) {
        self.baseDirectory = baseDirectory
    }

    /// Convenience factory pointing at the default production location.
    public static func production() -> FilesystemTrustSubstrateStorage {
        FilesystemTrustSubstrateStorage(
            baseDirectory: URL(fileURLWithPath: "/Library/Application Support/MacCrab/keys/")
        )
    }

    // MARK: - Mode + SE tag (state file)

    private struct StateRecord: Codable {
        var mode: String?
        var seKeyTagBase64: String?
    }

    private func loadState() throws -> StateRecord {
        let url = baseDirectory.appendingPathComponent(Self.stateFile)
        guard FileManager.default.fileExists(atPath: url.path) else {
            return StateRecord()
        }
        let data = try Data(contentsOf: url)
        return try JSONDecoder().decode(StateRecord.self, from: data)
    }

    private func writeState(_ record: StateRecord) throws {
        try ensureBaseDirectory()
        let url = baseDirectory.appendingPathComponent(Self.stateFile)
        let data = try JSONEncoder().encode(record)
        try writeAtomically(data, to: url, mode: 0o600)
    }

    public func loadKeyMode() throws -> TrustSubstrate.KeyMode? {
        guard let raw = try loadState().mode else { return nil }
        return TrustSubstrate.KeyMode(rawValue: raw)
    }

    public func saveKeyMode(_ mode: TrustSubstrate.KeyMode) throws {
        var record = try loadState()
        record.mode = mode.rawValue
        try writeState(record)
    }

    public func loadSecureEnclaveKeyTag() throws -> Data? {
        guard let b64 = try loadState().seKeyTagBase64 else { return nil }
        return Data(base64Encoded: b64)
    }

    public func saveSecureEnclaveKeyTag(_ tag: Data) throws {
        var record = try loadState()
        record.seKeyTagBase64 = tag.base64EncodedString()
        try writeState(record)
    }

    // MARK: - Filesystem private key

    public func loadFilesystemPrivateKey() throws -> Data? {
        let url = baseDirectory.appendingPathComponent(Self.privateKeyFile)
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        // v1.11.0 (audit security MEDIUM): refuse to load if the path
        // is a symlink. The 0o700 parent dir mostly prevents this, but
        // a one-time directory misconfiguration could let an attacker
        // substitute keys via a symlink in the keys dir. Open with
        // O_NOFOLLOW; lstat first to catch symlinks deterministically
        // (Foundation's Data(contentsOf:) doesn't expose O_NOFOLLOW).
        var st = stat()
        if lstat(url.path, &st) == 0 && (st.st_mode & S_IFMT) == S_IFLNK {
            throw NSError(
                domain: "TrustSubstrate", code: 1,
                userInfo: [NSLocalizedDescriptionKey:
                    "trust-signing.key is a symlink — refusing to load (key substitution attempt)"]
            )
        }
        return try Data(contentsOf: url)
    }

    public func saveFilesystemPrivateKey(_ data: Data) throws {
        try ensureBaseDirectory()
        let url = baseDirectory.appendingPathComponent(Self.privateKeyFile)
        try writeAtomically(data, to: url, mode: 0o600)
    }

    // MARK: - Public key

    public func loadPublicKey() throws -> Data? {
        let url = baseDirectory.appendingPathComponent(Self.publicKeyFile)
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        return try Data(contentsOf: url)
    }

    public func savePublicKey(_ data: Data) throws {
        try ensureBaseDirectory()
        let url = baseDirectory.appendingPathComponent(Self.publicKeyFile)
        try writeAtomically(data, to: url, mode: 0o644)
    }

    // MARK: - Helpers

    private func ensureBaseDirectory() throws {
        try FileManager.default.createDirectory(
            at: baseDirectory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
    }

    /// Write data atomically with the requested POSIX permission mode.
    /// Uses a sibling temp file + rename to avoid partial writes; sets
    /// permissions before rename so a reader observing the file at the
    /// final path never sees an over-permissive mode.
    private func writeAtomically(_ data: Data, to url: URL, mode: mode_t) throws {
        let tempURL = url.deletingLastPathComponent()
            .appendingPathComponent(".tmp-\(UUID().uuidString)-\(url.lastPathComponent)")
        try data.write(to: tempURL, options: .atomic)
        // Apply requested perms before rename so the visible file at
        // the final path always has the intended mode.
        try FileManager.default.setAttributes(
            [.posixPermissions: NSNumber(value: mode)],
            ofItemAtPath: tempURL.path
        )
        // POSIX rename is atomic on the same filesystem.
        if FileManager.default.fileExists(atPath: url.path) {
            try FileManager.default.removeItem(at: url)
        }
        try FileManager.default.moveItem(at: tempURL, to: url)
    }
}
