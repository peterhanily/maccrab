// CaseManager — top-level lifecycle owner for cases.
//
// Responsibilities:
//   - Create cases (random id, generate DEK, wrap via DEKVault,
//     create directory structure, write manifest, open ArtifactStore,
//     INSERT cases row).
//   - List cases by reading manifest.json from each case-directory
//     (no unlock required).
//   - Open a case (retrieve DEK from vault — prompts auth in
//     production — open ArtifactStore, return a CaseHandle with
//     ArtifactStore + BlobVault).
//   - Delete a case (close any open handle, delete DEK from vault,
//     remove directory).
//
// Plan reference: §3.4 + §10.4.

import Foundation
import CryptoKit

/// Errors from the case lifecycle.
public enum CaseManagerError: Error, CustomStringConvertible {
    case caseNotFound(id: String)
    case manifestMissing(id: String)
    case manifestDecodeFailed(id: String, message: String)
    case manifestWriteFailed(message: String)
    case directoryCreateFailed(message: String)
    case dekGenerationFailed
    case caseAlreadyExists(id: String)
    /// The supplied case id isn't a valid UUID. Refuse to use it in a
    /// filesystem path — guards against a tampered manifest id steering
    /// removeItem outside the Cases root via "../" or absolute paths.
    case invalidCaseID(id: String)
    /// A case path component is a symlink or a non-regular object. Case data is
    /// same-uid attacker writable, so following it would let open/shred escape
    /// the configured Cases root.
    case unsafeCasePath(path: String)
    /// The unencrypted manifest identity must be bound to its directory name.
    /// Otherwise a tampered manifest can redirect later open/delete operations.
    case manifestIdentityMismatch(expected: String, actual: String)
    /// Encryption state mismatch — the manifest says the case is
    /// .plaintext but a DEK was supplied (or vice versa).
    case encryptionStateMismatch(declared: CaseEncryptionState, suppliedDEK: Bool)

    public var description: String {
        switch self {
        case .caseNotFound(let id):
            return "CaseManager: no case '\(id)' under cases root"
        case .manifestMissing(let id):
            return "CaseManager: manifest.json missing for case '\(id)'"
        case .manifestDecodeFailed(let id, let msg):
            return "CaseManager: manifest.json for '\(id)' didn't decode: \(msg)"
        case .manifestWriteFailed(let msg):
            return "CaseManager: manifest.json write failed: \(msg)"
        case .directoryCreateFailed(let msg):
            return "CaseManager: case directory create failed: \(msg)"
        case .dekGenerationFailed:
            return "CaseManager: SecRandomCopyBytes refused to produce a DEK"
        case .caseAlreadyExists(let id):
            return "CaseManager: case '\(id)' already exists"
        case .invalidCaseID(let id):
            return "CaseManager: '\(id)' is not a valid case id"
        case .unsafeCasePath(let path):
            return "CaseManager: refusing symlink or non-regular case path at '\(path)'"
        case .manifestIdentityMismatch(let expected, let actual):
            return "CaseManager: manifest id '\(actual)' does not match case directory '\(expected)'"
        case .encryptionStateMismatch(let declared, let supplied):
            return "CaseManager: encryption_state=\(declared.rawValue) doesn't match suppliedDEK=\(supplied)"
        }
    }
}

/// An open case. Hold for the duration of operator work; the DEK
/// lives in memory only inside `store` and `vault`. Caller releases
/// by dropping the handle (no explicit close needed — actor deinit
/// closes the SQLite handle).
public struct CaseHandle: Sendable {
    public let caseID: String
    public let store: ArtifactStore
    public let vault: BlobVault?
    public let layout: CaseDirectoryLayout
    public let encryptionState: CaseEncryptionState

    public init(
        caseID: String,
        store: ArtifactStore,
        vault: BlobVault?,
        layout: CaseDirectoryLayout,
        encryptionState: CaseEncryptionState
    ) {
        self.caseID = caseID
        self.store = store
        self.vault = vault
        self.layout = layout
        self.encryptionState = encryptionState
    }
}

public actor CaseManager {

    private let casesRoot: URL
    private let dekVault: any DEKVault
    private let caseDirectoryRemover: @Sendable (URL) throws -> Void

    /// Construct a CaseManager.
    /// - `casesRoot`: defaults to
    ///   `~/Library/Application Support/MacCrab/Cases/`. Tests override.
    /// - `dekVault`: production uses KeychainDEKVault; tests use
    ///   InMemoryDEKVault.
    public init(
        casesRoot: URL = CaseDirectoryLayout.defaultCasesRoot,
        dekVault: any DEKVault,
        caseDirectoryRemover: @escaping @Sendable (URL) throws -> Void = {
            try FileManager.default.removeItem(at: $0)
        }
    ) {
        self.casesRoot = casesRoot
        self.dekVault = dekVault
        self.caseDirectoryRemover = caseDirectoryRemover
    }

    // MARK: - Create

    /// Generate a new case id, DEK, directory structure, manifest,
    /// and the SQLCipher store. Returns a CaseHandle ready for
    /// plugin invocations.
    ///
    /// `encrypted == false` produces a plaintext case (no DEK
    /// generated; no vault entry). Pass 2026-D will reject
    /// non-metadata artifacts on this case at INSERT time.
    public func createCase(
        name: String,
        timeWindow: TimeWindow? = nil,
        notes: String? = nil,
        encrypted: Bool = true
    ) async throws -> CaseHandle {
        let caseID = UUID().uuidString.lowercased()
        let layout = CaseDirectoryLayout(casesRoot: casesRoot, caseID: caseID)
        let state: CaseEncryptionState = encrypted ? .encryptedKeychain : .plaintext

        // Pre-flight: directory must not already exist (UUID
        // collision = ridiculously improbable, but treat the error
        // path cleanly).
        if FileManager.default.fileExists(atPath: layout.caseDirectory.path) {
            throw CaseManagerError.caseAlreadyExists(id: caseID)
        }

        do {
            try layout.createDirectoryStructure()
        } catch {
            throw CaseManagerError.directoryCreateFailed(
                message: error.localizedDescription
            )
        }

        // Everything after the directory is created must roll back
        // atomically: a failure partway through (manifest write, DEK
        // wrap, SQLite open, INSERT, vault init) would otherwise
        // orphan the case directory on disk and — once the DEK is
        // stored — a wrapped key in the keychain. On any throw, delete
        // the DEK (no-op when none was stored) then remove the
        // directory, mirroring deleteCase()'s ordering, and rethrow
        // the original error.
        do {
            // Write manifest BEFORE we touch the SQLite store. The
            // manifest is the lightweight ground truth used by
            // listCases(); if SQLite open fails downstream the
            // operator still sees the case in the list and can clean
            // it up.
            let manifest = CaseManifest(
                id: caseID,
                name: name,
                createdAt: Date(),
                encryptionState: state
            )
            try Self.writeManifest(manifest, to: layout.manifestFile)

            // Generate + wrap DEK (encrypted cases only).
            var dek: Data? = nil
            if encrypted {
                dek = try Self.makeDEK()
                try await dekVault.store(dek: dek!, for: caseID)
            }

            // Open the SQLCipher store, run the schema migration, and
            // INSERT the cases row.
            let store = try await ArtifactStore(
                path: layout.sqliteFile.path,
                dek: dek,
                encryptionState: state
            )
            try await store.insertCase(CaseRecord(
                id: caseID,
                name: name,
                createdAt: manifest.createdAt,
                timeWindowStart: timeWindow?.start,
                timeWindowEnd: timeWindow?.end,
                notes: notes,
                encryptionState: state
            ))

            let vault: BlobVault?
            if let dek = dek {
                vault = try BlobVault(layout: layout, dek: dek)
            } else {
                vault = nil
            }

            return CaseHandle(
                caseID: caseID,
                store: store,
                vault: vault,
                layout: layout,
                encryptionState: state
            )
        } catch {
            // Best-effort rollback. delete(for:) is a no-op when no
            // DEK was stored; removeItem tears down the directory we
            // created above (caseID is a freshly-minted UUID, so no
            // traversal exposure).
            // Preserve recoverability across a partial rollback: remove the
            // failed ciphertext first, then its only key. If removal fails, the
            // key remains available for operator recovery instead of leaving an
            // undecryptable directory behind.
            if (try? caseDirectoryRemover(layout.caseDirectory)) != nil {
                try? await dekVault.delete(for: caseID)
            }
            throw error
        }
    }

    // MARK: - Open

    /// Open an existing case. For encrypted cases, prompts the
    /// operator via DEKVault.retrieve. Returns a CaseHandle.
    public func openCase(id: String) async throws -> CaseHandle {
        try Self.validateCaseID(id)
        let layout = CaseDirectoryLayout(casesRoot: casesRoot, caseID: id)
        guard FileManager.default.fileExists(atPath: layout.caseDirectory.path) else {
            throw CaseManagerError.caseNotFound(id: id)
        }
        try Self.requireDirectoryWithoutSymlink(layout.caseDirectory)
        try Self.requireRegularFileWithoutSymlink(layout.manifestFile)
        let manifest = try Self.readManifest(from: layout.manifestFile, caseID: id)
        guard manifest.id == id else {
            throw CaseManagerError.manifestIdentityMismatch(
                expected: id,
                actual: manifest.id
            )
        }
        try Self.validateSQLiteFamily(at: layout.sqliteFile)

        var dek: Data? = nil
        if manifest.encryptionState != .plaintext {
            dek = try await dekVault.retrieve(for: id)
        }

        let store = try await ArtifactStore(
            path: layout.sqliteFile.path,
            dek: dek,
            encryptionState: manifest.encryptionState
        )
        let vault: BlobVault?
        if let dek = dek {
            vault = try BlobVault(layout: layout, dek: dek)
        } else {
            vault = nil
        }

        return CaseHandle(
            caseID: id,
            store: store,
            vault: vault,
            layout: layout,
            encryptionState: manifest.encryptionState
        )
    }

    // MARK: - List

    /// List cases by reading manifest.json from each case directory.
    /// Operator never has to unlock to enumerate cases.
    public func listCases() async throws -> [CaseManifest] {
        let fm = FileManager.default
        guard fm.fileExists(atPath: casesRoot.path) else {
            return []
        }
        let entries = try fm.contentsOfDirectory(
            at: casesRoot,
            includingPropertiesForKeys: [.isDirectoryKey],
            options: [.skipsHiddenFiles]
        )
        var out: [CaseManifest] = []
        for entry in entries {
            let directoryID = entry.lastPathComponent
            guard UUID(uuidString: directoryID) != nil,
                  Self.isDirectoryWithoutSymlink(entry) else {
                continue
            }
            let manifestPath = entry.appendingPathComponent("manifest.json")
            guard Self.isRegularFileWithoutSymlink(manifestPath) else { continue }
            do {
                let data = try Data(contentsOf: manifestPath)
                let m = try JSONDecoder().decode(CaseManifest.self, from: data)
                guard m.id == directoryID else { continue }
                out.append(m)
            } catch {
                // Skip malformed manifests rather than fail the whole
                // listing. The operator can investigate manually.
                continue
            }
        }
        // Newest first.
        return out.sorted { $0.createdAtMillis > $1.createdAtMillis }
    }

    // MARK: - Delete

    /// Delete a case. `shred = true` overwrites case.sqlite with
    /// random bytes before unlinking (best-effort on modern
    /// flash storage — the gesture is documented at the CLI level).
    public func deleteCase(id: String, shred: Bool = false) async throws {
        // Defense-in-depth: case ids are UUIDs minted by createCase.
        // Reject anything else so a "../" or absolute path in a tampered
        // manifest id can never steer removeItem outside the Cases root.
        try Self.validateCaseID(id)
        let layout = CaseDirectoryLayout(casesRoot: casesRoot, caseID: id)
        guard FileManager.default.fileExists(atPath: layout.caseDirectory.path) else {
            throw CaseManagerError.caseNotFound(id: id)
        }
        try Self.requireDirectoryWithoutSymlink(layout.caseDirectory)

        if shred {
            // Overwrite case.sqlite + WAL + SHM with random bytes
            // BEFORE unlinking. Modern flash with garbage-collection
            // makes this advisory only — but the gesture documents
            // operator intent and we'd want it true on the
            // not-so-rare disks that don't do GC.
            for tail in ["", "-wal", "-shm"] {
                let path = layout.sqliteFile.path + tail
                if FileManager.default.fileExists(atPath: path) {
                    Self.overwriteFileWithRandomBytes(path: path)
                }
            }
        }

        // Filesystem and Keychain do not share a transaction. Preserve evidence
        // on the only failure ordering that matters: remove the directory first,
        // and only after that succeeds erase its sole DEK. The previous ordering
        // permanently locked the operator out whenever removeItem failed.
        try caseDirectoryRemover(layout.caseDirectory)
        try await dekVault.delete(for: id)
    }

    /// v1.18: delete every case created before `cutoff`. Routes through
    /// `deleteCase` so encrypted scans release their keychain DEK (a raw
    /// removeItem would orphan it) and so each id is UUID-validated.
    /// Best-effort: a case that fails to delete is skipped, not fatal.
    /// Returns the ids removed and the bytes reclaimed. This is the
    /// enforcement the "Scan retention" setting (`forensics.retentionDays`)
    /// always promised — previously only the manual "Run cleanup now"
    /// button invoked it; nothing ran it automatically.
    @discardableResult
    public func pruneCases(olderThan cutoff: Date) async -> (deleted: [String], freedBytes: Int64) {
        var deleted: [String] = []
        var freed: Int64 = 0
        let manifests = (try? await listCases()) ?? []
        for manifest in manifests where manifest.createdAt < cutoff {
            let bytes = CaseDirectoryLayout(casesRoot: casesRoot, caseID: manifest.id).diskBytes()
            if (try? await deleteCase(id: manifest.id)) != nil {
                deleted.append(manifest.id)
                freed += bytes
            }
        }
        return (deleted, freed)
    }

    // MARK: - DEK + manifest helpers

    private static func makeDEK() throws -> Data {
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = bytes.withUnsafeMutableBufferPointer {
            SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!)
        }
        guard status == errSecSuccess else {
            throw CaseManagerError.dekGenerationFailed
        }
        return Data(bytes)
    }

    private static func writeManifest(_ manifest: CaseManifest, to url: URL) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        do {
            let data = try encoder.encode(manifest)
            try data.write(to: url, options: [.atomic])
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: url.path
            )
        } catch {
            throw CaseManagerError.manifestWriteFailed(message: error.localizedDescription)
        }
    }

    private static func readManifest(from url: URL, caseID: String) throws -> CaseManifest {
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw CaseManagerError.manifestMissing(id: caseID)
        }
        do {
            let data = try Data(contentsOf: url)
            return try JSONDecoder().decode(CaseManifest.self, from: data)
        } catch {
            throw CaseManagerError.manifestDecodeFailed(
                id: caseID,
                message: error.localizedDescription
            )
        }
    }

    private static func validateCaseID(_ id: String) throws {
        guard UUID(uuidString: id) != nil else {
            throw CaseManagerError.invalidCaseID(id: id)
        }
    }

    private static func isDirectoryWithoutSymlink(_ url: URL) -> Bool {
        var info = stat()
        guard lstat(url.path, &info) == 0 else { return false }
        return (UInt32(info.st_mode) & UInt32(S_IFMT)) == UInt32(S_IFDIR)
    }

    private static func isRegularFileWithoutSymlink(_ url: URL) -> Bool {
        var info = stat()
        guard lstat(url.path, &info) == 0 else { return false }
        return (UInt32(info.st_mode) & UInt32(S_IFMT)) == UInt32(S_IFREG)
    }

    private static func requireDirectoryWithoutSymlink(_ url: URL) throws {
        guard isDirectoryWithoutSymlink(url) else {
            throw CaseManagerError.unsafeCasePath(path: url.path)
        }
    }

    private static func requireRegularFileWithoutSymlink(_ url: URL) throws {
        guard isRegularFileWithoutSymlink(url) else {
            throw CaseManagerError.unsafeCasePath(path: url.path)
        }
    }

    private static func validateSQLiteFamily(at main: URL) throws {
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let url = URL(fileURLWithPath: main.path + suffix)
            var info = stat()
            if lstat(url.path, &info) == 0 {
                guard (UInt32(info.st_mode) & UInt32(S_IFMT)) == UInt32(S_IFREG) else {
                    throw CaseManagerError.unsafeCasePath(path: url.path)
                }
            } else if errno != ENOENT {
                throw CaseManagerError.unsafeCasePath(path: url.path)
            }
        }
    }

    private static func overwriteFileWithRandomBytes(path: String) {
        // O_NOFOLLOW is critical here: --shred must overwrite the case file,
        // never the target of a same-uid attacker's case.sqlite symlink.
        let fd = open(path, O_WRONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { return }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0,
              (UInt32(info.st_mode) & UInt32(S_IFMT)) == UInt32(S_IFREG),
              info.st_size > 0 else { return }
        // Write in 64 KB chunks to avoid huge allocations.
        let chunk = 65_536
        var remaining = Int64(info.st_size)
        while remaining > 0 {
            let n = min(Int64(chunk), remaining)
            var bytes = [UInt8](repeating: 0, count: Int(n))
            let randomStatus = bytes.withUnsafeMutableBufferPointer {
                SecRandomCopyBytes(kSecRandomDefault, Int(n), $0.baseAddress!)
            }
            guard randomStatus == errSecSuccess else { return }
            var offset = 0
            while offset < Int(n) {
                let written = bytes.withUnsafeBytes { raw -> Int in
                    guard let base = raw.baseAddress else { return -1 }
                    return write(fd, base.advanced(by: offset), Int(n) - offset)
                }
                if written < 0, errno == EINTR { continue }
                guard written > 0 else { return }
                offset += written
            }
            remaining -= n
        }
        _ = fsync(fd)
    }
}
