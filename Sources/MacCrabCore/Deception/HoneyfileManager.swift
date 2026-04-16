// HoneyfileManager.swift
// MacCrabCore
//
// Deception tier: deploys canary files at standard credential locations
// (e.g. ~/.aws/credentials.bak, ~/.ssh/id_rsa.old). Any read or write of
// a deployed honeyfile by a non-MacCrab process is a strong intrusion
// signal — legitimate software never touches these decoy paths.
//
// Maps to MITRE D3FEND D3-DF (Decoy File).
//
// Scope of this module: deployment + a fast `isHoneyfile(_:)` lookup
// callers can use to classify file events. Integration with the file
// event pipeline lives in the daemon hot path — that's the consumer.

import Foundation
import os.log

// MARK: - HoneyfileManager

public actor HoneyfileManager {

    /// MITRE D3FEND technique: D3-DF (Decoy File).
    public nonisolated static let d3fend = D3FENDMapping.honeyfile

    // MARK: - Types

    /// Kind of credential store being imitated. Lets consumers (SOC
    /// dashboards, threat hunters) filter by what's at stake.
    public enum HoneyfileType: String, Codable, Sendable, CaseIterable {
        case awsCredentials       = "aws_credentials"
        case sshPrivateKey        = "ssh_private_key"
        case kubeConfig           = "kube_config"
        case netrc                = "netrc"
        case browserPasswords     = "browser_passwords"
        case keychainBackup       = "keychain_backup"
        case gcpServiceAccount    = "gcp_service_account"
        case dockerConfig         = "docker_config"
    }

    /// One deployed honeyfile entry. Stored in the on-disk manifest.
    public struct Honeyfile: Sendable, Codable, Hashable {
        public let path: String
        public let type: HoneyfileType
        public let deployedAt: Date
        /// SHA-256 of the content at deploy time — used to detect tampering.
        public let contentSHA256: String

        public init(path: String, type: HoneyfileType, deployedAt: Date, contentSHA256: String) {
            self.path = path
            self.type = type
            self.deployedAt = deployedAt
            self.contentSHA256 = contentSHA256
        }
    }

    /// Snapshot of what's on disk vs. what we think we deployed.
    public struct Status: Sendable, Equatable {
        public let deployed: [Honeyfile]       // present and unchanged
        public let missing: [Honeyfile]        // in manifest, gone from disk
        public let tampered: [Honeyfile]       // present but content changed

        public var total: Int { deployed.count + missing.count + tampered.count }
    }

    // MARK: - Errors

    public enum HoneyfileError: Error, LocalizedError, Equatable {
        case pathExistsWithRealContent(String)
        case writeFailed(path: String, reason: String)
        case manifestCorrupted(String)

        public var errorDescription: String? {
            switch self {
            case .pathExistsWithRealContent(let p):
                return "Refusing to overwrite existing file at \(p) — deploy only replaces manifest-tracked honeyfiles"
            case .writeFailed(let p, let r):
                return "Failed to write honeyfile at \(p): \(r)"
            case .manifestCorrupted(let r):
                return "Honeyfile manifest corrupted: \(r)"
            }
        }
    }

    // MARK: - State

    private let logger = Logger(subsystem: "com.maccrab.deception", category: "honeyfile-manager")
    private let homeDir: String
    private let manifestURL: URL

    /// path → entry, fast lookup for isHoneyfile().
    private var deployed: [String: Honeyfile] = [:]

    // MARK: - Init

    /// - Parameters:
    ///   - homeDir: Override for tilde expansion (tests use this).
    ///   - manifestPath: Where to persist deployed honeyfile records.
    ///     Defaults to MacCrab's support dir.
    public init(
        homeDir: String = NSHomeDirectory(),
        manifestPath: String? = nil
    ) {
        self.homeDir = homeDir
        let path = manifestPath
            ?? "\(homeDir)/Library/Application Support/MacCrab/honeyfiles.json"
        self.manifestURL = URL(fileURLWithPath: path)
        Task { await self.loadManifest() }
    }

    // MARK: - Public API

    /// Deploy every honeyfile in the default set whose path is currently
    /// absent. Returns the entries that were freshly written.
    ///
    /// Never overwrites an existing file with different content — if the
    /// user has real data at a honeyfile path, that path is skipped.
    @discardableResult
    public func deploy() throws -> [Honeyfile] {
        var written: [Honeyfile] = []
        for entry in Self.defaultHoneyfileSet(homeDir: homeDir) {
            let expandedPath = entry.path
            let dir = (expandedPath as NSString).deletingLastPathComponent

            // Create parent dir if missing.
            try? FileManager.default.createDirectory(
                atPath: dir, withIntermediateDirectories: true
            )

            // Refuse to clobber real user data.
            if FileManager.default.fileExists(atPath: expandedPath),
               deployed[expandedPath] == nil {
                throw HoneyfileError.pathExistsWithRealContent(expandedPath)
            }

            let data = entry.content.data(using: .utf8) ?? Data()
            do {
                try data.write(to: URL(fileURLWithPath: expandedPath), options: .atomic)
            } catch {
                throw HoneyfileError.writeFailed(
                    path: expandedPath,
                    reason: error.localizedDescription
                )
            }

            // 0o400 — read-only for owner; credential files that mode matches
            // real `chmod 400` AWS/SSH key conventions, strengthening the bait.
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o400], ofItemAtPath: expandedPath
            )

            // Age the mtime so the file looks lived-in (90 days ago).
            try? FileManager.default.setAttributes(
                [.modificationDate: Date(timeIntervalSinceNow: -90 * 86400)],
                ofItemAtPath: expandedPath
            )

            let sha = Self.sha256Hex(data)
            let record = Honeyfile(
                path: expandedPath,
                type: entry.type,
                deployedAt: Date(),
                contentSHA256: sha
            )
            deployed[expandedPath] = record
            written.append(record)
            logger.info("Deployed honeyfile at \(expandedPath, privacy: .public)")
        }
        saveManifest()
        return written
    }

    /// Remove every manifest-tracked honeyfile from disk. Files the user
    /// has modified (tamper state) are still removed — the tamper signal
    /// should have already fired. Returns the entries removed.
    @discardableResult
    public func remove() -> [Honeyfile] {
        var removed: [Honeyfile] = []
        for entry in deployed.values {
            try? FileManager.default.removeItem(atPath: entry.path)
            removed.append(entry)
            logger.info("Removed honeyfile at \(entry.path, privacy: .public)")
        }
        deployed.removeAll()
        saveManifest()
        return removed
    }

    /// Return a snapshot comparing manifest to disk. Useful for the
    /// dashboard and for alerting on unexpected tampering.
    public func status() -> Status {
        var present: [Honeyfile] = []
        var missing: [Honeyfile] = []
        var tampered: [Honeyfile] = []

        for entry in deployed.values {
            guard let data = FileManager.default.contents(atPath: entry.path) else {
                missing.append(entry)
                continue
            }
            if Self.sha256Hex(data) == entry.contentSHA256 {
                present.append(entry)
            } else {
                tampered.append(entry)
            }
        }
        return Status(deployed: present, missing: missing, tampered: tampered)
    }

    /// Fast O(1) check used by file event handlers.
    public func isHoneyfile(_ path: String) -> Bool {
        deployed[path] != nil
    }

    /// Full entry for a honeyfile path (for alert enrichment).
    public func honeyfile(atPath path: String) -> Honeyfile? {
        deployed[path]
    }

    /// Current deployed count (diagnostics).
    public func deployedCount() -> Int { deployed.count }

    // MARK: - Manifest persistence

    private func loadManifest() {
        guard let data = try? Data(contentsOf: manifestURL) else { return }
        do {
            let entries = try JSONDecoder().decode([Honeyfile].self, from: data)
            deployed = Dictionary(uniqueKeysWithValues: entries.map { ($0.path, $0) })
        } catch {
            logger.error("Honeyfile manifest decode failed: \(error.localizedDescription)")
        }
    }

    private func saveManifest() {
        let entries = Array(deployed.values).sorted { $0.path < $1.path }
        do {
            try FileManager.default.createDirectory(
                at: manifestURL.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let data = try encoder.encode(entries)
            try data.write(to: manifestURL, options: .atomic)
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o600], ofItemAtPath: manifestURL.path
            )
        } catch {
            logger.error("Honeyfile manifest write failed: \(error.localizedDescription)")
        }
    }

    // MARK: - Canary content library
    //
    // Each entry uses a recognisable "canary" marker in the value field
    // (e.g. "AKIACANARY..." for AWS) so SIEMs and cloud audit pipelines
    // can alert upstream if the token is ever used.

    nonisolated static func defaultHoneyfileSet(homeDir: String) -> [(path: String, type: HoneyfileType, content: String)] {
        [
            (
                path: "\(homeDir)/.aws/credentials.bak",
                type: .awsCredentials,
                content: """
                [default]
                aws_access_key_id = AKIACANARYCRAB00XYZW
                aws_secret_access_key = CANARY+DO_NOT_USE+TOKEN+AAAAAAAAAAAAAAAAAAAAAA
                region = us-east-1
                """
            ),
            (
                path: "\(homeDir)/.ssh/id_rsa.old",
                type: .sshPrivateKey,
                content: """
                -----BEGIN OPENSSH PRIVATE KEY-----
                b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
                NhAAAAAwEAAQAAAYEAC4NARY_DO_NOT_USE_THIS_KEY_IT_IS_A_HONEYTOKEN_PLACED
                BY_MACCRAB_FOR_INTRUSION_DETECTION_AND_CONTAINS_NO_REAL_ENTROPY00000
                -----END OPENSSH PRIVATE KEY-----
                """
            ),
            (
                path: "\(homeDir)/.kube/config.backup",
                type: .kubeConfig,
                content: """
                apiVersion: v1
                kind: Config
                clusters:
                - name: canary-cluster
                  cluster:
                    server: https://kube.canary.invalid:6443
                users:
                - name: canary-admin
                  user:
                    token: canary.do.not.use.maccrab.honeytoken.0000
                """
            ),
            (
                path: "\(homeDir)/.netrc.backup",
                type: .netrc,
                content: """
                machine api.canary.invalid
                login canary
                password CANARY_MACCRAB_HONEYTOKEN_DO_NOT_USE
                """
            ),
            (
                path: "\(homeDir)/Library/Application Support/Passwords.backup",
                type: .keychainBackup,
                content: """
                # EXPORTED KEYCHAIN BACKUP (canary)
                # This file is a MacCrab deception honeytoken. If any read is
                # observed by a non-MacCrab process, treat as active intrusion.
                """
            ),
            (
                path: "\(homeDir)/Documents/passwords_backup.csv",
                type: .browserPasswords,
                content: """
                url,username,password
                https://canary.invalid,canary,CANARY_MACCRAB_00000000
                https://admin.canary.invalid,root,CANARY_MACCRAB_00000001
                """
            ),
            (
                path: "\(homeDir)/.docker/config.json.bak",
                type: .dockerConfig,
                content: """
                {
                  "_comment": "CANARY MacCrab honeytoken — do not use",
                  "auths": {
                    "ghcr.canary.invalid": {
                      "auth": "Y2FuYXJ5OkNBTkFSWV9ET19OT1RfVVNF"
                    }
                  }
                }
                """
            ),
            (
                path: "\(homeDir)/.gcp-service-account.json.bak",
                type: .gcpServiceAccount,
                content: """
                {
                  "type": "service_account",
                  "project_id": "canary-maccrab",
                  "private_key_id": "canary00000000000000000000000000000000",
                  "client_email": "canary@maccrab-honeytoken.invalid",
                  "client_id": "000000000000000000000"
                }
                """
            ),
        ]
    }

    // MARK: - SHA-256 helper

    nonisolated static func sha256Hex(_ data: Data) -> String {
        // Inline CryptoKit-based hash to avoid pulling FileHasher into the
        // Deception module. Deception events are low-frequency, so inline
        // hashing of small files (KB) is fine.
        import_CryptoKit.hash(data)
    }
}

// MARK: - Local CryptoKit shim
//
// `import CryptoKit` at the top would pull it into every type, which is
// fine but makes the static-helper's scope harder to read. Shimming here
// keeps the main actor focused on deception logic.

import CryptoKit

private enum import_CryptoKit {
    static func hash(_ data: Data) -> String {
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
