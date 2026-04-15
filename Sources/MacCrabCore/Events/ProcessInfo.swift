// ProcessInfo.swift
// MacCrabCore
//
// Process metadata captured at event time.
// Field names follow the Elastic Common Schema (ECS) for Sigma compatibility.

import Foundation

// MARK: - ProcessInfo

/// Describes the process that caused an event.
///
/// Always present on every `Event`. Fields map to ECS `process.*` and
/// Sigma `Image`, `CommandLine`, `User`, etc.
public struct ProcessInfo: Codable, Sendable, Hashable {

    // MARK: Identity

    /// Process ID.
    public let pid: Int32

    /// Parent process ID.
    public let ppid: Int32

    /// Responsible PID (macOS-specific; the process held accountable by the system).
    public let rpid: Int32

    /// Process name (basename of the executable).
    public let name: String

    /// Full path to the executable on disk (ECS `process.executable`, Sigma `Image`).
    public let executable: String

    /// Full command line as a single string (ECS `process.command_line`, Sigma `CommandLine`).
    public let commandLine: String

    /// Individual command-line arguments.
    public let args: [String]

    /// Working directory at the time the process was captured.
    public let workingDirectory: String

    // MARK: User / Group

    /// Numeric user ID of the process owner.
    public let userId: UInt32

    /// User name of the process owner (ECS `user.name`, Sigma `User`).
    public let userName: String

    /// Primary group ID of the process owner.
    public let groupId: UInt32

    // MARK: Timing

    /// Timestamp when the process started.
    public let startTime: Date

    /// Exit code, present only for process-exit events.
    public let exitCode: Int32?

    // MARK: Code Signature

    /// Code-signing information for the executable, if available.
    public let codeSignature: CodeSignatureInfo?

    // MARK: Ancestry

    /// Ordered chain of ancestor processes, starting with the direct parent.
    public let ancestors: [ProcessAncestor]

    // MARK: Platform details

    /// CPU architecture the binary was compiled for (e.g. `"arm64"`, `"x86_64"`).
    public let architecture: String?

    /// Whether the binary is part of the macOS platform (Apple-shipped).
    public let isPlatformBinary: Bool

    // MARK: Enrichment (Phase 1)
    //
    // Nil when not captured. Adding these as Optional keeps existing Codable
    // JSON rows readable (synthesized decodeIfPresent).

    /// File-level hashes of the executable on disk, plus macOS CDHash.
    public let hashes: ProcessHashes?

    /// Session / login context (TTY, SSH remote IP, launch source).
    public let session: SessionInfo?

    /// Environment variables at exec time. Opt-in capture via
    /// `MACCRAB_CAPTURE_ENV=1`. Keys are allowlisted; secret-bearing keys
    /// (AWS_SECRET_*, etc.) are never captured.
    public let envVars: [String: String]?

    // MARK: Initializer

    public init(
        pid: Int32,
        ppid: Int32,
        rpid: Int32,
        name: String,
        executable: String,
        commandLine: String,
        args: [String],
        workingDirectory: String,
        userId: UInt32,
        userName: String,
        groupId: UInt32,
        startTime: Date,
        exitCode: Int32? = nil,
        codeSignature: CodeSignatureInfo? = nil,
        ancestors: [ProcessAncestor] = [],
        architecture: String? = nil,
        isPlatformBinary: Bool = false,
        hashes: ProcessHashes? = nil,
        session: SessionInfo? = nil,
        envVars: [String: String]? = nil
    ) {
        self.pid = pid
        self.ppid = ppid
        self.rpid = rpid
        self.name = name
        self.executable = executable
        self.commandLine = commandLine
        self.args = args
        self.workingDirectory = workingDirectory
        self.userId = userId
        self.userName = userName
        self.groupId = groupId
        self.startTime = startTime
        self.exitCode = exitCode
        self.codeSignature = codeSignature
        self.ancestors = ancestors
        self.architecture = architecture
        self.isPlatformBinary = isPlatformBinary
        self.hashes = hashes
        self.session = session
        self.envVars = envVars
    }
}

// MARK: - ProcessHashes

/// Hash fingerprint for a process and its on-disk executable.
///
/// Field semantics:
/// - `sha256`: SHA-256 of the executable bytes on disk (matches MISP, AbuseIPDB).
/// - `cdhash`: macOS code-directory SHA-1 (matches Apple notarization records).
/// - `md5`: optional MD5 for legacy threat-intel feeds.
public struct ProcessHashes: Codable, Sendable, Hashable {
    public let sha256: String?
    public let cdhash: String?
    public let md5: String?

    public init(sha256: String? = nil, cdhash: String? = nil, md5: String? = nil) {
        self.sha256 = sha256
        self.cdhash = cdhash
        self.md5 = md5
    }
}

// MARK: - SessionInfo

/// Launch / session context for a process.
///
/// Helps distinguish user-initiated activity (Finder, Terminal) from
/// system daemons, scheduled tasks, and remote logins — critical for
/// account-compromise and lateral-movement detection.
public struct SessionInfo: Codable, Sendable, Hashable {

    /// Audit session ID (from audit_token) — groups processes in the same login session.
    public let sessionId: UInt32?

    /// Controlling TTY path (`/dev/ttys000`) or nil if detached.
    public let tty: String?

    /// Original login user, as set by `loginwindow` / `sudo`. Differs from
    /// `ProcessInfo.userName` when the process has changed effective UID.
    public let loginUser: String?

    /// Remote IP parsed from `SSH_CLIENT` / `SSH_CONNECTION` env vars, if present.
    public let sshRemoteIP: String?

    /// How the process was launched.
    public let launchSource: LaunchSource?

    public init(
        sessionId: UInt32? = nil,
        tty: String? = nil,
        loginUser: String? = nil,
        sshRemoteIP: String? = nil,
        launchSource: LaunchSource? = nil
    ) {
        self.sessionId = sessionId
        self.tty = tty
        self.loginUser = loginUser
        self.sshRemoteIP = sshRemoteIP
        self.launchSource = launchSource
    }
}

// MARK: - LaunchSource

/// Coarse classification of how a process was started.
public enum LaunchSource: String, Codable, Sendable, Hashable, CaseIterable {
    case finder
    case terminal
    case ssh
    case launchd
    case cron
    case xpc
    case applescript
    case unknown
}

// MARK: - CodeSignatureInfo

/// Code-signing details for a binary.
public struct CodeSignatureInfo: Codable, Sendable, Hashable {

    /// Type of signer (Apple, App Store, Developer ID, ad-hoc, or unsigned).
    public let signerType: SignerType

    /// Apple Team Identifier (10-character string), if present.
    public let teamId: String?

    /// Signing identifier (usually the bundle ID embedded in the signature).
    public let signingId: String?

    /// Certificate authority chain, ordered from leaf to root.
    public let authorities: [String]

    /// Raw `SecCodeSignatureFlags` value captured from the code signature.
    public let flags: UInt32

    /// Whether the binary has been notarized by Apple.
    public let isNotarized: Bool

    // MARK: Phase 1 additions
    //
    // All Optional so existing Codable JSON rows keep deserializing cleanly.

    /// Certificate issuer common names, ordered leaf → root. Nil = not captured.
    public let issuerChain: [String]?

    /// SHA-256 hex digests for each certificate in the signing chain.
    public let certHashes: [String]?

    /// True when the binary is ad-hoc signed (no Team ID, no notarization).
    public let isAdhocSigned: Bool?

    /// Declared entitlements (opt-in capture — may leak paths).
    public let entitlements: [String]?

    public init(
        signerType: SignerType,
        teamId: String? = nil,
        signingId: String? = nil,
        authorities: [String] = [],
        flags: UInt32 = 0,
        isNotarized: Bool = false,
        issuerChain: [String]? = nil,
        certHashes: [String]? = nil,
        isAdhocSigned: Bool? = nil,
        entitlements: [String]? = nil
    ) {
        self.signerType = signerType
        self.teamId = teamId
        self.signingId = signingId
        self.authorities = authorities
        self.flags = flags
        self.isNotarized = isNotarized
        self.issuerChain = issuerChain
        self.certHashes = certHashes
        self.isAdhocSigned = isAdhocSigned
        self.entitlements = entitlements
    }
}

// MARK: - ProcessAncestor

/// A single entry in the process ancestry chain.
public struct ProcessAncestor: Codable, Sendable, Hashable {

    /// Process ID of the ancestor.
    public let pid: Int32

    /// Full executable path of the ancestor.
    public let executable: String

    /// Process name of the ancestor.
    public let name: String

    public init(pid: Int32, executable: String, name: String) {
        self.pid = pid
        self.executable = executable
        self.name = name
    }
}
