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

    /// v1.21.4 (P6 fix): the subject process's real audit identity
    /// (pidversion/asid/uids from the ES `audit_token`), when this event came
    /// from Endpoint Security. Nil for non-ES sources (eslogger / FSEvents dev
    /// fallback). Load-bearing for agent-trace correlation: the TraceRegistry
    /// binding is keyed on the FULL `AuditIdentity`, so the correlator must
    /// reconstruct the SAME identity to match it — it cannot be synthesized
    /// with zeroed pidversion/asid (which is exactly why direct correlation
    /// silently missed before this field existed).
    public let auditIdentity: AuditIdentity?

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
        envVars: [String: String]? = nil,
        auditIdentity: AuditIdentity? = nil
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
        self.auditIdentity = auditIdentity
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
    /// True only when `sha256` was read from APFS the system mounted (such as
    /// the startup disk), from the very file identity (device, inode, size,
    /// mtime, ctime) the kernel reported for the exec'd image. A volume a
    /// user mounted can be detached, edited offline and attached again with
    /// that identity intact, and HFS+, FAT and exFAT keep times too coarse to
    /// tell a same-size rewrite apart, so no digest read there is bound. The
    /// identity is evidence, not proof: a write through a shared mapping
    /// keeps it until flushed. Any other digest is of whatever the path held
    /// when it was hashed: it identifies bytes for reputation lookups, but it
    /// must never authorize a suppression or any other trust decision.
    public let imageBound: Bool?

    public init(sha256: String? = nil, cdhash: String? = nil, md5: String? = nil, imageBound: Bool? = nil) {
        self.sha256 = sha256
        self.cdhash = cdhash
        self.md5 = md5
        self.imageBound = imageBound
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
    /// Attribution was UNRESOLVED and this is because a kernel telemetry gap
    /// (ES per-client-queue backpressure) was active for the event's window
    /// while the ancestor chain came back empty. Distinguishes an honest
    /// "the lineage was lost to a drop" from a benign orphan (`.unknown`).
    /// The raw value is the sentinel written to `events.session_launch_source`
    /// (see EventStore column 44). Every reader in-tree consumes LaunchSource
    /// via `.rawValue` (no exhaustive switch), so this case is additive.
    case telemetryGap = "telemetry_gap"
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

    /// The code directory hash of the image the process runs, as the kernel
    /// reports it with the event: lowercase hex of its 20 bytes, nil when the
    /// producer had none. The enricher believes a Security verdict about the
    /// file at the process's path only when this hash is among that file's
    /// code directory hashes. Transport only: it is not encoded and takes no
    /// part in equality or hashing, so a signature persists and compares the
    /// same with or without it.
    public private(set) var kernelCdhash: String? = nil

    /// Every field but `kernelCdhash`.
    private enum CodingKeys: String, CodingKey {
        case signerType, teamId, signingId, authorities, flags, isNotarized
        case issuerChain, certHashes, isAdhocSigned, entitlements
    }

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
        entitlements: [String]? = nil,
        kernelCdhash: String? = nil
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
        self.kernelCdhash = kernelCdhash
    }

    public static func == (lhs: CodeSignatureInfo, rhs: CodeSignatureInfo) -> Bool {
        lhs.signerType == rhs.signerType && lhs.teamId == rhs.teamId
            && lhs.signingId == rhs.signingId && lhs.authorities == rhs.authorities
            && lhs.flags == rhs.flags && lhs.isNotarized == rhs.isNotarized
            && lhs.issuerChain == rhs.issuerChain && lhs.certHashes == rhs.certHashes
            && lhs.isAdhocSigned == rhs.isAdhocSigned && lhs.entitlements == rhs.entitlements
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(signerType)
        hasher.combine(teamId)
        hasher.combine(signingId)
        hasher.combine(authorities)
        hasher.combine(flags)
        hasher.combine(isNotarized)
        hasher.combine(issuerChain)
        hasher.combine(certHashes)
        hasher.combine(isAdhocSigned)
        hasher.combine(entitlements)
    }

    /// Lowercase hex of a code directory hash of the length the kernel
    /// reports, 20 bytes (a longer digest truncated); nil for any other
    /// length and for the all-zero hash the kernel reports for code without
    /// one.
    public static func kernelCdhash<Bytes: Collection>(bytes: Bytes) -> String? where Bytes.Element == UInt8 {
        guard bytes.count == 20, bytes.contains(where: { $0 != 0 }) else { return nil }
        // A table lookup per nibble: this runs for every ES event.
        var ascii = [UInt8]()
        ascii.reserveCapacity(40)
        for byte in bytes {
            ascii.append(hexDigits[Int(byte >> 4)])
            ascii.append(hexDigits[Int(byte & 0x0f)])
        }
        return String(decoding: ascii, as: UTF8.self)
    }

    private static let hexDigits: [UInt8] = Array("0123456789abcdef".utf8)

    /// `kernelCdhash(bytes:)` for a hash written as 40 hex digits, as
    /// eslogger writes it.
    public static func kernelCdhash(hex: String) -> String? {
        let digits = hex.utf8
        guard digits.count == 40,
              digits.allSatisfy({ (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) }),
              digits.contains(where: { $0 != 48 }) else { return nil }
        return hex.lowercased()
    }

    /// A copy carrying `cdhash` as the running image's code directory hash.
    func withKernelCdhash(_ cdhash: String?) -> CodeSignatureInfo {
        var copy = self
        copy.kernelCdhash = cdhash
        return copy
    }

    /// True when the signature attests nothing about who signed it: CS_ADHOC
    /// in `flags`, an ad-hoc verdict from the collector or from Security, or
    /// the `.adHoc` signer. Its team and identifier are the author's choice.
    public var isAdHocFlagged: Bool {
        flags & SignerType.csAdhoc != 0 || isAdhocSigned == true || signerType == .adHoc
    }

    /// The team a certificate chain attests, or nil. An ad-hoc signature or
    /// an unsigned binary names no team worth a decision, whatever string it
    /// carries, so every team-based exemption reads this and never `teamId`.
    public var attestedTeamId: String? {
        guard let teamId, !teamId.isEmpty, !isAdHocFlagged, signerType != .unsigned else { return nil }
        return teamId
    }

    /// Return a copy with a corrected `signerType`, preserving every other
    /// field. Used by EventEnricher's v1.17.2 anti-spoof re-verification: a
    /// collector-side `.apple` classification derived from the
    /// attacker-controllable `com.apple.*` signing identifier is downgraded to
    /// the cryptographically-verified signer (`anchor apple` check) when the
    /// two disagree.
    public func withSignerType(_ newSignerType: SignerType) -> CodeSignatureInfo {
        CodeSignatureInfo(
            signerType: newSignerType,
            teamId: teamId,
            signingId: signingId,
            authorities: authorities,
            flags: flags,
            isNotarized: isNotarized,
            issuerChain: issuerChain,
            certHashes: certHashes,
            isAdhocSigned: isAdhocSigned,
            entitlements: entitlements,
            kernelCdhash: kernelCdhash
        )
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
