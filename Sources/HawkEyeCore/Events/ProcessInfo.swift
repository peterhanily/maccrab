// ProcessInfo.swift
// HawkEyeCore
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
        isPlatformBinary: Bool = false
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
    }
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

    public init(
        signerType: SignerType,
        teamId: String? = nil,
        signingId: String? = nil,
        authorities: [String] = [],
        flags: UInt32 = 0,
        isNotarized: Bool = false
    ) {
        self.signerType = signerType
        self.teamId = teamId
        self.signingId = signingId
        self.authorities = authorities
        self.flags = flags
        self.isNotarized = isNotarized
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
