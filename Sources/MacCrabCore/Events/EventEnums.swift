// EventEnums.swift
// MacCrabCore
//
// Enumerations for the MacCrab event model.
// All enums use ECS-compatible naming for Sigma rule compatibility.

import Foundation

// MARK: - EventCategory

/// Categorizes events using ECS event.category values.
public enum EventCategory: String, Codable, Sendable, Hashable, CaseIterable {
    case process
    case file
    case network
    case authentication
    case tcc
    case registry
}

// MARK: - EventType

/// Describes the type of action using ECS event.type values.
public enum EventType: String, Codable, Sendable, Hashable, CaseIterable {
    case creation
    case deletion
    case change
    case start
    case end
    case connection
    case info
}

// MARK: - FileAction

/// Specific file operation that triggered the event.
public enum FileAction: String, Codable, Sendable, Hashable, CaseIterable {
    case create
    case write
    case rename
    case delete
    case close
    case link
}

// MARK: - NetworkDirection

/// Direction of a network connection relative to the host.
public enum NetworkDirection: String, Codable, Sendable, Hashable, CaseIterable {
    case inbound
    case outbound
}

// MARK: - Severity

/// Alert severity levels, ordered from least to most severe.
public enum Severity: String, Codable, Sendable, Hashable, CaseIterable, Comparable {
    case informational
    case low
    case medium
    case high
    case critical

    private var ordinal: Int {
        switch self {
        case .informational: return 0
        case .low: return 1
        case .medium: return 2
        case .high: return 3
        case .critical: return 4
        }
    }

    public static func < (lhs: Severity, rhs: Severity) -> Bool {
        lhs.ordinal < rhs.ordinal
    }
}

// MARK: - SignerType

/// Code signature origin, from most trusted to unsigned.
public enum SignerType: String, Codable, Sendable, Hashable, CaseIterable {
    case apple
    case appStore
    case devId
    case adHoc
    case unsigned

    /// CS_VALID from <sys/codesign.h> — the only signing flag this
    /// classification needs. Not exposed to Swift, so redeclared here.
    private static let csValid: UInt32 = 0x00000001

    /// Classify a process's signer from the kernel-attested code-signing
    /// signals. Shared by the Endpoint Security collector (`ESHelpers`) and
    /// the eslogger fallback parser (`EsloggerParser`) so the two paths can
    /// never drift in how they trust a binary.
    ///
    /// `isPlatformBinary` is the ONLY signal trusted to promote a process to
    /// `.apple`: it is set by the kernel for genuine Apple platform binaries
    /// (e.g. `/usr/libexec/nehelper`, which carry a valid Apple signature with
    /// an EMPTY team_id). The code signature's *signing identifier* is NOT a
    /// trust input — it is the developer-chosen `Identifier=` field and any
    /// third party can set it to `com.apple.*`, so it must never be used to
    /// classify a binary as Apple (v1.17.1 spoofing fix).
    public static func classify(
        codesigningFlags: UInt32,
        teamId: String,
        isPlatformBinary: Bool
    ) -> SignerType {
        guard codesigningFlags & csValid != 0 else { return .unsigned }
        if isPlatformBinary { return .apple }
        if !teamId.isEmpty { return .devId }
        return .adHoc
    }
}
