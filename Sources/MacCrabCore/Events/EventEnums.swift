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
    /// Two Apple signals are used:
    ///  - `isPlatformBinary` (kernel-attested, UNSPOOFABLE): genuine Apple OS
    ///    components such as `/usr/libexec/nehelper`, which carry a valid Apple
    ///    signature with an EMPTY team_id. Checked first.
    ///  - a `com.apple.*` signing identifier on a binary that ALSO has a
    ///    non-empty team_id: Apple's own NON-platform apps (Xcode, iWork) are
    ///    signed this way, so this is required to keep them classified `.apple`
    ///    rather than tripping the ~126 SignerType:apple-negated rules.
    ///
    /// NOTE on the `com.apple.*` identifier: it is the developer-chosen
    /// `Identifier=` field, so a third party holding a Developer ID cert could
    /// self-name `com.apple.*` and reach `.apple` HERE (this is a cheap,
    /// collector-side classification with no crypto). That spoof is closed
    /// DOWNSTREAM in v1.17.2: `EventEnricher.enrich` re-verifies any
    /// (.apple AND NOT platform-binary) classification against the
    /// cryptographic `anchor apple` SecRequirement (LRU-cached) and downgrades
    /// a non-anchored binary to its real signer. The identifier check is also
    /// gated on a non-empty team_id so an AD-HOC binary (empty team_id) can
    /// never use it — that gate is the v1.17.1 hardening (a brief hoist had let
    /// ad-hoc `com.apple.*` binaries reach `.apple`).
    public static func classify(
        codesigningFlags: UInt32,
        teamId: String,
        signingId: String,
        isPlatformBinary: Bool
    ) -> SignerType {
        guard codesigningFlags & csValid != 0 else { return .unsigned }
        if isPlatformBinary { return .apple }
        if !teamId.isEmpty {
            if signingId.hasPrefix("com.apple.") { return .apple }
            return .devId
        }
        return .adHoc
    }
}
