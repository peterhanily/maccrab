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
}
