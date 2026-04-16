// D3FENDRef.swift
// MacCrabCore
//
// Map each MacCrab prevention module to a MITRE D3FEND defensive
// technique. D3FEND is the defensive twin of ATT&CK — when an alert
// fires, the dashboard can say "this would have been prevented by
// enabling X" and cite the technique ID for compliance reports.
//
// Reference: https://d3fend.mitre.org/

import Foundation

public struct D3FENDRef: Sendable, Hashable, Codable {
    public let id: String          // e.g. "D3-DNSBA"
    public let name: String        // human-readable technique name
    public let tactic: Tactic      // which D3FEND tactic column

    public enum Tactic: String, Sendable, Codable, CaseIterable {
        case model     = "Model"
        case harden    = "Harden"
        case detect    = "Detect"
        case isolate   = "Isolate"
        case deceive   = "Deceive"
        case evict     = "Evict"
        case restore   = "Restore"
    }

    public init(id: String, name: String, tactic: Tactic) {
        self.id = id
        self.name = name
        self.tactic = tactic
    }

    /// URL to the technique page on d3fend.mitre.org.
    public var url: String {
        "https://d3fend.mitre.org/technique/d3f:\(id.replacingOccurrences(of: "D3-", with: ""))/"
    }
}

// MARK: - Prevention module → D3FEND technique mapping

public enum D3FENDMapping {

    // DNS-level blackholing (d3f:DNSBlackholing, variant: allowlisting mode).
    public static let dnsSinkhole = D3FENDRef(
        id: "D3-DNSBA",
        name: "DNS Blackholing / Allowlisting",
        tactic: .isolate
    )

    // Outbound traffic filtering at the firewall layer.
    public static let networkBlocker = D3FENDRef(
        id: "D3-OTF",
        name: "Outbound Traffic Filtering",
        tactic: .isolate
    )

    // Verifies persistence-path file integrity — LaunchAgents / LaunchDaemons
    // immutability during normal operation.
    public static let persistenceGuard = D3FENDRef(
        id: "D3-PFV",
        name: "Process File Verification",
        tactic: .harden
    )

    // User-Account Permissions — TCC revocation is the macOS expression
    // of tightening user-level authorizations after abuse.
    public static let tccRevocation = D3FENDRef(
        id: "D3-UAP",
        name: "User Account Permissions",
        tactic: .harden
    )

    // Executable allowlisting applied to AI-tool subprocesses.
    public static let aiContainment = D3FENDRef(
        id: "D3-EAL",
        name: "Executable Allowlisting",
        tactic: .harden
    )

    // Kill-and-contain — the emergency big-red-button path.
    public static let panicButton = D3FENDRef(
        id: "D3-PL",
        name: "Process Lockout",
        tactic: .evict
    )

    // Travel Mode = a stricter firewall profile applied on demand.
    public static let travelMode = D3FENDRef(
        id: "D3-FCR",
        name: "Firewall Configuration Rules",
        tactic: .harden
    )

    // Supply chain gating — verify binary signature before allowing a new
    // dependency to land on disk.
    public static let supplyChainGate = D3FENDRef(
        id: "D3-SBV",
        name: "Software Binary Verification",
        tactic: .harden
    )

    // Static analysis of entitlements + sandbox posture.
    public static let sandboxAnalyzer = D3FENDRef(
        id: "D3-EHPV",
        name: "Executable Hashing and Permission Verification",
        tactic: .harden
    )

    // Honeyfile decoy files (Phase 3 deception tier).
    public static let honeyfile = D3FENDRef(
        id: "D3-DF",
        name: "Decoy File",
        tactic: .deceive
    )

    /// Flat list of every MacCrab-emitted D3FEND technique.
    public static let all: [D3FENDRef] = [
        dnsSinkhole, networkBlocker, persistenceGuard, tccRevocation,
        aiContainment, panicButton, travelMode, supplyChainGate,
        sandboxAnalyzer, honeyfile,
    ]
}
