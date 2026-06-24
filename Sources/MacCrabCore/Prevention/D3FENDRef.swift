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

    /// URL to the technique page on d3fend.mitre.org. The slug is the
    /// canonical PascalCase artifact NAME, not the dotted code —
    /// `d3f:OTF/` 404s, `d3f:OutboundTrafficFiltering/` resolves. The
    /// per-id slugs are kept (and verified) in `D3FENDMapping`.
    public var url: String {
        if let slug = D3FENDMapping.canonicalSlug[id] {
            return "https://d3fend.mitre.org/technique/d3f:\(slug)/"
        }
        // Unknown / non-catalog id — no canonical technique page exists;
        // send the operator to the D3FEND matrix rather than a 404.
        return "https://d3fend.mitre.org/"
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

    /// Canonical d3fend.mitre.org technique slug for each MacCrab
    /// D3FEND id. Several MacCrab ids/names are non-canonical, so the
    /// slug is the nearest REAL D3FEND artifact whose page resolves —
    /// each confirmed HTTP 200 against d3fend.mitre.org (the dotted code
    /// d3f:OTF/ 404s; the PascalCase artifact name resolves). Drives
    /// `D3FENDRef.url` so the dashboard chips + reports deep-link to a
    /// page that exists instead of a fabricated 404.
    public static let canonicalSlug: [String: String] = [
        "D3-DNSBA": "DNSAllowlisting",            // dnsSinkhole
        "D3-OTF":   "OutboundTrafficFiltering",   // networkBlocker
        "D3-PFV":   "FileIntegrityMonitoring",    // persistenceGuard — launch-item integrity
        "D3-UAP":   "UserAccountPermissions",     // tccRevocation
        "D3-EAL":   "ExecutableAllowlisting",     // aiContainment
        "D3-PL":    "ProcessTermination",         // panicButton — kill-and-contain
        "D3-FCR":   "NetworkTrafficFiltering",    // travelMode — stricter firewall profile
        "D3-SBV":   "ServiceBinaryVerification",  // supplyChainGate — binary signature verification
        "D3-EHPV":  "FileAnalysis",               // sandboxAnalyzer — static entitlement/sandbox analysis
        "D3-DF":    "DecoyFile",                  // honeyfile
    ]

    /// Look up a technique by its MacCrab D3FEND id.
    public static func ref(forID id: String) -> D3FENDRef? {
        all.first { $0.id == id }
    }

    // MARK: - ATT&CK tactic → D3FEND defensive twin

    /// Map a single MITRE ATT&CK tactic to the MacCrab prevention
    /// modules (D3FEND techniques) that defend against it. Accepts the
    /// Sigma-style `attack.<tactic>` tag form or the bare tactic name.
    /// Returns `[]` for tactics with no clean preventive twin in
    /// MacCrab's module set (discovery / impact / wireless / cve) and
    /// for unknown tactics — callers treat empty as "no default hint".
    public static func forTactic(_ tactic: String) -> [D3FENDRef] {
        var t = tactic.lowercased()
        if t.hasPrefix("attack.") { t = String(t.dropFirst("attack.".count)) }
        t = t.replacingOccurrences(of: "-", with: "_").replacingOccurrences(of: " ", with: "_")
        switch t {
        case "command_and_control", "exfiltration":
            return [networkBlocker, dnsSinkhole]          // outbound filtering + DNS blackholing
        case "persistence":
            return [persistenceGuard]                     // launch-item file verification
        case "privilege_escalation", "credential_access", "collection":
            return [tccRevocation]                        // tighten reachable permissions
        case "execution", "ai_safety":
            return [aiContainment]                        // executable allowlisting
        case "initial_access", "supply_chain":
            return [supplyChainGate]                      // binary signature verification
        case "defense_evasion":
            return [sandboxAnalyzer]                       // hash + permission verification
        case "lateral_movement":
            return [networkBlocker]                       // segment / filter east-west traffic
        default:
            return []
        }
    }

    /// Union (order-preserving, de-duplicated by id) of the D3FEND
    /// twins for a CSV of `attack.*` tactic tags — the shape stored in
    /// `Alert.mitreTactics`.
    public static func forTactics(_ csv: String) -> [D3FENDRef] {
        var seen = Set<String>()
        var out: [D3FENDRef] = []
        for token in csv.split(separator: ",") {
            for ref in forTactic(token.trimmingCharacters(in: .whitespaces)) where !seen.contains(ref.id) {
                seen.insert(ref.id)
                out.append(ref)
            }
        }
        return out
    }
}
