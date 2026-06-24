// D3FENDMappingTests.swift
// Every Prevention / Deception module exposes a valid D3FEND technique
// reference; the central mapping catalog stays in sync with the modules.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("D3FEND mappings")
struct D3FENDMappingTests {

    @Test("Every D3FEND ref has a well-formed id (D3-XXX)")
    func idsWellFormed() {
        for ref in D3FENDMapping.all {
            #expect(ref.id.hasPrefix("D3-"),
                    "Expected 'D3-' prefix, got \(ref.id)")
            #expect(ref.id.count >= 4,
                    "Expected at least 4 chars, got \(ref.id)")
            #expect(!ref.name.isEmpty)
        }
    }

    @Test("URL resolves to d3fend.mitre.org")
    func urlFormat() {
        for ref in D3FENDMapping.all {
            #expect(ref.url.hasPrefix("https://d3fend.mitre.org/technique/d3f:"))
        }
    }

    @Test("Every D3FEND id deep-links to its verified canonical technique slug")
    func canonicalSlugs() {
        // The dotted code (d3f:OTF/) 404s; only the PascalCase artifact
        // NAME resolves. Each slug below was confirmed HTTP 200 against
        // d3fend.mitre.org. Pinning the exact URL here makes a wrong/stale
        // slug fail CI instead of shipping a 404 to the operator (FIQ-3).
        let expected: [String: String] = [
            "D3-DNSBA": "DNSAllowlisting",
            "D3-OTF":   "OutboundTrafficFiltering",
            "D3-PFV":   "FileIntegrityMonitoring",
            "D3-UAP":   "UserAccountPermissions",
            "D3-EAL":   "ExecutableAllowlisting",
            "D3-PL":    "ProcessTermination",
            "D3-FCR":   "NetworkTrafficFiltering",
            "D3-SBV":   "ServiceBinaryVerification",
            "D3-EHPV":  "FileAnalysis",
            "D3-DF":    "DecoyFile",
        ]
        for ref in D3FENDMapping.all {
            guard let slug = expected[ref.id] else {
                Issue.record("no verified canonical slug pinned for \(ref.id)")
                continue
            }
            #expect(ref.url == "https://d3fend.mitre.org/technique/d3f:\(slug)/")
            #expect(D3FENDMapping.ref(forID: ref.id)?.id == ref.id)
        }
    }

    @Test("Prevention modules expose the expected D3FEND ref")
    func preventionModules() {
        #expect(DNSSinkhole.d3fend.id == "D3-DNSBA")
        #expect(NetworkBlocker.d3fend.id == "D3-OTF")
        #expect(PersistenceGuard.d3fend.id == "D3-PFV")
        #expect(TCCRevocation.d3fend.id == "D3-UAP")
        #expect(AIContainment.d3fend.id == "D3-EAL")
        #expect(PanicButton.d3fend.id == "D3-PL")
        #expect(TravelMode.d3fend.id == "D3-FCR")
        #expect(SupplyChainGate.d3fend.id == "D3-SBV")
        #expect(SandboxAnalyzer.d3fend.id == "D3-EHPV")
    }

    @Test("Deception tier maps to D3-DF (Decoy File)")
    func deceptionMapping() {
        #expect(HoneyfileManager.d3fend.id == "D3-DF")
        #expect(HoneyfileManager.d3fend.tactic == .deceive)
    }

    @Test("All mappings cover every tactic used")
    func tacticCoverage() {
        let tactics = Set(D3FENDMapping.all.map(\.tactic))
        #expect(tactics.contains(.harden))
        #expect(tactics.contains(.isolate))
        #expect(tactics.contains(.deceive))
        #expect(tactics.contains(.evict))
    }

    @Test("D3FENDMapping.all has no duplicates")
    func noDuplicates() {
        let ids = D3FENDMapping.all.map(\.id)
        let unique = Set(ids)
        #expect(ids.count == unique.count,
                "Duplicate D3FEND ids in mapping: \(ids)")
    }

    // MARK: - ATT&CK tactic → D3FEND twin (FIQ-3)

    @Test("forTactic maps known ATT&CK tactics to their D3FEND twins")
    func forTacticKnown() {
        #expect(D3FENDMapping.forTactic("attack.command_and_control").map(\.id) == ["D3-OTF", "D3-DNSBA"])
        #expect(D3FENDMapping.forTactic("attack.exfiltration").map(\.id) == ["D3-OTF", "D3-DNSBA"])
        #expect(D3FENDMapping.forTactic("attack.persistence").map(\.id) == ["D3-PFV"])
        #expect(D3FENDMapping.forTactic("attack.privilege_escalation").map(\.id) == ["D3-UAP"])
        #expect(D3FENDMapping.forTactic("attack.execution").map(\.id) == ["D3-EAL"])
        #expect(D3FENDMapping.forTactic("attack.initial_access").map(\.id) == ["D3-SBV"])
        #expect(D3FENDMapping.forTactic("attack.defense_evasion").map(\.id) == ["D3-EHPV"])
    }

    @Test("forTactic accepts the bare tactic name and dashes, normalizes case")
    func forTacticNormalizes() {
        #expect(D3FENDMapping.forTactic("command_and_control").map(\.id) == ["D3-OTF", "D3-DNSBA"])
        #expect(D3FENDMapping.forTactic("Command-And-Control").map(\.id) == ["D3-OTF", "D3-DNSBA"])
    }

    @Test("forTactic returns [] for tactics with no clean preventive twin")
    func forTacticUnknown() {
        #expect(D3FENDMapping.forTactic("attack.discovery").isEmpty)
        #expect(D3FENDMapping.forTactic("attack.impact").isEmpty)
        #expect(D3FENDMapping.forTactic("attack.t1059.004").isEmpty)   // a technique, not a tactic
        #expect(D3FENDMapping.forTactic("nonsense").isEmpty)
    }

    @Test("forTactics unions a CSV and de-duplicates by id, order-preserving")
    func forTacticsCSV() {
        // C2 and exfiltration both map to OTF+DNSBA → de-duped to two.
        #expect(D3FENDMapping.forTactics("attack.command_and_control,attack.exfiltration").map(\.id)
                == ["D3-OTF", "D3-DNSBA"])
        // Mixed tactics accumulate distinct twins.
        #expect(D3FENDMapping.forTactics("attack.persistence, attack.execution").map(\.id)
                == ["D3-PFV", "D3-EAL"])
        #expect(D3FENDMapping.forTactics("").isEmpty)
        #expect(D3FENDMapping.forTactics("attack.discovery").isEmpty)
    }
}
