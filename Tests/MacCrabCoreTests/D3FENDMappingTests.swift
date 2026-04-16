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
}
