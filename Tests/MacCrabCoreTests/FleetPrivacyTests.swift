// FleetPrivacyTests.swift
//
// Pins the fix for the fleet-telemetry username leak: FleetTelemetry's header
// promises "no user names", but processPath / context shipped raw
// (/Users/<name>/...) before redaction was added at the struct-init boundary.
// These assert the username is scrubbed in both the stored value AND the
// encoded JSON that actually leaves the host — while the IOC value survives.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("Fleet telemetry privacy")
struct FleetPrivacyTests {

    @Test("FleetAlertSummary redacts the username out of processPath")
    func alertSummaryRedacts() throws {
        let a = FleetAlertSummary(
            ruleId: "r1", ruleTitle: "t", severity: "high",
            processPath: "/Users/alice/Library/Application Support/evil",
            mitreTechniques: "attack.t1059", timestamp: Date(timeIntervalSince1970: 0))
        #expect(!a.processPath.contains("alice"))
        #expect(a.processPath.contains("[USER]"))
        let json = String(data: try JSONEncoder().encode(a), encoding: .utf8) ?? ""
        #expect(!json.contains("alice"), "encoded fleet alert leaks the username")
    }

    @Test("FleetBehaviorScore redacts the username out of processPath")
    func behaviorScoreRedacts() throws {
        let b = FleetBehaviorScore(processPath: "/Users/bob/.cargo/bin/tool",
                                   score: 9.9, topIndicators: ["unsigned"])
        #expect(!b.processPath.contains("bob"))
        let json = String(data: try JSONEncoder().encode(b), encoding: .utf8) ?? ""
        #expect(!json.contains("bob"), "encoded fleet behavior score leaks the username")
    }

    @Test("FleetIOCSighting scrubs context PII but preserves the IOC value")
    func iocSightingPreservesValueRedactsContext() throws {
        let s = FleetIOCSighting(type: "ip", value: "203.0.113.5",
                                 context: "/Users/carol/suspicious",
                                 timestamp: Date(timeIntervalSince1970: 0))
        #expect(s.value == "203.0.113.5", "the IOC value must NOT be redacted")
        #expect(!s.context.contains("carol"), "fleet IOC context leaks the username")
    }
}
