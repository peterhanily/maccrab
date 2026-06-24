// FindingHeuristicsTests.swift
// MacCrabAppTests
//
// FindingHeuristics.severity is ~150 lines of operator-facing "this needs a
// look" classification across ~15 content-type families. A regression here
// silently mislabels real findings as routine — and it feeds ArtifactExporter,
// so a heuristic regression corrupts EXPORTED evidence, not just the UI. One
// assertion per branch pins the contract.

import Testing
import Foundation
@testable import MacCrabApp
import MacCrabForensics

@Suite("FindingHeuristics severity classifier")
struct FindingHeuristicsTests {

    private func art(_ contentType: String,
                     data: [String: JSONValue] = [:],
                     summary: String? = nil) -> CommittedArtifact {
        let rec = ArtifactRecord(
            caseID: "c1", pluginID: "p", pluginVersion: "1",
            schemaVersion: 1, contentType: contentType,
            sha256: "deadbeef", observedAt: Date(),
            summary: summary, privacyClass: .metadata, data: data
        )
        return CommittedArtifact(id: 1, record: rec)
    }

    private func sev(_ ct: String, _ data: [String: JSONValue] = [:], summary: String? = nil) -> FindingSeverity {
        FindingHeuristics.severity(for: art(ct, data: data, summary: summary))
    }

    @Test("Posture / anomaly without a severity field falls back to attention")
    func postureAnomaly() {
        #expect(sev("posture.unsigned_persistence") == .attention)
        #expect(sev("baseline.anomaly_score") == .attention)
    }

    @Test("Posture findings RESPECT the analyzer's committed severity")
    func postureRespectsSeverity() {
        // FIQ-2: a committed-critical and a committed-medium must no
        // longer display identically.
        #expect(sev("posture.high_privilege_unsigned_combo", ["severity": .string("critical")]) == .critical)
        #expect(sev("posture.automation_to_sensitive_target", ["severity": .string("high")]) == .attention)
        #expect(sev("posture.permissioned_persistence", ["severity": .string("medium")]) == .notable)
        #expect(sev("posture.unsigned_persistence", ["severity": .string("low")]) == .routine)
        #expect(sev("posture.analysis_unavailable_encrypted", ["severity": .string("informational")]) == .routine)
        // Unknown severity string surfaces (doesn't hide) → attention.
        #expect(sev("posture.future_type", ["severity": .string("weird")]) == .attention)
    }

    @Test("TCC keys off the engine risk_score when present, legacy fallback otherwise")
    func tccRiskScore() {
        // FIQ-6: bands calibrated to TCCRiskScoring.Weight (≥35 attention,
        // ≥15 notable, else routine). Critical stays posture-only.
        #expect(sev("tcc.grant", ["risk_score": .integer(55)]) == .attention)   // FDA + unknown team
        #expect(sev("tcc.grant", ["risk_score": .integer(35)]) == .attention)   // boundary
        #expect(sev("tcc.grant", ["risk_score": .integer(34)]) == .notable)
        #expect(sev("tcc.grant", ["risk_score": .integer(15)]) == .notable)     // boundary
        #expect(sev("tcc.grant", ["risk_score": .integer(14)]) == .routine)
        #expect(sev("tcc.grant", ["risk_score": .integer(0)]) == .routine)       // addressbook/photos score 0
        // risk_score wins even over a sensitive service name.
        #expect(sev("tcc.grant", ["service": .string("camera"), "risk_score": .integer(0)]) == .routine)
        // No risk_score → legacy service-membership fallback still applies.
        #expect(sev("tcc.grant", ["service": .string("camera"), "client_signed": .bool(false)]) == .attention)
    }

    @Test("Launchd: unsigned or suspicious-path → attention, else routine")
    func launchd() {
        #expect(sev("launchd.agent", ["unsigned": .bool(true)]) == .attention)
        #expect(sev("launchd.agent", ["binary_path": .string("/tmp/payload")]) == .attention)
        #expect(sev("launchd.agent", ["binary_path": .string("/Library/Apple/System/x")]) == .routine)
    }

    @Test("Hosts: non-loopback entry → notable, loopback → routine")
    func hosts() {
        #expect(sev("hosts.entry", ["ip": .string("203.0.113.5")]) == .notable)
        #expect(sev("hosts.entry", ["ip": .string("127.0.0.1")]) == .routine)
    }

    @Test("TCC: unsigned/Terminal grant to sensitive service → attention")
    func tcc() {
        #expect(sev("tcc.grant", ["service": .string("camera"), "client_signed": .bool(false)]) == .attention)
        #expect(sev("tcc.grant", ["service": .string("accessibility"),
                                  "client": .string("/Applications/Utilities/Terminal.app")]) == .attention)
        #expect(sev("tcc.grant", ["service": .string("photos"), "client_signed": .bool(true)]) == .notable)
        #expect(sev("tcc.grant", ["service": .string("some-benign-service")]) == .routine)
    }

    @Test("Quarantine: registry/.onion origin → attention, else notable")
    func quarantine() {
        #expect(sev("quarantine.event", ["origin_url": .string("http://evil.onion/x")]) == .attention)
        #expect(sev("quarantine.event", ["origin_url": .string("https://registry.npmjs.org/x")]) == .attention)
        #expect(sev("quarantine.event", ["origin_url": .string("https://example.com/app")]) == .notable)
    }

    @Test("Safari: punycode history / dmg download / unsigned extension")
    func safari() {
        #expect(sev("safari.history_visit", ["url": .string("https://xn--80ak6aa92e.com")]) == .notable)
        #expect(sev("safari.history_visit", ["url": .string("https://apple.com")]) == .routine)
        #expect(sev("safari.download", ["origin_url": .string("https://x.io/app.dmg")]) == .notable)
        #expect(sev("safari.extension", ["signed": .bool(false)]) == .attention)
    }

    @Test("iMessage url_mention → attention, other → routine")
    func imessage() {
        #expect(sev("imessage.url_mention") == .attention)
        #expect(sev("imessage.message") == .routine)
    }

    @Test("Mail attachment → notable, plain → routine")
    func mail() {
        #expect(sev("mail.message", ["has_attachment": .bool(true)]) == .notable)
        #expect(sev("mail.message") == .routine)
    }

    @Test("Activity inventory (facetime/knowledgec/biome) → routine")
    func activityInventory() {
        #expect(sev("facetime.call") == .routine)
        #expect(sev("knowledgec.app_usage") == .routine)
        #expect(sev("biome.event") == .routine)
    }

    @Test("Static analysis: unsigned → attention, no-hardened-runtime → notable")
    func staticAnalysis() {
        #expect(sev("codesigning.info", ["signed": .bool(false)]) == .attention)
        #expect(sev("macho.load_commands", ["hardened_runtime": .bool(false)]) == .notable)
        #expect(sev("codesigning.info", ["signed": .bool(true)]) == .routine)
    }

    @Test("Installer payloads: unsigned → attention, else notable")
    func installers() {
        #expect(sev("dmg.scan", ["signed": .bool(false)]) == .attention)
        #expect(sev("pkg.scan") == .notable)
    }

    @Test("AppleScript activity → notable")
    func applescript() {
        #expect(sev("applescript.run") == .notable)
    }

    @Test("Default fallback: 'unsigned'/'unfamiliar' summary → attention, else routine")
    func defaultFallback() {
        #expect(sev("unknown.type", summary: "unsigned binary found") == .attention)
        #expect(sev("unknown.type", summary: "unfamiliar sender") == .attention)
        #expect(sev("unknown.type", summary: "looks normal") == .routine)
        #expect(sev("totally.unclassified") == .routine)
    }

    // MARK: - Tally + banner ordering

    @Test("Empty scan banner reads empty")
    func emptyBanner() {
        #expect(FindingHeuristics.bannerSummary([]) == "Nothing collected.")
        #expect(SeverityTally.zero.bannerSummary == "Nothing collected.")
    }

    @Test("Banner orders critical → needs-review → notable → inventoried")
    func bannerOrdering() {
        let t = SeverityTally(routine: 3, notable: 2, attention: 1, critical: 1)
        #expect(t.bannerSummary == "1 critical, 1 needs review, 2 notable, 3 inventoried")
        #expect(SeverityTally(routine: 5, notable: 0, attention: 0, critical: 0).bannerSummary == "5 inventoried")
    }

    @Test("tally() buckets a mixed artifact list correctly")
    func tallyMixed() {
        let t = FindingHeuristics.tally([
            art("codesigning.info", data: ["signed": .bool(false)]), // attention
            art("hosts.entry", data: ["ip": .string("203.0.113.5")]), // notable
            art("facetime.call"),                                      // routine
        ])
        #expect(t == SeverityTally(routine: 1, notable: 1, attention: 1, critical: 0))
        #expect(t.bannerSummary == "1 needs review, 1 notable, 1 inventoried")
    }
}
