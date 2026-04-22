import Testing
import Foundation
@testable import MacCrabCore

@Suite("Security Scorer")
struct SecurityScorerTests {
    @Test("Calculates score between 0 and 100")
    func scoreRange() async {
        let scorer = SecurityScorer()
        let result = await scorer.calculate()
        #expect(result.totalScore >= 0 && result.totalScore <= 100)
    }

    @Test("Returns a valid letter grade")
    func validGrade() async {
        let scorer = SecurityScorer()
        let result = await scorer.calculate()
        let validGrades = ["A+", "A", "A-", "B+", "B", "B-", "C", "D", "F"]
        #expect(validGrades.contains(result.grade))
    }

    @Test("Factors have non-zero maxScore")
    func factorsValid() async {
        let scorer = SecurityScorer()
        let result = await scorer.calculate()
        #expect(!result.factors.isEmpty)
        for factor in result.factors {
            #expect(factor.maxScore > 0)
            #expect(factor.score >= 0 && factor.score <= factor.maxScore)
        }
    }
}

@Suite("App Privacy Auditor")
struct AppPrivacyAuditorTests {
    @Test("Records connections and produces audit")
    func recordAndAudit() async {
        let auditor = AppPrivacyAuditor()
        await auditor.recordConnection(processName: "test", processPath: "/tmp/test", domain: "evil.com", ip: "1.2.3.4", port: 443)
        await auditor.recordConnection(processName: "test", processPath: "/tmp/test", domain: "tracker.com", ip: "5.6.7.8", port: 443)
        let profiles = await auditor.audit()
        #expect(!profiles.isEmpty)
        #expect(profiles.first?.processName == "test")
        #expect(profiles.first?.uniqueDomains == 2)
    }

    @Test("Purge removes old records")
    func purgeWorks() async {
        let auditor = AppPrivacyAuditor()
        await auditor.recordConnection(processName: "old", processPath: "/tmp/old", domain: "x.com", ip: "1.1.1.1", port: 80)
        // olderThan: -1 moves the cutoff 1s into the future, guaranteeing
        // every existing record falls before it regardless of clock resolution.
        await auditor.purge(olderThan: -1)
        let profiles = await auditor.audit()
        #expect(profiles.isEmpty)
    }

    @Test("Known tracking domain flagged in concerns")
    func trackingDomainFlagged() async {
        let auditor = AppPrivacyAuditor()
        await auditor.recordConnection(processName: "app", processPath: "/tmp/app",
            domain: "sub.amplitude.com", ip: "1.2.3.4", port: 443)
        let profiles = await auditor.audit()
        let concern = profiles.first?.concerns.first(where: { $0.contains("tracking") })
        #expect(concern != nil)
    }

    @Test("Bulk egress anomaly detected above 50 MB threshold")
    func bulkEgressDetected() async {
        let auditor = AppPrivacyAuditor()
        let mb55 = 55 * 1_048_576
        await auditor.recordConnection(processName: "leaky", processPath: "/tmp/leaky",
            domain: "somewhere.com", ip: "10.0.0.1", port: 443, bytesOut: mb55)
        let anomalies = await auditor.checkForAnomalies()
        let bulk = anomalies.first { $0.kind == .bulkEgress }
        #expect(bulk != nil)
        #expect(bulk?.processName == "leaky")
    }

    @Test("Single-domain spike anomaly detected above 10 MB to unknown domain")
    func singleDomainSpikeDetected() async {
        let auditor = AppPrivacyAuditor()
        let mb11 = 11 * 1_048_576
        await auditor.recordConnection(processName: "uploader", processPath: "/tmp/uploader",
            domain: "unknown-exfil.net", ip: "192.168.1.100", port: 443, bytesOut: mb11)
        let anomalies = await auditor.checkForAnomalies()
        let spike = anomalies.first { $0.kind == .singleDomainSpike }
        #expect(spike != nil)
        #expect(spike?.detail.contains("unknown-exfil.net") == true)
    }

    @Test("High-frequency tracker contact anomaly fires above 50 hits")
    func trackerContactDetected() async {
        let auditor = AppPrivacyAuditor()
        for _ in 0..<60 {
            await auditor.recordConnection(processName: "chatty", processPath: "/tmp/chatty",
                domain: "in.hotjar.com", ip: "1.2.3.4", port: 443)
        }
        let anomalies = await auditor.checkForAnomalies()
        let tracking = anomalies.first { $0.kind == .trackingContact }
        #expect(tracking != nil)
    }

    @Test("System processes are excluded from anomaly checks")
    func systemProcessesExcluded() async {
        let auditor = AppPrivacyAuditor()
        let mb60 = 60 * 1_048_576
        await auditor.recordConnection(processName: "cfnetd", processPath: "/System/Library/cfnetd",
            domain: "example.com", ip: "1.1.1.1", port: 443, bytesOut: mb60)
        let anomalies = await auditor.checkForAnomalies()
        #expect(anomalies.isEmpty)
    }

    @Test("DomainContact tracks bytes per domain")
    func domainBytesTracked() async {
        let auditor = AppPrivacyAuditor()
        await auditor.recordConnection(processName: "app", processPath: "/tmp/app2",
            domain: "cdn.example.com", ip: "5.5.5.5", port: 443, bytesOut: 1024)
        await auditor.recordConnection(processName: "app", processPath: "/tmp/app2",
            domain: "cdn.example.com", ip: "5.5.5.5", port: 443, bytesOut: 2048)
        let profiles = await auditor.audit()
        let contact = profiles.first?.domains.first(where: { $0.domain == "cdn.example.com" })
        #expect(contact?.bytesOut == 3072)
        #expect(contact?.connectionCount == 2)
    }
}

@Suite("Vulnerability Scanner")
struct VulnScannerTests {
    @Test("Scan completes without crash")
    func scanRuns() async {
        let scanner = VulnerabilityScanner()
        let results = await scanner.scanInstalledApps()
        // May or may not find vulns depending on installed apps
        #expect(results.count >= 0)
    }
}

// Panic Button and Travel Mode test suites moved to
// PanicButtonTests.swift and TravelModeTests.swift in Phase 6.

@Suite("Security Digest")
struct SecurityDigestTests {
    @Test("Generates digest from empty alerts")
    func emptyDigest() async {
        let digest = SecurityDigest()
        let result = await digest.generate(alerts: [], eventCount: 1000)
        #expect(result.totalAlerts == 0)
        #expect(result.totalEvents == 1000)
        #expect(result.summary.contains("Clean"))
    }

    @Test("Formats text digest")
    func textFormat() async {
        let digest = SecurityDigest()
        let result = await digest.generate(
            alerts: [("Test Rule", "high", "testproc", Date())],
            eventCount: 500
        )
        let text = await digest.formatText(result)
        #expect(text.contains("MacCrab"))
        #expect(text.contains("500"))
    }
}

@Suite("Bundled Threat Intel")
struct BundledThreatIntelTests {
    @Test("Has non-zero IOC counts")
    func hasCounts() {
        let stats = BundledThreatIntel.stats
        #expect(stats.hashes > 10)
        #expect(stats.ips > 10)
        #expect(stats.domains > 30)
    }

    @Test("Suspicious TLD detection works")
    func tldCheck() {
        #expect(BundledThreatIntel.hasSuspiciousTLD("evil.xyz") == true)
        #expect(BundledThreatIntel.hasSuspiciousTLD("google.com") == false)
    }
}

// MARK: - Fleet Client Tests

@Suite("Fleet Client")
struct FleetClientTests {
    @Test("Returns nil when MACCRAB_FLEET_URL is not set")
    func nilWithoutURL() async {
        // Ensure the env var is not set in this process
        // (CI and local test environments should not have it set)
        if ProcessInfo.processInfo.environment["MACCRAB_FLEET_URL"] != nil {
            // If the var happens to be set, just skip the nil assertion
            return
        }
        let client = FleetClient()
        #expect(client == nil)
    }

    @Test("FleetAlertSummary roundtrips through JSON")
    func alertSummaryCodable() throws {
        let summary = FleetAlertSummary(
            ruleId: "maccrab.test.rule",
            ruleTitle: "Test Rule",
            severity: "high",
            processPath: "/usr/bin/curl",
            mitreTechniques: "attack.t1059",
            timestamp: Date(timeIntervalSince1970: 1000000)
        )
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(summary)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode(FleetAlertSummary.self, from: data)
        #expect(decoded.ruleId == summary.ruleId)
        #expect(decoded.ruleTitle == summary.ruleTitle)
        #expect(decoded.severity == summary.severity)
        #expect(decoded.processPath == summary.processPath)
        #expect(decoded.mitreTechniques == summary.mitreTechniques)
    }

    @Test("FleetTelemetry encodes without crashing")
    func telemetryCodable() throws {
        let telemetry = FleetTelemetry(
            hostId: "abc123",
            timestamp: Date(),
            version: "1.0.0",
            alerts: [],
            iocSightings: [],
            behaviorScores: []
        )
        let data = try JSONEncoder().encode(telemetry)
        #expect(data.count > 0)
        let decoded = try JSONDecoder().decode(FleetTelemetry.self, from: data)
        #expect(decoded.hostId == "abc123")
        #expect(decoded.version == "1.0.0")
    }

    @Test("FleetAggregation decodes empty response")
    func aggregationDecodes() throws {
        let json = """
        {"iocs":[],"hotProcesses":[],"fleetSize":0,"timestamp":"2026-04-08T12:00:00Z"}
        """
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let agg = try decoder.decode(FleetAggregation.self, from: Data(json.utf8))
        #expect(agg.iocs.isEmpty)
        #expect(agg.hotProcesses.isEmpty)
        #expect(agg.fleetSize == 0)
    }

    @Test("FleetCampaign decodes snake_case keys correctly")
    func campaignDecodesSnakeCase() throws {
        let json = """
        {"rule_id":"r1","rule_title":"Test Campaign","severity":"high","alert_count":5,"host_count":3,"first_seen":1000000.0,"last_seen":1001000.0}
        """
        let campaign = try JSONDecoder().decode(FleetCampaign.self, from: Data(json.utf8))
        #expect(campaign.ruleId == "r1")
        #expect(campaign.ruleTitle == "Test Campaign")
        #expect(campaign.alertCount == 5)
        #expect(campaign.hostCount == 3)
    }
}
