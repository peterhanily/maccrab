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
        await auditor.purge(olderThan: 0) // Purge everything
        let profiles = await auditor.audit()
        #expect(profiles.isEmpty)
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

@Suite("Panic Button")
struct PanicButtonTests {
    @Test("Initializes without crash")
    func initOK() async {
        let _ = PanicButton()
        // Can't test activate() as it kills processes
    }
}

@Suite("Travel Mode")
struct TravelModeTests {
    @Test("Default status is inactive")
    func defaultInactive() async {
        let travel = TravelMode()
        let status = await travel.status()
        #expect(status.isActive == false)
    }

    @Test("Activate returns active status")
    func activateWorks() async {
        let travel = TravelMode()
        let status = await travel.activate(networkName: "Test WiFi")
        #expect(status.isActive == true)
        #expect(status.networkName == "Test WiFi")
        #expect(!status.protections.isEmpty)
        // Deactivate to clean up
        let _ = await travel.deactivate()
    }
}

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
