// AdvancedEngineTests.swift
// Tests for CampaignDetector, PackageFreshnessChecker, CrossProcessCorrelator,
// and DatabaseEncryption — components with zero prior test coverage.

import Testing
import Foundation
@testable import MacCrabCore

// MARK: - Campaign Detector Tests

@Suite("Campaign Detector")
struct CampaignDetectorTests {

    @Test("Kill chain detected from 3+ MITRE tactics")
    func killChainFromThreeTactics() async {
        let detector = CampaignDetector(
            campaignWindow: 600,
            stormThreshold: 100,      // high to avoid storm noise
            minTacticsForKillChain: 3
        )

        let alert1 = CampaignDetector.AlertSummary(
            ruleId: "maccrab.cred-dump",
            ruleTitle: "Credential Dumping",
            severity: .high,
            timestamp: Date(),
            tactics: ["credential_access"]
        )
        let alert2 = CampaignDetector.AlertSummary(
            ruleId: "maccrab.persist-agent",
            ruleTitle: "LaunchAgent Persistence",
            severity: .medium,
            timestamp: Date(),
            tactics: ["persistence"]
        )
        let alert3 = CampaignDetector.AlertSummary(
            ruleId: "maccrab.c2-beacon",
            ruleTitle: "C2 Beacon",
            severity: .high,
            timestamp: Date(),
            tactics: ["command_and_control"]
        )

        // Feed alerts one by one; the kill chain should trigger on the second or third
        _ = await detector.processAlert(alert1)
        _ = await detector.processAlert(alert2)
        let campaigns = await detector.processAlert(alert3)

        let killChains = campaigns.filter { $0.type == .killChain }
        #expect(!killChains.isEmpty, "Expected a kill_chain campaign from 3 MITRE tactics")
    }

    @Test("Alert storm detected at threshold")
    func alertStormAtThreshold() async {
        let detector = CampaignDetector(
            stormThreshold: 10,
            stormWindow: 300,
            minTacticsForKillChain: 99  // disable kill-chain detection
        )

        let ruleId = "maccrab.brute-force"
        let now = Date()
        var allCampaigns: [CampaignDetector.Campaign] = []

        for i in 0..<12 {
            let alert = CampaignDetector.AlertSummary(
                ruleId: ruleId,
                ruleTitle: "Brute Force",
                severity: .medium,
                timestamp: now.addingTimeInterval(Double(i)),
                tactics: []
            )
            allCampaigns.append(contentsOf: await detector.processAlert(alert))
        }

        let storms = allCampaigns.filter { $0.type == .alertStorm }
        #expect(!storms.isEmpty, "Expected an alert_storm campaign after 10+ same-rule alerts")
    }

    @Test("AI compromise from 2+ AI Guard categories")
    func aiCompromiseFromTwoCategories() async {
        let detector = CampaignDetector(
            campaignWindow: 600,
            stormThreshold: 100,
            minTacticsForKillChain: 99
        )

        let alert1 = CampaignDetector.AlertSummary(
            ruleId: "maccrab.ai-guard.credential-access",
            ruleTitle: "AI Credential Access",
            severity: .high,
            timestamp: Date(),
            tactics: []
        )
        let alert2 = CampaignDetector.AlertSummary(
            ruleId: "maccrab.ai-guard.boundary-violation",
            ruleTitle: "AI Boundary Violation",
            severity: .high,
            timestamp: Date(),
            tactics: []
        )

        _ = await detector.processAlert(alert1)
        let campaigns = await detector.processAlert(alert2)

        let aiCompromises = campaigns.filter { $0.type == .aiCompromise }
        #expect(!aiCompromises.isEmpty, "Expected ai_compromise campaign from 2 AI Guard categories")
    }

    @Test("Campaign dedup prevents re-emission")
    func campaignDedupPreventsReEmission() async {
        let detector = CampaignDetector(
            campaignWindow: 600,
            stormThreshold: 10,
            stormWindow: 300,
            minTacticsForKillChain: 99
        )

        let ruleId = "maccrab.scan-rule"
        let now = Date()

        // Feed 12 alerts to trigger a storm
        var firstStormCampaigns: [CampaignDetector.Campaign] = []
        for i in 0..<12 {
            let alert = CampaignDetector.AlertSummary(
                ruleId: ruleId,
                ruleTitle: "Scan Rule",
                severity: .medium,
                timestamp: now.addingTimeInterval(Double(i)),
                tactics: []
            )
            let result = await detector.processAlert(alert)
            if !result.isEmpty { firstStormCampaigns = result }
        }
        #expect(firstStormCampaigns.contains { $0.type == .alertStorm },
                "Storm should have been emitted on first batch")

        // Feed more alerts of the same rule — within the 10 min dedup window
        var secondBatchCampaigns: [CampaignDetector.Campaign] = []
        for i in 12..<24 {
            let alert = CampaignDetector.AlertSummary(
                ruleId: ruleId,
                ruleTitle: "Scan Rule",
                severity: .medium,
                timestamp: now.addingTimeInterval(Double(i)),
                tactics: []
            )
            let result = await detector.processAlert(alert)
            secondBatchCampaigns.append(contentsOf: result)
        }

        let secondStorms = secondBatchCampaigns.filter { $0.type == .alertStorm }
        #expect(secondStorms.isEmpty,
                "Storm should NOT re-emit within dedup window, got \(secondStorms.count)")
    }
}

// MARK: - Package Freshness Checker Tests

@Suite("Package Freshness Checker")
struct PackageFreshnessCheckerTests {

    @Test("Parses npm install command correctly")
    func parseNpmInstall() {
        let packages = PackageFreshnessChecker.parseInstallCommand("npm install lodash express")
        #expect(packages.count == 2)
        #expect(packages[0].name == "lodash")
        #expect(packages[0].registry == .npm)
        #expect(packages[1].name == "express")
        #expect(packages[1].registry == .npm)
    }

    @Test("Parses pip install with version specifier")
    func parsePipInstallWithVersion() {
        let packages = PackageFreshnessChecker.parseInstallCommand("pip install requests==2.31.0")
        #expect(packages.count == 1)
        #expect(packages[0].name == "requests")
        #expect(packages[0].registry == .pypi)
    }

    @Test("Parses brew install with --cask flag")
    func parseBrewCask() {
        let packages = PackageFreshnessChecker.parseInstallCommand("brew install --cask firefox")
        #expect(packages.count == 1)
        #expect(packages[0].name == "firefox")
        #expect(packages[0].registry == .homebrewCask)
    }

    @Test("Skips flags in install commands")
    func skipFlags() {
        let packages = PackageFreshnessChecker.parseInstallCommand("npm install --save-dev jest")
        #expect(packages.count == 1)
        #expect(packages[0].name == "jest")
        #expect(packages[0].registry == .npm)
    }
}

// MARK: - Cross-Process Correlator Tests

@Suite("Cross-Process Correlator")
struct CrossProcessCorrelatorTests {

    @Test("File write + execute from different PIDs creates chain")
    func fileWriteExecuteChain() async {
        // Use minChainLength: 2 so two distinct PIDs suffice
        let correlator = CrossProcessCorrelator(correlationWindow: 300, minChainLength: 2)

        let now = Date()

        // PID 100 writes a file
        await correlator.recordFileEvent(
            path: "/tmp/payload.bin",
            action: "write",
            pid: 100,
            processName: "curl",
            processPath: "/usr/bin/curl",
            timestamp: now
        )

        // PID 200 executes the same file
        let chain = await correlator.recordFileEvent(
            path: "/tmp/payload.bin",
            action: "execute",
            pid: 200,
            processName: "bash",
            processPath: "/bin/bash",
            timestamp: now.addingTimeInterval(5)
        )

        #expect(chain != nil, "Expected a correlation chain from write + execute by different PIDs")
        if let chain = chain {
            #expect(chain.processCount == 2)
            #expect(chain.sharedArtifact == "/tmp/payload.bin")
            #expect(chain.artifactType == "file")
        }
    }

    @Test("Same PID events do not create chain")
    func samePIDNoChain() async {
        let correlator = CrossProcessCorrelator(correlationWindow: 300, minChainLength: 2)

        let now = Date()

        await correlator.recordFileEvent(
            path: "/tmp/test.sh",
            action: "write",
            pid: 100,
            processName: "bash",
            processPath: "/bin/bash",
            timestamp: now
        )

        let chain = await correlator.recordFileEvent(
            path: "/tmp/test.sh",
            action: "execute",
            pid: 100,
            processName: "bash",
            processPath: "/bin/bash",
            timestamp: now.addingTimeInterval(2)
        )

        #expect(chain == nil, "Same PID should not form a cross-process chain")
    }

    @Test("Stale events are purged")
    func staleEventsPurged() async {
        let window: TimeInterval = 10  // short window for testing
        let correlator = CrossProcessCorrelator(correlationWindow: window, minChainLength: 2)

        let staleTime = Date().addingTimeInterval(-(window + 5))

        // Record an event with a timestamp older than the window
        await correlator.recordFileEvent(
            path: "/tmp/old-payload",
            action: "write",
            pid: 300,
            processName: "curl",
            processPath: "/usr/bin/curl",
            timestamp: staleTime
        )

        let countBefore = await correlator.trackedFileCount
        #expect(countBefore >= 1, "Should have at least 1 tracked file before purge")

        await correlator.purgeStale()

        let countAfter = await correlator.trackedFileCount
        #expect(countAfter == 0, "Stale event should be purged, but \(countAfter) files remain")
    }
}

// MARK: - Database Encryption Tests

@Suite("Database Encryption")
struct DatabaseEncryptionTests {

    @Test("Encrypt and decrypt roundtrips correctly")
    func encryptDecryptRoundtrip() {
        let encryption = DatabaseEncryption(enabled: true)
        let original = "sensitive data: password=hunter2"
        let encrypted = encryption.encrypt(original)
        let decrypted = encryption.decrypt(encrypted)
        #expect(decrypted == original, "Decrypted text should match original")
    }

    @Test("Encrypted string has ENC: prefix")
    func encryptedHasPrefix() {
        let encryption = DatabaseEncryption(enabled: true)
        let encrypted = encryption.encrypt("test data")
        #expect(encrypted.hasPrefix("ENC:"), "Encrypted output should start with 'ENC:' prefix")
    }

    @Test("Disabled encryption passes through unchanged")
    func disabledPassthrough() {
        let encryption = DatabaseEncryption(enabled: false)
        let original = "plaintext value"
        let result = encryption.encrypt(original)
        #expect(result == original, "With encryption disabled, encrypt should return original string")
        let decryptResult = encryption.decrypt(original)
        #expect(decryptResult == original, "With encryption disabled, decrypt should return original string")
    }
}
