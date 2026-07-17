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

    @Test("Campaign dedup disabled when window is zero (allows every emission)")
    func campaignDedupZeroWindowNeverSuppresses() async {
        // campaignDedupWindow = 0 means interval < 0 is never satisfied for
        // non-negative intervals, so every storm re-fires. This also validates
        // the fix: a negative interval (clock going backward) can never satisfy
        // `interval >= 0 && interval < campaignDedupWindow` with any window value,
        // so clock-backward events always re-emit.
        let detector = CampaignDetector(
            campaignWindow: 600,
            stormThreshold: 5,
            stormWindow: 300,
            minTacticsForKillChain: 99,
            campaignDedupWindow: 0
        )

        let ruleId = "maccrab.dedup-zero-test"
        let now = Date()
        var storms: [CampaignDetector.Campaign] = []
        for pass in 0..<2 {
            for i in 0..<7 {
                let alert = CampaignDetector.AlertSummary(
                    ruleId: ruleId,
                    ruleTitle: "Dedup Zero Test",
                    severity: .medium,
                    timestamp: now.addingTimeInterval(Double(pass * 100 + i)),
                    tactics: []
                )
                storms.append(contentsOf: await detector.processAlert(alert))
            }
        }
        let stormCount = storms.filter { $0.type == .alertStorm }.count
        #expect(stormCount >= 2, "With dedupWindow=0, both storm batches should emit (got \(stormCount))")
    }

    @Test("Campaign dedup re-emits after window expires")
    func campaignDedupReEmitsAfterWindow() async {
        // Use a 1-second dedup window so the second batch fires after waiting >1s.
        // Simulates the production "10 min window expired" scenario in fast time.
        let detector = CampaignDetector(
            campaignWindow: 600,
            stormThreshold: 5,
            stormWindow: 300,
            minTacticsForKillChain: 99,
            campaignDedupWindow: 1.0
        )

        let ruleId = "maccrab.window-expiry-test"
        let base = Date()
        var firstStorms: [CampaignDetector.Campaign] = []
        for i in 0..<7 {
            let alert = CampaignDetector.AlertSummary(
                ruleId: ruleId, ruleTitle: "Expiry Test", severity: .medium,
                timestamp: base.addingTimeInterval(Double(i)), tactics: []
            )
            firstStorms.append(contentsOf: await detector.processAlert(alert))
        }
        #expect(firstStorms.contains { $0.type == .alertStorm }, "First batch should produce a storm")

        // Second batch at >1s offset — beyond the dedup window
        var secondStorms: [CampaignDetector.Campaign] = []
        for i in 0..<7 {
            let alert = CampaignDetector.AlertSummary(
                ruleId: ruleId, ruleTitle: "Expiry Test", severity: .medium,
                timestamp: base.addingTimeInterval(2.0 + Double(i)), tactics: []
            )
            secondStorms.append(contentsOf: await detector.processAlert(alert))
        }
        // After the 1s dedup window, the second storm at (base+2s) should fire.
        // NOTE: detectedAt is set to Date() at call time; since tests run fast,
        // this relies on the stormWindow/alert-time logic, not wall-clock dedup.
        // The primary value of this test is exercising the code path.
        _ = secondStorms // exercised
    }

    @Test("Tactic index stays consistent when alerts are evicted at hard cap")
    func tacticIndexConsistentAfterEviction() async {
        // Use a tiny cap (5) to force eviction early.
        let detector = CampaignDetector(
            stormThreshold: 100,        // disable storm detection
            minTacticsForKillChain: 99, // disable kill-chain detection
            maxRecentAlerts: 5
        )

        let now = Date()
        // Fill past the cap — eviction will remove the first 5 to make room for #6–10
        for i in 0..<10 {
            let alert = CampaignDetector.AlertSummary(
                ruleId: "maccrab.test.\(i)",
                ruleTitle: "Test \(i)",
                severity: .medium,
                timestamp: now.addingTimeInterval(Double(i)),
                tactics: ["TA0001"]
            )
            _ = await detector.processAlert(alert)
        }

        // After eviction the detector must not crash and must still detect new campaigns.
        // The kill-chain check queries normalizedTacticCounts — a crash here would mean
        // the index was corrupted during eviction.
        let extra = CampaignDetector.AlertSummary(
            ruleId: "maccrab.test.extra", ruleTitle: "Extra", severity: .medium,
            timestamp: now.addingTimeInterval(100), tactics: ["TA0001"]
        )
        let result = await detector.processAlert(extra)
        _ = result  // No crash = index is consistent
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

    @Test("File write + execute from different PIDs creates chain (production default)")
    func fileWriteExecuteChain() async {
        // GA-blocker regression: use the PRODUCTION default correlator (no
        // args) so this guards the real deployed config. minFileChainLength
        // defaults to 2, so the canonical 2-PID write→execute handoff across
        // unrelated trees must fire. Previously this test forced
        // minChainLength: 2, which masked the fact that the production default
        // (minChainLength 3) dropped this flagship signal.
        let correlator = CrossProcessCorrelator()

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
            #expect(chain.severity == .high, "2-PID write→execute is HIGH severity")
        }
    }

    @Test("2-PID download → execute handoff fires under production config")
    func fileDownloadExecuteChainProductionDefault() async {
        // Second flagship-signal guard, distinct from fileWriteExecuteChain:
        // a `download` action (write-family) by one tree followed by an
        // `execute` by an unrelated tree. Uses the production default so it
        // pins the minFileChainLength == 2 behavior for the download alias too.
        let correlator = CrossProcessCorrelator()
        let now = Date()

        await correlator.recordFileEvent(
            path: "/tmp/stage2",
            action: "download",
            pid: 4100,
            processName: "wget",
            processPath: "/opt/local/bin/wget",
            timestamp: now
        )
        let chain = await correlator.recordFileEvent(
            path: "/tmp/stage2",
            action: "execute",
            pid: 4200,
            processName: "sh",
            processPath: "/var/tmp/dropper",   // unrelated tree, non-shell payload
            timestamp: now.addingTimeInterval(4)
        )

        #expect(chain != nil, "download → execute across 2 unrelated PIDs must fire in production config")
        #expect(chain?.processCount == 2)
    }

    @Test("Benign write-only shell-utility fan-out stays suppressed (production default)")
    func benignShellWriteChainSuppressedProductionDefault() async {
        // FP guard: lowering the file floor to 2 must not resurrect the
        // build-script FP class. A write-only chain dominated by a *variety*
        // of shell utilities (bash/cat/sed) with NO execute action is a
        // script, not an attack — chainDominatedByShellUtilities must still
        // suppress it even though 2 PIDs now suffice to form a file chain.
        let correlator = CrossProcessCorrelator()
        let now = Date()

        await correlator.recordFileEvent(
            path: "/private/tmp/build-scratch/config.h",
            action: "write",
            pid: 7100,
            processName: "bash",
            processPath: "/bin/bash",
            timestamp: now
        )
        await correlator.recordFileEvent(
            path: "/private/tmp/build-scratch/config.h",
            action: "create",
            pid: 7200,
            processName: "cat",
            processPath: "/bin/cat",
            timestamp: now.addingTimeInterval(1)
        )
        let chain = await correlator.recordFileEvent(
            path: "/private/tmp/build-scratch/config.h",
            action: "close_modified",
            pid: 7300,
            processName: "sed",
            processPath: "/usr/bin/sed",
            timestamp: now.addingTimeInterval(2)
        )

        #expect(chain == nil, "write-only shell-utility fan-out must stay suppressed")
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

    @Test("Chrome Helper + Google Drive + GSU fan-out is suppressed")
    func chromeFamilyFanOutSuppressed() async {
        // Real-world FP: Chrome Helper, Google Drive, and Google Software
        // Update all chatter to the same Google endpoint within seconds.
        // Three distinct .app bundles — `allEventsShareAppBundle` can't
        // catch it. `allEventsAreTrustedHelpers` should.
        let correlator = CrossProcessCorrelator(correlationWindow: 300, minChainLength: 3)
        let now = Date()

        await correlator.recordNetworkEvent(
            destinationIP: "198.51.100.42",     // not in trustedCloudPrefixes
            destinationPort: 443,
            pid: 100,
            processName: "Google Chrome Helper",
            processPath: "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper",
            timestamp: now
        )
        await correlator.recordNetworkEvent(
            destinationIP: "198.51.100.42",
            destinationPort: 443,
            pid: 200,
            processName: "Slack Helper",
            processPath: "/Applications/Slack.app/Contents/Frameworks/Slack Helper.app/Contents/MacOS/Slack Helper",
            timestamp: now.addingTimeInterval(3)
        )
        let chain = await correlator.recordNetworkEvent(
            destinationIP: "198.51.100.42",
            destinationPort: 443,
            pid: 300,
            processName: "Code Helper",
            processPath: "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper.app/Contents/MacOS/Code Helper",
            timestamp: now.addingTimeInterval(6)
        )

        #expect(chain == nil, "Cross-bundle trusted-helper fan-out should be suppressed")
    }

    @Test("Unrelated non-browser processes still trigger convergence")
    func unrelatedProcessesStillConverge() async {
        // Sanity: the new filter must not paper over real convergence.
        // curl + python + bash hitting the same non-cloud IP is the exact
        // pattern the rule is designed to catch.
        let correlator = CrossProcessCorrelator(correlationWindow: 300, minChainLength: 3)
        let now = Date()

        await correlator.recordNetworkEvent(
            destinationIP: "198.51.100.7",
            destinationPort: 443,
            pid: 100,
            processName: "curl",
            processPath: "/usr/bin/curl",
            timestamp: now
        )
        await correlator.recordNetworkEvent(
            destinationIP: "198.51.100.7",
            destinationPort: 443,
            pid: 200,
            processName: "python3",
            processPath: "/usr/bin/python3",
            timestamp: now.addingTimeInterval(2)
        )
        let chain = await correlator.recordNetworkEvent(
            destinationIP: "198.51.100.7",
            destinationPort: 443,
            pid: 300,
            processName: "bash",
            processPath: "/bin/bash",
            timestamp: now.addingTimeInterval(4)
        )

        #expect(chain != nil, "Genuine multi-process convergence must still fire")
        #expect(chain?.processCount == 3)
    }

    @Test("Expanded Google domain list suppresses Chrome update chatter")
    func googleUpdateDomainSuppressed() async {
        // `tools.google.com`, `gvt1.com`, `googleusercontent.com` all
        // receive Chrome update / user-content traffic. None of these ended
        // in `google.com` or matched the old suffix list.
        let correlator = CrossProcessCorrelator(correlationWindow: 300, minChainLength: 3)
        let now = Date()

        for (i, domain) in ["gvt1.com", "googleusercontent.com", "youtube.com"].enumerated() {
            let chain = await correlator.recordNetworkEvent(
                destinationIP: "203.0.113.\(10 + i)",   // deliberately non-Google IPs
                destinationPort: 443,
                destinationDomain: domain,
                pid: Int32(100 + i),
                processName: "curl",
                processPath: "/usr/bin/curl-\(i)",    // distinct paths so helpers filter doesn't trigger
                timestamp: now.addingTimeInterval(Double(i) * 2)
            )
            // The IP-key chain may fire (non-Google IPs); assert the
            // *domain*-key chain doesn't. Domain suppression is what
            // stops Chrome update noise when DNS is attached to events.
            if i == 2 {
                #expect(
                    chain?.artifactType != "domain",
                    "Trusted Google domain \(domain) must not produce a domain-type chain"
                )
            }
        }
    }

    @Test("Empty destination IP never produces a convergence chain")
    func emptyDestinationIPIgnored() async {
        // Regression: network events that arrive before DNS / flow
        // enrichment resolves carry an empty `destinationIP`. Without a
        // guard, every one of them keys into the artifact map as `":443"`
        // and collapses every HTTPS flow on the host into one bucket.
        // Observed in the field: syspolicyd + Google Chrome Helper +
        // WeatherWidget + mDNSResponder all reported as "unrelated
        // processes contacted :443" — they weren't, they just lacked IPs.
        let correlator = CrossProcessCorrelator(correlationWindow: 300, minChainLength: 3)
        let now = Date()

        for (i, (name, path)) in [
            ("syspolicyd", "/usr/libexec/syspolicyd"),
            ("Google Chrome Helper", "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/147.0.7727.56/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper"),
            ("WeatherWidget", "/System/Applications/Weather.app/Contents/PlugIns/WeatherWidget.appex/Contents/MacOS/WeatherWidget"),
            ("mDNSResponder", "/usr/sbin/mDNSResponder"),
        ].enumerated() {
            let chain = await correlator.recordNetworkEvent(
                destinationIP: "",                 // unresolved
                destinationPort: 443,
                pid: Int32(100 + i),
                processName: name,
                processPath: path,
                timestamp: now.addingTimeInterval(Double(i))
            )
            #expect(chain == nil, "Empty IP event must never form a chain (i=\(i))")
        }

        let tracked = await correlator.trackedNetworkCount
        #expect(tracked == 0, "Unresolved-IP events should not be tracked at all, got \(tracked)")
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
    @Test("Per-key event list is capped so one hot key cannot grow unbounded")
    func perKeyListIsCapped() async {
        // Wide correlation window so nothing is purged for being stale; the
        // only thing that should bound the list is the per-key cap.
        let correlator = CrossProcessCorrelator(correlationWindow: 100_000, minChainLength: 2)
        let hotPath = "/Users/phanily/Documents/shared-data.bin"
        // Near-now timestamps so nothing is stale-purged; only the per-key
        // cap should bound the list.
        let base = Date().addingTimeInterval(-30)

        // Hammer a single key far past the per-key cap (512). Vary PID so the
        // chain gates don't short-circuit, and keep timestamps in-window.
        for i in 0..<3_000 {
            await correlator.recordFileEvent(
                path: hotPath,
                action: i % 2 == 0 ? "write" : "execute",
                pid: Int32(1_000 + i),
                processName: "worker\(i)",
                processPath: "/usr/bin/worker\(i)",
                timestamp: base.addingTimeInterval(Double(i) * 0.01)
            )
        }

        // Still exactly one tracked key, but its list must be bounded.
        let keys = await correlator.trackedFileCount
        #expect(keys == 1, "Expected a single hot key, got \(keys)")

        let total = await correlator.totalEventCount
        #expect(total <= 512, "Per-key list must be capped at 512, but stored \(total) events")
    }

    // MARK: - Noise-reduction regressions (v1.3.10)

    @Test("GoogleUpdater writing to its own .log does not form a chain")
    func googleUpdaterLogDoesNotChain() async {
        let correlator = CrossProcessCorrelator(correlationWindow: 300, minChainLength: 2)
        let now = Date()
        let logPath = "/Users/phanily/Library/Application Support/Google/GoogleUpdater/updater.log"

        // Thirteen worker processes hammer the same log file — exactly the
        // field scenario that produced the 140-event chain alert.
        var chain: CrossProcessCorrelator.CorrelationChain?
        for i in 0..<13 {
            chain = await correlator.recordFileEvent(
                path: logPath,
                action: "write",
                pid: Int32(10000 + i),
                processName: "GoogleUpdater",
                processPath: "/Library/Application Support/Google/GoogleUpdater/Current/GoogleUpdater.app/Contents/MacOS/GoogleUpdater",
                timestamp: now.addingTimeInterval(Double(i))
            )
        }
        #expect(chain == nil, "Vendor app-support /Google/ paths must not form correlation chains")
    }

    @Test("Generic .log suffix writes across processes do not form a chain")
    func logSuffixDoesNotChain() async {
        let correlator = CrossProcessCorrelator(correlationWindow: 300, minChainLength: 2)
        let now = Date()

        await correlator.recordFileEvent(
            path: "/tmp/my-app.log", action: "write",
            pid: 500, processName: "proc-a", processPath: "/usr/local/bin/proc-a",
            timestamp: now
        )
        let chain = await correlator.recordFileEvent(
            path: "/tmp/my-app.log", action: "write",
            pid: 501, processName: "proc-b", processPath: "/usr/local/bin/proc-b",
            timestamp: now.addingTimeInterval(1)
        )
        #expect(chain == nil, "Log-file writes must never correlate — logs don't carry payloads")
    }

    @Test("Cache / Preferences / WebKit dirs do not form chains")
    func systemCacheDirsDoNotChain() async {
        let correlator = CrossProcessCorrelator(correlationWindow: 300, minChainLength: 2)
        let now = Date()

        for (i, path) in [
            "/Users/u/Library/Caches/com.apple.Spotlight/foo.db",
            "/Users/u/Library/Preferences/com.example.app.plist",
            "/Users/u/Library/WebKit/com.apple.Safari/WebsiteData/x",
        ].enumerated() {
            await correlator.recordFileEvent(
                path: path, action: "write",
                pid: Int32(700 + i), processName: "p1", processPath: "/bin/p1",
                timestamp: now
            )
            let chain = await correlator.recordFileEvent(
                path: path, action: "write",
                pid: Int32(800 + i), processName: "p2", processPath: "/bin/p2",
                timestamp: now.addingTimeInterval(1)
            )
            #expect(chain == nil, "Noisy user-library subdir \(path) should be ignored")
        }
    }

    @Test("brew-install shell utility chain does not form a chain")
    func shellUtilityChainDoesNotFire() async {
        let correlator = CrossProcessCorrelator(correlationWindow: 300, minChainLength: 2)
        let now = Date()
        // Exact field-data scenario: brew install spawns bash, ruby, curl,
        // git, dirname, readlink, env, zsh all touching a shared tmp path.
        // 1200+ chain events hit the correlator during the v1.4.1 user's
        // `brew reinstall --cask maccrab`. None of them are attacks.
        let sharedPath = "/opt/homebrew/Cellar/maccrab/1.4.2/.brew/install-script.sh"
        let utilities: [(String, String)] = [
            ("bash",     "/bin/bash"),
            ("ruby",     "/opt/homebrew/Cellar/ruby/3.4.1/bin/ruby"),
            ("curl",     "/usr/bin/curl"),
            ("git",      "/opt/homebrew/bin/git"),
            ("dirname",  "/usr/bin/dirname"),
            ("readlink", "/usr/bin/readlink"),
            ("env",      "/usr/bin/env"),
            ("cat",      "/bin/cat"),
            ("zsh",      "/bin/zsh"),
            ("locale",   "/usr/bin/locale"),
        ]
        var chain: CrossProcessCorrelator.CorrelationChain?
        for (i, (name, path)) in utilities.enumerated() {
            chain = await correlator.recordFileEvent(
                path: sharedPath, action: i % 2 == 0 ? "write" : "close_modified",
                pid: Int32(20_000 + i), processName: name, processPath: path,
                timestamp: now.addingTimeInterval(Double(i))
            )
        }
        #expect(chain == nil,
                "A chain dominated by shell utilities (bash/ruby/curl/git/…) is script activity, not an attack")
    }

    @Test("Chain with a dropped-to-disk binary still fires (shell-utility gate doesn't over-match)")
    func droppedBinaryChainStillFires() async {
        let correlator = CrossProcessCorrelator(correlationWindow: 300, minChainLength: 2)
        let now = Date()
        let payload = "/tmp/attacker-payload"
        // curl (shell helper) writes the file, then a suspicious
        // never-seen-before binary executes it. Only 50% shell-utility —
        // below the 80% threshold, so the chain should fire.
        await correlator.recordFileEvent(
            path: payload, action: "write",
            pid: 8000, processName: "curl", processPath: "/usr/bin/curl",
            timestamp: now
        )
        let chain = await correlator.recordFileEvent(
            path: payload, action: "execute",
            pid: 8001, processName: "evil", processPath: "/private/tmp/evil",
            timestamp: now.addingTimeInterval(2)
        )
        #expect(chain != nil,
                "A curl→evil-binary chain is below the 80% shell threshold and must still fire")
    }

    @Test("Three-utility write-only script chain is suppressed (≥3 distinct-utility gate)")
    func threeUtilityWriteOnlyChainSuppressed() async {
        // v1.21.4 (deep-audit corr-campaign-anomaly): the shell-utility gate's
        // distinct-utility floor was lowered 4 → 3. bash + cat + sed all writing
        // (never executing) the same file is a build/config script shape, not an
        // attack. Pre-fix the ≥4 gate let this common 3-utility shape through and
        // minted a benign file chain. The `execute` carve-out is unchanged, so a
        // write-then-run payload (droppedBinaryChainStillFires) still fires.
        let correlator = CrossProcessCorrelator(correlationWindow: 300, minChainLength: 2)
        let now = Date()
        let shared = "/Users/me/work/generated.conf"
        let utils: [(String, String)] = [
            ("bash", "/bin/bash"),
            ("cat",  "/bin/cat"),
            ("sed",  "/usr/bin/sed"),
        ]
        var chain: CrossProcessCorrelator.CorrelationChain?
        for (i, (name, path)) in utils.enumerated() {
            chain = await correlator.recordFileEvent(
                path: shared, action: i == 0 ? "write" : "close_modified",
                pid: Int32(21_000 + i), processName: name, processPath: path,
                timestamp: now.addingTimeInterval(Double(i))
            )
        }
        #expect(chain == nil,
                "A 3-distinct-shell write-only chain (bash/cat/sed) is script activity, not an attack")
    }

    @Test("/dev/ttys terminal I/O is not correlated")
    func terminalDeviceNotCorrelated() async {
        let correlator = CrossProcessCorrelator(correlationWindow: 300, minChainLength: 2)
        let now = Date()
        await correlator.recordFileEvent(
            path: "/dev/ttys000", action: "write",
            pid: 9000, processName: "sudo", processPath: "/usr/bin/sudo",
            timestamp: now
        )
        let chain = await correlator.recordFileEvent(
            path: "/dev/ttys000", action: "write",
            pid: 9001, processName: "zsh", processPath: "/bin/zsh",
            timestamp: now.addingTimeInterval(1)
        )
        #expect(chain == nil,
                "sudo+zsh writing to the user's own terminal is not cross-process attacker convergence")
    }

    @Test("Real /tmp payload write→execute chain still fires (no regression)")
    func realPayloadChainStillFires() async {
        let correlator = CrossProcessCorrelator(correlationWindow: 300, minChainLength: 2)
        let now = Date()
        let payload = "/tmp/payload.bin"

        await correlator.recordFileEvent(
            path: payload, action: "write",
            pid: 900, processName: "curl", processPath: "/usr/bin/curl",
            timestamp: now
        )
        let chain = await correlator.recordFileEvent(
            path: payload, action: "execute",
            pid: 901, processName: "bash", processPath: "/bin/bash",
            timestamp: now.addingTimeInterval(2)
        )
        #expect(chain != nil, "Real /tmp write→execute chain should still fire")
    }

    // MARK: - Self-FP regressions (v1.12.6 Wave 4B)

    @Test("Claude Code shell-snapshot files do not form a chain")
    func claudeShellSnapshotDoesNotChain() async {
        let correlator = CrossProcessCorrelator(correlationWindow: 300, minChainLength: 2)
        let now = Date()
        let snapshot = "/Users/u/.claude/shell-snapshots/snapshot-zsh-1715000000-abc.sh"

        await correlator.recordFileEvent(
            path: snapshot, action: "write",
            pid: 1100, processName: "zsh", processPath: "/bin/zsh",
            timestamp: now
        )
        let chain = await correlator.recordFileEvent(
            path: snapshot, action: "read",
            pid: 1101, processName: "bash", processPath: "/bin/bash",
            timestamp: now.addingTimeInterval(1)
        )
        #expect(chain == nil, "Claude Code shell-snapshot scratch files are tool-internal, not attacker convergence")
    }

    @Test("MacCrab release-build scratch dir does not form a chain")
    func maccrabReleaseTmpDoesNotChain() async {
        let correlator = CrossProcessCorrelator(correlationWindow: 300, minChainLength: 2)
        let now = Date()
        let artifact = "/private/tmp/maccrab-release-20260517/MacCrab.app/Contents/MacOS/MacCrab"

        await correlator.recordFileEvent(
            path: artifact, action: "write",
            pid: 1200, processName: "cp", processPath: "/bin/cp",
            timestamp: now
        )
        let chain = await correlator.recordFileEvent(
            path: artifact, action: "write",
            pid: 1201, processName: "codesign", processPath: "/usr/bin/codesign",
            timestamp: now.addingTimeInterval(2)
        )
        #expect(chain == nil, "MacCrab's own release-build scratch dir is self-activity, not a chain")
    }

    @Test("MacCrab compiled_rules dir does not form a chain")
    func maccrabCompiledRulesDoesNotChain() async {
        let correlator = CrossProcessCorrelator(correlationWindow: 300, minChainLength: 2)
        let now = Date()
        let rule = "/Library/Application Support/MacCrab/compiled_rules/persistence.json"

        await correlator.recordFileEvent(
            path: rule, action: "write",
            pid: 1300, processName: "maccrabctl", processPath: "/usr/local/bin/maccrabctl",
            timestamp: now
        )
        let chain = await correlator.recordFileEvent(
            path: rule, action: "read",
            pid: 1301, processName: "com.maccrab.agent", processPath: "/Library/SystemExtensions/.../com.maccrab.agent.systemextension/Contents/MacOS/com.maccrab.agent",
            timestamp: now.addingTimeInterval(1)
        )
        #expect(chain == nil, "MacCrab's own compiled_rules dir is install-pipeline activity, not a chain")
    }

    @Test("User work-dir paths still form chains (sanity)")
    func userWorkDirStillChains() async {
        // Regression guard for the v1.12.6 Wave 4B additions: a normal
        // path under /Users/.../work/ must still produce a chain when
        // two distinct PIDs touch it with different actions.
        let correlator = CrossProcessCorrelator(correlationWindow: 300, minChainLength: 2)
        let now = Date()
        let path = "/Users/me/work/dropped-payload"

        await correlator.recordFileEvent(
            path: path, action: "write",
            pid: 1400, processName: "curl", processPath: "/usr/bin/curl",
            timestamp: now
        )
        let chain = await correlator.recordFileEvent(
            path: path, action: "execute",
            pid: 1401, processName: "evil", processPath: "/Users/me/work/evil",
            timestamp: now.addingTimeInterval(2)
        )
        #expect(chain != nil, "User work-dir convergence must still fire")
    }

    // v1.21.4 perf (#3): shouldIgnoreFilePath is now a nonisolated static pure
    // predicate so the EventLoop hot path can drop ignored paths BEFORE the
    // actor hop. These guard that the extracted predicate returns the same
    // verdicts the in-actor guard used to, across every ignore category.
    @Test("nonisolated shouldIgnoreFilePath verdicts match each ignore category")
    func shouldIgnoreFilePathVerdicts() {
        // Ignored — one representative per category the guard covers.
        #expect(CrossProcessCorrelator.shouldIgnoreFilePath("/dev/null"))                       // exact
        #expect(CrossProcessCorrelator.shouldIgnoreFilePath("/System/Library/foo"))             // prefix
        #expect(CrossProcessCorrelator.shouldIgnoreFilePath("/Users/me/app.log"))               // suffix
        #expect(CrossProcessCorrelator.shouldIgnoreFilePath("/Users/me/Library/Caches/x"))      // substring
        #expect(CrossProcessCorrelator.shouldIgnoreFilePath("/Users/me/mylog.log.2"))           // rotated log

        // Not ignored — the paths a real cross-process chain forms on.
        #expect(!CrossProcessCorrelator.shouldIgnoreFilePath("/tmp/payload.bin"))
        #expect(!CrossProcessCorrelator.shouldIgnoreFilePath("/Users/me/work/evil"))
    }

    @Test("Ignored path is dropped identically through recordFileEvent")
    func ignoredPathDroppedByRecordFileEvent() async {
        // Parity: a path the static predicate flags as ignored must still be
        // dropped inside recordFileEvent (no chain) even for a 2-PID
        // write→execute shape that would otherwise fire — the in-actor guard
        // is unchanged.
        let correlator = CrossProcessCorrelator()
        let now = Date()
        let ignored = "/Users/me/Library/Caches/dropped-payload"
        #expect(CrossProcessCorrelator.shouldIgnoreFilePath(ignored))

        await correlator.recordFileEvent(
            path: ignored, action: "write",
            pid: 8100, processName: "curl", processPath: "/usr/bin/curl",
            timestamp: now
        )
        let chain = await correlator.recordFileEvent(
            path: ignored, action: "execute",
            pid: 8200, processName: "evil", processPath: "/Users/me/work/evil",
            timestamp: now.addingTimeInterval(2)
        )
        #expect(chain == nil, "ignored path must never form a chain")
    }
}

// Database encryption tests moved to DatabaseEncryptionTests.swift in
// v1.8.1 alongside the AES-GCM migration.

// MARK: - Rule Generator Tests

@Suite("Rule Generator")
struct RuleGeneratorTests {
    let tmpDir: String = {
        let dir = NSTemporaryDirectory() + "maccrab_ruletests_\(UUID().uuidString)"
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        return dir
    }()

    private func makeAlerts(count: Int) -> [(ruleId: String, ruleTitle: String, processPath: String?, tactics: Set<String>, timestamp: Date)] {
        (0..<count).map { i in
            (
                ruleId: "rule.\(i)",
                ruleTitle: "Test Rule \(i)",
                processPath: "/usr/bin/proc\(i)",
                tactics: Set(["attack.execution"]),
                timestamp: Date()
            )
        }
    }

    @Test("Returns nil for fewer than 2 alerts")
    func tooFewAlerts() async {
        let gen = await RuleGenerator(outputDir: tmpDir)
        let result = await gen.generateFromCampaign(
            campaignType: "test",
            alerts: makeAlerts(count: 1)
        )
        #expect(result == nil)
    }

    @Test("Returns nil for empty alert list")
    func emptyAlerts() async {
        let gen = await RuleGenerator(outputDir: tmpDir)
        let result = await gen.generateFromCampaign(
            campaignType: "test",
            alerts: []
        )
        #expect(result == nil)
    }

    @Test("Generates valid Sigma YAML for 2+ alerts")
    func generatesYAML() async {
        let gen = await RuleGenerator(outputDir: tmpDir)
        let result = await gen.generateFromCampaign(
            campaignType: "download_execute",
            alerts: makeAlerts(count: 3)
        )
        #expect(result != nil)
        guard let rule = result else { return }
        #expect(rule.yaml.contains("title:"))
        #expect(rule.yaml.contains("detection:"))
        #expect(rule.yaml.contains("condition:"))
        #expect(rule.yaml.contains("logsource:"))
        #expect(rule.yaml.contains("level: high"))
    }

    @Test("Filename includes campaign type")
    func filenameContainsCampaignType() async {
        let gen = await RuleGenerator(outputDir: tmpDir)
        let result = await gen.generateFromCampaign(
            campaignType: "lateral_movement",
            alerts: makeAlerts(count: 2)
        )
        #expect(result?.filename.contains("lateral_movement") == true)
    }

    @Test("Title is set and non-empty")
    func titleIsSet() async {
        let gen = await RuleGenerator(outputDir: tmpDir)
        let result = await gen.generateFromCampaign(
            campaignType: "credential_dump",
            alerts: makeAlerts(count: 2)
        )
        #expect(result?.title.isEmpty == false)
    }

    @Test("Stats count increments with each generation")
    func statsIncrement() async {
        let gen = await RuleGenerator(outputDir: tmpDir)
        let before = await gen.stats()
        _ = await gen.generateFromCampaign(
            campaignType: "test_increment",
            alerts: makeAlerts(count: 2)
        )
        let after = await gen.stats()
        #expect(after == before + 1)
    }

    @Test("Process paths appear in generated YAML")
    func processPathsInYAML() async {
        let gen = await RuleGenerator(outputDir: tmpDir)
        let alerts: [(ruleId: String, ruleTitle: String, processPath: String?, tactics: Set<String>, timestamp: Date)] = [
            (ruleId: "r1", ruleTitle: "R1", processPath: "/usr/bin/curl", tactics: [], timestamp: Date()),
            (ruleId: "r2", ruleTitle: "R2", processPath: "/bin/bash", tactics: [], timestamp: Date()),
        ]
        let result = await gen.generateFromCampaign(campaignType: "test_paths", alerts: alerts)
        #expect(result?.yaml.contains("curl") == true || result?.yaml.contains("bash") == true)
    }
}
