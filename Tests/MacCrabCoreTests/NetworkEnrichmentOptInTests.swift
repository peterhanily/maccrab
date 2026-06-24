// NetworkEnrichmentOptInTests.swift
//
// v1.19.1 privacy guarantee: the four features that make OUTBOUND network
// requests — abuse.ch threat-intel, osv.dev vuln scan, npm/PyPI/etc package
// freshness, and crt.sh certificate transparency — are OFF BY DEFAULT. Nothing
// about the machine leaves it until the user opts in. These tests pin the
// defaults and the opt-in decode paths so a future edit can't silently flip a
// feed back on.

import Testing
import Foundation
@testable import MacCrabAgentKit
@testable import MacCrabCore

@Suite("Network enrichment is opt-in (v1.19.1)")
struct NetworkEnrichmentOptInTests {

    private func writeConfig(_ json: String) -> String {
        let tmp = NSTemporaryDirectory() + "MacCrabOptInTest-\(UUID().uuidString)"
        try? FileManager.default.createDirectory(atPath: tmp, withIntermediateDirectories: true)
        try? json.data(using: .utf8)!.write(to: URL(fileURLWithPath: tmp + "/daemon_config.json"))
        return tmp
    }

    @Test("All four egress feeds default to OFF")
    func defaultsAreOff() {
        let cfg = DaemonConfig()
        #expect(cfg.threatIntelEnabled == false)
        #expect(cfg.vulnScanEnabled == false)
        #expect(cfg.packageFreshnessEnabled == false)
        #expect(cfg.certTransparencyEnabled == false)
    }

    @Test("An unrelated config file leaves all four OFF")
    func unrelatedConfigKeepsOff() {
        let tmp = writeConfig(#"{ "behavior_alert_threshold": 15.0 }"#)
        defer { try? FileManager.default.removeItem(atPath: tmp) }
        let cfg = DaemonConfig.load(from: tmp, applyOverrides: false)
        #expect(cfg.threatIntelEnabled == false)
        #expect(cfg.vulnScanEnabled == false)
        #expect(cfg.packageFreshnessEnabled == false)
        #expect(cfg.certTransparencyEnabled == false)
    }

    @Test("snake_case opt-in keys enable each feed")
    func snakeCaseOptIn() {
        let tmp = writeConfig("""
        {
          "threat_intel_enabled": true,
          "vuln_scan_enabled": true,
          "package_freshness_enabled": true,
          "cert_transparency_enabled": true
        }
        """)
        defer { try? FileManager.default.removeItem(atPath: tmp) }
        let cfg = DaemonConfig.load(from: tmp, applyOverrides: false)
        #expect(cfg.threatIntelEnabled)
        #expect(cfg.vulnScanEnabled)
        #expect(cfg.packageFreshnessEnabled)
        #expect(cfg.certTransparencyEnabled)
    }

    @Test("camelCase opt-in keys enable each feed")
    func camelCaseOptIn() {
        let tmp = writeConfig("""
        { "threatIntelEnabled": true, "certTransparencyEnabled": true }
        """)
        defer { try? FileManager.default.removeItem(atPath: tmp) }
        let cfg = DaemonConfig.load(from: tmp, applyOverrides: false)
        #expect(cfg.threatIntelEnabled)
        #expect(cfg.certTransparencyEnabled)
        // The ones NOT named stay off — opting one feed in must not enable others.
        #expect(cfg.vulnScanEnabled == false)
        #expect(cfg.packageFreshnessEnabled == false)
    }

    @Test("ThreatIntelFeed.refreshNow does NOT fetch when threat-intel is off (zero egress)")
    func refreshNowNoEgressWhenOff() async {
        // The off-by-default state: the network refresh loop was never started,
        // so refreshNow() — the path hit by SIGHUP, the refresh-intel inbox
        // request, and the dashboard "Refresh Now" button — must be a no-op.
        // This is the privacy-invariant regression for the review's P1: a
        // trailing refresh fired abuse.ch egress regardless of the flag.
        let tmp = NSTemporaryDirectory() + "MacCrabTI-\(UUID().uuidString)"
        let feed = ThreatIntelFeed(cacheDir: tmp)
        await feed.refreshNow()
        #expect(await feed.networkFetchAttempts == 0)
        // The default-off boot path (start with networkRefresh:false) loads only
        // local cache/bundled IOCs — still zero outbound fetches.
        await feed.start(networkRefresh: false)
        await feed.refreshNow()
        #expect(await feed.networkFetchAttempts == 0)
    }

    @Test("Enabling one feed does not enable the others")
    func oneFeedIsolated() {
        let tmp = writeConfig(#"{ "vuln_scan_enabled": true }"#)
        defer { try? FileManager.default.removeItem(atPath: tmp) }
        let cfg = DaemonConfig.load(from: tmp, applyOverrides: false)
        #expect(cfg.vulnScanEnabled)
        #expect(cfg.threatIntelEnabled == false)
        #expect(cfg.packageFreshnessEnabled == false)
        #expect(cfg.certTransparencyEnabled == false)
    }
}
