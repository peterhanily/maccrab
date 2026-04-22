// Phase5Tests.swift
// Coverage for Phase 4 & 5 additions:
//   - DoHDetector: new resolver IPs (Cloudflare for Families, Mullvad, ControlD, DNS.SB, Comodo)
//   - LLMBackend protocol extension: default completeWithExtendedThinking delegates to complete()
//   - AlertStore ruleId filtering for maccrab.vuln.* and maccrab.privacy.* alerts

import Testing
import Foundation
@testable import MacCrabCore

// MARK: - DoHDetector: Phase 4 resolver IP expansion

@Suite("DoHDetector — Phase 4 resolver expansion")
struct DoHDetectorResolverExpansionTests {

    private func check(_ ip: String) async -> DoHDetector.DoHViolation? {
        let detector = DoHDetector()
        return await detector.check(
            processName: "malware",
            processPath: "/tmp/malware",
            pid: 9999,
            destinationIP: ip,
            destinationPort: 443
        )
    }

    @Test("Cloudflare for Families malware-blocking IPs fire")
    func cloudflareFamiliesMalware() async {
        #expect(await check("1.1.1.2") != nil)
        #expect(await check("1.0.0.2") != nil)
    }

    @Test("Cloudflare for Families adult-blocking IPs fire")
    func cloudflareFamiliesAdult() async {
        #expect(await check("1.1.1.3") != nil)
        #expect(await check("1.0.0.3") != nil)
    }

    @Test("Mullvad DNS IPs fire")
    func mullvad() async {
        #expect(await check("194.242.2.2") != nil)
        #expect(await check("193.19.108.2") != nil)
    }

    @Test("ControlD IPs fire")
    func controlD() async {
        #expect(await check("76.76.2.0") != nil)
        #expect(await check("76.76.10.0") != nil)
    }

    @Test("DNS.SB IPs fire")
    func dnsSB() async {
        #expect(await check("185.222.222.222") != nil)
        #expect(await check("45.11.45.11") != nil)
    }

    @Test("Comodo Secure DNS IPs fire")
    func comodo() async {
        #expect(await check("8.26.56.26") != nil)
        #expect(await check("8.20.247.20") != nil)
    }

    @Test("Random non-DoH IP does not fire")
    func randomIPSilent() async {
        #expect(await check("203.0.113.42") == nil)
    }

    @Test("Non-HTTPS port does not fire for known resolver IP")
    func wrongPort() async {
        let detector = DoHDetector()
        let v = await detector.check(
            processName: "malware",
            processPath: "/tmp/malware",
            pid: 9999,
            destinationIP: "194.242.2.2",
            destinationPort: 53
        )
        #expect(v == nil)
    }

    @Test("Resolver name is correct for Mullvad")
    func mullvadResolverName() async {
        let v = await check("194.242.2.2")
        #expect(v?.resolverName == "Mullvad DNS")
    }

    @Test("Resolver name is correct for ControlD")
    func controlDResolverName() async {
        let v = await check("76.76.2.0")
        #expect(v?.resolverName == "ControlD DNS")
    }

    @Test("Resolver name is correct for DNS.SB")
    func dnsSBResolverName() async {
        let v = await check("185.222.222.222")
        #expect(v?.resolverName == "DNS.SB")
    }

    @Test("Resolver name is correct for Comodo")
    func comodoResolverName() async {
        let v = await check("8.26.56.26")
        #expect(v?.resolverName == "Comodo Secure DNS")
    }
}

// MARK: - LLMBackend protocol extension default

/// Minimal mock that tracks whether complete() was called from the protocol default.
private actor TrackingBackend: LLMBackend {
    var providerName: String { "Tracking" }
    var completeCalled = false
    var capturedMaxTokens: Int = 0

    func isAvailable() async -> Bool { true }

    func complete(
        systemPrompt: String,
        userPrompt: String,
        maxTokens: Int,
        temperature: Double
    ) async -> String? {
        completeCalled = true
        capturedMaxTokens = maxTokens
        return "mock-response"
    }
    // Does NOT override completeWithExtendedThinking — exercises protocol default.
}

@Suite("LLMBackend extended thinking protocol extension")
struct ExtendedThinkingProtocolTests {

    @Test("Default completeWithExtendedThinking delegates to complete()")
    func defaultFallbackToComplete() async {
        let backend = TrackingBackend()
        let result = await backend.completeWithExtendedThinking(
            systemPrompt: "sys",
            userPrompt: "usr",
            thinkingBudgetTokens: 8000,
            maxOutputTokens: 1024
        )
        let called = await backend.completeCalled
        #expect(called)
        #expect(result == "mock-response")
    }

    @Test("Default fallback passes maxOutputTokens as maxTokens to complete()")
    func maxTokensForwarded() async {
        let backend = TrackingBackend()
        _ = await backend.completeWithExtendedThinking(
            systemPrompt: "s",
            userPrompt: "u",
            thinkingBudgetTokens: 4000,
            maxOutputTokens: 2048
        )
        let captured = await backend.capturedMaxTokens
        #expect(captured == 2048)
    }
}

// MARK: - Vuln and Privacy alert ruleId filtering

@Suite("Vuln and Privacy alert ruleId filtering")
struct VulnPrivacyAlertFilterTests {

    private func makeTempStore() throws -> (AlertStore, URL) {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let store = try AlertStore(directory: dir.path)
        return (store, dir)
    }

    @Test("Vuln alerts are isolated by ruleId prefix")
    func vulnFilterByRuleId() async throws {
        let (store, dir) = try makeTempStore()
        defer { try? FileManager.default.removeItem(at: dir) }

        let vuln = Alert(
            id: "vuln-CVE-2025-9999",
            ruleId: "maccrab.vuln.CVE-2025-9999",
            ruleTitle: "CVE-2025-9999 in Foo 1.0.0",
            severity: .critical,
            eventId: "vuln-CVE-2025-9999",
            processPath: "/Applications/Foo.app",
            processName: "Foo",
            description: "Foo 1.0.0 contains CVE-2025-9999 (CRITICAL). Update to 1.0.1.",
            suppressed: false
        )
        let regular = makeAlert(ruleId: "some.other.rule", ruleTitle: "Other Alert")
        try await store.insert(alert: vuln)
        try await store.insert(alert: regular)

        let all = try await store.alerts(since: Date.distantPast, limit: 50)
        let vulns = all.filter { $0.ruleId.hasPrefix("maccrab.vuln.") }
        #expect(vulns.count == 1)
        #expect(vulns[0].id == "vuln-CVE-2025-9999")
        #expect(vulns[0].processName == "Foo")
    }

    @Test("Privacy alerts are isolated by ruleId prefix")
    func privacyFilterByRuleId() async throws {
        let (store, dir) = try makeTempStore()
        defer { try? FileManager.default.removeItem(at: dir) }

        let privacy = Alert(
            id: "privacy-SuspiciousApp-bulkEgress",
            ruleId: "maccrab.privacy.bulkEgress",
            ruleTitle: "Bulk Egress from SuspiciousApp",
            severity: .medium,
            eventId: "privacy-SuspiciousApp-bulkEgress",
            processPath: "/Applications/SuspiciousApp.app",
            processName: "SuspiciousApp",
            description: "SuspiciousApp sent 55 MB in 1h. Total: 55 MB to 3 domains.",
            suppressed: false
        )
        let vuln = Alert(
            id: "vuln-CVE-2025-0001",
            ruleId: "maccrab.vuln.CVE-2025-0001",
            ruleTitle: "CVE-2025-0001 in Bar 2.0.0",
            severity: .high,
            eventId: "vuln-CVE-2025-0001",
            processPath: "/Applications/Bar.app",
            processName: "Bar",
            description: "Update Bar.",
            suppressed: false
        )
        try await store.insert(alert: privacy)
        try await store.insert(alert: vuln)

        let all = try await store.alerts(since: Date.distantPast, limit: 50)
        let privAlerts = all.filter { $0.ruleId.hasPrefix("maccrab.privacy.") }
        #expect(privAlerts.count == 1)
        #expect(privAlerts[0].id == "privacy-SuspiciousApp-bulkEgress")
        #expect(privAlerts[0].severity == .medium)
    }

    @Test("Deterministic vuln alert ID deduplicates via INSERT OR REPLACE")
    func vulnAlertDeduplication() async throws {
        let (store, dir) = try makeTempStore()
        defer { try? FileManager.default.removeItem(at: dir) }

        let id = "vuln-CVE-2025-1234"
        let first = Alert(
            id: id, ruleId: "maccrab.vuln.CVE-2025-1234",
            ruleTitle: "CVE-2025-1234 in Bar 2.0.0", severity: .high,
            eventId: id, processPath: "/Applications/Bar.app", processName: "Bar",
            description: "First scan.", suppressed: false
        )
        let second = Alert(
            id: id, ruleId: "maccrab.vuln.CVE-2025-1234",
            ruleTitle: "CVE-2025-1234 in Bar 2.0.0", severity: .high,
            eventId: id, processPath: "/Applications/Bar.app", processName: "Bar",
            description: "Second scan — updated timestamp.", suppressed: false
        )
        try await store.insert(alert: first)
        try await store.insert(alert: second)

        let all = try await store.alerts(since: Date.distantPast, limit: 50)
        let vulns = all.filter { $0.ruleId == "maccrab.vuln.CVE-2025-1234" }
        #expect(vulns.count == 1, "INSERT OR REPLACE should deduplicate by id")
    }

    @Test("Deterministic privacy alert ID deduplicates via INSERT OR REPLACE")
    func privacyAlertDeduplication() async throws {
        let (store, dir) = try makeTempStore()
        defer { try? FileManager.default.removeItem(at: dir) }

        let id = "privacy-App-trackingContact"
        let first = Alert(
            id: id, ruleId: "maccrab.privacy.trackingContact",
            ruleTitle: "Tracker Contact from App", severity: .medium,
            eventId: id, processPath: "/Applications/App.app", processName: "App",
            description: "First audit.", suppressed: false
        )
        let second = Alert(
            id: id, ruleId: "maccrab.privacy.trackingContact",
            ruleTitle: "Tracker Contact from App", severity: .medium,
            eventId: id, processPath: "/Applications/App.app", processName: "App",
            description: "Second audit.", suppressed: false
        )
        try await store.insert(alert: first)
        try await store.insert(alert: second)

        let all = try await store.alerts(since: Date.distantPast, limit: 50)
        let privAlerts = all.filter { $0.ruleId == "maccrab.privacy.trackingContact" }
        #expect(privAlerts.count == 1, "INSERT OR REPLACE should deduplicate by id")
    }
}
