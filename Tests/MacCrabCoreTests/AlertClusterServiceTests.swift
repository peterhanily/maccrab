// AlertClusterServiceTests.swift
//
// Coverage for AlertClusterService — the deterministic-first
// similar-alert grouping that feeds the v1.6.6 Semantic Clustering
// dashboard. The LLM rationale pass is covered only at the fallback
// path (nil LLMService returns the cluster unchanged); refining with a
// real backend is exercised by the integration tests that hit Ollama.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("AlertClusterService: deterministic clustering")
struct AlertClusterServiceDeterministicTests {

    private func alert(
        id: String = UUID().uuidString,
        rule: String,
        title: String,
        severity: Severity = .medium,
        processName: String?,
        processPath: String? = nil,
        tactics: String? = nil,
        timestamp: Date = Date()
    ) -> Alert {
        Alert(
            id: id,
            timestamp: timestamp,
            ruleId: rule,
            ruleTitle: title,
            severity: severity,
            eventId: UUID().uuidString,
            processPath: processPath,
            processName: processName,
            description: nil,
            mitreTactics: tactics,
            mitreTechniques: nil,
            suppressed: false
        )
    }

    @Test("Empty input returns empty clusters")
    func emptyInput() async {
        let svc = AlertClusterService()
        let result = await svc.cluster(alerts: [])
        #expect(result.isEmpty)
    }

    @Test("Two alerts with identical ruleId + processName form one cluster of size 2")
    func identicalFingerprintOneCluster() async {
        let svc = AlertClusterService()
        let a = alert(rule: "rule.ps", title: "Process Listing by Unsigned", processName: "ps", processPath: "/bin/ps")
        let b = alert(rule: "rule.ps", title: "Process Listing by Unsigned", processName: "ps", processPath: "/bin/ps")
        let clusters = await svc.cluster(alerts: [a, b])
        #expect(clusters.count == 1)
        #expect(clusters[0].size == 2)
        #expect(clusters[0].ruleId == "rule.ps")
        #expect(clusters[0].processName == "ps")
    }

    @Test("Alerts with different processes form separate clusters")
    func differentProcessesSeparateClusters() async {
        let svc = AlertClusterService()
        let a = alert(rule: "rule.sysinfo", title: "Rapid System Info Enumeration", processName: "sw_vers")
        let b = alert(rule: "rule.sysinfo", title: "Rapid System Info Enumeration", processName: "system_profiler")
        let clusters = await svc.cluster(alerts: [a, b])
        #expect(clusters.count == 2)
        #expect(clusters.allSatisfy { $0.size == 1 })
    }

    @Test("Cluster id is stable across re-runs for the same fingerprint")
    func stableClusterId() async {
        let svc = AlertClusterService()
        let a = alert(rule: "rule.x", title: "X", processName: "xprocess")
        let b = alert(rule: "rule.x", title: "X", processName: "xprocess")
        let run1 = await svc.cluster(alerts: [a])
        let run2 = await svc.cluster(alerts: [b])
        #expect(run1.first?.id == run2.first?.id, "Same fingerprint must produce the same cluster id")
    }

    @Test("Max-severity is preserved across a mixed-severity cluster")
    func maxSeverityWins() async {
        let svc = AlertClusterService()
        let med = alert(rule: "rule.y", title: "Y", severity: .medium, processName: "y")
        let high = alert(rule: "rule.y", title: "Y", severity: .high, processName: "y")
        let low = alert(rule: "rule.y", title: "Y", severity: .low, processName: "y")
        let clusters = await svc.cluster(alerts: [med, high, low])
        #expect(clusters.count == 1)
        #expect(clusters[0].severity == .high)
    }

    @Test("Clusters are sorted by severity desc, then newest lastSeen first")
    func sortOrder() async {
        let svc = AlertClusterService()
        let now = Date()
        let oldHigh = alert(rule: "rule.old", title: "Old", severity: .high, processName: "a", timestamp: now.addingTimeInterval(-3600))
        let newMed = alert(rule: "rule.new", title: "New", severity: .medium, processName: "b", timestamp: now)
        let newCritical = alert(rule: "rule.cr", title: "Critical", severity: .critical, processName: "c", timestamp: now.addingTimeInterval(-60))
        let clusters = await svc.cluster(alerts: [oldHigh, newMed, newCritical])
        #expect(clusters.count == 3)
        #expect(clusters[0].severity == .critical)
        #expect(clusters[1].severity == .high)
        #expect(clusters[2].severity == .medium)
    }

    @Test("Nil processName falls back to processPath basename")
    func processNameFallback() async {
        let svc = AlertClusterService()
        let a = alert(rule: "rule.z", title: "Z", processName: nil, processPath: "/tmp/sneaky-binary")
        let b = alert(rule: "rule.z", title: "Z", processName: nil, processPath: "/tmp/sneaky-binary")
        let clusters = await svc.cluster(alerts: [a, b])
        #expect(clusters.count == 1)
        #expect(clusters[0].processName == "sneaky-binary")
        #expect(clusters[0].size == 2)
    }

    @Test("Tactics union across cluster members")
    func tacticsUnion() async {
        let svc = AlertClusterService()
        let a = alert(rule: "rule.t", title: "T", processName: "t", tactics: "TA0001,TA0002")
        let b = alert(rule: "rule.t", title: "T", processName: "t", tactics: "TA0002,TA0003")
        let clusters = await svc.cluster(alerts: [a, b])
        #expect(clusters[0].tactics == Set(["TA0001", "TA0002", "TA0003"]))
    }

    @Test("Member IDs ordered newest-first within a cluster")
    func memberOrdering() async {
        let svc = AlertClusterService()
        let now = Date()
        let older = alert(id: "older", rule: "rule.o", title: "O", processName: "o", timestamp: now.addingTimeInterval(-60))
        let newer = alert(id: "newer", rule: "rule.o", title: "O", processName: "o", timestamp: now)
        let clusters = await svc.cluster(alerts: [older, newer])
        #expect(clusters[0].memberAlertIds == ["newer", "older"])
    }

    @Test("v1.6.5 noise pattern: thirteen FPs collapse to ten clusters")
    func v165NoisePattern() async {
        // Reproduces the exact list we saw in the v1.6.5 test-machine run
        // (before the fixes landed) — the whole point of clustering is
        // to give the analyst a tight view of what families are firing.
        // This test documents the expected shape of that triage view:
        // 13 raw alerts collapse to 10 clusters (3 pairs + 7 singletons).
        let svc = AlertClusterService()
        let alerts: [Alert] = [
            alert(rule: "tcc_bypass", title: "TCC Bypass", severity: .high, processName: "GoogleUpdater"),
            alert(rule: "tcc_bypass", title: "TCC Bypass", severity: .high, processName: "launcher"),
            alert(rule: "process_listing_unsigned", title: "Process Listing by Unsigned", severity: .low, processName: "ps"),
            alert(rule: "process_listing_unsigned", title: "Process Listing by Unsigned", severity: .low, processName: "ps"),
            alert(rule: "defaults_read_sensitive", title: "Defaults Read Sensitive", severity: .low, processName: "defaults"),
            alert(rule: "defaults_read_sensitive", title: "Defaults Read Sensitive", severity: .low, processName: "defaults"),
            alert(rule: "csrutil_status", title: "SIP Status Queried", severity: .low, processName: "csrutil"),
            alert(rule: "csrutil_status", title: "SIP Status Queried", severity: .low, processName: "csrutil"),
            alert(rule: "sysinfo_burst", title: "Rapid System Info", severity: .low, processName: "sw_vers"),
            alert(rule: "sysinfo_burst", title: "Rapid System Info", severity: .low, processName: "system_profiler"),
            alert(rule: "cred_exfil", title: "Credential Exfil", severity: .critical, processName: "networkserviceproxy"),
            alert(rule: "mdm_enrollment", title: "MDM Enrollment", severity: .medium, processName: "profiles"),
            alert(rule: "hidden_file", title: "Hidden File", severity: .low, processName: "logioptionsplus_agent"),
        ]
        let clusters = await svc.cluster(alerts: alerts)
        // 10 clusters: tcc_bypass×2 (GoogleUpdater + launcher), process_listing×1 (ps, size 2),
        // defaults×1 (size 2), csrutil×1 (size 2), sysinfo_burst×2 (sw_vers + system_profiler),
        // cred_exfil×1, mdm_enrollment×1, hidden_file×1 = 10.
        #expect(clusters.count == 10)
        #expect(clusters[0].severity == .critical, "Critical cred-exfil must surface at the top")
        #expect(clusters[0].ruleId == "cred_exfil")
        let pairCount = clusters.filter { $0.size == 2 }.count
        #expect(pairCount == 3, "process_listing, defaults, and csrutil should each collapse a pair")
    }
}

@Suite("AlertClusterService: LLM rationale fallback")
struct AlertClusterServiceRationaleTests {

    @Test("refineRationale returns original cluster when LLM is unavailable")
    func noLLMReturnsUnchanged() async {
        let svc = AlertClusterService(llm: nil)
        let cluster = AlertCluster(
            id: "cluster.test", fingerprint: "x::y",
            ruleId: "x", ruleTitle: "X",
            processName: "y", processPath: nil,
            severity: .medium,
            memberAlertIds: ["a1", "a2"],
            tactics: [],
            firstSeen: Date(), lastSeen: Date(),
            rationale: nil
        )
        let refined = await svc.refineRationale(cluster, membersSnapshot: [])
        #expect(refined.rationale == nil)
        #expect(refined.id == cluster.id)
    }
}
