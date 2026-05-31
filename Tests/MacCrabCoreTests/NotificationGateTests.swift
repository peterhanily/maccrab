import Testing
import Foundation
@testable import MacCrabCore

/// Guards the shared notification decision logic that both the daemon
/// (NotificationOutput) and the app (AlertNotifier) rely on: severity
/// floor, enabled mute, per-minute rate limit + one storm summary, and
/// 1h per-(ruleId:processPath) dedup.
@Suite("NotificationGate")
struct NotificationGateTests {

    private func alert(rule: String = "r1", title: String = "Suspicious thing",
                       severity: Severity = .critical, process: String? = "/bin/evil",
                       name: String? = "evil") -> Alert {
        Alert(ruleId: rule, ruleTitle: title, severity: severity, eventId: "e1",
              processPath: process, processName: name)
    }

    @Test("enabled=false drops everything regardless of severity")
    func disabledDropsAll() {
        var gate = NotificationGate(minimumSeverity: .low, enabled: false)
        #expect(gate.evaluate(alert: alert(severity: .critical)) == .drop)
    }

    @Test("below the severity floor drops; at/above delivers")
    func severityFloor() {
        var gate = NotificationGate(minimumSeverity: .high)
        #expect(gate.evaluate(alert: alert(rule: "a", severity: .medium)) == .drop)
        if case .deliver = gate.evaluate(alert: alert(rule: "b", severity: .high)) {} else {
            Issue.record("high should deliver at min=high")
        }
        if case .deliver = gate.evaluate(alert: alert(rule: "c", severity: .critical)) {} else {
            Issue.record("critical should deliver at min=high")
        }
    }

    @Test("deliver banner carries severity emoji + rule title + process")
    func bannerText() {
        var gate = NotificationGate(minimumSeverity: .low)
        guard case let .deliver(title, body, _) = gate.evaluate(alert: alert(title: "Creds dumped", severity: .critical, name: "lsass")) else {
            Issue.record("expected deliver"); return
        }
        #expect(title.contains("🔴"))
        #expect(title.contains("Creds dumped"))
        #expect(body.contains("lsass"))
    }

    @Test("same rule+process within the window dedups; distinct rule delivers")
    func dedup() {
        var gate = NotificationGate(minimumSeverity: .low)
        let t0 = Date(timeIntervalSince1970: 1_000_000)
        if case .deliver = gate.evaluate(alert: alert(rule: "r1"), now: t0) {} else { Issue.record("first should deliver") }
        // same rule+process, 10 min later → deduped
        #expect(gate.evaluate(alert: alert(rule: "r1"), now: t0.addingTimeInterval(600)) == .drop)
        // different rule, same process → delivers
        if case .deliver = gate.evaluate(alert: alert(rule: "r2"), now: t0.addingTimeInterval(601)) {} else {
            Issue.record("distinct rule should deliver")
        }
        // same rule, just past the 1h window → delivers again
        if case .deliver = gate.evaluate(alert: alert(rule: "r1"), now: t0.addingTimeInterval(3601)) {} else {
            Issue.record("re-fire past dedup window should deliver")
        }
    }

    @Test("rate-limit storm yields exactly one summary, then drops")
    func stormSummary() {
        var gate = NotificationGate(minimumSeverity: .low, maxPerMinute: 3)
        let t = Date(timeIntervalSince1970: 2_000_000)
        // distinct rules so dedup never interferes; same instant so the
        // 60s window holds them all.
        var delivered = 0, summaries = 0, drops = 0
        for i in 0..<6 {
            switch gate.evaluate(alert: alert(rule: "rule\(i)"), now: t) {
            case .deliver:      delivered += 1
            case .stormSummary: summaries += 1
            case .drop:         drops += 1
            }
        }
        #expect(delivered == 3)   // up to maxPerMinute
        #expect(summaries == 1)   // exactly one storm summary
        #expect(drops == 2)       // the rest dropped
    }
}
