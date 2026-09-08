import Foundation
import Testing
@testable import MacCrabApp

@MainActor
@Suite("Mascot protection readiness")
struct V2CrabReadinessTests {
    @Test("an existing store and cheerful mood cannot override unavailable protection")
    func readinessOverridesMood() {
        let cases: [(V2ProtectionStatus, String)] = [
            (.starting, String(localized: "system.startupTitle", defaultValue: "Protection is starting")),
            (.unavailable, String(localized: "overview.bannerTitleUnavailable", defaultValue: "Protection unavailable — engine not ready")),
            (.degraded, String(localized: "overview.bannerTitleDegraded", defaultValue: "Protection degraded — review System Health")),
            (.inactive, String(localized: "overview.bannerTitleInactive", defaultValue: "Protection inactive — daemon not detected")),
        ]
        for (status, expected) in cases {
            // A preserved database remains connected after a failed engine
            // restart. The prior cheerful mood must not claim monitoring.
            let widget = V2CrabWidget(mood: .happy, protectionStatus: status, connected: true)
            #expect(widget.statusText == expected)
            let alarmed = V2CrabWidget(mood: .critical, protectionStatus: status,
                                      criticalCampaigns: 3, connected: true)
            #expect(alarmed.statusText == expected)
        }
    }

    @Test("confirmed active protection retains the existing cheerful quip")
    func activeMoodStillApplies() {
        let widget = V2CrabWidget(mood: .happy, protectionStatus: .active, connected: true)
        #expect(widget.statusText == String(localized: "overview.crab.quipHappy",
                    defaultValue: "Monitoring is active — no alerts waiting. 🦀"))
    }
}
