import Foundation
import Testing
@testable import MacCrabApp

/// Authored values and an explicit source string only: no file creation, real
/// preferences/configuration, native collectors, background tasks or listeners.
@MainActor
@Suite("AppState inert startup preferences")
struct AppStateStartupPreferencesTests {
    @Test("Background-disabled initialization never invokes persisted-preference readers")
    func inertInitializationSkipsReader() {
        let source = V2EngineSource(directory: "/private/tmp/inert-app-startup-" + UUID().uuidString)
        var reads = 0
        let app = AppState(engineSource: source, startBackgroundWork: false,
                           readStartupPreferences: {
            reads += 1
            Issue.record("Inert initialization attempted to read persisted preferences")
            return .init(fdaBannerDismissedByUser: true, agentTracesReceiverEnabled: true)
        })
        #expect(reads == 0)
        #expect(app.engineSource == source)
        #expect(!app.fdaBannerDismissedByUser && !app.agentTracesReceiverEnabled)
        #expect(app.agentTracesEnableRequestedAt == nil)
        #if DEBUG
        #expect(!app.hasCachedEventStoreForTesting && app.eventReaderAdmissionsForTesting == 0)
        #endif
        #expect(!app.eventsWorkspaceVisible && app.events.isEmpty && app.dashboardAlerts.isEmpty)
    }

    @Test("Startup preference reader preserves both booleans and reads each once",
          arguments: [false, true], [false, true])
    func preferenceValuesArePreserved(fda: Bool, receiver: Bool) {
        var reads: [String] = []
        let preferences = AppState.StartupPreferences.read(
            fdaDismissed: { reads.append("fda"); return fda },
            receiverEnabled: { reads.append("receiver"); return receiver }
        )
        #expect(preferences.fdaBannerDismissedByUser == fda)
        #expect(preferences.agentTracesReceiverEnabled == receiver)
        #expect(reads == ["fda", "receiver"])
    }
}
