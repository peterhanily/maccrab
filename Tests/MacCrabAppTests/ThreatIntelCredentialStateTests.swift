import Testing
@testable import MacCrabApp

@Suite("Threat-intelligence credential presentation")
struct ThreatIntelCredentialStateTests {
    enum Failure: Error { case unavailable }

    @Test("save and deletion require exact readback, without any network or consent dependency")
    func explicitChanges() {
        var state = ThreatIntelCredentialState()
        var stored: String?
        state.refresh { stored }
        #expect(state.hasStoredKey == false)
        state.change(candidate: "fixture-only", write: { stored = $0 }, read: { stored })
        #expect(state.outcome == .saved)
        #expect(state.hasStoredKey == true)
        state.change(candidate: nil, write: { stored = $0 }, read: { stored })
        #expect(state.outcome == .deleted)
        #expect(stored == nil)
    }

    @Test("failed reads and mismatched writes never report a verified change")
    func failureStates() {
        var state = ThreatIntelCredentialState()
        state.refresh { throw Failure.unavailable }
        #expect(state.hasStoredKey == nil)
        var writes = 0
        state.change(candidate: nil, write: { _ in writes += 1 }, read: { nil })
        #expect(writes == 0)
        state.change(candidate: "fixture-only", write: { _ in writes += 1 }, read: { "previous-fixture" })
        #expect(state.outcome == .failed)
        #expect(state.hasStoredKey == nil)
        state.change(candidate: "fixture-only", write: { _ in throw Failure.unavailable }, read: { "fixture-only" })
        #expect(state.outcome == .failed)
    }
}
