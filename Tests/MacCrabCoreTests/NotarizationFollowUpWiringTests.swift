import Foundation
import Testing
@testable import MacCrabCore

/// A lane-inline notarization miss is assessed on the bounded follow-up
/// plane; that plane's sheds are visible in the heartbeat and count as a
/// protection gap; a rule+hash suppression uses only the event's own digest.
@Suite("Notarization follow-up wiring and visibility")
struct NotarizationFollowUpWiringTests {
    private func source(_ path: String) throws -> String {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        return try String(contentsOf: root.appendingPathComponent(path), encoding: .utf8)
    }

    @Test("a shed follow-up check decodes as degraded protection")
    func shedIsProtectionLoss() throws {
        let h = try JSONDecoder().decode(HeartbeatSnapshot.self, from: Data("""
        {"schema_version": 5,
         "notarization_follow_up_lifecycle": {
           "accepting": true, "offered_handlers_total": 40, "accepted_handlers_total": 32,
           "completed_handlers_total": 32, "rejected_handlers_total": 0,
           "closed_rejected_handlers_total": 0, "overload_shed_handlers_total": 8,
           "coalesced_handlers_total": 0, "coalesced_by_label": {}, "rejected_by_label": {},
           "inline_fallback_handlers_total": 0, "inline_fallbacks_by_label": {},
           "in_flight_handlers": 0, "maximum_in_flight_handlers": 32,
           "conserves_accepted_handlers": true, "conserves_offered_handlers": true}}
        """.utf8))
        #expect(h.notarizationFollowUpLifecycle?.overloadShedHandlersTotal == 8)
        #expect(h.notarizationFollowUpLifecycle?.detectionProtectionDegraded == true)
    }

    @Test("the heartbeat publishes the follow-up plane")
    func heartbeatPublishesPlane() throws {
        let timers = try source("Sources/MacCrabAgentKit/DaemonTimers.swift")
        #expect(timers.contains("let notarizationFollowUpPlane = state.notarizationFollowUpLifecycle.snapshot()"))
        let key = try #require(timers.range(of: "\"notarization_follow_up_lifecycle\":"))
        #expect(timers[key.upperBound...].prefix(80).contains("workLifecycleDictionary(notarizationFollowUpPlane)"))
    }

    @Test("a lane-inline cache miss is assessed on the follow-up plane, off the lane")
    func missGoesToFollowUp() throws {
        let loop = try source("Sources/MacCrabAgentKit/EventLoop.swift")
        #expect(!loop.contains("cachedResultForOverload(binaryPath: execPath) else { return }"))
        let submit = try #require(loop.range(of: "notarizationFollowUps.submit(label: \"notarization-follow-up\") {"))
        let body = loop[submit.upperBound...].prefix(300)
        #expect(body.contains("DaemonWorkInlineContext.$isRunningOnLane.withValue(false)"))
        #expect(body.contains("await assessNotarization(await notarizationChecker.check(binaryPath: execPath))"))
    }

    @Test("rule+hash suppression uses only the event's own digest, never a path-keyed cache")
    func suppressionUsesEventDigest() throws {
        let state = try source("Sources/MacCrabAgentKit/DaemonState.swift")
        let start = try #require(state.range(of: "func isSuppressed(_ match: RuleMatch, event: Event) async -> Bool {"))
        let body = state[start.lowerBound...].prefix(400)
        #expect(body.contains("processSHA256: event.process.hashes?.sha256"))
        for cache in ["cachedExecutableSHA256", "cachedSHA256", "cachedHash", "fileHasher"] {
            #expect(!body.contains(cache), "\(cache)")
        }
    }
}
