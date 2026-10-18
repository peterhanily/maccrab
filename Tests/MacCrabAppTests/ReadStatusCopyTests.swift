import Foundation
import Testing
@testable import MacCrabApp

@Suite("Concise read status preserves incomplete-data meaning")
struct ReadStatusCopyTests {
    @Test("Only a current successful read without a coverage warning may show empty copy",
          arguments: UIContentReadiness.Phase.allCases)
    func eventsEmptyMeaning(phase: UIContentReadiness.Phase) {
        let notice = EventReadNotice.resolve(phase: phase, hasWarning: false)
        #expect((notice == nil) == phase.isFreshCompletion)
        let withWarning = EventReadNotice.resolve(phase: phase, hasWarning: true)
        #expect(withWarning != nil)
        if phase.isFreshCompletion { #expect(withWarning == .partial) }
        if let notice { #expect(notice.canRetry == (notice != .loading)) }
    }

    @Test("Coverage warnings keep the consequence visible even during a refresh",
          arguments: UIContentReadiness.Phase.allCases)
    func warningMeaning(phase: UIContentReadiness.Phase) {
        let expected: EventReadNotice
        switch phase {
        case .failed: expected = .failed
        case .deferred: expected = .deferred
        case .unavailable: expected = .unavailable
        default: expected = .partial
        }
        #expect(EventReadNotice.warning(phase: phase) == expected)
        #expect(EventReadNotice.warning(phase: phase) != .loading)
    }

    @Test("Loading, partial, waiting, unavailable and failure remain distinct")
    func distinctNotices() {
        let eventNotices: [EventReadNotice] = [.loading, .partial, .deferred, .unavailable, .failed]
        let alertNotices: [V2AlertReadNotice] = [.loading, .partial, .deferred, .unavailable, .failed]
        #expect(Set(eventNotices.map(\.text)).count == 5)
        #expect(Set(alertNotices.map(\.text)).count == 5)
        for text in eventNotices.map(\.text) + alertNotices.map(\.text) {
            #expect(!text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        }
    }

    @Test("Production keeps notice slots, explicit retry, full details and existing truth guards")
    func sourceBindings() throws {
        let app = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/MacCrabApp")
        let alerts = try String(contentsOf: app.appendingPathComponent("V2/Workspaces/V2AlertsWorkspace.swift"), encoding: .utf8)
        let events = try String(contentsOf: app.appendingPathComponent("Views/EventStream.swift"), encoding: .utf8)
        #expect(alerts.contains("reservedMessages: [cachedNotice]"))
        #expect(events.contains("reservedMessages: [refreshingNotice, incompleteNotice]"))
        #expect(alerts.contains("!presentation.isFresh(for: presentationContext) ? 0 : nil"))
        #expect(events.contains("querySession.showingCachedEvents && !presentedEvents.isEmpty"))
        #expect(alerts.contains("if daemonReporting && presentation.isFresh(for: presentationContext) && !hasOpenAlerts"))
        #expect(events.contains(".contentReadiness(contentReadinessForDisplay)"))
        for source in [alerts, events] {
            #expect(source.contains("DisclosureGroup(String(localized: \"inspector.details\""))
            #expect(source.contains("Button(String(localized: \"common.retry\""))
            #expect(!source.contains("This is not an all-clear."))
            #expect(!source.contains("Content loaded"))
        }
        #expect(alerts.contains("Text(error).textSelection(.enabled)"))
        #expect(events.contains("Text(warning).textSelection(.enabled)"))
        #expect(events.contains("Text(EventReadNotice.warning(phase: contentReadinessForDisplay.phase).text)"))
        #expect(events.components(separatedBy: "EventReadNotice.resolve(phase: contentReadinessForDisplay.phase,").count - 1 == 2)
        #expect(events.contains("guard !Task.isCancelled else { return }\n        if isAggregateMode { aggregateRefreshTick &+= 1 }\n        recomputeFilter()"))
    }
}
