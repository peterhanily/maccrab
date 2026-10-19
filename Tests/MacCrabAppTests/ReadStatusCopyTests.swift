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

    @Test("Histogram coverage does not change successful table-read meaning")
    func histogramProvenance() {
        let presentation = EventCoveragePresentation(phase: .loadedEmpty, isAggregate: false,
            tableIsEmpty: true, tableWarning: nil, histogramWarning: "retained interval only")
        #expect(presentation.emptyNotice == nil)
        #expect(presentation.tableWarning == nil)
        #expect(presentation.bannerWarnings.map(\.source) == [.histogram])
    }

    @Test("Independent warnings coexist; an empty table owns its warning exactly once",
          arguments: [true, false], UIContentReadiness.Phase.allCases)
    func independentCoverage(tableIsEmpty: Bool, phase: UIContentReadiness.Phase) {
        let presentation = EventCoveragePresentation(phase: phase, isAggregate: false,
            tableIsEmpty: tableIsEmpty, tableWarning: "query incomplete", histogramWarning: "bins unavailable")
        #expect(presentation.tableWarning?.source == .events)
        #expect(presentation.tableWarning?.detail == "query incomplete")
        #expect(presentation.emptyNotice != nil)
        #expect(presentation.bannerWarnings.map(\.source) == (tableIsEmpty ? [.histogram] : [.events, .histogram]))
        #expect(presentation.bannerWarnings.last?.detail == "bins unavailable")
    }

    @Test("Aggregate warnings remain attached to daily summaries", arguments: [true, false])
    func aggregateCoverage(tableIsEmpty: Bool) {
        let presentation = EventCoveragePresentation(phase: .partial, isAggregate: true,
            tableIsEmpty: tableIsEmpty, tableWarning: "summary failure", histogramWarning: "old histogram")
        #expect(presentation.tableWarning?.source == .summaries)
        #expect(presentation.bannerWarnings.map(\.source) == (tableIsEmpty ? [] : [.summaries]))
        #expect(presentation.emptyNotice == .partial)
    }

    @Test("A retry overrides the old failure notice while cached refresh has its own slot",
          arguments: [true, false], [true, false])
    func alertRetry(hasSnapshot: Bool, hasError: Bool) {
        for phase in [UIContentReadiness.Phase.loading, .refreshingCached] {
            #expect(V2AlertReadNotice.resolve(phase: phase, hasSnapshot: hasSnapshot, hasError: hasError)
                    == (hasSnapshot ? nil : .loading))
            #expect(V2AlertReadNotice.cachedNoticeIndex(phase: phase, hasSnapshot: hasSnapshot, isFresh: false)
                    == (hasSnapshot ? 1 : nil))
        }
        #expect(V2AlertReadNotice.cachedNoticeIndex(phase: .failed, hasSnapshot: hasSnapshot, isFresh: false)
                == (hasSnapshot ? 0 : nil))
        #expect(V2AlertReadNotice.cachedNoticeIndex(phase: .loadedNonempty, hasSnapshot: hasSnapshot, isFresh: true) == nil)
    }
}
