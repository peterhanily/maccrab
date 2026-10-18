import Foundation
import Testing
@testable import MacCrabApp

/// Pure injected-clock/sink fixtures. No logging, window, provider, database,
/// filesystem, polling, sleep or runtime performance assertions.
@MainActor
@Suite("Per-visit diagnostic timing")
struct V2VisitTimingTests {
    private final class Clock { var now: UInt64 = 1_000 }
    private final class Sink { var values: [V2VisitTiming.Summary] = [] }
    private func input(freshness: V2VisitTiming.Freshness = .fresh,
                       content: V2VisitTiming.Content = .nonempty,
                       table: UUID = UUID(uuidString: "00000000-0000-0000-0000-000000000001")!,
                       model: UUID = UUID(uuidString: "00000000-0000-0000-0000-000000000002")!) -> V2VisitTiming.AcceptedInput {
        .init(tableRevision: table, modelRevision: model, freshness: freshness, content: content)
    }
    private func recorder(_ clock: Clock, _ sink: Sink) -> V2VisitTiming {
        V2VisitTiming(now: { clock.now }, emit: { sink.values.append($0) })
    }

    @Test("Accepted navigation, provider, data and native host layout remain separate intervals")
    func phaseIntervals() throws {
        let clock = Clock(), sink = Sink(), timing = recorder(clock, sink)
        let ticket = timing.begin(.detection)
        clock.now += 20
        #expect(timing.providerReady(for: ticket))
        clock.now += 60
        #expect(timing.readAccepted(input(), for: ticket))
        #expect(sink.values.isEmpty)
        clock.now += 120
        #expect(timing.nativeTableDidLayout(input(), for: ticket, activeAttachment: true, positiveViewport: true))
        let value = try #require(sink.values.first)
        #expect(sink.values.count == 1)
        #expect(value.workspace == .detection && value.terminal == .nativeTableLayout)
        #expect(value.providerReadyNS == 20 && value.readAcceptedNS == 80)
        #expect(value.nativeTableLayoutNS == 200 && value.elapsedNS == 200)
        #expect(value.freshness == .fresh && value.content == .nonempty)
        #expect(timing.currentTicket(for: .detection) == nil)
        #expect(value.logLine == "ui_visit_timing.v1 workspace=detection terminal=nativeTableLayout"
                + " freshness=fresh content=nonempty navigation_accepted_ns=0 provider_ready_ns=20"
                + " read_accepted_ns=80 native_table_layout_ns=200 elapsed_ns=200")
    }

    @Test("Cached, accepted-empty and partial display do not become a fresh nonempty or health claim")
    func cachedEmptyAndPartial() throws {
        for content: V2VisitTiming.Content in [.empty, .nonempty, .partial] {
            let clock = Clock(), sink = Sink(), timing = recorder(clock, sink)
            let ticket = timing.begin(.alerts)
            clock.now += 1
            #expect(timing.readAccepted(input(freshness: .cached, content: content), for: ticket))
            // A duplicate builder cannot reset the accepted data timestamp.
            #expect(!timing.readAccepted(input(freshness: .cached, content: content), for: ticket))
            clock.now += 1
            #expect(timing.nativeTableDidLayout(input(freshness: .cached, content: content), for: ticket,
                                               activeAttachment: true, positiveViewport: true))
            let value = try #require(sink.values.first)
            #expect(value.freshness == .cached && value.content == content)
            #expect(value.providerReadyNS == nil, "Unobserved provider readiness must remain missing")
        }
    }

    @Test("Duplicate, obsolete and cross-visit callbacks cannot overwrite or finish the current visit")
    func ticketAndOnceOnlyGuards() {
        let clock = Clock(), sink = Sink(), timing = recorder(clock, sink)
        let old = timing.begin(.detection)
        #expect(timing.providerReady(for: old))
        #expect(!timing.providerReady(for: old))
        clock.now += 10
        let current = timing.begin(.alerts)
        #expect(sink.values.count == 1 && sink.values[0].terminal == .superseded)
        #expect(timing.currentTicket(for: .detection) == nil)
        #expect(timing.currentTicket(for: .alerts) == current)
        #expect(!timing.readAccepted(input(), for: old))
        #expect(!timing.nativeTableDidLayout(input(), for: old, activeAttachment: true, positiveViewport: true))
        #expect(!timing.stop(.windowClosed, for: old))
        #expect(timing.readAccepted(input(content: .empty), for: current))
        #expect(!timing.providerReady(for: current), "A late provider event cannot reverse phase order")
        #expect(timing.nativeTableDidLayout(input(content: .empty), for: current, activeAttachment: true, positiveViewport: true))
        #expect(!timing.nativeTableDidLayout(input(content: .empty), for: current, activeAttachment: true, positiveViewport: true))
        #expect(!timing.stop(.windowClosed, for: current))
        #expect(sink.values.count == 2)
    }

    @Test("Layout requires accepted data, an active attachment and a positive viewport")
    func layoutGuards() {
        let clock = Clock(), sink = Sink(), timing = recorder(clock, sink)
        let ticket = timing.begin(.alerts)
        #expect(!timing.nativeTableDidLayout(input(content: .empty), for: ticket, activeAttachment: true, positiveViewport: true))
        #expect(timing.readAccepted(input(content: .empty), for: ticket))
        #expect(!timing.nativeTableDidLayout(input(content: .empty), for: ticket, activeAttachment: false, positiveViewport: true))
        #expect(!timing.nativeTableDidLayout(input(content: .empty), for: ticket, activeAttachment: true, positiveViewport: false))
        #expect(sink.values.isEmpty)
        #expect(timing.nativeTableDidLayout(input(content: .empty), for: ticket, activeAttachment: true, positiveViewport: true))
    }

    @Test("Stopped visits retain missing phases and emit at most one terminal summary", arguments: V2VisitTiming.Stop.allCases)
    func stoppedVisits(reason: V2VisitTiming.Stop) throws {
        let clock = Clock(), sink = Sink(), timing = recorder(clock, sink)
        let ticket = timing.begin(.detection)
        clock.now += 15
        #expect(timing.stop(reason, for: ticket))
        #expect(!timing.stop(reason, for: ticket))
        let value = try #require(sink.values.first)
        #expect(sink.values.count == 1 && value.terminal.rawValue == reason.rawValue)
        #expect(value.elapsedNS == 15 && value.providerReadyNS == nil && value.readAcceptedNS == nil)
        #expect(value.nativeTableLayoutNS == nil && value.freshness == nil && value.content == nil)
        #expect(value.logLine.contains("provider_ready_ns=null read_accepted_ns=null native_table_layout_ns=null"))
    }

    @Test("Clock reversal is retained as invalid, never wrapped into a huge or successful duration")
    func invalidClock() throws {
        let clock = Clock(), sink = Sink(), timing = recorder(clock, sink)
        let ticket = timing.begin(.detection)
        clock.now += 10
        #expect(timing.providerReady(for: ticket))
        clock.now -= 1
        #expect(!timing.readAccepted(input(), for: ticket))
        let value = try #require(sink.values.first)
        #expect(value.terminal == .invalidClock && value.elapsedNS == nil)
        #expect(value.providerReadyNS == 10 && value.readAcceptedNS == nil)
        #expect(timing.currentTicket(for: .detection) == nil)
        #expect(!timing.stop(.windowClosed, for: ticket) && sink.values.count == 1)
    }

    @Test("Long visits are observations, not threshold-based passes or new polling work")
    func noPerformanceGate() throws {
        let clock = Clock(), sink = Sink(), timing = recorder(clock, sink)
        let ticket = timing.begin(.alerts)
        clock.now += 180_000_000_000
        #expect(timing.currentTicket(for: .alerts) == ticket && sink.values.isEmpty)
        #expect(timing.readAccepted(input(), for: ticket))
        clock.now += 1
        #expect(timing.nativeTableDidLayout(input(), for: ticket, activeAttachment: true, positiveViewport: true))
        let value = try #require(sink.values.first)
        #expect(value.elapsedNS == 180_000_000_001 && value.terminal == .nativeTableLayout)
    }

    @Test("Current storage is cleared before terminal delivery; later refresh callbacks remain inert")
    func terminalSinkBoundary() {
        let clock = Clock()
        var summaries = 0
        var timing: V2VisitTiming?
        timing = V2VisitTiming(now: { clock.now }, emit: { _ in
            #expect(timing?.currentTicket(for: .detection) == nil)
            summaries += 1
        })
        let ticket = timing!.begin(.detection)
        #expect(timing!.stop(.windowClosed, for: ticket))
        #expect(!timing!.readAccepted(input(), for: ticket))
        #expect(summaries == 1)
        timing = nil // Break the fixture's deliberately captured optional box.
    }
    @Test("Each window owns an isolated visit ticket even for identical accepted input")
    func windowIsolation() {
        let clock = Clock(), firstSink = Sink(), secondSink = Sink()
        let first = recorder(clock, firstSink), second = recorder(clock, secondSink)
        let firstTicket = first.begin(.detection), secondTicket = second.begin(.detection)
        #expect(firstTicket != secondTicket)
        #expect(!second.providerReady(for: firstTicket))
        #expect(!second.readAccepted(input(), for: firstTicket))
        #expect(!first.stop(.windowClosed, for: secondTicket))
        #expect(first.readAccepted(input(), for: firstTicket))
        #expect(first.nativeTableDidLayout(input(), for: firstTicket, activeAttachment: true, positiveViewport: true))
        #expect(firstSink.values.count == 1 && secondSink.values.isEmpty)
        #expect(second.currentTicket(for: .detection) == secondTicket)
        #expect(second.stop(.windowClosed, for: secondTicket))
        #expect(secondSink.values.count == 1)
    }

    @Test("Changed exact input, model generation or accepted provenance ends incomplete", arguments: 0..<4)
    func changedAcceptedBinding(change: Int) throws {
        let clock = Clock(), sink = Sink(), timing = recorder(clock, sink)
        let ticket = timing.begin(.alerts)
        let accepted = input()
        #expect(timing.readAccepted(accepted, for: ticket))
        let changed: V2VisitTiming.AcceptedInput
        switch change {
        case 0: changed = input(table: UUID())
        case 1: changed = input(model: UUID())
        case 2: changed = input(freshness: .cached)
        default: changed = input(content: .empty)
        }
        clock.now += 10
        #expect(!timing.readAccepted(changed, for: ticket))
        #expect(!timing.nativeTableDidLayout(accepted, for: ticket, activeAttachment: true, positiveViewport: true))
        #expect(!timing.nativeTableDidLayout(changed, for: ticket, activeAttachment: true, positiveViewport: true))
        let summary = try #require(sink.values.first)
        #expect(sink.values.count == 1 && summary.terminal == .contextChanged)
        #expect(summary.readAcceptedNS == 0 && summary.nativeTableLayoutNS == nil)
        #expect(summary.freshness == .fresh && summary.content == .nonempty)
        #expect(!summary.logLine.contains(accepted.tableRevision.uuidString))
        #expect(!summary.logLine.contains(accepted.modelRevision.uuidString))
    }

    @Test("A wrong-revision native callback cannot finish or discard the accepted current input")
    func staleLayoutBinding() {
        let clock = Clock(), sink = Sink(), timing = recorder(clock, sink)
        let ticket = timing.begin(.alerts)
        #expect(timing.readAccepted(input(), for: ticket))
        #expect(!timing.nativeTableDidLayout(input(model: UUID()), for: ticket,
                                          activeAttachment: true, positiveViewport: true))
        #expect(sink.values.isEmpty && timing.currentTicket(for: .alerts) == ticket)
        #expect(timing.nativeTableDidLayout(input(), for: ticket, activeAttachment: true, positiveViewport: true))
        #expect(sink.values.count == 1)
    }

    @Test("An offline placeholder or retained snapshot is not a completed live read failure")
    func placeholderAndReadFailures() {
        for phase: UIContentReadiness.Phase in [.unavailable, .failed, .deferred] {
            let clock = Clock(), sink = Sink(), timing = recorder(clock, sink)
            let ticket = timing.begin(.detection)
            #expect(!timing.readFinishedWithoutSnapshot(phase: phase, hasSnapshot: false,
                                                        observedLiveRead: false, for: ticket))
            #expect(timing.currentTicket(for: .detection) == ticket && sink.values.isEmpty)
            #expect(timing.providerReady(for: ticket))
            #expect(!timing.readFinishedWithoutSnapshot(phase: phase, hasSnapshot: true,
                                                        observedLiveRead: true, for: ticket))
            #expect(timing.readFinishedWithoutSnapshot(phase: phase, hasSnapshot: false,
                                                       observedLiveRead: true, for: ticket))
            let expected: V2VisitTiming.Terminal = phase == .failed ? .readFailed
                : (phase == .deferred ? .readDeferred : .readUnavailable)
            #expect(sink.values.count == 1 && sink.values.first?.terminal == expected)
            #expect(sink.values.first?.readAcceptedNS == nil)
        }
        let clock = Clock(), sink = Sink(), timing = recorder(clock, sink)
        let ticket = timing.begin(.alerts)
        for phase: UIContentReadiness.Phase in [.loading, .refreshingCached, .loadedEmpty, .loadedNonempty, .partial] {
            #expect(!timing.readFinishedWithoutSnapshot(phase: phase, hasSnapshot: false,
                                                        observedLiveRead: true, for: ticket))
        }
        #expect(sink.values.isEmpty && timing.currentTicket(for: .alerts) == ticket)
    }
}
