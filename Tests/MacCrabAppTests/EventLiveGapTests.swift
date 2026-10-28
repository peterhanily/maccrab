import Foundation
import Testing
@testable import MacCrabApp
@testable import MacCrabCore

/// A full live page may have skipped rows above the window's newest. The
/// window reloads its own query over that gap without starting a new query,
/// which would reset its selection, older pages and a paused table.
@Suite("Events live gap", .serialized)
@MainActor
struct EventLiveGapTests {
    private func event(_ index: Int, base: Date) -> Event {
        let time = base.addingTimeInterval(Double(index))
        return Event(timestamp: time, eventCategory: .process, eventType: .start,
            eventAction: "exec", process: MacCrabCore.ProcessInfo(
                pid: Int32(9_000 + index), ppid: 1, rpid: 1,
                name: "gapfixture", executable: "/usr/bin/true",
                commandLine: "gapfixture", args: [], workingDirectory: "/private/tmp",
                userId: 501, userName: "fixture", groupId: 20,
                startTime: time, ancestors: [], isPlatformBinary: false))
    }

    @Test("a 200-row incremental page marks the window's gap, and is not retried as a new query")
    func fullIncrementalPageMarksTheGap() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-live-gap-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let writer = try EventStore(directory: dir.path)
        let base = Date().addingTimeInterval(-3_600)
        for index in 0..<205 { try await writer.insert(event: event(index, base: base)) }
        let reader = try EventStore(directory: dir.path, forceReadOnly: true)
        let app = AppState(engineSource: .init(directory: dir.path), startBackgroundWork: false)
        defer { app.discardEventReaderForTesting() }
        app.primeCachedEventStoreForTesting(reader)
        let session = EventQuerySession(reader: app)
        let owner = UUID()
        app.setEventsWorkspaceVisible(true, owner: owner, session: session)
        defer { app.setEventsWorkspaceVisible(false, owner: owner) }
        await session.loadEvents(.init(filter: nil, since: .distantPast, until: .distantFuture,
                                       category: nil, acceptsIncremental: true))
        #expect(session.canReceiveIncremental)
        let retry = session.retryTick
        let gap = session.liveGapTick
        await app.loadEventsIncremental()
        #expect(session.liveGapTick == gap + 1, "a full page marks a possible hole")
        session.pollTick()
        #expect(session.retryTick == retry, "not a new query")
        #expect(session.claimLiveGapReload(paused: false))
    }

    @Test("the window's gap reload keeps the selection and leaves a paused table alone")
    func viewHandlesTheGap() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let view = try String(contentsOf: root.appendingPathComponent("Sources/MacCrabApp/Views/EventStream.swift"),
                              encoding: .utf8)
        let key = try #require(view.range(of: "private var eventQueryKey: EventQueryKey {"))
        #expect(!view[key.upperBound...].prefix(400).contains("liveGap"), "a gap is not part of the query key")
        #expect(view.contains(".onChange(of: querySession.liveGapTick) { _ in reloadForLiveGapIfDue() }"))
        #expect(view.contains("let selectionShown = selectedEventID.map { id in presentedEvents.contains { $0.id == id } } ?? false"),
                "only a selection still shown holds the window's gap")
        #expect(view.contains("querySession.claimLiveGapReload(paused: isPaused, selectionHeld: selectionShown)"),
                "a selection holds the window's gap")
        #expect(view.contains("guard !isAggregateMode, querySession.claimLiveGapReloadManually() else { return }"),
                "the held gap is read when the user asks")
        let held = try #require(view.range(of: "if querySession.liveGapAwaitingReload && !isPaused && !isAggregateMode {"))
        #expect(view[held.upperBound...].prefix(300).contains("reloadHeldLiveGap()"), "the status bar offers the reload")
        let release = try #require(view.range(of: ".onChange(of: selectedEventID) { selection in"))
        #expect(view[release.upperBound...].prefix(120).contains("if selection == nil { reloadForLiveGapIfDue() }"))
        let reload = try #require(view.range(of: ".task(id: liveGapReloadTick) {"))
        let body = view[reload.upperBound...].prefix(1_100)
        #expect(body.contains("let selection = selectedEventID"))
        #expect(body.contains("overLiveGap: true"), "the reload keeps the shown rows")
        #expect(body.contains("guard !Task.isCancelled, key == eventQueryKey, !isPaused else { return }"))
        // A click during the read wins over the selection the reload began with.
        #expect(body.contains("let wanted = querySession.presentationResetTick == resets ? selectedEventID : (selectedEventID ?? selection)"))
        #expect(body.contains("selectedEventID = wanted.flatMap { id in filteredCache.contains { $0.id == id } ? id : nil }"))
        #expect(!body.contains("selectedEventID = nil"))
        let resume = try #require(view.range(of: ".onChange(of: isPaused) { paused in"))
        #expect(view[resume.upperBound...].prefix(200).contains("reloadForLiveGapIfDue()"), "a paused gap reloads on resume")
    }
}
