import Foundation
import Testing
@testable import MacCrabApp
@testable import MacCrabCore

/// The notifier's read-and-advance step against a real alerts.db: commit
/// order, the severity floor in the read, and a cursor that survives a reused
/// rowid or another store.
@MainActor
@Suite("Alert notifier forward read", .serialized)
struct AlertNotifierForwardReadTests {
    private typealias Cursor = AlertNotifier.NotificationCursor

    private func alert(_ id: String, at seconds: TimeInterval, severity: MacCrabCore.Severity = .critical) -> Alert {
        Alert(id: id, timestamp: Date(timeIntervalSince1970: seconds), ruleId: "rule.\(id)",
              ruleTitle: "Fixture", severity: severity, eventId: UUID().uuidString,
              processPath: "/tmp/\(id)", processName: "fixture", description: "d",
              mitreTactics: nil, mitreTechniques: nil)
    }

    private func store() throws -> (AlertStore, URL) {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-notifier-read-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return (try AlertStore(directory: directory.path), directory)
    }

    private func read(_ store: AlertStore, _ cursor: Cursor?, floor: MacCrabCore.Severity = .critical,
                      enabled: Bool = true, determined: Bool = true,
                      now: Date = Date(timeIntervalSince1970: 10_000)) async throws -> AlertNotifier.ForwardRead {
        try await AlertNotifier.readForward(store: store, cursor: cursor, floor: floor, enabled: enabled,
                                            now: now, isAuthorizationDetermined: { determined })
    }

    @Test("the first read seeds at the newest alert and notifies none of the backlog")
    func firstRunSeeds() async throws {
        let (store, directory) = try store()
        defer { try? FileManager.default.removeItem(at: directory) }
        for index in 0..<3 { try await store.insert(alert: alert("old\(index)", at: 100 + Double(index))) }
        let seeded = try await read(store, nil)
        #expect(seeded.outcome == .seeded && seeded.alerts.isEmpty)
        #expect(seeded.cursor.alertID == "old2")
        try await store.insert(alert: alert("new", at: 200))
        let next = try await read(store, seeded.cursor)
        #expect(next.alerts.map(\.id) == ["new"])
    }

    @Test("a backlog over 5,000 is delivered oldest commit first, a slice at a time, none skipped or repeated")
    func largeBacklogDrains() async throws {
        let (store, directory) = try store()
        defer { try? FileManager.default.removeItem(at: directory) }
        var cursor = try await read(store, nil).cursor
        let ids = (0..<5_100).map { "b\($0)" }
        _ = try await store.insert(alerts: ids.enumerated().map { alert($1, at: 1_000 + Double($0)) })
        var delivered: [String] = []
        var reads = 0
        while reads < 200 {
            let step = try await read(store, cursor)
            cursor = step.cursor
            reads += 1
            guard step.outcome == .delivered else { break }
            #expect(step.alerts.count <= AlertNotifier.maximumDeliveriesPerTick)
            delivered += step.alerts.map(\.id)
            #expect(step.backlog == ids.count - delivered.count)
        }
        #expect(delivered == ids)
    }

    @Test("nothing is consumed while authorization is undetermined")
    func undeterminedAuthorizationKeepsTheCursor() async throws {
        let (store, directory) = try store()
        defer { try? FileManager.default.removeItem(at: directory) }
        let seeded = try await read(store, nil).cursor
        try await store.insert(alert: alert("c0", at: 300))
        _ = try await store.insert(alerts: (0..<20).map { alert("quiet\($0)", at: 300.5, severity: .low) })
        try await store.insert(alert: alert("c1", at: 301))
        let pending = try await read(store, seeded, determined: false)
        #expect(pending.outcome == .authorizationPending && pending.alerts.isEmpty)
        #expect(pending.backlog == 2)
        #expect(pending.cursor == seeded)
        let granted = try await read(store, pending.cursor)
        #expect(granted.alerts.map(\.id) == ["c0", "c1"])
    }

    @Test("an alert stamped earlier but committed later is still delivered")
    func lateCommitIsDelivered() async throws {
        let (store, directory) = try store()
        defer { try? FileManager.default.removeItem(at: directory) }
        var cursor = try await read(store, nil).cursor
        try await store.insert(alert: alert("later-stamp", at: 500))
        let first = try await read(store, cursor)
        #expect(first.alerts.map(\.id) == ["later-stamp"])
        cursor = first.cursor
        try await store.insert(alert: alert("earlier-stamp", at: 400))
        #expect(try await read(store, cursor).alerts.map(\.id) == ["earlier-stamp"])
    }

    @Test("a flood below the floor neither uses the slice nor counts as backlog")
    func floodBelowTheFloor() async throws {
        let (store, directory) = try store()
        defer { try? FileManager.default.removeItem(at: directory) }
        let cursor = try await read(store, nil).cursor
        _ = try await store.insert(alerts: (0..<300).map { alert("low\($0)", at: 600 + Double($0), severity: .low) })
        try await store.insert(alert: alert("critical", at: 1_000))
        let step = try await read(store, cursor)
        #expect(step.alerts.map(\.id) == ["critical"])
        #expect(step.backlog == 0)
        // Past the flood: the next read starts after it.
        #expect(step.cursor.alertID == "critical")
        _ = try await store.insert(alerts: (0..<10).map { alert("tail\($0)", at: 2_000 + Double($0), severity: .medium) })
        let quiet = try await read(store, step.cursor)
        #expect(quiet.outcome == .nothingFresh && quiet.cursor.alertID == "tail9")
    }

    @Test("alerts sharing a timestamp across the slice boundary are all delivered")
    func tiesAcrossTheBoundary() async throws {
        let (store, directory) = try store()
        defer { try? FileManager.default.removeItem(at: directory) }
        let seeded = try await read(store, nil).cursor
        let ids = (0..<60).map { "t\($0)" }
        _ = try await store.insert(alerts: ids.map { alert($0, at: 700) })
        let first = try await read(store, seeded)
        let second = try await read(store, first.cursor)
        #expect(first.alerts.map(\.id) + second.alerts.map(\.id) == ids)
    }

    @Test("muted notifications move the cursor on, so unmuting replays nothing")
    func disabledAdvances() async throws {
        let (store, directory) = try store()
        defer { try? FileManager.default.removeItem(at: directory) }
        let seeded = try await read(store, nil).cursor
        try await store.insert(alert: alert("muted", at: 800))
        let muted = try await read(store, seeded, enabled: false)
        #expect(muted.outcome == .disabled && muted.alerts.isEmpty && muted.cursor.alertID == "muted")
        try await store.insert(alert: alert("after", at: 801))
        #expect(try await read(store, muted.cursor).alerts.map(\.id) == ["after"])
    }

    @Test("a timestamp cursor, a reused rowid and another alerts.db all resume after the watermark")
    func cursorResumesByWatermark() async throws {
        let (store, directory) = try store()
        defer { try? FileManager.default.removeItem(at: directory) }
        for index in 0..<3 { try await store.insert(alert: alert("d\(index)", at: 900 + Double(index))) }
        // The cursor an older app persisted: a timestamp only.
        let migrated = try await read(store, Cursor(rowID: 0, alertID: nil, watermark: Date(timeIntervalSince1970: 900.5)))
        #expect(migrated.alerts.map(\.id) == ["d1", "d2"])

        // The newest alert is deleted and its rowid reused by the next one.
        let newest = try #require(try await store.newestAlertRow())
        #expect(try await store.delete(alertId: newest.id))
        try await store.insert(alert: alert("reuse", at: 950))
        #expect(try await store.newestAlertRow()?.rowID == newest.rowID)
        #expect(try await read(store, migrated.cursor).alerts.map(\.id) == ["reuse"])

        // A cursor from another alerts.db.
        let (other, otherDirectory) = try self.store()
        defer { try? FileManager.default.removeItem(at: otherDirectory) }
        for index in 0..<5 { try await other.insert(alert: alert("o\(index)", at: 890 + Double(index * 10))) }
        #expect(try await read(other, migrated.cursor).alerts.map(\.id) == ["o2", "o3", "o4"])
    }

    @Test("the backlog counts only alerts at or above the floor")
    func backlogCountsOnlyTheFloor() async throws {
        let (store, directory) = try store()
        defer { try? FileManager.default.removeItem(at: directory) }
        let seeded = try await read(store, nil).cursor
        var batch: [Alert] = []
        for index in 0..<60 {
            batch.append(alert("crit\(index)", at: 1_000 + Double(index)))
            batch += (0..<5).map { alert("low\(index)-\($0)", at: 1_000 + Double(index), severity: .low) }
        }
        _ = try await store.insert(alerts: batch)
        let step = try await read(store, seeded)
        #expect(step.alerts.count == AlertNotifier.maximumDeliveriesPerTick)
        #expect(step.backlog == 10, "the 10 criticals left, not the lows behind them")
    }

    @Test("a cursor resumed by watermark anchors on a row, so a later commit stamped earlier is still read")
    func resumedCursorIsAnchored() async throws {
        let (store, directory) = try store()
        defer { try? FileManager.default.removeItem(at: directory) }
        for index in 0..<3 { try await store.insert(alert: alert("r\(index)", at: 100 + Double(index))) }
        // An older app's cursor, already past every alert.
        let resumed = try await read(store, Cursor(rowID: 0, alertID: nil, watermark: Date(timeIntervalSince1970: 500)))
        #expect(resumed.outcome == .nothingFresh && resumed.alerts.isEmpty)
        #expect(resumed.cursor.alertID == "r2", "anchored, so the next tick follows rowids")
        try await store.insert(alert: alert("late", at: 400))
        #expect(try await read(store, resumed.cursor).alerts.map(\.id) == ["late"])
    }

    @Test("an alert rewritten in place at or above the floor is delivered once")
    func rewriteIsDeliveredOnce() async throws {
        let (store, directory) = try store()
        defer { try? FileManager.default.removeItem(at: directory) }
        var cursor = try await read(store, nil).cursor
        try await store.insert(alert: alert("vuln-CVE-1", at: 1_000, severity: .high))
        let below = try await read(store, cursor)
        #expect(below.alerts.isEmpty && below.cursor.alertID == "vuln-CVE-1", "passed below the floor")
        cursor = below.cursor
        // The next scan re-scores the CVE as critical on the same row.
        try await store.insert(alert: alert("vuln-CVE-1", at: 4_600))
        let rescored = try await read(store, cursor)
        #expect(rescored.alerts.map(\.id) == ["vuln-CVE-1"])
        #expect(rescored.alerts.first?.severity == .critical)
        let again = try await read(store, rescored.cursor)
        #expect(again.outcome == .nothingFresh && again.alerts.isEmpty, "once per new stamp")
        // Unsuppressing an old alert flips a flag, not its stamp: no banner.
        try await store.insert(alert: alert("silenced", at: 4_700))
        try await store.suppress(alertId: "silenced")
        let passed = try await read(store, again.cursor)
        #expect(passed.alerts.isEmpty)
        try await store.unsuppress(alertId: "silenced")
        #expect(try await read(store, passed.cursor).alerts.isEmpty)
    }

    @Test("a cursor read that fails is an error, never a first-run seed of the whole table")
    func failedReadDoesNotSeed() async throws {
        let (store, directory) = try store()
        defer { try? FileManager.default.removeItem(at: directory) }
        for index in 0..<3 { try await store.insert(alert: alert("h\(index)", at: 100 + Double(index))) }
        await store.interruptReadsForTesting(true)
        await #expect(throws: (any Error).self) { _ = try await read(store, nil) }
        await store.interruptReadsForTesting(false)
        let seeded = try await read(store, nil)
        #expect(seeded.outcome == .seeded && seeded.cursor.alertID == "h2")
    }

    @Test("an older build run in between wins with its newer watermark")
    func restoredCursor() throws {
        let saved = Cursor(rowID: 7, alertID: "a7", watermark: Date(timeIntervalSince1970: 1_000))
        let data = try JSONEncoder().encode(saved)
        #expect(AlertNotifier.restoredCursor(rowCursor: nil, legacy: nil) == nil)
        #expect(AlertNotifier.restoredCursor(rowCursor: data, legacy: nil) == saved)
        #expect(AlertNotifier.restoredCursor(rowCursor: data, legacy: saved.watermark.timeIntervalSince1970) == saved,
                "this build writes both, equal")
        #expect(AlertNotifier.restoredCursor(rowCursor: data, legacy: 1_500)
                == Cursor(rowID: 0, alertID: nil, watermark: Date(timeIntervalSince1970: 1_500)))
        #expect(AlertNotifier.restoredCursor(rowCursor: nil, legacy: 1_500)
                == Cursor(rowID: 0, alertID: nil, watermark: Date(timeIntervalSince1970: 1_500)))
    }

    @Test("after a downgrade and re-upgrade, alerts the older build showed are not shown again")
    func downgradeDoesNotReplay() async throws {
        let (store, directory) = try store()
        defer { try? FileManager.default.removeItem(at: directory) }
        let seeded = try await read(store, nil).cursor
        try await store.insert(alert: alert("u0", at: 1_000))
        let mine = try await read(store, seeded).cursor
        // The older build then advanced only the legacy timestamp past these.
        try await store.insert(alert: alert("u1", at: 1_100))
        try await store.insert(alert: alert("u2", at: 1_200))
        let restored = try #require(AlertNotifier.restoredCursor(rowCursor: try JSONEncoder().encode(mine), legacy: 1_200))
        try await store.insert(alert: alert("u3", at: 1_300))
        #expect(try await read(store, restored).alerts.map(\.id) == ["u3"])
    }

    @Test("an alert stamped again after a tick's rewrite read is delivered on the next tick")
    func restampDuringTheTickIsKept() async throws {
        let (store, directory) = try store()
        defer { try? FileManager.default.removeItem(at: directory) }
        var cursor = try await read(store, nil).cursor
        try await store.insert(alert: alert("vuln-CVE-1", at: 1_000, severity: .high))
        cursor = try await read(store, cursor).cursor
        try await store.insert(alert: alert("x", at: 2_000))
        let rescored = alert("vuln-CVE-1", at: 3_000)
        let step = try await AlertNotifier.readForward(
            store: store, cursor: cursor, floor: .critical, enabled: true,
            now: Date(timeIntervalSince1970: 10_000),
            isAuthorizationDetermined: {
                // The re-score commits after this tick's rewrite read ran.
                try? await store.insert(alert: rescored)
                return true
            })
        #expect(step.alerts.map(\.id) == ["x"])
        #expect(try await read(store, step.cursor).alerts.map(\.id) == ["vuln-CVE-1"])
    }

    @Test("a tick with nothing new passes alerts stamped again below the floor")
    func idleTickPassesRestampedRows() async throws {
        let (store, directory) = try store()
        defer { try? FileManager.default.removeItem(at: directory) }
        var cursor = try await read(store, nil).cursor
        try await store.insert(alert: alert("privacy-app-mic", at: 1_000, severity: .medium))
        try await store.insert(alert: alert("c0", at: 1_001))
        cursor = try await read(store, cursor).cursor
        try await store.insert(alert: alert("privacy-app-mic", at: 4_600, severity: .medium))
        let idle = try await read(store, cursor)
        #expect(idle.outcome == .nothingFresh && idle.alerts.isEmpty)
        #expect(idle.cursor.watermark == Date(timeIntervalSince1970: 4_600))
        #expect(idle.cursor.alertID == "c0")
    }

    @Test("a lost anchor does not resume behind an old alert stamped again, so nothing is replayed")
    func lostAnchorDoesNotReplay() async throws {
        let (store, directory) = try store()
        defer { try? FileManager.default.removeItem(at: directory) }
        let seeded = try await read(store, nil).cursor
        // A deterministic id below the floor, committed before the criticals.
        try await store.insert(alert: alert("privacy-app-mic", at: 1_000, severity: .medium))
        for index in 0..<3 { try await store.insert(alert: alert("c\(index)", at: 1_001 + Double(index))) }
        let delivered = try await read(store, seeded)
        #expect(delivered.alerts.map(\.id) == ["c0", "c1", "c2"])
        // An hourly scan stamps the old row again, then the newest alert, the
        // cursor's anchor, is deleted from the dashboard.
        try await store.insert(alert: alert("privacy-app-mic", at: 4_600, severity: .medium))
        #expect(try await store.delete(alertId: "c2"))
        let after = try await read(store, delivered.cursor)
        #expect(after.alerts.isEmpty, "c0 and c1 were shown already")
        try await store.insert(alert: alert("c3", at: 4_700))
        #expect(try await read(store, after.cursor).alerts.map(\.id) == ["c3"])
    }

    @Test("a new alert that reuses a deleted anchor's rowid is delivered exactly once")
    func reusedRowIDIsDeliveredOnce() async throws {
        let (store, directory) = try store()
        defer { try? FileManager.default.removeItem(at: directory) }
        let seeded = try await read(store, nil).cursor
        for index in 0..<3 { try await store.insert(alert: alert("k\(index)", at: 1_000 + Double(index))) }
        let delivered = try await read(store, seeded)
        let anchor = try #require(try await store.newestAlertRow())
        #expect(try await store.delete(alertId: anchor.id))
        try await store.insert(alert: alert("k-new", at: 1_100))
        #expect(try await store.newestAlertRow()?.rowID == anchor.rowID, "the rowid is reused")
        let first = try await read(store, delivered.cursor)
        #expect(first.alerts.map(\.id) == ["k-new"])
        let second = try await read(store, first.cursor)
        #expect(second.alerts.isEmpty && second.outcome == .nothingFresh)
    }

    private func rewritePosition(_ cursor: Cursor) throws -> Int64? {
        let raw = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(cursor)) as? [String: Any])
        return (raw["rewriteRowIDAtWatermark"] as? NSNumber)?.int64Value
    }

    private func rewriteBacklog(_ store: AlertStore, count: Int, tied: Bool = false) async throws -> (Cursor, [String]) {
        let empty = try await read(store, nil).cursor
        let ids = (0..<count).map { "rewrite-\($0)" }
        _ = try await store.insert(alerts: ids.enumerated().map { alert($1, at: 1_000 + Double($0), severity: .high) })
        let cursor = try await read(store, empty).cursor
        _ = try await store.insert(alerts: ids.enumerated().map { alert($1, at: 5_000 + (tied ? 0 : Double($0))) })
        return (cursor, ids)
    }

    @Test("rewrite bursts beyond the old cap drain in bounded pages, including timestamp ties", arguments: [false, true])
    func largeRewriteBacklogDrains(tied: Bool) async throws {
        let (store, directory) = try store()
        defer { try? FileManager.default.removeItem(at: directory) }
        let (initial, ids) = try await rewriteBacklog(store, count: 1_001, tied: tied)
        var cursor = initial
        var delivered: [String] = []
        for _ in 0..<30 {
            let step = try await read(store, cursor)
            cursor = step.cursor
            guard step.outcome == .delivered else { break }
            #expect(step.alerts.count <= AlertNotifier.maximumDeliveriesPerTick)
            delivered += step.alerts.map(\.id)
            #expect(step.backlog == ids.count - delivered.count)
            if step.backlog > 0 {
                #expect(cursor.rowID == initial.rowID && cursor.alertID == initial.alertID,
                        "fresh commit anchor stays fixed while rewrites wait")
            }
        }
        #expect(delivered == ids)
        #expect(try await read(store, cursor).alerts.isEmpty)
    }

    @Test("rewrites and fresh commits share one delivery budget", arguments: [49, 50, 51])
    func mixedRewriteAndFreshBudget(count: Int) async throws {
        let (store, directory) = try store()
        defer { try? FileManager.default.removeItem(at: directory) }
        let (initial, rewrittenIDs) = try await rewriteBacklog(store, count: count, tied: true)
        let freshIDs = (0..<60).map { "fresh-\($0)" }
        _ = try await store.insert(alerts: freshIDs.enumerated().map { alert($1, at: 8_000 + Double($0)) })
        var cursor = initial
        var delivered: [String] = []
        for _ in 0..<6 {
            let step = try await read(store, cursor)
            cursor = step.cursor
            guard step.outcome == .delivered else { break }
            #expect(step.alerts.count <= AlertNotifier.maximumDeliveriesPerTick)
            delivered += step.alerts.map(\.id)
            #expect(step.backlog == rewrittenIDs.count + freshIDs.count - delivered.count)
        }
        #expect(delivered == rewrittenIDs + freshIDs)
    }

    @Test("an unfinished rewrite tie survives cursor persistence and older cursor JSON still decodes")
    func rewriteCursorRoundTrip() async throws {
        let (store, directory) = try store()
        defer { try? FileManager.default.removeItem(at: directory) }
        let (initial, ids) = try await rewriteBacklog(store, count: 120, tied: true)
        let first = try await read(store, initial)
        let encoded = try JSONEncoder().encode(first.cursor)
        let restored = try #require(AlertNotifier.restoredCursor(
            rowCursor: encoded, legacy: first.cursor.watermark.timeIntervalSince1970))
        #expect(restored == first.cursor)
        #expect(try rewritePosition(restored) != nil)
        let second = try await read(store, restored)
        let third = try await read(store, try JSONDecoder().decode(Cursor.self, from: JSONEncoder().encode(second.cursor)))
        #expect((first.alerts + second.alerts + third.alerts).map(\.id) == ids)
        var legacyObject = try #require(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        legacyObject.removeValue(forKey: "rewriteRowIDAtWatermark")
        let legacy = try JSONDecoder().decode(Cursor.self, from: JSONSerialization.data(withJSONObject: legacyObject))
        #expect((try rewritePosition(legacy)) == nil)
        let downgraded = try #require(AlertNotifier.restoredCursor(
            rowCursor: encoded, legacy: first.cursor.watermark.timeIntervalSince1970 + 1))
        #expect(downgraded.rowID == 0)
        #expect(try rewritePosition(downgraded) == nil)
    }

    @Test("deleting or reusing the commit anchor during a rewrite tie loses no pending alert", arguments: [false, true])
    func rewriteContinuationAfterAnchorLoss(reuse: Bool) async throws {
        let (store, directory) = try store()
        defer { try? FileManager.default.removeItem(at: directory) }
        let (initial, ids) = try await rewriteBacklog(store, count: 120, tied: true)
        let first = try await read(store, initial)
        #expect(try await store.delete(alertId: try #require(ids.last)))
        if reuse {
            try await store.insert(alert: alert("reused-anchor", at: 8_000))
            #expect(try await store.newestAlertRow()?.rowID == initial.rowID)
        }
        var cursor = first.cursor
        var delivered = first.alerts.map(\.id)
        for _ in 0..<5 {
            let step = try await read(store, cursor)
            cursor = step.cursor
            guard step.outcome == .delivered else { break }
            #expect(step.alerts.count <= AlertNotifier.maximumDeliveriesPerTick)
            delivered += step.alerts.map(\.id)
        }
        #expect(delivered == Array(ids.dropLast()) + (reuse ? ["reused-anchor"] : []))
        #expect(try await read(store, cursor).alerts.isEmpty)
    }

    @Test("authorization pending preserves an unfinished rewrite page and its full backlog")
    func rewriteAuthorizationPending() async throws {
        let (store, directory) = try store()
        defer { try? FileManager.default.removeItem(at: directory) }
        let (initial, ids) = try await rewriteBacklog(store, count: 120, tied: true)
        let first = try await read(store, initial)
        let pending = try await read(store, first.cursor, determined: false)
        #expect(pending.outcome == .authorizationPending && pending.cursor == first.cursor)
        #expect(pending.alerts.isEmpty && pending.backlog == 70)
        let resumed = try await read(store, pending.cursor)
        #expect(resumed.alerts.map(\.id) == Array(ids[50..<100]))
    }

    @Test("muting during rewrite pagination discards its continuation and does not replay on unmute")
    func muteDiscardsRewriteContinuation() async throws {
        let (store, directory) = try store()
        defer { try? FileManager.default.removeItem(at: directory) }
        let (initial, _) = try await rewriteBacklog(store, count: 120, tied: true)
        let first = try await read(store, initial)
        let muted = try await read(store, first.cursor, enabled: false, now: Date(timeIntervalSince1970: 5_000))
        #expect(muted.outcome == .disabled)
        #expect(try rewritePosition(muted.cursor) == nil)
        #expect(try await read(store, muted.cursor).alerts.isEmpty)
        try await store.insert(alert: alert("after-mute", at: 6_000))
        #expect(try await read(store, muted.cursor).alerts.map(\.id) == ["after-mute"])
    }

}
