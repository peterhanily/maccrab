// CLICountClampTests.swift
// MacCrabCoreTests
//
// Pre-GA audit (LOW): the CLI count args (`events tail N`, `alerts N`,
// `campaigns N`, `tree-score N`) were bound straight into SQLite `LIMIT ?`.
// SQLite treats a NEGATIVE limit as "no limit" — so a fat-fingered
// `events tail -5` dumped the WHOLE table. The fix clamps each count to >= 0
// (`max(0, n)`) before it reaches the query.
//
// Two-part coverage:
//   1. Behavioral (this suite, importable): prove on the real EventStore that a
//      negative limit IS the unbounded-dump hazard and that the clamped value
//      (max(0, -5) == 0) bounds it. This exercises the exact `store.events(limit:)`
//      the CLI calls.
//   2. Source guard: maccrabctl is an executable target (not importable), so —
//      as CLIUsageParityTests does — assert the four call sites apply the clamp.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("CLI count-arg clamp (negative LIMIT hazard)")
struct CLICountClampTests {

    private func makeEvent(_ i: Int, at base: Date) -> Event {
        Event(
            timestamp: base.addingTimeInterval(Double(i)),
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: MacCrabCore.ProcessInfo(
                pid: Int32(1000 + i), ppid: 1, rpid: 0,
                name: "true", executable: "/usr/bin/true",
                commandLine: "/usr/bin/true", args: [], workingDirectory: "/",
                userId: 501, userName: "u", groupId: 20,
                startTime: base.addingTimeInterval(Double(i))
            )
        )
    }

    @Test("negative LIMIT is an unbounded dump; the clamped value (max(0,-5)==0) bounds it")
    func negativeLimitIsUnboundedButClampBounds() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("cli-clamp-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let store = try EventStore(directory: dir.path)
        let base = Date(timeIntervalSince1970: 1_700_000_000)
        for i in 0..<5 { try await store.insert(event: makeEvent(i, at: base)) }

        // Control: a normal positive limit is honored (the seed is present).
        let three = try await store.events(since: .distantPast, limit: 3)
        #expect(three.count == 3)

        // The HAZARD: a negative limit is treated by SQLite as "no limit" — all 5
        // rows come back regardless of the intended small count. This is the
        // whole-table dump `events tail -5` produced before the fix.
        let negative = try await store.events(since: .distantPast, limit: -5)
        #expect(negative.count == 5,
                "documents the hazard: SQLite treats a negative LIMIT as unbounded")

        // The FIX: the CLI clamps with max(0, n). For -5 that is 0 → `LIMIT 0` →
        // a BOUNDED (empty) result instead of the unbounded dump above.
        let clamped = try await store.events(since: .distantPast, limit: max(0, -5))
        #expect(clamped.count == 0,
                "the clamped value (max(0,-5)==0) yields a bounded result, not the whole table")
    }

    @Test("all four maccrabctl count-arg sites clamp with max(0, …)")
    func cliSitesClampCounts() throws {
        // maccrabctl is not importable — assert the source applies the clamp at
        // each count-arg site (events tail / alerts / campaigns / tree-score).
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/maccrabctl/MacCrabCtl.swift")
        let src = try String(contentsOf: url, encoding: .utf8)
        let clampSites = src.components(separatedBy: "= max(0,").count - 1
        #expect(clampSites >= 4,
                "expected the 4 CLI count-arg sites (events tail / alerts / campaigns / tree-score) to clamp with `= max(0, …)`; found \(clampSites)")
    }
}
