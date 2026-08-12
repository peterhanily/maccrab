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
//   1. Behavioral (this suite, importable): prove the owned exact reader treats
//      every nonpositive limit as an immediate empty page without decoding the
//      retained corpus. The CLI clamp remains defense in depth.
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

    @Test("negative and zero exact limits are owned empty snapshots")
    func nonpositiveExactLimitsAreEmpty() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("cli-clamp-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let store = try EventStore(directory: dir.path)
        let base = Date(timeIntervalSince1970: 1_700_000_000)
        for i in 0..<5 { try await store.insert(event: makeEvent(i, at: base)) }

        // Control: a normal positive limit is honored (the seed is present).
        let three = try await store.exactEventsSnapshot(
            since: .distantPast,
            limit: 3
        )
        #expect(three.events.count == 3)

        let decodesBefore = await store.journalExactQueryBlockDecodeCount()

        // Storage itself fails safe even if a caller forgets the CLI clamp.
        let negative = try await store.exactEventsSnapshot(
            since: .distantPast,
            limit: -5
        )
        #expect(negative.events.isEmpty)
        #expect(negative.isComplete)
        #expect(negative.mutationGeneration == three.mutationGeneration)

        let zero = try await store.exactEventsSnapshot(
            since: .distantPast,
            limit: 0
        )
        #expect(zero.events.isEmpty)
        #expect(zero.isComplete)
        #expect(zero.mutationGeneration == three.mutationGeneration)
        #expect(
            await store.journalExactQueryBlockDecodeCount() == decodesBefore,
            "nonpositive limits must not decode a retained journal block"
        )
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
