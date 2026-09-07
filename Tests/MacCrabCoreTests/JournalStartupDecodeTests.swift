import Foundation
import Testing
import CSQLCipher
@testable import MacCrabCore

@Suite("Journal startup decode ownership")
struct JournalStartupDecodeTests {
    private func retainedBlockCounts(at directory: URL) throws -> (bases: UInt64, terminals: UInt64) {
        var raw: OpaquePointer?
        let result = sqlite3_open_v2(
            directory.appendingPathComponent("events.db").path,
            &raw,
            SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX,
            nil
        )
        defer { if let raw { sqlite3_close(raw) } }
        try #require(result == SQLITE_OK)
        let database = try #require(raw)
        var statement: OpaquePointer?
        try #require(sqlite3_prepare_v2(
            database,
            """
            SELECT (SELECT COUNT(*) FROM event_journal_blocks),
                   (SELECT COUNT(DISTINCT block_id) FROM event_journal_terminal_revisions)
            """,
            -1,
            &statement,
            nil
        ) == SQLITE_OK)
        defer { sqlite3_finalize(statement) }
        try #require(sqlite3_step(statement) == SQLITE_ROW)
        let count = sqlite3_column_int64(statement, 0)
        let terminalCount = sqlite3_column_int64(statement, 1)
        try #require(count > 0)
        try #require(terminalCount >= 0)
        try #require(sqlite3_step(statement) == SQLITE_DONE)
        return (UInt64(count), UInt64(terminalCount))
    }

    @Test("cold verification avoids duplicate per-block decodes and preserves evidence leases",
          arguments: [false, true])
    func coldVerificationReusesOwnedBase(hasTerminalRevision: Bool) async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-startup-decode-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: directory) }

        let bases = try (0..<3).map { index in
            try EventJournalAdmissionValidator.prepare(makeEvent(
                processName: "startup-\(index)",
                commandLine: "/usr/bin/test ordinary-\(index)",
                pid: Int32(7_000 + index)
            )).event
        }
        var terminal = bases[0]
        if hasTerminalRevision {
            terminal.enrichments["reviewed"] = "ordinary terminal evidence"
            terminal.severity = .high
            terminal.ruleMatches = [RuleMatch(
                ruleId: "startup.ordinary",
                ruleName: "Startup fixture",
                severity: .high,
                description: "Ordinary retained evidence"
            )]
        }
        do {
            let writer = try EventStore(directory: directory.path)
            for base in bases { try await writer.insert(event: base) }
            if hasTerminalRevision {
                try await writer.appendTerminalRevision(
                    terminal,
                    lane: EventPipelineLane.finalLane(for: terminal)
                )
            }
        }
        let blocks = try retainedBlockCounts(at: directory)
        let expectedTerminalBlocks: UInt64 = hasTerminalRevision ? 1 : 0
        #expect(blocks.terminals == expectedTerminalBlocks)

        let budget = EventPipelineLiveMemoryBudget
            .isolatedProductionEquivalentForTesting()
        let reader = try EventStore(
            directory: directory.path,
            forceReadOnly: true,
            liveMemoryBudget: budget
        )
        let before = await reader.journalBaseBlockDecodesForTesting
        #expect(try await reader.count() == bases.count)
        let after = await reader.journalBaseBlockDecodesForTesting
        // The per-block exact/projection validation reuses its authenticated
        // base. The separate global terminal-integrity scan still authenticates
        // one base per distinct terminal block, including ordinal validation.
        // Keeping both counts independent of the decoder counter pins the
        // removed duplicate without weakening that separate integrity check.
        let expectedDecodes: UInt64 = blocks.bases + blocks.terminals
        #expect(after - before == expectedDecodes)
        #expect(budget.snapshot().currentBytes == 0)
        #expect(budget.snapshot().leasesConserved)

        let stages = await reader.journalIndexRefreshDiagnostics()
        #expect(stages.stagesComplete)
        #expect(stages.stagesNanoseconds["base_authentication", default: 0] > 0)
        #expect(stages.stagesNanoseconds["global_projection_and_fts", default: 0] > 0)
        #expect(stages.stagesNanoseconds.values.reduce(UInt64(0), +) <= stages.lastNanoseconds)

        // A warm count must keep the validated index without decoding again.
        #expect(try await reader.count() == bases.count)
        #expect(await reader.journalBaseBlockDecodesForTesting == after)

        // Reuse must preserve the exact terminal overlay and transfer its
        // charged ownership to the snapshot, then release it with that value.
        var snapshot: ExactEventQuerySnapshot? = try await reader
            .exactEventsSnapshot(since: .distantPast, limit: 10)
        #expect(snapshot?.isComplete == true)
        #expect(snapshot?.events.count == bases.count)
        #expect(snapshot?.events.contains(terminal) == true)
        #expect(snapshot?.events.contains(bases[1]) == true)
        #expect(snapshot?.events.contains(bases[2]) == true)
        #expect(budget.snapshot().currentBytes > 0)
        #expect(budget.snapshot().leasesConserved)
        snapshot = nil
        #expect(budget.snapshot().currentBytes == 0)
        #expect(budget.snapshot().leasesConserved)
    }
}
