// An array-returning exact query must stop walking journal blocks once a
// resource limit refuses a record. Before v1.22.0 the newest-first early
// exit needed 10,000 retained candidates, which a 16 MiB budget of ~9 KB
// records can never reach, so a bounded query authenticated and decoded the
// whole retained journal on the store actor. On a loaded engine the SIGHUP
// rule-reload scan therefore held the actor for ~30 s and a priority terminal
// revision missed its 30 s settlement deadline (GA8 installed runtime
// attempt 02, 2026-09-15).

import Testing
import Foundation
@testable import MacCrabCore

@Suite("Exact query resource limit stops the block walk")
struct ExactQueryByteBudgetTests {

    private func makeEvent(_ i: Int, at base: Date, payloadBytes: Int) -> Event {
        let padding = String(repeating: "x", count: payloadBytes)
        return Event(
            timestamp: base.addingTimeInterval(Double(i)),
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: MacCrabCore.ProcessInfo(
                pid: Int32(1000 + i), ppid: 1, rpid: 0,
                name: "true", executable: "/usr/bin/true",
                commandLine: "/usr/bin/true " + padding, args: [],
                workingDirectory: "/",
                userId: 501, userName: "u", groupId: 20,
                startTime: base.addingTimeInterval(Double(i))
            )
        )
    }

    /// Parallel fixtures must not compete for the process-wide pipeline
    /// budget: a foreign lease would make the block decode refuse and turn
    /// these assertions into scheduling noise.
    private func makeStore(_ label: String) throws -> (EventStore, URL) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("exact-\(label)-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let store = try EventStore(
            directory: dir.path,
            liveMemoryBudget: .isolatedProductionEquivalentForTesting()
        )
        return (store, dir)
    }

    @Test("a bounded newest-first query retains the newest records, counts the rest and reports no hard gap")
    func byteBoundedQueryStopsEarly() async throws {
        let (store, dir) = try makeStore("byte-budget")
        defer { try? FileManager.default.removeItem(at: dir) }

        let base = Date(timeIntervalSince1970: 1_700_000_000)
        // An older tail of small records: a walk that kept admitting on a
        // first-fit basis after the refusal would pull these in, because each
        // one still fits in the remaining budget.
        let tail = 16
        for i in 0..<tail {
            try await store.insert(event: makeEvent(i, at: base, payloadBytes: 1_024))
        }
        // ~256 KiB each: 96 of these (~24 MiB) exceed the 16 MiB budget.
        let large = 96
        for i in 0..<large {
            try await store.insert(event: makeEvent(100 + i, at: base, payloadBytes: 256 * 1024))
        }
        let total = tail + large

        // Reference: a narrow newest window that fits inside the budget.
        let newestWindow = base.addingTimeInterval(Double(100 + large - 20))
        let narrow = try await store.exactEventsSnapshot(since: newestWindow, limit: 10_000)
        #expect(narrow.isComplete)
        #expect(narrow.events.count == 20)

        // Bounded: asks for everything and must stop once a limit refuses.
        let before = await store.journalExactQueryBlockDecodeCount()
        let bounded = try await store.exactEventsSnapshot(since: .distantPast, limit: 10_000)
        let boundedDecodes = await store.journalExactQueryBlockDecodeCount() - before
        #expect(!bounded.isComplete)
        #expect(bounded.events.count > 0)
        #expect(bounded.events.count < large)

        // The retained set is exactly the newest N records, contiguous, and
        // contains none of the older small-payload tail.
        let retained = bounded.events.map { $0.timestamp.timeIntervalSince1970 }
        let expected = (0..<bounded.events.count).map {
            base.addingTimeInterval(Double(100 + large - 1 - $0)).timeIntervalSince1970
        }
        #expect(retained == expected)

        // Every in-range record this result does not carry is counted, whether
        // it was refused or sits in a block the walk never decoded.
        #expect(bounded.resourceLimitedRecords == total - bounded.events.count)
        // The walk decodes the retained blocks plus the one that hit the
        // limit; it never decodes the whole retained journal. Each insert
        // here seals its own block, so the bound is one decode per retained
        // record plus the refusing block, with margin for a snapshot retry.
        #expect(boundedDecodes <= UInt64(bounded.events.count) * 2 + 4)
        #expect(boundedDecodes < UInt64(total))
        // A resource-bounded, poison-free result is scannable: no hard gap.
        #expect(bounded.retroactiveScanGap == nil)
        withExtendedLifetime((narrow, bounded)) {}
    }

    @Test("a limit reached inside a multi-record block still retains that block's newest records")
    func boundedWalkRanksWithinTheBlockThatHitTheLimit() async throws {
        let (store, dir) = try makeStore("block-order")
        defer { try? FileManager.default.removeItem(at: dir) }

        let base = Date(timeIntervalSince1970: 1_700_000_000)
        // Batches of 128 (the per-block maximum) so blocks hold many records
        // and the budget is reached part-way through one of them. Records are
        // stored in arrival order, so a walk that admitted them as enumerated
        // would keep a block's oldest records and refuse its newest.
        let chunk = 128
        let chunks = 12
        for c in 0..<chunks {
            let events = (0..<chunk).map {
                makeEvent(c * chunk + $0, at: base, payloadBytes: 16 * 1024)
            }
            // A batch must carry the lane its events actually route to.
            let lane = EventPipelineLane.finalLane(for: events[0])
            _ = try await store.insert(events: events, lane: lane)
        }
        let total = chunk * chunks

        let before = await store.journalExactQueryBlockDecodeCount()
        let bounded = try await store.exactEventsSnapshot(since: .distantPast, limit: 10_000)
        let boundedDecodes = await store.journalExactQueryBlockDecodeCount() - before
        #expect(!bounded.isComplete)
        #expect(bounded.events.count > chunk)
        #expect(bounded.events.count < total)
        // Far fewer decodes than retained records proves the blocks really do
        // hold many records, which is the shape this fixture exists to pin.
        // Without it the ordering assertion below could pass on single-record
        // blocks and never exercise ranking inside a block at all.
        #expect(boundedDecodes * 4 < UInt64(bounded.events.count))

        let retained = bounded.events.map { $0.timestamp.timeIntervalSince1970 }
        let expected = (0..<bounded.events.count).map {
            base.addingTimeInterval(Double(total - 1 - $0)).timeIntervalSince1970
        }
        #expect(retained == expected)
        #expect(bounded.resourceLimitedRecords == total - bounded.events.count)
        #expect(bounded.retroactiveScanGap == nil)
        withExtendedLifetime(bounded) {}
    }

    @Test("hard evidence gaps still stop a retroactive scan; a resource bound alone does not")
    func retroactiveScanGapTaxonomy() {
        #expect(ExactEventQuerySnapshot.retroactiveScanGap(
            poisonRecords: 0, corruptLegacyRecords: 0,
            inheritedLegacyLossRecords: 0, resourceLimitedRecords: 148_000
        ) == nil)
        for (poison, corrupt, inherited) in [(1, 0, 0), (0, 1, 0), (0, 0, 1), (2, 3, 4)] {
            let gap = ExactEventQuerySnapshot.retroactiveScanGap(
                poisonRecords: poison, corruptLegacyRecords: corrupt,
                inheritedLegacyLossRecords: inherited, resourceLimitedRecords: 5
            )
            guard case let .exactEvidenceGap(p, c, i, r)? = gap else {
                Issue.record("expected a hard gap for poison=\(poison) corrupt=\(corrupt) inherited=\(inherited)")
                continue
            }
            #expect(p == poison && c == corrupt && i == inherited && r == 5)
        }
    }

    @Test("the SIGHUP handler tolerates a resource-bounded scan and keeps reloading after a scan error")
    func handlerUsesRetroactiveScanGap() throws {
        let source = try String(contentsOf: handlerSource, encoding: .utf8)
        #expect(source.contains("retroSnapshot.retroactiveScanGap"))
        #expect(!source.contains("guard retroSnapshot.isComplete"))
        #expect(source.contains("catch let cancellation as CancellationError"))
        #expect(source.contains("retroactiveScanNote"))
    }

    /// The installed-qualification gate fails a reload window whose [SIGHUP]
    /// lines carry a failure word, and it reads the message text: the probe
    /// runs `log show --style compact`, whose type column is `E`/`Df`, never
    /// the word "Error". A tolerable skip must therefore describe itself
    /// without one of those words, and a storage failure must carry one.
    @Test("the reload transcript gate reads a tolerable scan skip as clean and a storage failure as failed")
    func retroactiveSkipWordingMatchesTheProtocolGate() throws {
        func skipLine(_ error: EventStoreError) -> String {
            "[SIGHUP] Retroactive scan skipped: " + error.localizedDescription
        }
        let tolerated: [EventStoreError] = [
            .exactEvidenceGap(
                poisonRecords: 1, corruptLegacyRecords: 0,
                inheritedLegacyLossRecords: 0, resourceLimitedRecords: 148_000
            ),
            .memoryLeaseUnavailable("waiting for bounded record ownership"),
            .busy("database is locked")
        ]
        for error in tolerated {
            #expect(!trips(skipLine(error)), "\(error.localizedDescription)")
        }
        for error: EventStoreError in [.stepFailed("x"), .decodingFailed("x")] {
            #expect(trips(skipLine(error)))
        }
        // The genuinely-incomplete reload must still fail the gate.
        let source = try String(contentsOf: handlerSource, encoding: .utf8)
        #expect(source.contains("[SIGHUP] ERROR: reload incomplete"))

        // Every other [SIGHUP] line the reload writes to the unified log must
        // be clean in its own fixed text, because letting the reload continue
        // past a failed retroactive scan made the downstream handlers'
        // lines reachable for the first time. Their conditions are caught and
        // the reload is still reported successful, so the run must not fail on
        // them; only the interpolated reason can carry a failure word, and
        // only when the underlying error really is one.
        let literals = loggerSighupLiterals(in: source)
        // Guard against the scan silently matching nothing and the contract
        // below passing vacuously.
        #expect(literals.count >= 10)
        #expect(literals.contains { $0.contains("Reloaded") })
        for literal in literals {
            if literal.contains("ERROR: reload incomplete") { continue }
            #expect(!trips(literal), "gate-tripping [SIGHUP] log line: \(literal)")
        }
    }

    /// The fixed text of every `logger.*("[SIGHUP] …")` literal, with the
    /// interpolations removed — what `log show` prints minus the runtime values.
    private func loggerSighupLiterals(in source: String) -> [String] {
        var literals: [String] = []
        for call in ["logger.error(", "logger.notice(", "logger.warning("] {
            var search = source[...]
            while let range = search.range(of: call) {
                let rest = search[range.upperBound...]
                search = rest
                guard let open = rest.firstIndex(of: "\"") else { continue }
                let afterOpen = rest.index(after: open)
                guard let close = rest[afterOpen...].firstIndex(of: "\"") else { continue }
                let literal = String(rest[afterOpen..<close])
                guard literal.contains("[SIGHUP]") else { continue }
                literals.append(stripInterpolations(literal))
            }
        }
        return literals
    }

    private func stripInterpolations(_ text: String) -> String {
        var out = ""
        var depth = 0
        var index = text.startIndex
        while index < text.endIndex {
            if depth == 0, text[index] == "\\",
               text.index(after: index) < text.endIndex,
               text[text.index(after: index)] == "(" {
                depth = 1
                index = text.index(index, offsetBy: 2)
                continue
            }
            if depth > 0 {
                if text[index] == "(" { depth += 1 }
                if text[index] == ")" { depth -= 1 }
            } else {
                out.append(text[index])
            }
            index = text.index(after: index)
        }
        return out
    }

    private func trips(_ line: String) -> Bool {
        let lowered = line.lowercased()
        return [
            "error", "fail", "failed", "failure",
            "ignored", "ignoring", "rejected", "not admitted"
        ].contains { lowered.contains($0) }
    }

    private var handlerSource: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/MacCrabAgentKit/SignalHandlers.swift")
    }
}
