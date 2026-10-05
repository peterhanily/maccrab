// MCPTracePersistencePausedNoteTests.swift
// MacCrabCLITests
//
// get_traces / hunt_trace / trace_from_event must not let an empty result
// read as "nothing happened" while the engine reports TraceGraph persistence
// paused. The note is a pure function of the heartbeat and an injected clock
// (see the main.swift globals caveat in CLIExecutableUnitTests).

import Testing
import Foundation
@testable import maccrab_mcp
@testable import MacCrabCore

@Suite("maccrab-mcp: TraceGraph paused-persistence note")
struct MCPTracePersistencePausedNoteTests {

    private static let writtenAt: Double = 1_780_000_000
    /// Inside the 120 s freshness bound get_status also applies.
    private static let freshNow = writtenAt + 30

    private func heartbeat(_ admission: String?) throws -> HeartbeatSnapshot {
        let block = admission.map { #","tracegraph_storage_admission":\#($0)"# } ?? ""
        let json = #"{"schema_version":5,"written_at_unix":1780000000\#(block)}"#
        return try JSONDecoder().decode(HeartbeatSnapshot.self, from: Data(json.utf8))
    }

    /// Proportions from a real latched 1.22.5 heartbeat (250 MiB cap, write
    /// threshold at 75%, resume target at 50%, footprint in between).
    private func latched(autoVacuumMode: Int, deficit: Int64 = 33_202_177,
                         pinnedReader: Bool = false) -> String {
        """
        {"enabled":true,"accepting_mutations":false,"blocked":true,
         "store_available":true,"startup_blocked":false,
         "reason":"footprint_limit","footprint_bytes":164274176,
         "max_footprint_bytes":262144000,"admission_threshold_bytes":196608000,
         "resume_below_bytes":131072000,"recovery_deficit_bytes":\(deficit),
         "auto_vacuum_mode":\(autoVacuumMode),"pinned_reader":\(pinnedReader)}
        """
    }

    @Test("footprint latch names the threshold, the deficit, the deletion and auto-resume")
    func footprintLatch() throws {
        let note = try #require(traceGraphPersistencePausedNote(
            heartbeat(latched(autoVacuumMode: 2)), now: Self.freshNow))
        #expect(note.hasPrefix("TraceGraph persistence is PAUSED (footprint_limit)"))
        #expect(note.contains("the store passed its write threshold and stays paused until it falls below the resume target (threshold 187.5 MiB, resume below 125.0 MiB, now 156.7 MiB, cap 250.0 MiB)"))
        #expect(!note.contains("reached its on-disk size limit"))
        #expect(note.contains("no new traces are recorded"))
        #expect(note.contains("trace queries still run but return only evidence recorded before the pause"))
        #expect(note.contains("not evidence that nothing happened"))
        #expect(note.contains("Recovery is deleting the oldest pre-pause trace evidence (never anything under an hour old)"))
        #expect(note.contains("must free about 31.7 MiB more before writes resume automatically"))
        #expect(!note.contains("waiting for a reader"))
        #expect(note.contains("Events, alerts, Sigma and sequence rules keep running"))
        #expect(note.contains("Engine heartbeat written 2026-05-28T20:26:40Z"))

        let pinned = try #require(traceGraphPersistencePausedNote(
            heartbeat(latched(autoVacuumMode: 2, pinnedReader: true)), now: Self.freshNow))
        #expect(pinned.contains("it is currently waiting for a reader to release the database"))

        let caughtUp = try #require(traceGraphPersistencePausedNote(
            heartbeat(latched(autoVacuumMode: 2, deficit: 0)), now: Self.freshNow))
        #expect(caughtUp.contains("Recovery has reached its resume target"))
    }

    @Test("a latched legacy auto_vacuum=0 store is not promised an automatic resume")
    func legacyStore() throws {
        let note = try #require(traceGraphPersistencePausedNote(
            heartbeat(latched(autoVacuumMode: 0)), now: Self.freshNow))
        #expect(!note.contains("resume automatically"))
        #expect(!note.contains("Recovery is deleting"))
        #expect(note.contains("legacy auto_vacuum mode 0, so recovery cannot shrink it while the engine runs"))
        #expect(note.contains("storage.tracegraph_max_size_mb"))
        #expect(note.contains("converted offline with a full VACUUM while the engine is stopped"))

        let caughtUp = try #require(traceGraphPersistencePausedNote(
            heartbeat(latched(autoVacuumMode: 0, deficit: 0)), now: Self.freshNow))
        #expect(!caughtUp.contains("legacy auto_vacuum"))
    }

    @Test("a stale heartbeat does not claim detection is running now")
    func staleHeartbeat() throws {
        let stale = try #require(traceGraphPersistencePausedNote(
            heartbeat(latched(autoVacuumMode: 2)), now: Self.writtenAt + 3 * 86_400))
        #expect(stale.hasPrefix("The last engine heartbeat (written 2026-05-28T20:26:40Z, 4320 min ago) reported TraceGraph persistence PAUSED (footprint_limit)"))
        #expect(stale.contains("it may not be running, so nothing at all may currently be recorded"))
        #expect(!stale.contains("keep running"))
        #expect(!stale.contains("resume automatically"))
        #expect(stale.contains("not evidence that nothing happened"))

        // A heartbeat from the future is not fresh either.
        let future = try #require(traceGraphPersistencePausedNote(
            heartbeat(latched(autoVacuumMode: 2)), now: Self.writtenAt - 600))
        #expect(future.hasPrefix("The last engine heartbeat (written 2026-05-28T20:26:40Z)"))
        #expect(!future.contains("keep running"))
    }

    @Test("other blocks, a saturated queue and a missing store each say why")
    func otherPauses() throws {
        let lowSpace = try #require(traceGraphPersistencePausedNote(heartbeat("""
            {"enabled":true,"blocked":true,"store_available":true,"reason":"low_free_space"}
            """), now: Self.freshNow))
        #expect(lowSpace.contains("(low_free_space): free disk space is below"))
        #expect(!lowSpace.contains("resume automatically"))

        let saturated = try #require(traceGraphPersistencePausedNote(heartbeat("""
            {"enabled":true,"blocked":false,"store_available":true,"reason":"",
             "accepting_mutations":false,"recovery_mutation_queue_saturated":true}
            """), now: Self.freshNow))
        #expect(saturated.contains("(reason not reported): the bounded recovery write queue is saturated"))

        let missing = try #require(traceGraphPersistencePausedNote(heartbeat("""
            {"enabled":true,"accepting_mutations":false,"blocked":true,
             "store_available":false,"startup_blocked":true,"reason":"footprint_limit"}
            """), now: Self.freshNow))
        #expect(missing.contains("could not be opened when the engine started"))
        #expect(!missing.contains("resume automatically"))
    }

    @Test("accepting persistence or an absent block adds no note")
    func noNote() throws {
        #expect(traceGraphPersistencePausedNote(nil) == nil)
        #expect(try traceGraphPersistencePausedNote(heartbeat(nil), now: Self.freshNow) == nil)
        #expect(try traceGraphPersistencePausedNote(heartbeat("""
            {"enabled":true,"accepting_mutations":true,"blocked":false,
             "store_available":true,"reason":""}
            """), now: Self.freshNow) == nil)
    }
}
