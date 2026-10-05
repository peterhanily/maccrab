// MCPTracePersistencePausedNoteTests.swift
// MacCrabCLITests
//
// get_traces / hunt_trace / trace_from_event must not let an empty result
// read as "nothing happened" while the engine reports TraceGraph persistence
// paused. The note is a pure function of the heartbeat (see the main.swift
// globals caveat in CLIExecutableUnitTests).

import Testing
import Foundation
@testable import maccrab_mcp
@testable import MacCrabCore

@Suite("maccrab-mcp: TraceGraph paused-persistence note")
struct MCPTracePersistencePausedNoteTests {

    private func heartbeat(_ admission: String?) throws -> HeartbeatSnapshot {
        let block = admission.map { #","tracegraph_storage_admission":\#($0)"# } ?? ""
        let json = #"{"schema_version":5,"written_at_unix":1780000000\#(block)}"#
        return try JSONDecoder().decode(HeartbeatSnapshot.self, from: Data(json.utf8))
    }

    @Test("footprint latch names the cause, the remaining deficit and auto-resume")
    func footprintLatch() throws {
        let note = try #require(traceGraphPersistencePausedNote(heartbeat("""
            {"enabled":true,"accepting_mutations":false,"blocked":true,
             "store_available":true,"startup_blocked":false,
             "reason":"footprint_limit","recovery_deficit_bytes":12340001}
            """)))
        #expect(note.hasPrefix("TraceGraph persistence is PAUSED (footprint_limit)"))
        #expect(note.contains("the store reached its on-disk size limit"))
        #expect(note.contains("New causal evidence is not being recorded"))
        #expect(note.contains("not evidence that nothing happened"))
        #expect(note.contains("free about 12.4 MB before writes resume automatically"))
        #expect(note.contains("events, alerts, Sigma and sequence rules keep running"))
        #expect(note.contains("Engine heartbeat written 2026-05-28T20:26:40Z"))
    }

    @Test("other blocks, a saturated queue and a missing store each say why")
    func otherPauses() throws {
        let lowSpace = try #require(traceGraphPersistencePausedNote(heartbeat("""
            {"enabled":true,"blocked":true,"store_available":true,"reason":"low_free_space"}
            """)))
        #expect(lowSpace.contains("(low_free_space): free disk space is below"))
        #expect(!lowSpace.contains("resume automatically"))

        let saturated = try #require(traceGraphPersistencePausedNote(heartbeat("""
            {"enabled":true,"blocked":false,"store_available":true,"reason":"",
             "accepting_mutations":false,"recovery_mutation_queue_saturated":true}
            """)))
        #expect(saturated.contains("(reason not reported): the bounded recovery write queue is saturated"))

        let missing = try #require(traceGraphPersistencePausedNote(heartbeat("""
            {"enabled":true,"accepting_mutations":false,"blocked":true,
             "store_available":false,"startup_blocked":true,"reason":"footprint_limit"}
            """)))
        #expect(missing.contains("could not be opened when the engine started"))
        #expect(!missing.contains("resume automatically"))
    }

    @Test("accepting persistence or an absent block adds no note")
    func noNote() throws {
        #expect(traceGraphPersistencePausedNote(nil) == nil)
        #expect(try traceGraphPersistencePausedNote(heartbeat(nil)) == nil)
        #expect(try traceGraphPersistencePausedNote(heartbeat("""
            {"enabled":true,"accepting_mutations":true,"blocked":false,
             "store_available":true,"reason":""}
            """)) == nil)
    }
}
