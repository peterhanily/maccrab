// V2InvestigationOpaqueEntityIdTests.swift
// MacCrabAppTests
//
// rc.3 deep-audit (ui-investigation) related-instance regression guard:
// the trace-picker row rendered `trace.rootProcess` under a terminal
// icon, but the live provider maps that field from `rootEntityId` — the
// opaque `process:<stableKey>` causal-graph entity id — so the row showed
// a hash dressed up as a command line. `pickerRootProcess` now suppresses
// the opaque form via `isOpaqueEntityId`. These pin the predicate that
// decides "opaque id (hide/resolve)" vs "real, showable process name".

import Testing
import Foundation
@testable import MacCrabApp

@Suite("V2Investigation.isOpaqueEntityId")
struct V2InvestigationOpaqueEntityIdTests {

    @Test("entity ids of every known type read as opaque")
    func knownEntityTypesAreOpaque() {
        // Entity id shape is "\(entityType):\(stableKey)" (TraceGraphNode.canonicalId).
        for type in ["process", "file", "network", "ai_agent", "persistence", "tcc", "alert"] {
            #expect(V2InvestigationWorkspace.isOpaqueEntityId("\(type):9f3a2c1b0d"))
        }
        // Case-insensitive on the type half.
        #expect(V2InvestigationWorkspace.isOpaqueEntityId("PROCESS:abc123"))
    }

    @Test("the em-dash placeholder and empty string are opaque")
    func placeholderAndEmptyAreOpaque() {
        #expect(V2InvestigationWorkspace.isOpaqueEntityId("—"))
        #expect(V2InvestigationWorkspace.isOpaqueEntityId(""))
    }

    @Test("real process names / paths are NOT opaque and stay showable")
    func realProcessNamesAreShowable() {
        #expect(!V2InvestigationWorkspace.isOpaqueEntityId("/usr/bin/curl"))
        #expect(!V2InvestigationWorkspace.isOpaqueEntityId("bash"))
        #expect(!V2InvestigationWorkspace.isOpaqueEntityId("node --inspect server.js"))
        // A colon that is NOT a known-entity-type prefix must remain showable
        // (e.g. a Windows-style path or an unknown scheme should not be hidden).
        #expect(!V2InvestigationWorkspace.isOpaqueEntityId("C:\\Tools\\agent.exe"))
        #expect(!V2InvestigationWorkspace.isOpaqueEntityId("weird:value"))
    }
}
