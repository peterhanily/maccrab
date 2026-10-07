// MergedStreamCategorySplitTests.swift
// v1.21.4 (F2/A2) — the merged event stream is split priority/file so a
// file-write flood can only evict OTHER file events, never a high-value
// exec/network/tcc/auth event. This locks in the routing partition: ONLY the
// file category rides the file stream; everything else rides the protected
// priority stream. A regression that mis-routes a high-volume category onto
// the priority stream would silently reopen the eviction gap.
//
// Lives in MacCrabCoreTests because that is the test target that links
// MacCrabAgentKit (there is no separate MacCrabAgentKitTests target).

import Testing
import Foundation
@testable import MacCrabCore
@testable import MacCrabAgentKit

@Suite("F2/A2 merged-stream category split routing")
struct MergedStreamCategorySplitTests {

    @Test("only .file WRITE-family rides the file stream; every other category rides priority")
    func fileWriteFamilyIsTheOnlyFileStreamCategory() {
        // Use a write-family action — the flood the file stream is meant to absorb.
        for category in EventCategory.allCases {
            let ridesFile = DaemonState.ridesFileStream(category, action: "write")
            if category == .file {
                #expect(ridesFile, ".file write-family must ride the dedicated file stream")
            } else {
                #expect(!ridesFile, "\(category) must ride the protected priority stream, not the file stream")
            }
        }
    }

    @Test("high-value categories are explicitly on the priority stream")
    func highValueCategoriesAreProtected() {
        // The categories a file flood must never be able to evict.
        for category in [EventCategory.process, .network, .tcc, .authentication, .registry] {
            #expect(!DaemonState.ridesFileStream(category, action: "write"),
                    "\(category) is high-value and must be protected from file-flood eviction")
        }
    }

    @Test("BTM rides priority; OPEN rides the file stream with the rest of the file flood")
    func btmRidesPriorityAndOpenRidesFile() {
        // Pre-GA review fix: BTM is low-volume + persistence-critical, so a
        // file-WRITE flood must not be able to shed it.
        #expect(!DaemonState.ridesFileStream(.file, action: "btm_add"),
                "BTM launch-item registration must ride the priority stream")
        // v1.22.7: OPEN used to ride priority as a "low-volume credential
        // read". Since dynamic-AI admission it is a flood source — 47,931
        // admitted OPENs in one 30 s esbuild burst backlogged the priority
        // lane to 76,684 and evicted exec/fork/exit (attempt4 capture). It now
        // rides the file stream like every other file-category action.
        for action in ["open", "write", "create", "rename", "unlink", "close_modified", "setowner", "setmode"] {
            #expect(DaemonState.ridesFileStream(.file, action: action),
                    "\(action) is file-write flood and must ride the file stream")
        }
    }
}
