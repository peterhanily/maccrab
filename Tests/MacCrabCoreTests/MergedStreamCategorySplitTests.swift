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

    @Test("only .file rides the file stream; every other category rides priority")
    func fileIsTheOnlyFileStreamCategory() {
        for category in EventCategory.allCases {
            let ridesFile = DaemonState.ridesFileStream(category)
            if category == .file {
                #expect(ridesFile, ".file must ride the dedicated file stream")
            } else {
                #expect(!ridesFile, "\(category) must ride the protected priority stream, not the file stream")
            }
        }
    }

    @Test("high-value categories are explicitly on the priority stream")
    func highValueCategoriesAreProtected() {
        // The categories a file flood must never be able to evict.
        for category in [EventCategory.process, .network, .tcc, .authentication, .registry] {
            #expect(!DaemonState.ridesFileStream(category),
                    "\(category) is high-value and must be protected from file-flood eviction")
        }
    }
}
