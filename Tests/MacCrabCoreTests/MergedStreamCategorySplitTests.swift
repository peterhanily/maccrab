// MergedStreamCategorySplitTests.swift
// v1.21.4 (F2/A2) — the merged event stream is split priority/file so a
// file-write flood can only evict OTHER file events, never a high-value
// exec/network/tcc/auth event. This locks in the routing partition: ONLY the
// file category rides the file stream; everything else rides the protected
// priority stream. A regression that mis-routes a high-volume category onto
// the priority stream would silently reopen the eviction gap.
//
// v1.22.7: the routing is decided per EVENT (`DaemonState.ridesFileStream(_:)`
// → `EventPipelineLane.finalLane(for:)`) because one `.file` action, `open`,
// splits by admission class: a credential / agent-content OPEN keeps priority,
// a dynamic-AI-admitted OPEN (the measured flood source) rides file.
//
// Lives in MacCrabCoreTests because that is the test target that links
// MacCrabAgentKit (there is no separate MacCrabAgentKitTests target).

import Testing
import Foundation
@testable import MacCrabCore
@testable import MacCrabAgentKit

@Suite("F2/A2 merged-stream category split routing")
struct MergedStreamCategorySplitTests {

    private func event(
        _ category: EventCategory,
        action: String,
        enrichments: [String: String] = [:]
    ) -> Event {
        let process = ProcessInfo(
            pid: 4242, ppid: 1, rpid: 1,
            name: "node", executable: "/usr/local/bin/node",
            commandLine: "node", args: ["node"], workingDirectory: "/Users/x/project",
            userId: 501, userName: "x", groupId: 20,
            startTime: Date(timeIntervalSince1970: 1_700_000_000),
            isPlatformBinary: false
        )
        return Event(
            timestamp: Date(timeIntervalSince1970: 1_700_000_000),
            eventCategory: category, eventType: .change, eventAction: action,
            process: process,
            file: category == .file ? FileInfo(path: "/Users/x/project/a.ts", action: .write) : nil,
            enrichments: enrichments
        )
    }

    @Test("only .file WRITE-family rides the file stream; every other category rides priority")
    func fileWriteFamilyIsTheOnlyFileStreamCategory() {
        // Use a write-family action — the flood the file stream is meant to absorb.
        for category in EventCategory.allCases {
            let ridesFile = DaemonState.ridesFileStream(event(category, action: "write"))
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
            #expect(!DaemonState.ridesFileStream(event(category, action: "write")),
                    "\(category) is high-value and must be protected from file-flood eviction")
        }
    }

    @Test("rare high-value .file signals (credential OPEN, BTM) ride priority, not the flood stream")
    func credentialOpenAndBTMRidePriority() {
        // Pre-GA review fix: these are low-volume + persistence/credential-
        // critical, so a file-WRITE flood must not be able to shed them. The
        // sequence engine measures its windows in wall-clock processing time,
        // so a credential OPEN must stay in order with its exec on the same lane.
        #expect(!DaemonState.ridesFileStream(event(.file, action: "open")),
                "credential-read OPEN must ride the priority stream")
        #expect(!DaemonState.ridesFileStream(event(.file, action: "btm_add")),
                "BTM launch-item registration must ride the priority stream")
        // ...while write-family file noise still rides the file stream.
        for action in ["write", "create", "rename", "unlink", "close_modified", "setowner", "setmode"] {
            #expect(DaemonState.ridesFileStream(event(.file, action: action)),
                    "\(action) is file-write flood and must ride the file stream")
        }
    }

    @Test("a dynamic-AI-admitted OPEN is the one .file open that rides the flood stream")
    func dynamicAIOpenRidesFile() {
        // v1.22.7: 47,931 admitted dynamic-AI OPENs in one 30 s esbuild burst
        // backlogged the priority lane to 76,684 and evicted exec/fork/exit
        // (attempt4 capture). The ES worker stamps that class; nothing else
        // may move an OPEN off priority.
        let stamped = event(.file, action: "open", enrichments: [
            EventPipelineLane.openAdmissionEnrichmentKey: EventPipelineLane.dynamicAIOpenAdmission,
        ])
        #expect(DaemonState.ridesFileStream(stamped))
        #expect(!DaemonState.ridesFileStream(event(.file, action: "open", enrichments: ["open_admission": "other"])),
                "only the dynamic-AI stamp moves an OPEN; an unknown value keeps priority")
        #expect(!DaemonState.ridesFileStream(event(.process, action: "open", enrichments: [
            EventPipelineLane.openAdmissionEnrichmentKey: EventPipelineLane.dynamicAIOpenAdmission,
        ])), "the stamp only applies to the file category")
    }
}
