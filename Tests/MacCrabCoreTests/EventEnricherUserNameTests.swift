// EventEnricherUserNameTests.swift
// v1.12.6 Wave 9I — pin the uid → user_name resolution so ES-sourced
// events don't ship with user_name="" the way they did pre-9I.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("EventEnricher: Wave 9I uid → user_name resolution")
struct EventEnricherUserNameTests {

    private func makeProcess(
        userId: UInt32,
        userName: String,
        pid: Int32 = 999_999
    ) -> MacCrabCore.ProcessInfo {
        MacCrabCore.ProcessInfo(
            pid: pid,
            ppid: 1,
            rpid: 1,
            name: "test",
            executable: "/usr/bin/test",
            commandLine: "/usr/bin/test",
            args: ["/usr/bin/test"],
            workingDirectory: "/tmp",
            userId: userId,
            userName: userName,
            groupId: 20,
            startTime: Date()
        )
    }

    @Test("Empty userName from ES collector gets resolved via getpwuid")
    func resolvesEmptyUserName() async throws {
        // The current process's effective uid must resolve to a non-empty
        // name (since the test harness has a passwd entry). Using getuid()
        // makes this safe across CI / dev / arbitrary user shells.
        let currentUid = UInt32(getuid())
        let enricher = EventEnricher()
        let event = Event(
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: makeProcess(userId: currentUid, userName: "")
        )

        let enriched = await enricher.enrich(event)
        #expect(!enriched.process.userName.isEmpty,
                "uid → user_name resolution should fill in the empty userName")
    }

    @Test("Pre-set userName is preserved (no override on non-empty input)")
    func preservesNonEmptyUserName() async throws {
        let enricher = EventEnricher()
        let event = Event(
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: makeProcess(userId: 0, userName: "explicitly-set")
        )

        let enriched = await enricher.enrich(event)
        #expect(enriched.process.userName == "explicitly-set",
                "non-empty userName must not be overwritten by uid resolution")
    }

    @Test("Unknown uid resolves to empty string (no crash, no exception)")
    func unknownUidReturnsEmpty() async throws {
        // 4_294_967_290 is unlikely to have a passwd entry on any
        // ordinary system. Resolution must not crash — empty is fine.
        let enricher = EventEnricher()
        let event = Event(
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: makeProcess(userId: 4_294_967_290, userName: "")
        )

        let enriched = await enricher.enrich(event)
        // No assertion on the exact value: on some systems even high
        // uids resolve via Open Directory or local passwd, on others
        // they return nil → "". Just assert it doesn't crash and the
        // event makes it through.
        #expect(enriched.process.userId == 4_294_967_290)
    }
}
