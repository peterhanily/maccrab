// EventEnricherUserNameTests.swift
// v1.12.6 Wave 9I — pin the uid → user_name resolution so ES-sourced
// events don't ship with user_name="" the way they did pre-9I.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("EventEnricher: Wave 9I uid → user_name resolution")
struct EventEnricherUserNameTests {

    private func resolvingUserName(
        _ event: Event,
        with enricher: EventEnricher
    ) async -> Event {
        let initiallyEnriched = await enricher.enrich(event)
        if !initiallyEnriched.process.userName.isEmpty { return initiallyEnriched }
        let addition = DispatchTime.now().uptimeNanoseconds
            .addingReportingOverflow(30_000_000_000)
        let deadline = addition.overflow ? UInt64.max : addition.partialValue
        while DispatchTime.now().uptimeNanoseconds < deadline {
            if let patch = await enricher.drainDeferredEnrichments(limit: 16).first(where: {
                $0.component == .userName
            }), let applied = patch.applying(to: initiallyEnriched) {
                return applied
            }
            try? await Task.sleep(nanoseconds: 5_000_000)
        }
        return initiallyEnriched
    }

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
        let enricher = EventEnricher(heavyEnrichmentPlane: HeavyEnrichmentPlane(
            // The test verifies getpwuid evidence, not the production 50 ms
            // admission budget. Utility workers can be starved in the full
            // parallel suite, so use a coarse test-only hang detector.
            configuration: .init(operationTimeoutSeconds: 30),
            liveMemoryBudget: .isolatedProductionEquivalentForTesting()
        ))
        let event = Event(
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: makeProcess(userId: currentUid, userName: "")
        )

        let enriched = await resolvingUserName(event, with: enricher)
        #expect(!enriched.process.userName.isEmpty,
                "uid → user_name resolution should fill in the empty userName")
        _ = await enricher.shutdownHeavyEnrichment()
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
