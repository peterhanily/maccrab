import Testing
import Foundation
@testable import MacCrabCore

private final class UsernameAttemptCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var attempts = 0
    func next() -> Int { lock.lock(); defer { lock.unlock() }; attempts += 1; return attempts }
}

/// Inert resolvers and collector-supplied signatures keep these tests off the
/// real directory service, filesystem and Security framework on every host.
@Suite("EventEnricher: injected username evidence")
struct EventEnricherUserNameTests {
    private func event(userName: String = "") -> Event {
        Event(eventCategory: .process, eventType: .start, eventAction: "exec",
              process: MacCrabCore.ProcessInfo(
                pid: 999_999, ppid: 1, rpid: 1, name: "fixture",
                executable: "/inert/fixture", commandLine: "fixture", args: [],
                workingDirectory: "/", userId: 42, userName: userName,
                groupId: 20, startTime: Date(timeIntervalSince1970: 1_750_000_000),
                codeSignature: CodeSignatureInfo(signerType: .apple),
                isPlatformBinary: true))
    }

    private func enricher(resolver: @escaping @Sendable (UInt32) -> String?) -> EventEnricher {
        EventEnricher(heavyEnrichmentPlane: HeavyEnrichmentPlane(
            configuration: .init(operationTimeoutSeconds: 30),
            liveMemoryBudget: .isolatedProductionEquivalentForTesting()
        ), userNameResolver: resolver)
    }

    private func result(_ original: Event, from enricher: EventEnricher, owned: Bool = false) async throws -> Event {
        let initial = await enricher.enrich(original)
        #expect(DeferredEventEnrichment.coverageState(for: .userName, in: initial) == .pending)
        let deadline = ContinuousClock.now.advanced(by: .seconds(30))
        while ContinuousClock.now < deadline {
            let patches: [DeferredEventEnrichment]
            if owned { patches = await enricher.drainOwnedDeferredEnrichments().map(\.patch) }
            else { patches = await enricher.drainDeferredEnrichments() }
            if let patch = patches.first {
                #expect(patch.component == .userName)
                #expect(patch.binding.eventID == original.id)
                return try #require(patch.applying(to: initial))
            }
            try await Task.sleep(for: .milliseconds(5))
        }
        Issue.record("injected username worker did not complete")
        throw CancellationError()
    }

    private func wait(_ enricher: EventEnricher,
                      until predicate: (HeavyEnrichmentPlaneSnapshot) -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(30))
        while !predicate(await enricher.heavyEnrichmentSnapshot()) {
            try #require(ContinuousClock.now < deadline, "injected worker did not reach expected state")
            try await Task.sleep(for: .milliseconds(5))
        }
    }

    @Test("Accepted public and owned drains seed the inline cache with exact identity", arguments: [false, true])
    func resolvesEmptyUserName(owned: Bool) async throws {
        let enricher = enricher { uid in uid == 42 ? "fixture-user" : nil }
        let original = event()
        let enriched = try await result(original, from: enricher, owned: owned)
        #expect(enriched.id == original.id)
        #expect(enriched.process.userName == "fixture-user")
        #expect(DeferredEventEnrichment.coverageState(for: .userName, in: enriched) == nil)
        let offered = (await enricher.heavyEnrichmentSnapshot()).offeredRequestsTotal
        let warm = await enricher.enrich(event())
        #expect(warm.process.userName == "fixture-user")
        #expect(DeferredEventEnrichment.coverageState(for: .userName, in: warm) == nil)
        #expect((await enricher.heavyEnrichmentSnapshot()).offeredRequestsTotal == offered,
                "An accepted patch must seed the inline cache, avoiding another heavy offer")
        #expect((await enricher.shutdownHeavyEnrichment()).cleanlyDrained)
    }

    @Test("Collector names are preserved without calling the resolver")
    func preservesNonEmptyUserName() async {
        let enricher = enricher { _ in
            Issue.record("resolver called for an already named event")
            return "wrong"
        }
        let enriched = await enricher.enrich(event(userName: "explicitly-set"))
        #expect(enriched.process.userName == "explicitly-set")
        #expect((await enricher.heavyEnrichmentSnapshot()).offeredRequestsTotal == 0)
        #expect((await enricher.shutdownHeavyEnrichment()).cleanlyDrained)
    }

    @Test("Timed-out directory results cannot seed either cache or reopen their original event")
    func lateDirectoryResultDoesNotPublish() async throws {
        let attempts = UsernameAttemptCounter()
        let entered = DispatchSemaphore(value: 0)
        let release = DispatchSemaphore(value: 0)
        let plane = HeavyEnrichmentPlane(configuration: .init(operationTimeoutSeconds: 0.5),
                                        liveMemoryBudget: .isolatedProductionEquivalentForTesting())
        let enricher = EventEnricher(heavyEnrichmentPlane: plane, userNameResolver: { _ in
            let attempt = attempts.next()
            if attempt == 1 { entered.signal(); _ = release.wait(timeout: .now() + 30) }
            return "attempt-\(attempt)"
        })
        defer { release.signal() }
        let original = await enricher.enrich(event())
        try #require(entered.wait(timeout: .now() + 5) == .success)
        try await wait(enricher) { $0.timedOutRequestsTotal == 1 }
        let timeout = try #require(await enricher.drainOwnedDeferredEnrichments().first?.patch)
        #expect(timeout.outcome == .timedOut)
        #expect(timeout.applying(to: original)?.process.userName == "")
        release.signal()
        try await wait(enricher) { $0.physicalWorkers == 0 }
        #expect(await enricher.drainOwnedDeferredEnrichments().isEmpty)
        let recovered = try await result(event(), from: enricher, owned: true)
        #expect(recovered.process.userName == "attempt-2")
        #expect(recovered.id != original.id)
        #expect((await enricher.shutdownHeavyEnrichment()).cleanlyDrained)
    }

    @Test("Unavailable username is explicit, never a successful empty value", arguments: [false, true])
    func unknownUidReturnsUnavailable(empty: Bool) async throws {
        let enricher = enricher { _ in empty ? "" : nil }
        let original = event()
        let enriched = try await result(original, from: enricher)
        #expect(enriched.process.userName.isEmpty)
        #expect(enriched.process.userId == 42)
        #expect(DeferredEventEnrichment.coverageState(for: .userName, in: enriched) == .unavailable)
        #expect((await enricher.shutdownHeavyEnrichment()).cleanlyDrained)
    }
}
