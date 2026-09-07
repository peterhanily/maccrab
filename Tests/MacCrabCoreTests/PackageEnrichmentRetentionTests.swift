import Foundation
import Testing
@testable import MacCrabCore

@Suite("Optional package enrichment has bounded retention and shared fetches")
struct PackageEnrichmentRetentionTests {
    private final class Clock: @unchecked Sendable {
        private let lock = NSLock()
        private var instant = ContinuousClock.now
        func now() -> ContinuousClock.Instant {
            lock.lock(); defer { lock.unlock() }; return instant
        }
        func advance(_ duration: Duration) {
            lock.lock(); defer { lock.unlock() }; instant = instant.advanced(by: duration)
        }
    }

    /// One-shot scheduling barrier. Fixtures never depend on sleeps or polling.
    private final class Signal: @unchecked Sendable {
        private let lock = NSLock()
        private var fired = false
        private var waiters: [CheckedContinuation<Void, Never>] = []
        func wait() async {
            await withCheckedContinuation { register($0) }
        }
        private func register(_ continuation: CheckedContinuation<Void, Never>) {
            lock.lock()
            if fired { lock.unlock(); continuation.resume(); return }
            waiters.append(continuation)
            lock.unlock()
        }
        func fire() {
            lock.lock()
            fired = true
            let ready = waiters
            waiters.removeAll()
            lock.unlock()
            ready.forEach { $0.resume() }
        }
    }

    private actor Calls {
        private(set) var total = 0
        func record() -> Int { total += 1; return total }
    }

    private static let metadata = Data(#"{"description":"A maintained example package for ordinary fixtures","homepage":"https://example.org","versions":{"1.0.0":{}},"dist-tags":{"latest":"1.0.0"}}"#.utf8)
    private static let provenance = Data(#"{"attestations":[{"predicate":{"buildDefinition":{"externalParameters":{"workflow":{"repository":"https://example.org/source"}}},"runDetails":{"builder":{"id":"https://example.org/builder"}}}}]}"#.utf8)

    @Test("Metadata retention evicts the least recently used entry and expires distinct old keys")
    func metadataEvictionAndExpiry() async throws {
        let clock = Clock(), calls = Calls()
        let analyzer = PackageMetadataAnalyzer(cacheTTL: 60, capacity: 2, now: { clock.now() }) { _ in
            _ = await calls.record(); return Self.metadata
        }
        _ = try #require(await analyzer.analyze(packageName: "example-a", registry: .npm))
        _ = try #require(await analyzer.analyze(packageName: "example-b", registry: .npm))
        _ = try #require(await analyzer.analyze(packageName: "example-a", registry: .npm))
        _ = try #require(await analyzer.analyze(packageName: "example-c", registry: .npm))
        _ = try #require(await analyzer.analyze(packageName: "example-a", registry: .npm))
        #expect(await calls.total == 3)
        _ = try #require(await analyzer.analyze(packageName: "example-b", registry: .npm))
        #expect(await calls.total == 4)
        let retained = await analyzer.cacheSnapshot()
        #expect(retained.entries == 2)
        #expect(retained.chargedBytes > 0)
        #expect(retained.chargedBytes <= 8 * 1024 * 1024)
        clock.advance(.seconds(60))
        let expired = await analyzer.cacheSnapshot()
        #expect(expired.entries == 0)
        #expect(expired.chargedBytes == 0)
        _ = try #require(await analyzer.analyze(packageName: "example-a", registry: .npm))
        #expect(await calls.total == 5)
    }

    @Test("Successful responses larger than the retention budget are returned without caching")
    func oversizedResultIsNotRetained() async throws {
        let clock = Clock(), calls = Calls()
        let analyzer = PackageMetadataAnalyzer(cacheTTL: 60, capacity: 2, maximumBytes: 512,
                                               now: { clock.now() }) { _ in
            _ = await calls.record(); return Self.metadata
        }
        let first = try #require(await analyzer.analyze(packageName: "example", registry: .npm))
        let second = try #require(await analyzer.analyze(packageName: "example", registry: .npm))
        #expect(first.homepage == "https://example.org")
        #expect(second.score == first.score)
        #expect(await calls.total == 2)
        let snapshot = await analyzer.cacheSnapshot()
        #expect(snapshot.entries == 0)
        #expect(snapshot.chargedBytes == 0)
        #expect(snapshot.activeLoads == 0)
    }

    @Test("The byte budget evicts retained values before the item limit is reached")
    func byteBudgetEviction() async throws {
        let clock = Clock(), calls = Calls()
        let analyzer = PackageMetadataAnalyzer(cacheTTL: 60, capacity: 128, maximumBytes: 1800,
                                               now: { clock.now() }) { _ in
            _ = await calls.record(); return Self.metadata
        }
        _ = try #require(await analyzer.analyze(packageName: "example-a", registry: .npm))
        _ = try #require(await analyzer.analyze(packageName: "example-b", registry: .npm))
        let snapshot = await analyzer.cacheSnapshot()
        #expect(snapshot.entries == 1)
        #expect(snapshot.chargedBytes <= 1800)
        _ = try #require(await analyzer.analyze(packageName: "example-a", registry: .npm))
        #expect(await calls.total == 3)
    }

    @Test("Concurrent duplicates share a fetch while distinct requests respect the active limit")
    func coalescingAndSaturation() async throws {
        let clock = Clock(), calls = Calls(), entered = Signal(), release = Signal(), joined = Signal()
        let analyzer = PackageMetadataAnalyzer(cacheTTL: 60, capacity: 2, maximumActive: 1, maximumWaiters: 2,
                                               now: { clock.now() }, observe: {
            if $0.coalesced > 0 { joined.fire() }
        }) { _ in
            _ = await calls.record(); entered.fire(); await release.wait(); return Self.metadata
        }
        let first = Task { await analyzer.analyze(packageName: "example", registry: .npm) }
        await entered.wait()
        let second = Task { await analyzer.analyze(packageName: "example", registry: .npm) }
        await joined.wait()
        let duplicateUnavailable = await analyzer.analyze(packageName: "example", registry: .npm)
        #expect(duplicateUnavailable == nil)
        let unavailable = await analyzer.analyze(packageName: "another-example", registry: .npm)
        #expect(unavailable == nil)
        #expect(await calls.total == 1)
        let busy = await analyzer.cacheSnapshot()
        #expect(busy.activeLoads == 1)
        #expect(busy.waitingCalls == 2)
        #expect(busy.coalesced == 1)
        #expect(busy.saturated == 2)
        release.fire()
        let a = try #require(await first.value)
        let b = try #require(await second.value)
        #expect(a.score == b.score)
        #expect(a.packageName == b.packageName)
        let settled = await analyzer.cacheSnapshot()
        #expect(settled.activeLoads == 0)
        #expect(settled.entries == 1)
    }

    @Test("Cancelling one caller preserves another caller's shared request")
    func cancellationDoesNotCancelAnotherWaiter() async throws {
        let clock = Clock(), calls = Calls(), entered = Signal(), release = Signal(), joined = Signal()
        let analyzer = PackageMetadataAnalyzer(cacheTTL: 60, capacity: 2,
                                               now: { clock.now() }, observe: {
            if $0.coalesced > 0 { joined.fire() }
        }) { _ in
            _ = await calls.record(); entered.fire(); await release.wait(); return Self.metadata
        }
        let cancelled = Task { await analyzer.analyze(packageName: "example", registry: .npm) }
        await entered.wait()
        let surviving = Task { await analyzer.analyze(packageName: "example", registry: .npm) }
        await joined.wait()
        cancelled.cancel()
        #expect(await cancelled.value == nil)
        let remaining = await analyzer.cacheSnapshot()
        #expect(remaining.waitingCalls == 1)
        #expect(remaining.activeLoads == 1)
        #expect(remaining.cancelledLoads == 0)
        release.fire()
        _ = try #require(await surviving.value)
        #expect(await calls.total == 1)
        #expect(await analyzer.cacheSnapshot().entries == 1)
    }

    @Test("Last-caller cancellation releases its waiter while a late fetch retains its slot and cannot cache")
    func lastCallerCancellationRetainsLoadSlot() async throws {
        let clock = Clock(), calls = Calls(), entered = Signal(), release = Signal()
        let cancelled = Signal(), settled = Signal()
        let analyzer = PackageMetadataAnalyzer(cacheTTL: 60, capacity: 2, maximumActive: 1,
                                               now: { clock.now() }, observe: {
            if $0.cancelledLoads == 1, $0.activeLoads == 0 { settled.fire() }
        }) { _ in
            _ = await calls.record()
            return await withTaskCancellationHandler {
                entered.fire()
                // Simulate ordinary IO whose completion arrives after cancellation.
                await release.wait()
                return Self.metadata
            } onCancel: {
                cancelled.fire()
            }
        }
        let request = Task { await analyzer.analyze(packageName: "example", registry: .npm) }
        await entered.wait()
        request.cancel()
        await cancelled.wait()
        #expect(await request.value == nil)
        let abandoned = await analyzer.cacheSnapshot()
        #expect(abandoned.activeLoads == 1)
        #expect(abandoned.waitingCalls == 0)
        #expect(abandoned.cancelledLoads == 1)
        #expect(await analyzer.analyze(packageName: "example", registry: .npm) == nil)
        #expect(await analyzer.analyze(packageName: "another-example", registry: .npm) == nil)
        #expect(await calls.total == 1)
        release.fire()
        await settled.wait()
        let afterLateCompletion = await analyzer.cacheSnapshot()
        #expect(afterLateCompletion.entries == 0)
        #expect(afterLateCompletion.activeLoads == 0)
        _ = try #require(await analyzer.analyze(packageName: "example", registry: .npm))
        #expect(await calls.total == 2)
        #expect(await analyzer.cacheSnapshot().entries == 1)
    }

    @Test("Failed, unreadable and cancelled loads can be retried without cached failure state")
    func failedLoadsAreNotCached() async throws {
        let clock = Clock(), calls = Calls()
        let analyzer = PackageMetadataAnalyzer(cacheTTL: 60, capacity: 2, now: { clock.now() }) { _ in
            switch await calls.record() {
            case 1: return nil
            case 2: return Data("unavailable".utf8)
            case 3:
                withUnsafeCurrentTask { $0?.cancel() }
                return Self.metadata
            default: return Self.metadata
            }
        }
        for _ in 0..<3 {
            #expect(await analyzer.analyze(packageName: "example", registry: .npm) == nil)
            #expect(await analyzer.cacheSnapshot().entries == 0)
        }
        _ = try #require(await analyzer.analyze(packageName: "example", registry: .npm))
        _ = try #require(await analyzer.analyze(packageName: "example", registry: .npm))
        #expect(await calls.total == 4)
        #expect(await analyzer.cacheSnapshot().entries == 1)
    }

    @Test("Attestation cache retains registry facts independently of each caller's comparison")
    func attestationComparisonAndRetention() async {
        let clock = Clock(), calls = Calls()
        let enricher = AttestationEnricher(cacheTTL: 60, capacity: 1, now: { clock.now() }) { _ in
            _ = await calls.record(); return Self.provenance
        }
        let matching = await enricher.verify(packageName: "example", version: "1.0.0", registry: .npm,
                                              priorBuilder: "https://example.org/builder")
        let changed = await enricher.verify(packageName: "example", version: "1.0.0", registry: .npm,
                                             priorBuilder: "https://example.org/previous-builder")
        let noComparison = await enricher.verify(packageName: "example", version: "1.0.0", registry: .npm)
        #expect(matching.status == .verified)
        #expect(changed.status == .mismatched)
        #expect(changed.priorBuilder == "https://example.org/previous-builder")
        #expect(noComparison.status == .verified)
        #expect(noComparison.priorBuilder == nil)
        #expect(noComparison.warnings.isEmpty)
        #expect(await calls.total == 1)
        _ = await enricher.verify(packageName: "example", version: "2.0.0", registry: .npm)
        _ = await enricher.verify(packageName: "example", version: "1.0.0", registry: .npm)
        #expect(await calls.total == 3)
        #expect(await enricher.cacheSnapshot().entries == 1)
        clock.advance(.seconds(60))
        #expect(await enricher.cacheSnapshot().entries == 0)
        _ = await enricher.verify(packageName: "example", version: "1.0.0", registry: .npm)
        #expect(await calls.total == 4)
    }

    @Test("An unreadable attestation response does not become a cached absence")
    func attestationFailureDoesNotPoisonAbsence() async {
        let clock = Clock(), calls = Calls()
        let enricher = AttestationEnricher(cacheTTL: 60, capacity: 1, now: { clock.now() }) { _ in
            let count = await calls.record()
            return count == 1 ? Data(#"{"status":"temporarily unavailable"}"#.utf8)
                              : Data(#"{"attestations":[]}"#.utf8)
        }
        let failed = await enricher.verify(packageName: "example", version: "1.0.0", registry: .npm)
        #expect(failed.status == .fetchFailed)
        #expect(await enricher.cacheSnapshot().entries == 0)
        let absent = await enricher.verify(packageName: "example", version: "1.0.0", registry: .npm)
        let cached = await enricher.verify(packageName: "example", version: "1.0.0", registry: .npm)
        #expect(absent.status == .absent)
        #expect(cached.status == .absent)
        #expect(await calls.total == 2)
        #expect(await enricher.cacheSnapshot().entries == 1)
    }
}
