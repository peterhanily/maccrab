// NotarizationCheckerTests.swift
// Unit tests for the fork-free cache accessor used on the hot enrichment path.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("Notarization Checker")
struct NotarizationCheckerTests {

    @Test("cachedResult resolves system-prefix binaries inline without spctl")
    func systemPrefixResolvedInline() async {
        let checker = NotarizationChecker()
        // /usr/bin is a system prefix — must resolve synchronously, fork-free,
        // even though nothing has been checked yet (cold cache).
        let result = await checker.cachedResult(binaryPath: "/usr/bin/true")
        #expect(result != nil)
        #expect(result?.status == .notarized)
        #expect(result?.source == "Apple")
        // Pure read: must not have populated the real hit/miss counters.
        let stats = await checker.stats()
        #expect(stats.hits == 0)
        #expect(stats.misses == 0)
    }

    @Test("cachedResult returns nil for an unknown non-system binary (no fork)")
    func unknownReturnsNil() async {
        let checker = NotarizationChecker()
        let path = "/private/tmp/maccrab_notar_\(UUID().uuidString)"
        let result = await checker.cachedResult(binaryPath: path)
        #expect(result == nil)
        // Cold-miss read leaves stats untouched (no spctl, no cache write).
        let stats = await checker.stats()
        #expect(stats.cacheSize == 0)
        #expect(stats.misses == 0)
    }

    @Test("cachedResult serves a warm cache entry written by check()")
    func warmCacheServedAfterCheck() async {
        let checker = NotarizationChecker()
        // A system-prefix path is cached by check() without forking spctl.
        _ = await checker.check(binaryPath: "/bin/ls")
        let cached = await checker.cachedResult(binaryPath: "/bin/ls")
        #expect(cached != nil)
        #expect(cached?.status == .notarized)
    }

    @Test("spctl concurrency limiter never admits more than maxConcurrent at once")
    func concurrencyLimiterRespectsCap() async {
        let checker = NotarizationChecker()

        // Test-side gauge that measures how many tasks are simultaneously PAST
        // acquireSlot (i.e. actually holding a slot). Measured externally, so it
        // catches over-admission regardless of how the limiter counts internally.
        actor Gauge {
            private(set) var current = 0
            private(set) var peak = 0
            func enter() { current += 1; if current > peak { peak = current } }
            func leave() { current -= 1 }
        }
        let gauge = Gauge()

        // Far more concurrent acquire/release cycles than the cap of 5, with
        // yields at the actor's suspension points to maximise the interleaving
        // that a broken hand-off would need to over-admit.
        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<40 {
                group.addTask {
                    await checker.acquireSlotForTesting()
                    await gauge.enter()
                    for _ in 0..<3 { await Task.yield() }
                    await gauge.leave()
                    await checker.releaseSlotForTesting()
                }
            }
        }

        let peak = await gauge.peak
        #expect(peak <= 5, "concurrency limiter admitted \(peak) concurrent holders; cap is 5")
        // Every slot handed back exactly once — no leak, no underflow.
        let residual = await checker.inFlightForTesting
        #expect(residual == 0, "in-flight count should settle at 0; got \(residual)")
    }
}
