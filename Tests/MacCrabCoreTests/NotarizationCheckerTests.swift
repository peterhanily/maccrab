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
}
