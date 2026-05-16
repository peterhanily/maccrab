// V112QualityAuditCoverageTests.swift
// v1.12.0 — coverage tests added in response to the quality audit
// findings. Each test corresponds to a specific gap the audit
// identified; the suite is the durable record that the gap is closed.

import Foundation
import Testing
@testable import MacCrabCore

// MARK: - BayesianIntentEngine LRU eviction

@Suite("v1.12.0 audit: BayesianIntentEngine LRU eviction")
struct BayesianIntentEngineLRUTests {

    @Test("Tree count never exceeds maxTrees after sustained writes")
    func evictionRespectsMaxTrees() async {
        let engine = BayesianIntentEngine(maxTrees: 8)
        // Insert 32 distinct trees; engine should cap at 8.
        for i in 0..<32 {
            _ = await engine.observe(.credentialRead, treeKey: "tree-\(i)")
        }
        let count = await engine.trackedTreeCount()
        #expect(count <= 8)
        #expect(count > 0)
    }

    @Test("Eviction picks the least-recently-updated tree, not random")
    func evictionIsLeastRecentlyUpdated() async {
        let engine = BayesianIntentEngine(maxTrees: 3)
        // Insert 3 trees with detectable time-spacing.
        _ = await engine.observe(.credentialRead, treeKey: "old")
        try? await Task.sleep(nanoseconds: 5_000_000)  // 5ms
        _ = await engine.observe(.credentialRead, treeKey: "mid")
        try? await Task.sleep(nanoseconds: 5_000_000)
        _ = await engine.observe(.credentialRead, treeKey: "newest")
        // Now insert a 4th — capacity 3 should evict "old".
        _ = await engine.observe(.credentialRead, treeKey: "fourth")
        let oldPosterior = await engine.posterior(treeKey: "old")
        let newestPosterior = await engine.posterior(treeKey: "newest")
        let fourthPosterior = await engine.posterior(treeKey: "fourth")
        #expect(oldPosterior == nil, "Oldest tree should have been evicted")
        #expect(newestPosterior != nil)
        #expect(fourthPosterior != nil)
    }
}

// MARK: - PackageMetadataAnalyzer cacheTTL expiry

@Suite("v1.12.0 audit: PackageMetadataAnalyzer cacheTTL")
struct PackageMetadataAnalyzerCacheTests {

    @Test("Within cacheTTL, the analyzer reuses the cached fetch")
    func cacheHitWithinTTL() async {
        actor FetchCounter { var count = 0; func bump() { count += 1 } }
        let counter = FetchCounter()
        let fetcher: PackageMetadataAnalyzer.Fetcher = { _ in
            await counter.bump()
            return "{\"versions\":{}}".data(using: .utf8)
        }
        let analyzer = PackageMetadataAnalyzer(cacheTTL: 3600, fetcher: fetcher)
        _ = await analyzer.analyze(packageName: "react", registry: .npm)
        _ = await analyzer.analyze(packageName: "react", registry: .npm)
        _ = await analyzer.analyze(packageName: "react", registry: .npm)
        let count = await counter.count
        #expect(count == 1, "Expected 1 fetch within TTL but saw \(count)")
    }

    @Test("Past cacheTTL, the analyzer refetches")
    func cacheMissAfterTTL() async {
        actor FetchCounter { var count = 0; func bump() { count += 1 } }
        let counter = FetchCounter()
        let fetcher: PackageMetadataAnalyzer.Fetcher = { _ in
            await counter.bump()
            return "{\"versions\":{}}".data(using: .utf8)
        }
        // 0.1s TTL so we can blow past it quickly.
        let analyzer = PackageMetadataAnalyzer(cacheTTL: 0.1, fetcher: fetcher)
        _ = await analyzer.analyze(packageName: "react", registry: .npm)
        try? await Task.sleep(nanoseconds: 200_000_000)  // 200ms
        _ = await analyzer.analyze(packageName: "react", registry: .npm)
        let count = await counter.count
        #expect(count == 2, "Expected 2 fetches after TTL expiry but saw \(count)")
    }
}

// MARK: - HoneyPromptManager clobber refusal + tamper detection

@Suite("v1.12.0 audit: HoneyPromptManager safety invariants")
struct HoneyPromptManagerSafetyTests {

    private func makeManager() -> (HoneyPromptManager, String) {
        let dir = NSTemporaryDirectory() + "maccrab-hpm-clobber-\(UUID().uuidString)"
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        return (HoneyPromptManager(homeDir: dir, manifestPath: dir + "/honeyprompts.json"), dir)
    }

    @Test("Deploy refuses to clobber an existing user file at a bait path")
    func deployRefusesClobber() async throws {
        let (mgr, dir) = makeManager()
        defer { try? FileManager.default.removeItem(atPath: dir) }

        // Pre-create a real file at one of the default decoy paths.
        let decoyDir = dir + "/Library/Application Support/MacCrab/decoys"
        try? FileManager.default.createDirectory(atPath: decoyDir, withIntermediateDirectories: true)
        let realFile = decoyDir + "/CLAUDE.md.canary"
        let realContent = "user's real instructions, do not clobber"
        try realContent.write(toFile: realFile, atomically: true, encoding: .utf8)

        // Deploy MUST throw — the manager is designed to fail loud
        // rather than partially-deploy or silently skip. The throw is
        // the load-bearing safety contract: a partial deploy would
        // create a confusing half-state for the operator.
        do {
            _ = try await mgr.deploy()
            Issue.record("Deploy should have thrown pathExistsWithRealContent but returned successfully")
        } catch let error as HoneyPromptManager.HoneyPromptError {
            switch error {
            case .pathExistsWithRealContent(let path):
                #expect(path == realFile, "Throw should reference the clobber-target path")
            case .writeFailed:
                Issue.record("Expected pathExistsWithRealContent, got writeFailed")
            }
        }
        // Real file content unchanged (the throw must not clobber).
        let stillReal = try String(contentsOfFile: realFile, encoding: .utf8)
        #expect(stillReal == realContent)
    }

    @Test("Status detects tampered honey-prompts after content change")
    func statusDetectsTamper() async throws {
        let (mgr, dir) = makeManager()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let deployed = try await mgr.deploy()
        guard let first = deployed.first else {
            Issue.record("Deploy returned 0 honey-prompts — manager fixture broken")
            return
        }
        // Tamper with the file content.
        try "tampered content from attacker".write(toFile: first.path, atomically: true, encoding: .utf8)
        let status = await mgr.status()
        let tamperedPaths = Set(status.tampered.map { $0.path })
        #expect(tamperedPaths.contains(first.path), "Tampered path must appear in status.tampered")
    }
}

// MARK: - Stylometric negative test

@Suite("v1.12.0 audit: Stylometric false-positive guard")
struct StylometricNegativeTests {

    @Test("Plain technical commit message does NOT score high on llmTextScore")
    func plainTechnicalLow() {
        let s = StylometricFingerprinter()
        let plain = "Fix race condition in EventLoop where the alertSink could be torn down before in-flight matches submitted. Adds a guard around the actor call site and unit test covering the closed-actor case."
        let score = s.llmTextScore(plain)
        // Plain technical commit message: no em-dashes, no hedge
        // phrases, normal sentence-length variance. Must score < 30 —
        // anything higher would mean the LLM detector flags ordinary
        // engineer prose, which is exactly the FP class the audit
        // flagged.
        #expect(score < 30, "Plain technical text scored \(score) on llmTextScore — false-positive class")
    }

    @Test("Plain technical commit does NOT trigger urgency lexicon")
    func plainTechnicalUrgencyLow() {
        let s = StylometricFingerprinter()
        let plain = "Refactor the event enricher to use a single mutex around the cache. Adds tests for the read/write contention path."
        let result = s.urgencyScore(plain)
        #expect(result.score < 20, "Plain technical text scored \(result.score) on urgencyScore — false-positive class")
        #expect(result.matchedTerms.isEmpty)
    }
}
