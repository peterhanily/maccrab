// MCPBehavioralBaselineTests.swift
//
// Coverage for the v1.6.6 MCP Behavioral Baseline service — learning
// window promotion, deviation emission, domain normalisation, and the
// reset path.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("MCPBaselineService: learning vs enforcing")
struct BaselineLearningEnforcingTests {

    @Test("Learning-mode observations never emit deviations")
    func learningNeverEmits() async {
        let svc = MCPBaselineService(learningObservations: 10, learningWindow: 1)
        let emitted1 = await svc.observe(.init(tool: "claude", serverName: "gh", filePath: "/tmp/a"))
        let emitted2 = await svc.observe(.init(tool: "claude", serverName: "gh", domain: "api.github.com"))
        #expect(emitted1.isEmpty)
        #expect(emitted2.isEmpty)
    }

    @Test("Promotion requires both observation count AND wall-clock window")
    func dualPromotionGate() async {
        // Set thresholds low to keep the test quick: 3 observations AND
        // at least 1 second of wall-clock elapsed between first and
        // last observation.
        let svc = MCPBaselineService(learningObservations: 3, learningWindow: 1.0)
        let t0 = Date()
        _ = await svc.observe(.init(
            tool: "claude", serverName: "gh",
            filePath: "/tmp/x", timestamp: t0
        ))
        _ = await svc.observe(.init(
            tool: "claude", serverName: "gh",
            filePath: "/tmp/y", timestamp: t0.addingTimeInterval(0.1)
        ))
        _ = await svc.observe(.init(
            tool: "claude", serverName: "gh",
            filePath: "/tmp/z", timestamp: t0.addingTimeInterval(0.2)
        ))
        // 3 obs in 200 ms — count met, wall-clock NOT met.
        let mid = await svc.baseline(for: "claude", serverName: "gh")
        #expect(mid?.state == .learning, "Must not promote before wall-clock window elapses")

        // Add one more obs past the 1-second window. Promotion should
        // now fire on this call.
        _ = await svc.observe(.init(
            tool: "claude", serverName: "gh",
            filePath: "/tmp/w", timestamp: t0.addingTimeInterval(1.1)
        ))
        let after = await svc.baseline(for: "claude", serverName: "gh")
        #expect(after?.state == .enforcing)
    }

    @Test("After promotion, a previously-unseen file basename emits a deviation")
    func enforcementEmitsDeviation() async {
        let svc = MCPBaselineService(learningObservations: 2, learningWindow: 0.1)
        let t0 = Date()
        _ = await svc.observe(.init(tool: "cursor", serverName: "notes", filePath: "/a/notes.md", timestamp: t0))
        _ = await svc.observe(.init(tool: "cursor", serverName: "notes", filePath: "/b/notes.md", timestamp: t0.addingTimeInterval(0.2)))
        // Both of those used the same basename "notes.md". Now send a
        // NEW basename — should emit.
        let emitted = await svc.observe(.init(
            tool: "cursor", serverName: "notes",
            filePath: "/malicious/steal-keychain",
            timestamp: t0.addingTimeInterval(1.0)
        ))
        #expect(emitted.count == 1)
        #expect(emitted.first?.kind == .newFileBasename)
        #expect(emitted.first?.observedValue == "steal-keychain")
    }

    @Test("Single observation can emit multiple deviations across fields")
    func multiFieldDeviation() async {
        let svc = MCPBaselineService(learningObservations: 1, learningWindow: 0)
        let t0 = Date()
        // Single baseline observation promotes to enforcing.
        _ = await svc.observe(.init(
            tool: "claude", serverName: "svc",
            filePath: "/existing/a", domain: "github.com",
            childProcessBasename: "git",
            timestamp: t0
        ))
        let emitted = await svc.observe(.init(
            tool: "claude", serverName: "svc",
            filePath: "/new/b", domain: "evil.ru",
            childProcessBasename: "curl",
            timestamp: t0.addingTimeInterval(1)
        ))
        let kinds = Set(emitted.map(\.kind))
        #expect(kinds == [.newFileBasename, .newDomain, .newChildBasename],
                "All three fields must emit their deviation on one observation")
    }
}

@Suite("MCPBaselineService: domain normalisation")
struct BaselineDomainNormalisationTests {

    @Test("Subdomains collapse to eTLD+1")
    func eTLDPlusOne() {
        #expect(MCPBaselineService.normalizeDomain("api.github.com") == "github.com")
        #expect(MCPBaselineService.normalizeDomain("www.example.com") == "example.com")
        #expect(MCPBaselineService.normalizeDomain("a.b.c.example.com") == "example.com")
    }

    @Test("Single-label and already-eTLD+1 inputs pass through")
    func passthrough() {
        #expect(MCPBaselineService.normalizeDomain("localhost") == "localhost")
        #expect(MCPBaselineService.normalizeDomain("github.com") == "github.com")
    }

    @Test("Leading/trailing dots and case are normalised")
    func cleansPunctuation() {
        #expect(MCPBaselineService.normalizeDomain(".API.GITHUB.COM.") == "github.com")
    }
}

@Suite("MCPBaselineService: DoS hardening (v1.6.9)")
struct BaselineDoSHardeningTests {

    @Test("Exceeding maxBaselines evicts the LRU entry, doesn't grow unbounded")
    func baselineCountCap() async {
        let svc = MCPBaselineService(
            learningObservations: 1, learningWindow: 0,
            maxBaselines: 3, maxSetSize: 64
        )
        let base = Date()
        // Insert 10 distinct servers. Cap is 3.
        for i in 0..<10 {
            _ = await svc.observe(.init(
                tool: "claude", serverName: "s\(i)",
                filePath: "/x", timestamp: base.addingTimeInterval(Double(i))
            ))
        }
        let all = await svc.allBaselines()
        #expect(all.count == 3,
                "maxBaselines=3 must be hard-enforced under rotating serverName input")
    }

    @Test("Oldest baseline evicted first (LRU by lastSeen)")
    func lruEvictionOrder() async {
        let svc = MCPBaselineService(
            learningObservations: 1, learningWindow: 0,
            maxBaselines: 2, maxSetSize: 64
        )
        let base = Date()
        _ = await svc.observe(.init(tool: "claude", serverName: "oldest", filePath: "/a", timestamp: base))
        _ = await svc.observe(.init(tool: "claude", serverName: "middle", filePath: "/b", timestamp: base.addingTimeInterval(10)))
        // At cap. Next should evict "oldest".
        _ = await svc.observe(.init(tool: "claude", serverName: "newest", filePath: "/c", timestamp: base.addingTimeInterval(20)))
        let all = await svc.allBaselines().map(\.serverName).sorted()
        #expect(all == ["middle", "newest"],
                "LRU eviction must drop the server with the oldest lastSeen")
    }

    @Test("Exceeding maxSetSize stops inserting but doesn't crash")
    func fingerprintSetCap() async {
        let svc = MCPBaselineService(
            learningObservations: 1, learningWindow: 0,
            maxBaselines: 10, maxSetSize: 5
        )
        let base = Date()
        // 20 distinct basenames for one server, cap at 5.
        for i in 0..<20 {
            _ = await svc.observe(.init(
                tool: "claude", serverName: "s1",
                filePath: "/dir/file\(i).txt",
                timestamp: base.addingTimeInterval(Double(i))
            ))
        }
        let b = await svc.baseline(for: "claude", serverName: "s1")!
        #expect(b.fileBasenames.count <= 5,
                "fileBasenames must not exceed maxSetSize (got \(b.fileBasenames.count))")
    }

    @Test("Cap enforcement applies separately to files, domains, child processes")
    func perFieldCaps() async {
        let svc = MCPBaselineService(
            learningObservations: 1, learningWindow: 0,
            maxBaselines: 10, maxSetSize: 3
        )
        // Cross 3-cap on all three fields for one server.
        for i in 0..<10 {
            _ = await svc.observe(.init(
                tool: "claude", serverName: "s1",
                filePath: "/f\(i).txt", domain: "d\(i).example.com",
                childProcessBasename: "c\(i)"
            ))
        }
        let b = await svc.baseline(for: "claude", serverName: "s1")!
        #expect(b.fileBasenames.count <= 3)
        #expect(b.domains.count <= 3)
        #expect(b.childBasenames.count <= 3)
    }
}

@Suite("MCPBaselineService: reset semantics")
struct BaselineResetTests {

    @Test("Reset clears fingerprint and returns baseline to learning")
    func resetClears() async {
        let svc = MCPBaselineService(learningObservations: 1, learningWindow: 0)
        _ = await svc.observe(.init(
            tool: "claude", serverName: "gh",
            filePath: "/a", domain: "github.com",
            childProcessBasename: "git"
        ))
        // Second observation emits (already in enforcing).
        _ = await svc.observe(.init(
            tool: "claude", serverName: "gh",
            filePath: "/new", timestamp: Date().addingTimeInterval(1)
        ))

        await svc.reset(tool: "claude", serverName: "gh")
        let cleared = await svc.baseline(for: "claude", serverName: "gh")
        #expect(cleared?.state == .learning)
        #expect(cleared?.fileBasenames.isEmpty == true)
        #expect(cleared?.domains.isEmpty == true)
        #expect(cleared?.childBasenames.isEmpty == true)
    }

    @Test("resetAll wipes every baseline")
    func resetAllWipesEverything() async {
        let svc = MCPBaselineService(learningObservations: 1, learningWindow: 0)
        _ = await svc.observe(.init(tool: "claude", serverName: "a", filePath: "/x"))
        _ = await svc.observe(.init(tool: "cursor", serverName: "b", filePath: "/y"))
        await svc.resetAll()
        #expect(await svc.allBaselines().isEmpty)
    }
}
