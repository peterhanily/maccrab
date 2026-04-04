// SuppressionTests.swift
// Tests for SuppressionManager and the end-to-end suppression pipeline.

import Testing
import Foundation
@testable import MacCrabCore

// MARK: - SuppressionManager Unit Tests

@Suite("Suppression Manager")
struct SuppressionManagerTests {

    /// Helper: create a temp directory with a suppressions.json file.
    private func makeTempDir(suppressions: [String: [String]] = [:]) throws -> String {
        let dir = NSTemporaryDirectory() + "maccrab_test_\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        if !suppressions.isEmpty {
            let data = try JSONEncoder().encode(suppressions)
            try data.write(to: URL(fileURLWithPath: dir + "/suppressions.json"))
        }
        return dir
    }

    private func cleanup(_ dir: String) {
        try? FileManager.default.removeItem(atPath: dir)
    }

    @Test("Loads empty when no file exists")
    func loadNoFile() async throws {
        let dir = try makeTempDir()
        defer { cleanup(dir) }

        let mgr = SuppressionManager(dataDir: dir)
        await mgr.load()

        let stats = await mgr.stats()
        #expect(stats.ruleCount == 0)
        #expect(stats.pathCount == 0)
    }

    @Test("Loads suppressions from JSON file")
    func loadFromFile() async throws {
        let dir = try makeTempDir(suppressions: [
            "rule-001": ["/usr/libexec/universalaccessd", "/usr/sbin/mDNSResponder"],
            "rule-002": ["/usr/libexec/configd"]
        ])
        defer { cleanup(dir) }

        let mgr = SuppressionManager(dataDir: dir)
        await mgr.load()

        let stats = await mgr.stats()
        #expect(stats.ruleCount == 2)
        #expect(stats.pathCount == 3)
    }

    @Test("isSuppressed returns true for matching rule + process")
    func suppressedMatch() async throws {
        let dir = try makeTempDir(suppressions: [
            "maccrab.deep.event-tap-keylogger": ["/usr/libexec/universalaccessd"]
        ])
        defer { cleanup(dir) }

        let mgr = SuppressionManager(dataDir: dir)
        await mgr.load()

        let result = await mgr.isSuppressed(
            ruleId: "maccrab.deep.event-tap-keylogger",
            processPath: "/usr/libexec/universalaccessd"
        )
        #expect(result == true)
    }

    @Test("isSuppressed returns false for non-matching rule")
    func notSuppressedDifferentRule() async throws {
        let dir = try makeTempDir(suppressions: [
            "maccrab.deep.event-tap-keylogger": ["/usr/libexec/universalaccessd"]
        ])
        defer { cleanup(dir) }

        let mgr = SuppressionManager(dataDir: dir)
        await mgr.load()

        let result = await mgr.isSuppressed(
            ruleId: "some-other-rule",
            processPath: "/usr/libexec/universalaccessd"
        )
        #expect(result == false)
    }

    @Test("isSuppressed returns false for non-matching process")
    func notSuppressedDifferentProcess() async throws {
        let dir = try makeTempDir(suppressions: [
            "maccrab.deep.event-tap-keylogger": ["/usr/libexec/universalaccessd"]
        ])
        defer { cleanup(dir) }

        let mgr = SuppressionManager(dataDir: dir)
        await mgr.load()

        let result = await mgr.isSuppressed(
            ruleId: "maccrab.deep.event-tap-keylogger",
            processPath: "/usr/bin/some-keylogger"
        )
        #expect(result == false)
    }

    @Test("isSuppressed returns false when no suppressions loaded")
    func notSuppressedEmpty() async throws {
        let dir = try makeTempDir()
        defer { cleanup(dir) }

        let mgr = SuppressionManager(dataDir: dir)
        await mgr.load()

        let result = await mgr.isSuppressed(
            ruleId: "any-rule",
            processPath: "/any/path"
        )
        #expect(result == false)
    }

    @Test("Reload picks up new suppressions")
    func reloadUpdates() async throws {
        let dir = try makeTempDir(suppressions: [
            "rule-001": ["/usr/bin/a"]
        ])
        defer { cleanup(dir) }

        let mgr = SuppressionManager(dataDir: dir)
        await mgr.load()

        var stats = await mgr.stats()
        #expect(stats.pathCount == 1)

        // Write updated file
        let newSuppressions: [String: [String]] = [
            "rule-001": ["/usr/bin/a", "/usr/bin/b"],
            "rule-002": ["/usr/bin/c"]
        ]
        let data = try JSONEncoder().encode(newSuppressions)
        try data.write(to: URL(fileURLWithPath: dir + "/suppressions.json"))

        // Reload
        await mgr.load()
        stats = await mgr.stats()
        #expect(stats.ruleCount == 2)
        #expect(stats.pathCount == 3)

        // Verify new suppression works
        let result = await mgr.isSuppressed(ruleId: "rule-002", processPath: "/usr/bin/c")
        #expect(result == true)
    }

    @Test("Handles malformed JSON gracefully")
    func malformedJSON() async throws {
        let dir = try makeTempDir()
        defer { cleanup(dir) }

        // Write invalid JSON
        try "not valid json {{{".write(
            to: URL(fileURLWithPath: dir + "/suppressions.json"),
            atomically: true,
            encoding: .utf8
        )

        let mgr = SuppressionManager(dataDir: dir)
        await mgr.load()

        let stats = await mgr.stats()
        #expect(stats.ruleCount == 0)
        #expect(stats.pathCount == 0)
    }

    @Test("Multiple paths per rule all suppress correctly")
    func multiplePathsPerRule() async throws {
        let dir = try makeTempDir(suppressions: [
            "rule-001": [
                "/usr/libexec/universalaccessd",
                "/usr/libexec/authd",
                "/usr/sbin/securityd"
            ]
        ])
        defer { cleanup(dir) }

        let mgr = SuppressionManager(dataDir: dir)
        await mgr.load()

        #expect(await mgr.isSuppressed(ruleId: "rule-001", processPath: "/usr/libexec/universalaccessd") == true)
        #expect(await mgr.isSuppressed(ruleId: "rule-001", processPath: "/usr/libexec/authd") == true)
        #expect(await mgr.isSuppressed(ruleId: "rule-001", processPath: "/usr/sbin/securityd") == true)
        #expect(await mgr.isSuppressed(ruleId: "rule-001", processPath: "/usr/bin/unknown") == false)
    }
}

// MARK: - Suppression + Deduplication Integration Tests

@Suite("Suppression Pipeline Integration")
struct SuppressionPipelineTests {

    @Test("Suppressed alert is not emitted even when deduplicator allows it")
    func suppressionBeforeDedup() async throws {
        let dir = NSTemporaryDirectory() + "maccrab_pipe_\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }

        // Setup: suppress universalaccessd for the event-tap-keylogger rule
        let suppressions: [String: [String]] = [
            "maccrab.deep.event-tap-keylogger": ["/usr/libexec/universalaccessd"]
        ]
        let data = try JSONEncoder().encode(suppressions)
        try data.write(to: URL(fileURLWithPath: dir + "/suppressions.json"))

        let suppressionMgr = SuppressionManager(dataDir: dir)
        await suppressionMgr.load()

        let deduplicator = AlertDeduplicator(suppressionWindow: 3600)

        // Simulate the daemon's alert pipeline: suppression check first, then dedup
        let ruleId = "maccrab.deep.event-tap-keylogger"
        let processPath = "/usr/libexec/universalaccessd"

        // Step 1: suppression check (should block)
        let suppressed = await suppressionMgr.isSuppressed(ruleId: ruleId, processPath: processPath)
        #expect(suppressed == true, "universalaccessd should be suppressed")

        // Step 2: if not suppressed, dedup would run — but we should never get here
        // Verify dedup would have allowed it (first occurrence)
        let wouldDedup = await deduplicator.shouldSuppress(ruleId: ruleId, processPath: processPath)
        #expect(wouldDedup == false, "Dedup would have allowed first occurrence")

        // This proves suppression catches it BEFORE dedup, so it never fires
    }

    @Test("Non-suppressed alert passes through both stages")
    func nonSuppressedPassesThrough() async throws {
        let dir = NSTemporaryDirectory() + "maccrab_pipe_\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }

        // No suppressions configured
        let suppressionMgr = SuppressionManager(dataDir: dir)
        await suppressionMgr.load()

        let deduplicator = AlertDeduplicator(suppressionWindow: 3600)

        let ruleId = "maccrab.deep.event-tap-keylogger"
        let processPath = "/usr/local/bin/evil-keylogger"

        // Step 1: not suppressed
        let suppressed = await suppressionMgr.isSuppressed(ruleId: ruleId, processPath: processPath)
        #expect(suppressed == false)

        // Step 2: not deduped (first time)
        let deduped = await deduplicator.shouldSuppress(ruleId: ruleId, processPath: processPath)
        #expect(deduped == false)

        // Record it
        await deduplicator.recordAlert(ruleId: ruleId, processPath: processPath)

        // Step 3: second occurrence IS deduped
        let deduped2 = await deduplicator.shouldSuppress(ruleId: ruleId, processPath: processPath)
        #expect(deduped2 == true, "Second occurrence should be deduped")
    }
}

// MARK: - EventTapMonitor Allowlist Tests

@Suite("Event Tap Monitor Allowlist")
struct EventTapAllowlistTests {

    @Test("isAllowlistedSystemProcess allows universalaccessd")
    func allowsUniversalAccessD() {
        // We can't call the private static method directly, but we can verify
        // the allowlist contents via the public behavior.
        // Since EventTapMonitor is an actor with private allowlists,
        // we test the behavior indirectly by verifying the known processes
        // are in the list at compile time.

        // These are the processes that MUST be in the allowlist
        // (regression test for the universalaccessd false positive)
        let requiredProcesses = [
            "universalaccessd",
            "WindowServer",
            "Dock",
            "SystemUIServer",
            "loginwindow",
            "SecurityAgent",
            "TextInputMenuAgent",
        ]

        // Read the source file and verify each process is listed
        // #filePath is Tests/MacCrabCoreTests/SuppressionTests.swift
        // Go up 3 levels to project root, then into Sources/
        let sourceFile = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()  // Tests/MacCrabCoreTests/
            .deletingLastPathComponent()  // Tests/
            .deletingLastPathComponent()  // project root
            .appendingPathComponent("Sources/MacCrabCore/Collectors/EventTapMonitor.swift")

        guard let source = try? String(contentsOf: sourceFile, encoding: .utf8) else {
            Issue.record("Could not read EventTapMonitor.swift source")
            return
        }

        for process in requiredProcesses {
            #expect(
                source.contains("\"\(process)\""),
                "EventTapMonitor allowlist must include \(process)"
            )
        }
    }

    @Test("Allowlist includes all required path prefixes")
    func allowlistPathPrefixes() {
        // #filePath is Tests/MacCrabCoreTests/SuppressionTests.swift
        // Go up 3 levels to project root, then into Sources/
        let sourceFile = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()  // Tests/MacCrabCoreTests/
            .deletingLastPathComponent()  // Tests/
            .deletingLastPathComponent()  // project root
            .appendingPathComponent("Sources/MacCrabCore/Collectors/EventTapMonitor.swift")

        guard let source = try? String(contentsOf: sourceFile, encoding: .utf8) else {
            Issue.record("Could not read EventTapMonitor.swift source")
            return
        }

        let requiredPrefixes = [
            "/System/",
            "/usr/libexec/",
            "/usr/sbin/",
        ]

        for prefix in requiredPrefixes {
            #expect(
                source.contains("\"\(prefix)\""),
                "EventTapMonitor path prefixes must include \(prefix)"
            )
        }
    }
}
