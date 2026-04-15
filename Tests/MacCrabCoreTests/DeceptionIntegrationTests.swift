// DeceptionIntegrationTests.swift
// End-to-end: deploy a honeyfile, construct a file event touching it,
// run through EventEnricher + RuleEngine, verify the critical
// honeyfile-accessed rule fires.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("Deception integration")
struct DeceptionIntegrationTests {

    private func sandboxHome() throws -> (home: String, manifest: String, cleanup: () -> Void) {
        let home = NSTemporaryDirectory() + "maccrab_decep_home_\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: home, withIntermediateDirectories: true)
        let manifest = home + "/honey_manifest.json"
        let cleanup: () -> Void = { try? FileManager.default.removeItem(atPath: home) }
        return (home, manifest, cleanup)
    }

    private func fileEvent(
        path: String,
        processName: String = "attacker",
        processPath: String = "/tmp/attacker"
    ) -> Event {
        let dir = (path as NSString).deletingLastPathComponent
        let name = (path as NSString).lastPathComponent
        let ext = (path as NSString).pathExtension
        let proc = MacCrabCore.ProcessInfo(
            pid: 999_001, ppid: 1, rpid: 1,
            name: processName, executable: processPath,
            commandLine: "\(processPath) \(path)",
            args: [processPath, path],
            workingDirectory: "/tmp",
            userId: 501, userName: "alice", groupId: 20,
            startTime: Date()
        )
        let file = FileInfo(
            path: path, name: name, directory: dir,
            extension_: ext.isEmpty ? nil : ext,
            size: 1024, action: .write
        )
        return Event(
            eventCategory: .file, eventType: .change,
            eventAction: "write", process: proc, file: file
        )
    }

    @Test("EventEnricher tags file events hitting a deployed honeyfile")
    func enricherTagsHoneyfile() async throws {
        let (home, manifest, cleanup) = try sandboxHome()
        defer { cleanup() }

        let mgr = HoneyfileManager(homeDir: home, manifestPath: manifest)
        let deployed = try await mgr.deploy()
        let canaryPath = try #require(deployed.first).path

        let enricher = EventEnricher(honeyfileManager: mgr)
        let event = fileEvent(path: canaryPath)
        let enriched = await enricher.enrich(event)

        #expect(enriched.enrichments["IsHoneyfile"] == "true")
        #expect(enriched.enrichments["HoneyfileType"] != nil)
    }

    @Test("EventEnricher does NOT tag benign file paths")
    func enricherIgnoresBenignPaths() async throws {
        let (home, manifest, cleanup) = try sandboxHome()
        defer { cleanup() }

        let mgr = HoneyfileManager(homeDir: home, manifestPath: manifest)
        _ = try await mgr.deploy()

        let enricher = EventEnricher(honeyfileManager: mgr)
        let event = fileEvent(path: home + "/regular/user/file.txt")
        let enriched = await enricher.enrich(event)

        #expect(enriched.enrichments["IsHoneyfile"] == nil)
    }

    @Test("honeyfile_accessed detection rule fires on canary read")
    func ruleFiresOnCanary() async throws {
        let (home, manifest, cleanup) = try sandboxHome()
        defer { cleanup() }

        let mgr = HoneyfileManager(homeDir: home, manifestPath: manifest)
        let deployed = try await mgr.deploy()
        let canaryPath = try #require(deployed.first).path

        ensureRulesCompiled()
        let engine = RuleEngine()
        _ = try await engine.loadRules(from: URL(fileURLWithPath: "/tmp/maccrab_v3"))

        let enricher = EventEnricher(honeyfileManager: mgr)
        let event = fileEvent(path: canaryPath)
        let enriched = await enricher.enrich(event)

        let matches = await engine.evaluate(enriched)
        #expect(matches.contains { $0.ruleName.lowercased().contains("honeyfile") },
                "Expected honeyfile_accessed to fire, got: \(matches.map(\.ruleName))")
    }

    @Test("Rule does NOT fire when MacCrab itself reads the honeyfile")
    func ruleFiltersMacCrabSelfReads() async throws {
        let (home, manifest, cleanup) = try sandboxHome()
        defer { cleanup() }

        let mgr = HoneyfileManager(homeDir: home, manifestPath: manifest)
        let deployed = try await mgr.deploy()
        let canaryPath = try #require(deployed.first).path

        ensureRulesCompiled()
        let engine = RuleEngine()
        _ = try await engine.loadRules(from: URL(fileURLWithPath: "/tmp/maccrab_v3"))

        let enricher = EventEnricher(honeyfileManager: mgr)
        let event = fileEvent(
            path: canaryPath,
            processName: "maccrabd",
            processPath: "/usr/local/bin/maccrabd"
        )
        let enriched = await enricher.enrich(event)

        let matches = await engine.evaluate(enriched)
        #expect(!matches.contains { $0.ruleName.lowercased().contains("honeyfile") },
                "honeyfile_accessed should be filtered for MacCrab self-reads, got: \(matches.map(\.ruleName))")
    }
}
