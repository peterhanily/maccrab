// ResidualRuntimeOwnershipTests.swift
// Regression coverage for background work that used to outlive its owner.

import Foundation
import Testing
@testable import MacCrabCore

@Suite("Residual runtime ownership")
struct ResidualRuntimeOwnershipTests {
    @Test("SelfDefense terminal stop seals even before deferred start")
    func selfDefenseCannotResurrectAfterStop() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-self-defense-\(UUID().uuidString)")
        let rules = root.appendingPathComponent("compiled_rules")
        try FileManager.default.createDirectory(
            at: rules,
            withIntermediateDirectories: true
        )
        try Data(#"{"rules":[]}"#.utf8).write(
            to: rules.appendingPathComponent("test.json")
        )
        defer { try? FileManager.default.removeItem(at: root) }

        let defense = SelfDefense(dataDir: root.path, rulesDir: rules.path)
        #expect(await defense.stop(deadline: 2.0))
        #expect(await defense.start { _ in } == false)
    }

    @Test("Threat intel terminal stop refuses late startup resurrection")
    func threatIntelCannotRestartAfterTerminalStop() async {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-ti-lifecycle-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }

        let feed = ThreatIntelFeed(cacheDir: root.path)
        #expect(await feed.start(networkRefresh: false))
        #expect(await feed.stop(deadline: 1.0))
        #expect(await feed.start(networkRefresh: false) == false)
        #expect(await feed.setNetworkRefresh(true) == false)
        #expect(await feed.networkFetchAttempts == 0)
        let lateImport = await feed.addCustomIOCs(
            domains: ["post-stop.example"]
        )
        #expect(lateImport.accepted == 0)
        #expect(await feed.isDomainMalicious("post-stop.example") == false)
    }

    @Test("Certificate Transparency discards all queries after shutdown")
    func certificateTransparencyClosesMutationAdmission() async {
        let monitor = CertTransparency()
        await monitor.shutdown()
        let result = await monitor.checkDomain("late-result.example")
        #expect(result == nil)
        #expect(await monitor.getFindings().isEmpty)
    }

    @Test("Baseline auto-save is one-shot and bounded-joinable")
    func baselineAutoSaveCannotRestartAfterStop() async {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-baseline-lifecycle-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }

        let engine = BaselineEngine(
            persistPath: root.appendingPathComponent("baseline.json").path
        )
        #expect(await engine.startAutoSave())
        #expect(await engine.stopAutoSaveAndJoin(deadline: 1.0))
        #expect(await engine.startAutoSave() == false)
    }

    @Test("Known callback/init fire-and-forget patterns stay removed")
    func sourceOwnershipGuards() throws {
        let testFile = URL(fileURLWithPath: #filePath)
        let repoRoot = testFile
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let selfDefense = try String(
            contentsOf: repoRoot.appendingPathComponent(
                "Sources/MacCrabCore/Detection/SelfDefense.swift"
            ),
            encoding: .utf8
        )
        let ueba = try String(
            contentsOf: repoRoot.appendingPathComponent(
                "Sources/MacCrabCore/Detection/UEBAEngine.swift"
            ),
            encoding: .utf8
        )

        #expect(!selfDefense.contains("Task { await self.handleTamperEvent"))
        #expect(!selfDefense.contains("Task { await handleTamperEvent"))
        #expect(!selfDefense.contains("Task { await self.handleSelfUpdateDelete"))
        #expect(selfDefense.contains("periodicTask = Task"))
        #expect(selfDefense.contains("callbackTasks.sealAndCancel()"))
        #expect(!ueba.contains("Task { await self.load"))
    }
}
