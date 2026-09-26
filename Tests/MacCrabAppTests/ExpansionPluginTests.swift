import Testing
import Foundation
import SwiftUI
import AppKit
import MacCrabForensics
@testable import MacCrabApp

@Suite("Ten Rave expansion plugins")
struct ExpansionPluginTests {
    @Test func allProfilesPersistCompatibleSelection() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).resolvingSymlinksInPath()
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        for slug in ExpansionFinding.slugs {
            let profile = try #require(SecretTrailScope.Profile(pluginID: "com.maccrab.forensics." + slug))
            #expect(profile.folder == "Rave/" + slug)
            let sources = [SecretTrailScope.Source(path: "evidence/example", kind: profile.kinds[0])]
            try SecretTrailScope.save(sources, home: root, profile: profile)
            #expect(try SecretTrailScope.load(home: root, profile: profile) == sources)
            #expect(throws: (any Error).self) { try SecretTrailScope.validate([.init(path: "../outside", kind: profile.kinds[0])], profile: profile) }
        }
    }
    @Test func rendererRejectsForeignIdentityAndMalformedRows() {
        func row(_ plugin: String, version: String = "0.1.0", detail: JSONValue = .string("Declared setting only.")) -> CommittedArtifact {
            .init(id: 1, record: .init(caseID: "fixture", pluginID: plugin, pluginVersion: version, schemaVersion: 1,
                contentType: "remote_hands.finding", sha256: "fixture", observedAt: Date(), privacyClass: .content,
                data: ["title": .string("Remote access configuration"), "detail": detail, "statementType": .string("declared")]))
        }
        #expect(ExpansionFinding(row("com.maccrab.forensics.remote-hands"))?.statement == "declared")
        #expect(ExpansionFinding(row("com.example.foreign")) == nil)
        #expect(ExpansionFinding(row("com.maccrab.forensics.remote-hands", version: "9.0.0")) == nil)
        #expect(ExpansionFinding(row("com.maccrab.forensics.remote-hands", detail: .integer(7))) == nil)
    }
    @Test(.enabled(if: ProcessInfo.processInfo.environment["RAVE_TEN_ROOT"] != nil))
    @MainActor func samplesPassNativeBridgeAndRender() throws {
        guard let root = ProcessInfo.processInfo.environment["RAVE_TEN_ROOT"] else { return }
        let preview = ProcessInfo.processInfo.environment["RAVE_TEN_PREVIEW_DIR"]
        if preview != nil { _ = NSApplication.shared }
        for slug in ExpansionFinding.slugs {
            let package = URL(fileURLWithPath: root).appendingPathComponent("plugins/" + slug)
            let manifest = try JSONDecoder().decode(TierBManifest.self, from: Data(contentsOf: package.appendingPathComponent("manifest.draft.json")))
            let report = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: package.appendingPathComponent("samples/report.json"))) as? [String: Any])
            let rows = try #require(report["artifacts"] as? [[String: Any]])
            var committed: [CommittedArtifact] = []
            for (index, row) in rows.enumerated() {
                let dto = try JSONDecoder().decode(TierBArtifactDTO.self, from: JSONSerialization.data(withJSONObject: row))
                #expect(["observed", "derived", "heuristic"].contains(dto.confidence ?? "observed"))
                if dto.privacyClass != "metadata" {
                    if case .rejected = TierBArtifactBridge.map(dto: dto, caseID: "fixture", manifest: manifest, caseAllowsSensitive: false) {} else { Issue.record("Sensitive output accepted in plaintext") }
                }
                guard case .record(let record) = TierBArtifactBridge.map(dto: dto, caseID: "fixture", manifest: manifest, caseAllowsSensitive: true) else { Issue.record("Valid sample refused"); continue }
                let artifact = CommittedArtifact(id: Int64(index+1), record: record)
                if dto.contentType.hasSuffix(".finding") || dto.contentType.hasSuffix(".summary") {
                    #expect(ExpansionFinding(artifact) != nil)
                    if dto.contentType.hasSuffix(".finding") { committed.append(artifact) }
                }
            }
            #expect(!committed.isEmpty, "Each demonstration must exercise a real finding")
            if let preview, !committed.isEmpty {
                let view = ExpansionFindingsView(artifacts: committed).frame(width: 1000, height: 700)
                    .background(Color(nsColor: .windowBackgroundColor)).environment(\.colorScheme, .light)
                let hosting = NSHostingView(rootView: view)
                let window = NSWindow(contentRect: NSRect(x: -10000, y: -10000, width: 1000, height: 700), styleMask: [.borderless], backing: .buffered, defer: false)
                window.isReleasedWhenClosed = false; window.contentView = hosting; window.orderFrontRegardless()
                hosting.layoutSubtreeIfNeeded(); RunLoop.main.run(until: Date().addingTimeInterval(0.15)); window.displayIfNeeded()
                let bitmap = try #require(hosting.bitmapImageRepForCachingDisplay(in: hosting.bounds))
                hosting.cacheDisplay(in: hosting.bounds, to: bitmap)
                let png = try #require(bitmap.representation(using: .png, properties: [:]))
                try png.write(to: URL(fileURLWithPath: preview).appendingPathComponent(slug + "-native-0.1.png"))
                window.close()
            }
        }
    }

    @Test func summaryOnlyRunKeepsScopeAndLimitationsVisible() throws {
        let artifact = CommittedArtifact(id: 1, record: .init(caseID: "fixture", pluginID: "com.maccrab.forensics.skill-check",
            pluginVersion: "0.1.0", schemaVersion: 1, contentType: "skill_check.summary", sha256: "fixture",
            observedAt: Date(), summary: "Instruction review completed within declared coverage", privacyClass: .content,
            data: ["filesAttempted": .integer(2), "findingCount": .integer(0), "limitation": .string("English lexical review only. No safety verdict.")]))
        let finding = try #require(ExpansionFinding(artifact))
        #expect(finding.title == "Instruction review completed within declared coverage")
        #expect(finding.detail.contains("No safety verdict"))
        #expect(finding.evidence.contains("filesAttempted"))
        #expect(finding.evidence.contains("findingCount"))
    }
}
