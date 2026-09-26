import Testing
import Foundation
import SwiftUI
import AppKit
import MacCrabForensics
@testable import MacCrabApp

@Suite("Inspection plugin source selection and native findings")
struct InspectionPluginTests {
    @Test func sourceProfilesStayIsolatedAndRejectWrongKinds() throws {
        try SecretTrailTests().withHome { home in
            let repo = [SecretTrailScope.Source(path: "project", kind: .project)]
            let script = [SecretTrailScope.Source(path: "sample.sh", kind: .script)]
            try SecretTrailScope.save(repo, home: home, profile: .repoTripwire)
            try SecretTrailScope.save(script, home: home, profile: .scriptTrace)
            #expect(try SecretTrailScope.load(home: home, profile: .secretTrail).isEmpty)
            #expect(try SecretTrailScope.load(home: home, profile: .repoTripwire) == repo)
            #expect(try SecretTrailScope.load(home: home, profile: .scriptTrace) == script)
            #expect(throws: (any Error).self) { try SecretTrailScope.save(script, home: home, profile: .secretTrail) }
            #expect(throws: (any Error).self) { try SecretTrailScope.save(repo, home: home, profile: .scriptTrace) }
            #expect(throws: (any Error).self) { try SecretTrailScope.save(script, home: home, profile: .repoTripwire) }
        }
    }
    @Test func profilesEnforceFileOrDirectorySelection() throws {
        try SecretTrailTests().withHome { home in
            let file = home.appendingPathComponent("sample.sh"), folder = home.appendingPathComponent("project")
            try Data("echo fixture".utf8).write(to: file)
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
            #expect(try SecretTrailScope.relativeSelection(file, home: home, profile: .scriptTrace) == "sample.sh")
            #expect(try SecretTrailScope.relativeSelection(folder, home: home, profile: .repoTripwire) == "project")
            #expect(throws: (any Error).self) { try SecretTrailScope.relativeSelection(folder, home: home, profile: .scriptTrace) }
            #expect(throws: (any Error).self) { try SecretTrailScope.relativeSelection(file, home: home, profile: .repoTripwire) }
        }
    }
    func artifact(id: Int64 = 1, profile: SecretTrailScope.Profile = .scriptTrace,
                  code: String = "keychain-access", attention: Bool = true) -> CommittedArtifact {
        .init(id: id, record: .init(caseID: "fixture", pluginID: profile.pluginID, pluginVersion: "0.1.0", schemaVersion: 1,
            contentType: profile == .repoTripwire ? "repo_tripwire.finding" : "script_trace.finding",
            sha256: "fixture", observedAt: Date(), privacyClass: .content, data: [
                "code": .string(code), "title": .string(code == "coverage-gap" ? "Review incomplete" : "Targets Keychain data"),
                "explanation": .string(code == "coverage-gap" ? "Effective tool policy and external commands remain uninspected." :
                    "The command structure invokes a Keychain lookup operation. Returned data and access permission are unknown."),
                "action": .string("Confirm why this workflow requests credential access before trusting it."),
                "trigger": .string(profile == .repoTripwire ? "npm lifecycle: postinstall → referenced shell file" : "Selected script"),
                "path": .string("sample-project/scripts/setup.sh"), "line": .integer(2),
                "lineLabel": .string("Nested text line"), "trace": .array([.string("Base64 → shell at line 4")]),
                "attention": .bool(attention)]))
    }
    @Test func findingsPreserveTraceAndHandoff() throws {
        let finding = try #require(InspectionFinding(artifact()))
        #expect(finding.trace == ["Base64 → shell at line 4"])
        #expect(finding.handoff.contains("Nested text line 2"))
        #expect(finding.handoff.contains("execution and compromise are not established"))
    }
    @Test func foreignOrMalformedRowsCannotGetNativePresentation() {
        let malformed = CommittedArtifact(id: 1, record: .init(caseID: "fixture", pluginID: "com.example.other",
            pluginVersion: "0.1.0", schemaVersion: 1, contentType: "script_trace.finding", sha256: "fixture",
            observedAt: Date(), privacyClass: .content, data: [:]))
        #expect(InspectionFinding(malformed) == nil)
        #expect(!InspectionFinding.accepts(contentType: "script_trace.finding", artifacts: [artifact(), malformed]))
        #expect(!InspectionFinding.accepts(contentType: "repo_tripwire.finding", artifacts: [artifact()]))
    }
    @Test func findingsRequireEncryptedCaseAtRealBridge() {
        for profile in [SecretTrailScope.Profile.repoTripwire, .scriptTrace] {
            let manifest = TierBManifest(id: profile.pluginID, displayName: profile.title, version: "0.1.0",
                                         schemaVersion: 1, description: "Fixture", privacyClass: "content")
            let dto = TierBArtifactDTO(contentType: "fixture", privacyClass: "content")
            if case .rejected = TierBArtifactBridge.map(dto: dto, caseID: "fixture", manifest: manifest, caseAllowsSensitive: false) {} else {
                Issue.record("Content row accepted in plaintext case")
            }
            if case .record = TierBArtifactBridge.map(dto: dto, caseID: "fixture", manifest: manifest, caseAllowsSensitive: true) {} else {
                Issue.record("Content row rejected in encrypted case")
            }
        }
    }
    @Test(.enabled(if: ProcessInfo.processInfo.environment["RAVE_INSPECTION_PREVIEW_DIR"] != nil))
    @MainActor func renderNativeFindings() throws {
        guard let directory = ProcessInfo.processInfo.environment["RAVE_INSPECTION_PREVIEW_DIR"] else { return }
        _ = NSApplication.shared
        for profile in [SecretTrailScope.Profile.repoTripwire, .scriptTrace] {
            let rows = [artifact(profile: profile), artifact(id: 2, profile: profile, code: "coverage-gap", attention: false)]
            let view = InspectionFindingsView(artifacts: rows).frame(width: 820, height: 560)
                .background(Color(nsColor: .windowBackgroundColor)).environment(\.colorScheme, .light)
            let hosting = NSHostingView(rootView: view)
            let window = NSWindow(contentRect: NSRect(x: -10000, y: -10000, width: 820, height: 560),
                                  styleMask: [.borderless], backing: .buffered, defer: false)
            window.isReleasedWhenClosed = false; window.contentView = hosting
            window.orderFrontRegardless()
            hosting.layoutSubtreeIfNeeded()
            RunLoop.main.run(until: Date().addingTimeInterval(0.2)); window.displayIfNeeded()
            let bitmap = try #require(hosting.bitmapImageRepForCachingDisplay(in: hosting.bounds))
            hosting.cacheDisplay(in: hosting.bounds, to: bitmap)
            let png = try #require(bitmap.representation(using: .png, properties: [:]))
            try png.write(to: URL(fileURLWithPath: directory).appendingPathComponent(profile.rawValue + ".png"))
            window.close()
        }
    }
}
