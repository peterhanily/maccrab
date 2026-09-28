import Testing
import Foundation
import SwiftUI
import AppKit
import MacCrabForensics
@testable import MacCrabApp

@Suite("Review plugins and native follow-up")
struct ReviewPluginTests {
    @Test func sourceRolesRequireCompleteSelection() throws {
        let before = SecretTrailScope.Source(path: "old.app", kind: .previousApp)
        let current = SecretTrailScope.Source(path: "new.app", kind: .currentApp)
        try SecretTrailScope.validate([before], profile: .trustDelta, complete: false)
        #expect(throws: (any Error).self) { try SecretTrailScope.validate([before], profile: .trustDelta) }
        try SecretTrailScope.validate([before, current], profile: .trustDelta)
        #expect(throws: (any Error).self) { try SecretTrailScope.validate([before, current], profile: .firstHour) }
        try SecretTrailScope.validate([.init(path: "old.json", kind: .baseline), .init(path: "new.json", kind: .current)], profile: .firstHour)
    }
    @Test func nativeReviewRequiresMatchingIdentity() throws {
        let value = RaveSnapshot(domain: "incident", scope: ["fixture"], facts: [], gaps: [])
        let snapshot = try JSONDecoder().decode(JSONValue.self, from: RaveReviewEngine.encode(value))
        func artifact(_ plugin: String) -> CommittedArtifact {
            .init(id: 1, record: .init(caseID: "fixture", pluginID: plugin, pluginVersion: "0.1.0", schemaVersion: 1,
                contentType: "first_hour.review", sha256: "fixture", observedAt: Date(), privacyClass: .content,
                data: ["mode": .string("investigate"), "snapshot": snapshot]))
        }
        #expect(try NativeReview(artifact("com.maccrab.forensics.first-hour")).findings.count == 1)
        #expect(throws: (any Error).self) { try NativeReview(artifact("com.example.foreign")) }
    }
    @Test func privateExportRoundTripAndLinkRefusal() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).resolvingSymlinksInPath()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("review.json")
        let snapshot = RaveSnapshot(domain: "incident", scope: ["fixture"], facts: [], gaps: [])
        let bytes = try RaveReviewEngine.encode(snapshot)
        try ReviewFileIO.write(bytes, to: url)
        #expect(try RaveReviewEngine.decode(ReviewFileIO.read(url)) == snapshot)
        let attrs = try FileManager.default.attributesOfItem(atPath: url.path)
        #expect((attrs[.posixPermissions] as? NSNumber)?.intValue == 0o600)
        let link = dir.appendingPathComponent("link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: url)
        #expect(throws: (any Error).self) { try ReviewFileIO.read(link) }
        #expect(throws: (any Error).self) { try ReviewFileIO.write(bytes, to: link) }
    }
    @Test func unavailableCurrentEvidenceDoesNotMeanFixed() throws {
        let old = RaveSnapshot(domain: "incident", scope: ["fixture"], facts: [
            .init(kind: "persistence", path: "fixture.plist", code: "launch-configuration", value: "configured", reference: "record-1")], gaps: [])
        let current = RaveSnapshot(domain: "incident", scope: ["fixture"], facts: [], gaps: ["unreadable"])
        let rows = try RaveReviewEngine.compare(old, current)
        #expect(rows.first?.title == "Previous condition could not be reassessed")
    }
    @Test func encryptedBridgeRequiredForReviewResults() {
        let manifest = TierBManifest(id: "com.maccrab.forensics.first-hour", displayName: "First Hour",
            version: "0.1.0", schemaVersion: 1, description: "Fixture", privacyClass: "content")
        let dto = TierBArtifactDTO(contentType: "first_hour.review", privacyClass: "content")
        if case .rejected = TierBArtifactBridge.map(dto: dto, caseID: "fixture", manifest: manifest, caseAllowsSensitive: false) {} else {
            Issue.record("Sensitive review accepted in plaintext case")
        }
    }
    @Test(.enabled(if: ProcessInfo.processInfo.environment["RAVE_REVIEW_PREVIEW_DIR"] != nil))
    @MainActor func renderActualPackagedReports() throws {
        guard let directory = ProcessInfo.processInfo.environment["RAVE_REVIEW_PREVIEW_DIR"],
              let root = ProcessInfo.processInfo.environment["RAVE_REVIEW_SAMPLE_ROOT"] else { return }
        _ = NSApplication.shared
        for slug in ["trust-delta", "first-hour"] {
            let bytes = try Data(contentsOf: URL(fileURLWithPath: root).appendingPathComponent("plugins/\(slug)/samples/report.json"))
            let report = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
            let rows = try #require(report["artifacts"] as? [[String: Any]])
            let row = try #require(rows.first)
            let contentType = try #require(row["contentType"] as? String)
            let data = try JSONDecoder().decode([String: JSONValue].self, from: JSONSerialization.data(withJSONObject: row["data"]!))
            let artifact = CommittedArtifact(id: 1, record: .init(caseID: "fixture", pluginID: "com.maccrab.forensics." + slug,
                pluginVersion: report["pluginVersion"] as! String, schemaVersion: 1, contentType: contentType, sha256: "fixture",
                observedAt: Date(), privacyClass: .content, data: data))
            let view = ReviewFindingsView(artifacts: [artifact]).frame(width: 960, height: 680)
                .background(Color(nsColor: .windowBackgroundColor)).environment(\.colorScheme, .light)
            let hosting = NSHostingView(rootView: view)
            let window = NSWindow(contentRect: NSRect(x: -10000, y: -10000, width: 960, height: 680),
                styleMask: [.borderless], backing: .buffered, defer: false)
            window.isReleasedWhenClosed = false; window.contentView = hosting; window.orderFrontRegardless()
            hosting.layoutSubtreeIfNeeded()
            RunLoop.main.run(until: Date().addingTimeInterval(0.4)); window.displayIfNeeded()
            let bitmap = try #require(hosting.bitmapImageRepForCachingDisplay(in: hosting.bounds))
            hosting.cacheDisplay(in: hosting.bounds, to: bitmap)
            let png = try #require(bitmap.representation(using: .png, properties: [:]))
            try png.write(to: URL(fileURLWithPath: directory).appendingPathComponent(slug + "-native-0.2.png"))
            window.close()
        }
    }
}
