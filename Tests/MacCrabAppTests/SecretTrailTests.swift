import Testing
import Foundation
import Darwin
import SwiftUI
import AppKit
import MacCrabForensics
@testable import MacCrabApp

@Suite("Secret Trail source selection and native findings")
struct SecretTrailTests {
    func withHome(_ body: (URL) throws -> Void) throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("secret-trail-host-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: home) }
        try body(home)
    }
    @Test func selectionRoundTripAndPrivatePermissions() throws {
        try withHome { home in
            #expect(try SecretTrailScope.load(home: home).isEmpty)
            let sources = [SecretTrailScope.Source(path: "project", kind: .project), .init(path: "saved/session.jsonl", kind: .aiSession)]
            try SecretTrailScope.save(sources, home: home)
            #expect(try SecretTrailScope.load(home: home) == sources)
            let file = home.appendingPathComponent("Library/Application Support/MacCrab/SecretTrail/scope.json")
            let mode = try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? NSNumber
            #expect(mode?.intValue == 0o600)
            try SecretTrailScope.save([sources[0]], home: home)
            #expect(try SecretTrailScope.load(home: home).count == 1)
        }
    }
    @Test func refusesOutOfHomeAndSymlinkSelection() throws {
        try withHome { home in
            let file = home.appendingPathComponent("file")
            try Data("fixture".utf8).write(to: file)
            #expect(try SecretTrailScope.relativeSelection(file, home: home) == "file")
            #expect(throws: (any Error).self) { try SecretTrailScope.relativeSelection(home, home: home) }
            #expect(throws: (any Error).self) { try SecretTrailScope.relativeSelection(URL(fileURLWithPath: "/etc/hosts"), home: home) }
            let link = home.appendingPathComponent("link")
            try FileManager.default.createSymbolicLink(at: link, withDestinationURL: file)
            #expect(throws: (any Error).self) { try SecretTrailScope.relativeSelection(link, home: home) }
        }
    }
    @Test func symlinkedSettingsDirectoryCannotRedirectWrite() throws {
        try withHome { home in
            let outside = home.appendingPathComponent("outside")
            try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
            try FileManager.default.createSymbolicLink(at: home.appendingPathComponent("Library"), withDestinationURL: outside)
            #expect(throws: (any Error).self) { try SecretTrailScope.save([.init(path: "file", kind: .log)], home: home) }
            #expect(try FileManager.default.contentsOfDirectory(atPath: outside.path).isEmpty)
        }
    }
    @Test func rejectsAmbiguousScopeAndKeepsExistingSelectionOnFailure() throws {
        try withHome { home in
            let sources = [SecretTrailScope.Source(path: "file", kind: .project)]
            try SecretTrailScope.save(sources, home: home)
            #expect(throws: (any Error).self) { try SecretTrailScope.save([.init(path: "../escape", kind: .log)], home: home) }
            #expect(try SecretTrailScope.load(home: home) == sources)
            #expect(throws: (any Error).self) { try SecretTrailScope.decode(Data(#"{"schemaVersion":1,"sources":[{"path":"file","kind":"log","extra":true}]}"#.utf8)) }
            #expect(throws: (any Error).self) { try SecretTrailScope.save(sources + sources, home: home) }
        }
    }
    func artifact(_ data: [String: JSONValue], plugin: String = SecretTrailScope.pluginID) -> CommittedArtifact {
        .init(id: 12, record: .init(caseID: "fixture", pluginID: plugin, pluginVersion: "0.2.0", schemaVersion: 1,
            contentType: "secret_trail.credential", sha256: "fixture", observedAt: Date(), privacyClass: .credentialAdjacent, data: data))
    }
    @Test func groupedFindingUsesRedactedLocationsAndCoverage() throws {
        let row = artifact(["family": .string("GitHub classic personal access token"), "reviewPriority": .string("review-first"),
            "fileCount": .integer(2), "occurrenceCount": .integer(3), "countsAreLowerBounds": .bool(true),
            "locations": .array([.object(["relativePath": .string("ai/session.jsonl"), "sourceKind": .string("ai-session"),
                                         "line": .integer(2), "representation": .string("json-escaped")])])])
        let finding = try #require(SecretTrailFinding(row))
        #expect(finding.reviewFirst && finding.partial)
        #expect(finding.omitted == 2)
        #expect(finding.locations.first?.escaped == true)
        #expect(finding.handoff.contains("ai/session.jsonl:2"))
        #expect(finding.handoff.contains("Coverage incomplete"))
    }
    @Test func foreignArtifactsDoNotGetTrustedPluginPresentation() {
        #expect(SecretTrailFinding(artifact([:], plugin: "com.example.other")) == nil)
    }
    @Test func legacyOrMalformedLocationsRemainVisiblyIncomplete() throws {
        let finding = try #require(SecretTrailFinding(artifact(["occurrenceCount": .integer(5), "locations": .array([.null])])))
        #expect(finding.locations.isEmpty)
        #expect(finding.omitted == 5)
    }
    @Test func credentialRowsAreRejectedByTheRealBridgeInPlaintextCases() {
        let manifest = TierBManifest(id: SecretTrailScope.pluginID, displayName: "Secret Trail", version: "0.2.0",
                                     schemaVersion: 1, description: "Fixture", privacyClass: "credentialAdjacent")
        let dto = TierBArtifactDTO(contentType: "secret_trail.credential", privacyClass: "credentialAdjacent")
        if case .rejected = TierBArtifactBridge.map(dto: dto, caseID: "fixture", manifest: manifest, caseAllowsSensitive: false) {} else {
            Issue.record("Credential-adjacent row accepted by plaintext bridge")
        }
        if case .record(let record) = TierBArtifactBridge.map(dto: dto, caseID: "fixture", manifest: manifest, caseAllowsSensitive: true) {
            #expect(record.privacyClass == .credentialAdjacent)
        } else { Issue.record("Sensitive row rejected by encrypted-case bridge") }
    }
    @Test(.enabled(if: ProcessInfo.processInfo.environment["RAVE_SECRET_TRAIL_PREVIEW_PATH"] != nil))
    @MainActor func renderSyntheticFindingsForVisualInspection() throws {
        // Opt-in artifact creation only; all content is constructed and redacted.
        guard let path = ProcessInfo.processInfo.environment["RAVE_SECRET_TRAIL_PREVIEW_PATH"] else { return }
        let locations: [JSONValue] = [
            .object(["relativePath": .string("project/.env"), "sourceKind": .string("project"), "line": .integer(1), "representation": .string("literal")]),
            .object(["relativePath": .string("ai/escaped-session.jsonl"), "sourceKind": .string("ai-session"), "line": .integer(1), "representation": .string("json-escaped")]),
            .object(["relativePath": .string("ai/session.jsonl"), "sourceKind": .string("ai-session"), "line": .integer(1), "representation": .string("literal")]),
            .object(["relativePath": .string("shell/history"), "sourceKind": .string("shell-history"), "line": .integer(1), "representation": .string("literal")])
        ]
        let row = artifact(["family": .string("GitHub classic personal access token"), "reviewPriority": .string("review-first"),
            "priorityReason": .string("Candidate occurs in a selected saved conversation, shell history or log source. Review whether those copies were intended."),
            "fileCount": .integer(4), "occurrenceCount": .integer(4), "countsAreLowerBounds": .bool(true),
            "locations": .array(locations), "reviewSteps": .array([.string("Confirm ownership, rotate if needed, and check the selected locations again.")])])
        let content = SecretTrailFindingsView(artifacts: [row]).frame(width: 740, height: 620)
            .background(Color(nsColor: .windowBackgroundColor)).environment(\.colorScheme, .light)
        _ = NSApplication.shared
        let hosting = NSHostingView(rootView: content)
        let window = NSWindow(contentRect: NSRect(x: -10000, y: -10000, width: 740, height: 620),
                              styleMask: [.borderless], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.contentView = hosting
        window.orderFrontRegardless()
        defer { window.close() }
        hosting.layoutSubtreeIfNeeded()
        RunLoop.main.run(until: Date().addingTimeInterval(0.2))
        window.displayIfNeeded()
        let bitmap = try #require(hosting.bitmapImageRepForCachingDisplay(in: hosting.bounds))
        hosting.cacheDisplay(in: hosting.bounds, to: bitmap)
        let png = try #require(bitmap.representation(using: .png, properties: [:]))
        try png.write(to: URL(fileURLWithPath: path))
        #expect(bitmap.pixelsWide >= 740 && bitmap.pixelsHigh >= 620)
    }
}
