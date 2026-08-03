import Foundation
import Testing
@testable import MacCrabCore

@Suite("Atomic no-follow bundle export workspace")
struct BundleExportWorkspaceTests {
    private func scratch(_ tag: String) throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(tag)-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: false
        )
        return root
    }

    @Test("both production exporters share the staged workspace boundary")
    func productionExportersCannotDriftBackToPathWrites() throws {
        let testFile = URL(fileURLWithPath: #filePath)
        let repositoryRoot = testFile
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        for relativePath in [
            "Sources/MacCrabCore/TraceBundle/BundleExporter.swift",
            "Sources/MacCrabCore/TraceBundle/AgentSessionBundle.swift",
        ] {
            let source = try String(
                contentsOf: repositoryRoot.appendingPathComponent(relativePath),
                encoding: .utf8
            )
            #expect(
                source.components(
                    separatedBy: "BundleExportWorkspace.create(at:"
                ).count - 1 == 1,
                "\(relativePath) must create exactly one staged workspace"
            )
            #expect(
                source.components(separatedBy: "workspace.publish()").count - 1 == 1,
                "\(relativePath) must atomically publish exactly once"
            )
            #expect(!source.contains("createDirectory(at: bundle"))
            #expect(!source.contains(".write(to: bundle"))
        }

        let workspaceSource = try String(
            contentsOf: repositoryRoot.appendingPathComponent(
                "Sources/MacCrabCore/TraceBundle/BundleExportWorkspace.swift"
            ),
            encoding: .utf8
        )
        #expect(workspaceSource.contains("remainingEntryBudget: remainingEntryBudget"))
        #expect(workspaceSource.contains("guard names.count < remainingEntryBudget else"))
    }

    @Test("requested name stays absent until one exclusive complete-tree publication")
    func completeTreeVisibility() throws {
        let root = try scratch("bundle-workspace-publish")
        defer { try? FileManager.default.removeItem(at: root) }
        let target = root.appendingPathComponent("result.maccrabtrace")
        let workspace = try BundleExportWorkspace.create(at: target)
        let partial = try #require(workspace.diagnosticPartialURLIfStillOwned)

        try workspace.createDirectory("integrity")
        try workspace.writeNew(Data("payload".utf8), to: "events.jsonl")
        try workspace.writeNew(Data("signature".utf8), to: "integrity/signature.json")

        #expect(!FileManager.default.fileExists(atPath: target.path))
        #expect(FileManager.default.fileExists(atPath: partial.path))
        #expect(try workspace.snapshotArtifacts(excludingRootIntegrity: true).map(\.path) == ["events.jsonl"])

        #expect(try workspace.publish() == target)
        #expect(FileManager.default.fileExists(atPath: target.path))
        #expect(!FileManager.default.fileExists(atPath: partial.path))
        #expect(workspace.diagnosticPartialURLIfStillOwned == nil)
        #expect(try String(
            contentsOf: target.appendingPathComponent("events.jsonl"),
            encoding: .utf8
        ) == "payload")
        #expect(try permissions(at: target) == 0o700)
        #expect(try permissions(at: target.appendingPathComponent("integrity")) == 0o700)
        #expect(try permissions(at: target.appendingPathComponent("events.jsonl")) == 0o600)
        #expect(try permissions(
            at: target.appendingPathComponent("integrity/signature.json")
        ) == 0o600)
    }

    @Test("a preplanted destination symlink is never followed or overwritten")
    func preplantedRootSymlink() throws {
        let root = try scratch("bundle-workspace-root-link")
        defer { try? FileManager.default.removeItem(at: root) }
        let outside = root.appendingPathComponent("outside", isDirectory: true)
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: false)
        let sentinel = outside.appendingPathComponent("sentinel")
        try Data("unchanged".utf8).write(to: sentinel)
        let target = root.appendingPathComponent("result.maccrabtrace")
        try FileManager.default.createSymbolicLink(
            atPath: target.path,
            withDestinationPath: outside.path
        )

        #expect(throws: BundleExportWorkspace.WorkspaceError.self) {
            _ = try BundleExportWorkspace.create(at: target)
        }
        #expect(try String(contentsOf: sentinel, encoding: .utf8) == "unchanged")
        #expect(!FileManager.default.fileExists(
            atPath: outside.appendingPathComponent("manifest.json").path
        ))
    }

    @Test("renaming and replacing the staging root cannot redirect writes")
    func displacedStagingRoot() throws {
        let root = try scratch("bundle-workspace-displace")
        defer { try? FileManager.default.removeItem(at: root) }
        let outside = root.appendingPathComponent("outside", isDirectory: true)
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: false)
        let target = root.appendingPathComponent("result.maccrabtrace")
        let workspace = try BundleExportWorkspace.create(at: target)
        let partial = try #require(workspace.diagnosticPartialURLIfStillOwned)
        let displaced = root.appendingPathComponent("owned-but-displaced", isDirectory: true)
        try FileManager.default.moveItem(at: partial, to: displaced)
        try FileManager.default.createSymbolicLink(
            atPath: partial.path,
            withDestinationPath: outside.path
        )

        try workspace.writeNew(Data("owned".utf8), to: "manifest.json")
        #expect(try String(
            contentsOf: displaced.appendingPathComponent("manifest.json"),
            encoding: .utf8
        ) == "owned")
        #expect(!FileManager.default.fileExists(
            atPath: outside.appendingPathComponent("manifest.json").path
        ))
        #expect(throws: BundleExportWorkspace.WorkspaceError.self) {
            _ = try workspace.publish()
        }
        #expect(!FileManager.default.fileExists(atPath: target.path))
        #expect(workspace.diagnosticPartialURLIfStillOwned == nil)
    }

    @Test("an artifact symlink cannot redirect an exclusive descriptor write")
    func artifactSymlink() throws {
        let root = try scratch("bundle-workspace-artifact-link")
        defer { try? FileManager.default.removeItem(at: root) }
        let target = root.appendingPathComponent("result.maccrabtrace")
        let workspace = try BundleExportWorkspace.create(at: target)
        let partial = try #require(workspace.diagnosticPartialURLIfStillOwned)
        let outside = root.appendingPathComponent("outside")
        try Data("unchanged".utf8).write(to: outside)
        try FileManager.default.createSymbolicLink(
            atPath: partial.appendingPathComponent("events.jsonl").path,
            withDestinationPath: outside.path
        )

        #expect(throws: BundleExportWorkspace.WorkspaceError.self) {
            try workspace.writeNew(Data("redirected".utf8), to: "events.jsonl")
        }
        #expect(try String(contentsOf: outside, encoding: .utf8) == "unchanged")
    }

    @Test("same-inode content mutation immediately before publication fails closed")
    func finalSnapshotDetectsSameInodeMutation() throws {
        let root = try scratch("bundle-workspace-content-race")
        defer { try? FileManager.default.removeItem(at: root) }
        let target = root.appendingPathComponent("result.maccrabtrace")
        let hooks = BundleExportWorkspace.TestHooks(
            beforeFinalPublicationSnapshot: { staging in
                let url = staging.appendingPathComponent("events.jsonl")
                let handle = try! FileHandle(forWritingTo: url)
                try! handle.truncate(atOffset: 0)
                try! handle.write(contentsOf: Data("attacker".utf8))
                try! handle.close()
            }
        )
        let workspace = try BundleExportWorkspace.create(at: target, testHooks: hooks)
        try workspace.writeNew(Data("signed".utf8), to: "events.jsonl")

        #expect(throws: BundleExportWorkspace.WorkspaceError.self) {
            _ = try workspace.publish()
        }
        #expect(!FileManager.default.fileExists(atPath: target.path))
        #expect(workspace.diagnosticPartialURLIfStillOwned != nil)
    }

    @Test("permission widening immediately before publication fails closed")
    func finalSnapshotRejectsWidenedPermissions() throws {
        let root = try scratch("bundle-workspace-mode-race")
        defer { try? FileManager.default.removeItem(at: root) }
        let target = root.appendingPathComponent("result.maccrabtrace")
        let hooks = BundleExportWorkspace.TestHooks(
            beforeFinalPublicationSnapshot: { staging in
                try! FileManager.default.setAttributes(
                    [.posixPermissions: NSNumber(value: 0o644)],
                    ofItemAtPath: staging.appendingPathComponent("events.jsonl").path
                )
            }
        )
        let workspace = try BundleExportWorkspace.create(at: target, testHooks: hooks)
        try workspace.writeNew(Data("signed".utf8), to: "events.jsonl")

        #expect(throws: BundleExportWorkspace.WorkspaceError.self) {
            _ = try workspace.publish()
        }
        #expect(!FileManager.default.fileExists(atPath: target.path))
        #expect(workspace.diagnosticPartialURLIfStillOwned != nil)
    }

    @Test("an inheritable destination-parent ACL cannot leak into the bundle")
    func inheritedParentACLIsRejected() throws {
        let root = try scratch("bundle-workspace-inherited-acl")
        defer { try? FileManager.default.removeItem(at: root) }
        let chmod = Process()
        chmod.executableURL = URL(fileURLWithPath: "/bin/chmod")
        chmod.arguments = [
            "+a",
            "everyone allow read,search,file_inherit,directory_inherit",
            root.path,
        ]
        try chmod.run()
        chmod.waitUntilExit()
        // Some test filesystems do not support macOS extended ACLs. In that
        // environment there is no inheritable ACL for this boundary to reject.
        guard chmod.terminationStatus == 0 else { return }

        let target = root.appendingPathComponent("result.maccrabtrace")
        #expect(throws: BundleExportWorkspace.WorkspaceError.self) {
            _ = try BundleExportWorkspace.create(at: target)
        }
        #expect(!FileManager.default.fileExists(atPath: target.path))
        let leftovers = try FileManager.default.contentsOfDirectory(atPath: root.path)
            .filter { $0.hasPrefix(".partial-maccrab-export-") }
        #expect(leftovers.isEmpty)
    }

    @Test("replacement temp name swap is rejected before rename")
    func replacementTempNameSwap() throws {
        let root = try scratch("bundle-workspace-temp-race")
        defer { try? FileManager.default.removeItem(at: root) }
        let target = root.appendingPathComponent("result.maccrabtrace")
        let hooks = BundleExportWorkspace.TestHooks(
            beforeReplacementPostflight: { staging, _, temporaryLeaf in
                let temporary = staging.appendingPathComponent(temporaryLeaf)
                let displaced = staging.appendingPathComponent("displaced-replacement")
                try! FileManager.default.moveItem(at: temporary, to: displaced)
                try! Data("attacker".utf8).write(to: temporary)
            }
        )
        let workspace = try BundleExportWorkspace.create(at: target, testHooks: hooks)
        try workspace.writeNew(Data("original".utf8), to: "manifest.json")

        #expect(throws: BundleExportWorkspace.WorkspaceError.self) {
            try workspace.replaceOwned(Data("replacement".utf8), at: "manifest.json")
        }
        let partial = try #require(workspace.diagnosticPartialURLIfStillOwned)
        #expect(try String(
            contentsOf: partial.appendingPathComponent("manifest.json"),
            encoding: .utf8
        ) == "original")
    }

    @Test("post-rename failure is surfaced as committed, never partial")
    func committedStateIsExplicit() throws {
        let root = try scratch("bundle-workspace-committed")
        defer { try? FileManager.default.removeItem(at: root) }
        let target = root.appendingPathComponent("result.maccrabtrace")
        let hooks = BundleExportWorkspace.TestHooks(
            afterFinalRename: { published in
                let url = published.appendingPathComponent("events.jsonl")
                let handle = try! FileHandle(forWritingTo: url)
                try! handle.truncate(atOffset: 0)
                try! handle.write(contentsOf: Data("changed-after-rename".utf8))
                try! handle.close()
            }
        )
        let workspace = try BundleExportWorkspace.create(at: target, testHooks: hooks)
        try workspace.writeNew(Data("signed".utf8), to: "events.jsonl")

        var wasCommittedError = false
        do {
            _ = try workspace.publish()
        } catch let error as BundleExportWorkspace.WorkspaceError {
            if case .committedBundle(let url, _) = error {
                wasCommittedError = (url == target)
            }
        }
        #expect(wasCommittedError)
        #expect(FileManager.default.fileExists(atPath: target.path))
        #expect(workspace.diagnosticPartialURLIfStillOwned == nil)
    }

    private func permissions(at url: URL) throws -> Int {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        return try #require(attributes[.posixPermissions] as? NSNumber).intValue
    }
}
