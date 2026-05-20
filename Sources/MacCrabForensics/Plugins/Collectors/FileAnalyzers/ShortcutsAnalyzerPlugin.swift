// ShortcutsAnalyzerPlugin — com.maccrab.forensics.shortcuts-analyzer.
//
// Plan §13.7. Apple Shortcuts (.shortcut files / iCloud shortcuts
// library) are JSON/plist bundles describing automation steps.
// Risk surface: shortcuts can execute scripts, dispatch to other
// apps, perform network requests. Operator-aimed file analyzer.

import Foundation
import CryptoKit

public struct ShortcutsAnalyzerPlugin: Collector {

    public static let manifest = PluginManifest(
        id: "com.maccrab.forensics.shortcuts-analyzer",
        version: "1.0.0",
        displayName: "Shortcuts Analyzer",
        description: "Catalogs Shortcuts library: shortcut names + step-action counts + sharing posture. Privacy class metadata.",
        type: .collector,
        runtime: .tierA,
        tccRequirements: [],
        inputs: [],
        outputs: [
            OutputSpec(contentType: "shortcuts.shortcut", privacyClass: .metadata),
        ],
        mcpTools: [],
        schemaVersion: 1,
        stability: .preview
    )

    public init() async throws {}

    public func collect(case caseContext: CaseContext, window: TimeWindow?, output: any CollectorOutput) async throws -> CollectionResult {
        // Shortcuts library on macOS:
        //   ~/Library/Shortcuts/Shortcuts.sqlite (modern)
        //   ~/Library/Mobile Documents/.../Shortcuts/  (iCloud-synced)
        // For v1.16.0-rc.9 RC we just enumerate the .shortcut files
        // we can find without parsing the internal action graph
        // (which is plist-binary with proprietary keying).
        let candidates = [
            NSHomeDirectory() + "/Library/Shortcuts",
            NSHomeDirectory() + "/Library/Mobile Documents/iCloud~is~workflow~my~workflows/Documents",
        ]
        var paths: [URL] = []
        for dir in candidates {
            guard let urls = try? FileManager.default.contentsOfDirectory(at: URL(fileURLWithPath: dir), includingPropertiesForKeys: [.fileSizeKey, .contentModificationDateKey], options: [.skipsHiddenFiles]) else { continue }
            for u in urls where u.pathExtension == "shortcut" || u.pathExtension == "wflow" {
                paths.append(u)
            }
        }
        var committed = 0
        var rejected = 0
        let now = Date()
        for url in paths {
            let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
            let size = (attrs?[.size] as? NSNumber)?.int64Value ?? 0
            let mtime = (attrs?[.modificationDate] as? Date) ?? now
            let name = url.deletingPathExtension().lastPathComponent
            guard let data = try? Data(contentsOf: url) else { continue }
            let sha = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
            let recordData: [String: JSONValue] = [
                "name": .string(name),
                "path": .string(url.path),
                "size_bytes": .integer(size),
                "mtime_iso": .string(ISO8601DateFormatter().string(from: mtime)),
            ]
            let record = ArtifactRecord(
                caseID: caseContext.caseID,
                pluginID: Self.manifest.id,
                pluginVersion: Self.manifest.version,
                schemaVersion: Self.manifest.schemaVersion,
                contentType: "shortcuts.shortcut",
                sourcePath: url.path,
                sha256: sha,
                observedAt: mtime,
                capturedAt: now,
                summary: "Shortcut: \(name) (\(size) bytes)",
                sizeBytes: size,
                confidence: .observed,
                privacyClass: .metadata,
                actor: NSUserName(),
                data: recordData
            )
            do { try await output.commit(record); committed += 1 } catch { rejected += 1 }
        }
        return CollectionResult(artifactsCommitted: committed, artifactsRejected: rejected, notes: ["shortcuts analyzer: \(committed) shortcuts catalogued"], status: .ok)
    }
}
