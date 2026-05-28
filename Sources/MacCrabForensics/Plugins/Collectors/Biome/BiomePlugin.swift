// BiomePlugin — com.maccrab.forensics.biome.
//
// Plan §13.6 — Biome is macOS 13+'s replacement / complement for
// KnowledgeC. Streams of structured events live under
// ~/Library/Biome/Streams/public/<streamName>. Each stream is a
// directory containing serialized event records.
//
// v1.16.0-rc.15 ships a DISCOVERY plugin: enumerates streams +
// file counts + sizes. Full record-stream parsing (Apple's
// binary BiomeEvent format) is a follow-up.

import Foundation
import CryptoKit

public struct BiomePlugin: Collector {

    public static let manifest = PluginManifest(
        id: "com.maccrab.forensics.biome",
        version: "1.0.0",
        displayName: "Biome",
        description: "Discovery of macOS Biome event streams. Lists stream names + file counts + total bytes. Full record parsing deferred (Apple-internal BiomeEvent binary format).",
        type: .collector,
        runtime: .tierA,
        tccRequirements: [.fullDiskAccess],
        inputs: [],
        outputs: [
            OutputSpec(
                contentType: "biome.stream",
                privacyClass: .metadata,
                viewerHint: ViewerHint(
                    viewer: .timeline,
                    fieldRoles: [
                        "observed_at": .timestamp,
                        "stream_name": .title,
                        "value": .subtitle,
                        "source_app": .identifier,
                    ]
                )
            ),
        ],
        mcpTools: [],
        schemaVersion: 1,
        stability: .preview
    )

    public init() async throws {}

    public func collect(case caseContext: CaseContext, window: TimeWindow?, output: any CollectorOutput) async throws -> CollectionResult {
        let root = NSHomeDirectory() + "/Library/Biome/Streams/public"
        guard let entries = try? FileManager.default.contentsOfDirectory(at: URL(fileURLWithPath: root), includingPropertiesForKeys: nil, options: [.skipsHiddenFiles]) else {
            return CollectionResult(artifactsCommitted: 0, artifactsRejected: 0, notes: ["Biome streams root not present"], status: .partial)
        }
        var committed = 0
        var rejected = 0
        let now = Date()
        for streamDir in entries {
            var isDir: ObjCBool = false
            guard FileManager.default.fileExists(atPath: streamDir.path, isDirectory: &isDir), isDir.boolValue else { continue }
            let name = streamDir.lastPathComponent
            // Sum file count + total bytes in the stream dir.
            guard let files = try? FileManager.default.contentsOfDirectory(at: streamDir, includingPropertiesForKeys: [.fileSizeKey], options: []) else { continue }
            var totalBytes: Int64 = 0
            for f in files {
                let attrs = try? FileManager.default.attributesOfItem(atPath: f.path)
                totalBytes += (attrs?[.size] as? NSNumber)?.int64Value ?? 0
            }
            let data: [String: JSONValue] = [
                "stream_name": .string(name),
                "path": .string(streamDir.path),
                "file_count": .integer(Int64(files.count)),
                "total_bytes": .integer(totalBytes),
            ]
            let seed = "biome.stream:\(name)"
            let sha = SHA256.hash(data: Data(seed.utf8)).map { String(format: "%02x", $0) }.joined()
            let record = ArtifactRecord(
                caseID: caseContext.caseID,
                pluginID: Self.manifest.id,
                pluginVersion: Self.manifest.version,
                schemaVersion: Self.manifest.schemaVersion,
                contentType: "biome.stream",
                sourcePath: streamDir.path,
                sha256: sha,
                observedAt: now,
                capturedAt: now,
                summary: "Biome stream \(name): \(files.count) files, \(totalBytes) bytes",
                sizeBytes: totalBytes,
                confidence: .observed,
                privacyClass: .metadata,
                actor: NSUserName(),
                data: data
            )
            do { try await output.commit(record); committed += 1 } catch { rejected += 1 }
        }
        return CollectionResult(artifactsCommitted: committed, artifactsRejected: rejected, notes: ["Biome: \(committed) streams discovered"], status: .ok)
    }
}
