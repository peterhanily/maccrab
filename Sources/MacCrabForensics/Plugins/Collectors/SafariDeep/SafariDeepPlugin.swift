// SafariDeepPlugin — com.maccrab.forensics.safari-deep.
//
// Plan §13.3 Safari-deep split — opt-in companion to safari-lite.
// Emits content-class artifacts that safari-lite intentionally
// skips: cookie metadata (without value bodies in this RC) +
// LocalStorage / IndexedDB databases.
//
// v1.16.0-rc.14 ships:
//   - LocalStorage discovery (~/Library/Safari/LocalStorage/*.localstorage)
//   - IndexedDB discovery (~/Library/Safari/Databases/___IndexedDB/)
//
// Cookies.binarycookies parsing is deferred — the binary format
// is undocumented but reverse-engineered; a Swift port lands as a
// follow-up. The discovery surface here lets operators see "do I
// have local storage from suspicious sites?" without needing the
// full content extractor.

import Foundation
import CryptoKit

public struct SafariDeepPlugin: Collector {

    public static let manifest = PluginManifest(
        id: "com.maccrab.forensics.safari-deep",
        version: "1.0.0",
        displayName: "Safari Deep",
        description: "Opt-in companion to safari-lite. Discovers LocalStorage + IndexedDB databases per origin. Cookie content extraction deferred. Privacy class content.",
        type: .collector,
        runtime: .tierA,
        tccRequirements: [.fullDiskAccess],
        inputs: [],
        outputs: [
            OutputSpec(contentType: "safari.localstorage", privacyClass: .content, optInRequired: true),
            OutputSpec(contentType: "safari.indexeddb", privacyClass: .content, optInRequired: true),
        ],
        mcpTools: [],
        schemaVersion: 1,
        stability: .preview
    )

    public init() async throws {}

    public func collect(case caseContext: CaseContext, window: TimeWindow?, output: any CollectorOutput) async throws -> CollectionResult {
        let safari = NSHomeDirectory() + "/Library/Safari"
        var committed = 0
        var rejected = 0
        let now = Date()

        // LocalStorage discovery
        let lsDir = safari + "/LocalStorage"
        if let urls = try? FileManager.default.contentsOfDirectory(at: URL(fileURLWithPath: lsDir), includingPropertiesForKeys: [.fileSizeKey], options: [.skipsHiddenFiles]) {
            for url in urls where url.pathExtension == "localstorage" {
                let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
                let size = (attrs?[.size] as? NSNumber)?.int64Value ?? 0
                let origin = url.deletingPathExtension().lastPathComponent
                let seed = "safari.localstorage:\(origin)"
                let sha = SHA256.hash(data: Data(seed.utf8)).map { String(format: "%02x", $0) }.joined()
                let data: [String: JSONValue] = [
                    "origin": .string(origin),
                    "path": .string(url.path),
                    "size_bytes": .integer(size),
                ]
                let record = ArtifactRecord(
                    caseID: caseContext.caseID,
                    pluginID: Self.manifest.id,
                    pluginVersion: Self.manifest.version,
                    schemaVersion: Self.manifest.schemaVersion,
                    contentType: "safari.localstorage",
                    sourcePath: url.path,
                    sha256: sha,
                    observedAt: (attrs?[.modificationDate] as? Date) ?? now,
                    capturedAt: now,
                    summary: "LocalStorage: \(origin) (\(size) bytes)",
                    sizeBytes: size,
                    confidence: .observed,
                    privacyClass: .content,
                    actor: NSUserName(),
                    data: data
                )
                do { try await output.commit(record); committed += 1 } catch { rejected += 1 }
            }
        }

        // IndexedDB discovery
        let idbDir = safari + "/Databases/___IndexedDB"
        if let originDirs = try? FileManager.default.contentsOfDirectory(at: URL(fileURLWithPath: idbDir), includingPropertiesForKeys: nil, options: [.skipsHiddenFiles]) {
            for originDir in originDirs {
                var isDir: ObjCBool = false
                guard FileManager.default.fileExists(atPath: originDir.path, isDirectory: &isDir), isDir.boolValue else { continue }
                let origin = originDir.lastPathComponent
                let attrs = try? FileManager.default.attributesOfItem(atPath: originDir.path)
                let seed = "safari.indexeddb:\(origin)"
                let sha = SHA256.hash(data: Data(seed.utf8)).map { String(format: "%02x", $0) }.joined()
                let data: [String: JSONValue] = [
                    "origin": .string(origin),
                    "path": .string(originDir.path),
                ]
                let record = ArtifactRecord(
                    caseID: caseContext.caseID,
                    pluginID: Self.manifest.id,
                    pluginVersion: Self.manifest.version,
                    schemaVersion: Self.manifest.schemaVersion,
                    contentType: "safari.indexeddb",
                    sourcePath: originDir.path,
                    sha256: sha,
                    observedAt: (attrs?[.modificationDate] as? Date) ?? now,
                    capturedAt: now,
                    summary: "IndexedDB: \(origin)",
                    sizeBytes: 0,
                    confidence: .observed,
                    privacyClass: .content,
                    actor: NSUserName(),
                    data: data
                )
                do { try await output.commit(record); committed += 1 } catch { rejected += 1 }
            }
        }

        return CollectionResult(
            artifactsCommitted: committed,
            artifactsRejected: rejected,
            notes: ["safari-deep: \(committed) origins discovered. Cookies.binarycookies parser deferred."],
            status: .ok
        )
    }
}
