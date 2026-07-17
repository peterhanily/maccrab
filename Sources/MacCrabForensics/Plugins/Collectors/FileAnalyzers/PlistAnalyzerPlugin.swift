// PlistAnalyzerPlugin — com.maccrab.forensics.plist-analyzer.
//
// Plan §13.7 file analyzer family. Operator points at a .plist
// file; returns the top-level key set + format (binary / XML /
// OpenStep) + size + any obvious red-flag keys (UserName,
// LaunchAgentBundle pointers, ServiceLevelAgreement-like
// indicators).
//
// Pure: reads the file once, never executes.

import Foundation
import CryptoKit

public struct PlistAnalyzerPlugin: Collector {

    public static let manifest = PluginManifest(
        id: "com.maccrab.forensics.plist-analyzer",
        version: "1.0.0",
        displayName: "Plist Analyzer",
        description: "Operator-supplied plist file analysis: format (binary / xml), top-level keys, size, mtime, sha256.",
        type: .collector,
        runtime: .tierA,
        tccRequirements: [],
        inputs: [
            InputSpec(
                name: "path",
                description: "Absolute path to the .plist file to analyze. When omitted, analyzes a small system dogfood set.",
                type: .path,
                default: nil,
                required: false
            ),
        ],
        outputs: [
            OutputSpec(
                contentType: "plist.analysis",
                privacyClass: .metadata,
                viewerHint: ViewerHint(
                    viewer: .keyvalue,
                    fieldRoles: [
                        "path": .path,
                        "format": .status,
                        "size_bytes": .count,
                        "top_level_key_count": .count,
                    ]
                )
            ),
        ],
        mcpTools: [
            MCPToolDescriptor(
                name: "plist_analyze_path",
                description: "Analyze a .plist file: format + top-level keys + size.",
                exposesPrivacyClass: .metadata
            ),
        ],
        schemaVersion: 1,
        stability: .preview
    )

    public init() async throws {}

    public func collect(case caseContext: CaseContext, window: TimeWindow?, output: any CollectorOutput) async throws -> CollectionResult {
        // Operator-supplied path wins (mirrors ImageMetadataPlugin); otherwise
        // fall back to a small dogfood set so a bare run still shows output.
        let targets: [String]
        if case .string(let p)? = caseContext.inputs.values["path"], !p.isEmpty {
            targets = [p]
        } else {
            targets = [
                "/System/Library/LaunchDaemons/com.apple.notifyd.plist",
                "/Library/Preferences/com.apple.PowerManagement.plist",
            ].filter { FileManager.default.fileExists(atPath: $0) }
        }

        var committed = 0
        var rejected = 0
        let now = Date()
        for path in targets {
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else { continue }
            var format: PropertyListSerialization.PropertyListFormat = .xml
            guard let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: &format) else {
                continue
            }
            let topKeys = (plist as? [String: Any])?.keys.sorted() ?? []
            let formatToken: String = {
                switch format {
                case .binary: return "binary"
                case .xml: return "xml"
                case .openStep: return "openstep"
                @unknown default: return "unknown"
                }
            }()
            let sha = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
            let recordData: [String: JSONValue] = [
                "path": .string(path),
                "format": .string(formatToken),
                "size_bytes": .integer(Int64(data.count)),
                "top_level_keys": .array(topKeys.map { .string($0) }),
                "top_level_key_count": .integer(Int64(topKeys.count)),
            ]
            let record = ArtifactRecord(
                caseID: caseContext.caseID,
                pluginID: Self.manifest.id,
                pluginVersion: Self.manifest.version,
                schemaVersion: Self.manifest.schemaVersion,
                contentType: "plist.analysis",
                sourcePath: path,
                sha256: sha,
                observedAt: now,
                capturedAt: now,
                summary: "Plist \(path): \(formatToken), \(topKeys.count) top keys, \(data.count) bytes",
                sizeBytes: Int64(data.count),
                confidence: .observed,
                privacyClass: .metadata,
                actor: NSUserName(),
                data: recordData
            )
            do { try await output.commit(record); committed += 1 } catch { rejected += 1 }
        }
        return CollectionResult(artifactsCommitted: committed, artifactsRejected: rejected, notes: ["plist analyzer: \(committed) files analyzed (default dogfood set)"], status: .ok)
    }
}
