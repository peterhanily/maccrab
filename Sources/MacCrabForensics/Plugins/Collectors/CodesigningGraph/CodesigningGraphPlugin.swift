// CodesigningGraphPlugin — com.maccrab.forensics.codesigning-graph.
//
// Plan §13.6. Walks the common binary directories and emits one
// codesigning.binary artifact per binary with signer + team_id +
// notarization. Pairs with launchd-lite to surface fleet-wide
// trust posture: every binary either Apple-signed, Developer-ID
// from a known team, or unsigned / unknown.
//
// Sources: /Applications, ~/Applications, /usr/local/bin,
// /opt/homebrew/bin, /Library/PrivilegedHelperTools. /usr/bin
// is SIP-protected + mostly Apple; we skip unless the operator
// asks (future input flag).

import Foundation
import CryptoKit
import MacCrabCore

public struct CodesigningGraphPlugin: Collector {

    public static let manifest = PluginManifest(
        id: "com.maccrab.forensics.codesigning-graph",
        version: "1.0.0",
        displayName: "Codesigning Graph",
        description: "Inventories every binary in operator-installed paths (/Applications, /usr/local/bin, /opt/homebrew/bin) with signer_type + team_id + notarization. Pairs with launchd-lite for fleet-wide trust posture.",
        type: .collector,
        runtime: .tierA,
        tccRequirements: [.fullDiskAccess],
        inputs: [],
        outputs: [
            OutputSpec(contentType: "codesigning.binary", privacyClass: .metadata),
        ],
        mcpTools: [
            MCPToolDescriptor(
                name: "codesigning_graph_summary",
                description: "Inventoried binaries grouped by signer_type + team_id.",
                exposesPrivacyClass: .metadata
            ),
        ],
        schemaVersion: 1,
        stability: .preview
    )

    public init() async throws {}

    public func collect(case caseContext: CaseContext, window: TimeWindow?, output: any CollectorOutput) async throws -> CollectionResult {
        // Operator-installed binary paths.
        let roots = [
            "/Applications",
            NSHomeDirectory() + "/Applications",
            "/usr/local/bin",
            "/opt/homebrew/bin",
            "/opt/homebrew/sbin",
            "/Library/PrivilegedHelperTools",
        ]

        var committed = 0
        var rejected = 0
        let now = Date()
        let cache = CodeSigningCache()

        for root in roots {
            guard FileManager.default.fileExists(atPath: root) else { continue }
            // For /Applications-style roots: walk one level deep
            // looking for .app bundles + plain executables. Going
            // deeper would catch helper binaries; capped at one
            // level so the artifact volume stays sane.
            guard let entries = try? FileManager.default.contentsOfDirectory(
                at: URL(fileURLWithPath: root),
                includingPropertiesForKeys: [.isDirectoryKey, .isExecutableKey],
                options: [.skipsHiddenFiles]
            ) else { continue }
            for url in entries {
                var execPath: String? = nil
                if url.pathExtension == "app" {
                    // Resolve main executable via Info.plist's
                    // CFBundleExecutable.
                    let plist = url.appendingPathComponent("Contents/Info.plist")
                    if let data = try? Data(contentsOf: plist),
                       let p = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any],
                       let exe = p["CFBundleExecutable"] as? String {
                        execPath = url.appendingPathComponent("Contents/MacOS/\(exe)").path
                    }
                } else {
                    var isDir: ObjCBool = false
                    if FileManager.default.fileExists(atPath: url.path, isDirectory: &isDir), !isDir.boolValue,
                       FileManager.default.isExecutableFile(atPath: url.path) {
                        execPath = url.path
                    }
                }
                guard let path = execPath, FileManager.default.fileExists(atPath: path) else { continue }
                let info = await cache.evaluate(path: path)

                var data: [String: JSONValue] = [
                    "path": .string(path),
                    "bundle_path": .string(url.path),
                    "signer_type": .string(info.signerType.rawValue),
                    "is_notarized": .bool(info.isNotarized),
                ]
                if let teamID = info.teamId { data["team_id"] = .string(teamID) }
                if let signingID = info.signingId { data["signing_id"] = .string(signingID) }

                let seed = "codesigning.binary:\(path):\(info.teamId ?? "")"
                let sha = SHA256.hash(data: Data(seed.utf8)).map { String(format: "%02x", $0) }.joined()
                let record = ArtifactRecord(
                    caseID: caseContext.caseID,
                    pluginID: Self.manifest.id,
                    pluginVersion: Self.manifest.version,
                    schemaVersion: Self.manifest.schemaVersion,
                    contentType: "codesigning.binary",
                    sourcePath: path,
                    sha256: sha,
                    observedAt: now,
                    capturedAt: now,
                    summary: "\(url.lastPathComponent) → \(info.signerType.rawValue)\(info.teamId.map { " (\($0))" } ?? "")",
                    sizeBytes: 0,
                    confidence: .observed,
                    privacyClass: .metadata,
                    actor: NSUserName(),
                    data: data
                )
                do { try await output.commit(record); committed += 1 } catch { rejected += 1 }
            }
        }

        return CollectionResult(
            artifactsCommitted: committed,
            artifactsRejected: rejected,
            notes: ["codesigning-graph: \(committed) binaries surveyed across \(roots.count) directories"],
            status: .ok
        )
    }
}
