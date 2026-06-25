// DMGPKGAnalyzerPlugin — com.maccrab.forensics.dmg-pkg-analyzer.
//
// Plan §13.7. Operator points at a .dmg or .pkg; the plugin
// shells out to hdiutil / pkgutil for structured info, captures
// codesign posture, emits dmg.analysis / pkg.analysis artifacts.

import Foundation
import CryptoKit
import MacCrabCore

public struct DMGPKGAnalyzerPlugin: Collector {

    public static let manifest = PluginManifest(
        id: "com.maccrab.forensics.dmg-pkg-analyzer",
        version: "1.0.0",
        displayName: "DMG/PKG Analyzer",
        description: "Operator-supplied .dmg or .pkg analyzer. Shells out to hdiutil / pkgutil for layout + codesign team_id + notarization. Catches repackaged-installer supply-chain artifacts.",
        type: .collector,
        runtime: .tierA,
        tccRequirements: [],
        inputs: [],
        outputs: [
            OutputSpec(
                contentType: "dmg.analysis",
                privacyClass: .metadata,
                viewerHint: ViewerHint(
                    viewer: .keyvalue,
                    fieldRoles: [
                        "filename": .title,
                        "path": .path,
                        "codesign.signer_type": .status,
                        "codesign.team_id": .identifier,
                        "sha256": .identifier,
                        "size_bytes": .count,
                        "hdiutil_imageinfo_lines": .count,
                    ]
                )
            ),
            OutputSpec(
                contentType: "pkg.analysis",
                privacyClass: .metadata,
                viewerHint: ViewerHint(
                    viewer: .keyvalue,
                    fieldRoles: [
                        "filename": .title,
                        "path": .path,
                        "codesign.signer_type": .status,
                        "pkg_is_signed": .status,
                        "pkg_is_notarized": .status,
                        "codesign.team_id": .identifier,
                        "sha256": .identifier,
                        "size_bytes": .count,
                    ]
                )
            ),
        ],
        mcpTools: [
            MCPToolDescriptor(
                name: "dmg_analyze_path",
                description: "Analyze a .dmg disk image: hdiutil imageinfo + codesign + sha256.",
                exposesPrivacyClass: .metadata
            ),
            MCPToolDescriptor(
                name: "pkg_analyze_path",
                description: "Analyze a .pkg installer: pkgutil --check-signature + payload preview + codesign.",
                exposesPrivacyClass: .metadata
            ),
        ],
        schemaVersion: 1,
        stability: .preview
    )

    public init() async throws {}

    public func collect(case caseContext: CaseContext, window: TimeWindow?, output: any CollectorOutput) async throws -> CollectionResult {
        // Operator-supplied path wins (mirrors ImageMetadataPlugin); otherwise
        // default-scan ~/Downloads, where operators routinely keep installers.
        let urls: [URL]
        if case .string(let p)? = caseContext.inputs.values["path"], !p.isEmpty {
            urls = [URL(fileURLWithPath: p)]
        } else {
            let downloads = NSHomeDirectory() + "/Downloads"
            guard FileManager.default.fileExists(atPath: downloads),
                  let found = try? FileManager.default.contentsOfDirectory(
                    at: URL(fileURLWithPath: downloads),
                    includingPropertiesForKeys: [.fileSizeKey],
                    options: [.skipsHiddenFiles]
                  ) else {
                return CollectionResult(artifactsCommitted: 0, artifactsRejected: 0, notes: ["~/Downloads not accessible"], status: .partial)
            }
            urls = found
        }
        var committed = 0
        var rejected = 0
        let now = Date()
        let cache = CodeSigningCache()
        for url in urls {
            let ext = url.pathExtension.lowercased()
            guard ext == "dmg" || ext == "pkg" else { continue }
            guard FileAnalyzerIO.regularFileSize(url) != nil else { rejected += 1; continue }  // SEC-DELTA-1/2
            guard let data = try? Data(contentsOf: url) else { rejected += 1; continue }
            let sha = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
            var fields: [String: JSONValue] = [
                "path": .string(url.path),
                "filename": .string(url.lastPathComponent),
                "size_bytes": .integer(Int64(data.count)),
                "sha256": .string(sha),
            ]
            if ext == "dmg" {
                let info = await runSubprocess("/usr/bin/hdiutil", args: ["imageinfo", url.path])
                fields["hdiutil_imageinfo_lines"] = .integer(Int64(info.split(separator: "\n").count))
            } else {
                let info = await runSubprocess("/usr/sbin/pkgutil", args: ["--check-signature", url.path])
                let isSigned = info.contains("Status: signed by")
                let isNotarized = info.contains("Notarization: trusted")
                fields["pkg_is_signed"] = .bool(isSigned)
                fields["pkg_is_notarized"] = .bool(isNotarized)
            }
            // Container-level codesign (Apple wraps .pkg + signed
            // .dmg with codesign too).
            let info = await cache.evaluate(path: url.path)
            fields["codesign.signer_type"] = .string(info.signerType.rawValue)
            if let teamID = info.teamId {
                fields["codesign.team_id"] = .string(teamID)
            }

            let content: String = (ext == "dmg") ? "dmg.analysis" : "pkg.analysis"
            let record = ArtifactRecord(
                caseID: caseContext.caseID,
                pluginID: Self.manifest.id,
                pluginVersion: Self.manifest.version,
                schemaVersion: Self.manifest.schemaVersion,
                contentType: content,
                sourcePath: url.path,
                sha256: sha,
                observedAt: now,
                capturedAt: now,
                summary: "\(ext.uppercased()) \(url.lastPathComponent): \(info.signerType.rawValue)",
                sizeBytes: Int64(data.count),
                confidence: .observed,
                privacyClass: .metadata,
                actor: NSUserName(),
                data: fields
            )
            do { try await output.commit(record); committed += 1 } catch { rejected += 1 }
        }
        return CollectionResult(artifactsCommitted: committed, artifactsRejected: rejected, notes: ["DMG/PKG analyzer: \(committed) installers analyzed (scanned ~/Downloads)"], status: .ok)
    }

    private func runSubprocess(_ exe: String, args: [String]) async -> String {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: exe)
        proc.arguments = args
        let out = Pipe()
        proc.standardOutput = out
        proc.standardError = Pipe()
        do { try proc.run() } catch { return "" }
        proc.waitUntilExit()
        return String(data: out.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    }
}
