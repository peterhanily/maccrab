// MobileconfigPlugin — com.maccrab.forensics.mobileconfig-inspector.
//
// Plan §13.7. .mobileconfig is an MDM configuration profile —
// an XML plist signed via CMS. Risk surface: profiles can install
// root certs, change DNS, deploy MDM, ship custom URL schemes.
// Operator points it at a .mobileconfig file; the plugin emits
// a structured analysis of every PayloadType inside.

import Foundation
import CryptoKit

public struct MobileconfigPlugin: Collector {

    public static let manifest = PluginManifest(
        id: "com.maccrab.forensics.mobileconfig-inspector",
        version: "1.0.0",
        displayName: "Mobileconfig Inspector",
        description: "Scans Managed Preferences profiles for declared payloads (certificate / DNS / VPN presence flags), top-level keys, and CMS-signed posture.",
        type: .collector,
        runtime: .tierA,
        tccRequirements: [],
        inputs: [],
        outputs: [
            OutputSpec(
                contentType: "mobileconfig.analysis",
                privacyClass: .metadata,
                viewerHint: ViewerHint(
                    viewer: .keyvalue,
                    fieldRoles: [
                        "path": .path,
                        "size_bytes": .count,
                    ]
                )
            ),
        ],
        mcpTools: [
            MCPToolDescriptor(
                name: "mobileconfig_analyze_path",
                description: "Analyze a Managed Preferences profile: payload types, certificate / DNS / VPN presence, CMS-signed flag.",
                exposesPrivacyClass: .metadata
            ),
        ],
        schemaVersion: 1,
        stability: .preview
    )

    public init() async throws {}

    public func collect(case caseContext: CaseContext, window: TimeWindow?, output: any CollectorOutput) async throws -> CollectionResult {
        // Default discovery: scan common mobileconfig drop locations.
        let candidatePaths = [
            "/Library/Managed Preferences",
            NSHomeDirectory() + "/Library/Managed Preferences",
        ]
        var paths: [String] = []
        for dir in candidatePaths {
            guard let urls = try? FileManager.default.contentsOfDirectory(at: URL(fileURLWithPath: dir), includingPropertiesForKeys: nil, options: [.skipsHiddenFiles]) else { continue }
            for u in urls where u.pathExtension == "mobileconfig" || u.pathExtension == "plist" {
                paths.append(u.path)
            }
        }
        var committed = 0
        var rejected = 0
        let now = Date()
        for path in paths {
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else { continue }
            // .mobileconfig can be raw plist or CMS-signed. Detect by leading bytes.
            let isCMSSigned = !data.starts(with: Array("<?xml".utf8)) && !data.starts(with: [0x62, 0x70, 0x6C, 0x69, 0x73, 0x74])  // not XML, not bplist00
            var payloadTypes: [String] = []
            var topKeys: [String] = []
            if !isCMSSigned {
                if let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
                   let dict = plist as? [String: Any] {
                    topKeys = dict.keys.sorted()
                    if let payloads = dict["PayloadContent"] as? [[String: Any]] {
                        payloadTypes = payloads.compactMap { $0["PayloadType"] as? String }
                    }
                }
            }
            let sha = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
            let recordData: [String: JSONValue] = [
                "path": .string(path),
                "size_bytes": .integer(Int64(data.count)),
                "is_cms_signed": .bool(isCMSSigned),
                "top_level_keys": .array(topKeys.map { .string($0) }),
                "payload_types": .array(payloadTypes.map { .string($0) }),
                "has_certificate_payload": .bool(payloadTypes.contains("com.apple.security.root")),
                "has_dns_payload": .bool(payloadTypes.contains("com.apple.dnsSettings.managed")),
                "has_vpn_payload": .bool(payloadTypes.contains("com.apple.vpn.managed")),
            ]
            let record = ArtifactRecord(
                caseID: caseContext.caseID,
                pluginID: Self.manifest.id,
                pluginVersion: Self.manifest.version,
                schemaVersion: Self.manifest.schemaVersion,
                contentType: "mobileconfig.analysis",
                sourcePath: path,
                sha256: sha,
                observedAt: now,
                capturedAt: now,
                summary: "Mobileconfig \(path): \(payloadTypes.count) payload(s) — \(payloadTypes.joined(separator: ", "))",
                sizeBytes: Int64(data.count),
                confidence: .observed,
                privacyClass: .metadata,
                actor: NSUserName(),
                data: recordData
            )
            do { try await output.commit(record); committed += 1 } catch { rejected += 1 }
        }
        return CollectionResult(artifactsCommitted: committed, artifactsRejected: rejected, notes: ["mobileconfig analyzer: \(committed) profiles analyzed"], status: .ok)
    }
}
