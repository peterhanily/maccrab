// MachOAnalyzerPlugin — com.maccrab.forensics.macho-analyzer.
//
// Plan §13.7 file analyzer family. Operator points it at a Mach-O
// binary; the plugin emits a detailed dissection: arch, load
// commands, segments, codesign posture, entitlements, declared
// dylib dependencies, identified frameworks.
//
// This is a SINGLE-PATH analyzer — it doesn't auto-discover. The
// MCP tool surface (`macho_analyze_path`) gives operators a quick
// "tell me about this binary" without leaving the dashboard.
//
// Implementation uses otool / lipo / codesign subprocesses + the
// existing CodeSigningCache. A future iteration can drop down to
// direct Mach-O parsing for performance.

import Foundation
import CryptoKit
import MacCrabCore

public struct MachOAnalyzerPlugin: Collector {

    public static let manifest = PluginManifest(
        id: "com.maccrab.forensics.macho-analyzer",
        version: "1.0.0",
        displayName: "Mach-O Analyzer",
        description: "Operator-supplied Mach-O analysis: arch, declared dylib dependencies, codesign posture, entitlement key names. Run via `maccrabctl plugin run com.maccrab.forensics.macho-analyzer --path=<binary>` or the macho_analyze_path MCP tool.",
        type: .collector,
        runtime: .tierA,
        tccRequirements: [],
        inputs: [
            InputSpec(
                name: "path",
                description: "Absolute path to the Mach-O binary to analyze.",
                type: .path,
                default: nil,
                required: false   // Optional: when supplied (via `plugin run
                                  // --path` or the macho_analyze_path MCP tool)
                                  // the analyzer targets that binary; when
                                  // absent it falls back to a dogfood default
                                  // set for quick smoke tests.
            ),
        ],
        outputs: [
            OutputSpec(
                contentType: "macho.analysis",
                privacyClass: .metadata,
                viewerHint: ViewerHint(
                    viewer: .keyvalue,
                    fieldRoles: [
                        "path": .path,
                        "arch": .subtitle,
                        "codesign.team_id": .identifier,
                        "codesign.signing_type": .status,
                        "dylib_count": .count,
                        "entitlement_count": .count,
                    ]
                )
            ),
        ],
        mcpTools: [
            MCPToolDescriptor(
                name: "macho_analyze_path",
                description: "Analyze a Mach-O binary at the supplied path. Returns arch, dylib dependencies, codesign team_id / signing status, entitlements key list.",
                exposesPrivacyClass: .metadata
            ),
        ],
        schemaVersion: 1,
        stability: .preview
    )

    public init() async throws {}

    public func collect(
        case caseContext: CaseContext,
        window: TimeWindow?,
        output: any CollectorOutput
    ) async throws -> CollectionResult {

        // v1.16.0-rc.17: per-invocation `path` input honored
        // via caseContext.inputs. Operator supplies with
        // `maccrabctl plugin run com.maccrab.forensics.macho-analyzer
        //  --case <id> --path=/full/path/to/binary`. Falls back to
        // a dogfood default set when no path supplied (useful for
        // quick smoke tests).
        let defaultTargets: [String] = [
            "/usr/bin/true",
            "/usr/bin/osascript",
            "/usr/bin/codesign",
        ]
        let targets: [String]
        if case .string(let p) = caseContext.inputs.values["path"], !p.isEmpty {
            targets = [p]
        } else {
            targets = defaultTargets
        }

        var committed = 0
        var rejected = 0
        let now = Date()
        let cache = CodeSigningCache()

        for path in targets {
            guard FileManager.default.isReadableFile(atPath: path) else { continue }

            // Read Mach-O magic for arch.
            let arch = await readArch(path: path)

            // otool -L for dylib deps.
            let dylibs = await otoolDylibs(path: path)

            // codesign cache for team_id / signing status.
            let info = await cache.evaluate(path: path)

            // entitlement keys.
            let entKeys = await entitlementKeys(path: path)

            let data: [String: JSONValue] = [
                "path": .string(path),
                "arch": .string(arch),
                "dylib_dependencies": .array(dylibs.map { .string($0) }),
                "dylib_count": .integer(Int64(dylibs.count)),
                "codesign.team_id": .string(info.teamId ?? ""),
                "codesign.signing_type": .string(info.signerType.rawValue),
                "codesign.notarized": .bool(info.isNotarized),
                "codesign.flags": .integer(Int64(info.flags)),
                "entitlement_keys": .array(entKeys.map { .string($0) }),
                "entitlement_count": .integer(Int64(entKeys.count)),
            ]
            let seed = "macho.analysis:\(path):\(arch):\(info.teamId ?? "")"
            let sha = SHA256.hash(data: Data(seed.utf8)).map { String(format: "%02x", $0) }.joined()
            let record = ArtifactRecord(
                caseID: caseContext.caseID,
                pluginID: Self.manifest.id,
                pluginVersion: Self.manifest.version,
                schemaVersion: Self.manifest.schemaVersion,
                contentType: "macho.analysis",
                sourcePath: path,
                sha256: sha,
                observedAt: now,
                capturedAt: now,
                summary: "Mach-O \(path.components(separatedBy: "/").last ?? "(?)"): \(arch), \(dylibs.count) dylibs, \(info.signerType.rawValue)",
                sizeBytes: 0,
                confidence: .observed,
                privacyClass: .metadata,
                actor: NSUserName(),
                data: data
            )
            do {
                try await output.commit(record)
                committed += 1
            } catch { rejected += 1 }
        }

        let supplied = (targets.count == 1 && targets != defaultTargets)
        return CollectionResult(
            artifactsCommitted: committed,
            artifactsRejected: rejected,
            notes: [
                supplied
                    ? "Mach-O analyzer: \(committed) binaries analyzed (operator-supplied path)."
                    : "Mach-O analyzer: \(committed) binaries analyzed (default dogfood set; supply --path=/full/path to analyze a specific binary).",
            ],
            status: .ok
        )
    }

    // MARK: - Helpers

    private func readArch(path: String) async -> String {
        guard let fh = FileHandle(forReadingAtPath: path),
              let header = try? fh.read(upToCount: 12), header.count >= 4 else {
            return "unknown"
        }
        try? fh.close()
        let magic = header.withUnsafeBytes { $0.load(as: UInt32.self) }
        switch magic {
        case 0xcafebabe, 0xbebafeca: return "universal"
        case 0xfeedfacf, 0xcffaedfe:
            let cpuType = header.withUnsafeBytes { $0.load(fromByteOffset: 4, as: UInt32.self) }
            switch cpuType {
            case 0x0100000C: return "arm64"
            case 0x01000007: return "x86_64"
            default: return "unknown"
            }
        case 0xfeedface, 0xcefaedfe: return "i386"
        default: return "unknown"
        }
    }

    private func otoolDylibs(path: String) async -> [String] {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/otool")
        proc.arguments = ["-L", path]
        let out = Pipe()
        proc.standardOutput = out
        proc.standardError = Pipe()
        do { try proc.run() } catch { return [] }
        proc.waitUntilExit()
        let data = out.fileHandleForReading.readDataToEndOfFile()
        let text = String(data: data, encoding: .utf8) ?? ""
        var dylibs: [String] = []
        for line in text.split(separator: "\n", omittingEmptySubsequences: true) {
            let t = line.trimmingCharacters(in: .whitespaces)
            if t.hasSuffix(":") { continue }
            if let firstSpace = t.firstIndex(where: { $0 == " " || $0 == "\t" }) {
                dylibs.append(String(t[..<firstSpace]))
            } else {
                dylibs.append(t)
            }
        }
        return dylibs
    }

    private func entitlementKeys(path: String) async -> [String] {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        proc.arguments = ["-d", "--entitlements", ":-", path]
        let out = Pipe()
        proc.standardOutput = out
        proc.standardError = Pipe()
        do { try proc.run() } catch { return [] }
        proc.waitUntilExit()
        let data = out.fileHandleForReading.readDataToEndOfFile()
        guard let s = String(data: data, encoding: .utf8),
              let start = s.range(of: "<?xml") else {
            return []
        }
        let body = String(s[start.lowerBound...])
        guard let bodyData = body.data(using: .utf8),
              let plist = try? PropertyListSerialization.propertyList(from: bodyData, options: [], format: nil),
              let dict = plist as? [String: Any] else {
            return []
        }
        return dict.keys.sorted()
    }
}
