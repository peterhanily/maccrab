// ArchiveWalkerPlugin — com.maccrab.forensics.archive-walker.
//
// Plan §13.7. Catalogs zip / tar / tar.gz / 7z file metadata.
// Uses `unzip -l` for zip + `tar -tvf` for tar variants. Pure
// listing — no extraction.

import Foundation
import CryptoKit

public struct ArchiveWalkerPlugin: Collector {

    public static let manifest = PluginManifest(
        id: "com.maccrab.forensics.archive-walker",
        version: "1.0.0",
        displayName: "Archive Walker",
        description: "Catalog archive contents without extraction. Currently supports .zip / .tar / .tar.gz / .tgz. Reports entry count + total uncompressed size + filename list (capped).",
        type: .collector,
        runtime: .tierA,
        tccRequirements: [],
        inputs: [],
        outputs: [
            OutputSpec(contentType: "archive.listing", privacyClass: .metadata),
        ],
        mcpTools: [
            MCPToolDescriptor(
                name: "archive_list_contents",
                description: "List the contents of an archive (zip / tar / tar.gz) without extraction.",
                exposesPrivacyClass: .metadata
            ),
        ],
        schemaVersion: 1,
        stability: .preview
    )

    public init() async throws {}

    public func collect(case caseContext: CaseContext, window: TimeWindow?, output: any CollectorOutput) async throws -> CollectionResult {
        let downloads = NSHomeDirectory() + "/Downloads"
        guard let urls = try? FileManager.default.contentsOfDirectory(
            at: URL(fileURLWithPath: downloads),
            includingPropertiesForKeys: [.fileSizeKey],
            options: [.skipsHiddenFiles]
        ) else {
            return CollectionResult(artifactsCommitted: 0, artifactsRejected: 0, notes: ["~/Downloads not accessible"], status: .partial)
        }
        var committed = 0
        var rejected = 0
        let now = Date()
        for url in urls {
            let ext = url.pathExtension.lowercased()
            let isZip = ext == "zip"
            let isTar = ext == "tar" || ext == "tgz"
                || url.lastPathComponent.hasSuffix(".tar.gz")
            guard isZip || isTar else { continue }
            guard let data = try? Data(contentsOf: url) else { continue }
            let sha = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
            let raw: String
            if isZip {
                raw = await runSubprocess("/usr/bin/unzip", args: ["-l", url.path])
            } else {
                let isGz = ext == "tgz" || url.lastPathComponent.hasSuffix(".tar.gz")
                raw = await runSubprocess("/usr/bin/tar", args: [isGz ? "-tzvf" : "-tvf", url.path])
            }
            let lines = raw.split(separator: "\n").map(String.init)
            let entries = lines.count
            // Best-effort filename extraction.
            let filenames = lines.prefix(50).map { line -> String in
                let parts = line.split(separator: " ", omittingEmptySubsequences: true)
                return parts.last.map(String.init) ?? line
            }
            let fields: [String: JSONValue] = [
                "path": .string(url.path),
                "filename": .string(url.lastPathComponent),
                "size_bytes": .integer(Int64(data.count)),
                "sha256": .string(sha),
                "archive_format": .string(isZip ? "zip" : "tar"),
                "entry_line_count": .integer(Int64(entries)),
                "entry_names_preview": .array(filenames.map { .string($0) }),
            ]
            let record = ArtifactRecord(
                caseID: caseContext.caseID,
                pluginID: Self.manifest.id,
                pluginVersion: Self.manifest.version,
                schemaVersion: Self.manifest.schemaVersion,
                contentType: "archive.listing",
                sourcePath: url.path,
                sha256: sha,
                observedAt: now,
                capturedAt: now,
                summary: "Archive \(url.lastPathComponent): \(entries) entries",
                sizeBytes: Int64(data.count),
                confidence: .observed,
                privacyClass: .metadata,
                actor: NSUserName(),
                data: fields
            )
            do { try await output.commit(record); committed += 1 } catch { rejected += 1 }
        }
        return CollectionResult(artifactsCommitted: committed, artifactsRejected: rejected, notes: ["archive walker: \(committed) archives catalogued"], status: .ok)
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
