// OfficeDocumentPlugin — com.maccrab.forensics.office-document-analyzer.
//
// Plan §13.7. .docx / .xlsx / .pptx files are OPC packages
// (zip files containing XML). The package's docProps/core.xml
// holds creator / lastModifiedBy / created / modified metadata
// (useful for "who modified this document and when"); the
// presence of macros (vbaProject.bin in .docm / .xlsm) is a
// supply-chain risk signal.
//
// Implementation uses `unzip -p` to extract the relevant XML
// fragments without writing temp files.

import Foundation
import CryptoKit

public struct OfficeDocumentPlugin: Collector {

    public static let manifest = PluginManifest(
        id: "com.maccrab.forensics.office-document-analyzer",
        version: "1.0.0",
        displayName: "Office Document Analyzer",
        description: "Parses .docx / .xlsx / .pptx (OPC zip + XML) for core metadata + macro presence. Catches the supply-chain risk of macro-bearing docs.",
        type: .collector,
        runtime: .tierA,
        tccRequirements: [],
        inputs: [],
        outputs: [
            OutputSpec(
                contentType: "office.document",
                privacyClass: .metadata,
                viewerHint: ViewerHint(
                    viewer: .keyvalue,
                    fieldRoles: [
                        "filename": .title,
                        "path": .path,
                        "format": .subtitle,
                        "has_macros": .status,
                        "creator": .body,
                        "last_modified_by": .body,
                        "created_iso": .timestamp,
                        "modified_iso": .timestamp,
                        "size_bytes": .count,
                        "sha256": .identifier,
                    ]
                )
            ),
        ],
        mcpTools: [
            MCPToolDescriptor(
                name: "office_document_analyze",
                description: "Analyze .docx / .xlsx / .pptx core metadata + macro presence.",
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
            includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        ) else {
            return CollectionResult(artifactsCommitted: 0, artifactsRejected: 0, notes: ["~/Downloads not accessible"], status: .partial)
        }
        var committed = 0
        var rejected = 0
        let now = Date()
        for url in urls {
            let ext = url.pathExtension.lowercased()
            let isOffice = ["docx", "docm", "xlsx", "xlsm", "pptx", "pptm"].contains(ext)
            guard isOffice else { continue }
            guard FileAnalyzerIO.regularFileSize(url) != nil else { rejected += 1; continue }  // SEC-DELTA-1/2
            guard let data = try? Data(contentsOf: url) else { rejected += 1; continue }
            let sha = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
            // List entries.
            let entryList = await runSubprocess("/usr/bin/unzip", args: ["-l", url.path])
            let hasMacro = entryList.contains("vbaProject.bin")
            // Core metadata (docProps/core.xml).
            let coreXML = await runSubprocess("/usr/bin/unzip", args: ["-p", url.path, "docProps/core.xml"])
            let creator = Self.xmlValue(from: coreXML, tagSuffix: "creator")
            let lastModifiedBy = Self.xmlValue(from: coreXML, tagSuffix: "lastModifiedBy")
            let created = Self.xmlValue(from: coreXML, tagSuffix: "created")
            let modified = Self.xmlValue(from: coreXML, tagSuffix: "modified")
            let title = Self.xmlValue(from: coreXML, tagSuffix: "title")

            var recordData: [String: JSONValue] = [
                "path": .string(url.path),
                "filename": .string(url.lastPathComponent),
                "size_bytes": .integer(Int64(data.count)),
                "format": .string(ext),
                "has_macros": .bool(hasMacro),
                "sha256": .string(sha),
            ]
            if !creator.isEmpty { recordData["creator"] = .string(creator) }
            if !lastModifiedBy.isEmpty { recordData["last_modified_by"] = .string(lastModifiedBy) }
            if !created.isEmpty { recordData["created_iso"] = .string(created) }
            if !modified.isEmpty { recordData["modified_iso"] = .string(modified) }
            if !title.isEmpty { recordData["title"] = .string(title) }

            let record = ArtifactRecord(
                caseID: caseContext.caseID,
                pluginID: Self.manifest.id,
                pluginVersion: Self.manifest.version,
                schemaVersion: Self.manifest.schemaVersion,
                contentType: "office.document",
                sourcePath: url.path,
                sha256: sha,
                observedAt: now,
                capturedAt: now,
                summary: "\(ext.uppercased()) \(url.lastPathComponent)\(hasMacro ? " ⚠️ macros" : "")",
                sizeBytes: Int64(data.count),
                confidence: .observed,
                privacyClass: .metadata,
                actor: NSUserName(),
                data: recordData
            )
            do { try await output.commit(record); committed += 1 } catch { rejected += 1 }
        }
        return CollectionResult(
            artifactsCommitted: committed,
            artifactsRejected: rejected,
            notes: ["Office analyzer: \(committed) documents analyzed"],
            status: .ok
        )
    }

    /// Extract the inner text of an XML tag by suffix (handles
    /// namespaced tags like <dc:creator>...</dc:creator>).
    static func xmlValue(from xml: String, tagSuffix: String) -> String {
        // Match: `<...:tagSuffix>VALUE</...:tagSuffix>` or
        // `<tagSuffix>VALUE</tagSuffix>`.
        let pattern = "<(?:[a-zA-Z0-9_]+:)?\(tagSuffix)>([^<]*)</(?:[a-zA-Z0-9_]+:)?\(tagSuffix)>"
        guard let regex = try? NSRegularExpression(pattern: pattern, options: []) else { return "" }
        let ns = xml as NSString
        let matches = regex.matches(in: xml, range: NSRange(location: 0, length: ns.length))
        guard let m = matches.first, m.numberOfRanges >= 2 else { return "" }
        return ns.substring(with: m.range(at: 1))
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
