// DocumentAnalyzerPlugin — com.maccrab.forensics.document-analyzer.
//
// Plan §13.7. PDF dissection via PDFKit. Office formats
// (.docx / .xlsx / .pptx — OPC-zip-XML) are deferred to a
// follow-up sub-slice; their content extraction is heavier
// engineering and not in scope for v1.16.

import Foundation
import PDFKit
import CryptoKit

public struct DocumentAnalyzerPlugin: Collector {

    public static let manifest = PluginManifest(
        id: "com.maccrab.forensics.document-analyzer",
        version: "1.0.0",
        displayName: "Document Analyzer",
        description: "PDF dissection via PDFKit: page count + metadata (Author / Producer / Creator / CreationDate / ModDate) + embedded-JS detection. Office formats (.docx / .xlsx / .pptx) deferred to a follow-up sub-slice.",
        type: .collector,
        runtime: .tierA,
        tccRequirements: [],
        inputs: [],
        outputs: [
            OutputSpec(
                contentType: "document.analysis",
                privacyClass: .metadata,
                viewerHint: ViewerHint(
                    viewer: .keyvalue,
                    fieldRoles: [
                        "filename": .title,
                        "path": .path,
                        "author": .subtitle,
                        "page_count": .count,
                        "size_bytes": .count,
                        "creation_date_iso": .timestamp,
                        "modification_date_iso": .timestamp,
                        "has_javascript": .status,
                        "has_embedded_file": .status,
                        "sha256": .identifier,
                    ]
                )
            ),
        ],
        mcpTools: [
            MCPToolDescriptor(
                name: "document_analyze_path",
                description: "Analyze a PDF document: page count + metadata + embedded JS detection.",
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
        for url in urls where url.pathExtension.lowercased() == "pdf" {
            guard let data = try? Data(contentsOf: url) else { continue }
            let sha = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
            guard let pdf = PDFDocument(url: url) else { continue }
            let pageCount = pdf.pageCount
            let attrs = pdf.documentAttributes ?? [:]
            let author = attrs[PDFDocumentAttribute.authorAttribute] as? String ?? ""
            let producer = attrs[PDFDocumentAttribute.producerAttribute] as? String ?? ""
            let creator = attrs[PDFDocumentAttribute.creatorAttribute] as? String ?? ""
            let creationDate = (attrs[PDFDocumentAttribute.creationDateAttribute] as? Date).map { ISO8601DateFormatter().string(from: $0) } ?? ""
            let modDate = (attrs[PDFDocumentAttribute.modificationDateAttribute] as? Date).map { ISO8601DateFormatter().string(from: $0) } ?? ""
            // Embedded-JS detection: PDFDocument's allowsCommenting
            // / allowsContentAccessibility / allowsFormFieldEntry
            // don't expose JS directly; a substring search on the
            // raw PDF for "/JS" or "/JavaScript" is the
            // operator-grade signal.
            let hasJS = data.range(of: Data("/JavaScript".utf8)) != nil
                || data.range(of: Data("/JS".utf8)) != nil
            let hasEmbeddedFile = data.range(of: Data("/EmbeddedFile".utf8)) != nil

            let recordData: [String: JSONValue] = [
                "path": .string(url.path),
                "filename": .string(url.lastPathComponent),
                "size_bytes": .integer(Int64(data.count)),
                "page_count": .integer(Int64(pageCount)),
                "author": .string(author),
                "producer": .string(producer),
                "creator": .string(creator),
                "creation_date_iso": .string(creationDate),
                "modification_date_iso": .string(modDate),
                "has_javascript": .bool(hasJS),
                "has_embedded_file": .bool(hasEmbeddedFile),
                "sha256": .string(sha),
            ]
            let record = ArtifactRecord(
                caseID: caseContext.caseID,
                pluginID: Self.manifest.id,
                pluginVersion: Self.manifest.version,
                schemaVersion: Self.manifest.schemaVersion,
                contentType: "document.analysis",
                sourcePath: url.path,
                sha256: sha,
                observedAt: now,
                capturedAt: now,
                summary: "PDF \(url.lastPathComponent): \(pageCount) pages\(hasJS ? " (contains JS)" : "")\(hasEmbeddedFile ? " (embedded file)" : "")",
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
            notes: ["PDF analyzer: \(committed) documents analyzed. Office formats (DOCX/XLSX/PPTX) deferred."],
            status: .ok
        )
    }
}
