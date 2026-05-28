// ArtifactExporter — CSV + JSON export for a scan's artifacts.
// Modeled on AlertExporter (Sources/MacCrabCore/Output/) — same
// surface area, same flatten-JSON-to-columns approach.
//
// Output paths land in ~/Downloads/<scan-id>-<timestamp>.{csv,json}
// so the operator can hand the file directly to a forensic
// pipeline (Splunk, Sumo, Elastic) without further wrangling.

import Foundation
import MacCrabForensics
import AppKit

public enum ArtifactExporter {

    public enum Format: String, Sendable, CaseIterable {
        case json
        case csv
    }

    public enum ExportError: Error, CustomStringConvertible {
        case noArtifacts
        case writeFailed(String)
        public var description: String {
            switch self {
            case .noArtifacts: return "No artifacts to export."
            case .writeFailed(let s): return "Couldn't write file: \(s)"
            }
        }
    }

    /// Export the artifacts to ~/Downloads. Returns the URL of the
    /// file written so the caller can reveal in Finder.
    @discardableResult
    public static func export(
        artifacts: [CommittedArtifact],
        scanID: String,
        scanName: String,
        format: Format
    ) throws -> URL {
        guard !artifacts.isEmpty else { throw ExportError.noArtifacts }

        let fm = FileManager.default
        let downloads = fm.urls(for: .downloadsDirectory, in: .userDomainMask).first
            ?? fm.homeDirectoryForCurrentUser.appendingPathComponent("Downloads")
        let timestamp = DateFormatter.exportStamp.string(from: Date())
        let safeName = scanName
            .replacingOccurrences(of: "/", with: "-")
            .replacingOccurrences(of: ":", with: "-")
        let filename = "\(safeName)-\(timestamp).\(format.rawValue)"
        let url = downloads.appendingPathComponent(filename)

        let bytes: Data
        switch format {
        case .json:
            bytes = try renderJSON(artifacts: artifacts, scanID: scanID, scanName: scanName)
        case .csv:
            bytes = try renderCSV(artifacts: artifacts)
        }

        do {
            try bytes.write(to: url, options: [.atomic])
        } catch {
            throw ExportError.writeFailed("\(error)")
        }
        return url
    }

    // MARK: - JSON

    private static func renderJSON(artifacts: [CommittedArtifact], scanID: String, scanName: String) throws -> Data {
        var rows: [[String: Any]] = []
        for a in artifacts {
            var row: [String: Any] = [
                "id": Int(a.id),
                "case_id": a.record.caseID,
                "plugin_id": a.record.pluginID,
                "plugin_version": a.record.pluginVersion,
                "content_type": a.record.contentType,
                "schema_version": a.record.schemaVersion,
                "observed_at": ISO8601DateFormatter().string(from: a.record.observedAt),
                "captured_at": ISO8601DateFormatter().string(from: a.record.capturedAt),
                "summary": a.record.summary ?? NSNull(),
                "source_path": a.record.sourcePath ?? NSNull(),
                "sha256": a.record.sha256,
                "privacy_class": a.record.privacyClass.rawValue,
                "confidence": a.record.confidence.rawValue,
                "severity": FindingHeuristics.severity(for: a).rawValue,
                "data": jsonObject(from: a.record.data),
            ]
            if let actor = a.record.actor { row["actor"] = actor }
            rows.append(row)
        }
        let envelope: [String: Any] = [
            "exported_at": ISO8601DateFormatter().string(from: Date()),
            "exported_by": "MacCrab (ArtifactExporter)",
            "scan_id": scanID,
            "scan_name": scanName,
            "artifact_count": artifacts.count,
            "artifacts": rows,
        ]
        return try JSONSerialization.data(
            withJSONObject: envelope,
            options: [.prettyPrinted, .sortedKeys]
        )
    }

    /// Materialize a [String: JSONValue] into a Foundation tree
    /// JSONSerialization will accept.
    private static func jsonObject(from data: [String: JSONValue]) -> [String: Any] {
        var out: [String: Any] = [:]
        for (k, v) in data {
            out[k] = jsonAny(v)
        }
        return out
    }

    private static func jsonAny(_ v: JSONValue) -> Any {
        switch v {
        case .string(let s):  return s
        case .integer(let i): return i
        case .double(let d):  return d
        case .bool(let b):    return b
        case .null:           return NSNull()
        case .array(let arr): return arr.map { jsonAny($0) }
        case .object(let o):  return jsonObject(from: o)
        }
    }

    // MARK: - CSV

    /// Flatten artifacts to CSV. Columns: stable record fields
    /// first (id, observed_at, plugin_id, content_type, summary,
    /// severity), then a dynamic union of all data field keys.
    /// Nested objects + arrays serialize as JSON strings within
    /// their cell so the output remains a single CSV table.
    private static func renderCSV(artifacts: [CommittedArtifact]) throws -> Data {
        let recordCols = [
            "id", "observed_at", "plugin_id", "content_type",
            "summary", "severity", "privacy_class", "sha256",
        ]
        var dataKeys = Set<String>()
        for a in artifacts {
            for k in a.record.data.keys { dataKeys.insert(k) }
        }
        let dataCols = dataKeys.sorted()
        let allCols = recordCols + dataCols

        var lines: [String] = [allCols.map(csvEscape).joined(separator: ",")]
        let iso = ISO8601DateFormatter()
        for a in artifacts {
            var values: [String] = [
                "\(a.id)",
                iso.string(from: a.record.observedAt),
                a.record.pluginID,
                a.record.contentType,
                a.record.summary ?? "",
                FindingHeuristics.severity(for: a).rawValue,
                a.record.privacyClass.rawValue,
                a.record.sha256,
            ]
            for k in dataCols {
                values.append(csvCell(for: a.record.data[k]))
            }
            lines.append(values.map(csvEscape).joined(separator: ","))
        }
        return Data((lines.joined(separator: "\n") + "\n").utf8)
    }

    private static func csvCell(for v: JSONValue?) -> String {
        guard let v else { return "" }
        switch v {
        case .string(let s):  return s
        case .integer(let i): return "\(i)"
        case .double(let d):  return "\(d)"
        case .bool(let b):    return b ? "true" : "false"
        case .null:           return ""
        case .array, .object:
            // Embed JSON sub-tree in the cell — operators run csvkit /
            // jq downstream and routinely parse mixed-mode columns.
            if let data = try? JSONSerialization.data(
                withJSONObject: jsonAny(v),
                options: [.sortedKeys]
            ),
            let s = String(data: data, encoding: .utf8) {
                return s
            }
            return ""
        }
    }

    private static func csvEscape(_ s: String) -> String {
        if s.contains(",") || s.contains("\"") || s.contains("\n") {
            let escaped = s.replacingOccurrences(of: "\"", with: "\"\"")
            return "\"\(escaped)\""
        }
        return s
    }

    /// Reveal the exported file in Finder.
    public static func revealInFinder(_ url: URL) {
        NSWorkspace.shared.activateFileViewerSelecting([url])
    }
}

private extension DateFormatter {
    static let exportStamp: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd-HHmmss"
        return f
    }()
}
