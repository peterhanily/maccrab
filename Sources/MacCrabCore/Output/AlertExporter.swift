// AlertExporter.swift
// MacCrabCore
//
// Unified alert exporter supporting multiple output formats with filtering.
// Supports SARIF, CEF, LEEF, CSV, JSON, and STIX 2.1 formats.

import Foundation
import os.log

/// Unified alert exporter supporting multiple output formats with filtering.
public actor AlertExporter {
    private let logger = Logger(subsystem: "com.maccrab.output", category: "alert-exporter")

    // MARK: - Types

    public enum ExportFormat: String, Sendable, CaseIterable {
        case json = "json"
        case csv = "csv"
        case sarif = "sarif"        // GitHub Code Scanning compatible
        case cef = "cef"            // ArcSight Common Event Format
        case leef = "leef"          // QRadar Log Event Extended Format
        case stix = "stix"          // STIX 2.1 bundle
        case syslogCEF = "syslog-cef"  // CEF over syslog
        case ocsf = "ocsf"          // OCSF 1.3 Security Finding (JSONL, one per line)

        /// File extension for this format.
        public var fileExtension: String {
            switch self {
            case .json: return "json"
            case .csv: return "csv"
            case .sarif: return "sarif.json"
            case .cef, .syslogCEF: return "cef"
            case .leef: return "leef"
            case .stix: return "json"
            case .ocsf: return "ocsf.jsonl"
            }
        }

        /// Human-readable display name.
        public var displayName: String {
            switch self {
            case .json: return "JSON"
            case .csv: return "CSV"
            case .sarif: return "SARIF (GitHub)"
            case .cef: return "CEF (ArcSight)"
            case .leef: return "LEEF (QRadar)"
            case .stix: return "STIX 2.1"
            case .syslogCEF: return "Syslog CEF"
            case .ocsf: return "OCSF 1.3 (JSONL)"
            }
        }
    }

    public struct ExportFilter: Sendable {
        public var minSeverity: String?         // "critical", "high", "medium", "low"
        public var maxAge: TimeInterval?         // Seconds (e.g., 86400 for 24h)
        public var ruleIdPrefix: String?         // e.g., "maccrab.ai-guard"
        public var processNameContains: String?
        public var mitreCategory: String?        // e.g., "credential_access"
        public var limit: Int?

        public init(
            minSeverity: String? = nil,
            maxAge: TimeInterval? = nil,
            ruleIdPrefix: String? = nil,
            processNameContains: String? = nil,
            mitreCategory: String? = nil,
            limit: Int? = nil
        ) {
            self.minSeverity = minSeverity
            self.maxAge = maxAge
            self.ruleIdPrefix = ruleIdPrefix
            self.processNameContains = processNameContains
            self.mitreCategory = mitreCategory
            self.limit = limit
        }
    }

    public struct ExportableAlert: Sendable {
        public let id: String
        public let timestamp: Date
        public let ruleId: String
        public let ruleTitle: String
        public let severity: String
        public let processName: String
        public let processPath: String
        public let description: String
        public let mitreTactics: String
        public let mitreTechniques: String

        public init(
            id: String,
            timestamp: Date,
            ruleId: String,
            ruleTitle: String,
            severity: String,
            processName: String,
            processPath: String,
            description: String,
            mitreTactics: String,
            mitreTechniques: String
        ) {
            self.id = id
            self.timestamp = timestamp
            self.ruleId = ruleId
            self.ruleTitle = ruleTitle
            self.severity = severity
            self.processName = processName
            self.processPath = processPath
            self.description = description
            self.mitreTactics = mitreTactics
            self.mitreTechniques = mitreTechniques
        }
    }

    // MARK: - Initialization

    public init() {}

    // MARK: - Conversion from Alert model

    /// Convert a MacCrabCore `Alert` into an `ExportableAlert`.
    public static func exportable(from alert: Alert) -> ExportableAlert {
        ExportableAlert(
            id: alert.id,
            timestamp: alert.timestamp,
            ruleId: alert.ruleId,
            ruleTitle: alert.ruleTitle,
            severity: alert.severity.rawValue,
            processName: alert.processName ?? "unknown",
            processPath: alert.processPath ?? "",
            description: alert.description ?? "",
            mitreTactics: alert.mitreTactics ?? "",
            mitreTechniques: alert.mitreTechniques ?? ""
        )
    }

    // MARK: - Export

    /// Export alerts in the specified format with optional filtering.
    public func export(
        alerts: [ExportableAlert],
        format: ExportFormat,
        filter: ExportFilter? = nil
    ) -> String {
        var filtered = alerts

        if let f = filter {
            if let minSev = f.minSeverity {
                let order = ["informational", "low", "medium", "high", "critical"]
                let minIdx = order.firstIndex(of: minSev.lowercased()) ?? 0
                filtered = filtered.filter { order.firstIndex(of: $0.severity.lowercased()) ?? 0 >= minIdx }
            }
            if let maxAge = f.maxAge {
                let cutoff = Date().addingTimeInterval(-maxAge)
                filtered = filtered.filter { $0.timestamp >= cutoff }
            }
            if let prefix = f.ruleIdPrefix {
                filtered = filtered.filter { $0.ruleId.hasPrefix(prefix) }
            }
            if let proc = f.processNameContains {
                filtered = filtered.filter { $0.processName.lowercased().contains(proc.lowercased()) }
            }
            if let mitre = f.mitreCategory {
                filtered = filtered.filter { $0.mitreTactics.contains(mitre) }
            }
            if let limit = f.limit {
                filtered = Array(filtered.prefix(limit))
            }
        }

        let result: String
        switch format {
        case .json:       result = exportJSON(filtered)
        case .csv:        result = exportCSV(filtered)
        case .sarif:      result = exportSARIF(filtered)
        case .cef:        result = exportCEF(filtered)
        case .leef:       result = exportLEEF(filtered)
        case .stix:       result = exportSTIX(filtered)
        case .syslogCEF:  result = exportCEF(filtered) // Same format, different transport
        case .ocsf:       result = exportOCSF(filtered)
        }

        logger.info("Exported \(filtered.count) alerts in \(format.rawValue) format")
        return result
    }

    /// Export `Alert` model objects directly (convenience wrapper).
    public func export(
        coreAlerts: [Alert],
        format: ExportFormat,
        filter: ExportFilter? = nil
    ) -> String {
        let exportable = coreAlerts.map { Self.exportable(from: $0) }
        return export(alerts: exportable, format: format, filter: filter)
    }

    // MARK: - JSON

    private func exportJSON(_ alerts: [ExportableAlert]) -> String {
        let df = ISO8601DateFormatter()
        let dicts = alerts.map { a -> [String: Any] in
            [
                "id": a.id,
                "timestamp": df.string(from: a.timestamp),
                "rule_id": a.ruleId,
                "rule_title": a.ruleTitle,
                "severity": a.severity,
                "process_name": a.processName,
                "process_path": a.processPath,
                "description": a.description,
                "mitre_tactics": a.mitreTactics,
                "mitre_techniques": a.mitreTechniques,
            ]
        }
        guard let data = try? JSONSerialization.data(
            withJSONObject: dicts,
            options: [.prettyPrinted, .sortedKeys]
        ), let str = String(data: data, encoding: .utf8) else {
            return "[]"
        }
        return str
    }

    // MARK: - OCSF (Open Cybersecurity Schema Framework 1.3)

    /// Emit one OCSF Security Finding (class_uid 2004) per line — JSONL
    /// format suited to SIEM bulk-ingest pipelines. Each line is a complete,
    /// self-contained OCSF record.
    private func exportOCSF(_ alerts: [ExportableAlert]) -> String {
        var lines: [String] = []
        lines.reserveCapacity(alerts.count)
        for a in alerts {
            let alert = Alert(
                id: a.id,
                timestamp: a.timestamp,
                ruleId: a.ruleId,
                ruleTitle: a.ruleTitle,
                severity: Severity(rawValue: a.severity) ?? .informational,
                eventId: "",
                processPath: a.processPath,
                processName: a.processName,
                description: a.description,
                mitreTactics: a.mitreTactics.isEmpty ? nil : a.mitreTactics,
                mitreTechniques: a.mitreTechniques.isEmpty ? nil : a.mitreTechniques
            )
            let finding = OCSFMapper.mapAlert(alert)
            if let json = try? OCSFMapper.encodeJSON(finding) {
                lines.append(json)
            }
        }
        return lines.joined(separator: "\n")
    }

    // MARK: - CSV

    private func exportCSV(_ alerts: [ExportableAlert]) -> String {
        var csv = "id,timestamp,severity,rule_id,rule_title,process_name,process_path,mitre_techniques,description\n"
        let df = ISO8601DateFormatter()
        for a in alerts {
            let fields = [
                a.id,
                df.string(from: a.timestamp),
                a.severity,
                a.ruleId,
                csvEscape(a.ruleTitle),
                csvEscape(a.processName),
                csvEscape(a.processPath),
                csvEscape(a.mitreTechniques),
                csvEscape(a.description),
            ]
            csv += fields.joined(separator: ",") + "\n"
        }
        return csv
    }

    // MARK: - SARIF (Static Analysis Results Interchange Format v2.1.0)

    private func exportSARIF(_ alerts: [ExportableAlert]) -> String {
        let df = ISO8601DateFormatter()

        let results = alerts.map { a -> [String: Any] in
            let level: String
            switch a.severity.lowercased() {
            case "critical", "high": level = "error"
            case "medium": level = "warning"
            default: level = "note"
            }
            return [
                "ruleId": a.ruleId,
                "level": level,
                "message": ["text": a.ruleTitle + ": " + a.description],
                "locations": [[
                    "physicalLocation": [
                        "artifactLocation": [
                            "uri": a.processPath.isEmpty ? "unknown" : "file://" + a.processPath
                        ],
                        "region": ["startLine": 1],
                    ] as [String: Any]
                ]],
                "properties": [
                    "severity": a.severity,
                    "processName": a.processName,
                    "mitreTactics": a.mitreTactics,
                    "mitreTechniques": a.mitreTechniques,
                    "timestamp": df.string(from: a.timestamp),
                ] as [String: Any],
            ] as [String: Any]
        }

        let rules = Dictionary(grouping: alerts, by: \.ruleId).map { (ruleId, grouped) -> [String: Any] in
            [
                "id": ruleId,
                "name": grouped.first?.ruleTitle ?? ruleId,
                "shortDescription": ["text": grouped.first?.ruleTitle ?? ""],
                "helpUri": "https://github.com/peterhanily/maccrab",
            ]
        }

        let sarif: [String: Any] = [
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [[
                "tool": [
                    "driver": [
                        "name": "MacCrab",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/peterhanily/maccrab",
                        "rules": rules,
                    ] as [String: Any]
                ],
                "results": results,
            ] as [String: Any]],
        ]

        guard let data = try? JSONSerialization.data(
            withJSONObject: sarif,
            options: [.prettyPrinted, .sortedKeys]
        ), let str = String(data: data, encoding: .utf8) else {
            return "{}"
        }
        return str
    }

    // MARK: - CEF (Common Event Format — ArcSight)

    private func exportCEF(_ alerts: [ExportableAlert]) -> String {
        let df = ISO8601DateFormatter()
        return alerts.map { a in
            let severity: Int
            switch a.severity.lowercased() {
            case "critical": severity = 10
            case "high": severity = 7
            case "medium": severity = 4
            case "low": severity = 1
            default: severity = 0
            }
            // CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extensions
            let extensions = [
                "rt=\(df.string(from: a.timestamp))",
                "dproc=\(cefEscape(a.processName))",
                "filePath=\(cefEscape(a.processPath))",
                "cs1=\(cefEscape(a.mitreTechniques))",
                "cs1Label=MITRE",
                "msg=\(cefEscape(String(a.description.prefix(400))))",
            ].joined(separator: " ")
            return "CEF:0|MacCrab|MacCrab|1.0.0|\(cefEscape(a.ruleId))|\(cefEscape(a.ruleTitle))|\(severity)|\(extensions)"
        }.joined(separator: "\n")
    }

    // MARK: - LEEF (Log Event Extended Format — QRadar)

    private func exportLEEF(_ alerts: [ExportableAlert]) -> String {
        let df = ISO8601DateFormatter()
        return alerts.map { a in
            let severity: String
            switch a.severity.lowercased() {
            case "critical": severity = "10"
            case "high": severity = "7"
            case "medium": severity = "4"
            default: severity = "1"
            }
            // LEEF:Version|Vendor|Product|Version|EventID|
            let fields = [
                "devTime=\(df.string(from: a.timestamp))",
                "sev=\(severity)",
                "cat=\(a.mitreTactics)",
                "procName=\(a.processName)",
                "filePath=\(a.processPath)",
                "msg=\(String(a.description.prefix(400)))",
            ].joined(separator: "\t")
            return "LEEF:2.0|MacCrab|MacCrab|1.0.0|\(a.ruleId)|\t\(fields)"
        }.joined(separator: "\n")
    }

    // MARK: - STIX 2.1

    private func exportSTIX(_ alerts: [ExportableAlert]) -> String {
        let df = ISO8601DateFormatter()
        let objects = alerts.map { a -> [String: Any] in
            [
                "type": "sighting",
                "spec_version": "2.1",
                "id": "sighting--\(UUID().uuidString)",
                "created": df.string(from: a.timestamp),
                "modified": df.string(from: a.timestamp),
                "first_seen": df.string(from: a.timestamp),
                "description": "\(a.ruleTitle): \(String(a.description.prefix(300)))",
                "sighting_of_ref": "indicator--\(UUID().uuidString)",
                "where_sighted_refs": ["identity--maccrab-host"],
                "custom_properties": [
                    "x_maccrab_rule_id": a.ruleId,
                    "x_maccrab_severity": a.severity,
                    "x_maccrab_process": a.processName,
                ] as [String: String],
            ] as [String: Any]
        }
        let bundle: [String: Any] = [
            "type": "bundle",
            "id": "bundle--\(UUID().uuidString)",
            "objects": objects,
        ]
        guard let data = try? JSONSerialization.data(
            withJSONObject: bundle,
            options: .prettyPrinted
        ), let str = String(data: data, encoding: .utf8) else {
            return "{}"
        }
        return str
    }

    // MARK: - Helpers

    private func csvEscape(_ s: String) -> String {
        if s.contains(",") || s.contains("\"") || s.contains("\n") {
            return "\"" + s.replacingOccurrences(of: "\"", with: "\"\"") + "\""
        }
        return s
    }

    private func cefEscape(_ s: String) -> String {
        s.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "|", with: "\\|")
            .replacingOccurrences(of: "=", with: "\\=")
            .replacingOccurrences(of: "\n", with: " ")
    }
}
