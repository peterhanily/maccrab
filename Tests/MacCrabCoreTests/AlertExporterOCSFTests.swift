// AlertExporterOCSFTests.swift
// Verifies AlertExporter emits OCSF-formatted output via the new `.ocsf` case.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("AlertExporter OCSF")
struct AlertExporterOCSFTests {

    private func makeAlert(
        id: String = "alert-test",
        severity: Severity = .high,
        ruleId: String = "rule.test",
        mitreTactics: String? = "TA0005",
        mitreTechniques: String? = "T1562.001"
    ) -> Alert {
        Alert(
            id: id,
            timestamp: Date(timeIntervalSince1970: 1_712_345_678),
            ruleId: ruleId,
            ruleTitle: "Test rule",
            severity: severity,
            eventId: "evt",
            processPath: "/usr/bin/suspicious",
            processName: "suspicious",
            description: "Bad things happened",
            mitreTactics: mitreTactics,
            mitreTechniques: mitreTechniques
        )
    }

    @Test("OCSF export produces JSONL with class_uid 2004 per line")
    func jsonlShape() async throws {
        let exporter = AlertExporter()
        let alerts = [makeAlert(id: "a1"), makeAlert(id: "a2")]
        let out = await exporter.export(coreAlerts: alerts, format: .ocsf)

        let lines = out.split(separator: "\n")
        #expect(lines.count == 2)
        for line in lines {
            #expect(line.contains("\"class_uid\":2004"))
            #expect(line.contains("\"category_uid\":2"))
        }
    }

    @Test("OCSF export embeds MITRE ATT&CK attack block")
    func attackBlock() async throws {
        let exporter = AlertExporter()
        let out = await exporter.export(
            coreAlerts: [makeAlert()],
            format: .ocsf
        )
        #expect(out.contains("\"attacks\""))
        #expect(out.contains("\"TA0005\""))
        #expect(out.contains("\"T1562.001\""))
    }

    @Test("OCSF export maps severity correctly")
    func severityMapping() async throws {
        let exporter = AlertExporter()
        let out = await exporter.export(
            coreAlerts: [makeAlert(severity: .critical)],
            format: .ocsf
        )
        #expect(out.contains("\"severity\":\"Critical\""))
        #expect(out.contains("\"severity_id\":5"))
    }

    @Test("OCSF export uses snake_case keys, never camelCase")
    func snakeCase() async throws {
        let exporter = AlertExporter()
        let out = await exporter.export(coreAlerts: [makeAlert()], format: .ocsf)
        #expect(out.contains("class_uid"))
        #expect(out.contains("type_uid"))
        #expect(!out.contains("classUid"))
        #expect(!out.contains("typeUid"))
    }

    @Test("OCSF format is enumerable and has correct metadata")
    func formatMetadata() {
        #expect(AlertExporter.ExportFormat.allCases.contains(.ocsf))
        #expect(AlertExporter.ExportFormat.ocsf.fileExtension == "ocsf.jsonl")
        #expect(AlertExporter.ExportFormat.ocsf.displayName == "OCSF 1.3 (JSONL)")
    }

    @Test("Empty alert list produces empty OCSF output")
    func emptyInput() async throws {
        let exporter = AlertExporter()
        let out = await exporter.export(coreAlerts: [], format: .ocsf)
        #expect(out.isEmpty)
    }
}
