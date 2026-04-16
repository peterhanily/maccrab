// StreamOutputTests.swift
// Framing coverage for Splunk HEC / Elastic Bulk / Datadog Logs bodies.
// HTTP transport itself is exercised by integration tests; here we
// verify the body shape each SIEM expects.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("StreamOutput framing")
struct StreamOutputFramingTests {

    private func alertAndEvent() -> (Alert, Event) {
        let proc = MacCrabCore.ProcessInfo(
            pid: 1234, ppid: 1, rpid: 1,
            name: "curl", executable: "/usr/bin/curl",
            commandLine: "curl https://example.com",
            args: [], workingDirectory: "/tmp",
            userId: 501, userName: "alice", groupId: 20,
            startTime: Date(timeIntervalSince1970: 1_712_500_000)
        )
        let event = Event(
            eventCategory: .process, eventType: .start,
            eventAction: "exec", process: proc
        )
        let alert = Alert(
            id: "alert-x",
            timestamp: Date(timeIntervalSince1970: 1_712_500_000),
            ruleId: "rule.test", ruleTitle: "Test",
            severity: .critical, eventId: event.id.uuidString,
            description: "test", mitreTactics: "TA0005", mitreTechniques: "T1562"
        )
        return (alert, event)
    }

    // MARK: - Splunk HEC

    @Test("Splunk HEC body is JSON with event + sourcetype + time keys")
    func splunkHECFrame() async throws {
        let out = StreamOutput(
            kind: .splunkHEC,
            url: URL(string: "https://hec.example.com")!,
            token: "secret"
        )
        let (a, e) = alertAndEvent()
        let data = try #require(await out.buildBody(alert: a, event: e))
        let obj = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])

        #expect(obj["sourcetype"] as? String == "maccrab:alert")
        #expect(obj["time"] as? Double == 1_712_500_000.0)
        let event = try #require(obj["event"] as? [String: Any])
        #expect(event["class_uid"] as? Int == 2004)
    }

    @Test("Splunk HEC respects custom indexName as sourcetype")
    func splunkHECCustomSourcetype() async throws {
        let out = StreamOutput(
            kind: .splunkHEC,
            url: URL(string: "https://hec.example.com")!,
            token: "secret",
            indexName: "custom:mctest"
        )
        let (a, e) = alertAndEvent()
        let data = try #require(await out.buildBody(alert: a, event: e))
        let obj = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(obj["sourcetype"] as? String == "custom:mctest")
    }

    // MARK: - Elastic Bulk

    @Test("Elastic Bulk body is NDJSON with index action + doc on separate lines")
    func elasticBulkFrame() async throws {
        let out = StreamOutput(
            kind: .elasticBulk,
            url: URL(string: "https://es.example.com/_bulk")!,
            token: "ApiKey Zm9vOmJhcg=="
        )
        let (a, e) = alertAndEvent()
        let data = try #require(await out.buildBody(alert: a, event: e))
        let body = try #require(String(data: data, encoding: .utf8))

        let lines = body.split(separator: "\n", omittingEmptySubsequences: false)
        #expect(lines.count >= 2, "Bulk body needs at least two lines")

        // Line 0: the action header
        let action = try #require(try JSONSerialization.jsonObject(with: Data(lines[0].utf8)) as? [String: Any])
        let indexInfo = try #require(action["index"] as? [String: Any])
        #expect(indexInfo["_index"] as? String == "maccrab-alerts")

        // Line 1: the actual finding doc
        let doc = try #require(try JSONSerialization.jsonObject(with: Data(lines[1].utf8)) as? [String: Any])
        #expect(doc["class_uid"] as? Int == 2004)
    }

    @Test("Elastic Bulk respects custom index name")
    func elasticBulkCustomIndex() async throws {
        let out = StreamOutput(
            kind: .elasticBulk,
            url: URL(string: "https://es.example.com/_bulk")!,
            token: nil,
            indexName: "sec-events-2026"
        )
        let (a, e) = alertAndEvent()
        let data = try #require(await out.buildBody(alert: a, event: e))
        let body = try #require(String(data: data, encoding: .utf8))
        #expect(body.contains("\"_index\":\"sec-events-2026\""))
    }

    // MARK: - Datadog

    @Test("Datadog Logs body is single-element array with ddsource + message")
    func datadogFrame() async throws {
        let out = StreamOutput(
            kind: .datadogLogs,
            url: URL(string: "https://http-intake.logs.datadoghq.com/api/v2/logs")!,
            token: "dd-key"
        )
        let (a, e) = alertAndEvent()
        let data = try #require(await out.buildBody(alert: a, event: e))
        let arr = try #require(try JSONSerialization.jsonObject(with: data) as? [[String: Any]])
        #expect(arr.count == 1)
        #expect(arr[0]["ddsource"] as? String == "maccrab")
        let msg = try #require(arr[0]["message"] as? [String: Any])
        #expect(msg["class_uid"] as? Int == 2004)
    }

    // MARK: - Wazuh API

    @Test("Wazuh API body wraps the finding as a stringified events array")
    func wazuhFrame() async throws {
        let out = StreamOutput(
            kind: .wazuhAPI,
            url: URL(string: "https://wazuh.example.com:55000/events")!,
            token: "jwt-xyz"
        )
        let (a, e) = alertAndEvent()
        let data = try #require(await out.buildBody(alert: a, event: e))
        let obj = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        let events = try #require(obj["events"] as? [String])
        #expect(events.count == 1)
        #expect(events[0].contains("\"class_uid\":2004"))
    }

    // MARK: - Protocol conformance

    @Test("StreamOutput conforms to Output with kind-derived name")
    func protocolConformance() async {
        let splunk: any Output = StreamOutput(
            kind: .splunkHEC, url: URL(string: "https://x")!, token: nil
        )
        #expect(splunk.name == "splunk_hec")

        let elastic: any Output = StreamOutput(
            kind: .elasticBulk, url: URL(string: "https://x")!, token: nil
        )
        #expect(elastic.name == "elastic_bulk")
    }

    @Test("Default index names per Kind")
    func defaultIndexNames() async throws {
        // Splunk → maccrab:alert
        let s = StreamOutput(kind: .splunkHEC, url: URL(string: "https://x")!, token: nil)
        let sBody = try #require(await s.buildBody(alert: alertAndEvent().0, event: alertAndEvent().1))
        let sObj = try JSONSerialization.jsonObject(with: sBody) as? [String: Any]
        #expect(sObj?["sourcetype"] as? String == "maccrab:alert")

        // Elastic → maccrab-alerts
        let e = StreamOutput(kind: .elasticBulk, url: URL(string: "https://x")!, token: nil)
        let eBody = try #require(await e.buildBody(alert: alertAndEvent().0, event: alertAndEvent().1))
        let eStr = try #require(String(data: eBody, encoding: .utf8))
        #expect(eStr.contains("\"_index\":\"maccrab-alerts\""))
    }
}
