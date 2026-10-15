import CryptoKit
import Foundation
import Testing
@testable import MacCrabCore

@Suite("Encode-only wire compatibility")
struct EncodeOnlyCompatibilityTests {
    #if DEBUG
    @Test("Synthetic Metadata.v2 known answer preserves canonical bytes and every hash input")
    func journalMetadataGoldenDigest() throws {
        // Synthetic known-answer fixture, NOT a retained production capture.
        // This literal independently pins the historical sorted-key field names,
        // category order and omission of absent optional category bounds.
        let canonical = #"{"admissionBucket":42,"categories":[{"category":"process","count":2,"maximum":103.5,"minimum":100.25},{"category":"file","count":0},{"category":"network","count":1,"maximum":102.5,"minimum":102.5},{"category":"authentication","count":0},{"category":"tcc","count":0},{"category":"registry","count":0}],"codec":1,"eventCount":3,"maximum":103.5,"minimum":100.25,"rawBytes":1234,"retainedUntil":1000.75,"version":2}"#
        let roster = Data((0..<48).map(UInt8.init))
        let identities = Data((0..<96).map(UInt8.init))
        let payload = Data(repeating: 0xaa, count: 32)
        let expectedHex = "cab4cf6affa6d18b1c0da1065f0b6b8ac25c6e748687473bb7305d66154b5cda"
        var historicalInput = Data("MacCrab.EventJournal.Metadata.v2\0".utf8)
        historicalInput.append(Data(canonical.utf8))
        historicalInput.append(roster)
        historicalInput.append(identities)
        historicalInput.append(payload)
        let independentlyHashed = SHA256.hash(data: historicalInput)
            .map { String(format: "%02x", $0) }.joined()
        #expect(independentlyHashed == expectedHex)

        func digest(rosterBytes: Data? = nil, identityBytes: Data? = nil,
                    payloadBytes: Data? = nil, eventCount: Int = 3) throws -> Data {
            try EventStore.journalMetadataDigestForTesting(
                minimum: 100.25, maximum: 103.5, retainedUntil: 1000.75,
                admissionBucket: 42,
                categories: [.process: (2, 100.25, 103.5), .network: (1, 102.5, 102.5)],
                eventCount: eventCount, roster: rosterBytes ?? roster,
                sourceIdentityRoster: identityBytes ?? identities, rawBytes: 1234,
                codec: 1, payloadDigest: payloadBytes ?? payload
            )
        }
        let actual = try digest()
        let actualHex = actual.map { String(format: "%02x", $0) }.joined()
        #expect(actualHex == expectedHex)
        var changedRoster = roster
        changedRoster[0] ^= 1
        var changedIdentities = identities
        changedIdentities[0] ^= 1
        var changedPayload = payload
        changedPayload[0] ^= 1
        let mutations = [try digest(rosterBytes: changedRoster),
                         try digest(identityBytes: changedIdentities),
                         try digest(payloadBytes: changedPayload),
                         try digest(eventCount: 4)]
        #expect(mutations.allSatisfy { $0 != actual })
    }
    #endif

    @Test("Native output preserves complete JSON schema, values, timestamp and nil omission")
    func nativeOutputExactJSON() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-native-golden-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let path = root.appendingPathComponent("alerts.jsonl")
        let output = FileOutput(path: path.path, format: .native)
        let eventID = try #require(UUID(uuidString: "11111111-2222-3333-4444-555555555555"))
        let process = MacCrabCore.ProcessInfo(
            pid: 123, ppid: 1, rpid: 1,
            name: "fixture", executable: "/fixture/猫",
            commandLine: "fixture ordinary text", args: ["fixture", "ordinary", "text"],
            workingDirectory: "/fixture", userId: 501, userName: "fixture", groupId: 20,
            startTime: Date(timeIntervalSince1970: 100)
        )
        let event = Event(id: eventID, timestamp: Date(timeIntervalSince1970: 101),
                          eventCategory: .process, eventType: .start,
                          eventAction: "exec", process: process)
        let full = Alert(id: "full", ruleId: "fixture.rule", ruleTitle: "Fixture 猫",
                         severity: .high, eventId: eventID.uuidString,
                         processPath: "/fixture/猫", processName: "fixture",
                         description: "Quoted \"fixture\"", mitreTactics: "TA0001,TA0002",
                         mitreTechniques: "T0001,T0002", campaignId: "fixture-campaign")
        let minimal = Alert(id: "minimal", ruleId: "fixture.rule", ruleTitle: "Minimal",
                            severity: .low, eventId: eventID.uuidString)
        await output.send(alert: full, event: event)
        await output.send(alert: minimal, event: nil)
        await output.flush()
        let contents = try String(contentsOf: path, encoding: .utf8)
        let lines = contents.split(separator: "\n")
        #expect(lines.count == 2)
        let records = try lines.map { line in
            let object = try JSONSerialization.jsonObject(with: Data(line.utf8))
            return try #require(object as? [String: Any])
        }
        let fullRecord = try #require(records.first)
        let minimalRecord = try #require(records.last)
        #expect(Set(fullRecord.keys) == ["schema", "version", "timestamp", "alert", "event"])
        #expect(Set(minimalRecord.keys) == ["schema", "version", "timestamp", "alert"])
        for record in records {
            #expect(record["schema"] as? String == "maccrab.alert.v1")
            #expect(record["version"] as? String == "1.9.0")
            let timestamp = try #require(record["timestamp"] as? String)
            #expect(ISO8601DateFormatter().date(from: timestamp) != nil)
        }
        let expectedAlert: [String: Any] = [
            "id": "full", "rule_id": "fixture.rule", "rule_title": "Fixture 猫",
            "severity": "high", "description": "Quoted \"fixture\"",
            "process_path": "/fixture/猫", "process_name": "fixture",
            "mitre_tactics": ["TA0001", "TA0002"], "mitre_techniques": ["T0001", "T0002"],
            "campaign_id": "fixture-campaign"
        ]
        let expectedEvent: [String: Any] = [
            "id": eventID.uuidString, "category": "process", "action": "exec",
            "process_pid": 123, "process_path": "/fixture/猫",
            "process_command_line": "fixture ordinary text"
        ]
        let expectedMinimal: [String: Any] = [
            "id": "minimal", "rule_id": "fixture.rule", "rule_title": "Minimal",
            "severity": "low", "mitre_tactics": [String](), "mitre_techniques": [String]()
        ]
        let actualAlert = try #require(fullRecord["alert"] as? [String: Any])
        let actualEvent = try #require(fullRecord["event"] as? [String: Any])
        let actualMinimal = try #require(minimalRecord["alert"] as? [String: Any])
        #expect(NSDictionary(dictionary: actualAlert).isEqual(to: expectedAlert))
        #expect(NSDictionary(dictionary: actualEvent).isEqual(to: expectedEvent))
        #expect(NSDictionary(dictionary: actualMinimal).isEqual(to: expectedMinimal))
        // Re-encoding the complete parsed object with the preexisting options
        // pins sorted output and escaping as well as parsed key/value parity.
        for (line, record) in zip(lines, records) {
            let expected = try JSONSerialization.data(withJSONObject: record, options: [.sortedKeys])
            #expect(Data(line.utf8) == expected)
        }
    }
}
