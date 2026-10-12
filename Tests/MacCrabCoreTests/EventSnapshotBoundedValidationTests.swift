import CryptoKit
import Foundation
import Testing
@testable import MacCrabCore

/// In-memory representation checks only; no collectors, child processes or
/// installed stores are used by these fixtures.
@Suite("Event snapshot bounded validation")
struct EventSnapshotBoundedValidationTests {
    private func event() -> Event {
        Event(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000042")!,
            timestamp: Date(timeIntervalSince1970: 1_800_000_000),
            eventCategory: .process,
            eventType: .creation,
            eventAction: "fixture",
            process: ProcessInfo(
                pid: 42, ppid: 1, rpid: 42, name: "fixture",
                executable: "/fixture/ordinary", commandLine: "ordinary",
                args: [], workingDirectory: "/fixture", userId: 501,
                userName: "fixture", groupId: 20,
                startTime: Date(timeIntervalSince1970: 1_800_000_000)
            ),
            severity: .informational
        )
    }

    private func ingress(
        _ source: Event, bytes: Data, overflow: Bool = false
    ) -> EventJournalIngressPreparation {
        let digest = Data(SHA256.hash(data: bytes))
        return EventJournalIngressPreparation(
            event: source, canonicalJSON: bytes, canonicalSHA256: digest,
            overflow: overflow ? EventJournalOverflowEvidence(
                originalEventID: source.id, originalBytes: bytes.count,
                originalSHA256: digest, digestKind: .canonicalJSON,
                sourceIdentitySHA256:
                    EventJournalAdmissionValidator.sourceIdentityDigest(source)
            ) : nil
        )
    }

    @Test("valid bounded input preserves bytes, binding and overflow disposition",
          arguments: [false, true])
    func boundedInput(overflow: Bool) throws {
        let source = event()
        let canonical = try EventJournalAdmissionValidator.prepare(source)
        let input = ingress(source, bytes: canonical.canonicalJSON, overflow: overflow)
        let result = EventSnapshot.prepare(input)
        #expect(result.disposition == (overflow ? .poison : .complete))
        #expect(result.eventJSON == String(decoding: input.canonicalJSON, as: UTF8.self))
        #expect(result.eventID == source.id.uuidString)
        #expect(result.timestamp == source.timestamp)
        #expect(result.canonicalSHA256 == input.canonicalSHA256)
        #expect(result.canonicalByteCount == input.canonicalJSON.count)
        #expect(result.snapshotJSON == "[" + (result.eventJSON ?? "") + "]")
    }

    @Test("byte bound retains the exact boundary and compacts the next byte",
          arguments: [0, 1])
    func byteBoundary(extraBytes: Int) throws {
        let source = event()
        let canonical = try EventJournalAdmissionValidator.prepare(source).canonicalJSON
        // JSON permits trailing whitespace; this exercises the byte boundary
        // without adding a large Event graph or changing its decoded fields.
        try #require(canonical.count <= EventSnapshot.maxBytesPerEvent)
        var bytes = canonical
        bytes.append(Data(repeating: 0x20,
                          count: EventSnapshot.maxBytesPerEvent - bytes.count + extraBytes))
        let input = ingress(source, bytes: bytes)
        let result = EventSnapshot.prepare(input)
        #expect(result.disposition == (extraBytes == 0 ? .complete : .compacted))
        let json = try #require(result.eventJSON)
        #expect(json.utf8.count <= EventSnapshot.maxBytesPerEvent)
        let decoded = try JSONDecoder().decode(Event.self, from: Data(json.utf8))
        #expect(decoded.id == source.id)
        #expect(decoded.timestamp == source.timestamp)
        #expect(decoded.process.executable == source.process.executable)
        #expect(result.canonicalSHA256 == input.canonicalSHA256)
        #expect(result.canonicalByteCount == bytes.count)
        if extraBytes == 0 {
            #expect(Data(json.utf8) == bytes)
        }
    }

    @Test("unparseable public ingress remains content-free poison")
    func malformedPublicIngress() {
        let source = event()
        let input = ingress(source, bytes: Data("not JSON".utf8))
        let result = EventSnapshot.prepare(input)
        #expect(result.disposition == .poison)
        #expect(result.eventJSON == nil)
        #expect(!result.snapshotJSON.contains("not JSON"))
        #expect(result.canonicalSHA256 == input.canonicalSHA256)
        #expect(result.canonicalByteCount == input.canonicalJSON.count)
    }

    @Test("public ingress still checks decoded event identity and timestamp",
          arguments: ["id", "timestamp"])
    func mismatchedPublicIngress(field: String) throws {
        let source = event()
        let canonical = try EventJournalAdmissionValidator.prepare(source).canonicalJSON
        var object = try #require(JSONSerialization.jsonObject(with: canonical) as? [String: Any])
        if field == "id" {
            object[field] = "00000000-0000-0000-0000-000000000099"
        } else {
            object[field] = source.timestamp.timeIntervalSinceReferenceDate + 1
        }
        let bytes = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        let input = ingress(source, bytes: bytes)
        let result = EventSnapshot.prepare(input)
        #expect(result.disposition == .compacted)
        let json = try #require(result.eventJSON)
        let decoded = try JSONDecoder().decode(Event.self, from: Data(json.utf8))
        #expect(decoded.id == source.id)
        #expect(decoded.timestamp == source.timestamp)
        #expect(decoded.enrichments["alert_trigger_snapshot"] == "omitted_oversize")
        #expect(result.canonicalSHA256 == input.canonicalSHA256)
    }
}
