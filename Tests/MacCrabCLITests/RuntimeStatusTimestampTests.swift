import Foundation
import Testing
import MacCrabCore
@testable import maccrabctl

/// Only empty test-owned directories. No installed stores, processes or keys.
@Suite("Runtime status precise timestamp through the CLI encoder")
struct RuntimeStatusTimestampTests {
    private func directory() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-status-time-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(
            at: url, withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        return url
    }

    @Test("Same-second later/earlier and rollover retain strict ordering",
          arguments: [0.750, 0.500, 1.001])
    func preciseOrdering(fraction: Double) async throws {
        let url = try directory()
        defer { try? FileManager.default.removeItem(at: url) }
        let epoch = 1_791_842_108.0
        let tail = epoch + 0.638142
        let now = Date(timeIntervalSince1970: epoch + fraction)
        let document = try await RuntimeStatusDocument.read(directory: url.path, now: now)
        let data = try encodeCLIJSON(document)
        let object = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        let precise = try #require(object["observed_at_unix"] as? Double)
        #expect(precise == now.timeIntervalSince1970)
        #expect(document.observedAtUnix == document.observedAt.timeIntervalSince1970)
        #expect((precise >= tail) == (fraction > 0.638142))
        #expect(object["observed_at"] is String, "Keep the existing text field for compatibility.")
        let rendered = try #require(object["observed_at"] as? String)
        let parsed = try #require(ISO8601DateFormatter().date(from: rendered))
        #expect(parsed.timeIntervalSince1970 == floor(precise),
                "The legacy whole-second representation must contain the precise instant.")
        #expect(object["schema_version"] as? Int == 1)
        #expect(object["liveness"] as? String == "unavailable")
    }

    @Test("Legacy schema-1 documents do not invent missing precise time")
    func legacyIsExplicitlyImprecise() async throws {
        let url = try directory()
        defer { try? FileManager.default.removeItem(at: url) }
        let document = try await RuntimeStatusDocument.read(
            directory: url.path, now: Date(timeIntervalSince1970: 1_791_842_108.750)
        )
        var object = try #require(
            JSONSerialization.jsonObject(with: encodeCLIJSON(document)) as? [String: Any]
        )
        object.removeValue(forKey: "observed_at_unix")
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        decoder.dateDecodingStrategy = .iso8601
        let legacy = try decoder.decode(
            RuntimeStatusDocument.self, from: JSONSerialization.data(withJSONObject: object)
        )
        #expect(legacy.observedAtUnix == nil)
        #expect(legacy.schemaVersion == 1)
        let reencoded = try #require(
            JSONSerialization.jsonObject(with: encodeCLIJSON(legacy)) as? [String: Any]
        )
        #expect(reencoded["observed_at_unix"] == nil)
    }
}
