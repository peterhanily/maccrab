import Foundation

/// Versioned read contract shared by CLI and MCP. Counts describe the compiled
/// single-event corpus; coverage always carries its observation provenance.
public struct RuleInventoryDocument: Codable, Sendable {
    public struct Rule: Codable, Sendable {
        public let id: String
        public let title: String
        public let level: String
        public let category: String?
        public let tags: [String]
        public let status: String
        public let enabled: Bool
        public let coverage: RuleTelemetryContext.Coverage
        public let evaluationCount: UInt64?
        public let fireCount: UInt64?
    }

    public let schemaVersion: Int
    public let sourceDirectory: String
    public let telemetryFreshness: RuleTelemetryContext.Freshness
    public let telemetryWrittenAt: Date?
    public let telemetryAgeSeconds: Double?
    public let engineIdentity: EngineTelemetryIdentity?
    public let ruleProfile: String?
    public let rules: [Rule]

    public static func read(directory: String, now: Date = Date()) throws -> Self {
        let context = RuleTelemetryContext.load(directory: directory, now: now)
        let path = URL(fileURLWithPath: directory).appendingPathComponent("compiled_rules")
        let files = try FileManager.default.contentsOfDirectory(at: path, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "json" && $0.lastPathComponent != "manifest.json" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
        let rules = try files.map { file -> Rule in
            let data = try RuleFileLoadingPolicy.read(file)
            guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let id = object["id"] as? String, !id.isEmpty,
                  let title = object["title"] as? String,
                  let level = object["level"] as? String else {
                throw RuntimeConfigContractError("Compiled rule metadata is incomplete in \(file.lastPathComponent)")
            }
            let status = (object["status"] as? String ?? "experimental").lowercased()
            let enabled = object["enabled"] as? Bool ?? true
            let stats = context.statsByID[id]
            return Rule(id: id, title: title, level: level,
                        category: (object["logsource"] as? [String: Any])?["category"] as? String,
                        tags: object["tags"] as? [String] ?? [], status: status, enabled: enabled,
                        coverage: context.coverage(ruleID: id, status: status, enabled: enabled),
                        evaluationCount: stats?.evaluationCount, fireCount: stats?.fireCount)
        }
        return .init(schemaVersion: 1, sourceDirectory: directory,
                     telemetryFreshness: context.freshness,
                     telemetryWrittenAt: context.snapshotWrittenAt,
                     telemetryAgeSeconds: context.ageSeconds,
                     engineIdentity: context.engineIdentity,
                     ruleProfile: context.ruleProfile, rules: rules)
    }
}
