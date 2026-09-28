import Foundation

public enum RaveReviewImport {
    /// Reports retain independent source namespaces. Matching paths in separate
    /// acquisitions never establish a data flow or a common execution.
    public static func combine(_ inputs: [RaveSnapshot]) throws -> RaveSnapshot {
        guard (1...8).contains(inputs.count), inputs.allSatisfy({ $0.domain != "app" }) else { throw RaveReviewError.incompatible }
        for input in inputs { try RaveReviewEngine.validate(input) }
        guard inputs.count > 1 else { return try RaveReviewEngine.assess(inputs[0]) }
        let ordered = inputs.sorted { ($0.domain + $0.scope.sorted().joined(separator: "\0")) < ($1.domain + $1.scope.sorted().joined(separator: "\0")) }
        let scope = ordered.flatMap { input in input.scope.map { input.domain + ":" + $0 } }.sorted()
        guard Set(scope).count == scope.count else { throw RaveReviewError.incompatible }
        let facts = ordered.enumerated().flatMap { index, input in
            input.facts.map { fact -> RaveFact in
                var fact = fact
                fact.path = "Report \(index + 1) / " + fact.path
                fact.reference = "Report \(index + 1) / " + fact.reference
                return fact
            }
        }
        return try RaveReviewEngine.assess(.init(domain: Set(ordered.map(\.domain)).count > 1 ? "investigation" : ordered[0].domain,
            scope: scope, facts: facts, gaps: Array(Set(inputs.flatMap(\.gaps))).sorted()))
    }
    public static func decode(_ bytes: Data) throws -> RaveSnapshot {
        try RaveReviewEngine.boundedJSON(bytes)
        guard let root = try JSONSerialization.jsonObject(with: bytes) as? [String: Any] else { throw RaveReviewError.invalid }
        if root["documentType"] != nil { return try RaveReviewDocumentIO.decode(bytes).snapshot }
        if root["domain"] != nil {
            var snapshot = try RaveReviewEngine.decode(bytes)
            snapshot.provenance = "unverified-import"
            snapshot.findings = [] // Interpretations are rebuilt from validated facts.
            return snapshot
        }
        if root["exported_by"] as? String == "MacCrab (ArtifactExporter)" {
            guard let records = root["artifacts"] as? [[String: Any]], !records.isEmpty, records.count <= 5000,
                  root["artifact_count"] as? Int == records.count,
                  let plugin = records[0]["plugin_id"] as? String,
                  let version = records[0]["plugin_version"] as? String,
                  records.allSatisfy({ $0["plugin_id"] as? String == plugin && $0["plugin_version"] as? String == version && $0["schema_version"] as? Int == 1 }) else { throw RaveReviewError.invalid }
            let rows: [[String: Any]] = try records.map {
                guard let type = $0["content_type"] as? String, let data = $0["data"] as? [String: Any] else { throw RaveReviewError.invalid }
                return ["contentType": type, "data": data]
            }
            let normalized: [String: Any] = ["schemaVersion": 1, "pluginID": plugin, "pluginVersion": version,
                "artifacts": rows, "coverage": rows.filter { $0["contentType"] as? String == "rave.collection" }.compactMap { $0["data"] as? [String: Any] }]
            return try decode(JSONSerialization.data(withJSONObject: normalized))
        }
        guard (root["schemaVersion"] as? Int) == 1,
              let plugin = root["pluginID"] as? String,
              let version = root["pluginVersion"] as? String,
              let rows = root["artifacts"] as? [[String: Any]], rows.count <= 5000,
              let coverage = root["coverage"] as? [[String: Any]], coverage.count <= 128 else { throw RaveReviewError.invalid }
        let accepted = ["com.maccrab.forensics.script-trace": ["0.1.0", "0.1.1"],
                        "com.maccrab.forensics.repo-tripwire": ["0.1.0", "0.1.1"],
                        "com.maccrab.forensics.clickfix-review": ["0.1.0"],
                        "com.maccrab.forensics.secret-trail": ["0.2.0", "0.2.1"]]
        if ["com.maccrab.forensics.trust-delta", "com.maccrab.forensics.first-hour"].contains(plugin), ["0.1.0", "0.2.0"].contains(version) {
            let type = plugin.hasSuffix("trust-delta") ? "trust_delta.review" : "first_hour.review"
            let reviews = rows.filter { $0["contentType"] as? String == type }
            guard reviews.count == 1, let data = reviews[0]["data"] as? [String: Any] else { throw RaveReviewError.invalid }
            if let document = data["document"] { return try RaveReviewDocumentIO.decode(JSONSerialization.data(withJSONObject: document)).snapshot }
            guard let snapshot = data["snapshot"] else { throw RaveReviewError.invalid }
            return try decode(JSONSerialization.data(withJSONObject: snapshot))
        }
        guard accepted[plugin]?.contains(version) == true else { throw RaveReviewError.unsupported }
        let credentials = plugin.hasSuffix("secret-trail")
        var facts: [RaveFact] = [], gaps: [String] = [], scope: [String] = []
        if coverage.isEmpty { gaps.append("source-coverage-missing") }
        for item in coverage {
            guard let outcome = item["outcome"] as? String,
                  ["complete", "observed-empty", "unavailable", "partial", "truncated", "failed"].contains(outcome) else { throw RaveReviewError.invalid }
            if !["complete", "observed-empty"].contains(outcome) { gaps.append("source-coverage-incomplete") }
        }
        for (index, row) in rows.enumerated() {
            guard let type = row["contentType"] as? String, let data = row["data"] as? [String: Any] else { throw RaveReviewError.invalid }
            let reference = plugin + " / record " + String(index + 1)
            if (credentials && type == "secret_trail.summary") ||
                (plugin.hasSuffix("script-trace") && type == "script_trace.summary") ||
                (plugin.hasSuffix("repo-tripwire") && type == "repo_tripwire.summary"), let selected = data["sourceScope"] as? [[String: String]] {
                guard selected.count <= 32 else { throw RaveReviewError.oversized }
                for item in selected {
                    guard let path = item["path"], let kind = item["kind"], RaveReviewEngine.textOK(path),
                          (credentials ? ["project", "ai-session", "shell-history", "log"] : [plugin.hasSuffix("script-trace") ? "script" : "project"]).contains(kind) else { throw RaveReviewError.invalid }
                    guard !path.isEmpty else { throw RaveReviewError.invalid }
                    scope.append((credentials ? "" : plugin + ":") + kind + ":" + path)
                }
            } else if credentials, type == "secret_trail.credential" {
                guard let family = data["family"] as? String, RaveReviewEngine.families.contains(family),
                      let locations = data["locations"] as? [[String: Any]], locations.count <= 24 else { throw RaveReviewError.invalid }
                if (data["locationsOmitted"] as? Int ?? 0) > 0 { gaps.append("credential-locations-omitted") }
                if (data["countsAreLowerBounds"] as? Bool) == true { gaps.append("credential-coverage-incomplete") }
                for location in locations {
                    guard let path = location["relativePath"] as? String, let kind = location["sourceKind"] as? String else { throw RaveReviewError.invalid }
                    if path.contains("[REDACTED") { gaps.append("redacted-location-not-comparable"); continue }
                    facts.append(.init(kind: "credential", path: path, code: family, value: kind, reference: reference))
                }
            } else if !credentials, (type == "script_trace.finding" && plugin.hasSuffix("script-trace")) ||
                        (type == "repo_tripwire.finding" && plugin.hasSuffix("repo-tripwire")) {
                guard let code = data["code"] as? String else { throw RaveReviewError.invalid }
                if code == "coverage-gap" || code == "selection-required" { gaps.append("static-inspection-incomplete") }
                if RaveReviewEngine.scriptCodes.contains(code) {
                    guard let path = data["path"] as? String else { throw RaveReviewError.invalid }
                    facts.append(.init(kind: "script", path: path, code: code, reference: reference))
                }
            } else if plugin.hasSuffix("clickfix-review"), type == "clickfix_review.persistence" {
                guard let path = data["plistPath"] as? String else { throw RaveReviewError.invalid }
                facts.append(.init(kind: "persistence", path: path, code: "launch-configuration",
                    value: (data["runAtLoad"] as? Bool) == true ? "run-at-load" : "configured", reference: reference))
            }
        }
        if scope.isEmpty { scope = ["unscoped:" + plugin]; gaps.append("comparable-source-selection-unavailable") }
        var unique: [String: RaveFact] = [:]
        for fact in facts {
            if let old = unique[fact.key], old.value != fact.value { throw RaveReviewError.invalid }
            unique[fact.key] = unique[fact.key] ?? fact
        }
        let result = RaveSnapshot(domain: credentials ? "credentials" : "incident",
            scope: scope.sorted(), facts: unique.values.sorted { $0.key < $1.key },
            gaps: Array(Set(gaps)).sorted())
        try RaveReviewEngine.validate(result)
        return result
    }
}
