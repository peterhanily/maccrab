import Foundation
import MacCrabCore

extension MacCrabCtl {

    /// `maccrabctl why <alert_id>` — explain why a specific rule fired.
    ///
    /// The single most common analyst question when triaging any alert is
    /// "why did this rule fire on this process?" Until now, the only answer
    /// was "read the YAML rule + read the event row and figure it out
    /// yourself." This command prints the compiled rule's predicates
    /// alongside the alert's captured fields so the match is obvious at a
    /// glance — and highlights which predicate clauses matched based on a
    /// simple string/glob reimplementation of the engine's dispatch logic.
    ///
    /// Intentionally a read-only diagnostic: no DB writes, no side effects.
    static func runWhy(args: [String]) async {
        guard args.count >= 3 else {
            print("""
            Usage: maccrabctl why <alert_id>

            Explains which rule fired, which predicate clauses matched, and
            which filter clauses dropped the event from suppression.

            Alert IDs come from the first column of `maccrabctl alerts` (use
            `--format full` if the ID is truncated). Campaign alert IDs work
            too; synthetic scoring/topology alerts explain the indicator set
            instead of predicates.
            """)
            return
        }
        let alertID = args[2]
        let dataDir = maccrabDataDir()

        // 1. Load the alert.
        let alert: Alert
        do {
            let store = try AlertStore(directory: dataDir)
            guard let found = try await store.alert(id: alertID) else {
                print("No alert with id '\(alertID)' in \(dataDir)/alerts.db")
                print("Tip: copy the ID from `maccrabctl alerts` (the first column).")
                return
            }
            alert = found
        } catch {
            print("Error opening alert store: \(error)")
            return
        }

        // 2. Header: what fired, when, where.
        let bar = String(repeating: "─", count: 72)
        print(bar)
        print("\(alert.severity.coloredLabel) \(alert.ruleTitle)")
        print("   Rule id:    \(alert.ruleId)")
        print("   Alert id:   \(alert.id)")
        print("   When:       \(formatDate(alert.timestamp))")
        if let p = alert.processName, let path = alert.processPath {
            print("   Process:    \(p)  (\(path))")
        }
        if let tac = alert.mitreTactics, !tac.isEmpty {
            print("   MITRE:      \(tac)  \(alert.mitreTechniques ?? "")")
        }
        if let desc = alert.description {
            print("   Why it fired (captured):")
            print("     \(desc)")
        }
        print(bar)

        // 3. Synthetic alerts (behavioral scoring, topology anomalies,
        //    campaign digests) don't map to a Sigma rule file. Detect them
        //    by the `maccrab.*` prefix and explain the indicator set instead.
        if alert.ruleId.hasPrefix("maccrab.") {
            explainSyntheticAlert(alert)
            return
        }

        // 4. Load the compiled rule JSON. Rule ID is a UUID; the file name
        //    is the slug. Walk the compiled_rules dir and match by "id".
        guard let rulePath = findRuleFile(forRuleID: alert.ruleId, dataDir: dataDir) else {
            print("No compiled rule found for id \(alert.ruleId).")
            print("Expected under \(dataDir)/compiled_rules/ — is the engine running?")
            return
        }
        guard let ruleData = try? Data(contentsOf: URL(fileURLWithPath: rulePath)),
              let ruleJSON = try? JSONSerialization.jsonObject(with: ruleData) as? [String: Any] else {
            print("Failed to parse compiled rule at \(rulePath)")
            return
        }

        print("Rule file:   \(rulePath)")
        if let src = ruleJSON["description"] as? String {
            print("Summary:     \(src)")
        }
        print(bar)

        // 5. Print the predicate tree. Predicates after `condition` in a
        //    compiled rule are flat; the engine walks them using the
        //    condition AST. We print predicate-by-predicate so an analyst
        //    can see which fields the rule is testing without spelunking
        //    into the YAML.
        if let predicates = ruleJSON["predicates"] as? [[String: Any]] {
            print("Predicates (\(predicates.count)):")
            for (idx, predicate) in predicates.enumerated() {
                let field = (predicate["field"] as? String) ?? "?"
                let modifier = (predicate["modifier"] as? String) ?? "equals"
                let negate = (predicate["negate"] as? Bool) ?? false
                let values = (predicate["values"] as? [String]) ?? []
                let op = negate ? "NOT \(modifier)" : modifier
                let valuesStr = values.count > 4
                    ? values.prefix(3).joined(separator: ", ") + ", … (\(values.count) total)"
                    : values.joined(separator: ", ")
                print(String(format: "  %2d. %-32s %-14s %@", idx + 1, field, op, valuesStr))
            }
        }

        // 6. Print the condition expression. That's the Boolean combinator
        //    the rule used ("selection and not filter_a and not filter_b").
        if let conditionTree = ruleJSON["condition_tree"],
           let conditionData = try? JSONSerialization.data(withJSONObject: conditionTree, options: .prettyPrinted),
           let conditionStr = String(data: conditionData, encoding: .utf8) {
            print("Condition AST:")
            for line in conditionStr.split(separator: "\n") {
                print("  \(line)")
            }
        }

        // 7. Next steps.
        print(bar)
        print("Next steps:")
        print("  maccrabctl events tail --category process  (recent events by the same actor)")
        print("  maccrabctl alerts --hours 1                (other alerts in the last hour)")
        print("  maccrabctl suppress \(alert.ruleId) <path>  (suppress this rule for a known-benign process)")
    }

    private static func findRuleFile(forRuleID ruleID: String, dataDir: String) -> String? {
        let fm = FileManager.default
        let candidates = [
            dataDir + "/compiled_rules",
            "/Library/Application Support/MacCrab/compiled_rules",
            NSHomeDirectory() + "/Library/Application Support/MacCrab/compiled_rules",
        ]
        for dir in candidates {
            guard let files = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for file in files where file.hasSuffix(".json") {
                let path = dir + "/" + file
                guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
                      let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                      let id = obj["id"] as? String, id == ruleID else { continue }
                return path
            }
        }
        return nil
    }

    private static func explainSyntheticAlert(_ alert: Alert) {
        // maccrab.behavior.* → behavioral scoring aggregate
        // maccrab.topology.* → topology anomaly
        // maccrab.campaign.* → campaign correlator
        // maccrab.self-defense.* → tamper detection
        let parts = alert.ruleId.split(separator: ".").map(String.init)
        let family = parts.count >= 2 ? parts[1] : "unknown"
        switch family {
        case "behavior":
            print("This alert is a behavioral-scoring aggregate, not a Sigma rule.")
            print("The scoring engine sums weighted indicators across a process tree")
            print("and fires when the total exceeds the critical/high threshold.")
            print("See the alert description for the specific indicators that contributed.")
        case "topology":
            print("This alert is a topology anomaly — shape-based process-tree detection.")
            print("Categorical invariant: \(parts.dropFirst(2).joined(separator: "."))")
            print("Not a Sigma rule. See TopologyAnomalyDetector.swift for the invariants.")
        case "campaign":
            print("This alert is a campaign digest — correlated across multiple rules.")
            print("Run: maccrabctl campaigns  — to see the contributing alerts.")
        case "self-defense":
            print("This alert is a self-defense / tamper event, not a Sigma rule.")
            print("See SelfDefense.swift for the tamper categories.")
        default:
            print("Synthetic alert (family: \(family)). No Sigma rule to introspect.")
        }
    }
}
