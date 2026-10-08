import Foundation
import MacCrabCore

extension MacCrabCtl {

    /// `maccrabctl why <alert_id>` — explain why a specific rule fired.
    ///
    /// The single most common analyst question when triaging any alert is
    /// "why did this rule fire on this process?" Until now, the only answer
    /// was "read the YAML rule + read the event row and figure it out
    /// yourself." This command prints the alert's captured fields, then the
    /// rule that raised it, from user_rules (dashboard-authored rules and
    /// overrides, which replace a bundled rule with the same id) or
    /// compiled_rules: a single-event rule's predicates and condition AST, a
    /// sequence rule's window, correlation, trigger and steps, or a graph
    /// rule's nodes, edges, scope and constraints. It does not evaluate the
    /// rule against the event, so it does not mark which clauses matched.
    /// Alerts from built-in detectors have no rule file.
    ///
    /// Intentionally a read-only diagnostic: no DB writes, no side effects.
    static func runWhy(args: [String]) async {
        guard args.count >= 3 else {
            print("""
            Usage: maccrabctl why <alert_id>

            Prints the alert's captured details, then the rule that raised it,
            from user_rules (dashboard-authored rules and overrides) or
            compiled_rules: the predicates and condition of a single-event
            rule, the steps of a sequence rule, or the nodes and edges of a
            graph rule. Alerts from built-in detectors have no rule file.

            Alert IDs are shown in the app's alert inspector, by
            `maccrabctl ai-alerts` (AI alerts only) and in
            `maccrabctl export json`. Campaign alert IDs work too. Synthetic
            maccrab.* alerts, such as behavior scoring, topology, campaign and
            self-defense alerts, print a short note about their detector
            instead of a rule.
            """)
            exit(1)
        }
        let alertID = args[2]
        let dataDir = maccrabDataDir()

        // 1. Load the alert.
        let alert: Alert
        do {
            let store = try openAlertStoreForReading(directory: dataDir)
            guard let found = try await store.alert(id: alertID) else {
                print("No alert with id '\(alertID)' in \(dataDir)/alerts.db")
                print("Tip: alert IDs are shown in the app's alert inspector, by `maccrabctl ai-alerts` (AI alerts only) and in `maccrabctl export json`.")
                exit(1)
            }
            alert = found
        } catch {
            print("Error opening alert store: \(error)")
            exit(1)
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

        // 4. Load the rule JSON. Rule ID is a UUID (a slug for graph rules);
        //    the file name is the slug. In each support dir, the top level of
        //    user_rules comes first: the daemon overlays single-event rules
        //    from there after the bundled rules, so a user rule replaces the
        //    bundled one with the same id. compiled_rules follows, with its
        //    sequences/ and graph/ folders.
        let searchDirs = whySearchDirs(supportDirs: [
            dataDir,
            "/Library/Application Support/MacCrab",
            NSHomeDirectory() + "/Library/Application Support/MacCrab",
        ])
        guard let rulePath = findRuleFile(forRuleID: alert.ruleId, in: searchDirs) else {
            print("No rule file with the id \(alert.ruleId) was found in user_rules or compiled_rules.")
            print(alert.description != nil
                ? "Built-in detectors have no rule file; for their alerts, the description printed above is what was captured."
                : "Built-in detectors have no rule file.")
            exit(1)
        }
        guard let ruleData = try? Data(contentsOf: URL(fileURLWithPath: rulePath)),
              let ruleJSON = try? JSONSerialization.jsonObject(with: ruleData) as? [String: Any] else {
            print("Failed to parse compiled rule at \(rulePath)")
            exit(1)
        }

        // 5. The rule: its file and summary, then a single-event rule's
        //    predicates and condition AST, a sequence rule's steps, or a
        //    graph rule's pattern.
        for line in whyRuleLines(ruleJSON, rulePath: rulePath) {
            print(line)
        }
        // The daemon skips an override it doesn't trust (DaemonSetup's
        // overlay gate and RuleEngine's per-file owner check).
        if (rulePath as NSString).deletingLastPathComponent.hasSuffix("/user_rules") {
            print("Note: this is a user rule. The daemon skips user rules that root does not own")
            print("or whose folder others can write to; the bundled rule with this id then applies.")
        }

        // 6. Next steps.
        print(bar)
        print("Next steps:")
        print("  maccrabctl events tail --category process  (recent events by the same actor)")
        print("  maccrabctl alerts --hours 1                (other alerts in the last hour)")
        print("  maccrabctl suppress \(alert.ruleId) <path>  (suppress this rule for a known-benign process)")
    }

    /// The folders `why` searches, in order. For each support dir: the top
    /// level of user_rules, where the daemon overlays single-event rules
    /// after the bundled ones (so a user rule replaces a bundled rule with the
    /// same id), then compiled_rules and its sequences/ and graph/ folders.
    static func whySearchDirs(supportDirs: [String]) -> [String] {
        supportDirs.flatMap { dir -> [String] in
            let compiled = dir + "/compiled_rules"
            return [dir + "/user_rules", compiled, compiled + "/sequences", compiled + "/graph"]
        }
    }

    /// The path of the first rule file, in `directories` order, whose "id"
    /// is `ruleID`. Only the top level of each folder is read.
    static func findRuleFile(forRuleID ruleID: String, in directories: [String]) -> String? {
        let fm = FileManager.default
        for dir in directories {
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

    /// The compiled-rule part of `why`, one string per printed line: the
    /// rule file and summary, then the predicates and condition AST of a
    /// single-event rule, the settings and steps of a sequence rule, or the
    /// pattern of a graph rule.
    static func whyRuleLines(_ rule: [String: Any], rulePath: String) -> [String] {
        var lines = ["Rule file:   \(rulePath)"]
        if let src = rule["description"] as? String {
            lines.append("Summary:     \(src)")
        }
        lines.append(String(repeating: "─", count: 72))

        if (rule["type"] as? String) == "graph" {
            return lines + whyGraphLines(rule)
        }
        if let steps = rule["steps"] as? [[String: Any]] {
            return lines + whySequenceLines(rule, steps: steps)
        }

        // Single-event rule. Predicates after `condition` in a compiled rule
        // are flat; the engine walks them using the condition AST. We print
        // predicate-by-predicate so an analyst can see which fields the rule
        // is testing without spelunking into the YAML.
        if let predicates = rule["predicates"] as? [[String: Any]] {
            lines += whyPredicateLines(predicates)
        }
        // The condition expression: the Boolean combinator the rule used
        // ("selection and not filter_a and not filter_b").
        if let conditionTree = rule["condition_tree"] {
            lines += whyConditionASTLines(conditionTree)
        }
        return lines
    }

    /// "Predicates (N):" and one numbered line per predicate. Used for
    /// single-event rules and for each step of a sequence rule.
    private static func whyPredicateLines(_ predicates: [[String: Any]]) -> [String] {
        var lines = ["Predicates (\(predicates.count)):"]
        for (idx, predicate) in predicates.enumerated() {
            let field = (predicate["field"] as? String) ?? "?"
            let modifier = (predicate["modifier"] as? String) ?? "equals"
            let negate = (predicate["negate"] as? Bool) ?? false
            let values = (predicate["values"] as? [String]) ?? []
            let op = negate ? "NOT \(modifier)" : modifier
            lines.append("  \(String(format: "%2d", idx + 1)). \(field.padding(toLength: 32, withPad: " ", startingAt: 0)) \(op.padding(toLength: 14, withPad: " ", startingAt: 0)) \(whyValueList(values))")
        }
        return lines
    }

    /// "Condition AST:" and the tree as indented JSON.
    private static func whyConditionASTLines(_ conditionTree: Any) -> [String] {
        guard let conditionData = try? JSONSerialization.data(withJSONObject: conditionTree, options: .prettyPrinted),
              let conditionStr = String(data: conditionData, encoding: .utf8) else { return [] }
        return ["Condition AST:"] + conditionStr.split(separator: "\n").map { "  \($0)" }
    }

    /// A sequence rule: window, correlation, ordering and trigger, then each
    /// step's event category, process relation, predicates and condition.
    private static func whySequenceLines(_ rule: [String: Any], steps: [[String: Any]]) -> [String] {
        var lines = [
            "Window:      \(whyJSONValue(rule["window"] ?? "?")) seconds",
            "Correlation: \(whyJSONValue(rule["correlationType"] ?? "?"))",
            "Ordered:     \(whyJSONValue(rule["ordered"] ?? "?"))",
        ]
        if let trigger = rule["trigger"] as? [String: Any] {
            let type = (trigger["type"] as? String) ?? "?"
            lines.append("Trigger:     " + (trigger["value"].map { "\(type) \(whyJSONValue($0))" } ?? type))
        }
        for (idx, step) in steps.enumerated() {
            let id = (step["id"] as? String) ?? "?"
            let category = (step["logsourceCategory"] as? String) ?? "?"
            lines.append("Step \(idx + 1) of \(steps.count): \(id)  (\(category))")
            var body: [String] = []
            if let relation = step["processRelation"] as? [String: Any] {
                let kind = (relation["relation"] as? String) ?? "?"
                let other = (relation["relativeToStep"] as? String) ?? "?"
                body.append("Process relation: \(kind) (relative to step \(other))")
            }
            body += whyPredicateLines((step["predicates"] as? [[String: Any]]) ?? [])
            if let conditionTree = step["condition_tree"] {
                body += whyConditionASTLines(conditionTree)
            } else {
                body.append("Condition:   \((step["condition"] as? String) ?? "?")")
            }
            lines += body.map { "  " + $0 }
        }
        return lines
    }

    /// A graph rule's pattern: nodes with their type and where clause, edges
    /// as `from -relation-> to` with the minimum tier, then scope and
    /// constraints.
    private static func whyGraphLines(_ rule: [String: Any]) -> [String] {
        let nodes = (rule["nodes"] as? [String: Any]) ?? [:]
        let edges = (rule["edges"] as? [[String: Any]]) ?? []
        let width = nodes.keys.map(\.count).max() ?? 0
        var lines = ["Nodes (\(nodes.count)):"]
        for name in nodes.keys.sorted() {
            let node = (nodes[name] as? [String: Any]) ?? [:]
            var line = "  \(name.padding(toLength: width, withPad: " ", startingAt: 0))  \((node["type"] as? String) ?? "?")"
            if let clauses = node["where"] as? [String: Any], !clauses.isEmpty {
                let tests = clauses.sorted { $0.key < $1.key }.flatMap { field, ops in
                    ((ops as? [String: Any]) ?? [:]).sorted { $0.key < $1.key }
                        .map { "\(field) \($0.key) \(whyJSONValue($0.value))" }
                }
                line += "  where " + tests.joined(separator: ", ")
            }
            lines.append(line)
        }
        lines.append("Edges (\(edges.count)):")
        for edge in edges {
            var line = "  \((edge["from"] as? String) ?? "?") -\((edge["relation"] as? String) ?? "?")-> \((edge["to"] as? String) ?? "?")"
            if let tier = edge["min_tier"] as? String {
                line += "  (min tier: \(tier))"
            }
            lines.append(line)
        }
        if let scope = rule["scope"] {
            lines.append("Scope:       \(whyJSONValue(scope))")
        }
        if let constraints = rule["constraints"] {
            lines.append("Constraints: \(whyJSONValue(constraints))")
        }
        return lines
    }

    /// Joins values, shortening a list of more than four to its first three
    /// and the total.
    private static func whyValueList(_ values: [String]) -> String {
        values.count > 4
            ? values.prefix(3).joined(separator: ", ") + ", … (\(values.count) total)"
            : values.joined(separator: ", ")
    }

    /// A JSON value as plain text: strings bare, lists in brackets (shortened
    /// like predicate values), objects as sorted `key=value` pairs.
    private static func whyJSONValue(_ value: Any) -> String {
        switch value {
        case let string as String:
            return string
        case let number as NSNumber:
            if CFGetTypeID(number) == CFBooleanGetTypeID() {
                return number.boolValue ? "true" : "false"
            }
            return number.stringValue
        case let list as [Any]:
            return "[" + whyValueList(list.map(whyJSONValue)) + "]"
        case let object as [String: Any]:
            return object.sorted { $0.key < $1.key }
                .map { "\($0.key)=\(whyJSONValue($0.value))" }
                .joined(separator: ", ")
        default:
            return "\(value)"
        }
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
