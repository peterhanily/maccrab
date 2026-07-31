import Foundation
import MacCrabCore

extension MacCrabCtl {
    static func listRules() async {
        let supportDir = maccrabDataDir()
        let compiledDir = supportDir + "/compiled_rules"

        guard FileManager.default.fileExists(atPath: compiledDir) else {
            print("No compiled rules found. Run: maccrabctl compile <rules-dir> <output-dir>")
            return
        }

        guard let files = try? FileManager.default.contentsOfDirectory(atPath: compiledDir) else {
            print("Failed to read compiled rules directory")
            return
        }

        // v1.19.0: exclude manifest.json (the rule-bundle manifest, not a rule —
        // it has no `level` key) so the count matches the engine's loaded total
        // (438) instead of inflating to 439 / showing a phantom "unknown" level.
        let jsonFiles = files.filter { $0.hasSuffix(".json") && $0 != "manifest.json" }.sorted()

        // v1.21.6 (audit DET-12): a listing of title + level cannot distinguish
        // "silent because nothing attacked me" from "silent because it never
        // ran" — which is exactly the distinction that decides whether an EDR is
        // trustworthy. Two facts the daemon already publishes close it:
        //
        //   * the effective rule_profile — the compiled `enabled` flag is only
        //     the YAML-level switch, so all 338 experimental rules ship
        //     enabled:true on disk and were listed as if they run, when the
        //     default "stable" profile never loads them;
        //   * rule_telemetry.json — evaluationCount / fireCount per rule, i.e.
        //     which loaded rules were actually evaluated and how often they hit.
        //
        // Prefer the heartbeat's published profile: daemon_config.json is 0600
        // root-owned, so reading it as the CLI's uid silently yields the
        // "stable" default and would mislabel an `all`-profile install.
        // Both inputs are optional — absent data annotates nothing rather than
        // guessing.
        var heartbeatProfile: String?
        if let hbData = try? Data(contentsOf: URL(fileURLWithPath: supportDir + "/heartbeat_rich.json")),
           let hb = try? JSONSerialization.jsonObject(with: hbData) as? [String: Any] {
            heartbeatProfile = hb["rule_profile"] as? String
        }
        let profileEnablesAll =
            (heartbeatProfile ?? ruleProfileFromConfig(supportDir: supportDir)).lowercased() == "all"
        var telemetryByID: [String: RuleEngine.RuleStats] = [:]
        if let snapshot = RuleEngine.readTelemetrySnapshot(at: supportDir + "/rule_telemetry.json") {
            for stat in snapshot.stats { telemetryByID[stat.ruleId] = stat }
        }

        print("Detection Rules (\(jsonFiles.count) total)")
        if !telemetryByID.isEmpty {
            print(ANSIColor.wrap(
                "State tags cover the daemon's CURRENT boot only (rule_telemetry.json).", .gray))
        }
        print("══════════════════════════════════════════════════════════════")
        print("\("Level".padding(toLength: 8, withPad: " ", startingAt: 0)) \("Title".padding(toLength: 50, withPad: " ", startingAt: 0)) Tags")
        print(String(repeating: "─", count: 80))

        for file in jsonFiles {
            let path = compiledDir + "/" + file
            guard let data = FileManager.default.contents(atPath: path),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                continue
            }

            let title = json["title"] as? String ?? "Unknown"
            let level = json["level"] as? String ?? "?"
            let tags = (json["tags"] as? [String])?.prefix(3).joined(separator: ", ") ?? ""

            let levelStr: String
            switch level {
            case "critical": levelStr = "[CRIT]"
            case "high":     levelStr = "[HIGH]"
            case "medium":   levelStr = "[MED] "
            case "low":      levelStr = "[LOW] "
            default:         levelStr = "[INFO]"
            }

            var line = "\(levelStr.padding(toLength: 8, withPad: " ", startingAt: 0)) \(String(title.prefix(48)).padding(toLength: 50, withPad: " ", startingAt: 0)) \(String(tags.prefix(30)))"
            // Visually flag deprecated detections — retained (id/title/
            // suppressions stay valid) but disabled and non-firing.
            let ruleStatus = (json["status"] as? String)?.lowercased() ?? "experimental"
            let ruleId = json["id"] as? String ?? ""
            if ruleStatus == "deprecated" {
                line += "  " + ANSIColor.wrap("[DEPRECATED]", .orange)
            } else if !(profileEnablesAll || ruleStatus == "stable") {
                // v1.21.6 (audit DET-12): NOT LOADED under the active profile.
                // Previously indistinguishable from a running rule.
                line += "  " + ANSIColor.wrap("[OFF: rule_profile]", .gray)
            } else if let stats = telemetryByID[ruleId] {
                line += stats.fireCount > 0
                    ? "  " + ANSIColor.wrap("[matched \(stats.fireCount)x]", .yellow)
                    : "  " + ANSIColor.wrap(
                        "[quiet: \(stats.evaluationCount) evals, 0 matches]", .gray)
            } else if telemetryByID.isEmpty {
                // No telemetry snapshot at all (daemon not running, or it has
                // not written one yet). Say nothing — mislabelling every rule
                // dark would be worse than saying nothing.
            } else {
                // Loaded, the daemon HAS written telemetry for other rules, and
                // this one has no entry: it was never evaluated once. That means
                // its logsource has no live producer — the state that made the
                // tcc_event rules (DET-06) look identical to healthy quiet rules
                // from the operator's side.
                line += "  " + ANSIColor.wrap("[DARK: never evaluated]", .red)
            }
            print(line)
        }
    }

    static func countRules() async {
        let supportDir = maccrabDataDir()
        let compiledDir = supportDir + "/compiled_rules"

        guard let files = try? FileManager.default.contentsOfDirectory(atPath: compiledDir) else {
            print("No compiled rules found.")
            return
        }

        var bySeverity: [String: Int] = [:]
        var byCategory: [String: Int] = [:]

        // v1.19.0: skip manifest.json (not a rule, no `level`) so `rules count`
        // doesn't show a phantom "unknown: 1" severity or a 437 total.
        for file in files where file.hasSuffix(".json") && file != "manifest.json" {
            let path = compiledDir + "/" + file
            guard let data = FileManager.default.contents(atPath: path),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { continue }

            let level = json["level"] as? String ?? "unknown"
            bySeverity[level, default: 0] += 1

            if let logsource = json["logsource"] as? [String: String],
               let category = logsource["category"] {
                byCategory[category, default: 0] += 1
            }
        }

        print("Rules by Severity:")
        for (level, count) in bySeverity.sorted(by: { $0.value > $1.value }) {
            print("  \(level): \(count)")
        }
        print("\nRules by Log Source:")
        for (cat, count) in byCategory.sorted(by: { $0.value > $1.value }) {
            print("  \(cat): \(count)")
        }
    }

    static func compileRules(inputDir: String, outputDir: String) {
        print("Compiling rules from \(inputDir) to \(outputDir)...")
        print("Note: Use the Python compiler for full Sigma YAML support:")
        print("  python3 Compiler/compile_rules.py --input-dir \(inputDir) --output-dir \(outputDir)")
    }

    /// Flip a rule's `enabled` flag on disk inside its compiled JSON. The
    /// detection engine reads the flag on load — a SIGHUP or sysext
    /// restart after running this picks up the change. Lets a user park
    /// a noisy rule without deleting the source YAML or recompiling.
    ///
    /// Writes to compiled_rules/<file>.json directly; falls back to
    /// scanning the dir for a matching rule id when no filename is given.
    static func setRuleEnabled(ruleId: String, enabled: Bool) {
        let compiledDir = maccrabDataDir() + "/compiled_rules"
        guard let files = try? FileManager.default.contentsOfDirectory(atPath: compiledDir) else {
            print("Cannot read \(compiledDir) — is the detection engine installed?")
            return
        }

        for file in files where file.hasSuffix(".json") {
            let path = compiledDir + "/" + file
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
                  var json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let id = json["id"] as? String,
                  id == ruleId else {
                continue
            }

            json["enabled"] = enabled
            guard let rewritten = try? JSONSerialization.data(
                withJSONObject: json,
                options: [.prettyPrinted, .sortedKeys]
            ) else {
                print("Failed to serialize updated rule JSON")
                return
            }

            do {
                try rewritten.write(to: URL(fileURLWithPath: path))
                print("\(enabled ? "Enabled" : "Disabled") rule \(ruleId) (\(file))")
                print("Send SIGHUP to the detection engine or restart MacCrab.app for the change to take effect:")
                print("  pkill -HUP com.maccrab.agent   # release sysext")
                print("  pkill -HUP maccrabd            # dev fallback")
            } catch {
                print("Failed to write \(path): \(error.localizedDescription)")
            }
            return
        }

        print("Rule \(ruleId) not found under \(compiledDir)")
        print("Use `maccrabctl rules list` to find the rule id.")
    }

    static func createRuleTemplate(category: String) {
        let id = UUID().uuidString.lowercased()
        let date = {
            let f = DateFormatter()
            f.dateFormat = "yyyy/MM/dd"
            return f.string(from: Date())
        }()

        let template: String
        switch category {
        case "process_creation":
            template = """
            title: <Rule Title — what does it detect?>
            id: \(id)
            status: experimental
            description: >
                <Describe the threat behavior this rule detects.>
            author: <Your name>
            date: \(date)
            references:
                - https://attack.mitre.org/techniques/TXXXX/
            tags:
                - attack.execution
                - attack.tXXXX
            logsource:
                category: process_creation
                product: macos
            detection:
                selection:
                    Image|endswith:
                        - '/suspicious-binary'
                    CommandLine|contains:
                        - '--malicious-flag'
                filter_signed:
                    SignerType:
                        - 'apple'
                        - 'devId'
                condition: selection and not filter_signed
            falsepositives:
                - <Known legitimate use cases>
            level: high
            """

        case "file_event":
            template = """
            title: <Rule Title>
            id: \(id)
            status: experimental
            description: >
                <Describe suspicious file activity this rule detects.>
            author: <Your name>
            date: \(date)
            references:
                - https://attack.mitre.org/techniques/TXXXX/
            tags:
                - attack.persistence
                - attack.tXXXX
            logsource:
                category: file_event
                product: macos
            detection:
                selection:
                    TargetFilename|contains:
                        - '/Library/LaunchAgents/'
                    TargetFilename|endswith:
                        - '.plist'
                filter_system:
                    SignerType:
                        - 'apple'
                condition: selection and not filter_system
            falsepositives:
                - <Known legitimate use cases>
            level: high
            """

        case "network_connection":
            template = """
            title: <Rule Title>
            id: \(id)
            status: experimental
            description: >
                <Describe suspicious network behavior this rule detects.>
            author: <Your name>
            date: \(date)
            references:
                - https://attack.mitre.org/techniques/TXXXX/
            tags:
                - attack.command_and_control
                - attack.tXXXX
            logsource:
                category: network_connection
                product: macos
            detection:
                selection:
                    DestinationPort:
                        - 4444
                        - 5555
                    DestinationIsPrivate: 'false'
                condition: selection
            falsepositives:
                - <Known legitimate use cases>
            level: high
            """

        case "tcc_event":
            template = """
            title: <Rule Title>
            id: \(id)
            status: experimental
            description: >
                <Describe suspicious TCC permission access this rule detects.>
            author: <Your name>
            date: \(date)
            references:
                - https://attack.mitre.org/techniques/TXXXX/
            tags:
                - attack.collection
                - attack.tXXXX
            logsource:
                category: tcc_event
                product: macos
            detection:
                selection:
                    TCCService: 'kTCCServiceCamera'
                    TCCAllowed: 'true'
                filter_signed:
                    SignerType:
                        - 'apple'
                        - 'appStore'
                        - 'devId'
                condition: selection and not filter_signed
            falsepositives:
                - <Known legitimate use cases>
            level: high
            """

        case "sequence":
            template = """
            title: <Sequence Rule Title>
            id: \(id)
            status: experimental
            description: >
                <Describe the multi-step attack chain this rule detects.>
            author: <Your name>
            date: \(date)
            references:
                - https://attack.mitre.org/techniques/TXXXX/
            tags:
                - attack.execution
                - attack.tXXXX

            type: sequence
            window: 60s
            correlation: process.lineage
            ordered: true

            steps:
                - id: step1
                  logsource:
                      category: process_creation
                      product: macos
                  detection:
                      selection:
                          Image|endswith:
                              - '/suspicious-tool'
                      condition: selection

                - id: step2
                  logsource:
                      category: network_connection
                      product: macos
                  detection:
                      selection:
                          DestinationIsPrivate: 'false'
                      condition: selection
                  process: step1.descendant

            trigger: all
            level: critical
            """

        default:
            template = "Unknown category: \(category). Use: process_creation, file_event, network_connection, tcc_event, sequence"
        }

        print(template)
        print("")
        print("# Save this to Rules/<tactic>/<rule_name>.yml")
        print("# Then compile: python3 Compiler/compile_rules.py --input-dir Rules/ --output-dir compiled_rules/")
    }
}
