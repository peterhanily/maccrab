import Foundation
import MacCrabCore

extension MacCrabCtl {
    static func listRules(json: Bool = false) async {
        do {
            let document = try RuleInventoryDocument.read(directory: maccrabDataDir())
            if json { try printCLIJSON(document); return }
            print("Compiled single-event rules (\(document.rules.count) total)")
            print(document.telemetryFreshness.reason)
            if let date = document.telemetryWrittenAt {
                print("Telemetry written: \(ISO8601DateFormatter().string(from: date))")
            }
            print("Rule profile: \(document.ruleProfile ?? "unknown")")
            for rule in document.rules {
                let counts = rule.evaluationCount.map { " — \($0) evaluations, \(rule.fireCount ?? 0) matches" } ?? ""
                print("[\(rule.level.uppercased())] \(rule.title) [\(rule.coverage.rawValue)]\(counts)")
                print("  \(rule.id)")
            }
        } catch { cliFailure("rules list: \(error.localizedDescription)") }
    }

    static func countRules(json: Bool = false) async {
        do {
            let document = try RuleInventoryDocument.read(directory: maccrabDataDir())
            var bySeverity: [String: Int] = [:]
            var byCategory: [String: Int] = [:]
            for rule in document.rules {
                bySeverity[rule.level, default: 0] += 1
                byCategory[rule.category ?? "unknown", default: 0] += 1
            }
            if json {
                try printCLIJSONObject([
                    "schema_version": 1, "source_directory": document.sourceDirectory,
                    "total": document.rules.count, "by_severity": bySeverity,
                    "by_category": byCategory,
                ])
                return
            }
            print("Compiled single-event rules: \(document.rules.count)")
            print("Rules by severity:")
            for key in bySeverity.keys.sorted() { print("  \(key): \(bySeverity[key]!)") }
            print("Rules by log source:")
            for key in byCategory.keys.sorted() { print("  \(key): \(byCategory[key]!)") }
        } catch { cliFailure("rules count: \(error.localizedDescription)") }
    }

    static func compileRules(inputDir: String, outputDir: String) {
        cliFailure("The CLI does not include a Sigma compiler. From the repository, run Python Compiler/compile_rules.py with --input-dir and --output-dir. No rules were compiled.")
    }

    /// Flip a rule's `enabled` flag on disk inside its compiled JSON. The
    /// detection engine reads the flag on load — a SIGHUP or sysext
    /// restart after running this picks up the change. Lets a user park
    /// a noisy rule without deleting the source YAML or recompiling.
    ///
    /// Writes to compiled_rules/<file>.json directly; falls back to
    /// scanning the dir for a matching rule id when no filename is given.
    static func setRuleEnabled(ruleId: String, enabled: Bool) {
        let directory = maccrabDataDir()
        do {
            _ = try RuleInventoryDocument.read(directory: directory)
            let root = URL(fileURLWithPath: directory + "/compiled_rules")
            let files = try FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil)
                .filter { $0.pathExtension == "json" && $0.lastPathComponent != "manifest.json" }
            for file in files {
                let data = try Data(contentsOf: file)
                guard var object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                      object["id"] as? String == ruleId else { continue }
                object["enabled"] = enabled
                let output = try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
                try output.write(to: file, options: .atomic)
                print("Saved enabled=\(enabled) for compiled rule \(ruleId). Runtime application is pending.")
                print("Run maccrabctl rules reload, then inspect the returned request ID with config status.")
                return
            }
            throw RuntimeConfigContractError("Rule '\(ruleId)' was not found in the compiled corpus")
        } catch { cliFailure("rule \(enabled ? "enable" : "disable"): \(error.localizedDescription)") }
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
