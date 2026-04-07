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

        let jsonFiles = files.filter { $0.hasSuffix(".json") }.sorted()

        print("Detection Rules (\(jsonFiles.count) total)")
        print("══════════════════════════════════════════════════════════════")
        print(String(format: "%-8s %-50s %s", "Level", "Title", "Tags"))
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

            print(String(format: "%-8s %-50s %s", levelStr, String(title.prefix(48)), String(tags.prefix(30))))
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

        for file in files where file.hasSuffix(".json") {
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
