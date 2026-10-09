// WhyCommandTests.swift
// MacCrabCLITests
//
// `maccrabctl why`: the rule lookup reads the top level of user_rules before
// compiled_rules and its sequences/ and graph/ folders, sequence and graph
// rules are rendered, and the single-event rendering keeps its previous form.
// The fixtures are real compiled rules: the kill-chain sequence
// supply_chain_full_kill_chain.yml run through Compiler/compile_rules.py, a
// rule from Rules/graph, and the compiled single-event rules ssh_key_access.yml
// and sudoers_modification.yml.

import Foundation
import Testing
@testable import maccrabctl

@Suite("maccrabctl: why rule lookup and rendering")
struct WhyCommandTests {

    @Test("the lookup reads user_rules first, then compiled_rules and its sequences/ and graph/ folders, and finds nothing for an unknown id")
    func ruleLookup() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrabctl-why-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let rules = dir.appendingPathComponent("compiled_rules")
        let users = dir.appendingPathComponent("user_rules")

        func write(_ json: String, _ folder: URL, _ name: String) throws -> String {
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
            let path = folder.appendingPathComponent(name).path
            try json.write(toFile: path, atomically: true, encoding: .utf8)
            return path
        }
        let single = try write(Self.flatRule, rules, "ssh_key_access.json")
        let sequence = try write(Self.sequenceRule, rules.appendingPathComponent("sequences"), "supply_chain_full_kill_chain.json")
        let graph = try write(Self.graphRule, rules.appendingPathComponent("graph"), "maccrab_agent_associated_shell_writes_to_login_item.json")
        // A support dir that does not exist is skipped.
        let dirs = MacCrabCtl.whySearchDirs(supportDirs: [dir.appendingPathComponent("missing").path, dir.path])
        #expect(Array(dirs.suffix(4)) == [users.path, rules.path, rules.path + "/sequences", rules.path + "/graph"])

        func lookup(_ id: String) -> String? { MacCrabCtl.findRuleFile(forRuleID: id, in: dirs) }

        #expect(lookup("d1a2b3c4-0032-4000-a000-000000000032") == single)
        #expect(lookup("e1f2a3b4-0023-4000-b000-000000000023") == sequence)
        #expect(lookup("maccrab_agent_associated_shell_writes_to_login_item") == graph)
        // Built-in detectors raise alerts under ids that have no rule file.
        #expect(lookup("baseline-anomaly") == nil)

        // A user rule (dashboard-authored, or an override of a bundled rule)
        // is found before the compiled rule with the same id.
        let override = try write(Self.flatRule, users, "ssh_key_access.json")
        #expect(lookup("d1a2b3c4-0032-4000-a000-000000000032") == override)
        // Like the daemon, only the top level of user_rules is read.
        _ = try write(Self.sequenceRule, users.appendingPathComponent("sequences"), "supply_chain_full_kill_chain.json")
        #expect(lookup("e1f2a3b4-0023-4000-b000-000000000023") == sequence)
    }

    @Test("a sequence rule shows its window, correlation, ordering, trigger and every step")
    func sequenceRendering() throws {
        let (lines, _) = try Self.render(
            Self.sequenceRule, path: "compiled_rules/sequences/supply_chain_full_kill_chain.json"
        )

        #expect(lines.contains("Window:      300 seconds"))
        #expect(lines.contains("Correlation: processLineage"))
        #expect(lines.contains("Ordered:     true"))
        #expect(lines.contains("Trigger:     steps [persist, exfil]"))
        #expect(lines.filter { $0.hasPrefix("Step ") } == [
            "Step 1 of 3: package_install  (process_creation)",
            "Step 2 of 3: persist  (file_event)",
            "Step 3 of 3: exfil  (network_connection)",
        ])
        // Each step's predicates use the single-event format, indented under the step.
        #expect(lines.filter { $0.hasPrefix("  Predicates (") } == [
            "  Predicates (4):", "  Predicates (6):", "  Predicates (1):",
        ])
        #expect(lines.contains(
            "     1. process.executable               endswith       /npm, /npx, /pip, … (6 total)"
        ))
        #expect(lines.filter { $0 == "  Process relation: descendant (relative to step package_install)" }.count == 2)
        #expect(lines.filter { $0 == "  Condition AST:" }.count == 2)
        // The exfil step has no condition tree, so its flat condition is shown.
        #expect(lines.last == "  Condition:   all_of")
    }

    @Test("a graph rule shows its nodes, edges, scope and constraints")
    func graphRendering() throws {
        let (lines, _) = try Self.render(
            Self.graphRule, path: "compiled_rules/graph/maccrab_agent_associated_shell_writes_to_login_item.json"
        )

        // A graph rule has no description, so the rule file and the bar come first.
        #expect(Array(lines.dropFirst(2)) == [
            "Nodes (3):",
            "  agent  ai_agent",
            "  login  persistence  where persistence_type in [login_item, launch_agent]",
            "  shell  process  where executable_name in [zsh, bash, sh, … (7 total)]",
            "Edges (2):",
            "  agent -associated_with_agent-> shell  (min tier: strong_inferred)",
            "  shell -created_persistence-> login  (min tier: strong_inferred)",
            "Scope:       common_ancestor=shell",
            "Constraints: min_confidence=0.7, within_seconds=600",
        ])
    }

    @Test("a single-event rule renders exactly as before")
    func singleEventRendering() throws {
        let bar = String(repeating: "─", count: 72)

        let flatPath = "compiled_rules/ssh_key_access.json"
        let (flat, _) = try Self.render(Self.flatRule, path: flatPath)
        #expect(flat == [
            "Rule file:   \(flatPath)",
            "Summary:     Detects non-SSH processes reading SSH private key files, "
                + "which may indicate credential theft.",
            bar,
            "Predicates (4):",
            "   1. file.path                        contains       /.ssh/",
            "   2. file.path                        endswith       /id_rsa, /id_ed25519, /id_ecdsa, /id_dsa",
            "   3. process.executable               NOT endswith   /ssh, /ssh-agent, /ssh-add, … (8 total)",
            "   4. SignerType                       NOT equals     apple",
        ])

        let treePath = "compiled_rules/sudoers_modification.json"
        let (tree, treeRule) = try Self.render(Self.treeRule, path: treePath)
        #expect(Array(tree.prefix(8)) == [
            "Rule file:   \(treePath)",
            "Summary:     Detects any modification to /etc/sudoers or files under /etc/sudoers.d/. Attackers modify "
                + "sudoers to grant themselves passwordless sudo access, establishing persistent privilege escalation "
                + "without needing to exploit a vulnerability.\n",
            bar,
            "Predicates (4):",
            "   1. file.path                        startswith     /etc/sudoers, /private/etc/sudoers",
            "   2. FileAction                       equals         write",
            "   3. process.executable               endswith       /visudo",
            "   4. SignerType                       equals         apple",
        ])
        // Then the condition tree, pretty-printed by JSONSerialization and indented two spaces.
        let conditionTree = try #require(treeRule["condition_tree"])
        let ast = String(decoding: try JSONSerialization.data(withJSONObject: conditionTree, options: .prettyPrinted),
                         as: UTF8.self)
        #expect(Array(tree.dropFirst(8)) == ["Condition AST:"] + ast.split(separator: "\n").map { "  \($0)" })
        #expect(tree.contains(#"    "type" : "or","#))
    }

    /// Parses a fixture the way `runWhy` parses a rule file, then renders it.
    private static func render(_ json: String, path: String) throws -> (lines: [String], rule: [String: Any]) {
        let rule = try #require(try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
        return (MacCrabCtl.whyRuleLines(rule, rulePath: path), rule)
    }

    // Rules/sequences/supply_chain_full_kill_chain.yml, compiled.
    private static let sequenceRule = #"""
        {
          "id": "e1f2a3b4-0023-4000-b000-000000000023",
          "title": "Full Supply Chain Kill Chain - Install to Persist to Exfiltrate",
          "description": "Detects a supply chain attack chain: a package-manager install, then persistence (a LaunchAgent or LaunchDaemon, cron, a .pth file or a shell profile) and a network connection to a public address, both from the install's descendants.\n",
          "level": "high",
          "tags": [
            "attack.initial_access",
            "attack.persistence",
            "attack.credential_access",
            "attack.exfiltration",
            "attack.t1195.001",
            "attack.t1543.001",
            "attack.t1552.001"
          ],
          "window": 300.0,
          "correlationType": "processLineage",
          "ordered": true,
          "steps": [
            {
              "id": "package_install",
              "logsourceCategory": "process_creation",
              "predicates": [
                {
                  "field": "process.executable",
                  "modifier": "endswith",
                  "values": ["/npm", "/npx", "/pip", "/pip3", "/gem", "/cargo"],
                  "negate": false
                },
                {"field": "process.commandline", "modifier": "contains", "values": ["install"], "negate": false},
                {"field": "process.executable", "modifier": "endswith", "values": ["/node"], "negate": false},
                {
                  "field": "process.commandline",
                  "modifier": "contains",
                  "values": ["/npm install", "/npm-cli.js install"],
                  "negate": false
                }
              ],
              "condition": "any_of",
              "afterStep": null,
              "processRelation": null,
              "condition_tree": {
                "type": "or",
                "operands": [
                  {"type": "group", "rangeStart": 0, "rangeEnd": 2, "mode": "all_of"},
                  {"type": "group", "rangeStart": 2, "rangeEnd": 4, "mode": "all_of"}
                ]
              }
            },
            {
              "id": "persist",
              "logsourceCategory": "file_event",
              "predicates": [
                {"field": "file.path", "modifier": "contains", "values": ["/LaunchAgents/"], "negate": false},
                {"field": "file.path", "modifier": "contains", "values": ["/LaunchDaemons/"], "negate": false},
                {"field": "file.path", "modifier": "startswith", "values": ["/private/var/at/tabs/"], "negate": false},
                {"field": "file.path", "modifier": "endswith", "values": [".pth"], "negate": false},
                {"field": "file.path", "modifier": "contains", "values": ["site-packages"], "negate": false},
                {
                  "field": "file.path",
                  "modifier": "endswith",
                  "values": ["/.zshrc", "/.bashrc", "/.bash_profile"],
                  "negate": false
                }
              ],
              "condition": "any_of",
              "afterStep": "package_install",
              "processRelation": {"relation": "descendant", "relativeToStep": "package_install"},
              "condition_tree": {
                "type": "or",
                "operands": [
                  {"type": "predicate", "index": 0},
                  {"type": "predicate", "index": 1},
                  {"type": "predicate", "index": 2},
                  {"type": "group", "rangeStart": 3, "rangeEnd": 5, "mode": "all_of"},
                  {"type": "predicate", "index": 5}
                ]
              }
            },
            {
              "id": "exfil",
              "logsourceCategory": "network_connection",
              "predicates": [
                {"field": "DestinationIsPrivate", "modifier": "equals", "values": ["false"], "negate": false}
              ],
              "condition": "all_of",
              "afterStep": "persist",
              "processRelation": {"relation": "descendant", "relativeToStep": "package_install"}
            }
          ],
          "trigger": {"type": "steps", "value": ["persist", "exfil"]},
          "enabled": true,
          "status": "stable",
          "suppressible": false
        }
        """#

    // Rules/graph/maccrab_agent_associated_shell_writes_to_login_item.json.
    private static let graphRule = #"""
        {
          "id": "maccrab_agent_associated_shell_writes_to_login_item",
          "title": "AI-associated shell wrote to a login item",
          "severity": "high",
          "type": "graph",
          "status": "stable",
          "nodes": {
            "agent": {"type": "ai_agent"},
            "shell": {
              "type": "process",
              "where": {"executable_name": {"in": ["zsh", "bash", "sh", "osascript", "python", "python3", "node"]}}
            },
            "login": {"type": "persistence", "where": {"persistence_type": {"in": ["login_item", "launch_agent"]}}}
          },
          "edges": [
            {"from": "agent", "to": "shell", "relation": "associated_with_agent", "min_tier": "strong_inferred"},
            {"from": "shell", "to": "login", "relation": "created_persistence", "min_tier": "strong_inferred"}
          ],
          "scope": {"common_ancestor": "shell"},
          "constraints": {"within_seconds": 600, "min_confidence": 0.7},
          "attack": ["T1543.001", "T1547"]
        }
        """#

    // Rules/credential_access/ssh_key_access.yml, compiled: a flat condition with negated predicates.
    private static let flatRule = #"""
        {
          "id": "d1a2b3c4-0032-4000-a000-000000000032",
          "title": "SSH Private Key Accessed by Unusual Process",
          "description": "Detects non-SSH processes reading SSH private key files, which may indicate credential theft.",
          "level": "medium",
          "suppressible": true,
          "tags": ["attack.credential_access", "attack.t1552.004"],
          "logsource": {"category": "file_event", "product": "macos"},
          "predicates": [
            {"field": "file.path", "modifier": "contains", "values": ["/.ssh/"], "negate": false},
            {
              "field": "file.path",
              "modifier": "endswith",
              "values": ["/id_rsa", "/id_ed25519", "/id_ecdsa", "/id_dsa"],
              "negate": false
            },
            {
              "field": "process.executable",
              "modifier": "endswith",
              "values": ["/ssh", "/ssh-agent", "/ssh-add", "/sshd", "/scp", "/sftp", "/git", "/ssh-keygen"],
              "negate": true
            },
            {"field": "SignerType", "modifier": "equals", "values": ["apple"], "negate": true}
          ],
          "condition": "all_of",
          "falsepositives": ["Key management tools", "IDE SSH integrations"],
          "enabled": true,
          "status": "experimental"
        }
        """#

    // Rules/defense_evasion/sudoers_modification.yml, compiled: a condition tree.
    private static let treeRule = #"""
        {
          "id": "d1a2b3c4-0439-4000-b000-000000000439",
          "title": "Sudoers File Modified",
          "description": "Detects any modification to /etc/sudoers or files under /etc/sudoers.d/. Attackers modify sudoers to grant themselves passwordless sudo access, establishing persistent privilege escalation without needing to exploit a vulnerability.\n",
          "level": "high",
          "suppressible": true,
          "tags": ["attack.defense_evasion", "attack.privilege_escalation", "attack.t1548.003"],
          "logsource": {"category": "file_event", "product": "macos"},
          "predicates": [
            {
              "field": "file.path",
              "modifier": "startswith",
              "values": ["/etc/sudoers", "/private/etc/sudoers"],
              "negate": false
            },
            {"field": "FileAction", "modifier": "equals", "values": ["write"], "negate": false},
            {"field": "process.executable", "modifier": "endswith", "values": ["/visudo"], "negate": false},
            {"field": "SignerType", "modifier": "equals", "values": ["apple"], "negate": false}
          ],
          "condition": "any_of",
          "falsepositives": [
            "Legitimate system administration via visudo",
            "MDM or configuration management tools adjusting sudo policies"
          ],
          "enabled": true,
          "status": "experimental",
          "condition_tree": {
            "type": "or",
            "operands": [
              {"type": "group", "rangeStart": 0, "rangeEnd": 2, "mode": "all_of"},
              {
                "type": "and",
                "operands": [
                  {"type": "predicate", "index": 2},
                  {"type": "not", "operands": [{"type": "predicate", "index": 3}]}
                ]
              }
            ]
          }
        }
        """#
}
