// WormSelfPropagationRuleCompilationTests.swift
// v1.12.0 — smoke-tests that the 9 surgical YAML rules + the worm
// sequence rule from the May 2026 Mini Shai-Hulud wave compile cleanly
// and produce loadable JSON predicates. Pairs with GraphRuleEvaluatorTests
// which covers the graph rule end-to-end.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("v1.12.0: WormSelfPropagation rule corpus")
struct WormSelfPropagationRuleCompilationTests {

    private let compiledDir = "/tmp/maccrab_v3"

    /// Slugs of the 20 single-event YAML rules added in v1.12.0
    /// (initial 9 worm-loop wedge + 11 dep-confusion / content-anomaly
    /// rules added in the second v1.12.0 expansion). Each must
    /// produce a JSON sibling under the compiled output dir.
    private let singleEventRuleSlugs: [String] = [
        // Worm-loop wedge
        "homebrew_tap_mitm_cleartext_http",
        "homebrew_formula_no_check_sha",
        "bun_executes_from_node_modules",
        "claude_settings_hook_injection_by_non_claude",
        "github_user_repos_post_from_non_git",
        "npm_publish_self_propagation",
        "pypi_twine_upload_from_non_interactive",
        "dead_mans_switch_literal_scanner",
        "package_runtime_drop_evasion",
        // Dependency confusion / namespace
        "pip_install_with_extra_index_url_to_public_pypi",
        "npmrc_pypirc_modified_by_non_package_manager",
        "registry_oidc_token_exchange_from_non_interactive",
        // Content anomaly / cross-ecosystem smuggle
        "package_drops_native_binary_in_pure_js_pkg",
        "pip_wheel_drops_javascript_runtime_files",
        "webhook_exfil_url_in_install_content",
        "package_postinstall_fetches_alt_runtime",
        "node_modules_contains_leaked_dotfile",
        "obfuscator_signature_in_package_payload",
        // Editor / CI persistence (extends agent-context hook coverage)
        "package_install_drops_github_workflow",
        "vscode_tasks_json_modified_by_non_vscode",
        // Dead-man's-switch space (Wave 3)
        "token_revocation_polling_loop",
        "mass_unlink_from_package_lineage",
        "launchagent_with_distant_future_trigger",
        "locale_check_from_package_lineage",
        "vm_detection_probe_from_package_lineage",
        "maccrab_tamper_attempt",
        "staged_fetch_then_exec_from_user_writable",
        "openssl_decrypt_in_install_lineage",
        // macOS app threat space (Wave 4)
        "fake_apple_bundle_in_user_dir",
        "mas_receipt_access_by_non_sandbox",
        "binary_resigned_post_installation",
        "adhoc_signed_app_execution_from_user_dir",
        "network_policy_plist_tampered",
        "info_plist_modification_post_install",
        "url_scheme_handler_collision",
        "bulk_quarantine_strip",
        // Innovative research wave (Wave 5)
        "honeyprompt_canary_package_install",
        "persona_takeover_fingerprint_drift",
        "urgency_lexicon_in_install_lineage_pr",
        "maintainer_publish_hour_anomaly",
        "canary_skill_or_rules_read",
        "llm_classifier_high_risk_intent",
    ]

    /// Slug of the v1.12.0 sequence rule that mirrors the graph signature.
    private let sequenceRuleSlug = "worm_self_propagation_signal"

    @Test("All 42 v1.12.0 single-event YAML rules compile to JSON predicates")
    func singleEventRulesCompile() {
        ensureRulesCompiled()
        for slug in singleEventRuleSlugs {
            let path = "\(compiledDir)/\(slug).json"
            #expect(
                FileManager.default.fileExists(atPath: path),
                "Expected compiled rule at \(path) — rule did not compile or output landed elsewhere"
            )
        }
    }

    @Test("Worm-self-propagation sequence rule compiles to JSON")
    func sequenceRuleCompiles() {
        ensureRulesCompiled()
        let path = "\(compiledDir)/sequences/\(sequenceRuleSlug).json"
        #expect(
            FileManager.default.fileExists(atPath: path),
            "Expected sequence rule at \(path)"
        )
    }

    @Test("Each compiled rule decodes as JSON with required top-level fields")
    func compiledRulesAreWellFormed() throws {
        ensureRulesCompiled()
        for slug in singleEventRuleSlugs {
            let path = "\(compiledDir)/\(slug).json"
            let data = try Data(contentsOf: URL(fileURLWithPath: path))
            let any = try JSONSerialization.jsonObject(with: data)
            guard let dict = any as? [String: Any] else {
                Issue.record("Rule \(slug) JSON is not a top-level object")
                continue
            }
            #expect(dict["id"] is String, "rule \(slug) missing id")
            #expect(dict["title"] is String, "rule \(slug) missing title")
            #expect(dict["level"] is String, "rule \(slug) missing level")
        }
    }

    @Test("Critical-severity worm rules are tagged as critical")
    func criticalRulesAreCritical() throws {
        ensureRulesCompiled()
        let mustBeCritical = [
            "github_user_repos_post_from_non_git",
            "npm_publish_self_propagation",
            "pypi_twine_upload_from_non_interactive",
            "dead_mans_switch_literal_scanner",
            // Second-wave critical rules
            "pip_wheel_drops_javascript_runtime_files",
            "webhook_exfil_url_in_install_content",
            "registry_oidc_token_exchange_from_non_interactive",
            // v1.12.0 RC3 (Det-H1): `package_install_drops_github_workflow`
            // dropped from must-be-critical list. The rule was downgraded
            // to high because critical-severity fired on every legit
            // project scaffold (create-react-app, vite, cookiecutter)
            // dropping .github/workflows/*.yml — the scaffold pattern is
            // structurally indistinguishable from the worm-scrape
            // signature. Re-classify as critical once we can detect
            // scaffold context (no prior .git, fresh cwd).
            // Wave 3/4 critical rules
            "mass_unlink_from_package_lineage",
            // v1.17.1: `maccrab_tamper_attempt` is intentionally NOT critical.
            // rm/launchctl/pkill of MacCrab paths via a shell is identical in
            // shape to MacCrab's own install/update/reload (and the OS's
            // privileged sysext de/activation), and those break the MacCrab
            // lineage, so the rule can't be made low-FP. Demoted to HIGH (so
            // NoiseFilter's Apple-binary gate suppresses it); SelfDefense is
            // the authoritative tamper detector. See the rule's header comment.
            // Wave 5 — innovative research
            "honeyprompt_canary_package_install",
            "canary_skill_or_rules_read",
        ]
        for slug in mustBeCritical {
            let path = "\(compiledDir)/\(slug).json"
            let data = try Data(contentsOf: URL(fileURLWithPath: path))
            let dict = try JSONSerialization.jsonObject(with: data) as? [String: Any]
            let level = dict?["level"] as? String
            #expect(level == "critical", "rule \(slug) should be critical, got \(level ?? "nil")")
        }
    }

    @Test("All v1.12.0 sequence rule IDs are unique across Rules/sequences/")
    func sequenceRuleIdsAreUnique() throws {
        let projectDir = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()   // Tests/MacCrabCoreTests
            .deletingLastPathComponent()   // Tests
            .deletingLastPathComponent()   // project root
        let seqDir = projectDir.appendingPathComponent("Rules/sequences")
        let fm = FileManager.default
        let files = try fm.contentsOfDirectory(atPath: seqDir.path)
            .filter { $0.hasSuffix(".yml") || $0.hasSuffix(".yaml") }
        var seen: [String: String] = [:]
        for f in files {
            let body = try String(contentsOf: seqDir.appendingPathComponent(f), encoding: .utf8)
            guard let idLine = body.split(separator: "\n").first(where: { $0.hasPrefix("id:") }) else {
                Issue.record("\(f) missing id: line")
                continue
            }
            let id = idLine
                .dropFirst("id:".count)
                .trimmingCharacters(in: .whitespaces)
            if let prior = seen[id] {
                Issue.record("Duplicate sequence rule id \(id): \(prior) and \(f)")
            }
            seen[id] = f
        }
    }
}
