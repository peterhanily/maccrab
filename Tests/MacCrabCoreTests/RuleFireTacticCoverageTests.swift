// RuleFireTacticCoverageTests.swift
// v1.18 — positive + true-negative fire tests for high-stakes rules in
// tactic directories that previously had ZERO rule-fire coverage
// (privilege_escalation, lateral_movement, container, collection) plus the
// residual credential_access / defense_evasion rules the audit flagged.
//
// Identity is pinned by EXACT rule UUID (not a ruleName substring), so a
// rename or removal fails loudly instead of turning the test vacuous. The
// RuleFireCoverageGateTests suite below makes that a regressible signal.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("Rule fires — zero-coverage tactics (v1.18)")
struct RuleFireTacticCoverageTests {

    private func process(
        executable: String,
        commandLine: String,
        signer: SignerType = .unsigned,
        parentExec: String = "/bin/bash"
    ) -> MacCrabCore.ProcessInfo {
        let sig = CodeSignatureInfo(
            signerType: signer, teamId: signer == .devId ? "ABC1234567" : nil,
            signingId: nil, authorities: [], flags: 0,
            isNotarized: signer == .apple || signer == .devId,
            issuerChain: nil, certHashes: nil, isAdhocSigned: nil, entitlements: nil)
        return MacCrabCore.ProcessInfo(
            pid: 4321, ppid: 1, rpid: 1,
            name: (executable as NSString).lastPathComponent,
            executable: executable, commandLine: commandLine, args: [executable],
            workingDirectory: "/tmp", userId: 501, userName: "alice", groupId: 20,
            startTime: Date(), codeSignature: sig,
            ancestors: [ProcessAncestor(pid: 1, executable: parentExec, name: (parentExec as NSString).lastPathComponent)],
            architecture: "arm64", isPlatformBinary: signer == .apple)
    }

    private func event(_ p: MacCrabCore.ProcessInfo) -> Event {
        Event(eventCategory: .process, eventType: .start, eventAction: "exec", process: p)
    }

    private func loadEngine() async throws -> RuleEngine {
        ensureRulesCompiled()
        let engine = RuleEngine()
        _ = try await engine.loadRules(from: URL(fileURLWithPath: "/tmp/maccrab_v3"))
        return engine
    }

    private func fires(_ matches: [RuleMatch], _ id: String) -> Bool {
        matches.contains { $0.ruleId == id }
    }

    // defense_evasion — nvram AMFI manipulation
    @Test("nvram AMFI manipulation fires; benign nvram read does not")
    func nvramAmfi() async throws {
        let e = try await loadEngine()
        let id = "d1a2b3c4-0342-4000-a000-000000000342"
        let tp = await e.evaluate(event(process(executable: "/usr/sbin/nvram", commandLine: "nvram boot-args=amfi_get_out_of_my_way=1")))
        let tn = await e.evaluate(event(process(executable: "/usr/sbin/nvram", commandLine: "nvram -p")))
        #expect(fires(tp, id), "expected nvram_amfi_manipulation, got \(tp.map(\.ruleId))")
        #expect(!fires(tn, id), "benign `nvram -p` must not fire")
    }

    // container — docker socket mount
    @Test("docker socket mount fires; a benign volume mount does not")
    func dockerSocket() async throws {
        let e = try await loadEngine()
        let id = "d1a2b3c4-0421-4000-a000-000000000421"
        let tp = await e.evaluate(event(process(executable: "/usr/local/bin/docker", commandLine: "docker run -v /var/run/docker.sock:/var/run/docker.sock alpine")))
        let tn = await e.evaluate(event(process(executable: "/usr/local/bin/docker", commandLine: "docker run -v /data:/data alpine")))
        #expect(fires(tp, id), "expected docker_socket_mount, got \(tp.map(\.ruleId))")
        #expect(!fires(tn, id), "a non-socket volume mount must not fire")
    }

    // credential_access — keychain dump via the security CLI.
    // /usr/bin/security IS an Apple platform binary, so the rule must key on the
    // SPAWNER (ParentSignerType), not the subject's own always-Apple signature
    // (the BLOCKER-2 bug). Model reality: the Apple-signed `security` LOLBin run
    // by a non-Apple dropper. Pre-fix this only "passed" because it modeled an
    // impossible UNSIGNED /usr/bin/security.
    @Test("Apple-signed security dump-keychain from a non-Apple parent fires; benign subcommand does not")
    func keychainDump() async throws {
        let e = try await loadEngine()
        let id = "d1a2b3c4-0030-4000-a000-000000000030"
        let tp = await e.evaluate(event(process(executable: "/usr/bin/security", commandLine: "security dump-keychain -d", signer: .apple, parentExec: "/tmp/dropper")))
        let tn = await e.evaluate(event(process(executable: "/usr/bin/security", commandLine: "security list-keychains", signer: .apple, parentExec: "/tmp/dropper")))
        #expect(fires(tp, id), "expected keychain_dump_via_security, got \(tp.map(\.ruleId))")
        #expect(!fires(tn, id), "`security list-keychains` must not fire")
    }

    // privilege_escalation — platform-binary dylib injection
    @Test("tclsh dylib-load injection fires; a benign tclsh script does not")
    func dylibInjection() async throws {
        let e = try await loadEngine()
        let id = "d1a2b3c4-0340-4000-a000-000000000340"
        let tp = await e.evaluate(event(process(executable: "/usr/bin/tclsh", commandLine: "tclsh -c load /tmp/evil.dylib")))
        let tn = await e.evaluate(event(process(executable: "/usr/bin/tclsh", commandLine: "tclsh /tmp/harmless.tcl")))
        #expect(fires(tp, id), "expected platform_binary_dylib_injection, got \(tp.map(\.ruleId))")
        #expect(!fires(tn, id), "a benign tclsh script must not fire")
    }

    // collection — CGEventTap keylogger reference
    @Test("CGEventTap keylogger reference by unsigned process fires; Apple-signed does not")
    func keyloggerEventTap() async throws {
        let e = try await loadEngine()
        let id = "d1a2b3c4-0091-4000-a000-000000000091"
        let tp = await e.evaluate(event(process(executable: "/tmp/klog", commandLine: "/tmp/klog --hook CGEventTapCreate")))
        let tn = await e.evaluate(event(process(executable: "/usr/bin/hidtool", commandLine: "hidtool CGEventTapCreate", signer: .apple)))
        #expect(fires(tp, id), "expected keylogger_event_tap, got \(tp.map(\.ruleId))")
        #expect(!fires(tn, id), "Apple-signed CGEventTap use must not fire")
    }

    // lateral_movement — SSH agent socket hijacking
    @Test("SSH_AUTH_SOCK access by an untrusted process fires; git does not")
    func sshAgentHijack() async throws {
        let e = try await loadEngine()
        let id = "a1b2c3d4-1002-4000-b000-000000001002"
        let tp = await e.evaluate(event(process(executable: "/tmp/stealer", commandLine: "/tmp/stealer SSH_AUTH_SOCK=/tmp/ssh-abc/agent.123")))
        let tn = await e.evaluate(event(process(executable: "/usr/bin/git", commandLine: "git fetch SSH_AUTH_SOCK=/tmp/ssh-abc/agent.123")))
        #expect(fires(tp, id), "expected ssh_agent_hijacking, got \(tp.map(\.ruleId))")
        #expect(!fires(tn, id), "git (a known SSH_AUTH_SOCK consumer) must not fire")
    }
}

@Suite("Rule-fire coverage gate (v1.18)")
struct RuleFireCoverageGateTests {

    /// Rule UUIDs that have an explicit positive fire test, kept in sync with
    /// the fire-test suites. A rename/removal here fails loudly instead of
    /// silently making a fire test vacuous.
    static let coveredRuleIds: [String: String] = [
        "d1a2b3c4-0342-4000-a000-000000000342": "nvram_amfi_manipulation",
        "d1a2b3c4-0421-4000-a000-000000000421": "docker_socket_mount",
        "d1a2b3c4-0030-4000-a000-000000000030": "keychain_dump_via_security",
        "d1a2b3c4-0340-4000-a000-000000000340": "platform_binary_dylib_injection",
        "d1a2b3c4-0091-4000-a000-000000000091": "keylogger_event_tap",
        "a1b2c3d4-1002-4000-b000-000000001002": "ssh_agent_hijacking",
        "c4f6a9b2-3e5d-4c1a-8d90-1b2e3f4a5c60": "ssh_launched_security_dump",
    ]

    private func loadEngine() async throws -> RuleEngine {
        ensureRulesCompiled()
        let engine = RuleEngine()
        _ = try await engine.loadRules(from: URL(fileURLWithPath: "/tmp/maccrab_v3"))
        return engine
    }

    @Test("every fire-tested rule id still exists in the compiled ruleset (no vacuous fire tests)")
    func coveredIdsAreReal() async throws {
        let engine = try await loadEngine()
        let all = Set(await engine.listRules().map(\.id))
        for (id, slug) in Self.coveredRuleIds {
            #expect(all.contains(id), "fire-tested rule \(slug) (\(id)) is gone from the compiled set — update its fire test")
        }
    }

    @Test("every compiled rule is dispatchable in its declared category (no silently-unfireable rules)")
    func everyRuleDispatchable() async throws {
        let engine = try await loadEngine()
        let total = await engine.ruleCount
        #expect(total > 300, "rule-count floor — guards against an accidental mass-drop (got \(total))")
        for rule in await engine.listRules() {
            let reachable = await engine.listRules(category: rule.logsource.category).contains { $0.id == rule.id }
            #expect(reachable, "rule \(rule.id) (\(rule.title)) is not dispatchable in category '\(rule.logsource.category)'")
        }
    }
}
