// NoiseFilterPipelineTests.swift
// v1.18 — the END-TO-END guard the corpus suite was missing.
//
// RuleCorpusTests assert RuleEngine.evaluate() matches; they never pipe the
// match through NoiseFilter.apply, which is the actual live path. That blind
// spot let Gate 7 silently drop the entire LOLBin/C2 execution class (curl|bash,
// osascript do-shell-script) — every shell/interpreter is an Apple platform
// binary, so a suppressible exec match was removed AFTER matching, and CI stayed
// green. These tests run the FULL pipeline (evaluate → NoiseFilter.apply) and
// assert the user-visible outcome: a real LOLBin match SURVIVES.
import Testing
import Foundation
@testable import MacCrabCore

@Suite("NoiseFilter end-to-end pipeline (Gate-7 LOLBin regression guard)")
struct NoiseFilterPipelineTests {

    /// A process event whose subject is an Apple-shipped interpreter (so Gate 7's
    /// isAppleSystemBinary fires) running a malicious commandline.
    private func appleInterpreterEvent(exec: String, commandLine: String,
                                       parent: String = "/bin/zsh") -> Event {
        let sig = CodeSignatureInfo(signerType: .apple, teamId: nil, signingId: nil, authorities: [],
                                    flags: 0, isNotarized: true, issuerChain: nil, certHashes: nil,
                                    isAdhocSigned: nil, entitlements: nil)
        let p = MacCrabCore.ProcessInfo(
            pid: 4321, ppid: 1, rpid: 1, name: (exec as NSString).lastPathComponent,
            executable: exec, commandLine: commandLine, args: [exec, "-c", commandLine],
            workingDirectory: "/tmp", userId: 501, userName: "t", groupId: 20, startTime: Date(),
            codeSignature: sig,
            ancestors: [ProcessAncestor(pid: 1, executable: parent,
                                        name: (parent as NSString).lastPathComponent)],
            architecture: "arm64", isPlatformBinary: true)
        return Event(eventCategory: .process, eventType: .start, eventAction: "exec", process: p)
    }

    private func engineLoaded() async throws -> RuleEngine {
        ensureRulesCompiled()
        let engine = RuleEngine()
        _ = try await engine.loadRules(from: URL(fileURLWithPath: "/tmp/maccrab_v3"))
        return engine
    }

    @Test("curl|bash on /bin/bash matches AND survives NoiseFilter (Gate-7 exemption)")
    func curlBashSurvivesPipeline() async throws {
        let engine = try await engineLoaded()
        let ev = appleInterpreterEvent(exec: "/bin/bash",
                                       commandLine: "curl -s http://127.0.0.1:9/x.sh | bash")
        var matches = await engine.evaluate(ev)
        let id = "d1a2b3c4-0003-4000-a000-000000000003"  // curl_wget_download_execute
        // Stage 1 — the rule must MATCH (true today).
        #expect(matches.contains { $0.ruleId == id }, "curl_wget_download_execute must match curl|bash")
        // Stage 2 — it must SURVIVE the live suppression pipeline. /bin/bash is an
        // Apple platform binary, so pre-fix Gate 7 dropped this suppressible match.
        NoiseFilter.apply(&matches, event: ev, isWarmingUp: false)
        #expect(matches.contains { $0.ruleId == id },
                "curl|bash LOLBin match must SURVIVE NoiseFilter Gate 7 — the execution-technique exemption")
    }

    @Test("osascript do-shell-script matches AND survives NoiseFilter")
    func osascriptSurvivesPipeline() async throws {
        let engine = try await engineLoaded()
        let ev = appleInterpreterEvent(exec: "/usr/bin/osascript",
                                       commandLine: "osascript -e do shell script \"id\"")
        var matches = await engine.evaluate(ev)
        let id = "d1a2b3c4-0454-4000-b000-000000000454"  // osascript_shell_command
        #expect(matches.contains { $0.ruleId == id }, "osascript_shell_command must match")
        NoiseFilter.apply(&matches, event: ev, isWarmingUp: false)
        #expect(matches.contains { $0.ruleId == id },
                "osascript do-shell-script must SURVIVE Gate 7")
    }

    @Test("a non-execution suppressible match on an Apple binary is STILL dropped (exemption is narrow)")
    func nonExecutionStillDropped() {
        // A discovery-tagged (t1083) suppressible match must still be suppressed
        // on an Apple platform binary — the exemption must not re-noise the whole
        // Gate-7 class, only execution/C2 LOLBin matches.
        var m = [RuleMatch(ruleId: "generic-discovery", ruleName: "n", severity: .high,
                           description: "", mitreTechniques: ["attack.t1083"], tags: [],
                           suppressible: true)]
        NoiseFilter.apply(&m, event: appleInterpreterEvent(exec: "/bin/bash", commandLine: "ls -la"),
                          isWarmingUp: false)
        #expect(m.isEmpty, "Gate 7 must still drop non-execution suppressible matches on Apple binaries")
    }

    @Test("a LOW-severity execution match on an Apple binary is STILL dropped (severity floor)")
    func lowSeverityExecutionDropped() {
        // A low-confidence exec indicator (e.g. osascript_from_non_apple, demoted
        // to low) is too weak to override the Apple-binary trust gate — only
        // medium+ LOLBin/C2 matches survive, so the dev-noisy low rules don't flood.
        var m = [RuleMatch(ruleId: "low-exec", ruleName: "n", severity: .low, description: "",
                           mitreTechniques: ["attack.t1059.002"], tags: [], suppressible: true)]
        NoiseFilter.apply(&m, event: appleInterpreterEvent(exec: "/usr/bin/osascript", commandLine: "osascript x"),
                          isWarmingUp: false)
        #expect(m.isEmpty, "a LOW exec match must still be dropped on an Apple binary")
    }

    @Test("a re-tightened formerly-deferred exec rule re-arms (survives Gate 7)")
    func reArmedRuleSurvives() {
        // installer_pkg_script_execution (0449) was held off Gate-7 survival in
        // Wave 1 (gate7NonExemptRuleIds) because it flooded on every PKG install.
        // Wave 3-B tightened it (suspicious-payload requirement) and emptied the
        // denylist, so a medium+ exec match like it now re-arms on an Apple
        // interpreter — confirming the deferral was lifted, not permanent.
        var m = [RuleMatch(ruleId: "d1a2b3c4-0449-4000-a000-000000000449", ruleName: "n",
                           severity: .medium, description: "", mitreTechniques: ["attack.t1059"],
                           tags: [], suppressible: true)]
        NoiseFilter.apply(&m, event: appleInterpreterEvent(exec: "/bin/sh", commandLine: "sh postinstall"),
                          isWarmingUp: false)
        #expect(!m.isEmpty, "a re-tightened exec rule re-arms (survives Gate 7) now the denylist is empty")
    }
}
