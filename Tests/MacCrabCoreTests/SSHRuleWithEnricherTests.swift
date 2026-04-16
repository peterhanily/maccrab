// SSHRuleWithEnricherTests.swift
// End-to-end: a process with sshd in its ancestor chain but no preset
// session field should still fire the ssh_launched_security_dump rule
// once SessionEnricher populates launchSource.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("SSH rule with live session inference")
struct SSHRuleWithEnricherTests {

    @Test("ssh_launched_security_dump fires on sshd-descendant keychain dump")
    func sshdDescendantFires() async throws {
        let proc = MacCrabCore.ProcessInfo(
            pid: 10_001, ppid: 9_999, rpid: 9_999,
            name: "security", executable: "/usr/bin/security",
            commandLine: "/usr/bin/security dump-keychain -d login.keychain",
            args: ["/usr/bin/security", "dump-keychain"],
            workingDirectory: "/Users/victim",
            userId: 501, userName: "victim", groupId: 20,
            startTime: Date(),
            // No preset session — SessionEnricher must infer .ssh from sshd.
            ancestors: [
                ProcessAncestor(pid: 9_999, executable: "/bin/zsh", name: "zsh"),
                ProcessAncestor(pid: 500, executable: "/usr/sbin/sshd", name: "sshd"),
            ]
        )
        let event = Event(
            eventCategory: .process, eventType: .start,
            eventAction: "exec", process: proc
        )

        ensureRulesCompiled()
        let engine = RuleEngine()
        _ = try await engine.loadRules(from: URL(fileURLWithPath: "/tmp/maccrab_v3"))
        let enricher = EventEnricher()
        let enriched = await enricher.enrich(event)

        // Sanity: enricher put the session on the process.
        #expect(enriched.process.session?.launchSource == .ssh)

        // Rule fires.
        let matches = await engine.evaluate(enriched)
        #expect(matches.contains {
            $0.ruleName.lowercased().contains("keychain") ||
            $0.ruleName.lowercased().contains("credential") ||
            $0.ruleName.lowercased().contains("ssh")
        }, "Expected an SSH credential-dump rule to fire; got: \(matches.map(\.ruleName))")
    }

    @Test("Same command from a Terminal session does NOT fire SSH-specific rule")
    func terminalDescendantDoesNotFire() async throws {
        let proc = MacCrabCore.ProcessInfo(
            pid: 10_002, ppid: 9_998, rpid: 9_998,
            name: "security", executable: "/usr/bin/security",
            commandLine: "/usr/bin/security dump-keychain -d login.keychain",
            args: ["/usr/bin/security", "dump-keychain"],
            workingDirectory: "/Users/alice",
            userId: 501, userName: "alice", groupId: 20,
            startTime: Date(),
            ancestors: [
                ProcessAncestor(pid: 9_998, executable: "/bin/zsh", name: "zsh"),
                ProcessAncestor(
                    pid: 300,
                    executable: "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
                    name: "Terminal"
                ),
            ]
        )
        let event = Event(
            eventCategory: .process, eventType: .start,
            eventAction: "exec", process: proc
        )

        ensureRulesCompiled()
        let engine = RuleEngine()
        _ = try await engine.loadRules(from: URL(fileURLWithPath: "/tmp/maccrab_v3"))
        let enricher = EventEnricher()
        let enriched = await enricher.enrich(event)

        #expect(enriched.process.session?.launchSource == .terminal)

        // The SSH-specific rule ID must not appear.
        let matches = await engine.evaluate(enriched)
        #expect(!matches.contains { $0.ruleId.contains("ssh_launched_security_dump") },
                "ssh_launched_security_dump should not fire for Terminal-launched process; matches: \(matches.map(\.ruleId))")
    }
}
