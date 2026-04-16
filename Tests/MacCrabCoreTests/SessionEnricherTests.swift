// SessionEnricherTests.swift
// Ancestor-chain inference for LaunchSource — drives IsSSHLaunched and
// the Phase 2 ssh_launched_security_dump rule.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("Session enricher")
struct SessionEnricherTests {

    private func ancestor(_ name: String, pid: Int32 = 100, path: String? = nil) -> ProcessAncestor {
        ProcessAncestor(
            pid: pid,
            executable: path ?? "/usr/bin/\(name)",
            name: name
        )
    }

    @Test("sshd ancestor → .ssh")
    func sshdAncestor() {
        let src = SessionEnricher.inferLaunchSource(ancestors: [
            ancestor("bash"),
            ancestor("sshd", path: "/usr/sbin/sshd"),
            ancestor("launchd", path: "/sbin/launchd"),
        ])
        #expect(src == .ssh)
    }

    @Test("Terminal.app ancestor → .terminal")
    func terminalApp() {
        let src = SessionEnricher.inferLaunchSource(ancestors: [
            ancestor("zsh"),
            ancestor("Terminal", path: "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal"),
            ancestor("launchd"),
        ])
        #expect(src == .terminal)
    }

    @Test("iTerm2 ancestor → .terminal")
    func iterm() {
        let src = SessionEnricher.inferLaunchSource(ancestors: [
            ancestor("bash"),
            ancestor("iTerm2", path: "/Applications/iTerm.app/Contents/MacOS/iTerm2"),
        ])
        #expect(src == .terminal)
    }

    @Test("Ghostty ancestor → .terminal")
    func ghostty() {
        let src = SessionEnricher.inferLaunchSource(ancestors: [
            ancestor("ghostty", path: "/Applications/Ghostty.app/Contents/MacOS/ghostty"),
        ])
        #expect(src == .terminal)
    }

    @Test("Finder ancestor → .finder (user double-click)")
    func finder() {
        let src = SessionEnricher.inferLaunchSource(ancestors: [
            ancestor("Finder", path: "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"),
        ])
        #expect(src == .finder)
    }

    @Test("osascript ancestor → .applescript")
    func osascript() {
        let src = SessionEnricher.inferLaunchSource(ancestors: [
            ancestor("osascript"),
        ])
        #expect(src == .applescript)
    }

    @Test("cron ancestor → .cron")
    func cron() {
        let src = SessionEnricher.inferLaunchSource(ancestors: [
            ancestor("cron", path: "/usr/sbin/cron"),
        ])
        #expect(src == .cron)
    }

    @Test("Only launchd in chain → .launchd")
    func launchdOnly() {
        let src = SessionEnricher.inferLaunchSource(ancestors: [
            ancestor("launchd"),
        ])
        #expect(src == .launchd)
    }

    @Test("Shells pass through — classify by grandparent")
    func shellsPassThrough() {
        let src = SessionEnricher.inferLaunchSource(ancestors: [
            ancestor("bash"),            // skipped
            ancestor("zsh"),             // skipped
            ancestor("sudo"),            // skipped
            ancestor("sshd"),            // hit!
        ])
        #expect(src == .ssh)
    }

    @Test("Empty ancestors → .unknown")
    func emptyChain() {
        let src = SessionEnricher.inferLaunchSource(ancestors: [])
        #expect(src == .unknown)
    }

    @Test("Unknown process → .unknown")
    func unknownProcess() {
        let src = SessionEnricher.inferLaunchSource(ancestors: [
            ancestor("mystery-binary-xyz"),
        ])
        #expect(src == .unknown)
    }

    @Test("XPC proxy → .xpc")
    func xpcProxy() {
        let src = SessionEnricher.inferLaunchSource(ancestors: [
            ancestor("xpcproxy"),
        ])
        #expect(src == .xpc)
    }

    @Test("enrich returns SessionInfo with inferred source")
    func enrichReturnsSessionInfo() {
        let info = SessionEnricher.enrich(
            pid: 1234,
            ancestors: [ancestor("sshd", path: "/usr/sbin/sshd")]
        )
        #expect(info?.launchSource == .ssh)
        #expect(info?.tty == nil)           // not implemented in v1
        #expect(info?.sshRemoteIP == nil)   // not implemented in v1
    }

    @Test("enrich returns nil when ancestors empty and source unknown")
    func enrichReturnsNilForEmpty() {
        let info = SessionEnricher.enrich(pid: 1234, ancestors: [])
        #expect(info == nil)
    }
}

@Suite("Session enricher pipeline")
struct SessionEnricherPipelineTests {

    /// Verify the full EventEnricher.enrich path sets session.launchSource.
    @Test("EventEnricher populates session.launchSource from ancestors")
    func eventEnricherWiresSession() async {
        let proc = MacCrabCore.ProcessInfo(
            pid: 1000, ppid: 500, rpid: 500,
            name: "security", executable: "/usr/bin/security",
            commandLine: "/usr/bin/security dump-keychain",
            args: ["/usr/bin/security", "dump-keychain"],
            workingDirectory: "/tmp",
            userId: 501, userName: "alice", groupId: 20,
            startTime: Date(),
            ancestors: [
                ProcessAncestor(pid: 500, executable: "/bin/zsh", name: "zsh"),
                ProcessAncestor(pid: 200, executable: "/usr/sbin/sshd", name: "sshd"),
            ]
        )
        let event = Event(
            eventCategory: .process, eventType: .start,
            eventAction: "exec", process: proc
        )

        let enricher = EventEnricher()
        let enriched = await enricher.enrich(event)

        #expect(enriched.process.session?.launchSource == .ssh)
    }

    @Test("Existing collector-provided session is preserved")
    func preservesExistingSession() async {
        let preset = SessionInfo(
            sessionId: 42, tty: "/dev/ttys000",
            loginUser: "root", sshRemoteIP: "10.0.0.1",
            launchSource: .ssh
        )
        let proc = MacCrabCore.ProcessInfo(
            pid: 1000, ppid: 500, rpid: 500,
            name: "curl", executable: "/usr/bin/curl",
            commandLine: "curl", args: ["/usr/bin/curl"],
            workingDirectory: "/tmp",
            userId: 501, userName: "alice", groupId: 20,
            startTime: Date(),
            ancestors: [
                ProcessAncestor(pid: 500, executable: "/usr/sbin/cron", name: "cron"),
            ],
            session: preset
        )
        let event = Event(
            eventCategory: .process, eventType: .start,
            eventAction: "exec", process: proc
        )

        let enricher = EventEnricher()
        let enriched = await enricher.enrich(event)

        // SessionEnricher must NOT override the collector-set session.
        #expect(enriched.process.session?.launchSource == .ssh)   // from preset
        #expect(enriched.process.session?.tty == "/dev/ttys000")
        #expect(enriched.process.session?.sshRemoteIP == "10.0.0.1")
    }
}
