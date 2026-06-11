// NoiseFilterSelfTestNoiseTests.swift
//
// v1.19 (S1-T6): flag-gated suppression of self-inflicted honeyfile noise.
// `make test` runs the Swift test runner, which reads MacCrab's OWN deployed
// decoy files and trips the credential/discovery rules that key on those
// paths — dev-harness noise, not threat signal. Gate 4c drops the suppressible
// matches ONLY when the flag is enabled (off in prod). The must-fire
// `honeyfile_accessed` rule (suppressible: false) is UNAFFECTED — it bypasses
// every gate including this one.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("NoiseFilter: self-test honeyfile noise (v1.19 S1-T6)", .serialized)
struct NoiseFilterSelfTestNoiseTests {

    // The flag is process-global static state; reset to the prod default (off)
    // after each test so suites stay independent regardless of run order.
    private func withFlag(_ enabled: Bool, _ body: () -> Void) {
        let prior = NoiseFilter.selfTestNoiseSuppressionEnabled
        NoiseFilter.selfTestNoiseSuppressionEnabled = enabled
        defer { NoiseFilter.selfTestNoiseSuppressionEnabled = prior }
        body()
    }

    private func suppressibleMatch() -> RuleMatch {
        RuleMatch(ruleId: "cred.honey-trigger", ruleName: "Credential path read",
                  severity: .high, description: "", suppressible: true)
    }

    // honeyfile_accessed ships as suppressible: false (must-fire).
    private func honeyfileAccessedMatch() -> RuleMatch {
        RuleMatch(ruleId: "f1e2d3c4-b5a6-4987-9876-543210dec0de",
                  ruleName: "Deception Honeyfile Accessed",
                  severity: .high, description: "", suppressible: false)
    }

    // Event: the Swift test runner reading a MacCrab-deployed honeyfile. Decoys
    // live at realistic credential paths (e.g. ~/.aws/credentials.bak), NOT the
    // support dir — the IsHoneyfile enrichment is what marks them.
    private func testRunnerHoneyfileEvent(runnerName: String = "swiftpm-testing-helper") -> Event {
        let honeyPath = "/Users/x/.aws/credentials.bak"
        let p = MacCrabCore.ProcessInfo(
            pid: 200, ppid: 1, rpid: 1, name: runnerName,
            executable: "/Applications/Xcode.app/Contents/Developer/usr/bin/\(runnerName)",
            commandLine: runnerName, args: [runnerName], workingDirectory: "/tmp",
            userId: 501, userName: "t", groupId: 20, startTime: Date(), codeSignature: nil,
            ancestors: [], architecture: "arm64", isPlatformBinary: false)
        return Event(eventCategory: .file, eventType: .info, eventAction: "open",
                     process: p, file: FileInfo(path: honeyPath, action: .open),
                     enrichments: ["IsHoneyfile": "true"])
    }

    @Test("Flag OFF (prod default): self-test honeyfile noise is NOT dropped")
    func flagOffKeepsNoise() {
        withFlag(false) {
            var m = [suppressibleMatch()]
            NoiseFilter.apply(&m, event: testRunnerHoneyfileEvent(), isWarmingUp: false)
            #expect(m.count == 1, "with the flag off, prod behavior is unchanged — the match is kept")
        }
    }

    @Test("Flag ON: the test-runner's self-decoy honeyfile-trigger match is dropped")
    func flagOnDropsNoise() {
        withFlag(true) {
            var m = [suppressibleMatch()]
            NoiseFilter.apply(&m, event: testRunnerHoneyfileEvent(), isWarmingUp: false)
            #expect(m.isEmpty, "Gate 4c drops the suppressible self-test honeyfile-trigger match")
        }
    }

    @Test("Flag ON: must-fire honeyfile_accessed STILL fires (deception detection unaffected)")
    func flagOnHoneyfileAccessedSurvives() {
        withFlag(true) {
            var m = [suppressibleMatch(), honeyfileAccessedMatch()]
            NoiseFilter.apply(&m, event: testRunnerHoneyfileEvent(), isWarmingUp: false)
            #expect(m.count == 1)
            #expect(m.first?.suppressible == false, "the must-fire honeyfile_accessed rule survives every gate")
        }
    }

    @Test("Flag ON is scoped: a NON-runner reading a honeyfile is NOT swept in by Gate 4c")
    func flagOnScopedToRunner() {
        withFlag(true) {
            // A non-test-runner intruder reading the same honeyfile must NOT be
            // suppressed by Gate 4c — this is a real intruder tripping the decoy.
            // Use an untrusted, non-Apple subject so Gates 7/8 don't independently
            // drop the match, isolating Gate 4c's scoping behavior.
            let honeyPath = "/Users/x/.aws/credentials.bak"
            let p = MacCrabCore.ProcessInfo(
                pid: 300, ppid: 1, rpid: 1, name: "intruder",
                executable: "/tmp/intruder", commandLine: "intruder", args: ["intruder"],
                workingDirectory: "/tmp", userId: 501, userName: "t", groupId: 20,
                startTime: Date(), codeSignature: nil, ancestors: [],
                architecture: "arm64", isPlatformBinary: false)
            let ev = Event(eventCategory: .file, eventType: .info, eventAction: "open",
                           process: p, file: FileInfo(path: honeyPath, action: .open),
                           enrichments: ["IsHoneyfile": "true"])
            var m = [suppressibleMatch()]
            NoiseFilter.apply(&m, event: ev, isWarmingUp: false)
            #expect(m.count == 1, "a non-runner honeyfile read is real signal — Gate 4c must not suppress it")
        }
    }

    @Test("Flag ON is scoped: the runner reading a NON-honeyfile is NOT swept in")
    func flagOnScopedToHoneyfile() {
        withFlag(true) {
            // The runner reading a non-decoy file (no IsHoneyfile enrichment)
            // must not be suppressed by Gate 4c.
            let p = MacCrabCore.ProcessInfo(
                pid: 400, ppid: 1, rpid: 1, name: "swiftpm-testing-helper",
                executable: "/Applications/Xcode.app/Contents/Developer/usr/bin/swiftpm-testing-helper",
                commandLine: "swiftpm-testing-helper", args: [], workingDirectory: "/tmp",
                userId: 501, userName: "t", groupId: 20, startTime: Date(), codeSignature: nil,
                ancestors: [], architecture: "arm64", isPlatformBinary: false)
            let ev = Event(eventCategory: .file, eventType: .info, eventAction: "open",
                           process: p, file: FileInfo(path: "/Users/x/.ssh/id_rsa", action: .open))
            var m = [suppressibleMatch()]
            NoiseFilter.apply(&m, event: ev, isWarmingUp: false)
            #expect(m.count == 1, "the runner reading a non-honeyfile is not Gate-4c noise")
        }
    }
}
