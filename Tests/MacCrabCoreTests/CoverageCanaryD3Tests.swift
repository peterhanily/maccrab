// CoverageCanaryD3Tests.swift
//
// v1.21.4 Phase-2 (D3) — watchdog canary / coverage probe.
//
// The watchdog spawns a benign `/usr/bin/env /usr/bin/true <nonce>` on a
// jittered interval, then verifies the OBSERVED `/usr/bin/true` exec reached
// BOTH the ES callback and events.db. These tests cover the DETERMINISTIC
// pieces:
//   1. the two-point verdict logic (CoverageCanaryEvaluator),
//   2. the callback recognizer matching only LIVE nonces (ESCanaryRegistry),
//   3. the suppression allowlist (NoiseFilter.isCoverageCanaryProbe) so the
//      probe can never raise a detection alert / feedback loop,
//   4. the self-trip safety invariant vs SelfDefense's impersonation probe,
//   5. the nonce scheme.
//
// The LIVE spawn + ES-callback + DB path (runCoverageCanary / spawnCanaryProbe /
// canaryPresentInDB) is NEEDS-ON-DEVICE — it requires a root sysext with an ES
// entitlement and depends on the muteSelf interaction the env intermediary
// works around.

import Testing
import Foundation
@testable import MacCrabCore
@testable import MacCrabAgentKit

// MARK: - 1. Two-point verdict logic (pure)

@Suite("D3 CoverageCanaryEvaluator: two-point verdict")
struct CoverageCanaryEvaluatorTests {
    typealias Eval = CoverageCanaryEvaluator

    @Test("missing at callback ⇒ kernel/ingest gap")
    func missingAtCallbackIsKernelGap() {
        #expect(Eval.verdict(seenAtCallback: false, foundInDB: false) == .kernelGap)
    }

    @Test("miss at callback dominates even if a row is later found in the DB")
    func missDominatesDBHit() {
        // A DB hit without a callback sighting is a recognizer-window timing
        // artifact, not real coverage — a callback miss is still a kernel gap.
        #expect(Eval.verdict(seenAtCallback: false, foundInDB: true) == .kernelGap)
    }

    @Test("seen at callback but absent in DB ⇒ store/eviction gap")
    func seenButNotStoredIsEvictionGap() {
        #expect(Eval.verdict(seenAtCallback: true, foundInDB: false) == .evictionGap)
    }

    @Test("seen at both points ⇒ healthy")
    func seenAndStoredIsHealthy() {
        #expect(Eval.verdict(seenAtCallback: true, foundInDB: true) == .healthy)
    }

    @Test("verdict stage labels name the failing stage (nil when healthy)")
    func stageLabels() {
        #expect(Eval.Verdict.kernelGap.stageLabel == "kernel/ingest")
        #expect(Eval.Verdict.evictionGap.stageLabel == "store/eviction")
        #expect(Eval.Verdict.healthy.stageLabel == nil)
    }

    @Test("jittered interval stays within the 5-15 min bounds")
    func jitterBounds() {
        for _ in 0..<200 {
            let s = DaemonTimers.canaryJitterSeconds()
            #expect(s >= DaemonTimers.canaryMinIntervalSeconds)
            #expect(s <= DaemonTimers.canaryMaxIntervalSeconds)
        }
        #expect(DaemonTimers.canaryMinIntervalSeconds == 300)
        #expect(DaemonTimers.canaryMaxIntervalSeconds == 900)
    }
}

// MARK: - 2. Callback recognizer (ESCanaryRegistry)

@Suite("D3 ESCanaryRegistry: recognizer matches only LIVE nonces")
struct ESCanaryRegistryTests {

    @Test("unarmed registry never records a sighting")
    func unarmedIsNoOp() {
        let reg = ESCanaryRegistry()
        let nonce = CoverageCanary.makeNonce()
        reg.noteExecIfCanary(commandLine: "/usr/bin/true \(nonce)")
        #expect(reg.seenAtCallback(nonce) == false)
    }

    @Test("armed nonce present in the command line is latched as seen")
    func armedMatchIsSeen() {
        let reg = ESCanaryRegistry()
        let nonce = CoverageCanary.makeNonce()
        reg.arm(nonce)
        reg.noteExecIfCanary(commandLine: "/usr/bin/true \(nonce)")
        #expect(reg.seenAtCallback(nonce))
    }

    @Test("a command line WITHOUT the live nonce does not set the flag")
    func nonMatchingCommandLineIgnored() {
        let reg = ESCanaryRegistry()
        let nonce = CoverageCanary.makeNonce()
        reg.arm(nonce)
        reg.noteExecIfCanary(commandLine: "/usr/bin/true SOME-OTHER-ARG")
        #expect(reg.seenAtCallback(nonce) == false)
    }

    @Test("only the matching live nonce is latched (per-nonce isolation)")
    func perNonceIsolation() {
        let reg = ESCanaryRegistry()
        let a = CoverageCanary.makeNonce()
        let b = CoverageCanary.makeNonce()
        reg.arm(a); reg.arm(b)
        reg.noteExecIfCanary(commandLine: "/usr/bin/true \(a)")
        #expect(reg.seenAtCallback(a))
        #expect(reg.seenAtCallback(b) == false)
    }

    @Test("disarm clears state and re-notes stay unarmed")
    func disarmClears() {
        let reg = ESCanaryRegistry()
        let nonce = CoverageCanary.makeNonce()
        reg.arm(nonce)
        reg.noteExecIfCanary(commandLine: "/usr/bin/true \(nonce)")
        #expect(reg.seenAtCallback(nonce))
        reg.disarm(nonce)
        #expect(reg.seenAtCallback(nonce) == false)
        // After disarm the registry is unarmed again → notes are no-ops.
        reg.noteExecIfCanary(commandLine: "/usr/bin/true \(nonce)")
        #expect(reg.seenAtCallback(nonce) == false)
    }

    @Test("re-arming the same nonce resets its seen state")
    func rearmResetsSeen() {
        let reg = ESCanaryRegistry()
        let nonce = CoverageCanary.makeNonce()
        reg.arm(nonce)
        reg.noteExecIfCanary(commandLine: "/usr/bin/true \(nonce)")
        #expect(reg.seenAtCallback(nonce))
        reg.arm(nonce)   // new cycle for the same nonce string
        #expect(reg.seenAtCallback(nonce) == false)
    }
}

// MARK: - 3. Suppression allowlist (NoiseFilter)

@Suite("D3 NoiseFilter: coverage-canary suppression allowlist")
struct CoverageCanarySuppressionTests {

    private func execEvent(
        executable: String, commandLine: String, name: String, platform: Bool
    ) -> Event {
        let p = MacCrabCore.ProcessInfo(
            pid: 4242, ppid: 1, rpid: 1, name: name,
            executable: executable, commandLine: commandLine,
            args: commandLine.split(separator: " ").map(String.init),
            workingDirectory: "/", userId: 0, userName: "root", groupId: 0,
            startTime: Date(), codeSignature: nil, ancestors: [],
            architecture: "arm64", isPlatformBinary: platform)
        return Event(eventCategory: .process, eventType: .start, eventAction: "exec", process: p)
    }

    private func canaryEvent(nonce: String) -> Event {
        execEvent(executable: CoverageCanary.spawnBinaryPath,
                  commandLine: "\(CoverageCanary.spawnBinaryPath) \(nonce)",
                  name: "true", platform: true)
    }

    private func mustFireMatch() -> RuleMatch {
        RuleMatch(ruleId: "edr.some-detection", ruleName: "Some must-fire detection",
                  severity: .critical, description: "", suppressible: false)
    }

    @Test("the canary probe exec is recognized")
    func canaryRecognized() {
        let ev = canaryEvent(nonce: CoverageCanary.makeNonce())
        #expect(NoiseFilter.isCoverageCanaryProbe(event: ev))
    }

    @Test("/usr/bin/true WITHOUT the marker is NOT recognized")
    func trueWithoutMarkerNotRecognized() {
        let ev = execEvent(executable: CoverageCanary.spawnBinaryPath,
                           commandLine: "/usr/bin/true --version",
                           name: "true", platform: true)
        #expect(NoiseFilter.isCoverageCanaryProbe(event: ev) == false)
    }

    @Test("the marker on a DIFFERENT binary is NOT recognized (can't launder a real binary)")
    func markerOnOtherBinaryNotRecognized() {
        let nonce = CoverageCanary.makeNonce()
        let ev = execEvent(executable: "/tmp/evil",
                           commandLine: "/tmp/evil \(nonce)",
                           name: "evil", platform: false)
        #expect(NoiseFilter.isCoverageCanaryProbe(event: ev) == false)
    }

    @Test("a file event is never a canary probe")
    func fileEventNotRecognized() {
        let p = MacCrabCore.ProcessInfo(
            pid: 1, ppid: 0, rpid: 0, name: "true",
            executable: CoverageCanary.spawnBinaryPath,
            commandLine: "/usr/bin/true \(CoverageCanary.argvMarker)-x", args: [],
            workingDirectory: "/", userId: 0, userName: "root", groupId: 0,
            startTime: Date(), codeSignature: nil, ancestors: [],
            architecture: "arm64", isPlatformBinary: true)
        let ev = Event(eventCategory: .file, eventType: .info, eventAction: "open",
                       process: p, file: FileInfo(path: "/tmp/x", action: .open))
        #expect(NoiseFilter.isCoverageCanaryProbe(event: ev) == false)
    }

    @Test("Gate 0 drops ALL matches on the canary — even a must-fire one (no feedback loop)")
    func gate0DropsEvenMustFire() {
        var m = [mustFireMatch()]
        NoiseFilter.apply(&m, event: canaryEvent(nonce: CoverageCanary.makeNonce()), isWarmingUp: false)
        #expect(m.isEmpty, "the coverage-canary exec must never raise a detection alert")
    }

    @Test("Gate 0 does NOT suppress a real binary carrying the marker (laundering is refused)")
    func gate0DoesNotLaunder() {
        let nonce = CoverageCanary.makeNonce()
        let ev = execEvent(executable: "/tmp/evil",
                           commandLine: "/tmp/evil \(nonce)",
                           name: "evil", platform: false)
        var m = [mustFireMatch()]   // must-fire survives every OTHER gate
        NoiseFilter.apply(&m, event: ev, isWarmingUp: false)
        #expect(m.count == 1, "the marker on a non-/usr/bin/true binary must NOT be suppressed by Gate 0")
    }
}

// MARK: - 4. Self-defense safety invariant

@Suite("D3 self-trip safety: canary is disjoint from SelfDefense's impersonation probe")
struct CoverageCanarySelfDefenseTests {

    @Test("a real MacCrab command line still matches the impersonation pattern (sanity)")
    func realInstanceMatches() {
        #expect(SelfDefense.matchesImpersonationPattern("/usr/local/bin/maccrabd --foreground"))
        #expect(SelfDefense.matchesImpersonationPattern(
            "/Library/SystemExtensions/…/com.maccrab.agent.systemextension/Contents/MacOS/com.maccrab.agent"))
    }

    @Test("the canary command line does NOT match the impersonation pattern")
    func canaryCommandLineDisjoint() {
        let cmdline = "\(CoverageCanary.spawnBinaryPath) \(CoverageCanary.makeNonce())"
        #expect(SelfDefense.matchesImpersonationPattern(cmdline) == false,
                "the canary must never be flagged as another maccrabd instance")
    }

    @Test("the marker itself contains none of the impersonation tokens")
    func markerHasNoImpersonationTokens() {
        #expect(SelfDefense.matchesImpersonationPattern(CoverageCanary.argvMarker) == false)
        // Belt-and-braces: the marker must not embed "maccrab".
        #expect(CoverageCanary.argvMarker.lowercased().contains("maccrab") == false)
    }
}

// MARK: - 5. Nonce scheme

@Suite("D3 CoverageCanary: nonce scheme")
struct CoverageCanaryNonceTests {

    @Test("nonce carries the fixed marker prefix")
    func nonceHasMarkerPrefix() {
        #expect(CoverageCanary.makeNonce().hasPrefix(CoverageCanary.argvMarker))
    }

    @Test("nonces are unique per run")
    func noncesAreUnique() {
        let a = CoverageCanary.makeNonce()
        let b = CoverageCanary.makeNonce()
        #expect(a != b)
    }

    @Test("nonce contains only argv-safe characters (no shell/quoting metacharacters)")
    func nonceIsArgvSafe() {
        let nonce = CoverageCanary.makeNonce()
        let allowed = CharacterSet(charactersIn:
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-")
        #expect(nonce.unicodeScalars.allSatisfy { allowed.contains($0) },
                "the nonce is interpolated into argv — it must be free of shell metacharacters")
    }

    @Test("observed image and unmuted intermediary are the expected Apple platform binaries")
    func binaryPaths() {
        #expect(CoverageCanary.spawnBinaryPath == "/usr/bin/true")
        #expect(CoverageCanary.intermediaryBinaryPath == "/usr/bin/env")
    }
}
