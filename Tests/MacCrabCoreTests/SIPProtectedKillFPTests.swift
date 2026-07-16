// SIPProtectedKillFPTests.swift
// Detection-as-code regression for the v1.21.4 FP-reduction pass on
// sip_protected_process_interference.yml ("Attempt to Kill or Signal
// SIP-Protected Security Process", rule id d1a2b3c4-0344-...-000344).
//
// Two hazards were fixed without weakening real detection:
//
//   (b) the bare 3-char 'MRT' CommandLine|contains substring matched any
//       kill command line merely CONTAINING those letters (e.g. a path or
//       a larger word). Replaced with word-bounded forms: MRT.app /
//       com.apple.MRT (contains) + " MRT" (endswith), so `killall MRT`
//       still fires but `pkill -9 FormatMRTHelper` does not.
//
//   (2) non-terminating control signals (-HUP/-USR1/-USR2 and SIG*
//       spellings) are excluded — sending one is not a kill attempt. The
//       default (no signal = SIGTERM) and explicit fatal signals still
//       match, so the attack case is unaffected.
//
// The rule is `suppressible: false` (must-fire, bypasses NoiseFilter trust
// gates), so an over-broad match here is expensive — hence the guard.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("SIP-protected-kill FP regression (v1.21.4)")
struct SIPProtectedKillFPTests {

    private static let ruleId = "d1a2b3c4-0344-4000-a000-000000000344"

    // MARK: - Builders (mirrors Phase2RuleFireTests)

    private func process(
        name: String,
        executable: String,
        commandLine: String,
        parentExec: String
    ) -> MacCrabCore.ProcessInfo {
        let sig = CodeSignatureInfo(
            signerType: .apple,
            teamId: nil,
            signingId: nil,
            authorities: [],
            flags: 0,
            isNotarized: true,
            issuerChain: nil,
            certHashes: nil,
            isAdhocSigned: false,
            entitlements: nil
        )
        return MacCrabCore.ProcessInfo(
            pid: 4321,
            ppid: 900,
            rpid: 900,
            name: name,
            executable: executable,
            commandLine: commandLine,
            args: commandLine.split(separator: " ").map(String.init),
            workingDirectory: "/Users/alice",
            userId: 501,
            userName: "alice",
            groupId: 20,
            startTime: Date(),
            codeSignature: sig,
            ancestors: [ProcessAncestor(pid: 900, executable: parentExec, name: (parentExec as NSString).lastPathComponent)],
            architecture: "arm64",
            isPlatformBinary: true,
            session: nil,
            envVars: nil
        )
    }

    private func processEvent(_ p: MacCrabCore.ProcessInfo) -> Event {
        Event(eventCategory: .process, eventType: .start, eventAction: "exec", process: p)
    }

    private func loadEngine() async throws -> RuleEngine {
        ensureRulesCompiled()
        let engine = RuleEngine()
        _ = try await engine.loadRules(from: URL(fileURLWithPath: "/tmp/maccrab_v3"))
        return engine
    }

    private func fires(_ commandLine: String, image: String, parent: String = "/bin/zsh") async throws -> Bool {
        let engine = try await loadEngine()
        let proc = process(
            name: (image as NSString).lastPathComponent,
            executable: image,
            commandLine: commandLine,
            parentExec: parent
        )
        let matches = await engine.evaluate(processEvent(proc))
        return matches.contains { $0.ruleId == Self.ruleId }
    }

    // MARK: - Fire cases (real attack forms must still be detected)

    @Test("killall xprotectd (default TERM) from a shell still fires")
    func killXprotectdFires() async throws {
        #expect(try await fires("/usr/bin/killall xprotectd", image: "/usr/bin/killall"))
    }

    @Test("killall MRT (bare process-name kill) still fires via word boundary")
    func killMRTByNameFires() async throws {
        #expect(try await fires("/usr/bin/killall MRT", image: "/usr/bin/killall"))
    }

    @Test("pkill -9 syspolicyd (explicit fatal signal) still fires")
    func killSyspolicydFatalFires() async throws {
        #expect(try await fires("/usr/bin/pkill -9 syspolicyd", image: "/usr/bin/pkill"))
    }

    // MARK: - Non-fire cases (the FPs this pass eliminates)

    @Test("FP (b): pkill on a benign name merely CONTAINING 'MRT' does not fire")
    func incidentalMRTSubstringDoesNotFire() async throws {
        // Was the exact over-broad-substring hazard: 'FormatMRTHelper' contains
        // the letters MRT but is not MRT.app / com.apple.MRT and does not end
        // with " MRT", so it must not match.
        #expect(try await !fires("/usr/bin/pkill -9 FormatMRTHelper", image: "/usr/bin/pkill"))
    }

    @Test("FP (signal): pkill -HUP xprotectd (non-terminating reload) does not fire")
    func nonFatalSignalDoesNotFire() async throws {
        #expect(try await !fires("/usr/bin/pkill -HUP xprotectd", image: "/usr/bin/pkill"))
    }

    @Test("System-parented internal signaling of xprotectd stays excluded")
    func systemParentStaysExcluded() async throws {
        #expect(try await !fires("/usr/bin/killall xprotectd", image: "/usr/bin/killall", parent: "/usr/libexec/xpcproxy"))
    }
}
