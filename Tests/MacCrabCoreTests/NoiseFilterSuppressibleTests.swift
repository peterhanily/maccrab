// NoiseFilterSuppressibleTests.swift
// v1.18 — the suppressible/severity decoupling. NoiseFilter gates now drop
// SUPPRESSIBLE matches and keep must-fire (suppressible == false) ones, instead
// of keying on severity == .critical (which made any CRITICAL rule a permanent
// suppression-bypass — the structural flaw). Plus Gate 8, the Developer-ID /
// notarized / first-party trust suppressor.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("NoiseFilter: suppressible decoupling + Gate 8 (v1.18)")
struct NoiseFilterSuppressibleTests {

    private func match(suppressible: Bool, severity: Severity = .high, techniques: [String] = []) -> RuleMatch {
        RuleMatch(ruleId: "r", ruleName: "n", severity: severity, description: "",
                  mitreTechniques: techniques, tags: [], suppressible: suppressible)
    }

    private func event(exec: String, signer: SignerType?, notarized: Bool = false, platform: Bool = false, team: String? = nil) -> Event {
        let sig: CodeSignatureInfo? = signer.map {
            CodeSignatureInfo(signerType: $0, teamId: team, signingId: nil, authorities: [],
                              flags: 0, isNotarized: notarized, issuerChain: nil, certHashes: nil,
                              isAdhocSigned: nil, entitlements: nil)
        }
        let p = MacCrabCore.ProcessInfo(
            pid: 100, ppid: 1, rpid: 1, name: (exec as NSString).lastPathComponent,
            executable: exec, commandLine: exec, args: [exec], workingDirectory: "/tmp",
            userId: 501, userName: "t", groupId: 20, startTime: Date(), codeSignature: sig,
            ancestors: [], architecture: "arm64", isPlatformBinary: platform)
        return Event(eventCategory: .process, eventType: .start, eventAction: "exec", process: p)
    }

    @Test("Critical is a must-fire FLOOR; a suppressible non-critical match is still dropped")
    func criticalIsMustFireFloor() {
        // v1.19: the old `severity == .critical` blanket must-fire floor is GONE
        // (it structurally defeated Gates 7/8 for criticals — a trusted-signer
        // critical-rated NOISE match could never be suppressed). A suppressible
        // critical is now a must-fire floor ONLY on an UNTRUSTED subject; on a
        // trusted/Apple subject it is gate-able. Genuine must-fire criticals are
        // all explicitly suppressible:false and survive regardless.

        // (1) suppressible critical on a TRUSTED Apple binary → now DROPPED.
        var critTrusted = [match(suppressible: true, severity: .critical)]
        NoiseFilter.apply(&critTrusted, event: event(exec: "/usr/bin/x", signer: .apple, platform: true), isWarmingUp: false)
        #expect(critTrusted.isEmpty, "a suppressible critical on a trusted Apple binary is now gate-able")

        // (2) suppressible critical on an UNTRUSTED subject → still bypasses (floor).
        var critUntrusted = [match(suppressible: true, severity: .critical)]
        NoiseFilter.apply(&critUntrusted, event: event(exec: "/tmp/dropper", signer: nil), isWarmingUp: false)
        #expect(critUntrusted.count == 1, "a critical on an untrusted subject still bypasses as the floor")

        // (3) suppressible non-critical on a trusted Apple binary → dropped.
        var high = [match(suppressible: true, severity: .high)]
        NoiseFilter.apply(&high, event: event(exec: "/usr/bin/x", signer: .apple, platform: true), isWarmingUp: false)
        #expect(high.isEmpty, "a suppressible non-critical match is still dropped on a trusted Apple binary")
    }

    @Test("a must-fire match (suppressible=false) survives the Apple-binary gate")
    func mustFireSurvives() {
        var m = [match(suppressible: false, severity: .high)]
        NoiseFilter.apply(&m, event: event(exec: "/usr/bin/x", signer: .apple, platform: true), isWarmingUp: false)
        #expect(m.count == 1)
    }

    @Test("Gate 8: a notarized Developer-ID subject drops suppressible, keeps must-fire")
    func gate8DevId() {
        var m = [match(suppressible: true, severity: .high), match(suppressible: false, severity: .high)]
        NoiseFilter.apply(&m, event: event(exec: "/opt/homebrew/bin/tool", signer: .devId, notarized: true), isWarmingUp: false)
        #expect(m.count == 1)
        #expect(m.first?.suppressible == false)
    }

    @Test("Gate 8 credential exception: a notarized devId reading credentials (T1555) survives")
    func gate8CredentialException() {
        // AMOS/Banshee: a notarized Developer-ID stealer reading the keychain/wallet.
        var cred = [match(suppressible: true, severity: .high, techniques: ["attack.t1555.001"])]
        NoiseFilter.apply(&cred, event: event(exec: "/Applications/Stealer.app/Contents/MacOS/x", signer: .devId, notarized: true), isWarmingUp: false)
        #expect(cred.count == 1, "a credential-theft match must survive Gate 8 on a notarized devId subject")
        // A non-credential suppressible match on the same trusted subject IS dropped.
        var other = [match(suppressible: true, severity: .high, techniques: ["attack.t1059"])]
        NoiseFilter.apply(&other, event: event(exec: "/Applications/Tool.app/Contents/MacOS/x", signer: .devId, notarized: true), isWarmingUp: false)
        #expect(other.isEmpty, "a non-credential suppressible match is still dropped by Gate 8")
    }

    @Test("Gate 7 still suppresses a credential read by an APPLE platform binary (no re-noise)")
    func gate7CredentialOnApple() {
        // securityd reading the keychain is legit — Gate 7 must still suppress it;
        // the Gate-8 credential exception is scoped to Gate 8 (notarized devId).
        var cred = [match(suppressible: true, severity: .high, techniques: ["attack.t1555.001"])]
        NoiseFilter.apply(&cred, event: event(exec: "/usr/libexec/securityd", signer: .apple, platform: true), isWarmingUp: false)
        #expect(cred.isEmpty, "an Apple platform binary credential read is still suppressed by Gate 7")
    }

    @Test("Gate 8: a MacCrab first-party (team 79S425CW99) subject is trusted")
    func gate8FirstParty() {
        var m = [match(suppressible: true)]
        NoiseFilter.apply(&m, event: event(exec: "/Applications/Tool.app/Contents/MacOS/tool", signer: .devId, team: "79S425CW99"), isWarmingUp: false)
        #expect(m.isEmpty)
    }

    @Test("no trust gate fires on an unsigned /tmp subject: a suppressible match survives")
    func untrustedSurvives() {
        var m = [match(suppressible: true, severity: .high)]
        // name must not be "unknown" (that trips Gate 1, the unattributable-event gate)
        NoiseFilter.apply(&m, event: event(exec: "/tmp/randomtool", signer: nil), isWarmingUp: false)
        #expect(m.count == 1)
    }

    @Test("an un-notarized Developer-ID subject is NOT auto-trusted by Gate 8")
    func unNotarizedDevIdNotTrusted() {
        var m = [match(suppressible: true, severity: .high)]
        NoiseFilter.apply(&m, event: event(exec: "/tmp/tool", signer: .devId, notarized: false), isWarmingUp: false)
        #expect(m.count == 1, "Gate 8 requires notarization (or first-party team); a bare devId is not enough")
    }

    @Test("compiled rules carry suppressible: the must-fire tranche resolves to false")
    func compiledRulesCarrySuppressible() async throws {
        ensureRulesCompiled()
        let engine = RuleEngine()
        _ = try await engine.loadRules(from: URL(fileURLWithPath: "/tmp/maccrab_v3"))
        let rules = await engine.listRules()
        // developer_cert_revoked — a must-fire IOC
        #expect(rules.first { $0.id == "d1a2b3c4-3007-4000-a000-000000003007" }?.suppressible == false)
        // every loaded rule has a defined suppressible (defaults true)
        #expect(rules.allSatisfy { _ in true })
        // at least the assessed must-fire tranche is present
        let mustFire = rules.filter { !$0.suppressible }
        #expect(mustFire.count >= 40, "expected the must-fire tranche (~49 single-event) to load as suppressible=false, got \(mustFire.count)")
    }
}
