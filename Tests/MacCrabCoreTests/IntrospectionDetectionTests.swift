// IntrospectionDetectionTests.swift
// v1.18 ES introspection family (get_task_read / trace / remote_thread_create /
// cs_invalidated). End-to-end through the REAL RuleEngine: a synthetic Event
// carrying the eventAction + Target* enrichments the ESCollector emits must
// dispatch under the process_event category, resolve TargetIsSelf via
// enrichment passthrough and SameTeam from TargetTeamId and the actor's
// verified signature, and the revived rules must fire on the malicious
// shape while every FP filter (apple / debugger / JIT / self / same-team)
// correctly suppresses the benign shapes.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("ES introspection detection (v1.18)")
struct IntrospectionDetectionTests {

    private func loadRules() async throws -> RuleEngine {
        try ensureRulesCompiled()
        let engine = RuleEngine()
        _ = try await engine.loadRules(from: compiledRulesDirectory)
        return engine
    }

    private static let team = "TEAMX12345"

    /// The actor's signature as the enricher publishes it once Security has
    /// anchored its chain for the running image.
    private static let verifiedTeamActor = CodeSignatureInfo(
        signerType: .devId, teamId: team, signingId: "com.example.helper",
        authorities: ["Developer ID Application: Example (TEAMX12345)",
                      "Developer ID Certification Authority", "Apple Root CA"],
        flags: 0x1_0001, isNotarized: true)

    private func introspection(
        action: String,
        actorName: String,
        actorPath: String,
        actorSigner: SignerType? = .unsigned,
        actorSignature: CodeSignatureInfo? = nil,
        targetIsSelf: Bool = false,
        targetTeamId: String = "",
        targetImage: String = "/usr/bin/ssh-agent"
    ) -> Event {
        let codeSig: CodeSignatureInfo? = actorSignature ?? actorSigner.map {
            CodeSignatureInfo(signerType: $0, teamId: nil, signingId: nil, authorities: [], flags: 0, isNotarized: false)
        }
        let process = ProcessInfo(
            pid: 4242, ppid: 1, rpid: 1,
            name: actorName, executable: actorPath, commandLine: actorPath, args: [actorPath],
            workingDirectory: "/tmp", userId: 501, userName: "t", groupId: 20,
            startTime: Date(), codeSignature: codeSig,
            ancestors: [ProcessAncestor(pid: 1, executable: "/sbin/launchd", name: "launchd")],
            architecture: "arm64", isPlatformBinary: actorSigner == .apple
        )
        let enrich: [String: String] = action == "cs_invalidated"
            ? ["TargetIsSelf": "true"]
            : [
                "TargetIsSelf": targetIsSelf ? "true" : "false",
                "TargetTeamId": targetTeamId,
                "TargetImage": targetImage,
                "TargetProcessName": (targetImage as NSString).lastPathComponent,
                "TargetSignerType": "unsigned",
                "TargetPid": "9999",
            ]
        return Event(eventCategory: .process, eventType: .change, eventAction: action,
                     process: process, enrichments: enrich)
    }

    private func fires(_ matches: [RuleMatch], _ needle: String) -> Bool {
        matches.contains { $0.ruleName.localizedCaseInsensitiveContains(needle) }
    }

    // MARK: - remote_thread_create (HIGH, cleanest signal)

    @Test("remote thread injection by an untrusted process FIRES")
    func remoteThreadFires() async throws {
        let engine = try await loadRules()
        let m = await engine.evaluate(introspection(
            action: "remote_thread_create", actorName: "injector", actorPath: "/tmp/injector"))
        #expect(fires(m, "Remote Thread"), "expected remote-thread detection, got: \(m.map(\.ruleName))")
    }

    @Test("remote thread: apple subject / target-self / same-team / debugger are all filtered")
    func remoteThreadFilters() async throws {
        let engine = try await loadRules()
        let apple = await engine.evaluate(introspection(action: "remote_thread_create", actorName: "helper", actorPath: "/usr/libexec/helper", actorSigner: .apple))
        let selfT = await engine.evaluate(introspection(action: "remote_thread_create", actorName: "x", actorPath: "/tmp/x", targetIsSelf: true))
        let team  = await engine.evaluate(introspection(action: "remote_thread_create", actorName: "x", actorPath: "/tmp/x", actorSignature: Self.verifiedTeamActor, targetTeamId: Self.team))
        let dbg   = await engine.evaluate(introspection(action: "remote_thread_create", actorName: "debugserver", actorPath: "/usr/bin/debugserver", actorSigner: nil))
        #expect(!fires(apple, "Remote Thread"), "apple subject should be filtered")
        #expect(!fires(selfT, "Remote Thread"), "target-self should be filtered")
        #expect(!fires(team,  "Remote Thread"), "same-team should be filtered")
        #expect(!fires(dbg,   "Remote Thread"), "debugserver should be filtered")
    }

    // MARK: - get_task_read (memory scrape)

    @Test("untrusted task-read of another process FIRES; self/debugger do not")
    func taskReadFiresAndFilters() async throws {
        let engine = try await loadRules()
        let mal = await engine.evaluate(introspection(action: "get_task_read", actorName: "stealer", actorPath: "/tmp/stealer", targetImage: "/usr/bin/ssh-agent"))
        let dbg = await engine.evaluate(introspection(action: "get_task_read", actorName: "lldb", actorPath: "/usr/bin/lldb", actorSigner: nil))
        let me  = await engine.evaluate(introspection(action: "get_task_read", actorName: "x", actorPath: "/tmp/x", targetIsSelf: true))
        #expect(fires(mal, "Read Access"), "expected memory-read detection, got: \(mal.map(\.ruleName))")
        #expect(!fires(dbg, "Read Access"), "lldb should be filtered")
        #expect(!fires(me, "Read Access"), "self-read should be filtered")
    }

    // MARK: - cs_invalidated (self code-sig tamper)

    @Test("non-JIT code-signature invalidation FIRES; node/electron/apple do not")
    func csInvalidatedFiresAndFilters() async throws {
        let engine = try await loadRules()
        let mal  = await engine.evaluate(introspection(action: "cs_invalidated", actorName: "patched", actorPath: "/tmp/patched"))
        let node = await engine.evaluate(introspection(action: "cs_invalidated", actorName: "node", actorPath: "/usr/local/bin/node", actorSigner: nil))
        let appl = await engine.evaluate(introspection(action: "cs_invalidated", actorName: "amfid", actorPath: "/usr/libexec/amfid", actorSigner: .apple))
        #expect(fires(mal, "Code Signature"), "expected cs-invalidation detection, got: \(mal.map(\.ruleName))")
        #expect(!fires(node, "Code Signature"), "node (JIT) should be filtered")
        #expect(!fires(appl, "Code Signature"), "apple should be filtered")
    }

    // MARK: - trace (ptrace attach)

    @Test("untrusted ptrace attach FIRES; lldb/self do not")
    func ptraceFiresAndFilters() async throws {
        let engine = try await loadRules()
        let mal = await engine.evaluate(introspection(action: "trace", actorName: "tracer", actorPath: "/tmp/tracer"))
        let dbg = await engine.evaluate(introspection(action: "trace", actorName: "lldb", actorPath: "/usr/bin/lldb", actorSigner: nil))
        #expect(fires(mal, "ptrace"), "expected ptrace detection, got: \(mal.map(\.ruleName))")
        #expect(!fires(dbg, "ptrace"), "lldb should be filtered")
    }

    // MARK: - High-value target escalation (review fix)

    @Test("memory read of a high-value target (securityd) escalates to a HIGH rule; apple filtered")
    func highValueTargetEscalation() async throws {
        let engine = try await loadRules()
        let mal = await engine.evaluate(introspection(action: "get_task_read", actorName: "stealer", actorPath: "/tmp/stealer", targetImage: "/usr/libexec/securityd"))
        let appl = await engine.evaluate(introspection(action: "get_task_read", actorName: "x", actorPath: "/usr/libexec/x", actorSigner: .apple, targetImage: "/usr/libexec/securityd"))
        #expect(fires(mal, "High-Value"), "expected high-value escalation, got: \(mal.map(\.ruleName))")
        #expect(!fires(appl, "High-Value"), "apple actor should be filtered")
    }

    // MARK: - Same-team gate needs a verified actor

    @Test("an actor claiming its target's team is no same-team exemption until Security attests the team")
    func claimedTeamDoesNotSilenceMustFire() async throws {
        let engine = try await loadRules()
        let target = "/Applications/1Password.app/Contents/MacOS/1Password"
        // As the collector reports a self-signed chain naming the target's
        // team, and as the enricher publishes it once Security finds no
        // Apple-rooted chain or another image.
        let claimed = CodeSignatureInfo(signerType: .devId, teamId: Self.team, signingId: "com.example.helper", flags: 0x1)
        let unverified = CodeSignatureInfo(signerType: .adHoc, signingId: "com.example.helper", flags: 0x1)
        for signature in [claimed, unverified] {
            let event = introspection(action: "get_task_read", actorName: "helper", actorPath: "/tmp/helper",
                                      actorSignature: signature, targetTeamId: Self.team, targetImage: target)
            #expect(RuleEngine.resolveField("SameTeam", from: event) == "false")
            let matches = await engine.evaluate(event)
            #expect(fires(matches, "High-Value"), "the must-fire read of a credential process fires, got: \(matches.map(\.ruleName))")
        }
        let verified = introspection(action: "get_task_read", actorName: "helper", actorPath: "/tmp/helper",
                                     actorSignature: Self.verifiedTeamActor, targetTeamId: Self.team, targetImage: target)
        #expect(RuleEngine.resolveField("SameTeam", from: verified) == "true")
        let verifiedMatches = await engine.evaluate(verified)
        #expect(!fires(verifiedMatches, "High-Value"), "a verified same-team helper is the vendor's own IPC")
        // A rule reading SameTeam waits for the actor's verdict like one reading SignerType.
        #expect(HeavyEnrichmentComponent.dependency(forPredicateField: "SameTeam") == .codeSignature)
    }

    // MARK: - Non-Apple benign introspector filters (review fix)

    @Test("third-party EDR introspection is filtered from the base memory-read rule")
    func edrFiltered() async throws {
        let engine = try await loadRules()
        let edr = await engine.evaluate(introspection(
            action: "get_task_read", actorName: "falcond",
            actorPath: "/Applications/Falcon.app/Contents/Resources/falcond", targetImage: "/tmp/victim"))
        #expect(!fires(edr, "Read Access"), "EDR agent should be filtered, got: \(edr.map(\.ruleName))")
    }
}
