// RuleEngineFieldMemoTests.swift
//
// Tier-B per-event perf batch (#13): rule evaluation for a single event
// resolved + case-folded the SAME field path across the many predicates that
// reference it (the scoping counted ~121 redundant folds/event). RuleEngine now
// carries a per-event `FieldMemo` that resolves (and lowercases) each distinct
// field path at most once per event and reuses the cached value across every
// rule/predicate.
//
// These tests lock down the DETECTION-EXACT contract:
//   1. The memoized value is BYTE-IDENTICAL to the canonical, non-memoized
//      `RuleEngine.resolveField` (raw AND lowercased) for every referenced field.
//   2. Aliases that resolve to DIFFERENT values (e.g. `file.name` vs
//      `TargetFilename` → `file.path`) key to DISTINCT memo entries and never
//      collide.
//   3. Two events never share cache state — a fresh memo is bound to one event
//      and can't cross-contaminate another, at both the FieldMemo unit level and
//      the engine `evaluate(_:)` level.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("RuleEngine per-event field memo (Tier-B #13)")
struct RuleEngineFieldMemoTests {

    // MARK: - Fixtures

    /// A representative event exercising process, parent/grandparent lineage,
    /// code signature, file, network, TCC, and enrichment fields. Values use
    /// MIXED case so the case-fold parity assertions are observable, and
    /// `file.name != file.path` so the alias-distinctness check is meaningful.
    private func representativeEvent(commandLine: String = "/usr/sbin/NVRAM boot-ARGS=amfi=1") -> Event {
        let sig = CodeSignatureInfo(signerType: .devId, teamId: "ABCDE12345",
                                    signingId: "com.Example.Tool", isNotarized: true)
        let proc = MacCrabCore.ProcessInfo(
            pid: 4321, ppid: 42, rpid: 7, name: "NVRAM",
            executable: "/usr/sbin/NVRAM",
            commandLine: commandLine,
            args: ["/usr/sbin/NVRAM", "boot-ARGS=amfi=1"],
            workingDirectory: "/Users/T/Work",
            userId: 501, userName: "TestUser", groupId: 20, startTime: Date(),
            codeSignature: sig,
            ancestors: [
                ProcessAncestor(pid: 42, executable: "/bin/ZSH", name: "ZSH"),
                ProcessAncestor(pid: 1, executable: "/sbin/LaunchD", name: "LaunchD"),
            ],
            architecture: "ARM64", isPlatformBinary: true)
        let file = FileInfo(
            path: "/Users/T/Downloads/Payload.DMG",
            name: "Payload.DMG",
            directory: "/Users/T/Downloads",
            extension_: "DMG",
            action: .create)
        let net = NetworkInfo(
            sourceIp: "192.168.1.20", sourcePort: 51000,
            destinationIp: "203.0.113.9", destinationPort: 4444,
            destinationHostname: "Evil.Example.COM",
            direction: .outbound, transport: "tcp")
        let tcc = TCCInfo(
            service: "kTCCServiceScreenCapture", client: "com.Bad.App",
            clientPath: "/Applications/Bad.app", allowed: true, authReason: "user_consent")
        return Event(
            eventCategory: .process, eventType: .start, eventAction: "exec",
            process: proc, file: file, network: net, tcc: tcc,
            enrichments: ["ai_tool": "Claude_Code", "custom.plugin.field": "PluginVALUE"])
    }

    /// Every field path the assertions sweep. Mixes ECS dotted forms with the
    /// Sigma aliases the corpus actually predicates on, and includes fields that
    /// resolve to nil (so nil-memoization is covered too).
    private let referencedFields: [String] = [
        "process.executable", "Image",
        "process.name",
        "process.commandline", "process.command_line", "CommandLine",
        "process.pid", "ProcessId", "process.ppid",
        "process.args",
        "process.working_directory", "WorkingDirectory",
        "process.user.name", "User", "process.user.id",
        "process.parent.executable", "ParentImage", "process.parent.name", "ParentName",
        "process.grandparent.executable", "GrandparentImage", "process.grandparent.name",
        "process.code_signature.signer_type", "SignerType",
        "process.code_signature.team_id", "process.code_signature.signing_id",
        "process.is_notarized", "IsNotarized", "NotarizationStatus",
        "process.architecture", "Architecture",
        "process.is_platform_binary", "IsPlatformBinary", "PlatformBinary",
        "ProcessAncestors",
        "process.env", "EnvVarsFlat",                    // nil on this event
        "file.path", "TargetFilename", "file.name", "file.directory",
        "file.extension", "file.action", "FileAction", "file.source_path",  // source_path nil
        "network.destination.ip", "DestinationIp",
        "network.destination.port", "DestinationPort",
        "network.destination.hostname", "DestinationHostname",
        "DestinationIsPrivate",
        "tcc.service", "TCCService", "tcc.client", "TCCClient", "tcc.allowed", "TCCAllowed",
        "event.category", "event.type", "event.action",
        "AiTool", "AITool",                              // enrichment-backed
        "custom.plugin.field",                           // default → enrichments dict
        "no.such.field.anywhere",                        // default → nil
    ]

    // MARK: - 1. Memoized == non-memoized (byte-identical)

    @Test("memo.value / lowercasedValue are byte-identical to resolveField for every referenced field")
    func memoMatchesResolveFieldForEveryField() {
        let event = representativeEvent()
        let memo = RuleEngine.FieldMemo(event: event)

        for field in referencedFields {
            let expectedRaw = RuleEngine.resolveField(field, from: event)
            #expect(memo.value(for: field) == expectedRaw,
                    "raw memo mismatch for \(field): got \(String(describing: memo.value(for: field))), want \(String(describing: expectedRaw))")
            // Second lookup must return the SAME memoized value (cache hit path).
            #expect(memo.value(for: field) == expectedRaw)

            let expectedLower = expectedRaw?.lowercased()
            #expect(memo.lowercasedValue(for: field) == expectedLower,
                    "lowercased memo mismatch for \(field)")
            #expect(memo.lowercasedValue(for: field) == expectedLower)
        }
    }

    @Test("nil (absent) fields memoize as nil and are byte-identical to resolveField")
    func nilFieldsMemoizeAsNil() {
        let event = representativeEvent()
        let memo = RuleEngine.FieldMemo(event: event)
        // These are genuinely absent on this event.
        for absent in ["process.env", "file.source_path", "no.such.field.anywhere"] {
            #expect(RuleEngine.resolveField(absent, from: event) == nil)   // precondition
            #expect(memo.value(for: absent) == nil)
            #expect(memo.lowercasedValue(for: absent) == nil)
            // Cache-hit path (second call) still nil — the `.some(nil)` sentinel
            // must not be re-resolved into a spurious value.
            #expect(memo.value(for: absent) == nil)
        }
    }

    // MARK: - 2. Alias distinctness (no key collision)

    @Test("aliases resolving to DIFFERENT values key to DISTINCT memo entries")
    func aliasesDoNotCollide() {
        let event = representativeEvent()
        let memo = RuleEngine.FieldMemo(event: event)

        // file.name is the basename; TargetFilename resolves to the full path.
        let name = memo.value(for: "file.name")
        let full = memo.value(for: "TargetFilename")
        #expect(name == "Payload.DMG")
        #expect(full == "/Users/T/Downloads/Payload.DMG")
        #expect(name != full)   // distinct entries, no collision onto one key

        // process.name vs process.executable — same family, different values.
        let pname = memo.value(for: "process.name")
        let pexec = memo.value(for: "process.executable")
        #expect(pname == "NVRAM")
        #expect(pexec == "/usr/sbin/NVRAM")
        #expect(pname != pexec)

        // Order independence: resolving in the reverse order yields the same
        // per-key values (a fresh memo can't inherit the other's result).
        let memo2 = RuleEngine.FieldMemo(event: event)
        #expect(memo2.value(for: "TargetFilename") == full)
        #expect(memo2.value(for: "file.name") == name)
    }

    @Test("distinct aliases mapping to the SAME field resolve equal (and match resolveField)")
    func synonymAliasesAgree() {
        let event = representativeEvent()
        let memo = RuleEngine.FieldMemo(event: event)
        // CommandLine is a Sigma alias of process.commandline — same value.
        #expect(memo.value(for: "CommandLine") == memo.value(for: "process.commandline"))
        #expect(memo.value(for: "CommandLine") == RuleEngine.resolveField("CommandLine", from: event))
        #expect(memo.lowercasedValue(for: "CommandLine") == memo.value(for: "process.commandline")?.lowercased())
    }

    // MARK: - 3. No cross-event contamination (FieldMemo unit level)

    @Test("two memos for two events never share cache state")
    func twoMemosDoNotShareState() {
        let eventA = representativeEvent(commandLine: "AAA boot-ARGS=first")
        let eventB = representativeEvent(commandLine: "BBB safe-command")
        let memoA = RuleEngine.FieldMemo(event: eventA)
        let memoB = RuleEngine.FieldMemo(event: eventB)

        // Populate memoA first, then memoB.
        #expect(memoA.value(for: "process.commandline") == "AAA boot-ARGS=first")
        #expect(memoA.lowercasedValue(for: "process.commandline") == "aaa boot-args=first")

        #expect(memoB.value(for: "process.commandline") == "BBB safe-command")
        #expect(memoB.lowercasedValue(for: "process.commandline") == "bbb safe-command")

        // memoB's resolution must NOT have overwritten memoA's cached value.
        #expect(memoA.value(for: "process.commandline") == "AAA boot-ARGS=first")
        #expect(memoA.value(for: "process.commandline") != memoB.value(for: "process.commandline"))
    }

    // MARK: - 3b. No cross-event contamination (engine evaluate level)

    private func nvramEvent() -> Event {
        let proc = MacCrabCore.ProcessInfo(
            pid: 4321, ppid: 1, rpid: 1, name: "nvram",
            executable: "/usr/sbin/nvram",
            commandLine: "nvram boot-args=amfi_get_out_of_my_way=1",
            args: ["/usr/sbin/nvram"], workingDirectory: "/tmp",
            userId: 501, userName: "t", groupId: 20, startTime: Date(),
            codeSignature: nil,
            ancestors: [ProcessAncestor(pid: 1, executable: "/bin/bash", name: "bash")],
            architecture: "arm64", isPlatformBinary: false)
        return Event(eventCategory: .process, eventType: .start, eventAction: "exec", process: proc)
    }

    private func benignEvent() -> Event {
        let proc = MacCrabCore.ProcessInfo(
            pid: 5555, ppid: 1, rpid: 1, name: "ls",
            executable: "/bin/ls",
            commandLine: "ls -la",
            args: ["/bin/ls", "-la"], workingDirectory: "/Users/t",
            userId: 501, userName: "t", groupId: 20, startTime: Date(),
            codeSignature: nil,
            ancestors: [ProcessAncestor(pid: 1, executable: "/bin/bash", name: "bash")],
            architecture: "arm64", isPlatformBinary: true)
        return Event(eventCategory: .process, eventType: .start, eventAction: "exec", process: proc)
    }

    @Test("evaluate() memo is fresh per event — a benign event never inherits a prior event's cached fields")
    func engineMemoDoesNotLeakAcrossEvaluateCalls() async throws {
        ensureRulesCompiled()
        let engine = RuleEngine()
        _ = try await engine.loadRules(from: URL(fileURLWithPath: "/tmp/maccrab_v3"))
        let nvramRuleId = "d1a2b3c4-0342-4000-a000-000000000342"

        // The nvram event fires the nvram rule (commandLine contains boot-args).
        let nvramMatches = await engine.evaluate(nvramEvent())
        #expect(nvramMatches.contains { $0.ruleId == nvramRuleId },
                "nvram event should fire the nvram rule through the memoized path")

        // Immediately evaluating a benign event on the SAME engine must NOT match
        // the nvram rule. If the per-event memo leaked, the benign event could
        // reuse the prior event's cached `process.commandline` and mis-fire.
        let benignMatches = await engine.evaluate(benignEvent())
        #expect(!benignMatches.contains { $0.ruleId == nvramRuleId },
                "benign event must not inherit the prior event's cached command line")

        // Re-evaluating the nvram event still fires — deterministic across calls.
        let nvramAgain = await engine.evaluate(nvramEvent())
        #expect(nvramAgain.contains { $0.ruleId == nvramRuleId })
    }

    @Test("evaluate() is deterministic — identical events yield identical match sets")
    func engineEvaluateIsDeterministic() async throws {
        ensureRulesCompiled()
        let engine = RuleEngine()
        _ = try await engine.loadRules(from: URL(fileURLWithPath: "/tmp/maccrab_v3"))
        let event = representativeEvent()
        let first = Set((await engine.evaluate(event)).map { $0.ruleId })
        let second = Set((await engine.evaluate(event)).map { $0.ruleId })
        #expect(first == second)
    }
}
