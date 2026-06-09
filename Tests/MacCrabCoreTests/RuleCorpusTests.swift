// RuleCorpusTests.swift
// v1.18 — data-driven golden replay corpus. Each fixture in
// fixtures/rule_corpus.json names a rule UUID + an event + whether the rule
// should fire; the harness drives the REAL RuleEngine and asserts. Adding a
// fixture extends coverage with ZERO new Swift — the path to driving every
// rule's predicate through a regression gate, not just the ~16 hand-written
// fire tests. Seeded with process_creation rules; the builder extends to other
// categories as fixtures are added.

import Testing
import Foundation
@testable import MacCrabCore

struct RuleCorpusFixture: Codable {
    let name: String
    let category: String
    let ruleId: String
    let shouldFire: Bool
    let process: ProcessFixture
    var file: FileFixture?     // present → builds a file_event instead of process_creation
}

struct ProcessFixture: Codable {
    let executable: String
    let commandLine: String
    var signer: String?       // "unsigned" (default) | "apple" | "devId" | "adHoc"
    var parentExec: String?
}

struct FileFixture: Codable {
    let path: String
    let action: String        // create | write | close | rename | delete | open | link
    var content: String?      // → enrichments["FileContent"] for content-matching rules
}

@Suite("Rule corpus: data-driven TP/TN replay (v1.18)")
struct RuleCorpusTests {

    private func signerType(_ s: String?) -> SignerType {
        switch s {
        case "apple": return .apple
        case "devId": return .devId
        case "adHoc": return .adHoc
        default: return .unsigned
        }
    }

    private func event(_ f: RuleCorpusFixture) -> Event {
        let sig = CodeSignatureInfo(
            signerType: signerType(f.process.signer),
            teamId: nil, signingId: nil, authorities: [], flags: 0,
            isNotarized: f.process.signer == "apple" || f.process.signer == "devId",
            issuerChain: nil, certHashes: nil, isAdhocSigned: nil, entitlements: nil)
        let proc = MacCrabCore.ProcessInfo(
            pid: 4321, ppid: 1, rpid: 1,
            name: (f.process.executable as NSString).lastPathComponent,
            executable: f.process.executable, commandLine: f.process.commandLine,
            args: [f.process.executable], workingDirectory: "/tmp",
            userId: 501, userName: "t", groupId: 20, startTime: Date(), codeSignature: sig,
            ancestors: [ProcessAncestor(pid: 1, executable: f.process.parentExec ?? "/bin/bash", name: "parent")],
            architecture: "arm64", isPlatformBinary: f.process.signer == "apple")
        if let ff = f.file {
            let action = FileAction(rawValue: ff.action) ?? .write
            var enr: [String: String] = [:]
            if let c = ff.content { enr["FileContent"] = c }
            return Event(eventCategory: .file, eventType: .change, eventAction: ff.action,
                         process: proc, file: FileInfo(path: ff.path, action: action), enrichments: enr)
        }
        return Event(eventCategory: .process, eventType: .start, eventAction: "exec", process: proc)
    }

    @Test("every corpus fixture: a positive fires its rule, a negative does not")
    func corpus() async throws {
        ensureRulesCompiled()
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appendingPathComponent("fixtures/rule_corpus.json")
        let fixtures = try JSONDecoder().decode([RuleCorpusFixture].self, from: Data(contentsOf: url))
        #expect(fixtures.count >= 6, "corpus should be seeded (got \(fixtures.count))")

        let engine = RuleEngine()
        _ = try await engine.loadRules(from: URL(fileURLWithPath: "/tmp/maccrab_v3"))

        for f in fixtures {
            // Builder supports process_creation fixtures and (when `file` is
            // present) file_event fixtures.
            let fired = await engine.evaluate(event(f)).contains { $0.ruleId == f.ruleId }
            #expect(fired == f.shouldFire,
                    "corpus '\(f.name)': expected rule \(f.ruleId) fire=\(f.shouldFire), got \(fired)")
        }
    }
}
