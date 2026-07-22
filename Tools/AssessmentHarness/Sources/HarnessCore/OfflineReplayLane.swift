// OfflineReplayLane.swift
// assessment-framework (P1): Lane 1 — offline event replay. Validates detection
// LOGIC by feeding a labeled corpus of synthetic process_creation events through
// the REAL RuleEngine (a public MacCrabCore API) and measuring the target rule's
// detection-engineering score against the ground-truth labels. No live sensor,
// no product seam — the engine is driven directly from this non-shipping harness.

import Foundation
import MacCrabCore

public struct OfflineReplayLane: Sendable {

    public enum LaneError: Error, CustomStringConvertible {
        case compilerFailed(String)
        case noRulesLoaded
        public var description: String {
            switch self {
            case .compilerFailed(let s): return "rule compilation failed: \(s)"
            case .noRulesLoaded: return "no compiled rules loaded"
            }
        }
    }

    public let repoRoot: String

    /// `repoRoot` defaults to the repository root derived from this file's
    /// compile-time path (Tools/AssessmentHarness/Sources/HarnessCore/ → up 4).
    public init(repoRoot: String? = nil) {
        self.repoRoot = repoRoot ?? Self.defaultRepoRoot()
    }

    static func defaultRepoRoot() -> String {
        // #filePath = <root>/Tools/AssessmentHarness/Sources/HarnessCore/OfflineReplayLane.swift
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { url.deleteLastPathComponent() }   // strip file + 4 dirs
        return url.path
    }

    // MARK: - Run

    /// Replays `corpus` through a freshly-loaded RuleEngine and returns the
    /// target rule's measured detection score plus tp/fp/fn. Pure w.r.t. the
    /// labels — the same corpus + same compiled rules always yields the same
    /// numbers (the determinism gate).
    public func run(corpus: TechniqueCorpus,
                    compiledRulesDir: String? = nil) async throws -> DetectionScore {
        let rulesDir = try compiledRulesDir ?? compileTargetRule(corpus: corpus)
        let engine = RuleEngine()
        let loaded = try await engine.loadRules(from: URL(fileURLWithPath: rulesDir),
                                                enabledStatuses: ["stable"])
        guard loaded > 0 else { throw LaneError.noRulesLoaded }

        var tp = 0, fp = 0, fn = 0
        var visibleHits = 0, visibleTotal = 0
        var heldOutHits = 0, heldOutTotal = 0
        var repsDetected = Set<String>()
        var repsTotal = Set<String>()

        for sample in corpus.samples {
            let event = Self.processCreationEvent(commandLine: sample.commandLine)
            let matches = await engine.evaluate(event)
            let fired = matches.contains {
                $0.ruleId == corpus.targetRuleId || $0.ruleName == corpus.targetRuleName
            }
            if sample.malicious {
                if sample.heldOut { heldOutTotal += 1; if fired { heldOutHits += 1 } }
                else { visibleTotal += 1; if fired { visibleHits += 1 } }
                repsTotal.insert(sample.representation)
                if fired { tp += 1; repsDetected.insert(sample.representation) } else { fn += 1 }
            } else if fired {
                fp += 1
            }
        }

        let precision: Double? = (tp + fp) > 0 ? Double(tp) / Double(tp + fp) : nil
        let visibleRecall: Double? = visibleTotal > 0 ? Double(visibleHits) / Double(visibleTotal) : nil
        let heldOutRecall: Double? = heldOutTotal > 0 ? Double(heldOutHits) / Double(heldOutTotal) : nil
        let obfCoverage: Double? = repsTotal.isEmpty ? nil
            : Double(repsDetected.count) / Double(repsTotal.count)

        return DetectionScore(
            precision: precision,
            recall: visibleRecall,
            heldOutRecall: heldOutRecall,
            obfuscationCoverage: obfCoverage,
            fpPerDay: nil,                 // Lane 3 / FP corpus territory, not offline replay
            evalP95Ms: nil,                // rule_telemetry territory (P4)
            peakPartialMatches: nil,       // sequence-engine territory
            tp: tp, fp: fp, fn: fn,
            metadataComplete: metadataComplete(corpus: corpus)
        )
    }

    // MARK: - Compilation

    /// Compiles ONLY the target rule into a temp dir via the repo's Python
    /// compiler, keeping the run fast and isolated. Faithful: the same
    /// Compiler/compile_rules.py the product uses.
    private func compileTargetRule(corpus: TechniqueCorpus) throws -> String {
        let fm = FileManager.default
        // Find the target rule's YAML by id under Rules/.
        let rulesRoot = repoRoot + "/Rules"
        guard let yaml = findRuleYAML(id: corpus.targetRuleId, under: rulesRoot) else {
            throw LaneError.compilerFailed("could not find rule YAML for id \(corpus.targetRuleId) under \(rulesRoot)")
        }
        let tmp = fm.temporaryDirectory.appendingPathComponent("assess-rules-\(UUID().uuidString)")
        let inDir = tmp.appendingPathComponent("in/command_and_control")
        let outDir = tmp.appendingPathComponent("out")
        try fm.createDirectory(at: inDir, withIntermediateDirectories: true)
        try fm.createDirectory(at: outDir, withIntermediateDirectories: true)
        try fm.copyItem(at: URL(fileURLWithPath: yaml),
                        to: inDir.appendingPathComponent((yaml as NSString).lastPathComponent))

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        proc.arguments = ["python3", repoRoot + "/Compiler/compile_rules.py",
                          "--input-dir", tmp.appendingPathComponent("in").path,
                          "--output-dir", outDir.path]
        let err = Pipe()
        proc.standardError = err
        proc.standardOutput = Pipe()
        try proc.run()
        proc.waitUntilExit()
        guard proc.terminationStatus == 0 else {
            let e = String(data: err.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            throw LaneError.compilerFailed("exit \(proc.terminationStatus): \(e)")
        }
        return outDir.path
    }

    private func findRuleYAML(id: String, under dir: String) -> String? {
        guard let en = FileManager.default.enumerator(atPath: dir) else { return nil }
        for case let rel as String in en where rel.hasSuffix(".yml") {
            let full = dir + "/" + rel
            if let text = try? String(contentsOfFile: full, encoding: .utf8),
               text.contains("id: \(id)") { return full }
        }
        return nil
    }

    private func metadataComplete(corpus: TechniqueCorpus) -> Bool {
        guard let yaml = findRuleYAML(id: corpus.targetRuleId, under: repoRoot + "/Rules"),
              let text = try? String(contentsOfFile: yaml, encoding: .utf8) else { return false }
        return text.contains("description:") && text.contains("references:") && text.contains("attack.")
    }

    // MARK: - Event construction (fidelity: match what ESCollector emits)

    /// Builds a synthetic process_creation Event whose (category .process,
    /// type .creation) maps to the "process_creation" logsource the rule filters
    /// on, and whose `process.commandLine` carries the payload the rule reads.
    /// Fixed ids/timestamps keep replay deterministic.
    static func processCreationEvent(commandLine: String) -> Event {
        let fixedDate = Date(timeIntervalSince1970: 1_700_000_000)
        let process = MacCrabCore.ProcessInfo(
            pid: 4242, ppid: 1, rpid: 1,
            name: "sh", executable: "/bin/sh",
            commandLine: commandLine,
            args: commandLine.split(separator: " ").map(String.init),
            workingDirectory: "/tmp",
            userId: 501, userName: "assess", groupId: 20,
            startTime: fixedDate
        )
        return Event(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000042")!,
            timestamp: fixedDate,
            eventCategory: .process,
            eventType: .creation,
            eventAction: "exec",
            process: process
        )
    }
}
