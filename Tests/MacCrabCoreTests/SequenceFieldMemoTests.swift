import Foundation
import Testing
@testable import MacCrabCore

/// Benign in-memory metadata only: no files, executable launches, installed
/// rules, live collector or daemon. The oracle retains the pre-memo operations.
@Suite("Sequence evaluation-local field memo")
struct SequenceFieldMemoTests {
    private func event(text: String? = nil, enrichments: [String: String] = [:]) -> Event {
        let process = MacCrabCore.ProcessInfo(
            pid: 41, ppid: 1, rpid: 41, name: "fixture", executable: "/usr/bin/true",
            commandLine: "fixture document", args: ["fixture", "document"],
            workingDirectory: "/private/tmp", userId: 501, userName: "fixture",
            groupId: 20, startTime: Date(timeIntervalSince1970: 1_700_000_000)
        )
        var fields = enrichments
        if let text { fields["fixture.text"] = text }
        return Event(eventCategory: .file, eventType: .creation, eventAction: "create",
            process: process, file: FileInfo(path: "/private/tmp/Notes.txt", name: "Notes.txt", directory: "/private/tmp", action: .create),
            enrichments: fields)
    }

    private func rule(_ id: String, predicates: [MacCrabCore.Predicate],
                      condition: RuleCondition = .allOf, tree: ConditionNode? = nil) -> SequenceRule {
        SequenceRule(id: id, title: "ordinary document metadata", description: "memo regression",
            level: .low, tags: [], window: 60, correlationType: .none, ordered: true,
            steps: [SequenceStep(id: "only", logsourceCategory: "file_event", predicates: predicates,
                                 condition: condition, conditionTree: tree)], trigger: .allSteps)
    }

    /// Independent of FieldMemo and SequenceEngine's helpers. Deliberately use
    /// Foundation/Swift's original operations, not alternate byte matching.
    private func reference(_ predicate: MacCrabCore.Predicate, event: Event) -> Bool {
        let value = RuleEngine.resolveField(predicate.field, from: event)
        let raw: Bool
        if predicate.modifier == .exists {
            raw = value?.isEmpty == false
        } else if let value {
            let lower = value.lowercased()
            let values = predicate.values
            switch predicate.modifier {
            case .equals: raw = values.contains { lower == $0.lowercased() }
            case .contains: raw = values.contains { lower.contains($0.lowercased()) }
            case .startswith: raw = values.contains { lower.hasPrefix($0.lowercased()) }
            case .endswith: raw = values.contains { lower.hasSuffix($0.lowercased()) }
            case .regex:
                raw = values.contains { pattern in
                    guard let regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else {
                        return false
                    }
                    return regex.firstMatch(in: value, range: NSRange(value.startIndex..., in: value)) != nil
                }
            case .exists: raw = !value.isEmpty
            case .gt: raw = Double(value).map { number in values.contains { Double($0).map { number > $0 } ?? false } } ?? false
            case .lt: raw = Double(value).map { number in values.contains { Double($0).map { number < $0 } ?? false } } ?? false
            case .gte: raw = Double(value).map { number in values.contains { Double($0).map { number >= $0 } ?? false } } ?? false
            case .lte: raw = Double(value).map { number in values.contains { Double($0).map { number <= $0 } ?? false } } ?? false
            }
        } else {
            raw = false
        }
        return predicate.negate ? !raw : raw
    }

    @Test("Flat and tree paths match the original Unicode, empty, missing, regex and numeric operations")
    func modifierOracle() async throws {
        let cases: [(String?, PredicateModifier, [String])] = [
            ("Draft Notes", .equals, ["draft notes"]),
            ("Draft Notes", .contains, ["unrelated", "NOTES"]),
            ("Draft Notes", .startswith, ["DRAFT"]),
            ("Draft Notes", .endswith, ["NOTES"]),
            ("Café", .equals, ["Cafe\u{301}"]),
            ("Cafe\u{301} notes", .contains, ["CAFÉ"]),
            ("İSTANBUL", .contains, ["i\u{307}stan"]),
            ("ΟΣ notes", .startswith, ["ος"]),
            ("Straße", .equals, ["STRASSE"]),
            ("👩‍💻 Notes", .contains, ["👩‍💻"]),
            ("résumé", .endswith, ["ME\u{301}"]),
            ("", .equals, [""]), ("", .contains, [""]),
            ("notes", .contains, [""]), ("notes", .equals, []),
            ("notes", .contains, []), ("notes", .startswith, []),
            ("notes", .endswith, []), ("notes", .regex, []),
            (nil, .contains, ["notes"]), (nil, .exists, []),
            ("", .exists, []), ("notes", .exists, []),
            ("ABC", .regex, ["(?-i:^[A-Z]+$)"]),
            ("abc", .regex, ["(?-i:^[A-Z]+$)"]),
            ("Notes", .regex, ["^notes$"]), ("notes", .regex, ["["]),
            ("12", .gt, ["11", "not numeric"]), ("12", .lt, ["13"]),
            ("12", .gte, ["12"]), ("12", .lte, ["12"]),
            ("1E2", .gt, ["99"]), ("not numeric", .gte, ["12"]),
            ("12", .lt, []), (nil, .gt, ["0"]),
        ]
        for (index, item) in cases.enumerated() {
            for negate in [false, true] {
                let input = event(text: item.0)
                let predicate = MacCrabCore.Predicate(field: "fixture.text", modifier: item.1,
                                                     values: item.2, negate: negate)
                let engine = SequenceEngine(lineage: ProcessLineage())
                // Repeated references hit the same memo in both flat and tree
                // paths; the .not(.not(...)) also preserves negation semantics.
                try await engine.addRule(rule("flat", predicates: [predicate, predicate, predicate]))
                try await engine.addRule(rule("tree", predicates: [predicate, predicate, predicate],
                    tree: .and([.predicate(0), .not(.not(.predicateGroup(range: 1..<3, mode: .allOf)))])))
                let matches = Set(await engine.evaluate(input).map(\.ruleId))
                let expected: Set<String> = reference(predicate, event: input) ? ["flat", "tree"] : []
                #expect(matches == expected, "case \(index), negate=\(negate)")
            }
        }
    }

    @Test("Grouping preserves alias distinctions and the flat predicate-free contract")
    func groupingAndAliasDistinctions() async throws {
        let name = MacCrabCore.Predicate(field: "file.name", modifier: .equals, values: ["notes.txt"], negate: false)
        let pathMiss = MacCrabCore.Predicate(field: "TargetFilename", modifier: .equals, values: ["notes.txt"], negate: false)
        let pathHit = MacCrabCore.Predicate(field: "TargetFilename", modifier: .endswith, values: ["/notes.txt"], negate: false)
        let predicates = [name, pathMiss, pathHit]
        let engine = SequenceEngine(lineage: ProcessLineage())
        try await engine.addRule(rule("all", predicates: predicates, condition: .allOf))
        try await engine.addRule(rule("any", predicates: predicates, condition: .anyOf))
        try await engine.addRule(rule("each", predicates: predicates, condition: .oneOfEach))
        try await engine.addRule(rule("tree-each", predicates: predicates,
                                     tree: .predicateGroup(range: 0..<3, mode: .oneOfEach)))
        try await engine.addRule(rule("tree-any", predicates: predicates,
                                     tree: .predicateGroup(range: 0..<3, mode: .anyOf)))
        try await engine.addRule(rule("tree-or", predicates: predicates,
                                     tree: .or([.predicate(1), .and([.predicate(0), .predicate(2)])])))
        try await engine.addRule(rule("empty-flat", predicates: [], condition: .anyOf))
        #expect(Set(await engine.evaluate(event()).map(\.ruleId)) ==
                ["any", "each", "tree-each", "tree-any", "tree-or", "empty-flat"])
    }

    @Test("Distinct events and enriched replays receive fresh field caches even with the same event ID")
    func eventAndReplayLifetime() async throws {
        let engine = SequenceEngine(lineage: ProcessLineage())
        for word in ["First", "Second"] {
            try await engine.addRule(rule(word, predicates: [MacCrabCore.Predicate(
                field: "fixture.text", modifier: .equals, values: [word], negate: false)]))
        }
        try await engine.addRule(rule("updated-content", predicates: [MacCrabCore.Predicate(
            field: "FileContent", modifier: .equals, values: ["Updated Notes"], negate: false)]))
        let initial = event(text: "First", enrichments: ["FileContent": "Draft Notes"])
        #expect(Set(await engine.evaluate(initial).map(\.ruleId)) == ["First"])
        #expect(Set(await engine.evaluate(event(text: "Second")).map(\.ruleId)) == ["Second"])
        var revised = initial
        revised.enrichments["fixture.text"] = "Second"
        revised.enrichments["FileContent"] = "Updated Notes"
        #expect(revised.id == initial.id && revised.timestamp == initial.timestamp)
        #expect(Set(await engine.reevaluate(revised, forCompleted: [.fileContent]).map(\.ruleId)) == ["updated-content"])
        #expect(await engine.reevaluate(revised, forCompleted: []).isEmpty)
        #expect(Set(await engine.evaluate(revised).map(\.ruleId)) == ["Second", "updated-content"])
    }

    @Test("Unresolved evidence remains false before flat negation and tree-not")
    func unresolvedEvidenceGuard() async throws {
        let positive = MacCrabCore.Predicate(field: "FileContent", modifier: .equals, values: ["Draft Notes"], negate: false)
        let negative = MacCrabCore.Predicate(field: "FileContent", modifier: .equals, values: ["Draft Notes"], negate: true)
        let engine = SequenceEngine(lineage: ProcessLineage())
        try await engine.addRule(rule("flat-negative", predicates: [negative]))
        try await engine.addRule(rule("tree-not", predicates: [positive], tree: .not(.predicate(0))))
        for state in [HeavyEnrichmentCoverage.pending, .rejected, .timedOut, .cancelled, .unavailable] {
            var input = event()
            input.enrichments[DeferredEventEnrichment.coverageKey] =
                DeferredEventEnrichment.coverageMarker([.fileContent: state])
            #expect(await engine.evaluate(input).isEmpty)
        }
        #expect(Set(await engine.evaluate(event()).map(\.ruleId)) == ["flat-negative", "tree-not"])
    }
}
