import Testing
import MacCrabCore
@testable import MacCrabApp

@Suite("Detection presentation single-pass statistics")
struct V2DetectionRuleStatisticsTests {
    private func row(_ id: String, enabled: Bool = true, custom: Bool = false,
                     matches: Int = 0) -> V2MockRule {
        .init(id: id, title: "Inert statistics fixture", category: "File", severity: .low,
              mitre: [], isEnabled: enabled, lastFired: nil, firesLastWeek: matches,
              isCustom: custom, description: "No rule predicates or live data")
    }

    private func expectPreviousOracle(_ rows: [V2MockRule]) {
        let stats = V2DetectionRuleStatistics(rows)
        let builtinCount = rows.filter { BuiltinRuleCatalog.byId[$0.id] != nil }.count
        #expect(stats.builtinCount == builtinCount)
        #expect(stats.sigmaCount == rows.count - builtinCount)
        #expect(stats.enabled == rows.filter { $0.isEnabled }.count)
        #expect(stats.custom == rows.filter { $0.isCustom }.count)
        #expect(stats.firedRecently == rows.reduce(0) { $0 + $1.firesLastWeek })
    }

    @Test("empty population has zero totals")
    func emptyPopulation() {
        let stats = V2DetectionRuleStatistics([])
        #expect(stats.builtinCount == 0 && stats.sigmaCount == 0)
        #expect(stats.enabled == 0 && stats.custom == 0 && stats.firedRecently == 0)
        expectPreviousOracle([])
    }

    @Test("catalog membership is exact, while custom/enabled and duplicate rows remain independent")
    func exactMembershipAndIndependentFlags() throws {
        let builtin = try #require(BuiltinRuleCatalog.all.first?.id)
        let unknown = "maccrab.inert-statistics-not-in-catalog"
        try #require(BuiltinRuleCatalog.byId[unknown] == nil)
        let rows = [row(builtin, enabled: false, custom: true, matches: 7),
                    row(builtin, matches: 3),
                    row(unknown, custom: true, matches: 5),
                    row("inert.sequence", enabled: false, matches: 11)]
        let stats = V2DetectionRuleStatistics(rows)
        #expect(stats.builtinCount == 2 && stats.sigmaCount == 2)
        #expect(stats.enabled == 2 && stats.custom == 2 && stats.firedRecently == 26)
        expectPreviousOracle(rows)
    }

    @Test("telemetry and override replacements update totals without caching the old population")
    func refreshedRows() throws {
        let builtin = try #require(BuiltinRuleCatalog.all.first?.id)
        let before = [row(builtin, matches: 1), row("inert.user", custom: true, matches: 2)]
        let after = [row(builtin, enabled: false, matches: 4),
                     row("inert.user", enabled: false, custom: true, matches: 9)]
        expectPreviousOracle(before)
        expectPreviousOracle(after)
        #expect(V2DetectionRuleStatistics(before).enabled == 2)
        #expect(V2DetectionRuleStatistics(after).enabled == 0)
        #expect(V2DetectionRuleStatistics(after).firedRecently == 13)
    }

    @Test("a roughly production-sized inert population preserves every previous total")
    func largeMixedPopulation() throws {
        let builtin = try #require(BuiltinRuleCatalog.all.first?.id)
        let rows = (0..<5_000).map { index in
            row(index.isMultiple(of: 11) ? builtin : "inert.rule.\(index)",
                enabled: !index.isMultiple(of: 3), custom: index.isMultiple(of: 7),
                matches: index % 19)
        }
        expectPreviousOracle(rows)
        #expect(V2DetectionRuleStatistics(rows).builtinCount
                + V2DetectionRuleStatistics(rows).sigmaCount == rows.count)
    }
}
