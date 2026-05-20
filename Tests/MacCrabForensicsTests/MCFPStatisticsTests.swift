// MCFPStatistics — Wilson score + different-family separation
// math correctness tests. Plan §6.4 R2 statistical framework.

import Testing
import Foundation
@testable import MacCrabForensics

@Suite("MCFPStatistics")
struct MCFPStatisticsTests {

    @Test("Wilson CI on n=0 returns full range")
    func wilsonZeroTrials() {
        let (lo, hi) = MCFPStatistics.wilsonCI95(successes: 0, trials: 0)
        #expect(lo == 0.0)
        #expect(hi == 1.0)
    }

    @Test("Wilson CI on 100% successes is bounded away from 1.0 below")
    func wilsonAllSuccesses() {
        let (lo, hi) = MCFPStatistics.wilsonCI95(successes: 20, trials: 20)
        // Point estimate is 1.0; Wilson lower for n=20 ≈ 0.832
        // (textbook). The unit test asserts the lower bound is
        // strictly below 1.0 so we can flag noisy-perfect runs.
        #expect(hi == 1.0)
        #expect(lo < 1.0)
        #expect(lo > 0.5)
    }

    @Test("Wilson CI on 0% successes is bounded away from 0.0 above")
    func wilsonAllFailures() {
        let (lo, hi) = MCFPStatistics.wilsonCI95(successes: 0, trials: 20)
        #expect(lo == 0.0)
        #expect(hi > 0.0)
        #expect(hi < 0.5)
    }

    @Test("Wilson CI on balanced sample is symmetric around 0.5")
    func wilsonBalancedSample() {
        let (lo, hi) = MCFPStatistics.wilsonCI95(successes: 50, trials: 100)
        let mid = (lo + hi) / 2.0
        // Balanced binomial → CI centered close to 0.5.
        #expect(abs(mid - 0.5) < 0.05)
    }

    @Test("Larger n produces tighter CI (the whole point of n)")
    func tighterCIForLargerN() {
        let (lo20, hi20) = MCFPStatistics.wilsonCI95(successes: 18, trials: 20)
        let (lo2000, hi2000) = MCFPStatistics.wilsonCI95(successes: 1800, trials: 2000)
        // Both have p=0.9. CI width must shrink as n grows.
        let width20 = hi20 - lo20
        let width2000 = hi2000 - lo2000
        #expect(width20 > width2000)
    }

    @Test("Separation: all from one family → insufficient data")
    func separationSingleFamily() {
        let entries = (0..<10).map { i in
            CorpusEntry(
                path: "/Applications/Foo.app/Contents/MacOS/foo-\(i)",
                sha256OfFile: nil,
                archToken: "arm64",
                lc: "lc-A",
                cs: "cs-A",
                ent: "ent-A",
                canonical: "mcfp1/static/arm64/lc-A/cs-A/ent-A",
                collectedAtISO: "",
                hostname: "test"
            )
        }
        let report = MCFPStatistics.differentFamilySeparation(entries: entries) { _ in "app:Foo" }
        #expect(report.familyCount == 1)
        #expect(report.pairsCompared == 0)
        #expect(report.verdict == .insufficientData)
    }

    @Test("Separation: two families with diverging cs hits 100%")
    func separationTwoFamiliesAllDiff() {
        var entries: [CorpusEntry] = []
        for i in 0..<5 {
            entries.append(CorpusEntry(
                path: "/Applications/A.app/bin-\(i)",
                sha256OfFile: nil,
                archToken: "arm64",
                lc: "lc-A",
                cs: "cs-A",
                ent: "ent-A",
                canonical: "mcfp1/static/arm64/lc-A/cs-A/ent-A",
                collectedAtISO: "",
                hostname: "test"
            ))
        }
        for i in 0..<5 {
            entries.append(CorpusEntry(
                path: "/Applications/B.app/bin-\(i)",
                sha256OfFile: nil,
                archToken: "arm64",
                lc: "lc-A",
                cs: "cs-B",
                ent: "ent-B",
                canonical: "mcfp1/static/arm64/lc-A/cs-B/ent-B",
                collectedAtISO: "",
                hostname: "test"
            ))
        }
        let report = MCFPStatistics.differentFamilySeparation(entries: entries) { entry in
            MCFPStatistics.defaultFamilyToken(forPath: entry.path)
        }
        // 5 × 5 = 25 cross-family pairs; every pair has differing
        // cs + ent → 100% separation.
        #expect(report.pairsCompared == 25)
        #expect(report.csOrEntSeparationPercent == 100.0)
        // Wilson lower bound for k=n=25 is well above 80% — verdict PASS.
        #expect(report.verdict == .pass)
    }

    @Test("Separation: identical fingerprints across families → 0% + FAIL")
    func separationIdenticalAcrossFamilies() {
        var entries: [CorpusEntry] = []
        for prefix in ["/Applications/A.app/", "/Applications/B.app/"] {
            for i in 0..<5 {
                entries.append(CorpusEntry(
                    path: prefix + "bin-\(i)",
                    sha256OfFile: nil,
                    archToken: "arm64",
                    lc: "same",
                    cs: "same",
                    ent: "same",
                    canonical: "mcfp1/static/arm64/same/same/same",
                    collectedAtISO: "",
                    hostname: "test"
                ))
            }
        }
        let report = MCFPStatistics.differentFamilySeparation(entries: entries) { entry in
            MCFPStatistics.defaultFamilyToken(forPath: entry.path)
        }
        #expect(report.csOrEntSeparationPercent == 0.0)
        #expect(report.verdict == .fail)
    }

    @Test("defaultFamilyToken classifies known path patterns")
    func defaultFamilyTokenClassifies() {
        #expect(MCFPStatistics.defaultFamilyToken(forPath: "/usr/bin/true") == "apple")
        #expect(MCFPStatistics.defaultFamilyToken(forPath: "/System/Library/foo") == "apple")
        #expect(MCFPStatistics.defaultFamilyToken(forPath: "/Applications/Firefox.app/Contents/MacOS/firefox") == "app:Firefox.app")
        #expect(MCFPStatistics.defaultFamilyToken(forPath: "/tmp/unknown") == "other")
    }

    @Test("stabilityConfidenceIntervals applies Wilson per component")
    func stabilityCIPerComponent() {
        let report = CorpusDiffReport(
            matchedBinaryCount: 100,
            onlyInA: 0,
            onlyInB: 0,
            archStabilityPercent: 100.0,
            lcStabilityPercent: 95.0,
            csStabilityPercent: 50.0,
            entStabilityPercent: 95.0,
            fileSha256StabilityPercent: 100.0,
            r2StabilityVerdict: .pass,
            divergenceSamples: []
        )
        let cis = report.stabilityConfidenceIntervals()
        #expect(cis.count == 4)
        // 50% sample @ n=100 → CI roughly [40%, 60%]
        let cs = cis.first(where: { $0.component == "cs" })!
        #expect(cs.ci95LowerPct > 35.0 && cs.ci95LowerPct < 45.0)
        #expect(cs.ci95UpperPct > 55.0 && cs.ci95UpperPct < 65.0)
        // 100% sample @ n=100 → upper = 100, lower ≈ 96.4
        let arch = cis.first(where: { $0.component == "arch" })!
        #expect(arch.ci95UpperPct == 100.0)
        #expect(arch.ci95LowerPct > 95.0)
        #expect(arch.ci95LowerPct < 100.0)
    }
}
