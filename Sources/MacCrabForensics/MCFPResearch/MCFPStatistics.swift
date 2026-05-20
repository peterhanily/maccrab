// MCFPStatistics — Wilson score confidence intervals + different-
// family separation measurement.
//
// Plan §6.4 R2 ship criteria require BOTH:
//   1. ≥3 components at ≥95% same-binary stability across Macs
//   2. ≥80% different-family separation within a corpus
// Plus a statistical layer:
//   3. Wilson score 95% CI lower bound also above the threshold
//      (so we don't accept a noisy 95% from N=20 binaries).
//
// Wilson score interval reference: Wilson (1927), recommended in
// Brown/Cai/DasGupta (2001) over the normal approximation because
// it stays in [0,1] and behaves correctly near p=0 or p=1.

import Foundation

public enum MCFPStatistics {

    /// 95% Wilson score confidence interval for a binomial
    /// proportion. Returns (lower, upper) in [0.0, 1.0].
    ///
    /// For p = k/n successes:
    ///   center = (p + z²/(2n)) / (1 + z²/n)
    ///   margin = z * sqrt(p(1-p)/n + z²/(4n²)) / (1 + z²/n)
    ///   lower = center - margin
    ///   upper = center + margin
    ///
    /// Returns (0.0, 1.0) when n == 0 (no information).
    public static func wilsonCI95(successes k: Int, trials n: Int) -> (lower: Double, upper: Double) {
        guard n > 0 else { return (0.0, 1.0) }
        let z = 1.959963984540054   // 95% two-sided
        let p = Double(k) / Double(n)
        let nDbl = Double(n)
        let zSquared = z * z
        let denom = 1.0 + zSquared / nDbl
        let center = (p + zSquared / (2.0 * nDbl)) / denom
        let radical = sqrt((p * (1.0 - p) / nDbl) + (zSquared / (4.0 * nDbl * nDbl)))
        let margin = z * radical / denom
        let lower = max(0.0, center - margin)
        let upper = min(1.0, center + margin)
        return (lower, upper)
    }

    /// Different-family separation: across all unordered pairs
    /// (a, b) where a and b belong to different families, what
    /// fraction have differing fingerprint components?
    ///
    /// Plan §6.4 R2 — at least 80% of cross-family pairs should
    /// produce a different fingerprint on cs OR ent (signing
    /// authority OR entitlement set). The signal we want is that
    /// the fingerprint actually discriminates between families
    /// rather than only collapsing duplicates.
    public static func differentFamilySeparation(
        entries: [CorpusEntry],
        familyOf: (CorpusEntry) -> String
    ) -> SeparationReport {
        // Group by family.
        var byFamily: [String: [CorpusEntry]] = [:]
        for e in entries {
            let f = familyOf(e)
            byFamily[f, default: []].append(e)
        }
        let families = byFamily.keys.sorted()
        // Cross-family pair sampling. The full Cartesian product
        // is O(N²); we cap at 100_000 sampled pairs to keep this
        // tractable for ~100K-binary corpora.
        let pairCap = 100_000
        var pairs: [(CorpusEntry, CorpusEntry)] = []
        outer: for i in 0..<families.count {
            for j in (i + 1)..<families.count {
                let listA = byFamily[families[i]] ?? []
                let listB = byFamily[families[j]] ?? []
                for a in listA {
                    for b in listB {
                        pairs.append((a, b))
                        if pairs.count >= pairCap { break outer }
                    }
                }
            }
        }
        if pairs.isEmpty {
            return SeparationReport(
                familyCount: families.count,
                pairsCompared: 0,
                csOrEntDifferentCount: 0,
                csOrEntSeparationPercent: 0,
                fullyDifferentCount: 0,
                fullSeparationPercent: 0,
                ci95Lower: 0,
                ci95Upper: 0,
                verdict: .insufficientData
            )
        }
        var csOrEntDifferent = 0
        var fullyDifferent = 0
        for (a, b) in pairs {
            let csDiff = a.cs != b.cs
            let entDiff = a.ent != b.ent
            let lcDiff = a.lc != b.lc
            let archDiff = a.archToken != b.archToken
            if csDiff || entDiff { csOrEntDifferent += 1 }
            if csDiff && entDiff && lcDiff && archDiff { fullyDifferent += 1 }
        }
        let csOrEntPct = Double(csOrEntDifferent) / Double(pairs.count) * 100
        let fullPct = Double(fullyDifferent) / Double(pairs.count) * 100
        let ci = wilsonCI95(successes: csOrEntDifferent, trials: pairs.count)
        // R2 verdict on this dimension: CI95 lower bound ≥ 0.80.
        let verdict: SeparationReport.Verdict =
            ci.lower >= 0.80 ? .pass : .fail
        return SeparationReport(
            familyCount: families.count,
            pairsCompared: pairs.count,
            csOrEntDifferentCount: csOrEntDifferent,
            csOrEntSeparationPercent: csOrEntPct,
            fullyDifferentCount: fullyDifferent,
            fullSeparationPercent: fullPct,
            ci95Lower: ci.lower * 100,
            ci95Upper: ci.upper * 100,
            verdict: verdict
        )
    }

    public struct SeparationReport: Sendable, Codable {
        public let familyCount: Int
        public let pairsCompared: Int
        public let csOrEntDifferentCount: Int
        public let csOrEntSeparationPercent: Double
        public let fullyDifferentCount: Int
        public let fullSeparationPercent: Double
        /// Wilson 95% CI lower bound on the cs-or-ent separation
        /// fraction (× 100, so a percentage).
        public let ci95Lower: Double
        public let ci95Upper: Double
        public let verdict: Verdict

        public enum Verdict: String, Sendable, Codable {
            case pass
            case fail
            case insufficientData
        }
    }

    /// Convenience: extract a family token from a binary path.
    /// "Apple" if path starts with /System or /usr; otherwise the
    /// first component after /Applications/. This is a coarse
    /// heuristic — meaningful enough for an R2 separation check
    /// without needing to parse codesign teamIDs.
    public static func defaultFamilyToken(forPath path: String) -> String {
        if path.hasPrefix("/System") || path.hasPrefix("/usr/") || path.hasPrefix("/sbin/") || path.hasPrefix("/bin/") {
            return "apple"
        }
        if path.hasPrefix("/Applications/") {
            let tail = String(path.dropFirst("/Applications/".count))
            if let slash = tail.firstIndex(of: "/") {
                return "app:\(String(tail[..<slash]))"
            }
            return "app:\(tail)"
        }
        return "other"
    }
}

public extension CorpusDiffReport {
    /// Annotate a CorpusDiffReport with a Wilson 95% lower-bound
    /// for each component stability percentage. The R2 ship rule
    /// requires not just point-estimate ≥95% but lower-bound ≥95%
    /// (to guard against small-N noise).
    struct StabilityCI: Sendable, Codable {
        public let component: String
        public let pointEstimatePct: Double
        public let ci95LowerPct: Double
        public let ci95UpperPct: Double
    }

    /// Compute 95% CI per component from this report's match
    /// counts. Derives counts by reversing the percentage; this
    /// only works perfectly if you have the source numerators,
    /// which we recover from matchedBinaryCount × percent.
    func stabilityConfidenceIntervals() -> [StabilityCI] {
        let n = matchedBinaryCount
        let entries: [(String, Double)] = [
            ("arch", archStabilityPercent),
            ("lc", lcStabilityPercent),
            ("cs", csStabilityPercent),
            ("ent", entStabilityPercent),
        ]
        return entries.map { (name, pct) in
            let k = Int((pct / 100.0) * Double(n))
            let (lower, upper) = MCFPStatistics.wilsonCI95(successes: k, trials: n)
            return StabilityCI(
                component: name,
                pointEstimatePct: pct,
                ci95LowerPct: lower * 100,
                ci95UpperPct: upper * 100
            )
        }
    }
}
