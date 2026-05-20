// CorpusDiff — compares two corpus JSONL files (from different
// Macs) and reports per-component stability. Plan §6.4 R2.

import Foundation

public struct CorpusDiffReport: Sendable, Codable {

    /// Number of binaries present in both corpora (matched by file
    /// path).
    public let matchedBinaryCount: Int

    /// Number of binaries unique to corpus A.
    public let onlyInA: Int

    /// Number of binaries unique to corpus B.
    public let onlyInB: Int

    /// Component-stability percentages [0.0, 100.0]. Each is the
    /// fraction of matched binaries whose component value is
    /// equal across the two corpora.
    public let archStabilityPercent: Double
    public let lcStabilityPercent: Double
    public let csStabilityPercent: Double
    public let entStabilityPercent: Double

    /// File-content sha256 equality across both corpora. When
    /// binaries are byte-identical we expect this to be high; a
    /// divergence flags "same path, different content."
    public let fileSha256StabilityPercent: Double

    /// Plan §6.4 R2 ship verdict: at least three of [arch, lc, cs,
    /// ent] components show ≥95% same-binary stability.
    public let r2StabilityVerdict: Verdict

    /// Sample of diverging entries (capped 50) for human review.
    public let divergenceSamples: [DivergenceSample]

    public enum Verdict: String, Sendable, Codable {
        case pass
        case fail
        case insufficientData
    }

    public struct DivergenceSample: Sendable, Codable {
        public let path: String
        public let archDiverged: Bool
        public let lcDiverged: Bool
        public let csDiverged: Bool
        public let entDiverged: Bool
        public let fileShaDiverged: Bool

        public init(path: String, archDiverged: Bool, lcDiverged: Bool, csDiverged: Bool, entDiverged: Bool, fileShaDiverged: Bool) {
            self.path = path
            self.archDiverged = archDiverged
            self.lcDiverged = lcDiverged
            self.csDiverged = csDiverged
            self.entDiverged = entDiverged
            self.fileShaDiverged = fileShaDiverged
        }
    }
}

public enum CorpusDiff {

    /// Compare two corpora. Returns a structured report.
    public static func diff(
        corpusA: [CorpusEntry],
        corpusB: [CorpusEntry]
    ) -> CorpusDiffReport {
        // Index by path.
        var byPathA: [String: CorpusEntry] = [:]
        for e in corpusA { byPathA[e.path] = e }
        var byPathB: [String: CorpusEntry] = [:]
        for e in corpusB { byPathB[e.path] = e }

        let pathsA = Set(byPathA.keys)
        let pathsB = Set(byPathB.keys)
        let matched = pathsA.intersection(pathsB)
        let onlyInA = pathsA.subtracting(pathsB)
        let onlyInB = pathsB.subtracting(pathsA)

        guard !matched.isEmpty else {
            return CorpusDiffReport(
                matchedBinaryCount: 0,
                onlyInA: onlyInA.count,
                onlyInB: onlyInB.count,
                archStabilityPercent: 0,
                lcStabilityPercent: 0,
                csStabilityPercent: 0,
                entStabilityPercent: 0,
                fileSha256StabilityPercent: 0,
                r2StabilityVerdict: .insufficientData,
                divergenceSamples: []
            )
        }

        var archMatches = 0
        var lcMatches = 0
        var csMatches = 0
        var entMatches = 0
        var shaMatches = 0
        var samples: [CorpusDiffReport.DivergenceSample] = []
        for path in matched {
            guard let a = byPathA[path], let b = byPathB[path] else { continue }
            let arch = a.archToken == b.archToken
            let lc = a.lc == b.lc
            let cs = a.cs == b.cs
            let ent = a.ent == b.ent
            let sha = a.sha256OfFile != nil && a.sha256OfFile == b.sha256OfFile
            if arch { archMatches += 1 }
            if lc { lcMatches += 1 }
            if cs { csMatches += 1 }
            if ent { entMatches += 1 }
            if sha { shaMatches += 1 }
            // Sample non-perfect rows for human review.
            if !arch || !lc || !cs || !ent {
                if samples.count < 50 {
                    samples.append(CorpusDiffReport.DivergenceSample(
                        path: path,
                        archDiverged: !arch,
                        lcDiverged: !lc,
                        csDiverged: !cs,
                        entDiverged: !ent,
                        fileShaDiverged: !sha
                    ))
                }
            }
        }

        let total = Double(matched.count)
        let archPct = Double(archMatches) / total * 100
        let lcPct = Double(lcMatches) / total * 100
        let csPct = Double(csMatches) / total * 100
        let entPct = Double(entMatches) / total * 100
        let shaPct = Double(shaMatches) / total * 100

        // R2 verdict: at least three of [arch, lc, cs, ent] ≥ 95%.
        let above95 = [archPct, lcPct, csPct, entPct].filter { $0 >= 95.0 }.count
        let verdict: CorpusDiffReport.Verdict = above95 >= 3 ? .pass : .fail

        return CorpusDiffReport(
            matchedBinaryCount: matched.count,
            onlyInA: onlyInA.count,
            onlyInB: onlyInB.count,
            archStabilityPercent: archPct,
            lcStabilityPercent: lcPct,
            csStabilityPercent: csPct,
            entStabilityPercent: entPct,
            fileSha256StabilityPercent: shaPct,
            r2StabilityVerdict: verdict,
            divergenceSamples: samples
        )
    }
}
