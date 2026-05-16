// StylometricFingerprinter.swift
// MacCrabCore
//
// 32-feature stylometric fingerprint for code / commit messages /
// PR descriptions. Three uses:
//
//   1. **Maintainer drift detection** — compute fingerprint of each
//      new commit by author X, compare to author X's cached baseline,
//      alert on cosine-distance spike (XZ-Utils / Jia Tan / mockingbird
//      pattern).
//   2. **LLM-text scoring** on commit messages touching privileged
//      paths — em-dash frequency + perplexity proxy. Post-RLHF
//      (per arXiv 2603.27006), this is best used as a *prior* not
//      a binary classifier.
//   3. **Urgency-lexicon scoring** on README / PR / issue text fetched
//      at install time — catches the XZ-Utils "Jigar Kumar" /
//      polyfill.io social-engineering pattern.
//
// All computation is local + deterministic; no LLM call, no cloud.

import Foundation
import os.log

// MARK: - StylometricFingerprinter

public actor StylometricFingerprinter {

    private let logger = Logger(subsystem: "com.maccrab.enrichment", category: "stylometric-fingerprinter")

    // MARK: - Types

    /// Compact 32-feature vector. Each element is a normalized [0,1] scalar.
    public struct Fingerprint: Sendable, Equatable, Codable {
        public let vector: [Double]
        public init(vector: [Double]) { self.vector = vector }
    }

    public struct DriftResult: Sendable {
        public let author: String
        public let cosineDistance: Double      // 0 = identical, 1 = orthogonal
        public let flagged: Bool                // distance > threshold
        public let reasons: [String]
        public init(author: String, cosineDistance: Double, flagged: Bool, reasons: [String]) {
            self.author = author
            self.cosineDistance = cosineDistance
            self.flagged = flagged
            self.reasons = reasons
        }
    }

    public struct UrgencyResult: Sendable {
        /// 0-100 urgency score.
        public let score: Int
        public let matchedTerms: [String]
        public init(score: Int, matchedTerms: [String]) {
            self.score = score
            self.matchedTerms = matchedTerms
        }
    }

    // MARK: - State

    /// Per-author rolling baseline. Caps at maxAuthors and N most-recent
    /// fingerprints per author.
    private var baselines: [String: [Fingerprint]] = [:]
    private let maxAuthors: Int
    private let maxFingerprintsPerAuthor: Int
    private let driftThreshold: Double

    public init(
        maxAuthors: Int = 1024,
        maxFingerprintsPerAuthor: Int = 30,
        driftThreshold: Double = 0.35
    ) {
        self.maxAuthors = maxAuthors
        self.maxFingerprintsPerAuthor = maxFingerprintsPerAuthor
        self.driftThreshold = driftThreshold
    }

    // MARK: - Public API

    /// Compute the 32-dim stylometric fingerprint of a text sample.
    public nonisolated func fingerprint(_ text: String) -> Fingerprint {
        Self.computeFingerprint(text)
    }

    /// Update an author's rolling baseline (e.g., after a confirmed
    /// commit) so future drift checks compare against recent history.
    public func recordBaseline(_ fingerprint: Fingerprint, author: String) {
        var fps = baselines[author] ?? []
        fps.append(fingerprint)
        if fps.count > maxFingerprintsPerAuthor {
            fps.removeFirst(fps.count - maxFingerprintsPerAuthor)
        }
        baselines[author] = fps
        if baselines.count > maxAuthors {
            if let oldest = baselines.keys.first { baselines.removeValue(forKey: oldest) }
        }
    }

    /// Check whether a new commit's fingerprint deviates from the
    /// author's cached baseline.
    public func checkDrift(author: String, text: String) -> DriftResult? {
        guard let baseline = baselines[author], !baseline.isEmpty else {
            return nil
        }
        let newFp = Self.computeFingerprint(text)
        let centroid = Self.centroid(of: baseline)
        let distance = Self.cosineDistance(newFp.vector, centroid.vector)
        var reasons: [String] = []
        let flagged = distance > driftThreshold
        if flagged {
            reasons.append("stylometric distance \(String(format: "%.2f", distance)) exceeds threshold \(driftThreshold)")
            // Identify which feature dimensions moved most.
            let deltas = zip(newFp.vector, centroid.vector).map { abs($0 - $1) }
            if let maxIdx = deltas.enumerated().max(by: { $0.element < $1.element })?.offset {
                reasons.append("largest delta on feature[\(maxIdx)] (\(Self.featureName(at: maxIdx)))")
            }
        }
        return DriftResult(author: author, cosineDistance: distance, flagged: flagged, reasons: reasons)
    }

    /// Score urgency markers in a free-form text blob (PR description,
    /// issue body, release notes).
    public nonisolated func urgencyScore(_ text: String) -> UrgencyResult {
        let lowered = text.lowercased()
        let terms: [(String, Int)] = [
            ("urgent", 15), ("asap", 15), ("immediately", 10),
            ("critical", 10), ("emergency", 15), ("must merge", 20),
            ("please merge", 12), ("security fix", 8),
            ("zero day", 18), ("0-day", 18), ("0day", 18),
            ("won't compile without", 12), ("blocking release", 12),
            ("blocking production", 14), ("breaks ci", 8),
            ("merge now", 18), ("fix now", 10), ("hotfix", 6),
            ("revert pending", 8),
        ]
        var score = 0
        var matched: [String] = []
        for (term, weight) in terms where lowered.contains(term) {
            score += weight
            matched.append(term)
        }
        return UrgencyResult(score: min(score, 100), matchedTerms: matched)
    }

    /// LLM-text-presence prior using the post-RLHF stable signals:
    /// em-dash frequency + n-gram surprise + sentence-length variance.
    /// Returns 0-100 ("how LLM-shaped does this text look").
    /// Per arXiv 2603.27006 ("The Last Fingerprint"), em-dash rate is
    /// still useful as a *probabilistic* feature even after detector
    /// arms races.
    public nonisolated func llmTextScore(_ text: String) -> Int {
        guard text.count >= 40 else { return 0 }
        let total = max(text.count, 1)
        // 1. Em-dash density (per 1K chars).
        let emCount = text.filter { $0 == "—" }.count
        let emDensity = (Double(emCount) * 1000.0) / Double(total)
        // 2. Sentence-length uniformity (LLMs tend to produce
        // suspiciously consistent sentence lengths).
        let sentences: [Int] = Self.splitSentenceLengths(text)
        let lengthVariance: Double = {
            guard sentences.count > 1 else { return 100 }
            let mean = Double(sentences.reduce(0, +)) / Double(sentences.count)
            let variance = sentences.reduce(0.0) { acc, l in acc + pow(Double(l) - mean, 2) } / Double(sentences.count)
            return variance
        }()
        // 3. Hedge-phrase density ("it is important to note",
        // "in summary", "to ensure", "moreover", "furthermore").
        let hedgeMarkers = ["it is important to note", "in summary", "to ensure", "moreover", "furthermore", "delve", "tapestry", "in conclusion"]
        let lowered = text.lowercased()
        let hedgeCount = hedgeMarkers.filter { lowered.contains($0) }.count

        var score = 0
        if emDensity >= 2.0 { score += min(35, Int(emDensity * 5)) }
        if lengthVariance < 25 { score += 15 }
        score += hedgeCount * 12
        return min(score, 100)
    }

    public func baselineCount(author: String) -> Int {
        baselines[author]?.count ?? 0
    }

    // MARK: - Fingerprint computation

    nonisolated static func computeFingerprint(_ text: String) -> Fingerprint {
        // v1.12.0 — single-pass character accumulation. Pre-rewrite,
        // this function walked the text 22+ times (one .filter per
        // character class plus 17 separate passes for the top-char
        // letter-frequency vector, each preceded by an allocation-heavy
        // text.lowercased() call). On 100KB input that's ~2.2M character
        // visits and 17 String allocations. We now do ONE pass that
        // bumps every relevant counter in lockstep, with lines split
        // exactly once for per-line metrics. Expected speedup: ~6-10×
        // on >10KB inputs, with proportionally fewer allocations.

        // ---- char-level single pass ----
        var tabs = 0
        var spaces = 0
        var semicolons = 0
        var emDash = 0
        var digits = 0
        var letterTotal = 0
        // Top-17 English letter frequency buckets (Burrows' Delta lite).
        // Indexed by character; order must match `topChars` below so the
        // vector layout matches the pre-rewrite ordering.
        var topCounts = [Character: Int](minimumCapacity: 17)
        let topChars: [Character] = ["e", "t", "a", "o", "i", "n", "s", "h", "r", "d", "l", "u", "c", "m", "w", "f", "g"]
        for ch in topChars { topCounts[ch] = 0 }

        for ch in text {
            switch ch {
            case "\t": tabs += 1
            case " ":  spaces += 1
            case ";":  semicolons += 1
            case "—":  emDash += 1
            default: break
            }
            if ch.isNumber { digits += 1 }
            if ch.isLetter {
                letterTotal += 1
                // Lowercase one Character at a time — cheaper than
                // allocating a full String via text.lowercased().
                let lower = Character(ch.lowercased())
                if topCounts[lower] != nil {
                    topCounts[lower]! += 1
                }
            }
        }

        let total = max(text.count, 1)
        // 1: tab-vs-space indent ratio
        let f1 = Double(tabs) / Double(max(tabs + spaces, 1))
        // 6: semicolon density
        let f6 = min(1.0, Double(semicolons) / Double(total) * 100.0)
        // 7: em-dash density
        let f7 = min(1.0, Double(emDash) / Double(total) * 500.0)
        // 10: digit density
        let f10 = Double(digits) / Double(total)

        // ---- line-level single pass ----
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false)
        let lineCount = max(lines.count, 1)

        var openBraceLineEnd = 0
        var openBraceNewLine = 0
        var comments = 0
        var blanks = 0
        var trailing = 0
        var todos = 0
        var lineLenSum = 0.0
        var lineLenSqSum = 0.0
        for line in lines {
            let lineLen = Double(line.count)
            lineLenSum += lineLen
            lineLenSqSum += lineLen * lineLen
            if line.hasSuffix("{") { openBraceLineEnd += 1 }
            if line.hasSuffix(" ") { trailing += 1 }
            // Trim only when we actually need the trimmed view.
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty {
                blanks += 1
            } else {
                if trimmed.hasPrefix("{") { openBraceNewLine += 1 }
                if trimmed.hasPrefix("//") || trimmed.hasPrefix("#") || trimmed.hasPrefix("/*") {
                    comments += 1
                }
            }
            if line.localizedCaseInsensitiveContains("TODO") || line.localizedCaseInsensitiveContains("FIXME") {
                todos += 1
            }
        }

        // 2: mean line length
        let f2 = min(1.0, (Double(total) / Double(lineCount)) / 120.0)
        // 3: brace style — open-brace at line end vs new line
        let f3 = Double(openBraceLineEnd) / Double(max(openBraceLineEnd + openBraceNewLine, 1))
        // 4: comment-density
        let f4 = Double(comments) / Double(lineCount)
        // 11: blank-line frequency
        let f11 = Double(blanks) / Double(lineCount)
        // 12: trailing-whitespace lines
        let f12 = Double(trailing) / Double(lineCount)
        // 13: line-length variance (normalised) — derived from
        // sum + sum-of-squares so the second pass over lines is avoided.
        let meanLL = lineLenSum / Double(lineCount)
        let variance = max(0.0, (lineLenSqSum / Double(lineCount)) - meanLL * meanLL)
        let f13 = min(1.0, sqrt(variance) / 80.0)
        // 14: TODO / FIXME marker density
        let f14 = Double(todos) / Double(lineCount)
        // 15: hashbang prefix presence
        let f15 = lines.first?.hasPrefix("#!") == true ? 1.0 : 0.0

        // ---- regex-based identifier ratio (kept as 2 passes — both
        // are NSRegularExpression-backed and O(N) already) ----
        // 5: snake-case vs camelCase identifier ratio
        let snakeMatches = text.ranges(matching: #"[a-z]+_[a-z0-9_]+"#).count
        let camelMatches = text.ranges(matching: #"[a-z]+[A-Z][a-zA-Z0-9]+"#).count
        let f5 = Double(snakeMatches) / Double(max(snakeMatches + camelMatches, 1))

        // ---- word-level single pass ----
        let wordSubs: [String] = Self.splitWords(text)
        var wordLenSum = 0
        var capsCount = 0
        for w in wordSubs {
            wordLenSum += w.count
            if w.first?.isUppercase == true { capsCount += 1 }
        }
        let wordCount = max(wordSubs.count, 1)
        // 8: avg-word-length
        let f8 = min(1.0, (wordSubs.isEmpty ? 0 : Double(wordLenSum) / Double(wordCount)) / 12.0)
        // 9: capitalised-words frequency
        let f9 = Double(capsCount) / Double(wordCount)

        // ---- char-distribution vector (already counted in pass 1) ----
        var charFeatures: [Double] = []
        for ch in topChars {
            let cnt = topCounts[ch] ?? 0
            charFeatures.append(Double(cnt) / Double(max(letterTotal, 1)))
        }

        var vector: [Double] = [f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, f11, f12, f13, f14, f15]
        vector.append(contentsOf: charFeatures)
        return Fingerprint(vector: vector)
    }

    nonisolated static func centroid(of fps: [Fingerprint]) -> Fingerprint {
        guard let dim = fps.first?.vector.count, dim > 0 else { return Fingerprint(vector: []) }
        var sum = Array(repeating: 0.0, count: dim)
        for fp in fps {
            for i in 0..<dim { sum[i] += fp.vector[i] }
        }
        let n = Double(fps.count)
        return Fingerprint(vector: sum.map { $0 / n })
    }

    nonisolated static func cosineDistance(_ a: [Double], _ b: [Double]) -> Double {
        guard a.count == b.count, !a.isEmpty else { return 1.0 }
        var dot = 0.0
        var normA = 0.0
        var normB = 0.0
        for i in 0..<a.count {
            dot += a[i] * b[i]
            normA += a[i] * a[i]
            normB += b[i] * b[i]
        }
        let denom = sqrt(normA) * sqrt(normB)
        if denom == 0 { return 1.0 }
        let similarity = dot / denom
        return 1.0 - similarity
    }

    /// Manual sentence-length split — avoids Swift's
    /// String.split ambiguity between Sequence and Collection
    /// overloads.
    nonisolated static func splitSentenceLengths(_ text: String) -> [Int] {
        var lengths: [Int] = []
        var current = 0
        for ch in text {
            if ".!?".contains(ch) {
                if current > 0 { lengths.append(current) }
                current = 0
            } else {
                current += 1
            }
        }
        if current > 0 { lengths.append(current) }
        return lengths
    }

    /// Manual word splitter — same rationale as
    /// `splitSentenceLengths`.
    nonisolated static func splitWords(_ text: String) -> [String] {
        var words: [String] = []
        var current = ""
        for ch in text {
            if ch.isLetter {
                current.append(ch)
            } else {
                if !current.isEmpty { words.append(current); current = "" }
            }
        }
        if !current.isEmpty { words.append(current) }
        return words
    }

    nonisolated static func featureName(at index: Int) -> String {
        let names = [
            "tab-vs-space ratio", "mean line length", "brace style",
            "comment density", "snake-vs-camel", "semicolon density",
            "em-dash density", "avg word length", "capitalisation rate",
            "digit density", "blank-line rate", "trailing whitespace",
            "line-length variance", "TODO/FIXME density", "hashbang prefix",
        ]
        if index < names.count { return names[index] }
        return "char-distribution-\(index - names.count)"
    }
}

// MARK: - Regex helper

private extension String {
    func ranges(matching pattern: String) -> [Range<String.Index>] {
        guard let regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else {
            return []
        }
        let ns = self as NSString
        let matches = regex.matches(in: self, range: NSRange(location: 0, length: ns.length))
        return matches.compactMap { Range($0.range, in: self) }
    }
}
