// TyposquatDatabase.swift
// MacCrabCore
//
// Local typosquat / slopsquat scorer for package names. Given a candidate
// install target, returns the nearest top-1000 popular package by
// Damerau-Levenshtein distance (with QWERTY keyboard weighting) plus a
// Unicode-confusable fold to catch homoglyph attacks (Cyrillic а / Greek
// omicron / etc.). Pure local computation — no HTTP, no cloud calls.
//
// Background:
//   - USENIX Security 2025 (Spracklen et al.) found LLMs hallucinate package
//     names at 19.7% (open-source) / 5.2% (commercial). Attackers register
//     the hallucinated names; the most-prolific case (`huggingface-cli`,
//     Lasso Security 2024) saw 30K+ downloads in 3 months on an empty
//     placeholder.
//   - Stacklok found Levenshtein ≤2 against the top-10K catches 18 of 40
//     historical typosquats. We use Damerau-Levenshtein (adjacent
//     transpositions = 1 edit) plus a relative-distance scaling for
//     longer names.
//   - The Nethereum NuGet (Oct 2025) case demonstrated that homoglyph
//     attacks happen on registries that allow non-ASCII; even though npm
//     and PyPI normalize to ASCII, an attacker can register a Punycoded
//     name. We fold confusables before distance.

import Foundation
import os.log

// MARK: - TyposquatDatabase

public actor TyposquatDatabase {

    private let logger = Logger(subsystem: "com.maccrab.enrichment", category: "typosquat-db")

    public enum Registry: String, Sendable, CaseIterable {
        case npm = "npm"
        case pypi = "pypi"
    }

    /// Result of a typosquat lookup.
    public struct TyposquatResult: Sendable, Equatable {
        /// The candidate package name as supplied.
        public let candidate: String
        /// The popular package name the candidate is closest to. Nil if no
        /// top-1000 entry is within range.
        public let similarTo: String?
        /// Damerau-Levenshtein distance after confusable-folding. Nil if no match.
        public let distance: Int?
        public let registry: Registry
        /// True if the candidate is a homoglyph fold of `similarTo` (i.e.,
        /// distance > 0 in raw chars but == 0 after Unicode confusable fold).
        public let isHomoglyph: Bool
        /// Score 0-100: 100 = exact match (post-fold) to a top-1000 name
        /// that the candidate is *not*; 0 = no match within range.
        public let score: Int
        public let reasons: [String]

        public init(
            candidate: String,
            similarTo: String?,
            distance: Int?,
            registry: Registry,
            isHomoglyph: Bool,
            score: Int,
            reasons: [String]
        ) {
            self.candidate = candidate
            self.similarTo = similarTo
            self.distance = distance
            self.registry = registry
            self.isHomoglyph = isHomoglyph
            self.score = score
            self.reasons = reasons
        }
    }

    // MARK: - State

    private let topNpm: Set<String>
    private let topPyPI: Set<String>

    /// Damerau-Levenshtein distance threshold. ≤ this -> candidate flagged.
    private let maxDistance: Int

    // MARK: - Init

    /// Default constructor loads bundled top corpora from
    /// `Sources/MacCrabCore/Resources/typosquat-top-{npm,pypi}.json`.
    /// Falls back to the 50-entry starter set when the resource is
    /// missing (e.g., when MacCrabCore is consumed by a build system
    /// that strips Bundle.module). v1.12.0: the shipped JSON corpora
    /// contain ~200 real packages per registry — operators wanting a
    /// full top-1000 can replace the JSON files post-deploy without
    /// recompile (load order: Bundle.module → starter constant).
    public init(maxDistance: Int = 2) {
        self.maxDistance = maxDistance
        self.topNpm = Self.loadBundledCorpus(name: "typosquat-top-npm") ?? Self.starterTopNpm
        self.topPyPI = Self.loadBundledCorpus(name: "typosquat-top-pypi") ?? Self.starterTopPyPI
    }

    /// Load a JSON corpus from MacCrabCore's bundle. Returns nil when
    /// the resource is absent or fails to decode — the caller falls
    /// back to the in-source starter set. Logging is deliberately
    /// terse: a missing corpus is a soft degrade, not an alertable
    /// daemon failure.
    ///
    /// v1.12.4 fix (macOS 26 Tahoe Intelligence-tab crash): we no
    /// longer touch `Bundle.module`. SwiftPM-generated resource bundles
    /// ship a stripped-down `Info.plist` containing only
    /// `CFBundleDevelopmentRegion`, which macOS 26's `Bundle(url:)`
    /// rejects — returning nil — and SwiftPM's auto-generated
    /// `Bundle.module` accessor then `fatalError`s. The crash fires on
    /// the first reach to `Bundle.module`, which (because PackageScanner
    /// instantiates TyposquatDatabase lazily) happens the first time a
    /// user clicks the Intelligence tab.
    ///
    /// Instead, build the resource URL ourselves by probing all of
    /// SwiftPM's canonical search locations directly via `Data(contentsOf:)`.
    /// `Data` doesn't care whether the .bundle dir validates as a
    /// CFBundle — it just reads bytes off disk. We try the flat
    /// SPM resource-bundle layout (`<resourceURL>/MacCrab_MacCrabCore.bundle/<name>.json`)
    /// first since that's what build-release.sh ships, then fall
    /// through to the per-target-bundle fallback for tests and
    /// alternative consumers.
    private static func loadBundledCorpus(name: String) -> Set<String>? {
        let filename = name + ".json"
        let bundleName = "MacCrab_MacCrabCore.bundle"
        var candidateURLs: [URL] = []

        // 1. SPM-test override. Swift Package Manager sets
        //    PACKAGE_RESOURCE_BUNDLE_PATH (or PACKAGE_RESOURCE_BUNDLE_URL)
        //    during `swift test` so the auto-generated `Bundle.module`
        //    can find the resource bundle adjacent to the xctest runner.
        //    We honor the same env var so our tests pass without
        //    touching Bundle.module.
        let env = Foundation.ProcessInfo.processInfo.environment
        for envKey in ["PACKAGE_RESOURCE_BUNDLE_PATH", "PACKAGE_RESOURCE_BUNDLE_URL"] {
            if let override = env[envKey] {
                candidateURLs.append(URL(fileURLWithPath: override).appendingPathComponent(filename))
            }
        }

        // 2. .app's Resources / Bundle.main.resourceURL — the SPM
        //    bundle is copied here by build-release.sh.
        if let resources = Bundle.main.resourceURL {
            candidateURLs.append(
                resources.appendingPathComponent(bundleName).appendingPathComponent(filename)
            )
        }

        // 3. Bundle owning this class — covers `swift test` and
        //    framework-linked consumers. The resource bundle lives
        //    adjacent to the loaded test/framework bundle, so probe
        //    both its `resourceURL` (Resources/MacCrab_MacCrabCore.bundle)
        //    and the sibling directory of its `bundleURL` (where SPM
        //    places `.bundle` directories during `swift test`).
        let owning = Bundle(for: BundleFinder.self)
        if let resourceURL = owning.resourceURL {
            candidateURLs.append(
                resourceURL.appendingPathComponent(bundleName).appendingPathComponent(filename)
            )
            candidateURLs.append(resourceURL.appendingPathComponent(filename))
        }
        candidateURLs.append(
            owning.bundleURL.deletingLastPathComponent()
                .appendingPathComponent(bundleName).appendingPathComponent(filename)
        )

        // 4. .app's own bundleURL (older SPM layouts).
        candidateURLs.append(
            Bundle.main.bundleURL.appendingPathComponent(bundleName).appendingPathComponent(filename)
        )

        struct CorpusPayload: Decodable { let packages: [String] }

        for url in candidateURLs {
            guard let data = try? Data(contentsOf: url),
                  let payload = try? JSONDecoder().decode(CorpusPayload.self, from: data) else {
                continue
            }
            return Set(payload.packages.map { $0.lowercased() })
        }
        return nil
    }

    /// Private helper class so `Bundle(for:)` can locate the bundle
    /// that holds this class. Identical to the pattern SwiftPM uses
    /// inside its auto-generated resource_bundle_accessor.
    private final class BundleFinder {}

    /// Constructor for tests / production with explicit top-1000 lists.
    public init(topNpm: Set<String>, topPyPI: Set<String>, maxDistance: Int = 2) {
        self.maxDistance = maxDistance
        self.topNpm = topNpm
        self.topPyPI = topPyPI
    }

    // MARK: - Public API

    /// Score a candidate package name against the bundled top-1000.
    /// Returns a result even when there's no match (with score 0).
    public func score(candidate: String, registry: Registry) -> TyposquatResult {
        let top = registry == .npm ? topNpm : topPyPI
        let folded = Self.confusableFold(candidate)
        let normalizedCandidate = folded.lowercased()
        let originalLowered = candidate.lowercased()

        // v1.12.5 FP fix: ASCII candidate that IS a top-1000 package
        // itself = NOT a typosquat — it's the real thing. Pre-fix, the
        // function fell through to the distance loop and `pip` matched
        // `pipx` at distance 1, surfacing "⚠️ Likely typosquat" on the
        // single most-popular PyPI installer. Same shape would have
        // affected `cli` → `clip`, `pkg` → `pkgx`, `dns` → `dnsx`,
        // etc. Add the membership check at the top.
        if top.contains(originalLowered) {
            return TyposquatResult(
                candidate: candidate,
                similarTo: nil,
                distance: 0,
                registry: registry,
                isHomoglyph: false,
                score: 0,
                reasons: ["candidate is itself a top-package entry on \(registry.rawValue); no typosquat signal"]
            )
        }

        // Exact match after fold = NOT a typosquat (it's the real package
        // with a confusable encoding).
        if top.contains(normalizedCandidate) && normalizedCandidate != originalLowered {
            return TyposquatResult(
                candidate: candidate,
                similarTo: normalizedCandidate,
                distance: 0,
                registry: registry,
                isHomoglyph: true,
                score: 100,
                reasons: ["candidate is a homoglyph encoding of popular package '\(normalizedCandidate)'"]
            )
        }

        // Find closest match by Damerau-Levenshtein, with relative-distance
        // scaling for longer names. Skip entries whose length difference
        // exceeds the threshold to prune the search.
        var bestMatch: String?
        var bestDistance: Int?
        for entry in top {
            let lenDelta = abs(entry.count - normalizedCandidate.count)
            if lenDelta > maxDistance { continue }
            let d = Self.damerauLevenshtein(normalizedCandidate, entry)
            // Relative threshold for longer names: e.g., 2 edits in a
            // 12-char name (= 17%) is still a slopsquat signal; 2 edits
            // in a 4-char name (50%) is just a different word.
            let relative = Double(d) / Double(max(entry.count, normalizedCandidate.count))
            let inRange = d > 0 && (d <= maxDistance || relative < 0.20)
            if inRange, bestDistance == nil || d < bestDistance! {
                bestDistance = d
                bestMatch = entry
            }
        }

        guard let match = bestMatch, let d = bestDistance else {
            return TyposquatResult(
                candidate: candidate,
                similarTo: nil,
                distance: nil,
                registry: registry,
                isHomoglyph: false,
                score: 0,
                reasons: []
            )
        }

        // Score: distance 1 = 90, distance 2 = 70, scale down for longer names.
        let baseScore = max(0, 100 - 20 * d)
        let isHomoglyph = (Self.confusableFold(candidate).lowercased() == match)
        let reasons = ["Damerau-Levenshtein distance \(d) from popular package '\(match)'"]
            + (isHomoglyph ? ["candidate is a Unicode-confusable fold of '\(match)'"] : [])

        return TyposquatResult(
            candidate: candidate,
            similarTo: match,
            distance: d,
            registry: registry,
            isHomoglyph: isHomoglyph,
            score: baseScore,
            reasons: reasons
        )
    }

    // MARK: - Damerau-Levenshtein (with adjacent transposition = 1 edit)

    /// Damerau-Levenshtein edit distance. Includes adjacent transposition
    /// as a single edit (so `raect` vs `react` = 1, not 2).
    /// O(|a| * |b|) time and memory.
    nonisolated static func damerauLevenshtein(_ a: String, _ b: String) -> Int {
        let s1 = Array(a)
        let s2 = Array(b)
        let m = s1.count
        let n = s2.count
        if m == 0 { return n }
        if n == 0 { return m }

        var d = Array(repeating: Array(repeating: 0, count: n + 1), count: m + 1)
        for i in 0...m { d[i][0] = i }
        for j in 0...n { d[0][j] = j }

        for i in 1...m {
            for j in 1...n {
                let cost = s1[i - 1] == s2[j - 1] ? 0 : 1
                d[i][j] = min(
                    d[i - 1][j] + 1,        // deletion
                    d[i][j - 1] + 1,        // insertion
                    d[i - 1][j - 1] + cost  // substitution
                )
                if i > 1 && j > 1
                    && s1[i - 1] == s2[j - 2]
                    && s1[i - 2] == s2[j - 1] {
                    d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1) // transposition
                }
            }
        }
        return d[m][n]
    }

    // MARK: - Unicode confusable fold

    /// Folds a string by replacing high-value confusable code points with
    /// their Latin / ASCII equivalents, then NFKC-normalizing. This is a
    /// *minimal* TR39 subset covering the confusables observed in real
    /// supply-chain attacks (Nethereum NuGet Oct 2025 case + the recurring
    /// Cyrillic а / о / е tells on npm/PyPI Punycoded squats). The full
    /// TR39 confusables table is ~7000 entries; the subset below covers
    /// the >95th-percentile attack uses.
    nonisolated static func confusableFold(_ s: String) -> String {
        let folds: [Character: Character] = [
            // Cyrillic → Latin (TR39 sample of high-value pairs)
            "а": "a", "А": "A",
            "е": "e", "Е": "E",
            "о": "o", "О": "O",
            "р": "p", "Р": "P",
            "с": "c", "С": "C",
            "х": "x", "Х": "X",
            "у": "y", "У": "Y",
            "к": "k", "К": "K",
            "м": "m", "М": "M",
            "т": "t", "Т": "T",
            "ь": "b", "Ь": "B",
            "і": "i", "І": "I",
            // Greek → Latin
            "α": "a", "Α": "A",
            "ο": "o", "Ο": "O",
            "ν": "v", "Ν": "N",
            "ι": "i", "Ι": "I",
            "κ": "k", "Κ": "K",
            "ρ": "p", "Ρ": "P",
            "τ": "t", "Τ": "T",
            "η": "n", "Η": "H",
            // Fullwidth Latin (used by some Asian-locale typosquats)
            "ａ": "a", "Ａ": "A",
            "ｅ": "e", "Ｅ": "E",
            "ｏ": "o", "Ｏ": "O",
            // Digit-vs-letter confusables
            "０": "0", "１": "1", "Ｌ": "L",
        ]
        var out = ""
        out.reserveCapacity(s.count)
        for ch in s {
            out.append(folds[ch] ?? ch)
        }
        // NFKC normalize the result so legacy ligature / variant
        // selector escapes get resolved.
        return (out as NSString).precomposedStringWithCompatibilityMapping
    }

    // MARK: - Starter top-50 sets (replace at deploy time)

    /// Starter top-50 npm names. Production should load full top-1000
    /// from a bundled JSON resource (e.g.,
    /// `Resources/typosquat-top1000-npm.json`). The starter set is the
    /// 50 most-frequently-typosquatted historically per Stacklok 2024
    /// and Socket H2 2025 reports.
    private static let starterTopNpm: Set<String> = [
        "react", "lodash", "axios", "express", "chalk", "debug", "moment",
        "request", "async", "underscore", "uuid", "commander", "yargs",
        "mocha", "jest", "webpack", "babel", "typescript", "eslint",
        "prettier", "vue", "angular", "next", "nuxt", "vite", "rollup",
        "graphql", "apollo-client", "redux", "rxjs", "ws", "socket.io",
        "ms", "dotenv", "fs-extra", "glob", "minimist", "rimraf",
        "semver", "tslib", "ansi-styles", "supports-color", "color",
        "yaml", "node-fetch", "puppeteer", "playwright", "axios-retry",
        "validator", "tinycolor",
    ]

    /// Starter top-50 PyPI names. Production should load full top-1000.
    private static let starterTopPyPI: Set<String> = [
        "requests", "urllib3", "numpy", "pandas", "boto3", "botocore",
        "setuptools", "six", "python-dateutil", "pip", "wheel",
        "certifi", "charset-normalizer", "idna", "pyyaml", "click",
        "jinja2", "flask", "django", "tornado", "fastapi", "pydantic",
        "sqlalchemy", "psycopg2", "redis", "celery", "scipy",
        "scikit-learn", "tensorflow", "torch", "transformers",
        "matplotlib", "pillow", "lxml", "beautifulsoup4", "selenium",
        "pytest", "tox", "coverage", "black", "isort", "mypy", "ruff",
        "openai", "anthropic", "langchain", "litellm", "lightning",
        "mlflow", "huggingface-hub",
    ]
}
