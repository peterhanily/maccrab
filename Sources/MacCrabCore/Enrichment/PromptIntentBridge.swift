// PromptIntentBridge.swift
// MacCrabCore
//
// Correlates an AI agent's behavior (from AgentLineageService) with
// the user's recent intent context, surfacing high-signal anomalies
// that are invisible to behavior-only detection:
//
//   - Autonomous install: package was installed without appearing in
//     any file the agent read in the prior window
//   - Slopsquat shape: installed name has typo-distance ≤ 2 from a
//     name in the agent's recent file reads
//   - Vague-prompt → destructive-action magnitude asymmetry: agent
//     made few LLM calls relative to the destructive blast radius
//   - Injection-context: recently-read files contain known prompt-
//     injection markers AND the agent spawned a destructive action
//
// What this is NOT: we don't read the user's raw prompts. AgentEvent's
// llmCall variant carries provider/endpoint/byteCounts, not text — that
// matches Anthropic's published privacy posture (Claude Code Enterprise
// telemetry deliberately omits prompt body from OTLP exports). Instead
// we infer intent context from what the agent *read* (the user's
// CLAUDE.md, the project's README, the files in the working directory)
// — proxies that don't require new privacy surface.

import Foundation
import Darwin
import os.log

// MARK: - PromptIntentBridge

public actor PromptIntentBridge {

    private let logger = Logger(subsystem: "com.maccrab.enrichment", category: "prompt-intent-bridge")

    // MARK: - Types

    public enum PromptIntentLabel: String, Sendable, CaseIterable {
        case userInitiated         // a recently-read file references the package by name
        case autonomous            // no recently-read file mentions it
        case slopsquat             // recently-read file mentions a SIMILAR-but-different name
        case vagueDestructive      // small prompt-context vs large destructive action
        case injectionContext      // recently-read files contain injection markers
        case unknown
    }

    public struct PromptIntentResult: Sendable {
        public let aiPid: Int32
        public let packageName: String
        public let label: PromptIntentLabel
        public let confidence: Double
        public let nearestMentionedName: String?
        public let nearestMentionDistance: Int?
        public let injectionMarkersFound: [String]
        public let reasons: [String]

        public init(
            aiPid: Int32, packageName: String, label: PromptIntentLabel,
            confidence: Double, nearestMentionedName: String?,
            nearestMentionDistance: Int?, injectionMarkersFound: [String], reasons: [String]
        ) {
            self.aiPid = aiPid
            self.packageName = packageName
            self.label = label
            self.confidence = confidence
            self.nearestMentionedName = nearestMentionedName
            self.nearestMentionDistance = nearestMentionDistance
            self.injectionMarkersFound = injectionMarkersFound
            self.reasons = reasons
        }
    }

    /// Injectable snapshot reader so tests don't need a live
    /// AgentLineageService.
    public typealias SnapshotProvider = @Sendable (Int32) async -> AgentSessionSnapshot?

    /// Optional reader for the text content of a file the agent recently
    /// read. Default reader uses FileManager. Tests can inject.
    public typealias FileReader = @Sendable (String) async -> String?

    // MARK: - State

    private let snapshotProvider: SnapshotProvider
    private let fileReader: FileReader
    /// Max bytes to inspect from each candidate context file.
    private let maxFileBytes: Int

    // v1.12.0 RC3 fix (Perf-H3): cache file-read results across
    // analyzeInstall calls. Context files (CLAUDE.md, README,
    // project dotfiles) get re-read every install — three back-to-
    // back `npm install foo bar baz` calls cause 96 redundant
    // file reads. The cache is small (cap 128 × 64KB = 8MB
    // ceiling) and keyed by path; mutation is detected by the
    // PromptIntentBridge's natural 300s window — if a file changed
    // mid-window, the next analyzeInstall outside the window builds
    // a fresh snapshot anyway. TTL kept short (60s) so stale data
    // doesn't leak across long-lived sessions.
    // v1.12.0 RC4 fix (Sec-R4-N1): cache key includes (mtime_ns,
    // size) so an adversary who controls a context file cannot
    // poison the cache by writing benign content (caching it),
    // then replacing with attack content within the 60s TTL — the
    // next read will see different mtime/size and miss the cache.
    private struct CacheEntry {
        let mtimeNs: Int64
        let size: Int64
        let text: String
        let cachedAt: Date
    }
    private var readCache: [String: CacheEntry] = [:]
    private var readCacheOrder: [String] = []
    private let readCacheCap: Int = 128
    private let readCacheTTL: TimeInterval = 60

    // MARK: - Init

    public init(
        snapshotProvider: @escaping SnapshotProvider,
        fileReader: FileReader? = nil,
        maxFileBytes: Int = 64 * 1024
    ) {
        self.snapshotProvider = snapshotProvider
        self.fileReader = fileReader ?? Self.defaultFileReader
        self.maxFileBytes = maxFileBytes
    }

    /// Default file reader. Uses SecureFileIO (O_NOFOLLOW) and
    /// restricts reads to `/Users/` by default so a compromised
    /// agent's fileRead-event stream can't be replayed to make us
    /// scan `/etc/` or `/private/`. Override the reader closure in
    /// tests.
    ///
    /// v1.12.0 RC4 fix (Sec-R4-N6): pre-fix the scope was
    /// `NSHomeDirectory()` which under the System Extension resolves
    /// to `/var/root` (the root daemon's home), causing
    /// `SecureFileIO.readBytes` to reject every `/Users/<u>/...`
    /// path the AI agent had read — the bridge's corpus was always
    /// empty in production and the slopsquat/autonomous detection
    /// silently never fired. We scope to `/Users/` (any real user's
    /// home) since the lineage paths we want to read are
    /// per-user dotfiles + CLAUDE.md / README context.
    private static let defaultFileReader: FileReader = { path in
        guard let data = try? SecureFileIO.readBytes(at: path, maxBytes: 64 * 1024, scope: "/Users/") else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

    // MARK: - Public API

    /// Analyze whether the install of `packageName` by `aiPid` looks
    /// user-initiated, autonomous, slopsquat, etc. Looks at AgentLineage
    /// events from `windowSeconds` before the call (default 300s).
    public func analyzeInstall(
        aiPid: Int32, packageName: String, destructiveBlastRadius: Int = 0,
        windowSeconds: TimeInterval = 300
    ) async -> PromptIntentResult {
        guard let snapshot = await snapshotProvider(aiPid) else {
            return PromptIntentResult(
                aiPid: aiPid, packageName: packageName,
                label: .unknown, confidence: 0.0,
                nearestMentionedName: nil, nearestMentionDistance: nil,
                injectionMarkersFound: [],
                reasons: ["no agent-lineage snapshot for pid \(aiPid)"]
            )
        }

        let cutoff = Date().addingTimeInterval(-windowSeconds)
        let recentReads = snapshot.events.compactMap { event -> String? in
            guard event.timestamp >= cutoff else { return nil }
            if case .fileRead(let path) = event.kind { return path }
            return nil
        }
        let llmCallCount = snapshot.events.filter { event in
            guard event.timestamp >= cutoff else { return false }
            if case .llmCall = event.kind { return true }
            return false
        }.count

        // Gather context text (read up to 32 files of context).
        // v1.12.0 RC3 (Perf-H3): consult the in-bridge cache before
        // re-reading. Most analyzeInstall calls hit overlapping
        // context paths (CLAUDE.md, README, project dotfiles).
        let candidatePaths = Array(recentReads.prefix(32))
        var contextCorpus: [(path: String, text: String)] = []
        for path in candidatePaths {
            // v1.12.0 RC4 (Sec-R4-N1): stat the file first so the
            // (mtime_ns, size) tuple validates any cached entry.
            // If the underlying file changed between cache-write and
            // now, treat as a miss — the attacker's mid-window swap
            // pattern doesn't survive.
            var st = stat()
            let statResult = path.withCString { lstat($0, &st) }
            let mtimeNs: Int64
            let fileSize: Int64
            if statResult == 0 {
                mtimeNs = Int64(st.st_mtimespec.tv_sec) * 1_000_000_000 + Int64(st.st_mtimespec.tv_nsec)
                fileSize = Int64(st.st_size)
            } else {
                // Couldn't stat — skip caching; do the read but don't trust it.
                mtimeNs = 0
                fileSize = -1
            }
            // Cache hit: (path, mtimeNs, size) all match AND within TTL.
            if let entry = readCache[path],
               entry.mtimeNs == mtimeNs,
               entry.size == fileSize,
               Date().timeIntervalSince(entry.cachedAt) < readCacheTTL {
                if !entry.text.isEmpty {
                    contextCorpus.append((path: path, text: entry.text))
                }
                continue
            }
            // Cache miss or expired: re-read.
            if let text = await fileReader(path), !text.isEmpty {
                contextCorpus.append((path: path, text: text))
                // FIFO eviction at cap.
                if readCache.count >= readCacheCap, let oldest = readCacheOrder.first {
                    readCache.removeValue(forKey: oldest)
                    readCacheOrder.removeFirst()
                }
                // v1.12.0 RC5 fix (Perf-R5-N3): pre-fix `readCacheOrder`
                // would accumulate duplicate entries when the same
                // path was re-read after a cache miss (TTL expiry or
                // mtime/size change), because `append(path)` ran even
                // when `path` was still in the dict + ring. Over a
                // long-lived session this caused FIFO eviction to pop
                // stale entries that `removeValue` couldn't find, and
                // the order array grew unboundedly. Remove any prior
                // index of `path` before appending the fresh one.
                if let existingIdx = readCacheOrder.firstIndex(of: path) {
                    readCacheOrder.remove(at: existingIdx)
                }
                readCache[path] = CacheEntry(mtimeNs: mtimeNs, size: fileSize, text: text, cachedAt: Date())
                readCacheOrder.append(path)
            }
        }

        // 1) Direct package-name mention.
        let directMention = contextCorpus.first { entry in
            entry.text.contains(packageName)
        }

        // 2) Slopsquat / typosquat candidates from context.
        let extractedNames = Self.extractPackageNames(from: contextCorpus.map { $0.text })
        var bestSimilar: (name: String, distance: Int)?
        for candidate in extractedNames where candidate != packageName {
            let distance = Self.damerauLevenshtein(candidate, packageName)
            if distance == 0 { continue }
            if distance <= 2, bestSimilar == nil || distance < bestSimilar!.distance {
                bestSimilar = (candidate, distance)
            }
        }

        // 3) Injection markers in context.
        let injectionMarkers = Self.findInjectionMarkers(in: contextCorpus.map { $0.text })

        // Decision tree.
        if !injectionMarkers.isEmpty && destructiveBlastRadius > 0 {
            return PromptIntentResult(
                aiPid: aiPid, packageName: packageName,
                label: .injectionContext, confidence: 0.85,
                nearestMentionedName: bestSimilar?.name,
                nearestMentionDistance: bestSimilar?.distance,
                injectionMarkersFound: injectionMarkers,
                reasons: [
                    "context corpus contains injection markers (\(injectionMarkers.joined(separator: ", ")))",
                    "destructive action with blast radius \(destructiveBlastRadius)",
                ]
            )
        }

        if directMention != nil {
            return PromptIntentResult(
                aiPid: aiPid, packageName: packageName,
                label: .userInitiated, confidence: 0.9,
                nearestMentionedName: packageName,
                nearestMentionDistance: 0,
                injectionMarkersFound: injectionMarkers,
                reasons: ["package name '\(packageName)' explicitly mentioned in agent-read context"]
            )
        }

        if let near = bestSimilar {
            return PromptIntentResult(
                aiPid: aiPid, packageName: packageName,
                label: .slopsquat, confidence: 0.8,
                nearestMentionedName: near.name,
                nearestMentionDistance: near.distance,
                injectionMarkersFound: injectionMarkers,
                reasons: [
                    "agent context mentions '\(near.name)' (Damerau-Levenshtein distance \(near.distance) from installed '\(packageName)')",
                    "package name was not explicitly mentioned by the user",
                ]
            )
        }

        // No mention. Check magnitude asymmetry.
        if destructiveBlastRadius >= 3 && llmCallCount <= 2 {
            return PromptIntentResult(
                aiPid: aiPid, packageName: packageName,
                label: .vagueDestructive, confidence: 0.7,
                nearestMentionedName: nil,
                nearestMentionDistance: nil,
                injectionMarkersFound: injectionMarkers,
                reasons: [
                    "only \(llmCallCount) LLM call(s) preceded a destructive install (blast radius \(destructiveBlastRadius))",
                    "no recently-read context mentions the package",
                ]
            )
        }

        // No mention, no asymmetry → autonomous install.
        return PromptIntentResult(
            aiPid: aiPid, packageName: packageName,
            label: .autonomous, confidence: 0.75,
            nearestMentionedName: nil,
            nearestMentionDistance: nil,
            injectionMarkersFound: injectionMarkers,
            reasons: [
                "no recently-read context mentions the package",
                "agent chose to install '\(packageName)' without explicit operator reference",
            ]
        )
    }

    // MARK: - Helpers

    /// Compile the package-name regex exactly once at first use —
    /// PERF audit caught this being recompiled per analyzeInstall()
    /// call. NSRegularExpression compile is ~1ms each; on a hot path
    /// over many install events that adds up.
    nonisolated static let packageNameRegex: NSRegularExpression? = {
        try? NSRegularExpression(
            pattern: "@?[a-z0-9][a-z0-9._-]{1,80}(?:/[a-z0-9._-]{1,80})?",
            options: [.caseInsensitive]
        )
    }()

    /// Extract identifier-like tokens that look like package names
    /// (lowercase, digits, hyphens, underscores, @scope/name).
    nonisolated static func extractPackageNames(from texts: [String]) -> Set<String> {
        var set: Set<String> = []
        guard let regex = packageNameRegex else { return set }
        for text in texts {
            let ns = text as NSString
            let matches = regex.matches(in: text, range: NSRange(location: 0, length: ns.length))
            for match in matches.prefix(500) {
                let token = ns.substring(with: match.range).lowercased()
                // Heuristic filter — skip very short tokens, file extensions,
                // and dotted segments without a hyphen.
                if token.count < 3 { continue }
                if token.hasPrefix(".") { continue }
                if token.allSatisfy({ $0.isLetter }) && token.count < 4 { continue }
                set.insert(token)
                if set.count > 2000 { return set }
            }
        }
        return set
    }

    /// Injection markers per Forensicate.ai (87+ rule corpus) and
    /// Anthropic's published examples. Subset; the production scanner
    /// is PromptInjectionScanner.
    nonisolated static func findInjectionMarkers(in texts: [String]) -> [String] {
        let markers = [
            "ignore previous instructions",
            "ignore all prior",
            "disregard previous",
            "you are now",
            "act as ",
            "system:",
            "<|im_start|>",
            "ignore your guidelines",
            "you must",
            "[INST]",
            "###new instructions",
            "always install",
        ]
        var found: [String] = []
        for text in texts {
            let lower = text.lowercased()
            for marker in markers where lower.contains(marker) {
                if !found.contains(marker) { found.append(marker) }
            }
        }
        return found
    }

    /// Damerau-Levenshtein distance (transposition cost 1).
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
                d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
                if i > 1 && j > 1 && s1[i - 1] == s2[j - 2] && s1[i - 2] == s2[j - 1] {
                    d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
                }
            }
        }
        return d[m][n]
    }
}
