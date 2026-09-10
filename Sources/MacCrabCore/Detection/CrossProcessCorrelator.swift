// CrossProcessCorrelator.swift
// MacCrabCore
//
// Connects events from distinct PID values through shared artifacts: files,
// network destinations, and domains. When one PID downloads a file, another
// executes it, and a third reaches out to a C2 server, the shared artifacts
// are useful evidence for one attack chain. This API receives neither stable
// process-start identity nor ancestry, so it does not claim the PIDs belong to
// unrelated process trees.

import Foundation
import os.log

/// Correlates events across process boundaries using shared artifacts.
///
/// Links distinct PID values that touch the same file, network destination,
/// or domain within a sliding time window. A distinct PID is cross-process
/// evidence, but is not proof of distinct process lifetimes or ancestry.
///
/// **Typical chain:** curl writes `/tmp/payload` → bash executes `/tmp/payload`
/// → payload connects to 198.51.100.7:443. Three PID values, one candidate
/// attack chain.
public actor CrossProcessCorrelator {

    private let logger = Logger(subsystem: "com.maccrab", category: "cross-process")

    // MARK: - Types

    /// The kind of artifact that links events together.
    private enum ArtifactType: Hashable, Sendable {
        case filePath(String)
        case networkDestination(String)   // "ip:port"
        case domainDestination(String)
    }

    /// A single event in a cross-process correlation chain.
    public struct ChainEvent: Sendable {
        public let timestamp: Date
        public let pid: Int32
        public let processName: String
        public let processPath: String
        public let action: String   // "download", "write", "execute", "connect", "read"

        public init(
            timestamp: Date,
            pid: Int32,
            processName: String,
            processPath: String,
            action: String
        ) {
            self.timestamp = timestamp
            self.pid = pid
            self.processName = processName
            self.processPath = processPath
            self.action = action
        }
    }

    /// A completed correlation chain spanning multiple PID values.
    public struct CorrelationChain: Sendable {
        public let id: String
        public let events: [ChainEvent]
        public let sharedArtifact: String
        public let artifactType: String   // "file", "network", "domain"
        public let timeSpanSeconds: Double
        /// Number of distinct PID values in `events`. This does not establish
        /// stable process lifetime or lineage identity.
        public let distinctPIDCount: Int

        /// Compatibility spelling retained for existing consumers. New copy
        /// should use `distinctPIDCount` and say "distinct PIDs", not infer
        /// unrelated processes or process trees.
        @available(*, deprecated, renamed: "distinctPIDCount")
        public var processCount: Int { distinctPIDCount }
        public let severity: Severity
        public let description: String
    }

    /// Fixed-cardinality capacity accounting for one artifact map. The two
    /// conservation equations make silent loss or accidental unbounded state
    /// visible without exposing any paths, hosts, or process data.
    public struct ArtifactMapTelemetry: Sendable, Equatable {
        public let acceptedEvents: UInt64
        public let uniqueArtifactInsertions: UInt64
        public let trackedArtifacts: Int
        public let recencyIndexEntries: Int
        public let peakTrackedArtifacts: Int
        public let retainedEvents: Int
        public let staleArtifactsRemoved: UInt64
        public let capacityArtifactsEvicted: UInt64
        public let evictionSelectionOperations: UInt64
        public let staleEventsRemoved: UInt64
        public let capacityEventsEvicted: UInt64
        public let perArtifactEventsEvicted: UInt64

        public var artifactConservationMaintained: Bool {
            uniqueArtifactInsertions == UInt64(trackedArtifacts)
                &+ staleArtifactsRemoved
                &+ capacityArtifactsEvicted
        }

        public var eventConservationMaintained: Bool {
            acceptedEvents == UInt64(retainedEvents)
                &+ staleEventsRemoved
                &+ capacityEventsEvicted
                &+ perArtifactEventsEvicted
        }

        public var indexConservationMaintained: Bool {
            recencyIndexEntries == trackedArtifacts
        }

        /// One indexed selection per capacity eviction. A value of `false`
        /// would mean the constant-work eviction contract has drifted.
        public var constantWorkEvictionMaintained: Bool {
            evictionSelectionOperations == capacityArtifactsEvicted
        }
    }

    /// Capacity state for all three artifact maps. Counters are fixed in
    /// cardinality; artifact values never become metric labels.
    public struct Telemetry: Sendable, Equatable {
        public let maximumArtifactsPerMap: Int
        public let maximumEventsPerArtifact: Int
        public let filePIDIndexEntries: Int
        public let file: ArtifactMapTelemetry
        public let network: ArtifactMapTelemetry
        public let domain: ArtifactMapTelemetry

        public var conservationMaintained: Bool {
            [file, network, domain].allSatisfy {
                $0.artifactConservationMaintained
                    && $0.eventConservationMaintained
                    && $0.indexConservationMaintained
                    && $0.constantWorkEvictionMaintained
            }
                && filePIDIndexEntries == file.trackedArtifacts
        }

        public var capacityMaintained: Bool {
            [file, network, domain].allSatisfy {
                $0.trackedArtifacts <= maximumArtifactsPerMap
                    && $0.peakTrackedArtifacts <= maximumArtifactsPerMap
            }
        }
    }

    /// Intrusive dictionary-backed LRU. Unlike a lazy heap, this index has
    /// exactly one node per retained artifact, so repeated touches cannot grow
    /// auxiliary state. Selection and removal are deterministic O(1).
    private struct ArtifactRecencyIndex {
        private struct Node {
            var previous: String?
            var next: String?
        }

        private var nodes: [String: Node] = [:]
        private var oldest: String?
        private var newest: String?

        var count: Int { nodes.count }

        mutating func touch(_ key: String) {
            if let node = nodes[key] {
                guard newest != key else { return }
                if let previous = node.previous {
                    nodes[previous]?.next = node.next
                } else {
                    oldest = node.next
                }
                if let next = node.next {
                    nodes[next]?.previous = node.previous
                }
            } else if oldest == nil {
                oldest = key
            }

            let previousNewest = newest
            nodes[key] = Node(previous: previousNewest, next: nil)
            if let previousNewest {
                nodes[previousNewest]?.next = key
            }
            newest = key
        }

        @discardableResult
        mutating func remove(_ key: String) -> Bool {
            guard let node = nodes.removeValue(forKey: key) else { return false }
            if let previous = node.previous {
                nodes[previous]?.next = node.next
            } else {
                oldest = node.next
            }
            if let next = node.next {
                nodes[next]?.previous = node.previous
            } else {
                newest = node.previous
            }
            return true
        }

        mutating func removeOldest() -> String? {
            guard let key = oldest else { return nil }
            precondition(remove(key), "oldest artifact must exist in recency index")
            return key
        }
    }

    private struct ArtifactAppendOutcome {
        let capacityEvictedKey: String?
        let trimmedEvents: Bool
    }

    /// Bounded storage and exact lifetime accounting for one artifact class.
    private struct ArtifactStore {
        var eventsByKey: [String: [ChainEvent]] = [:]
        private var recency = ArtifactRecencyIndex()
        private var acceptedEvents: UInt64 = 0
        private var uniqueArtifactInsertions: UInt64 = 0
        private var peakTrackedArtifacts: Int = 0
        private var staleArtifactsRemoved: UInt64 = 0
        private var capacityArtifactsEvicted: UInt64 = 0
        private var evictionSelectionOperations: UInt64 = 0
        private var staleEventsRemoved: UInt64 = 0
        private var capacityEventsEvicted: UInt64 = 0
        private var perArtifactEventsEvicted: UInt64 = 0

        mutating func append(
            key: String,
            event: ChainEvent,
            maximumArtifacts: Int,
            maximumEventsPerArtifact: Int
        ) -> ArtifactAppendOutcome {
            var capacityEvictedKey: String?
            if eventsByKey[key] == nil {
                uniqueArtifactInsertions &+= 1
                if eventsByKey.count >= maximumArtifacts {
                    evictionSelectionOperations &+= 1
                    guard let victim = recency.removeOldest(),
                          let evictedEvents = eventsByKey.removeValue(forKey: victim) else {
                        preconditionFailure("artifact map and recency index diverged")
                    }
                    capacityArtifactsEvicted &+= 1
                    capacityEventsEvicted &+= UInt64(evictedEvents.count)
                    capacityEvictedKey = victim
                }
            }

            acceptedEvents &+= 1
            eventsByKey[key, default: []].append(event)

            var trimmedEvents = false
            if var events = eventsByKey[key], events.count > maximumEventsPerArtifact {
                // At most one event is over the cap after one append. Remove
                // the oldest timestamp; equal timestamps retain arrival order.
                var oldestIndex = events.startIndex
                for index in events.indices.dropFirst()
                    where events[index].timestamp < events[oldestIndex].timestamp {
                    oldestIndex = index
                }
                events.remove(at: oldestIndex)
                eventsByKey[key] = events
                perArtifactEventsEvicted &+= 1
                trimmedEvents = true
            }

            recency.touch(key)
            peakTrackedArtifacts = max(peakTrackedArtifacts, eventsByKey.count)
            return ArtifactAppendOutcome(
                capacityEvictedKey: capacityEvictedKey,
                trimmedEvents: trimmedEvents
            )
        }

        mutating func purge(cutoff: Date) {
            // Materializing at most `maximumArtifacts` keys is bounded. Map
            // iteration order does not affect results or the LRU order of the
            // surviving keys.
            for key in Array(eventsByKey.keys) {
                guard let events = eventsByKey[key] else { continue }
                let live = events.filter { $0.timestamp >= cutoff }
                staleEventsRemoved &+= UInt64(events.count - live.count)
                if live.isEmpty {
                    eventsByKey.removeValue(forKey: key)
                    precondition(recency.remove(key), "artifact map and recency index diverged")
                    staleArtifactsRemoved &+= 1
                } else if live.count != events.count {
                    eventsByKey[key] = live
                }
            }
        }

        func telemetry() -> ArtifactMapTelemetry {
            ArtifactMapTelemetry(
                acceptedEvents: acceptedEvents,
                uniqueArtifactInsertions: uniqueArtifactInsertions,
                trackedArtifacts: eventsByKey.count,
                recencyIndexEntries: recency.count,
                peakTrackedArtifacts: peakTrackedArtifacts,
                retainedEvents: eventsByKey.values.reduce(0) { $0 + $1.count },
                staleArtifactsRemoved: staleArtifactsRemoved,
                capacityArtifactsEvicted: capacityArtifactsEvicted,
                evictionSelectionOperations: evictionSelectionOperations,
                staleEventsRemoved: staleEventsRemoved,
                capacityEventsEvicted: capacityEventsEvicted,
                perArtifactEventsEvicted: perArtifactEventsEvicted
            )
        }
    }

    // MARK: - Configuration

    /// Maximum elapsed time between first and last event for correlation.
    private let correlationWindow: TimeInterval

    /// Minimum number of distinct PIDs required to emit a NETWORK / domain
    /// fan-out chain. Network convergence needs more participants to be
    /// meaningful — a browser + git legitimately hitting the same CDN is only
    /// 2 PIDs — so this stays at 3. FILE chains use `minFileChainLength`.
    private let minChainLength: Int

    /// Minimum number of distinct PIDs required to emit a FILE chain. Defaults
    /// to 2 so the canonical write→execute handoff fires: process A writes
    /// `/tmp/payload`, another PID executes it. This is the engine's flagship
    /// cross-PID signal. File chains are already gated on action diversity
    /// (write+execute, not write+write) and the shell-utility guard, so 2 PID
    /// values here are useful evidence without making an ancestry claim.
    private let minFileChainLength: Int

    /// Maximum number of distinct artifacts tracked per map before eviction.
    private let maxArtifactsPerMap: Int

    /// Maximum number of events retained per artifact key. Bounds the per-key
    /// list so one hot key (e.g. a shared log file hammered by many worker
    /// PIDs) can't grow unbounded and turn the per-call correlation scan into
    /// O(n^2). Well above the largest real-world single-key chain observed in
    /// the field (~140 events), so detection behavior is unchanged.
    private let maxEventsPerKey: Int

    // MARK: - State

    /// Each artifact store owns its event map, a bounded O(1) LRU index, and
    /// exact conservation counters. Capacity is enforced before every new key
    /// is inserted; the periodic stale purge is cleanup, not the safety rail.
    private var fileArtifacts = ArtifactStore()
    private var networkArtifacts = ArtifactStore()
    private var domainArtifacts = ArtifactStore()

    /// File path -> distinct PIDs observed touching that path. A conservative
    /// UPPER BOUND on the windowed distinct-PID count used by
    /// `evaluateFileChain`: updated on every append, rebuilt when a per-key
    /// event trim occurs, removed with capacity eviction, and rebuilt after a
    /// stale purge. It can never UNDER-count the retained distinct PIDs. That lets
    /// `evaluateFileChain` bail in O(1) when a key provably can't reach
    /// `minFileChainLength`, skipping the window scan + pid-Set alloc on the
    /// single-PID same-file flood (the log/build-writer hot path).
    private var fileArtifactPIDs: [String: Set<Int32>] = [:]

    /// Tracks when we last ran a purge pass, to avoid purging on every call.
    private var lastPurge: Date

    // MARK: - Noise-reduction sets

    /// System paths that many processes legitimately touch.
    private static let ignoredPathPrefixes: [String] = [
        "/System/",
        "/usr/lib/",
        "/usr/share/",
        "/Library/Apple/",
        "/private/var/db/dyld/",
    ]

    /// Specific paths that are never interesting for correlation.
    private static let ignoredPaths: Set<String> = [
        "/dev/null",
        "/dev/urandom",
        "/dev/random",
        "/dev/zero",
    ]

    /// File-name suffixes that never form an attack chain. Log files are the
    /// dominant source of false positives here: a single vendor app with
    /// multiple worker processes (GoogleUpdater, Microsoft AutoUpdate, Slack,
    /// VSCode) can emit hundreds of `write → close_modified → write` events
    /// against one `.log` file inside its own app-support directory over a
    /// short window — the correlator then reports it as "13 processes, 140
    /// events" convergence. Attacks don't propagate through log writes; drop
    /// the path at ingress.
    private static let ignoredPathSuffixes: [String] = [
        ".log",
        ".log.gz",
        ".log.bz2",
        ".crash",
        ".ips",
    ]

    /// Numeric-suffix rotated logs never form an attack chain. newsyslog's
    /// rotation emits `setmode → setowner → close_modified → unlink` across
    /// `airportd` / `bzip2` / `newsyslog` on paths like `wifi.log.0`,
    /// `system.log.1`, and the cross-process correlator converged on the
    /// tuple. Strip trailing `.gz`/`.bz2`, then if the file is `<name>.log.N`
    /// where N is all digits, treat it as rotated.
    private static func hasRotatedLogSuffix(_ path: String) -> Bool {
        var stem = path
        for ext in [".gz", ".bz2"] where stem.hasSuffix(ext) {
            stem.removeLast(ext.count)
        }
        guard let lastDot = stem.lastIndex(of: ".") else { return false }
        let tail = stem[stem.index(after: lastDot)...]
        guard !tail.isEmpty, tail.allSatisfy({ $0.isNumber }) else { return false }
        return stem[..<lastDot].hasSuffix(".log")
    }

    /// Path substrings that mark a location as vendor-internal or
    /// system-cache. These paths see multi-process writes constantly and
    /// are never a useful correlation signal. Substring (not prefix) match
    /// so these catch both `/Users/<u>/Library/...` and
    /// `/Library/Application Support/...` without needing per-user variants.
    private static let ignoredPathSubstrings: [String] = [
        // Cache / log / preference dirs on user home
        "/Library/Caches/",
        "/Library/Logs/",
        "/Library/Preferences/",
        "/Library/HTTPStorages/",
        "/Library/Cookies/",
        "/Library/WebKit/",
        "/Library/Saved Application State/",
        "/Library/Metadata/CoreSpotlight/",
        "/Library/Mobile Documents/",               // iCloud Drive sync
        "/Library/ColorSync/",
        "/Library/Fonts/",                          // font cache rebuilds
        // Well-known vendors that fan out across many worker processes into
        // their own Application Support state dirs. Each entry here blocked
        // a real FP class reported by users — add conservatively.
        "/Library/Application Support/Google/",
        "/Library/Application Support/Microsoft/",
        "/Library/Application Support/CrashReporter/",
        "/Library/Application Support/MobileSync/",
        "/Library/Application Support/Code/",            // VSCode
        "/Library/Application Support/Slack/",
        "/Library/Application Support/Spotify/",
        "/Library/Application Support/Dropbox/",
        "/Library/Application Support/iCloud/",
        "/Library/Application Support/Adobe/",
        "/Library/Application Support/Creative Cloud/",
        "/Library/Application Support/JetBrains/",
        "/Library/Application Support/zoom.us/",
        "/Library/Application Support/1Password/",
        "/Library/Application Support/Firefox/",
        "/Library/Application Support/com.apple.sharedfilelist/",
        "/Library/Application Support/com.apple.spotlight/",
        "/Library/Application Support/com.apple.TCC/",   // TCC daemon state
        "/Library/Application Support/Backblaze/",
        "/Library/Application Support/DoctorClink/",
        "/Library/Application Support/Notion/",
        "/Library/Application Support/Obsidian/",
        // ~/.config fan-outs
        "/.config/JetBrains/",
        "/.mozilla/firefox/",
        "/.cache/",
        // Dev tooling fan-outs
        "/.git/",
        "/node_modules/",
        "/.pnpm/",
        "/.npm/",
        "/.yarn/",
        "/.cargo/",
        "/.rustup/",
        "/.gradle/",
        "/.m2/",
        "/.venv/",
        "/__pycache__/",
        // OS backup / snapshot volumes
        "/Volumes/MobileBackups/",
        "/Volumes/Backups of ",
        "/.DocumentRevisions-V100/",
        "/.MobileBackups/",
        "/.TemporaryItems/",
        // Terminal device files. A sudo + zsh chain "touching /dev/ttys000"
        // is the shell writing your password prompt to your terminal — the
        // user's 62-hit repeat FP in v1.4.1. Also /dev/pts on other platforms.
        "/dev/tty",
        "/dev/pts/",
        "/dev/ttys",
        // PTY master. iTerm2 → iTermServer → sudo writing /dev/ptmx is normal
        // interactive sudo in a terminal (allocating the slave PTY), not a
        // cross-process attack. EventInsertFilter already treats it as benign;
        // the two exemption lists had drifted (audit: 35 firings, 19 hand-suppressed).
        "/dev/ptmx",
        // Homebrew scratch + cellar. `brew install` fires 3,000+ chain
        // events from bash/ruby/curl/git/dirname/readlink touching
        // /opt/homebrew/var/ and /private/tmp/brew-*/. The shell-utility
        // gate handles the process side; these handle the path side.
        "/private/tmp/homebrew-",
        "/private/tmp/brew-",
        "/private/tmp/d20",                         // mktemp default used by brew + many installer scripts
        "/opt/homebrew/var/",
        "/opt/homebrew/Cellar/",
        "/usr/local/Homebrew/",                     // legacy Intel brew
        "/usr/local/Cellar/",
        // System log rotation. newsyslog spawns airportd, bzip2, and touches
        // files here as a matter of course — the three-process chain across
        // /private/var/log/wifi.log.0 etc. is not attacker convergence.
        "/private/var/log/",
        "/var/log/",
        // v1.8.0: Claude Code per-session task scratch dirs. Each subagent
        // run writes its captured stdout/stderr to a per-task .output file
        // here, with sh / df / head / tail / ps / zsh as part of the
        // command being captured. With ~12 tools per subagent and several
        // subagents per session, the writer fanout fires this rule
        // continuously through any active dev session. The
        // ProcessAncestors-on-Claude-Code path can't be relied on here
        // (the captured tools' parent is sh, not Claude). Path-side gate
        // is the right answer.
        "/private/tmp/claude-",
        "/private/var/folders/",                    // macOS per-user TemporaryItems / DerivedData
        // v1.8.0 polish: SwiftPM build output. `swift build` + the
        // bundle-app.sh chain (codesign, cp, install_name_tool, rm
        // against .build/<triple>/{debug,release}/<App>.app/Contents/MacOS/<bin>)
        // looks indistinguishable from a 4-process file-tampering chain
        // to the correlator. If the file path contains `/.build/`, it's
        // an SPM build artifact — the cross-process signal is noise.
        "/.build/",
        // v1.12.6: Claude Code shell-snapshot scratch files. Each tool
        // invocation captures the shell environment to
        // ~/.claude/shell-snapshots/snapshot-<shell>-<ts>-<rand>.sh,
        // written by zsh/bash and re-read by the next tool. Many tools
        // per session × snapshot-per-tool produces a steady stream of
        // multi-process file convergence with zero attack signal.
        "/.claude/shell-snapshots/",
        // v1.12.6: MacCrab's own release-build scratch dir. scripts/
        // build-release.sh writes /private/tmp/maccrab-release-<ts>/
        // and codesign/productbuild/cp fan out across it. Self-FP.
        "/private/tmp/maccrab-release-",
        // v1.17.1: MacCrab's entire support root, both system + user-home
        // dev-daemon copies. The install / uninstall / rule-reload pipeline
        // (sysextd, the daemon's writer, maccrabctl, chown/cp/rm/touch)
        // fans coreutils across this tree, producing 3-process chains
        // against our own files. Was scoped to compiled_rules/ only, which
        // missed the parent dir (DB/WAL/cache/keys/inbox writes). Self-FP.
        // Matched as one fully-slashed segment: covers the system path
        // (/Library/Application Support/MacCrab/…) AND the user dev path
        // (/Users/<u>/Library/Application Support/MacCrab/…) without matching a
        // bare "MacCrab", a sibling "MacCrabExtra", or an attacker-made dir (the
        // earlier no-leading-/no-trailing-slash variants did all three).
        "/Library/Application Support/MacCrab/",
    ]

    /// Per-substring ASCII character mask for the `ignoredPathSubstrings`
    /// prefilter (#18). A necessary condition for `path.contains(sub)` is that
    /// `path` contains every character of `sub`, so comparing 128-bit ASCII
    /// presence masks lets the per-event hot path skip the O(n) `contains`
    /// scan for the (common) substrings a path provably can't contain — while
    /// producing byte-identical ignore verdicts. Derived from
    /// `ignoredPathSubstrings`, so the gate can never drift out of sync. A
    /// substring with any non-ASCII byte is marked `pureASCII == false` and is
    /// always scanned (never gated), keeping the gate sound if a future entry
    /// ever contains non-ASCII characters.
    private static let ignoredSubstringMasks: [(m0: UInt64, m1: UInt64, pureASCII: Bool, sub: String)] =
        ignoredPathSubstrings.map { sub in
            let mask = CrossProcessCorrelator.asciiMask(of: sub)
            return (mask.m0, mask.m1, mask.pureASCII, sub)
        }

    /// Build a 128-bit ASCII presence mask over a string's UTF-8 bytes: bytes
    /// 0–63 set a bit in `m0`, 64–127 set a bit in `m1`, and a byte ≥ 128
    /// (non-ASCII) sets no bit and clears `pureASCII`. ASCII bytes never appear
    /// inside a multi-byte UTF-8 sequence, so a set bit exactly means "this
    /// ASCII character is present in the string."
    private static func asciiMask(of s: String) -> (m0: UInt64, m1: UInt64, pureASCII: Bool) {
        var m0: UInt64 = 0
        var m1: UInt64 = 0
        var pureASCII = true
        for byte in s.utf8 {
            if byte < 64 {
                m0 |= (1 as UInt64) << UInt64(byte)
            } else if byte < 128 {
                m1 |= (1 as UInt64) << UInt64(byte - 64)
            } else {
                pureASCII = false
            }
        }
        return (m0, m1, pureASCII)
    }

    /// Network destinations that are never interesting.
    private static let ignoredNetworkPrefixes: [String] = [
        "127.",            // loopback
        "0.0.0.0",
        "::1",
        "169.254.",        // link-local
        "fe80:",           // link-local v6
    ]

    /// Destinations served by well-known cloud / AI-service CDNs. Multiple
    /// processes hitting one of these is almost always a legitimate tool
    /// family (Claude Code + its node MCP helpers + its cli wrapper, for
    /// example) — not attacker convergence. These ranges mirror the AI
    /// network sandbox allowlist so the two stay in sync.
    private static let trustedCloudPrefixes: [String] = [
        // Apple (ASN 714 — 17.0.0.0/8 is Apple's own registered IP space)
        "17.",
        // Anthropic (Fastly)
        "160.79.",
        // OpenAI / Cloudflare-fronted services
        "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "104.22.",
        "172.64.", "172.65.", "172.66.", "172.67.",
        // Google / GCP / Gemini (mirrors the AI-sandbox Google IP list so
        // the two stay in sync — see https://www.gstatic.com/ipranges/goog.json)
        "34.96.", "34.97.", "34.98.", "34.99.", "34.149.", "34.150.",
        "35.186.", "35.187.", "35.188.", "35.189.", "35.190.", "35.191.",
        "64.233.", "66.102.", "66.249.",
        "72.14.",
        "74.125.",
        "108.177.",
        "142.250.", "142.251.",
        "172.217.", "172.253.",
        "173.194.",
        "209.85.",
        "216.58.", "216.239.",
        // GitHub / Copilot
        "140.82.", "185.199.",
        // Cloudflare
        "162.159.", "141.101.", "108.162.",
    ]

    /// Destination domains served by trusted APIs. Used when the chain key
    /// is domain-based rather than IP-based. Suffix-matched, so
    /// `clients2.google.com` matches `google.com`.
    ///
    /// Google's browser + update + drive + media stack fans out across
    /// several TLDs — adding only `google.com` wasn't enough, since Chrome
    /// chatters to `gvt1.com`, `googleusercontent.com`, `googlevideo.com`,
    /// etc. These are all Google-owned CDNs and were the dominant source of
    /// Chrome-Helper convergence false positives on real workstations.
    private static let trustedCloudDomains: [String] = [
        // AI APIs
        "anthropic.com", "claude.ai",
        "openai.com", "chatgpt.com", "oaiusercontent.com",
        "mistral.ai", "groq.com", "perplexity.ai",
        // Source forges
        "github.com", "githubusercontent.com", "githubassets.com",
        "gitlab.com", "bitbucket.org",
        // Google — browser + update + services + media
        "google.com", "googleapis.com", "gstatic.com",
        "gvt1.com", "gvt2.com",                 // Google Update / CRX
        "googleusercontent.com",                // User content CDN
        "googlevideo.com", "ytimg.com", "youtube.com", "youtu.be",
        "doubleclick.net", "googlesyndication.com",
        "google-analytics.com", "googletagmanager.com", "googleadservices.com",
        "goog.gl", "goo.gl",
        // Microsoft — Edge, Teams, OneDrive, Windows Update equivalents
        "microsoft.com", "microsoftonline.com", "office.com", "office365.com",
        "azureedge.net", "azure.com", "live.com", "windows.net",
        "msn.com", "bing.com",
        // Mozilla
        "mozilla.org", "mozilla.net", "firefox.com",
        // Apple CDNs
        "apple.com", "icloud.com", "mzstatic.com", "apple-cloudkit.com",
        "apple-mapkit.com", "apple-livephotoskit.com", "cdn-apple.com",
        // Cloudflare
        "cloudflare.com", "cloudflare-dns.com", "cloudflareinsights.com",
        // Collab / messaging Electron apps — same fan-out pattern as browsers
        "slack.com", "slack-edge.com", "slack-msgs.com",
        "discord.com", "discordapp.com", "discord.gg",
        "zoom.us", "zoomgov.com",
    ]

    // MARK: - Initialization

    /// Creates a new cross-process correlator.
    ///
    /// - Parameters:
    ///   - correlationWindow: Maximum time span (seconds) for events to be
    ///     considered part of the same chain. Defaults to 300 (5 minutes).
    ///   - minChainLength: Minimum number of distinct PIDs required to emit a
    ///     NETWORK / domain fan-out chain. Defaults to 3 (reduces noise from
    ///     normal multi-process traffic like browsers + git to same CDN).
    ///   - minFileChainLength: Minimum number of distinct PIDs required to emit
    ///     a FILE chain. Defaults to 2 so the canonical cross-PID write→execute
    ///     handoff fires; file chains are already gated on action diversity and
    ///     the shell-utility guard, which hold FP noise down.
    ///   - maxArtifactsPerMap: Hard cap independently enforced for file, IP,
    ///     and domain keys. Values below one are clamped to one.
    ///   - maxEventsPerArtifact: Hard event-list cap for each retained key.
    public init(
        correlationWindow: TimeInterval = 300,
        minChainLength: Int = 3,
        minFileChainLength: Int = 2,
        maxArtifactsPerMap: Int = 10_000,
        maxEventsPerArtifact: Int = 512
    ) {
        self.correlationWindow = correlationWindow
        self.minChainLength = minChainLength
        self.minFileChainLength = minFileChainLength
        self.maxArtifactsPerMap = max(1, maxArtifactsPerMap)
        self.maxEventsPerKey = max(1, maxEventsPerArtifact)
        self.lastPurge = Date()
    }

    // MARK: - Public API

    /// Record a file event (write, execute, read, download, create).
    ///
    /// Returns a correlation chain if this event completes a cross-process
    /// chain involving the same file path.
    @discardableResult
    public func recordFileEvent(
        path: String,
        action: String,
        pid: Int32,
        processName: String,
        processPath: String,
        timestamp: Date = Date()
    ) -> CorrelationChain? {
        guard !Self.shouldIgnoreFilePath(path) else { return nil }

        let event = ChainEvent(
            timestamp: timestamp,
            pid: pid,
            processName: processName,
            processPath: processPath,
            action: action
        )

        let outcome = fileArtifacts.append(
            key: path,
            event: event,
            maximumArtifacts: maxArtifactsPerMap,
            maximumEventsPerArtifact: maxEventsPerKey
        )
        if let evictedKey = outcome.capacityEvictedKey {
            fileArtifactPIDs.removeValue(forKey: evictedKey)
        }
        fileArtifactPIDs[path, default: []].insert(pid)
        if outcome.trimmedEvents,
           let retained = fileArtifacts.eventsByKey[path] {
            fileArtifactPIDs[path] = Set(retained.map(\.pid))
        }
        purgeIfNeeded()

        return evaluateFileChain(path: path)
    }

    /// Record a network event (connect, DNS lookup).
    ///
    /// Returns a correlation chain if this event completes a cross-process
    /// chain involving the same destination.
    @discardableResult
    public func recordNetworkEvent(
        destinationIP: String,
        destinationPort: UInt16,
        destinationDomain: String? = nil,
        pid: Int32,
        processName: String,
        processPath: String,
        timestamp: Date = Date()
    ) -> CorrelationChain? {
        guard !shouldIgnoreNetworkDestination(destinationIP) else { return nil }

        let event = ChainEvent(
            timestamp: timestamp,
            pid: pid,
            processName: processName,
            processPath: processPath,
            action: "connect"
        )

        let ipKey = "\(destinationIP):\(destinationPort)"
        _ = networkArtifacts.append(
            key: ipKey,
            event: event,
            maximumArtifacts: maxArtifactsPerMap,
            maximumEventsPerArtifact: maxEventsPerKey
        )

        var chain = evaluateNetworkChain(key: ipKey, artifactType: "network")

        // Also track by domain if provided.
        if let domain = destinationDomain,
           let domainKey = Self.normalizedDomain(domain) {
            _ = domainArtifacts.append(
                key: domainKey,
                event: event,
                maximumArtifacts: maxArtifactsPerMap,
                maximumEventsPerArtifact: maxEventsPerKey
            )
            if chain == nil {
                chain = evaluateNetworkChain(key: domainKey, artifactType: "domain")
            }
        }

        purgeIfNeeded()
        return chain
    }

    /// Remove stale events and any artifact left empty. The hard capacity rail
    /// is enforced at insertion; this periodic pass controls data age.
    public func purgeStale() {
        let cutoff = Date().addingTimeInterval(-correlationWindow)

        fileArtifacts.purge(cutoff: cutoff)
        networkArtifacts.purge(cutoff: cutoff)
        domainArtifacts.purge(cutoff: cutoff)

        // Rebuild the file-PID upper-bound index from the surviving file
        // artifacts so it stays in sync with pruning/eviction: this bounds its
        // memory (its keys track `fileArtifacts` exactly) and keeps it a valid
        // upper bound (distinct PIDs of all stored events ⊇ in-window PIDs).
        fileArtifactPIDs = rebuildFilePIDIndex(fileArtifacts.eventsByKey)

        lastPurge = Date()
        logger.debug("Purge complete — files: \(self.fileArtifacts.eventsByKey.count), network: \(self.networkArtifacts.eventsByKey.count), domains: \(self.domainArtifacts.eventsByKey.count)")
    }

    // MARK: - Diagnostics

    /// Number of distinct file artifacts currently tracked.
    public var trackedFileCount: Int { fileArtifacts.eventsByKey.count }

    /// Number of distinct network artifacts currently tracked.
    public var trackedNetworkCount: Int { networkArtifacts.eventsByKey.count }

    /// Number of distinct domain artifacts currently tracked.
    public var trackedDomainCount: Int { domainArtifacts.eventsByKey.count }

    /// Total number of individual events stored across all artifact maps.
    public var totalEventCount: Int {
        fileArtifacts.eventsByKey.values.reduce(0) { $0 + $1.count }
            + networkArtifacts.eventsByKey.values.reduce(0) { $0 + $1.count }
            + domainArtifacts.eventsByKey.values.reduce(0) { $0 + $1.count }
    }

    /// Fixed-cardinality capacity and conservation snapshot.
    public func telemetrySnapshot() -> Telemetry {
        Telemetry(
            maximumArtifactsPerMap: maxArtifactsPerMap,
            maximumEventsPerArtifact: maxEventsPerKey,
            filePIDIndexEntries: fileArtifactPIDs.count,
            file: fileArtifacts.telemetry(),
            network: networkArtifacts.telemetry(),
            domain: domainArtifacts.telemetry()
        )
    }

    // MARK: - Chain Evaluation

    /// Evaluate whether the events for a given file path form a complete chain.
    private func evaluateFileChain(path: String) -> CorrelationChain? {
        // O(1) fast bail (#14): the incrementally-maintained distinct-PID set is
        // a conservative UPPER BOUND on the windowed distinct-PID count — it's a
        // superset of the PIDs of the currently-stored events, which are a
        // superset of the in-window events. So when it can't reach
        // `minFileChainLength`, no window scan can either — the chain is
        // provably impossible — and we skip `eventsWithinWindow`'s 2×O(n) scan
        // plus the pid-Set alloc. When the index is absent we fall through to
        // the full scan, so the outcome is byte-identical to the pre-opt path.
        if let pids = fileArtifactPIDs[path], pids.count < minFileChainLength {
            return nil
        }
        guard let events = fileArtifacts.eventsByKey[path] else { return nil }

        // Filter to events within the correlation window.
        let windowEvents = eventsWithinWindow(events)

        // Must involve multiple distinct PIDs. File chains fire at
        // `minFileChainLength` (2 by default) — the write→execute handoff
        // across distinct PIDs — while network fan-out needs `minChainLength`
        // (3) to be meaningful.
        let distinctPIDs = Set(windowEvents.map(\.pid))
        guard distinctPIDs.count >= minFileChainLength else { return nil }

        // Must span different action types, not just write+write.
        //
        // DO NOT add `actions.contains("execute")` here. It reads like the
        // obvious tightening and it is unsatisfiable: the file map has exactly
        // one producer, `EventLoop.recordFileEvent`, and that call site is
        // guarded on `enrichedEvent.file != nil`. Every exec producer
        // (ESCollector NOTIFY_EXEC, KdebugCollector, EsloggerParser) builds a
        // `.process` Event with no `file`, and `Event.file` is `let`, so no
        // enricher can supply one later. The `exec` -> `execute` mapping beside
        // that call site has therefore never been reachable. Requiring
        // "execute" silences this tier completely — verified on an installed
        // host, where every cross-process chain alert carries only file actions
        // (open/write/create/rename/unlink/close_modified/setmode) and is
        // MEDIUM, because the `hasExecute`/`hasNetwork` branches of
        // `computeFileSeverity` are unreachable for the same reason.
        //
        // A drop-and-run still forms a chain here without an execute leg: the
        // drop itself emits two actions (NOTIFY_CREATE + NOTIFY_WRITE, or
        // write+setmode for `chmod +x`), which satisfies this guard.
        //
        // Making the execute leg real means feeding the exec path into the
        // correlator keyed on `process.executable`, not tightening this guard.
        let actions = Set(windowEvents.map(\.action))
        guard actions.count >= 2 else { return nil }

        // Same homogeneity gates that evaluateNetworkChain uses: if every
        // event in the chain comes from the same executable / app bundle /
        // tool-version dir, it's a single vendor's worker fan-out — not
        // cross-process attacker convergence. Catches the belt-and-braces
        // case where v1.3.10's path filter misses a vendor dir (for
        // example a new GoogleUpdater sub-path we haven't enumerated yet).
        if allEventsShareExecutable(windowEvents) { return nil }
        if allEventsShareAppBundle(windowEvents) { return nil }
        if allEventsShareToolDirectory(windowEvents) { return nil }
        if allEventsAreTrustedHelpers(windowEvents) { return nil }
        // And a processName-based check: if every event shares the same
        // processName, it's the same binary running multiple times even if
        // its executable path looks different (e.g. GoogleUpdater forked
        // with different argv[0] presentations). Log-style fan-out never
        // crosses process identities.
        if allEventsShareProcessName(windowEvents) { return nil }
        // Shell-utility chain (v1.4.2): `brew install` fires ~3,000 chain
        // events in 30s from bash + ruby + curl + git + dirname +
        // readlink + env + locale touching shared tmp dirs. Attackers
        // don't chain through coreutils. If >=80% of chain participants
        // are small shell helpers, drop — this is a script, not a
        // campaign.
        if chainDominatedByShellUtilities(windowEvents) { return nil }

        let severity = computeFileSeverity(events: windowEvents, actions: actions)
        let chain = buildChain(
            events: windowEvents,
            artifact: path,
            artifactType: "file",
            severity: severity
        )

        logger.warning(
            "Cross-process file chain detected: \(chain.description) [\(chain.severity.rawValue)]"
        )
        return chain
    }

    /// Evaluate whether the events for a given network key form a complete chain.
    private func evaluateNetworkChain(key: String, artifactType: String) -> CorrelationChain? {
        let events: [ChainEvent]
        if artifactType == "domain" {
            guard let stored = domainArtifacts.eventsByKey[key] else { return nil }
            events = stored
        } else {
            guard let stored = networkArtifacts.eventsByKey[key] else { return nil }
            events = stored
        }

        let windowEvents = eventsWithinWindow(events)

        // Must involve multiple distinct PIDs.
        let distinctPIDs = Set(windowEvents.map(\.pid))
        guard distinctPIDs.count >= minChainLength else { return nil }

        // Skip when the destination is a well-known cloud/AI service CDN.
        // Multi-process fan-out to Anthropic / OpenAI / Google / GitHub is
        // expected when a developer has several AI tools running: the cli
        // wrapper, a node MCP helper, and an IDE plugin all talk to the same
        // backend. Flagging that as "convergence" produced the overwhelming
        // majority of false positives on real dev workstations.
        if destinationIsTrustedCloud(key: key, artifactType: artifactType) { return nil }

        // Skip "convergence" events where every contacting process lives in
        // the same application bundle. Electron / Chromium apps routinely
        // spawn 5+ helper processes that all hit the same Google / Slack /
        // GitHub endpoint — that's architecture, not attack.
        if allEventsShareAppBundle(windowEvents) { return nil }
        // Also skip when every process is the same executable (e.g. multiple
        // `node` instances making concurrent API calls) or lives in the same
        // tool-version directory (e.g. Claude Code forks under
        // `.local/share/claude/versions/<ver>/`). A tool calling itself in
        // parallel isn't a convergence event.
        if allEventsShareExecutable(windowEvents) { return nil }
        if allEventsShareToolDirectory(windowEvents) { return nil }
        // And skip when every chain participant is a known browser or
        // Electron helper — even if they span *different* bundles. A fan-out
        // of `Google Chrome Helper` + `Google Drive` + `Google Software
        // Update` to a Google endpoint is three distinct `.app`s but one
        // vendor stack; the bundle-match above can't see that. This is the
        // single biggest source of Chrome-Helper `network-convergence` noise
        // on workstations where the user runs the Google suite end-to-end.
        if allEventsAreTrustedHelpers(windowEvents) { return nil }
        // Skip when every contacting process is an Apple system daemon
        // (e.g. mDNSResponder, nsurlsessiond, trustd all hitting an Apple
        // CDN IP). These belong to /System/ or /usr/ paths and are never
        // attack convergence regardless of what IP they share.
        if allEventsAreAppleSystemProcesses(windowEvents) { return nil }
        // Skip when every contacting process is part of a legitimate
        // developer workflow (git push/pull spawning git-remote-http +
        // openssl, GitHub Desktop Helper + git subprocesses, Xcode's
        // embedded git + curl on release builds). These produce the
        // most common false "N processes contacting github.com"
        // convergence alerts on developer machines.
        if allEventsAreDevWorkflow(windowEvents) { return nil }

        let severity = computeNetworkSeverity(events: windowEvents)
        let chain = buildChain(
            events: windowEvents,
            artifact: key,
            artifactType: artifactType,
            severity: severity
        )

        logger.warning(
            "Cross-process \(artifactType) convergence: \(chain.description) [\(chain.severity.rawValue)]"
        )
        return chain
    }

    /// True when the artifact key (ip:port or domain) belongs to a trusted
    /// cloud / AI-service provider. Called before per-event-process filters
    /// because the destination is a much stronger noise signal: if the
    /// target is Anthropic or Google, multi-process fan-out to that target
    /// is architecture regardless of which local processes are involved.
    private func destinationIsTrustedCloud(key: String, artifactType: String) -> Bool {
        if artifactType == "network" {
            // key format: "ip:port"
            let ip = key.split(separator: ":").first.map(String.init) ?? key
            for prefix in Self.trustedCloudPrefixes where ip.hasPrefix(prefix) {
                return true
            }
        } else if artifactType == "domain" {
            return Self.isTrustedCloudDomain(key)
        }
        return false
    }

    /// Whether a DNS host is exactly a trusted domain or one of its
    /// subdomains. Character suffixes alone are unsafe: `evilopenai.com`
    /// ends with `openai.com` but is not beneath it in the DNS hierarchy.
    public nonisolated static func isTrustedCloudDomain(_ domain: String) -> Bool {
        guard let host = normalizedDomain(domain) else { return false }
        return trustedCloudDomains.contains { trusted in
            host == trusted || host.hasSuffix("." + trusted)
        }
    }

    /// Canonical form used both for domain map keys and trust decisions.
    /// A fully-qualified trailing dot is accepted; empty labels are not.
    private nonisolated static func normalizedDomain(_ domain: String) -> String? {
        var host = domain.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if host.hasSuffix(".") {
            host.removeLast()
        }
        guard !host.isEmpty,
              !host.hasPrefix("."),
              !host.hasSuffix("."),
              !host.contains("..") else {
            return nil
        }
        return host
    }

    /// True when every event's process lives under the same `.app` bundle.
    private func allEventsShareAppBundle(_ events: [ChainEvent]) -> Bool {
        var bundles: Set<String> = []
        for event in events {
            guard let bundle = appBundleRoot(for: event.processPath) else { return false }
            bundles.insert(bundle)
            if bundles.count > 1 { return false }
        }
        return bundles.count == 1
    }

    /// True when every event is the same executable (same path).
    private func allEventsShareExecutable(_ events: [ChainEvent]) -> Bool {
        guard let first = events.first else { return false }
        return events.allSatisfy { $0.processPath == first.processPath }
    }

    /// True when every event's processName matches. Same binary running as
    /// multiple workers emits identical processName even when processPath
    /// can differ (e.g. GoogleUpdater exec'd as argv[0]=`GoogleUpdater` vs.
    /// argv[0]=`/Library/.../GoogleUpdater.app/.../GoogleUpdater` look the
    /// same to ps but compare unequal on processPath when one is a shim).
    private func allEventsShareProcessName(_ events: [ChainEvent]) -> Bool {
        guard let first = events.first, !first.processName.isEmpty else { return false }
        return events.allSatisfy { $0.processName == first.processName }
    }

    /// True when a chain is dominated by a *variety* of shell helpers
    /// AND doesn't include an `execute` action. That shape — many
    /// distinct shell utilities, all touching a shared path, no
    /// execution — is a build/install script (brew, configure, make
    /// install) not an attack chain. Drops the 3,000+ FP storm the
    /// v1.4.1 user saw during `brew reinstall`.
    ///
    /// Deliberately NARROW: a classic curl→bash two-process attack
    /// (curl writes payload, bash executes it) has only 2 shell
    /// utilities, below the variety floor, so it escapes this gate on the
    /// utility count alone. Combined with `minFileChainLength` == 2 (which
    /// lets a 2-PID file chain through at all), the drop half of that handoff
    /// forms a chain via its own action pair (create+write, or write+setmode
    /// for `chmod +x`).
    ///
    /// The `execute` carve-out below is currently INERT — no event reaching
    /// this correlator carries that action; see the note in
    /// `evaluateFileChain`. It is retained deliberately so the carve-out is
    /// already correct if the exec path is ever wired in, but it must not be
    /// cited as the thing protecting write→execute today. Nothing is.
    private func chainDominatedByShellUtilities(_ events: [ChainEvent]) -> Bool {
        // Execute would be the attack signal. If anything in the chain
        // executed the shared file, keep the chain — this is exactly
        // what "download + run" malware looks like. Unreachable today.
        let actions = Set(events.map(\.action))
        if actions.contains("execute") { return false }

        // Require both coverage (≥80% of events are shell helpers) AND
        // variety (≥3 distinct utilities). Variety distinguishes a
        // build/install script from a 2-process attack.
        //
        // v1.21.4 (deep-audit corr-campaign-anomaly): lowered the variety
        // floor from 4 → 3. The ≥4 gate let the very common 3-utility
        // write-only script shapes (bash/cat/sed, cp/rm/touch) slip through
        // and mint benign file-chain alerts. This can only ADD suppression to
        // write-only chains — any chain containing an `execute` still fires via
        // the carve-out above, so no download-and-run attack is affected.
        var shellHits = 0
        var distinctShellNames: Set<String> = []
        for e in events {
            let name = (e.processPath as NSString).lastPathComponent.lowercased()
            if Self.shellUtilityBasenames.contains(name) {
                shellHits += 1
                distinctShellNames.insert(name)
            }
        }
        let coverage = Double(shellHits) / Double(events.count)
        return coverage >= 0.8 && distinctShellNames.count >= 3
    }

    /// Small shell helpers that legitimately chain through shared paths.
    /// Intentionally conservative — anything listed here must be a tool
    /// an attacker wouldn't use as a payload. Full shells (bash/zsh/sh)
    /// are here because they're script interpreters, not persistence
    /// mechanisms — an attack uses them AS a shell to run another
    /// dropped binary, and the binary would fall outside this list and
    /// keep the percentage below threshold.
    /// One whitespace-separated literal rather than 97 array elements: the
    /// element-wise form costs enough code and string metadata to push the
    /// signed app past its fixed footprint budget, and membership is what
    /// matters here, not the literal's shape. Line grouping below is, in order:
    /// shells and interpreters; core text and file tools; archive and hash;
    /// network helpers install scripts use; dev-tool wrappers brew/pip/npm
    /// invoke constantly; JSON and templating.
    ///
    /// `shellUtilityBasenamesAreExactlyTheDocumentedSet` pins the full
    /// membership element by element, so a typo here fails the suite rather
    /// than silently widening or narrowing the FP gate.
    private static let shellUtilityBasenames: Set<String> = Set(
        """
        bash sh zsh ksh dash fish
        ruby perl python python3 node npm yarn pnpm
        cat cp mv rm ln mkdir rmdir touch
        dirname basename readlink realpath pwd
        echo printf true false test env exec
        grep egrep fgrep sed awk cut tr tee
        sort uniq head tail wc od xxd
        find xargs locate which type
        file stat chmod chown chgrp
        locale date id tty hostname uname
        tar gzip gunzip zip unzip
        md5 md5sum shasum openssl
        curl wget nc ping host dig nslookup
        git svn make cmake pkg-config
        brew pip pip3 gem bundle cargo rustc go
        jq yq xmllint
        """.split(whereSeparator: \.isWhitespace).map(String.init)
    )

    #if DEBUG
    /// Test-only window onto the set above; the suite pins its exact members.
    internal static var shellUtilityBasenamesForTesting: Set<String> {
        shellUtilityBasenames
    }
    #endif

    /// True when every event's process lives under the same tool-version
    /// directory — i.e. the parent directory of the executable matches, or
    /// they share a common ancestor that looks like `/versions/<ver>`.
    /// Catches cases like Claude Code forking several processes under
    /// `~/.local/share/claude/versions/2.1.111/` where there's no `.app`.
    private func allEventsShareToolDirectory(_ events: [ChainEvent]) -> Bool {
        guard let first = events.first else { return false }
        let firstDir = (first.processPath as NSString).deletingLastPathComponent
        return events.allSatisfy {
            ($0.processPath as NSString).deletingLastPathComponent == firstDir
        }
    }

    /// True when every event's process sits under one of the
    /// `NoiseFilter.trustedBrowserPrefixes` bundles. This allows a chain to
    /// be suppressed when participants cross bundle boundaries but all
    /// belong to widely-deployed browsers / Electron apps (Chrome + Chrome
    /// Helper + Slack, all talking to Google's CDN). The bundle-identity
    /// filter above can't catch cross-bundle cases like that on its own.
    private func allEventsAreTrustedHelpers(_ events: [ChainEvent]) -> Bool {
        guard !events.isEmpty else { return false }
        return events.allSatisfy {
            NoiseFilter.isTrustedBrowserHelper(path: $0.processPath)
        }
    }

    /// True when every event's process is an Apple system daemon — path
    /// in /System/, /usr/libexec/, /usr/sbin/, or /sbin/. Multiple Apple
    /// daemons (mDNSResponder, nsurlsessiond, trustd) contacting the same
    /// CDN IP is normal system operation, not convergence. Deliberately
    /// excludes /usr/bin/ and /bin/ so that user-level tools (curl,
    /// python3, bash) still trigger convergence alerts.
    private func allEventsAreAppleSystemProcesses(_ events: [ChainEvent]) -> Bool {
        guard !events.isEmpty else { return false }
        return events.allSatisfy { event in
            let path = event.processPath
            return path.hasPrefix("/System/") ||
                   path.hasPrefix("/usr/libexec/") ||
                   path.hasPrefix("/usr/sbin/") ||
                   path.hasPrefix("/sbin/")
        }
    }

    /// True when every event's process is a legitimate developer workflow
    /// binary contacting the same destination — git workflow (GitHub
    /// Desktop, the various git-remote-* helpers, openssl for TLS),
    /// Xcode-embedded tooling, or package-manager installers (brew, npm,
    /// pip) that routinely fan out several short-lived children against
    /// the same registry host.
    ///
    /// Field dogfooding showed this path producing "N processes contacting
    /// github.com" alerts on every git push/pull sequence — high volume,
    /// zero signal. Real attack convergence involves processes outside
    /// this well-known set (a dropper + a shell + a staged payload).
    private func allEventsAreDevWorkflow(_ events: [ChainEvent]) -> Bool {
        guard !events.isEmpty else { return false }
        return events.allSatisfy { event in isDevWorkflowPath(event.processPath) }
    }

    private nonisolated func isDevWorkflowPath(_ path: String) -> Bool {
        // Path-prefix allowlist — covers app-bundle helpers + IDE toolchains
        let prefixAllowlist = [
            "/Applications/GitHub Desktop.app/",
            "/Applications/Xcode.app/Contents/Developer/",
            "/Library/Developer/CommandLineTools/",
            "/Applications/Docker.app/",
            "/opt/homebrew/Cellar/",
            "/opt/homebrew/bin/",
            "/opt/homebrew/opt/",
            "/usr/local/Cellar/",
            "/usr/local/bin/brew",
        ]
        if prefixAllowlist.contains(where: { path.hasPrefix($0) }) { return true }

        // Exact-path allowlist — legitimate system tools that developers
        // invoke directly from terminals for git/HTTP workflows.
        let exactAllowlist: Set<String> = [
            "/usr/bin/git",
            "/usr/bin/git-receive-pack",
            "/usr/bin/git-upload-pack",
            "/usr/bin/ssh",
            "/usr/bin/curl",
            "/usr/bin/wget",
        ]
        if exactAllowlist.contains(path) { return true }

        // Basename allowlist — covers `git` invoked via PATH lookup when
        // the resolved path is a symlink we haven't pre-enumerated.
        let base = (path as NSString).lastPathComponent
        let basenameAllowlist: Set<String> = [
            "git", "git-remote-http", "git-remote-https",
            "git-credential-osxkeychain", "git-lfs",
            "GitHub Desktop Helper", "GitHub Desktop Helper (Renderer)",
            "GitHub Desktop Helper (GPU)", "GitHub Desktop Helper (Plugin)",
        ]
        return basenameAllowlist.contains(base)
    }

    /// Returns the outermost `.app/` directory for an executable path, or nil
    /// if the path isn't inside an app bundle.
    private func appBundleRoot(for path: String) -> String? {
        guard let range = path.range(of: ".app/") else { return nil }
        return String(path[path.startIndex..<range.upperBound])
    }

    // MARK: - Severity Calculation

    /// Compute severity for a file-based chain.
    ///
    /// - 2 events, file only: medium
    /// - 2+ events with both file and network actions: high
    /// - 3+ events spanning write -> execute -> network: critical
    ///
    /// Only the medium branch is reachable today. `recordFileEvent` is fed
    /// exclusively from the file branch of the event loop, so the file map
    /// never contains "execute" or "connect" and both escalations are dead —
    /// which is why every cross-process chain alert observed on an installed
    /// host is MEDIUM. Retained rather than deleted because they become
    /// correct the moment the exec/network legs are wired in; see the note in
    /// `evaluateFileChain`. Do not read a MEDIUM here as evidence that the
    /// chain lacked execution or network activity.
    private func computeFileSeverity(events: [ChainEvent], actions: Set<String>) -> Severity {
        let hasWrite = actions.contains("write") || actions.contains("download")
        let hasExecute = actions.contains("execute")
        let hasNetwork = actions.contains("connect")
        let distinctPIDs = Set(events.map(\.pid)).count

        // 3+ events spanning write -> execute -> network: critical
        if distinctPIDs >= 3, hasWrite, hasExecute, hasNetwork {
            return .critical
        }

        // 2+ events with both file and network
        if hasNetwork, (hasWrite || hasExecute) {
            return .high
        }

        // write -> execute by different process
        if hasWrite, hasExecute {
            return .high
        }

        // Baseline: two processes touching the same file with different actions
        return .medium
    }

    /// Compute severity for a network-based chain (multiple distinct PID values
    /// contacting the same destination).
    private func computeNetworkSeverity(events: [ChainEvent]) -> Severity {
        let distinctPIDs = Set(events.map(\.pid)).count

        if distinctPIDs >= 3 {
            return .high
        }
        return .medium
    }

    // MARK: - Chain Construction

    /// Build a `CorrelationChain` from a set of events.
    private func buildChain(
        events: [ChainEvent],
        artifact: String,
        artifactType: String,
        severity: Severity
    ) -> CorrelationChain {
        let sorted = events.sorted { $0.timestamp < $1.timestamp }
        let firstTime = sorted.first?.timestamp ?? Date()
        let lastTime = sorted.last?.timestamp ?? Date()
        let span = lastTime.timeIntervalSince(firstTime)
        let distinctPIDs = Set(sorted.map(\.pid))
        let processNames = Set(sorted.map(\.processName))

        let desc: String
        switch artifactType {
        case "file":
            let actions = sorted.map(\.action).joined(separator: " -> ")
            desc = "\(processNames.sorted().joined(separator: ", ")) touched \(artifact) [\(actions)] over \(Int(span))s"
        case "network":
            desc = "\(distinctPIDs.count) distinct PIDs contacted \(artifact) over \(Int(span))s"
        case "domain":
            desc = "\(distinctPIDs.count) distinct PIDs resolved \(artifact) over \(Int(span))s"
        default:
            desc = "\(distinctPIDs.count) distinct PIDs share artifact \(artifact)"
        }

        return CorrelationChain(
            id: "XPROC-\(UUID().uuidString.prefix(8))",
            events: sorted,
            sharedArtifact: artifact,
            artifactType: artifactType,
            timeSpanSeconds: span,
            distinctPIDCount: distinctPIDs.count,
            severity: severity,
            description: desc
        )
    }

    // MARK: - Filtering Helpers

    /// Whether a file path should be ignored for correlation (system noise).
    ///
    /// `nonisolated static` (v1.21.4 perf): a pure predicate over the immutable
    /// ignore-sets, so the EventLoop hot path can short-circuit ignored paths
    /// BEFORE the actor hop into `recordFileEvent`. `recordFileEvent` still calls
    /// this as its first guard, so a direct caller — and every ignored path —
    /// sees byte-identical behavior; only the wasted actor hop is elided.
    public nonisolated static func shouldIgnoreFilePath(_ path: String) -> Bool {
        if ignoredPaths.contains(path) { return true }
        for prefix in ignoredPathPrefixes {
            if path.hasPrefix(prefix) { return true }
        }
        for suffix in ignoredPathSuffixes {
            if path.hasSuffix(suffix) { return true }
        }
        // Substring scan with a cheap ASCII-mask prefilter (#18): a path can
        // only contain `sub` if it contains every character of `sub`, so skip
        // the O(n) `contains` for any substring whose ASCII character mask is
        // not a subset of the path's. Identical verdicts — only provably
        // impossible matches are skipped; a non-ASCII substring is always
        // scanned (`pureASCII == false`).
        let pathMask = asciiMask(of: path)
        for entry in ignoredSubstringMasks {
            if entry.pureASCII &&
                ((entry.m0 & pathMask.m0) != entry.m0 ||
                 (entry.m1 & pathMask.m1) != entry.m1) {
                continue
            }
            if path.contains(entry.sub) { return true }
        }
        if hasRotatedLogSuffix(path) { return true }
        return false
    }

    /// Whether a network destination should be ignored (localhost, link-local,
    /// or unresolved / sentinel values).
    ///
    /// Unresolved IP is the most important guard here: the network collector
    /// emits events the instant a connection is observed, which can land
    /// before DNS / flow-enrichment completes. Those events arrive with an
    /// empty `destinationIp`, and without this guard every one of them keys
    /// into the artifact map as `":443"` — collapsing every HTTPS flow on
    /// the box into a single bucket and producing a permanent flood of
    /// "N distinct PIDs contacted :443" convergence alerts. The fix
    /// is to drop these at ingress. A later event carrying a resolved IP and
    /// domain can populate both keys; this unresolved event itself is discarded.
    private func shouldIgnoreNetworkDestination(_ ip: String) -> Bool {
        // Empty / unresolved / wildcard IPs can never belong to a real
        // convergence signal — they're the product of enrichment gaps.
        let trimmed = ip.trimmingCharacters(in: .whitespaces)
        if trimmed.isEmpty { return true }
        if trimmed == "::" || trimmed == "0.0.0.0" { return true }
        // Must look like an IP: contain a dot (IPv4) or colon (IPv6).
        if !trimmed.contains(".") && !trimmed.contains(":") { return true }
        for prefix in Self.ignoredNetworkPrefixes {
            if trimmed.hasPrefix(prefix) { return true }
        }
        return false
    }

    /// Return only events within the correlation window relative to the most
    /// recent event in the list.
    private func eventsWithinWindow(_ events: [ChainEvent]) -> [ChainEvent] {
        guard let latest = events.max(by: { $0.timestamp < $1.timestamp }) else {
            return []
        }
        let cutoff = latest.timestamp.addingTimeInterval(-correlationWindow)
        return events.filter { $0.timestamp >= cutoff }
    }

    // MARK: - Purge Helpers

    /// Rebuild the per-file distinct-PID upper-bound index (`fileArtifactPIDs`)
    /// from the surviving artifact map. Called after pruning/eviction so the
    /// index tracks exactly the keys still present in `fileArtifacts` (bounding
    /// its memory) and reflects only their stored PIDs — which remain an upper
    /// bound on the windowed distinct-PID count, since the in-window events are
    /// always a subset of the stored events.
    private func rebuildFilePIDIndex(
        _ map: [String: [ChainEvent]]
    ) -> [String: Set<Int32>] {
        var result: [String: Set<Int32>] = [:]
        result.reserveCapacity(map.count)
        for (key, events) in map {
            result[key] = Set(events.map(\.pid))
        }
        return result
    }

    /// Run a purge pass if enough time has elapsed since the last one
    /// (at most once per 30 seconds).
    private func purgeIfNeeded() {
        let now = Date()
        if now.timeIntervalSince(lastPurge) > 30 {
            purgeStale()
        }
    }
}
