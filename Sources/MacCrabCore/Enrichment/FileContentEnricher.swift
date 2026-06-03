// FileContentEnricher.swift
// MacCrabCore
//
// Reads the first N bytes of a file at close-write time for a small
// allowlist of "interesting" paths and stores the text into
// `event.enrichments["FileContent"]` so detection rules can use
// `FileContent|contains: '...'` selectors.
//
// Background: 10 v1.12.0 rules ship with FileContent predicates but
// the compiler's _KNOWN_PASSTHROUGH_FIELDS only declares the field
// — no enricher previously populated it. The pre-RC audit caught
// this. This enricher closes the gap with a tight allowlist (no
// blanket read of every modified file — way too expensive) and a
// 64 KB head cap.
//
// Allowlist principle: only the files whose content is required by
// a shipped rule, on paths where reading is cheap (already in FS
// cache from the writing process). Read-on-demand, no background
// polling.

import Foundation
import os.log

public actor FileContentEnricher {

    private let logger = Logger(subsystem: "com.maccrab.enrichment", category: "file-content-enricher")

    /// Maximum bytes read from any file. 64 KB covers description /
    /// IOC-marker scans without blowing up the hot path.
    public let maxBytes: Int

    /// Maximum file size we'll attempt to read. Files larger than
    /// this are skipped — they're never the carriers of the marker
    /// strings the rules look for, and reading them would jam the
    /// event loop.
    public let maxFileSize: Int64

    // v1.12.0 RC3 fix (Perf-H1): the broadened allowlist (any *.js/.ts/
    // .py inside node_modules/site-packages — H-Det5) means an `npm
    // install` of a mid-size dep tree creates thousands of matching
    // close-write events, each calling `scan()` synchronously on the
    // enricher actor. To keep the hot path bounded:
    //
    //   1. Cache by (path, mtime, size) — repeated reads of the same
    //      file within npm's install/extract pipeline (which writes →
    //      reads → writes the same files) hit the cache.
    //   2. Cap the cache size with FIFO eviction so memory stays
    //      bounded under storms.
    //   3. Per-second rate limit (token bucket) so even a fresh-files
    //      storm can't consume more than N enricher-ticks/sec.
    private struct CacheEntry {
        let mtime: Int64
        let size: Int64
        let content: String
    }
    private var cache: [String: CacheEntry] = [:]
    private var cacheOrder: [String] = [] // FIFO ring
    private let cacheCap: Int = 512
    private var lastReadAt: Date = .distantPast
    private var readsThisSecond: Int = 0
    private let maxReadsPerSecond: Int = 200

    public init(maxBytes: Int = 64 * 1024, maxFileSize: Int64 = 8 * 1024 * 1024) {
        self.maxBytes = maxBytes
        self.maxFileSize = maxFileSize
    }

    // MARK: - Allowlist

    /// Returns true if the target path should be content-scanned.
    /// Tightly scoped so we only pay the file-read cost on paths
    /// whose content actually carries detection markers.
    nonisolated public static func shouldScan(targetPath: String) -> Bool {
        // Order matters: more-specific checks first so we can early-exit.
        if targetPath.hasSuffix("/Info.plist") { return true }
        if targetPath.hasSuffix(".rb") && targetPath.contains("/Library/Taps/") { return true }
        if targetPath.hasSuffix("/CHANGELOG.md")
            || targetPath.hasSuffix("/CHANGELOG")
            || targetPath.hasSuffix("/RELEASE_NOTES.md")
            || targetPath.hasSuffix("/SECURITY.md")
            || targetPath.hasSuffix("/README.md") { return true }
        if targetPath.hasSuffix("/.gitconfig") || targetPath.hasSuffix("/.git/config") { return true }
        // LaunchAgents / LaunchDaemons plist content — for time-bomb detection.
        if (targetPath.contains("/LaunchAgents/") || targetPath.contains("/LaunchDaemons/"))
            && targetPath.hasSuffix(".plist") { return true }
        // v1.12.0 post-audit (H-Det5): broaden the node_modules /
        // site-packages allowlist beyond 6 specific basenames so the
        // `webhook_exfil_url_in_install_content` rule can actually
        // catch Shai-Hulud-class payloads embedded in arbitrary
        // installed source files. Restricted to the four package-
        // install root paths (npm + yarn + pnpm + pip) plus .js/.mjs/
        // .cjs/.ts/.py extensions — anything else is binary or
        // non-installer content. Size cap on the read still enforces
        // 64KB/8MB upper bounds so this stays cheap on the hot path.
        let installRoots: [String] = [
            "/node_modules/",
            "/site-packages/",
            "/.yarn/cache/",
            "/.npm/_cacache/",
        ]
        let installExtensions: [String] = [".js", ".mjs", ".cjs", ".ts", ".py", ".json"]
        for root in installRoots where targetPath.contains(root) {
            for ext in installExtensions where targetPath.hasSuffix(ext) {
                return true
            }
        }
        // Specific installer-log filenames kept for backward compat
        // (the original v1.12.0 audit cited these IOC carriers).
        let installerLogFiles: [String] = [
            "/bun_environment.js", "/setup_bun.js", "/router_runtime.js",
            "/router_init.js", "/execution.js", "/start.py",
        ]
        for marker in installerLogFiles where targetPath.hasSuffix(marker) { return true }
        // v1.17.4: AI-agent skill / config / hook / CI roots. The 14
        // FileContent|contains rules (skill_md_poisoning_install,
        // mcp_server_suspicious_command, claude_code_project_config_rce,
        // binary_dropped_into_claude_dir, workflow_drop_with_self_hosted_runner,
        // …) all target these paths; before the close-gate fix they were
        // dead, and even after it they stayed dead because shouldScan
        // returned false for them. Bounded volume (these change rarely vs
        // the event firehose) and the 64 KB / 8 MB read caps still apply.
        let agentContentRoots: [String] = [
            "/.claude/skills/", "/.codex/skills/", "/.cursor/skills/",
            "/.claude/scripts/", "/.claude/hooks/", "/.claude/agents/",
            "/.github/workflows/",
        ]
        for root in agentContentRoots where targetPath.contains(root) { return true }
        let agentConfigFiles: [String] = [
            "/.claude/claude_desktop_config.json", "/.claude.json", "/.cursor/mcp.json",
            "/.claude/settings.json", "/.claude/project.json", "/.claude/local.json",
        ]
        for file in agentConfigFiles where targetPath.hasSuffix(file) { return true }
        // NOTE: the non-root maccrabd FSEvents fallback emits no close-class
        // action, so FileContent enrichment is sysext/ES-only by design.
        return false
    }

    /// Read up to `maxBytes` from `path` using SecureFileIO
    /// (O_NOFOLLOW — refuses to read through symlinks). Returns
    /// the decoded UTF-8 text or nil on any error / non-text content
    /// / oversized file.
    ///
    /// v1.12.0 RC3 (Perf-H1): the broadened install-content allowlist
    /// means this function can be hit thousands of times per second
    /// during an `npm install` storm. We cache by (path, mtime, size)
    /// AND token-bucket rate-limit to keep the enricher actor latency
    /// bounded. On rate-limit overflow we return nil — the event
    /// flows through enrichment-less, the rule predicating on
    /// FileContent simply doesn't fire on THAT event, and the next
    /// matching event has a fresh budget.
    public func scan(path: String) -> String? {
        // Pre-flight size check so we don't open giant binaries.
        var st = stat()
        let statResult = path.withCString { lstat($0, &st) }
        guard statResult == 0 else { return nil }
        // Refuse non-regular files (symlinks, devices, FIFOs).
        guard (st.st_mode & S_IFMT) == S_IFREG else { return nil }
        guard st.st_size <= maxFileSize else {
            logger.debug("Skipped oversized file at \(path, privacy: .private)")
            return nil
        }
        // v1.12.0 RC4 fix (Sec-R4-N2): include nanoseconds in the
        // mtime field. Pre-fix tv_sec alone meant an attacker who
        // matched file size + mtime second could replace content and
        // the daemon would return cached stale bytes.
        let mtime = Int64(st.st_mtimespec.tv_sec) * 1_000_000_000 + Int64(st.st_mtimespec.tv_nsec)
        let size = Int64(st.st_size)

        // Cache hit: (path, mtime, size) tuple matches a prior read.
        if let entry = cache[path], entry.mtime == mtime, entry.size == size {
            return entry.content
        }

        // Rate limit: token bucket per wall-clock second.
        let now = Date()
        if now.timeIntervalSince(lastReadAt) >= 1.0 {
            readsThisSecond = 0
            lastReadAt = now
        }
        if readsThisSecond >= maxReadsPerSecond {
            return nil
        }
        readsThisSecond += 1

        guard let data = try? SecureFileIO.readBytes(at: path, maxBytes: maxBytes) else {
            return nil
        }
        let content = String(data: data, encoding: .utf8)
        if let content {
            // FIFO eviction when over cap.
            if cache.count >= cacheCap, let oldest = cacheOrder.first {
                cache.removeValue(forKey: oldest)
                cacheOrder.removeFirst()
            }
            cache[path] = CacheEntry(mtime: mtime, size: size, content: content)
            cacheOrder.append(path)
        }
        return content
    }
}

// MARK: - Darwin imports

import Darwin
