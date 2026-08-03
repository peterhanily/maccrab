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

    /// Agent instruction roots mirrored by ESCollector's OPEN admission.
    /// Internal visibility is intentional: the drift guard exercises the
    /// actual production lists instead of maintaining a third test-only copy.
    nonisolated static let agentContentRoots: [String] = [
        "/.claude/skills/", "/.codex/skills/", "/.cursor/skills/",
        "/.claude/scripts/", "/.claude/hooks/", "/.claude/agents/",
        "/.github/workflows/",
    ]

    /// Exact agent-config suffix set content rules consume. Keep this in
    /// lockstep with ESCollector.agentConfigReadFileSuffixes and the union of
    /// the shipped MCP/config FileContent rule predicates (guarded by tests).
    nonisolated static let agentConfigFileSuffixes: [String] = [
        "/.claude/claude_desktop_config.json", "/.claude.json", "/.cursor/mcp.json",
        "/.continue/config.json", "/.vscode/mcp.json", "/.windsurf/mcp.json",
        "/.claude/settings.json", "/.claude/project.json", "/.claude/local.json",
    ]

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
    //   1. Each admitted read is one stable descriptor snapshot. A path-only
    //      metadata cache can return stale content after same-size/mtime
    //      replacement, so it is not a valid detection shortcut.
    //   2. Per-second rate limit (token bucket) so even a fresh-files
    //      storm can't consume more than N enricher-ticks/sec.
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
        for root in agentContentRoots where targetPath.contains(root) { return true }
        for file in agentConfigFileSuffixes where targetPath.hasSuffix(file) { return true }
        // NOTE: the non-root maccrabd FSEvents fallback emits no close-class
        // action, so FileContent enrichment is sysext/ES-only by design.
        return false
    }

    /// Read up to `maxBytes` from `path` using one descriptor-relative stable
    /// snapshot. Returns
    /// the decoded UTF-8 text or nil on any error / non-text content
    /// / oversized file.
    ///
    /// v1.12.0 RC3 (Perf-H1): the broadened install-content allowlist
    /// means this function can be hit thousands of times per second
    /// during an `npm install` storm. A token-bucket rate limit keeps the
    /// enricher actor latency bounded. On overflow we return nil — the event
    /// flows through enrichment-less, the rule predicating on
    /// FileContent simply doesn't fire on THAT event, and the next
    /// matching event has a fresh budget.
    public func scan(path: String) -> String? {
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

        guard case .success(let snapshot) = BoundedRegularFileReader.readPrefixOutcome(
            at: path,
            maximumBytes: maxBytes
        ) else {
            return nil
        }
        guard snapshot.sizeBytes <= maxFileSize else {
            logger.debug("Skipped oversized file at \(path, privacy: .private)")
            return nil
        }
        return String(data: snapshot.data, encoding: .utf8)
    }
}
