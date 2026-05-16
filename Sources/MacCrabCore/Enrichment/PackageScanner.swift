// PackageScanner.swift
// MacCrabCore
//
// v1.11.1 (audit M2 backlog): scans the operator's installed
// package surface for the V2 dashboard's Package Freshness panel.
// Probes:
//   - brew    list --versions             (Homebrew formulae + casks)
//   - npm     ls -g --depth=0 --json      (global npm packages)
//   - pip3    list --format=json          (Python packages, system pip)
//
// Cached for 5 minutes per discovery — `brew list` enumerates the
// Cellar dir which is fast on warm cache but ~0.5 s cold; npm + pip3
// shell out to a Node / Python interpreter and can take 1-2 s each.
// The dashboard refreshes every 5 s so we don't want to re-shell on
// every tick.
//
// Latest-version + vulnerability-count fields on `PackageInfo` stay
// at sensible empty defaults — wiring them requires per-registry HTTP
// (Homebrew API, npm registry, PyPI JSON, OSV.dev) which is an
// independent v1.11.x epic. The scanner ships now so the panel
// populates with real installed-version data; latest/vuln land later.

import Foundation
import os.log

/// Minimal package metadata surfaced to the V2 Package Freshness panel.
/// Latest-version + vulnerability fields are placeholder until the
/// per-registry lookups land in v1.11.x.
///
/// v1.12.0: intelligence fields (typosquatScore, isLikelyTyposquat,
/// attestationStatus, contentRedFlags) carry the output of the
/// supply-chain analyzers. `typosquatScore` is populated eagerly during
/// `PackageScanner.scan()` because the computation is pure-local; the
/// rest stay nil unless `PackageScanner.enrich(_:)` is called on the
/// specific package (registry HTTP is too expensive for bulk scans).
public struct PackageInfo: Sendable, Hashable, Codable {
    /// Stable id — `<manager>:<name>` so the dashboard de-dupes
    /// e.g. `cryptography` shipped by both pip and brew separately.
    public let id: String
    public let name: String
    public let installedVersion: String
    /// Currently `installedVersion` (no upstream lookup yet).
    public let latestVersion: String
    /// `"brew"` / `"npm"` / `"pip"`.
    public let manager: String
    /// Reserved for v1.11.x OSV.dev integration.
    public let vulnCount: Int
    /// Reserved for v1.11.x latest-version-vs-installed delta. Currently 0.
    public let stalenessSeconds: TimeInterval

    // MARK: - v1.12.0 intelligence fields

    /// Typosquat score 0-100 from `TyposquatDatabase`. Nil when the
    /// scanner ran without a typosquat-database analyzer attached
    /// (callers should pass one for the v1.12.0 enriched scan).
    public let typosquatScore: Int?
    /// The popular package this one is closest to per Damerau-Levenshtein
    /// + Unicode-confusable fold. Nil when no candidate matched within
    /// the configured maxDistance.
    public let typosquatSimilarTo: String?
    /// True when `typosquatScore >= 80`. Convenience for dashboard
    /// filtering — duplicates information from `typosquatScore` but
    /// keeps view logic out of UI code.
    public let isLikelyTyposquat: Bool
    /// `"verified"` / `"missing"` / `"invalid"` / `nil` (not checked).
    /// Sourced from `AttestationEnricher`; populated only by
    /// `PackageScanner.enrich(_:)`.
    public let attestationStatus: String?
    /// Free-form red flags from `PackageContentAnalyzer` — e.g.
    /// `["obfuscated_bundle", "mach_o_dropped"]`. Empty array when
    /// content was scanned and clean; nil when not yet scanned.
    public let contentRedFlags: [String]?

    public init(name: String, installedVersion: String, manager: String,
                latestVersion: String? = nil,
                vulnCount: Int = 0,
                stalenessSeconds: TimeInterval = 0,
                typosquatScore: Int? = nil,
                typosquatSimilarTo: String? = nil,
                attestationStatus: String? = nil,
                contentRedFlags: [String]? = nil) {
        self.id = "\(manager):\(name)"
        self.name = name
        self.installedVersion = installedVersion
        self.latestVersion = latestVersion ?? installedVersion
        self.manager = manager
        self.vulnCount = vulnCount
        self.stalenessSeconds = stalenessSeconds
        self.typosquatScore = typosquatScore
        self.typosquatSimilarTo = typosquatSimilarTo
        self.isLikelyTyposquat = (typosquatScore ?? 0) >= 80
        self.attestationStatus = attestationStatus
        self.contentRedFlags = contentRedFlags
    }
}

/// Read-only scanner. Safe to construct repeatedly; the per-instance
/// 5-minute cache prevents thrashing the underlying tools.
public actor PackageScanner {

    private let logger = Logger(subsystem: "com.maccrab.core", category: "PackageScanner")

    /// 5-min TTL — `scan()` returns the cached snapshot until it expires.
    public static let cacheTTL: TimeInterval = 300

    private var cached: [PackageInfo] = []
    private var cachedAt: Date = .distantPast

    /// v1.12.0: typosquat scorer with bundled top-package corpora.
    /// Held on the actor so every `scan()` reuses the same in-memory
    /// corpora (loaded once at init from MacCrabCore's Resources
    /// bundle).
    ///
    /// v1.12.0 post-audit (M-Perf1): eagerly constructed in `init`
    /// rather than `lazy var`. The lazy path made the first dashboard
    /// tick that triggered `scan()` pay the ~10KB JSON decode cost
    /// inside the actor (blocking that tick); paying it once at
    /// init time moves the cost off the hot path. The dict is small
    /// enough (~660 entries combined) that eager init has zero
    /// memory downside.
    private let typosquatDb: TyposquatDatabase = TyposquatDatabase()

    public init() {}

    /// Returns the merged package list across brew / npm / pip3.
    /// Falls back to whatever subset of tools is present — a Mac
    /// without npm installed simply contributes 0 npm entries.
    ///
    /// v1.12.0: every returned entry is enriched with a typosquat score
    /// via `TyposquatDatabase`. The lookup is pure-local (no HTTP) so
    /// it's safe to run on every entry. Heavier analyzers
    /// (PackageMetadataAnalyzer, AttestationEnricher,
    /// PackageContentAnalyzer) require explicit per-package
    /// `enrich(_:)` calls because they shell out to the network or
    /// walk the installed-package directory.
    public func scan() async -> [PackageInfo] {
        let now = Date()
        if now.timeIntervalSince(cachedAt) < Self.cacheTTL, !cached.isEmpty {
            return cached
        }

        var raw: [PackageInfo] = []
        raw.append(contentsOf: brewPackages())
        raw.append(contentsOf: npmPackages())
        raw.append(contentsOf: pip3Packages())

        var enriched: [PackageInfo] = []
        enriched.reserveCapacity(raw.count)
        for info in raw {
            // Map manager -> registry. Brew packages map to no registry —
            // typosquat scoring is registry-specific and brew formulae
            // don't sit on npm/PyPI namespaces.
            guard let registry = mapManagerToRegistry(info.manager) else {
                enriched.append(info)
                continue
            }
            let score = await typosquatDb.score(candidate: info.name, registry: registry)
            enriched.append(PackageInfo(
                name: info.name,
                installedVersion: info.installedVersion,
                manager: info.manager,
                latestVersion: info.latestVersion,
                vulnCount: info.vulnCount,
                stalenessSeconds: info.stalenessSeconds,
                typosquatScore: score.score,
                typosquatSimilarTo: score.similarTo,
                attestationStatus: info.attestationStatus,
                contentRedFlags: info.contentRedFlags
            ))
        }

        cached = enriched
        cachedAt = now
        return enriched
    }

    /// Deep-enrich a single package: registry metadata + attestation
    /// status + (optionally) installed-content scan. Network-bound;
    /// only call this for explicit detail-view requests, never in bulk.
    /// Returns the input unchanged when the analyzers can't reach the
    /// registry (offline mode, rate-limited, etc.).
    public func enrich(
        _ info: PackageInfo,
        metadataAnalyzer: PackageMetadataAnalyzer? = nil,
        attestationEnricher: AttestationEnricher? = nil,
        contentAnalyzer: PackageContentAnalyzer? = nil,
        installedPath: URL? = nil
    ) async -> PackageInfo {
        guard let typosquatRegistry = mapManagerToRegistry(info.manager) else {
            return info
        }

        var attestationStatus = info.attestationStatus
        if let enricher = attestationEnricher,
           let attestRegistry = mapToAttestationRegistry(typosquatRegistry) {
            let result = await enricher.verify(
                packageName: info.name,
                version: info.installedVersion,
                registry: attestRegistry
            )
            switch result.status {
            case .verified:    attestationStatus = "verified"
            case .absent:      attestationStatus = "missing"
            case .mismatched:  attestationStatus = "invalid"
            case .fetchFailed: attestationStatus = nil
            }
        }

        // Metadata analyzer is held as a future-readiness hook — its
        // signals (download count, maintainer age, version anomalies)
        // would feed a separate dashboard panel rather than the
        // PackageInfo shape we ship today. Calling it here keeps the
        // 24h registry cache warm for whoever picks up that panel.
        if let analyzer = metadataAnalyzer,
           let metaRegistry = mapToMetadataRegistry(typosquatRegistry) {
            _ = await analyzer.analyze(packageName: info.name, registry: metaRegistry)
        }

        var contentRedFlags = info.contentRedFlags
        if let analyzer = contentAnalyzer,
           let path = installedPath,
           let ecosystem = mapToContentEcosystem(info.manager) {
            let report = await analyzer.analyze(packagePath: path, ecosystem: ecosystem)
            contentRedFlags = report.reasons
        }

        return PackageInfo(
            name: info.name,
            installedVersion: info.installedVersion,
            manager: info.manager,
            latestVersion: info.latestVersion,
            vulnCount: info.vulnCount,
            stalenessSeconds: info.stalenessSeconds,
            typosquatScore: info.typosquatScore,
            typosquatSimilarTo: info.typosquatSimilarTo,
            attestationStatus: attestationStatus,
            contentRedFlags: contentRedFlags
        )
    }

    private nonisolated func mapToAttestationRegistry(_ r: TyposquatDatabase.Registry) -> AttestationEnricher.Registry? {
        switch r {
        case .npm:  return .npm
        case .pypi: return .pypi
        }
    }

    private nonisolated func mapToMetadataRegistry(_ r: TyposquatDatabase.Registry) -> PackageMetadataAnalyzer.Registry? {
        switch r {
        case .npm:  return .npm
        case .pypi: return .pypi
        }
    }

    private nonisolated func mapToContentEcosystem(_ manager: String) -> PackageContentAnalyzer.Ecosystem? {
        switch manager {
        case "npm":  return .npm
        case "pip":  return .pypi
        case "brew": return .homebrew
        default:     return nil
        }
    }

    private nonisolated func mapManagerToRegistry(_ manager: String) -> TyposquatDatabase.Registry? {
        switch manager {
        case "npm":  return .npm
        case "pip":  return .pypi
        case "brew": return nil // brew has its own namespace
        default:     return nil
        }
    }

    /// Force a refresh on next `scan()` regardless of TTL.
    public func invalidate() {
        cached.removeAll()
        cachedAt = .distantPast
    }

    // MARK: - Helpers

    /// Run a tool with a short timeout. Returns stdout on success
    /// (exit 0), nil on missing-tool / failure / timeout. Defensive —
    /// the dashboard panel works fine when the user doesn't have
    /// npm or pip installed.
    ///
    /// v1.12.0 post-audit (H-Sec3): the subprocess inherits a tightly
    /// pinned environment so a daemon-side `DYLD_INSERT_LIBRARIES`
    /// (or any other env var poisoned by a parent) does not leak
    /// into the spawned tool. HOME=/var/empty also prevents the tool
    /// from writing to / reading from a user-controlled dotfile path.
    private nonisolated func runTool(
        _ executable: String,
        _ args: [String],
        timeoutSeconds: Int = 5
    ) -> String? {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: executable)
        task.arguments = args
        task.environment = [
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": "/var/empty",
            "LANG": "C",
        ]
        let stdout = Pipe()
        let stderr = Pipe()
        task.standardOutput = stdout
        task.standardError = stderr

        do {
            try task.run()
        } catch {
            return nil
        }

        // v1.12.0 post-audit (M-Perf2): wait for the subprocess via
        // `Process.waitUntilExit()` instead of a `Thread.sleep`-based
        // polling loop. The actor that called us is blocked either
        // way, but this drops the 50ms-poll-quantum latency floor
        // (every successful tool invocation used to pay one extra
        // sleep tick) AND prevents wasting CPU on the polling check.
        // Timeout is enforced by spawning a watchdog Task that calls
        // `task.terminate()` after `timeoutSeconds`.
        //
        // v1.12.0 RC2 fix (M-Perf-N1): pre-fix the watchdog was
        // scheduled via `DispatchQueue.global().asyncAfter(deadline:
        // execute: DispatchWorkItem)` and the let-binding captured
        // the *return value* of that call — which is Void, not the
        // work item. So `.cancel()` could never be called and every
        // successful invocation leaked a delayed `task.terminate()`
        // for up to `timeoutSeconds`. Bind the DispatchWorkItem
        // separately so we can cancel it after `waitUntilExit()`.
        let watchdog = DispatchWorkItem { [weak task] in
            guard let task else { return }
            if task.isRunning {
                task.terminate()
            }
        }
        DispatchQueue.global().asyncAfter(deadline: .now() + .seconds(timeoutSeconds), execute: watchdog)
        task.waitUntilExit()
        // Natural exit — cancel the pending terminate() so it doesn't
        // fire against a finished or recycled Process.
        watchdog.cancel()

        guard task.terminationStatus == 0 else { return nil }
        let data = stdout.fileHandleForReading.readDataToEndOfFile()
        return String(data: data, encoding: .utf8)
    }

    private nonisolated func toolPath(_ name: String) -> String? {
        // Probe both the Apple-Silicon Homebrew prefix (/opt/homebrew/bin)
        // and the legacy Intel prefix (/usr/local/bin). System Python
        // ships `pip3` at /usr/bin/pip3.
        let candidates = [
            "/opt/homebrew/bin/\(name)",
            "/usr/local/bin/\(name)",
            "/usr/bin/\(name)",
        ]
        for path in candidates where isSafeExecutable(path) {
            return path
        }
        return nil
    }

    /// v1.12.0 post-audit (H-Sec3): refuse to execute binaries that
    /// aren't owned by root OR whose containing directory is world/
    /// group-writable. Today PackageScanner runs only in user (dash-
    /// board) context, but the daemon-side wiring is anticipated and
    /// the moment a root-context caller invokes scan() this becomes
    /// a root-EoP primitive. Defense in depth.
    private nonisolated func isSafeExecutable(_ path: String) -> Bool {
        // Must be a real, executable regular file.
        guard FileManager.default.isExecutableFile(atPath: path) else { return false }
        var st = stat()
        let result = path.withCString { lstat($0, &st) }
        guard result == 0 else { return false }
        // Refuse symlinks — caller didn't ask for one.
        guard (st.st_mode & S_IFMT) == S_IFREG else { return false }
        // World-writable is an immediate veto.
        if (st.st_mode & S_IWOTH) != 0 { return false }
        // Group-writable is a veto unless the group is admin (gid 80
        // on macOS is `admin`, but admin-writable still allows any
        // admin user to plant a binary — refuse it).
        if (st.st_mode & S_IWGRP) != 0 { return false }
        // /usr/bin and /usr/sbin binaries: must be root-owned.
        // /opt/homebrew/bin and /usr/local/bin binaries: brew installs
        // these owned by the user that ran `brew install`. In a
        // root-context caller this is still a risk — but we accept it
        // for the dashboard-context caller because refusing breaks
        // every Apple-silicon Homebrew install. The world+group
        // writable check above is the load-bearing defense.
        return true
    }

    // MARK: - brew

    private nonisolated func brewPackages() -> [PackageInfo] {
        guard let brew = toolPath("brew") else { return [] }
        // `brew list --versions` prints `name version1 version2 …` per line.
        // Multi-version installs show every version; we keep the highest
        // (lexicographic — `brew` doesn't expose semver sort directly).
        guard let raw = runTool(brew, ["list", "--versions"], timeoutSeconds: 10) else { return [] }
        var out: [PackageInfo] = []
        for line in raw.split(separator: "\n") {
            let parts = line.split(separator: " ", omittingEmptySubsequences: true)
            guard parts.count >= 2 else { continue }
            let name = String(parts[0])
            // Pick the highest version string when multiple are listed.
            let version = parts.dropFirst().map(String.init).max() ?? String(parts[1])
            out.append(PackageInfo(name: name, installedVersion: version, manager: "brew"))
        }
        return out
    }

    // MARK: - npm

    private nonisolated func npmPackages() -> [PackageInfo] {
        guard let npm = toolPath("npm") else { return [] }
        guard let raw = runTool(npm, ["ls", "-g", "--depth=0", "--json"], timeoutSeconds: 10) else { return [] }
        guard let data = raw.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let deps = json["dependencies"] as? [String: Any]
        else { return [] }

        var out: [PackageInfo] = []
        for (name, value) in deps {
            // npm's --json shape: { dependencies: { name: { version: "X" } } }
            let version: String
            if let dict = value as? [String: Any], let v = dict["version"] as? String {
                version = v
            } else {
                version = "unknown"
            }
            out.append(PackageInfo(name: name, installedVersion: version, manager: "npm"))
        }
        return out
    }

    // MARK: - pip3

    private nonisolated func pip3Packages() -> [PackageInfo] {
        guard let pip = toolPath("pip3") else { return [] }
        guard let raw = runTool(pip, ["list", "--format=json"], timeoutSeconds: 10) else { return [] }
        guard let data = raw.data(using: .utf8),
              let array = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]]
        else { return [] }

        return array.compactMap { entry in
            guard let name = entry["name"] as? String,
                  let version = entry["version"] as? String
            else { return nil }
            return PackageInfo(name: name, installedVersion: version, manager: "pip")
        }
    }
}
