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

    public init(name: String, installedVersion: String, manager: String,
                latestVersion: String? = nil,
                vulnCount: Int = 0,
                stalenessSeconds: TimeInterval = 0) {
        self.id = "\(manager):\(name)"
        self.name = name
        self.installedVersion = installedVersion
        self.latestVersion = latestVersion ?? installedVersion
        self.manager = manager
        self.vulnCount = vulnCount
        self.stalenessSeconds = stalenessSeconds
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

    public init() {}

    /// Returns the merged package list across brew / npm / pip3.
    /// Falls back to whatever subset of tools is present — a Mac
    /// without npm installed simply contributes 0 npm entries.
    public func scan() async -> [PackageInfo] {
        let now = Date()
        if now.timeIntervalSince(cachedAt) < Self.cacheTTL, !cached.isEmpty {
            return cached
        }

        var out: [PackageInfo] = []
        out.append(contentsOf: brewPackages())
        out.append(contentsOf: npmPackages())
        out.append(contentsOf: pip3Packages())

        cached = out
        cachedAt = now
        return out
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
    private nonisolated func runTool(
        _ executable: String,
        _ args: [String],
        timeoutSeconds: Int = 5
    ) -> String? {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: executable)
        task.arguments = args
        let stdout = Pipe()
        let stderr = Pipe()
        task.standardOutput = stdout
        task.standardError = stderr

        do {
            try task.run()
        } catch {
            return nil
        }

        // Cap runtime — a hung subprocess shouldn't wedge the dashboard.
        let deadline = Date().addingTimeInterval(TimeInterval(timeoutSeconds))
        while task.isRunning && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.05)
        }
        if task.isRunning {
            task.terminate()
            return nil
        }

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
        for path in candidates where FileManager.default.isExecutableFile(atPath: path) {
            return path
        }
        return nil
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
