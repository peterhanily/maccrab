// V2DaemonControl.swift
// Out-of-process actions targeting the running MacCrab daemon /
// system extension.

import Foundation

public enum V2DaemonControl {
    /// Ask the detection engine to reload its rules.
    ///
    /// The release engine is the System Extension, which runs as **root**.
    /// This app runs as the console user, so it CANNOT `pkill -HUP` the
    /// sysext (cross-uid signal → EPERM), and a hardened-runtime app
    /// often can't spawn `pkill` at all. So the primary path drops a
    /// `reload-rules-<token>.json` request into the privileged inbox the
    /// sysext polls (it raises SIGHUP to itself on receipt) — the same
    /// cross-uid-safe channel used by suppress / refresh-intel.
    ///
    /// `pkill -HUP maccrabd` is kept as a best-effort fallback for a
    /// `swift run maccrabd` dev daemon, which runs as the same user and
    /// can be signaled directly.
    ///
    /// Returns true if a reload was successfully requested by either path.
    @discardableResult
    public static func reloadDetectionRules() -> Bool {
        var requested = false

        // Primary: inbox request → root sysext (cross-uid-safe).
        if let inboxDir = resolveInboxDir() {
            requested = writeReloadRulesRequest(inboxDir: inboxDir) || requested
        }

        // Fallback: same-uid dev daemon via pkill.
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
        p.arguments = ["-HUP", "maccrabd"]
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        do {
            try p.run()
            p.waitUntilExit()
            if p.terminationStatus == 0 { requested = true }
        } catch {
            // pkill absent / sandbox-denied — the inbox path is primary.
        }

        return requested
    }

    /// Push the (non-secret) LLM backend config to the ROOT engine via the
    /// privileged inbox. Settings → AI Backend writes the uid-501 user-dir
    /// llm_config.json, which the root sysext never reads (it reads
    /// /Library/.../llm_config.json — a path this app can't write). This
    /// drops an `llm-config-<token>.json` request the sysext validates +
    /// URL-hardens before persisting. Cloud API KEYS are NOT sent here (a
    /// uid-501 file steering a root process's outbound URL + keys is an
    /// SSRF/exfil surface) — only provider, URLs, model names, and the
    /// agentic flag travel this channel; keys travel via the shared
    /// keychain. Returns true if the request was queued.
    @discardableResult
    public static func sendLLMConfig(_ config: [String: Any]) -> Bool {
        guard let inboxDir = resolveInboxDir() else { return false }
        return writeLLMConfigRequest(inboxDir: inboxDir, config: config)
    }

    private static func writeLLMConfigRequest(inboxDir: String, config: [String: Any]) -> Bool {
        let fm = FileManager.default
        if !fm.fileExists(atPath: inboxDir) {
            try? fm.createDirectory(atPath: inboxDir, withIntermediateDirectories: true)
        }
        let path = inboxDir + "/llm-config-\(UUID().uuidString).json"
        var payload = config
        payload["queuedAt"] = ISO8601DateFormatter().string(from: Date())
        payload["source"] = "MacCrabApp"
        guard let data = try? JSONSerialization.data(withJSONObject: payload) else { return false }
        return (try? data.write(to: URL(fileURLWithPath: path), options: .atomic)) != nil
    }

    /// Resolve the data directory the daemon actually writes to, matching
    /// V2LiveDataProvider.pickDataDirectory: prefer the root sysext's
    /// /Library path, else the dev daemon's ~/Library path.
    private static func resolveInboxDir() -> String? {
        let system = "/Library/Application Support/MacCrab"
        let user = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)
            .first?.appendingPathComponent("MacCrab").path
            ?? NSHomeDirectory() + "/Library/Application Support/MacCrab"
        let fm = FileManager.default
        for base in [system, user] {
            if fm.fileExists(atPath: base + "/inbox")
                || fm.fileExists(atPath: base + "/alerts.db")
                || fm.fileExists(atPath: base + "/events.db") {
                return base + "/inbox"
            }
        }
        return nil
    }

    /// Drop a parameterless reload-rules request the daemon coalesces.
    private static func writeReloadRulesRequest(inboxDir: String) -> Bool {
        let fm = FileManager.default
        if !fm.fileExists(atPath: inboxDir) {
            // Usually the sysext created this at boot (mode 1777). On a
            // fresh install this may fail under /Library without
            // elevation — in which case we honestly report failure.
            try? fm.createDirectory(atPath: inboxDir, withIntermediateDirectories: true)
        }
        let path = inboxDir + "/reload-rules-\(UUID().uuidString).json"
        let payload: [String: Any] = [
            "queuedAt": ISO8601DateFormatter().string(from: Date()),
            "source": "MacCrabApp",
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: payload) else {
            return false
        }
        return (try? data.write(to: URL(fileURLWithPath: path), options: .atomic)) != nil
    }

    // MARK: - user_overrides.json (merge-safe)

    /// Merge-safe read-modify-write of the console user's `user_overrides.json`.
    ///
    /// The daemon reads ONE file for both the storage{} tuning block AND the
    /// top-level network-enrichment privacy flags (DaemonConfig.applyUserOverrides
    /// is uid-validated). A whole-file overwrite by one surface would clobber the
    /// other group, so every writer must read the existing file, mutate ONLY its
    /// own keys, and atomically write back. The app runs as the console user and
    /// writes its OWN ~/Library copy — exactly the file applyUserOverrides scans.
    @discardableResult
    public static func writeUserOverrides(_ mutate: (inout [String: Any]) -> Void) -> Bool {
        let dir = NSHomeDirectory() + "/Library/Application Support/MacCrab"
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        let path = dir + "/user_overrides.json"
        var obj: [String: Any] = [:]
        if let data = try? Data(contentsOf: URL(fileURLWithPath: path)) {
            // File EXISTS. If it's present but unparseable, ABORT — a
            // single-group write onto {} would clobber the other group. Only a
            // genuinely absent file legitimately starts from an empty object.
            guard let parsed = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
                return false
            }
            obj = parsed
        }
        mutate(&obj)
        guard let data = try? JSONSerialization.data(withJSONObject: obj, options: [.prettyPrinted, .sortedKeys]) else { return false }
        return (try? data.write(to: URL(fileURLWithPath: path), options: .atomic)) != nil
    }

    /// Persist the four network-enrichment privacy flags (top-level, camelCase —
    /// the shape DaemonConfig.applyUserOverrides reads) and ask the root sysext
    /// to re-read live (cross-uid-safe inbox → self-SIGHUP, which re-applies all
    /// four flags and stops/starts the threat-intel network loop without a
    /// restart). Returns whether a live reload was requested; the file write
    /// itself is durable and applies on the next daemon start regardless (so a
    /// `false` means "saved, applies on next start", not "failed").
    @discardableResult
    public static func applyEnrichmentFlags(threatIntel: Bool, vulnScan: Bool, packageFreshness: Bool, certTransparency: Bool) -> Bool {
        _ = writeUserOverrides { obj in
            obj["threatIntelEnabled"]      = threatIntel
            obj["vulnScanEnabled"]         = vulnScan
            obj["packageFreshnessEnabled"] = packageFreshness
            obj["certTransparencyEnabled"] = certTransparency
        }
        return reloadDetectionRules()
    }
}
