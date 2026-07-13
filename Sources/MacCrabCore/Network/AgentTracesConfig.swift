// AgentTracesConfig.swift
// MacCrabCore
//
// v1.9 Phase-3 — operator-controlled receiver toggle. Pre-Phase-3 the
// OTLP receiver was env-var-only (MACCRAB_OTLP_RECEIVER=1) which meant
// dashboard users couldn't enable agent traces without a terminal.
//
// File layout follows the v1.6.19 NotificationIntegrations pattern:
//   * Dashboard (user) writes to ~/Library/Application Support/MacCrab/agent_traces_config.json
//   * Daemon (root) walks /Users/* for the same file (uid-validated against
//     each home's owner) and applies the most recent.
//   * Daemon SIGHUP triggers reload + receiver lifecycle change.
//   * Daemon's own /Library/Application Support/MacCrab/agent_traces_config.json
//     is read first if present (operator can preconfigure).

import Foundation
import os.log

/// One config record. The dashboard writes; the daemon reads.
public struct AgentTracesConfig: Sendable, Codable, Equatable {
    /// v1.21.4 Phase-6 6A: master enable for the whole agent-traces
    /// stack — the producer env-scan (TRACEPARENT lift on NOTIFY_EXEC),
    /// the TraceRegistry, and the event correlation that stamps
    /// `agent_trace_id`. Default false (opt-in). The shipped System
    /// Extension can't be handed an env var, so this file field is the
    /// only way to reach the master gate on a release build; on a dev
    /// build `MACCRAB_AGENT_TRACES=1` still works and is OR'd with this.
    /// JSON key: `agent_traces_enabled`.
    public var enabled: Bool
    /// Whether the OTLP receiver should be running. Default false. Only
    /// takes effect when the master `enabled` is also on.
    public var receiverEnabled: Bool
    /// TCP port for the receiver. Default OTel canonical 4318.
    public var port: UInt16

    public init(enabled: Bool = false, receiverEnabled: Bool = false, port: UInt16 = 4318) {
        self.enabled = enabled
        self.receiverEnabled = receiverEnabled
        self.port = port
    }

    private enum CodingKeys: String, CodingKey {
        case enabled = "agent_traces_enabled"
        case receiverEnabled
        case port
    }

    /// Tolerant decode: any missing key falls back to its default so a
    /// partial config — or an older file written before the `enabled`
    /// master existed — keeps decoding instead of reverting the whole
    /// record to defaults (the DaemonConfig snake-case decoder hazard).
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? false
        self.receiverEnabled = try c.decodeIfPresent(Bool.self, forKey: .receiverEnabled) ?? false
        self.port = try c.decodeIfPresent(UInt16.self, forKey: .port) ?? 4318
    }

    public static let defaultConfig = AgentTracesConfig()
}

/// File-IO helpers. No state — just pure functions for read / write
/// and the userhome walk.
public enum AgentTracesConfigStore {

    public static let filename = "agent_traces_config.json"
    public static let systemPath = "/Library/Application Support/MacCrab/" + filename

    private static let logger = Logger(subsystem: "com.maccrab.network", category: "agent-traces-config")

    /// Atomic write to `path`. Used by the dashboard to persist the
    /// operator's toggle. Mirrors the temp-rename pattern from
    /// AgentLineageService.
    @discardableResult
    public static func write(_ config: AgentTracesConfig, to path: String) -> Bool {
        let url = URL(fileURLWithPath: path)
        do {
            try FileManager.default.createDirectory(
                at: url.deletingLastPathComponent(),
                withIntermediateDirectories: true,
                attributes: nil
            )
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let data = try encoder.encode(config)
            let tmpURL = url.appendingPathExtension("tmp")
            try data.write(to: tmpURL, options: .atomic)
            try FileManager.default.replaceItemAt(url, withItemAt: tmpURL)
            return true
        } catch {
            logger.error("write failed: \(error.localizedDescription, privacy: .public)")
            return false
        }
    }

    /// Read from `path`. Returns nil on missing file or malformed JSON.
    public static func read(from path: String) -> AgentTracesConfig? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let cfg = try? JSONDecoder().decode(AgentTracesConfig.self, from: data) else {
            return nil
        }
        return cfg
    }

    /// Resolve the EFFECTIVE config the daemon should obey. Mirrors
    /// NotificationIntegrations.loadEffectiveConfig: try the system
    /// path first, then walk /Users/* for the most-recent
    /// uid-validated user-home file. Falls back to default.
    public static func loadEffective() -> AgentTracesConfig {
        let systemCfg = read(from: systemPath)
        let userPath = findUserHomeConfigPath()
        let userCfg = userPath.flatMap { read(from: $0) }
        let fm = FileManager.default
        let systemMtime = (try? fm.attributesOfItem(atPath: systemPath))?[.modificationDate] as? Date
        let userMtime = userPath.flatMap {
            (try? fm.attributesOfItem(atPath: $0))?[.modificationDate] as? Date
        }
        switch (systemCfg, userCfg) {
        case (nil, nil):
            return .defaultConfig
        case (let sc?, nil):
            return sc
        case (nil, let uc?):
            return uc
        case (let sc?, let uc?):
            let sm = systemMtime ?? .distantPast
            let um = userMtime ?? .distantPast
            return um > sm ? uc : sc
        }
    }

    /// Walk /Users/* for an agent_traces_config.json owned by the home's
    /// uid. Returns the most recent matching path, or nil.
    public static func findUserHomeConfigPath() -> String? {
        let fm = FileManager.default
        guard let users = try? fm.contentsOfDirectory(atPath: "/Users") else { return nil }

        struct Candidate { let path: String; let mtime: Date }
        var candidates: [Candidate] = []
        for user in users where user != "Shared" && !user.hasPrefix(".") {
            let home = "/Users/\(user)"
            let path = home + "/Library/Application Support/MacCrab/" + filename
            guard fm.fileExists(atPath: path) else { continue }
            guard let homeAttrs = try? fm.attributesOfItem(atPath: home),
                  let fileAttrs = try? fm.attributesOfItem(atPath: path) else { continue }
            let homeUID = (homeAttrs[.ownerAccountID] as? NSNumber)?.uint32Value ?? UInt32.max
            let fileUID = (fileAttrs[.ownerAccountID] as? NSNumber)?.uint32Value ?? UInt32.max
            guard homeUID == fileUID, homeUID != UInt32.max else { continue }
            let mtime = (fileAttrs[.modificationDate] as? Date) ?? .distantPast
            candidates.append(Candidate(path: path, mtime: mtime))
        }
        return candidates.max(by: { $0.mtime < $1.mtime })?.path
    }
}

// MARK: - Status snapshot (daemon → dashboard)

/// What the daemon publishes to surface receiver health to the
/// dashboard. Written every time the receiver starts / stops / fails
/// to bind. Read by AppState on the regular refresh tick.
public struct AgentTracesStatus: Sendable, Codable, Equatable {
    public var running: Bool
    public var port: UInt16
    public var lastError: String?
    public var lastErrorAt: Date?
    public var updatedAt: Date

    public init(
        running: Bool,
        port: UInt16,
        lastError: String? = nil,
        lastErrorAt: Date? = nil,
        updatedAt: Date = Date()
    ) {
        self.running = running
        self.port = port
        self.lastError = lastError
        self.lastErrorAt = lastErrorAt
        self.updatedAt = updatedAt
    }
}

public enum AgentTracesStatusStore {

    public static let filename = "agent_traces_status.json"

    private static let logger = Logger(subsystem: "com.maccrab.network", category: "agent-traces-status")

    @discardableResult
    public static func write(_ status: AgentTracesStatus, to directory: String) -> Bool {
        let path = directory + "/" + filename
        let url = URL(fileURLWithPath: path)
        do {
            try FileManager.default.createDirectory(
                at: url.deletingLastPathComponent(),
                withIntermediateDirectories: true,
                attributes: nil
            )
            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .iso8601
            encoder.outputFormatting = [.sortedKeys]
            let data = try encoder.encode(status)
            let tmpURL = url.appendingPathExtension("tmp")
            try data.write(to: tmpURL, options: .atomic)
            try FileManager.default.replaceItemAt(url, withItemAt: tmpURL)
            // 0o644 so the dashboard can read it (it's not sensitive).
            chmod(path, 0o644)
            return true
        } catch {
            logger.error("status write failed: \(error.localizedDescription, privacy: .public)")
            return false
        }
    }

    public static func read(from directory: String) -> AgentTracesStatus? {
        let path = directory + "/" + filename
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
            return nil
        }
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .iso8601
        return try? dec.decode(AgentTracesStatus.self, from: data)
    }
}
