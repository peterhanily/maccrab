// AgentTracesConfig.swift
// MacCrabCore
//
// v1.9 Phase-3 — operator-controlled receiver toggle. Pre-Phase-3 the
// OTLP receiver was env-var-only (MACCRAB_OTLP_RECEIVER=1) which meant
// dashboard users couldn't enable agent traces without a terminal.
//
// File layout follows the v1.6.19 NotificationIntegrations pattern:
//   * Dashboard (user) writes to ~/Library/Application Support/MacCrab/agent_traces_config.json
//   * Daemon (root) checks resolver-validated homes for the same uid-bound
//     file and applies the most recent.
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
    static let maxConfigBytes = 64 * 1024

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
        guard let data = BoundedRegularFileReader.read(
                  at: path,
                  maximumBytes: maxConfigBytes
              ),
              let cfg = try? JSONDecoder().decode(AgentTracesConfig.self, from: data) else {
            return nil
        }
        return cfg
    }

    /// Resolve the EFFECTIVE config the daemon should obey. Mirrors
    /// NotificationIntegrations.loadEffectiveConfig: try the system
    /// path first, then inspect every resolver-validated local home for the
    /// most-recent uid-bound user file. Falls back to default.
    public static func loadEffective() -> AgentTracesConfig {
        let systemSnapshot = configSnapshot(at: systemPath)
        let systemCfg = systemSnapshot.flatMap(decodeConfig)

        // A valid root-owned system config is authoritative. Do not inspect a
        // user-home carrier that cannot affect the result; an ignored FIFO used
        // to block the root daemon before this precedence decision ran.
        if let systemCfg, systemSnapshot?.ownerUID == 0 {
            return systemCfg
        }

        let userCandidate = findUserHomeConfigSnapshot()
        let userCfg = userCandidate.flatMap { decodeConfig($0.snapshot) }
        switch (systemCfg, userCfg) {
        case (nil, nil):
            return .defaultConfig
        case (let sc?, nil):
            return sc
        case (nil, let uc?):
            return uc
        case (let sc?, let uc?):
            // Any valid root-owned system config returned above. Reaching this
            // case therefore means the system path is non-root-owned (the dev
            // ~/Library path); retain its legacy mtime precedence behavior.
            let sm = systemSnapshot?.modificationDate ?? .distantPast
            let um = userCandidate?.snapshot.modificationDate ?? .distantPast
            return um > sm ? uc : sc
        }
    }

    /// Inspect resolver-validated homes for an agent_traces_config.json owned
    /// by the home's uid. Returns the most recent matching path, or nil.
    public static func findUserHomeConfigPath() -> String? {
        findUserHomeConfigSnapshot()?.path
    }

    private static func configSnapshot(
        at path: String
    ) -> BoundedRegularFileReader.Snapshot? {
        guard case .success(let snapshot) = BoundedRegularFileReader.readOutcome(
            at: path,
            maximumBytes: maxConfigBytes
        ) else { return nil }
        return snapshot
    }

    private static func decodeConfig(
        _ snapshot: BoundedRegularFileReader.Snapshot
    ) -> AgentTracesConfig? {
        try? JSONDecoder().decode(AgentTracesConfig.self, from: snapshot.data)
    }

    private static func findUserHomeConfigSnapshot()
        -> (path: String, snapshot: BoundedRegularFileReader.Snapshot)? {
        var candidates: [(path: String, snapshot: BoundedRegularFileReader.Snapshot)] = []
        for home in RealUserHomeResolver.all() {
            let path = home.appending("Library/Application Support/MacCrab/" + filename)
            guard let snapshot = configSnapshot(at: path),
                  home.userID == snapshot.ownerUID else { continue }
            // v1.21.4 audit A2-01 added this admin gate to the other four
            // user-home config sites and missed this one: without it any
            // NON-admin local user (standard account, guest, service account with
            // a home under /Users) steers the root daemon's OTLP receiver.
            guard Self.isAdminUID(home.userID) else { continue }
            candidates.append((path: path, snapshot: snapshot))
        }
        return candidates.max(by: {
            $0.snapshot.modificationDate < $1.snapshot.modificationDate
        })
    }

    /// Mirrors `NotificationIntegrations.isAdminUID` / `ResponseAction.isAdminUID`
    /// / `DaemonTimers.isAdminUID` — those are file-private and cannot be reached
    /// cross-file, so this is replicated for the same reason they are.
    private static func isAdminUID(_ uid: UInt32) -> Bool {
        guard let pw = getpwuid(uid) else { return false }
        let name = String(cString: pw.pointee.pw_name)
        let baseGID = Int32(bitPattern: pw.pointee.pw_gid)
        var ngroups: Int32 = 64
        var groups = [Int32](repeating: 0, count: Int(ngroups))
        if getgrouplist(name, baseGID, &groups, &ngroups) == -1 {
            // Buffer too small; ngroups now holds the needed size — retry once.
            groups = [Int32](repeating: 0, count: Int(ngroups))
            guard getgrouplist(name, baseGID, &groups, &ngroups) != -1 else { return false }
        }
        return groups.prefix(Int(ngroups)).contains(80)   // gid 80 == admin
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
