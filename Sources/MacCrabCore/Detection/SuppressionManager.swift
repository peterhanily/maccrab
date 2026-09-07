// SuppressionManager.swift
// MacCrabCore
//
// Allowlist / alert suppression with TTL, scope, audit trail.
// v2 schema — load continues to accept v1 JSON (a flat dict of
// ruleId → [path]) and transparently migrates it on first save.
//
// Scope kinds:
//   rulePath — suppress alert X from process Y (v1 shape)
//   ruleHash — suppress alert X when the process SHA-256 matches
//   rule     — suppress all instances of rule X (universally noisy)
//   path     — suppress all alerts triggered by process Y
//   host     — suppress alerts from a specific hostname
//
// Every add/remove/expire is appended to suppressions_audit.jsonl so
// analysts can reconstruct allowlist history without having to diff the
// live file.

import Foundation
import os.log

// MARK: - SuppressionScope

public enum SuppressionScope: Sendable, Hashable {
    case rulePath(ruleId: String, path: String)
    case ruleHash(ruleId: String, sha256: String)
    case rule(String)
    case path(String)
    case host(String)

    public var kind: String {
        switch self {
        case .rulePath:  return "rule_path"
        case .ruleHash:  return "rule_hash"
        case .rule:      return "rule"
        case .path:      return "path"
        case .host:      return "host"
        }
    }

    /// True for scopes that silence MANY rules at once — a general "trust this
    /// rule / process / host" allowlist. Must-fire critical detections (active
    /// C2 / credential theft) are exempt from these broad scopes so a general
    /// allowlist can't accidentally hide a live attack; the narrow,
    /// rule-specific scopes (`.rulePath` / `.ruleHash`) stay honored for FP
    /// management. See `SuppressionManager.isSuppressed(match:…)`.
    public var isBroad: Bool {
        switch self {
        case .rule, .path, .host: return true
        case .rulePath, .ruleHash: return false
        }
    }

    /// Human-readable one-line summary for UI and CLI tables.
    public var summary: String {
        switch self {
        case let .rulePath(r, p):  return "rule=\(r) path=\(p)"
        case let .ruleHash(r, h):  return "rule=\(r) sha256=\(String(h.prefix(12)))…"
        case let .rule(r):         return "rule=\(r)"
        case let .path(p):         return "path=\(p)"
        case let .host(h):         return "host=\(h)"
        }
    }
}

extension SuppressionScope: Codable {
    private enum CodingKeys: String, CodingKey {
        case type, ruleId, path, sha256, rule, host
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(kind, forKey: .type)
        switch self {
        case let .rulePath(r, p):
            try c.encode(r, forKey: .ruleId)
            try c.encode(p, forKey: .path)
        case let .ruleHash(r, h):
            try c.encode(r, forKey: .ruleId)
            try c.encode(h, forKey: .sha256)
        case let .rule(r):
            try c.encode(r, forKey: .rule)
        case let .path(p):
            try c.encode(p, forKey: .path)
        case let .host(h):
            try c.encode(h, forKey: .host)
        }
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let type = try c.decode(String.self, forKey: .type)
        switch type {
        case "rule_path":
            self = .rulePath(
                ruleId: try c.decode(String.self, forKey: .ruleId),
                path: try c.decode(String.self, forKey: .path)
            )
        case "rule_hash":
            self = .ruleHash(
                ruleId: try c.decode(String.self, forKey: .ruleId),
                sha256: try c.decode(String.self, forKey: .sha256)
            )
        case "rule":
            self = .rule(try c.decode(String.self, forKey: .rule))
        case "path":
            self = .path(try c.decode(String.self, forKey: .path))
        case "host":
            self = .host(try c.decode(String.self, forKey: .host))
        default:
            throw DecodingError.dataCorruptedError(
                forKey: .type, in: c,
                debugDescription: "unknown scope type '\(type)'"
            )
        }
    }
}

// MARK: - SuppressionSource

public enum SuppressionSource: String, Codable, Sendable, Hashable, CaseIterable {
    case cli
    case ui
    case auto
    case migration   // synthesized from a v1 JSON row
}

// MARK: - Suppression

public struct Suppression: Codable, Sendable, Hashable, Identifiable {
    public let id: String
    public let createdAt: Date
    public let expiresAt: Date?
    public let scope: SuppressionScope
    public let source: SuppressionSource
    public let reason: String

    public init(
        id: String = UUID().uuidString,
        createdAt: Date = Date(),
        expiresAt: Date? = nil,
        scope: SuppressionScope,
        source: SuppressionSource,
        reason: String
    ) {
        self.id = id
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.scope = scope
        self.source = source
        self.reason = reason
    }

    /// Has `expiresAt` passed? Permanent entries (`expiresAt == nil`) return false.
    public func isExpired(at now: Date = Date()) -> Bool {
        guard let e = expiresAt else { return false }
        return e <= now
    }
}

// MARK: - SuppressionFile (v2 wire format)

public struct SuppressionFile: Codable, Sendable {
    public let version: Int
    public let entries: [Suppression]
    public let writtenAt: Date?

    public init(version: Int = 2, entries: [Suppression], writtenAt: Date? = nil) {
        self.version = version
        self.entries = entries
        self.writtenAt = writtenAt
    }

    public static func decode(data: Data) throws -> SuppressionFile {
        guard data.count <= 4 * 1024 * 1024 else {
            throw RuntimeConfigContractError("Suppression document exceeds the supported size")
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let document = try decoder.decode(Self.self, from: data)
        guard document.version == 2 else {
            throw RuntimeConfigContractError("Unsupported suppression document version")
        }
        return document
    }

    public static func read(at path: String) throws -> SuppressionFile? {
        guard let data = try RuntimeConfigurationFiles.readControlData(at: path, maximumBytes: 4 * 1024 * 1024) else { return nil }
        return try decode(data: data)
    }

    public static func read(at url: URL) throws -> SuppressionFile? {
        try read(at: url.path)
    }
}

// MARK: - SuppressionAuditEntry

public struct SuppressionAuditEntry: Codable, Sendable, Hashable {
    public enum Action: String, Codable, Sendable {
        case add, remove, expire
    }

    public let timestamp: Date
    public let action: Action
    public let suppressionId: String
    public let scope: SuppressionScope
    public let source: SuppressionSource
    public let reason: String
}

// MARK: - SuppressionManager

public actor SuppressionManager {

    // MARK: - State

    private var entries: [String: Suppression] = [:]

    // Indexes for O(1) match checks.
    private var byRulePath: [String: Set<String>] = [:]
    private var byRuleHash: [String: Set<String>] = [:]
    private var byRuleOnly: Set<String> = []
    private var byPath: Set<String> = []
    private var byHost: Set<String> = []

    private let filePath: String
    private let auditPath: String
    private let publishesReadableSnapshot: Bool
    private let logger = Logger(subsystem: "com.maccrab.detection", category: "SuppressionManager")

    // MARK: - Init

    public init(dataDir: String, publishReadableSnapshot: Bool = false) {
        self.publishesReadableSnapshot = publishReadableSnapshot
        self.filePath = (dataDir as NSString).appendingPathComponent("suppressions.json")
        self.auditPath = (dataDir as NSString).appendingPathComponent("suppressions_audit.jsonl")
    }

    // MARK: - Load / Save

    /// Load suppressions from disk. Accepts v1 (flat dict) or v2 (versioned)
    /// formats. v1 rows are migrated into v2 Suppression records on the fly.
    public func load() {
        let data: Data
        do {
            guard let saved = try RuntimeConfigurationFiles.readControlData(at: filePath, maximumBytes: 4 * 1024 * 1024) else {
                if entries.isEmpty { publishSnapshot() }
                return
            }
            data = saved
        } catch {
            logger.error("Suppression store read failed: \(error.localizedDescription)")
            return
        }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        if let v2 = try? decoder.decode(SuppressionFile.self, from: data), v2.version == 2 {
            loadEntries(v2.entries)
            publishSnapshot()
            logger.info("Loaded \(self.entries.count) v2 suppressions")
            return
        }

        // Fall back to v1 — flat dict of ruleId → [path].
        if let raw = try? JSONDecoder().decode([String: [String]].self, from: data) {
            let migrated = Self.migrateV1(raw)
            loadEntries(migrated)
            logger.info("Migrated \(migrated.count) v1 suppressions to v2 schema")
            // Write back in v2 shape so we don't re-migrate next start.
            saveToDisk()
            return
        }

        logger.warning("Failed to decode suppressions.json as v1 or v2")
    }

    /// Persist entries to disk in v2 format.
    public func save() {
        saveToDisk()
    }

    // MARK: - Queries

    /// Returns true iff the given alert+event pair matches any unexpired entry.
    /// Respects TTL — entries whose expiresAt has passed never match.
    public func isSuppressed(ruleId: String, processPath: String) -> Bool {
        matchingSuppression(ruleId: ruleId, processPath: processPath,
                            processSHA256: nil, hostname: nil) != nil
    }

    /// Match-aware suppression check. Honours the same scope rules as
    /// `isSuppressed(ruleId:processPath:)`, with one exception: a BROAD scope
    /// (`.rule` / `.path` / `.host`) does NOT silence a must-fire critical
    /// (active C2 / credential theft) match — only a narrow `.rulePath` /
    /// `.ruleHash` entry can. This stops a general "trust this process/host"
    /// allowlist from accidentally hiding a live attack, while still allowing
    /// explicit, rule-specific false-positive management. Mirrors the
    /// rule-engine rule that a critical can't be muted by swiping it away.
    public func isSuppressed(
        match: RuleMatch,
        processPath: String,
        processSHA256: String? = nil,
        hostname: String? = nil
    ) -> Bool {
        guard let entry = matchingSuppression(
            ruleId: match.ruleId,
            processPath: processPath,
            processSHA256: processSHA256,
            hostname: hostname
        ) else { return false }
        if entry.scope.isBroad, NoiseFilter.resistsBroadSuppression(match) {
            logger.notice("Broad suppression (\(entry.scope.kind, privacy: .public)) NOT applied to must-fire critical rule=\(match.ruleId, privacy: .public) — broad allowlists can't silence active C2 / credential-theft")
            return false
        }
        return true
    }

    /// Richer check that considers every scope type. Returns the matching
    /// entry so callers can log WHY an alert was silenced.
    public func matchingSuppression(
        ruleId: String,
        processPath: String?,
        processSHA256: String?,
        hostname: String?,
        now: Date = Date()
    ) -> Suppression? {
        // rulePath
        if let path = processPath,
           let paths = byRulePath[ruleId], paths.contains(path),
           let entry = firstUnexpired(for: .rulePath(ruleId: ruleId, path: path), now: now) {
            return entry
        }
        // ruleHash
        if let sha = processSHA256,
           let hashes = byRuleHash[ruleId], hashes.contains(sha),
           let entry = firstUnexpired(for: .ruleHash(ruleId: ruleId, sha256: sha), now: now) {
            return entry
        }
        // rule
        if byRuleOnly.contains(ruleId),
           let entry = firstUnexpired(for: .rule(ruleId), now: now) {
            return entry
        }
        // path
        if let path = processPath, byPath.contains(path),
           let entry = firstUnexpired(for: .path(path), now: now) {
            return entry
        }
        // host
        if let host = hostname, byHost.contains(host),
           let entry = firstUnexpired(for: .host(host), now: now) {
            return entry
        }
        return nil
    }

    public func list(includeExpired: Bool = false, now: Date = Date()) -> [Suppression] {
        let all = Array(entries.values)
        return includeExpired ? all : all.filter { !$0.isExpired(at: now) }
    }

    public func get(id: String) -> Suppression? {
        entries[id]
    }

    public func stats() -> (ruleCount: Int, pathCount: Int, totalEntries: Int, expired: Int) {
        let pathCount = byRulePath.values.reduce(0) { $0 + $1.count }
                      + byPath.count
        let now = Date()
        let expired = entries.values.filter { $0.isExpired(at: now) }.count
        return (byRulePath.count, pathCount, entries.count, expired)
    }

    // MARK: - Mutations

    @discardableResult
    public func add(_ suppression: Suppression) -> Suppression {
        entries[suppression.id] = suppression
        indexInsert(suppression)
        appendAudit(.init(
            timestamp: Date(),
            action: .add,
            suppressionId: suppression.id,
            scope: suppression.scope,
            source: suppression.source,
            reason: suppression.reason
        ))
        lastPersistError = saveToDisk()
        logger.info("Suppression added id=\(suppression.id) scope=\(suppression.scope.kind)")
        return suppression
    }

    @discardableResult
    public func remove(id: String) -> Suppression? {
        guard let entry = entries.removeValue(forKey: id) else { return nil }
        indexRemove(entry)
        appendAudit(.init(
            timestamp: Date(),
            action: .remove,
            suppressionId: entry.id,
            scope: entry.scope,
            source: entry.source,
            reason: entry.reason
        ))
        lastPersistError = saveToDisk()
        logger.info("Suppression removed id=\(id)")
        return entry
    }

    /// Persist a removal before changing the running allowlist or appending
    /// its audit outcome. A failed write leaves the existing state intact.
    @discardableResult
    public func removePersisted(ids: Set<String>) throws -> [Suppression] {
        let removed = entries.values.filter { ids.contains($0.id) }
        guard !removed.isEmpty else { return [] }
        let retained = entries.values.filter { !ids.contains($0.id) }.sorted { $0.createdAt < $1.createdAt }
        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            encoder.dateEncodingStrategy = .iso8601
            let data = try encoder.encode(SuppressionFile(entries: retained))
            try SecureFileIO.atomicReplace(at: filePath, data: data, mode: 0o600)
        } catch {
            lastPersistError = error.localizedDescription
            throw error
        }
        lastPersistError = nil
        for entry in removed {
            entries.removeValue(forKey: entry.id)
            indexRemove(entry)
            appendAudit(.init(timestamp: Date(), action: .remove, suppressionId: entry.id,
                              scope: entry.scope, source: entry.source, reason: entry.reason))
        }
        publishSnapshot()
        return removed
    }

    /// Admin-readable saved-state view; the daemon's authoritative allowlist
    /// retains its private permissions. Snapshot errors never claim removal.
    private func publishSnapshot() {
        guard publishesReadableSnapshot else { return }
        let path = URL(fileURLWithPath: filePath).deletingLastPathComponent()
            .appendingPathComponent("suppressions_snapshot.json").path
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        do {
            let data = try encoder.encode(SuppressionFile(
                entries: entries.values.sorted { $0.createdAt < $1.createdAt }, writtenAt: Date()))
            try SecureFileIO.atomicReplace(at: path, data: data, mode: 0o640)
            if geteuid() == 0 {
                try FileManager.default.setAttributes([.groupOwnerAccountID: 80], ofItemAtPath: path)
            }
        } catch {
            logger.error("Saved suppression snapshot could not be published: \(error.localizedDescription)")
        }
    }

    /// Remove every suppression whose TTL has elapsed. Returns the list of
    /// removed entries so the caller can emit audit events or notifications.
    @discardableResult
    public func sweepExpired(now: Date = Date()) -> [Suppression] {
        let expired = entries.values.filter { $0.isExpired(at: now) }
        for entry in expired {
            entries.removeValue(forKey: entry.id)
            indexRemove(entry)
            appendAudit(.init(
                timestamp: now,
                action: .expire,
                suppressionId: entry.id,
                scope: entry.scope,
                source: entry.source,
                reason: entry.reason
            ))
        }
        if !expired.isEmpty {
            saveToDisk()
            logger.info("Expired \(expired.count) suppressions")
        }
        return expired
    }

    /// Wipe all entries. Intended for "reset allowlist" flows; every removal
    /// gets audited.
    public func removeAll() -> Int {
        let ids = Array(entries.keys)
        for id in ids { _ = remove(id: id) }
        return ids.count
    }

    // MARK: - Private helpers

    private func loadEntries(_ list: [Suppression]) {
        entries.removeAll()
        byRulePath.removeAll()
        byRuleHash.removeAll()
        byRuleOnly.removeAll()
        byPath.removeAll()
        byHost.removeAll()
        for entry in list {
            entries[entry.id] = entry
            indexInsert(entry)
        }
    }

    private func indexInsert(_ s: Suppression) {
        switch s.scope {
        case let .rulePath(r, p):
            byRulePath[r, default: []].insert(p)
        case let .ruleHash(r, h):
            byRuleHash[r, default: []].insert(h)
        case let .rule(r):
            byRuleOnly.insert(r)
        case let .path(p):
            byPath.insert(p)
        case let .host(h):
            byHost.insert(h)
        }
    }

    private func indexRemove(_ s: Suppression) {
        switch s.scope {
        case let .rulePath(r, p):
            byRulePath[r]?.remove(p)
            if byRulePath[r]?.isEmpty == true { byRulePath.removeValue(forKey: r) }
        case let .ruleHash(r, h):
            byRuleHash[r]?.remove(h)
            if byRuleHash[r]?.isEmpty == true { byRuleHash.removeValue(forKey: r) }
        case let .rule(r):
            // Only remove the index mark if no other .rule entry targets this id.
            if !entries.values.contains(where: {
                if case .rule(let otherId) = $0.scope, otherId == r { return true }
                return false
            }) { byRuleOnly.remove(r) }
        case let .path(p):
            if !entries.values.contains(where: {
                if case .path(let otherPath) = $0.scope, otherPath == p { return true }
                return false
            }) { byPath.remove(p) }
        case let .host(h):
            if !entries.values.contains(where: {
                if case .host(let otherHost) = $0.scope, otherHost == h { return true }
                return false
            }) { byHost.remove(h) }
        }
    }

    private func firstUnexpired(for scope: SuppressionScope, now: Date) -> Suppression? {
        entries.values.first(where: { $0.scope == scope && !$0.isExpired(at: now) })
    }

    /// Persist the store. Returns the failure reason, or nil on success.
    ///
    /// Used to swallow every error into os.log and return void, so `add()` handed
    /// the caller a Suppression that had NOT been written — on a release install
    /// the store lives under root-owned `/Library/Application Support/MacCrab`, so
    /// every uid-501 `maccrabctl allow add` reported success and persisted
    /// nothing. An operator tuning down false positives believed their allowlist
    /// was in effect while the engine never saw an entry.
    @discardableResult
    private func saveToDisk() -> String? {
        let sorted = entries.values.sorted { $0.createdAt < $1.createdAt }
        let file = SuppressionFile(version: 2, entries: sorted)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        do {
            let data = try encoder.encode(file)
            try data.write(to: URL(fileURLWithPath: filePath), options: .atomic)
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o600], ofItemAtPath: filePath
            )
            publishSnapshot()
            return nil
        } catch {
            logger.error("saveToDisk failed: \(error.localizedDescription)")
            return error.localizedDescription
        }
    }

    /// Where this store persists. Surfaced so a caller can tell the operator
    /// exactly which path a failed write was attempted against.
    public nonisolated var storePath: String { filePath }

    /// Reason the most recent mutation failed to persist, or nil if it landed.
    /// Callers that report success to a human MUST check this — `add` returns a
    /// Suppression whether or not it reached disk.
    public private(set) var lastPersistError: String?

    private func appendAudit(_ entry: SuppressionAuditEntry) {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        guard let data = try? encoder.encode(entry),
              let line = String(data: data, encoding: .utf8) else {
            return
        }
        let full = line + "\n"
        let url = URL(fileURLWithPath: auditPath)

        // v1.10.0 audit fix: rotate when audit log exceeds 50 MB.
        // Pre-fix this jsonl was append-only with no cap; on a busy
        // machine that suppresses hundreds of false positives a day,
        // it would grow indefinitely. Now: when the file passes 50
        // MB, atomically rename it to `.1` (overwriting any prior
        // .1) and start a fresh file. One generation kept; older
        // entries discarded. Audit retention beyond that should be
        // exported via the daemon's syslog/SIEM sinks.
        let maxBytes: UInt64 = 50 * 1024 * 1024
        if let attrs = try? FileManager.default.attributesOfItem(atPath: auditPath),
           let size = attrs[.size] as? UInt64, size > maxBytes {
            let rotated = auditPath + ".1"
            try? FileManager.default.removeItem(atPath: rotated)
            try? FileManager.default.moveItem(atPath: auditPath, toPath: rotated)
            logger.info("suppressions audit rotated at \(size) bytes -> \(rotated)")
        }

        if FileManager.default.fileExists(atPath: auditPath),
           let handle = try? FileHandle(forWritingTo: url) {
            defer { try? handle.close() }
            _ = try? handle.seekToEnd()
            try? handle.write(contentsOf: Data(full.utf8))
        } else {
            try? Data(full.utf8).write(to: url, options: .atomic)
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o600], ofItemAtPath: auditPath
            )
        }
    }

    // MARK: - v1 → v2 migration

    /// Convert a v1 flat dict into Suppression records. Used by `load()` when
    /// it detects the file isn't a v2 SuppressionFile.
    nonisolated static func migrateV1(_ raw: [String: [String]]) -> [Suppression] {
        var out: [Suppression] = []
        let now = Date()
        for (ruleId, paths) in raw {
            for path in paths {
                out.append(Suppression(
                    createdAt: now,
                    expiresAt: nil,
                    scope: .rulePath(ruleId: ruleId, path: path),
                    source: .migration,
                    reason: "migrated from v1 suppressions.json"
                ))
            }
        }
        return out
    }
}
