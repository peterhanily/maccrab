// UEBAEngine.swift
// MacCrabCore
//
// Per-user entity behaviour analytics. Tracks a rolling baseline for
// every observed user — login hours, SSH remote IPs, tool-usage
// frequencies — and flags deviations. Addresses the "80% of attacks
// are malware-free / credential abuse" gap that signature and rule
// engines miss.
//
// Cold-start guard: anomalies only fire once a user has accumulated
// minObservationsForScoring events (default 100). New users are
// baselined silently for that period.

import Foundation
import os.log

// MARK: - UserEntityProfile

public struct UserEntityProfile: Codable, Sendable, Hashable {

    public let userName: String
    public var firstSeen: Date
    public var lastObserved: Date

    /// Rolling histogram of observed launch hours (local time), one
    /// bucket per hour of day. Combined across weekdays and weekends —
    /// used as the stable public API (tests depend on hourFrequency(_:)).
    public var loginHourCounts: [Int]

    /// Hour-of-day histograms split by weekday (Mon–Fri) and weekend
    /// (Sat–Sun). Gives sharper anomaly precision: 3 AM on a Saturday
    /// is less suspicious for a night-owl developer than 3 AM on a
    /// Tuesday.
    public var weekdayHourCounts: [Int]
    public var weekendHourCounts: [Int]
    public var weekdayObservations: Int
    public var weekendObservations: Int

    /// Set of SSH source IPs this user has logged in from.
    public var sshRemoteIPs: Set<String>

    /// Per-executable launch counts.
    public var toolUsage: [String: Int]

    /// Sticky completeness markers. Once bounded retention has discarded or
    /// refused history, absence no longer proves novelty. Persisting these
    /// flags prevents an evicted tool or SSH source from becoming a false
    /// "first-ever" signal after a restart.
    public var toolHistorySaturated: Bool
    public var sshHistorySaturated: Bool

    public var totalObservations: Int

    public init(userName: String, now: Date = Date()) {
        self.userName = userName
        self.firstSeen = now
        self.lastObserved = now
        self.loginHourCounts = Array(repeating: 0, count: 24)
        self.weekdayHourCounts = Array(repeating: 0, count: 24)
        self.weekendHourCounts = Array(repeating: 0, count: 24)
        self.weekdayObservations = 0
        self.weekendObservations = 0
        self.sshRemoteIPs = []
        self.toolUsage = [:]
        self.toolHistorySaturated = false
        self.sshHistorySaturated = false
        self.totalObservations = 0
    }

    // MARK: - Codable (backward-compatible)

    private enum CodingKeys: String, CodingKey {
        case userName, firstSeen, lastObserved, loginHourCounts
        case weekdayHourCounts, weekendHourCounts
        case weekdayObservations, weekendObservations
        case sshRemoteIPs, toolUsage, totalObservations
        case toolHistorySaturated, sshHistorySaturated
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        userName              = try c.decode(String.self,   forKey: .userName)
        firstSeen             = try c.decode(Date.self,     forKey: .firstSeen)
        lastObserved          = try c.decode(Date.self,     forKey: .lastObserved)
        loginHourCounts       = try c.decode([Int].self,    forKey: .loginHourCounts)
        weekdayHourCounts     = try c.decodeIfPresent([Int].self, forKey: .weekdayHourCounts)
                                    ?? Array(repeating: 0, count: 24)
        weekendHourCounts     = try c.decodeIfPresent([Int].self, forKey: .weekendHourCounts)
                                    ?? Array(repeating: 0, count: 24)
        weekdayObservations   = try c.decodeIfPresent(Int.self, forKey: .weekdayObservations) ?? 0
        weekendObservations   = try c.decodeIfPresent(Int.self, forKey: .weekendObservations) ?? 0
        sshRemoteIPs          = try c.decode(Set<String>.self,     forKey: .sshRemoteIPs)
        toolUsage             = try c.decode([String: Int].self,   forKey: .toolUsage)
        toolHistorySaturated  = try c.decodeIfPresent(
            Bool.self, forKey: .toolHistorySaturated
        ) ?? false
        sshHistorySaturated   = try c.decodeIfPresent(
            Bool.self, forKey: .sshHistorySaturated
        ) ?? false
        totalObservations     = try c.decode(Int.self,    forKey: .totalObservations)
    }

    // MARK: - Frequency helpers

    /// Ratio of combined (weekday + weekend) observations at this hour.
    /// Stable public API — tests and callers that don't need weekday
    /// precision use this.
    public func hourFrequency(_ hour: Int) -> Double {
        guard (0..<24).contains(hour), totalObservations > 0 else { return 0 }
        return Double(loginHourCounts[hour]) / Double(totalObservations)
    }

    /// Ratio of weekday-only (or weekend-only) observations at this
    /// hour. Returns 0 when the corresponding observation count is too
    /// small to be meaningful (< 5 obs). Falls back to the combined
    /// `hourFrequency` when the split bucket is under-sampled.
    public func hourFrequency(_ hour: Int, isWeekend: Bool) -> Double {
        guard (0..<24).contains(hour) else { return 0 }
        let obs = isWeekend ? weekendObservations : weekdayObservations
        guard obs >= 5 else {
            // Not enough weekday/weekend data yet — fall back to combined.
            return hourFrequency(hour)
        }
        let counts = isWeekend ? weekendHourCounts : weekdayHourCounts
        return Double(counts[hour]) / Double(obs)
    }

    /// True when the tool has never (or almost never) been seen. Uses a
    /// flat minimum-count threshold rather than Welford for v1 since
    /// tool-usage distributions are heavy-tailed and z-score on counts
    /// is unstable for rare tools.
    public func toolIsNovel(_ path: String) -> Bool {
        !toolHistorySaturated && (toolUsage[path] ?? 0) == 0
    }
}

// MARK: - UEBAAnomaly

public struct UEBAAnomaly: Sendable, Hashable {
    public enum Kind: String, Sendable, Hashable, CaseIterable {
        case unusualLoginHour   // activity at an hour < 2% of baseline
        case newSSHSource        // SSH from an IP never seen before
        case novelTool            // process executable never launched by this user before
        case coldStart            // cold-start gate still active (no anomalies possible yet)
    }
    public let kind: Kind
    public let userName: String
    public let detail: String
    public let severity: Severity

    public init(kind: Kind, userName: String, detail: String, severity: Severity) {
        self.kind = kind
        self.userName = userName
        self.detail = detail
        self.severity = severity
    }
}

// MARK: - Alert mapping

/// Deterministic mapping from a `UEBAAnomaly` onto the fields the daemon's
/// alert sink needs. Kept here (rather than at the EventLoop callsite) so the
/// engine owns its own alert framing and the mapping is unit-testable without
/// standing up the daemon.
public extension UEBAAnomaly {

    /// Stable rule id — mirrors the `maccrab.<engine>.<kind>` convention the
    /// other engine-emitted alerts use (e.g. `maccrab.clickfix.paste-and-run`).
    var alertRuleId: String { "maccrab.ueba.\(kind.rawValue)" }

    /// Human-readable alert title.
    var alertTitle: String {
        switch kind {
        case .unusualLoginHour: return "UEBA: activity at an unusual hour for this user"
        case .newSSHSource:     return "UEBA: SSH login from a never-before-seen source"
        case .novelTool:        return "UEBA: first-ever execution of this tool by user"
        case .coldStart:        return "UEBA: baseline still warming (cold start)"
        }
    }

    /// MITRE ATT&CK tactic tags (comma-joined) or nil when none map cleanly.
    var mitreTactics: String? {
        switch kind {
        case .newSSHSource:          return "attack.initial_access,attack.lateral_movement"
        case .unusualLoginHour:      return "attack.initial_access"
        case .novelTool, .coldStart: return nil
        }
    }

    /// MITRE ATT&CK technique tags (comma-joined) or nil. Both credential-abuse
    /// signals map to T1078 (Valid Accounts) — UEBA's remit is malware-free
    /// account/credential misuse, not tool-specific techniques.
    var mitreTechniques: String? {
        switch kind {
        case .newSSHSource:          return "attack.t1078"
        case .unusualLoginHour:      return "attack.t1078"
        case .novelTool, .coldStart: return nil
        }
    }
}

// MARK: - UEBAEngine

public actor UEBAEngine {

    private let logger = Logger(subsystem: "com.maccrab.detection", category: "ueba")

    /// Before this many observations, we baseline silently instead of
    /// alerting. Default 100 events — roughly a day of normal use.
    private let minObservationsForScoring: Int

    /// Hour-frequency ratio below which we call it "unusual". Applies
    /// only once past the cold-start gate.
    private let hourAnomalyThreshold: Double

    private var profiles: [String: UserEntityProfile] = [:]

    /// Hard bounds for adversarial/high-churn identity data. User names and
    /// executable paths originate in event data; neither may be allowed to
    /// mint an unbounded in-memory or persisted UEBA model.
    private let maxProfiles: Int
    private let maxToolsPerProfile: Int
    private let maxSSHRemoteIPsPerProfile: Int
    private let toolEvictionLowWater: Int
    private let sshEvictionLowWater: Int
    private let maxAggregateToolEntries: Int
    private let maxAggregateSSHRemoteIPEntries: Int
    private let maxAggregateEntityUTF8Bytes: Int

    /// Incremental accounting for every variable-cardinality string retained
    /// by the model (user names, executable paths, and SSH sources). The
    /// default entry and byte budgets keep UEBA comfortably inside MacCrab's
    /// 450 MiB process contract even after allowing for Swift collection and
    /// histogram overhead; the persistence ceiling is only a second line of
    /// defence, not the memory bound.
    private var aggregateToolEntries: Int = 0
    private var aggregateSSHRemoteIPEntries: Int = 0
    private var aggregateEntityUTF8Bytes: Int = 0

    /// Fixed-cardinality pressure telemetry. No attacker-controlled identity
    /// is used as a label or dictionary key in these metrics.
    private var modelSaturated = false
    private var profileHistorySaturated = false
    private var saturationEvents: UInt64 = 0
    private var rejectedProfiles: UInt64 = 0
    private var rejectedTools: UInt64 = 0
    private var rejectedSSHRemoteIPs: UInt64 = 0
    private var evictedProfiles: UInt64 = 0
    private var evictedTools: UInt64 = 0
    private var evictedSSHRemoteIPs: UInt64 = 0

    /// Optional on-disk path for profile persistence. When set, load()
    /// must be acknowledged explicitly through `loadPersistedProfiles()`
    /// before observations or saves are accepted.
    private let persistencePath: String?
    private var persistenceReady: Bool
    private static let maximumPersistenceBytes: UInt64 = 32 * 1_024 * 1_024
    private static let maximumUserNameUTF8Bytes = 1_024
    private static let maximumToolPathUTF8Bytes = 4 * 1_024
    private static let maximumSSHRemoteIPUTF8Bytes = 512

    private struct PersistenceEnvelope: Codable {
        let schemaVersion: Int
        let profileHistorySaturated: Bool
        let profiles: [UserEntityProfile]
    }

    public init(
        minObservationsForScoring: Int = 100,
        hourAnomalyThreshold: Double = 0.02,
        persistencePath: String? = nil,
        maxProfiles: Int = 4_096,
        maxToolsPerProfile: Int = 2_000,
        maxSSHRemoteIPsPerProfile: Int = 4_096,
        maxAggregateToolEntries: Int = 50_000,
        maxAggregateSSHRemoteIPEntries: Int = 20_000,
        maxAggregateEntityUTF8Bytes: Int = 8 * 1_024 * 1_024
    ) {
        self.minObservationsForScoring = minObservationsForScoring
        self.hourAnomalyThreshold = hourAnomalyThreshold
        self.persistencePath = persistencePath
        // Injection points may tighten budgets for tests or constrained hosts,
        // but cannot raise the shipping process-memory contract.
        let profileCap = min(4_096, max(1, maxProfiles))
        let toolCap = min(2_000, max(1, maxToolsPerProfile))
        let sshCap = min(4_096, max(1, maxSSHRemoteIPsPerProfile))
        self.maxProfiles = profileCap
        self.maxToolsPerProfile = toolCap
        self.maxSSHRemoteIPsPerProfile = sshCap
        self.toolEvictionLowWater = max(1, Int(Double(toolCap) * 0.9))
        self.sshEvictionLowWater = max(1, Int(Double(sshCap) * 0.9))
        self.maxAggregateToolEntries = min(
            50_000, max(1, maxAggregateToolEntries)
        )
        self.maxAggregateSSHRemoteIPEntries = min(
            20_000, max(1, maxAggregateSSHRemoteIPEntries)
        )
        self.maxAggregateEntityUTF8Bytes = min(
            8 * 1_024 * 1_024, max(1, maxAggregateEntityUTF8Bytes)
        )
        self.persistenceReady = persistencePath == nil
    }

    /// Convenience construction for persisted engines. Unlike the former init
    /// fire-and-forget Task, returning from this factory is a real readiness
    /// boundary: disk state is loaded (or a missing file is acknowledged) and
    /// can no longer overwrite observations made immediately after init.
    public static func loaded(
        minObservationsForScoring: Int = 100,
        hourAnomalyThreshold: Double = 0.02,
        persistencePath: String,
        maxProfiles: Int = 4_096,
        maxToolsPerProfile: Int = 2_000,
        maxSSHRemoteIPsPerProfile: Int = 4_096,
        maxAggregateToolEntries: Int = 50_000,
        maxAggregateSSHRemoteIPEntries: Int = 20_000,
        maxAggregateEntityUTF8Bytes: Int = 8 * 1_024 * 1_024
    ) async -> UEBAEngine? {
        let engine = UEBAEngine(
            minObservationsForScoring: minObservationsForScoring,
            hourAnomalyThreshold: hourAnomalyThreshold,
            persistencePath: persistencePath,
            maxProfiles: maxProfiles,
            maxToolsPerProfile: maxToolsPerProfile,
            maxSSHRemoteIPsPerProfile: maxSSHRemoteIPsPerProfile,
            maxAggregateToolEntries: maxAggregateToolEntries,
            maxAggregateSSHRemoteIPEntries: maxAggregateSSHRemoteIPEntries,
            maxAggregateEntityUTF8Bytes: maxAggregateEntityUTF8Bytes
        )
        guard await engine.loadPersistedProfiles() else { return nil }
        return engine
    }

    // MARK: - Persistence

    /// Serialize every profile to JSON at `persistencePath`. Returns true for
    /// an atomic write or intentional in-memory mode (no path), false when
    /// readiness, encoding, size, write, or permission hardening fails. Daemon
    /// timer should call this every 5 minutes and graceful shutdown must fold
    /// the final result into its clean persistence boundary.
    @discardableResult
    public func save() async -> Bool {
        // No configured persistence is an intentional in-memory mode, not a
        // failed write.
        guard let path = persistencePath else { return true }
        guard persistenceReady else {
            logger.error("UEBA save refused before persisted profiles reached readiness")
            return false
        }
        let envelope = PersistenceEnvelope(
            schemaVersion: 1,
            profileHistorySaturated: profileHistorySaturated,
            profiles: Array(profiles.values)
        )
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        do {
            let data = try encoder.encode(envelope)
            guard UInt64(data.count) <= Self.maximumPersistenceBytes else {
                logger.error("UEBA save refused: encoded model exceeds the 32 MiB persistence boundary")
                return false
            }
            try data.write(to: URL(fileURLWithPath: path), options: .atomic)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600], ofItemAtPath: path
            )
            return true
        } catch {
            logger.error("UEBA save failed: \(error.localizedDescription)")
            return false
        }
    }

    /// Explicitly load profiles from disk. Returns true for both a successful
    /// decode and a missing file (a valid fresh baseline), false for unreadable
    /// or malformed persistence. Failed loads remain retryable and cannot be
    /// followed by an accidental overwrite through `save()`.
    @discardableResult
    public func loadPersistedProfiles() -> Bool {
        if persistenceReady { return true }
        guard let path = persistencePath else {
            persistenceReady = true
            return true
        }
        guard FileManager.default.fileExists(atPath: path) else {
            persistenceReady = true
            return true
        }
        guard let attributes = try? FileManager.default.attributesOfItem(
            atPath: path
        ),
        attributes[.type] as? FileAttributeType == .typeRegular,
        let byteCount = (attributes[.size] as? NSNumber)?.uint64Value,
        byteCount <= Self.maximumPersistenceBytes else {
            logger.error("UEBA load failed: persistence file is not a bounded regular file")
            return false
        }
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
            logger.error("UEBA load failed: persistence file is unreadable")
            return false
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        do {
            let list: [UserEntityProfile]
            let persistedProfileHistorySaturated: Bool
            if let envelope = try? decoder.decode(
                PersistenceEnvelope.self, from: data
            ), envelope.schemaVersion == 1 {
                list = envelope.profiles
                persistedProfileHistorySaturated =
                    envelope.profileHistorySaturated
            } else {
                // v1.21.5 and earlier stored the bare profile array. Keep that
                // migration path, then write the versioned envelope next save.
                list = try decoder.decode([UserEntityProfile].self, from: data)
                persistedProfileHistorySaturated = false
            }
            guard list.allSatisfy(Self.isStructurallyValid) else {
                logger.error("UEBA load failed: persistence contains an invalid profile shape")
                return false
            }
            guard Set(list.map(\.userName)).count == list.count else {
                logger.error("UEBA load failed: persistence contains duplicate profiles")
                return false
            }
            installLoadedProfiles(list)
            if persistedProfileHistorySaturated {
                markProfileHistorySaturated()
            }
            persistenceReady = true
            logger.info("UEBA loaded \(self.profiles.count) bounded profiles from disk")
            return true
        } catch {
            logger.error("UEBA load failed: \(error.localizedDescription)")
            return false
        }
    }

    // MARK: - Observation

    /// Absorb a process event into the appropriate user's profile.
    /// Returns any anomalies the observation surfaced — callers can
    /// turn those into Alerts or feed them into the detection pipeline.
    @discardableResult
    public func observe(event: Event, now: Date = Date()) -> [UEBAAnomaly] {
        guard persistenceReady else {
            logger.error("UEBA observation refused before persisted profiles reached readiness")
            return []
        }
        // UEBA only cares about process-launch events — file/network
        // events roll up under their originating process.
        guard event.eventCategory == .process,
              event.eventAction == "exec" || event.eventAction == "fork" else {
            return []
        }
        let user = event.process.userName
        let userBytes = user.utf8.count
        guard !user.isEmpty,
              user.count <= 256,
              userBytes <= Self.maximumUserNameUTF8Bytes else { return [] }

        let toolPath = event.process.executable
        let toolPathBytes = toolPath.utf8.count
        guard !toolPath.isEmpty,
              toolPath.count <= 4_096,
              toolPathBytes <= Self.maximumToolPathUTF8Bytes else { return [] }

        let sshIP = event.process.session?.sshRemoteIP.flatMap { source in
            let bytes = source.utf8.count
            return !source.isEmpty
                && source.count <= 128
                && bytes <= Self.maximumSSHRemoteIPUTF8Bytes
                ? source : nil
        }

        var profile: UserEntityProfile
        if let existing = profiles[user] {
            profile = existing
        } else {
            // Live profile churn never evicts an established baseline. Once
            // identity history is incomplete, refusing later identities is
            // safer than relearning an evicted user and reporting its old
            // tools as first-ever executions.
            guard !profileHistorySaturated,
                  profiles.count < maxProfiles,
                  canFitEntityBytes(adding: userBytes) else {
                rejectedProfiles &+= 1
                markProfileHistorySaturated()
                return []
            }
            profile = UserEntityProfile(userName: user, now: now)
            aggregateEntityUTF8Bytes += userBytes
        }

        let cal = Calendar.current
        let hour = cal.component(.hour, from: now)
        let weekday = cal.component(.weekday, from: now) // 1=Sun, 7=Sat
        let isWeekend = weekday == 1 || weekday == 7

        // Plan bounded retention before scoring. Any eviction or refusal marks
        // that dimension incomplete before `assess`, so the event that first
        // reaches a bound cannot create a false novelty alert.
        var projectedToolEntries = aggregateToolEntries
        var projectedSSHEntries = aggregateSSHRemoteIPEntries
        var projectedEntityBytes = aggregateEntityUTF8Bytes

        var sshVictims: [String] = []
        var retainNewSSHSource = false
        if let ip = sshIP, !profile.sshRemoteIPs.contains(ip) {
            if profile.sshRemoteIPs.count >= maxSSHRemoteIPsPerProfile {
                let removeCount = profile.sshRemoteIPs.count
                    - sshEvictionLowWater + 1
                sshVictims = Array(
                    profile.sshRemoteIPs.sorted().prefix(removeCount)
                )
                markSSHHistorySaturated(&profile)
            }
            let removedBytes = sshVictims.reduce(0) {
                $0 + $1.utf8.count
            }
            let baseEntries = projectedSSHEntries - sshVictims.count
            let baseBytes = projectedEntityBytes - removedBytes
            if baseEntries < maxAggregateSSHRemoteIPEntries,
               canFitEntityBytes(base: baseBytes, adding: ip.utf8.count) {
                retainNewSSHSource = true
                projectedSSHEntries = baseEntries + 1
                projectedEntityBytes = baseBytes + ip.utf8.count
            } else {
                sshVictims.removeAll(keepingCapacity: false)
                rejectedSSHRemoteIPs &+= 1
                markSSHHistorySaturated(&profile)
            }
        }

        var toolVictims: [String] = []
        var retainNewTool = false
        if profile.toolUsage[toolPath] == nil {
            if profile.toolUsage.count >= maxToolsPerProfile {
                let removeCount = profile.toolUsage.count
                    - toolEvictionLowWater + 1
                toolVictims = profile.toolUsage
                    .sorted {
                        if $0.value == $1.value { return $0.key < $1.key }
                        return $0.value < $1.value
                    }
                    .prefix(removeCount)
                    .map(\.key)
                markToolHistorySaturated(&profile)
            }
            let removedBytes = toolVictims.reduce(0) {
                $0 + $1.utf8.count
            }
            let baseEntries = projectedToolEntries - toolVictims.count
            let baseBytes = projectedEntityBytes - removedBytes
            if baseEntries < maxAggregateToolEntries,
               canFitEntityBytes(base: baseBytes, adding: toolPathBytes) {
                retainNewTool = true
                projectedToolEntries = baseEntries + 1
                projectedEntityBytes = baseBytes + toolPathBytes
            } else {
                toolVictims.removeAll(keepingCapacity: false)
                rejectedTools &+= 1
                markToolHistorySaturated(&profile)
            }
        }

        // Anomaly assessment happens BEFORE the profile is updated so
        // the observation itself doesn't baseline away its own novelty.
        let anomalies = assess(
            profile: profile, hour: hour, isWeekend: isWeekend,
            sshIP: sshIP, toolPath: toolPath
        )

        // Fold the observation in.
        profile.totalObservations = Self.saturatingIncrement(
            profile.totalObservations
        )
        profile.lastObserved = now
        if (0..<24).contains(hour) {
            profile.loginHourCounts[hour] = Self.saturatingIncrement(
                profile.loginHourCounts[hour]
            )
            if isWeekend {
                profile.weekendHourCounts[hour] = Self.saturatingIncrement(
                    profile.weekendHourCounts[hour]
                )
                profile.weekendObservations = Self.saturatingIncrement(
                    profile.weekendObservations
                )
            } else {
                profile.weekdayHourCounts[hour] = Self.saturatingIncrement(
                    profile.weekdayHourCounts[hour]
                )
                profile.weekdayObservations = Self.saturatingIncrement(
                    profile.weekdayObservations
                )
            }
        }

        if retainNewSSHSource, let ip = sshIP {
            for victim in sshVictims {
                profile.sshRemoteIPs.remove(victim)
            }
            profile.sshRemoteIPs.insert(ip)
            evictedSSHRemoteIPs &+= UInt64(sshVictims.count)
        }

        if let count = profile.toolUsage[toolPath] {
            profile.toolUsage[toolPath] = Self.saturatingIncrement(count)
        } else if retainNewTool {
            for victim in toolVictims {
                profile.toolUsage.removeValue(forKey: victim)
            }
            profile.toolUsage[toolPath] = 1
            evictedTools &+= UInt64(toolVictims.count)
        }

        aggregateToolEntries = projectedToolEntries
        aggregateSSHRemoteIPEntries = projectedSSHEntries
        aggregateEntityUTF8Bytes = projectedEntityBytes
        profiles[user] = profile

        return anomalies
    }

    // MARK: - Queries

    public func profile(for userName: String) -> UserEntityProfile? {
        profiles[userName]
    }

    public func stats() -> (users: Int, totalObservations: Int) {
        let total = profiles.values.reduce(0) {
            Self.saturatingAdd($0, $1.totalObservations)
        }
        return (profiles.count, total)
    }

    public func allProfiles() -> [UserEntityProfile] {
        Array(profiles.values)
    }

    public struct CapacityStats: Sendable, Equatable {
        public let profiles: Int
        public let maxProfiles: Int
        public let toolEntries: Int
        public let maxAggregateToolEntries: Int
        public let sshRemoteIPEntries: Int
        public let maxAggregateSSHRemoteIPEntries: Int
        public let entityUTF8Bytes: Int
        public let maxAggregateEntityUTF8Bytes: Int
        public let modelSaturated: Bool
        public let profileHistorySaturated: Bool
        public let saturatedToolProfiles: Int
        public let saturatedSSHProfiles: Int
        public let saturationEvents: UInt64
        public let rejectedProfiles: UInt64
        public let rejectedTools: UInt64
        public let rejectedSSHRemoteIPs: UInt64
        public let evictedProfiles: UInt64
        public let evictedTools: UInt64
        public let evictedSSHRemoteIPs: UInt64
    }

    public func capacityStats() -> CapacityStats {
        CapacityStats(
            profiles: profiles.count,
            maxProfiles: maxProfiles,
            toolEntries: aggregateToolEntries,
            maxAggregateToolEntries: maxAggregateToolEntries,
            sshRemoteIPEntries: aggregateSSHRemoteIPEntries,
            maxAggregateSSHRemoteIPEntries: maxAggregateSSHRemoteIPEntries,
            entityUTF8Bytes: aggregateEntityUTF8Bytes,
            maxAggregateEntityUTF8Bytes: maxAggregateEntityUTF8Bytes,
            modelSaturated: modelSaturated,
            profileHistorySaturated: profileHistorySaturated,
            saturatedToolProfiles: profiles.values.reduce(0) {
                $0 + ($1.toolHistorySaturated ? 1 : 0)
            },
            saturatedSSHProfiles: profiles.values.reduce(0) {
                $0 + ($1.sshHistorySaturated ? 1 : 0)
            },
            saturationEvents: saturationEvents,
            rejectedProfiles: rejectedProfiles,
            rejectedTools: rejectedTools,
            rejectedSSHRemoteIPs: rejectedSSHRemoteIPs,
            evictedProfiles: evictedProfiles,
            evictedTools: evictedTools,
            evictedSSHRemoteIPs: evictedSSHRemoteIPs
        )
    }

    /// Reject malformed persisted shapes before they can produce out-of-range
    /// histogram indexing or negative-count scoring behavior.
    private nonisolated static func isStructurallyValid(
        _ profile: UserEntityProfile
    ) -> Bool {
        !profile.userName.isEmpty
            && profile.userName.count <= 256
            && profile.userName.utf8.count <= maximumUserNameUTF8Bytes
            && profile.loginHourCounts.count == 24
            && profile.weekdayHourCounts.count == 24
            && profile.weekendHourCounts.count == 24
            && profile.loginHourCounts.allSatisfy { $0 >= 0 }
            && profile.weekdayHourCounts.allSatisfy { $0 >= 0 }
            && profile.weekendHourCounts.allSatisfy { $0 >= 0 }
            && profile.weekdayObservations >= 0
            && profile.weekendObservations >= 0
            && profile.totalObservations >= 0
            && profile.sshRemoteIPs.allSatisfy {
                !$0.isEmpty
                    && $0.count <= 128
                    && $0.utf8.count <= maximumSSHRemoteIPUTF8Bytes
            }
            && profile.toolUsage.allSatisfy {
                !$0.key.isEmpty
                    && $0.key.count <= 4_096
                    && $0.key.utf8.count <= maximumToolPathUTF8Bytes
                    && $0.value > 0
            }
    }

    /// Installs decoded state through both the per-profile and aggregate
    /// budgets. Recent profiles and frequently used tools win deterministic
    /// admission; SSH sources are retained deterministically. Any discarded
    /// history sets a sticky completeness marker before scoring resumes.
    private func installLoadedProfiles(_ source: [UserEntityProfile]) {
        profiles.removeAll(keepingCapacity: true)
        aggregateToolEntries = 0
        aggregateSSHRemoteIPEntries = 0
        aggregateEntityUTF8Bytes = 0

        let ordered = source.sorted {
            if $0.lastObserved == $1.lastObserved {
                return $0.userName < $1.userName
            }
            return $0.lastObserved > $1.lastObserved
        }

        for original in ordered {
            let userBytes = original.userName.utf8.count
            guard profiles.count < maxProfiles,
                  canFitEntityBytes(adding: userBytes) else {
                evictedProfiles &+= 1
                markProfileHistorySaturated()
                continue
            }

            var profile = bounded(original)
            aggregateEntityUTF8Bytes += userBytes

            var retainedSSH: Set<String> = []
            var removedSSH = 0
            for sourceIP in profile.sshRemoteIPs.sorted() {
                if aggregateSSHRemoteIPEntries < maxAggregateSSHRemoteIPEntries,
                   canFitEntityBytes(adding: sourceIP.utf8.count) {
                    retainedSSH.insert(sourceIP)
                    aggregateSSHRemoteIPEntries += 1
                    aggregateEntityUTF8Bytes += sourceIP.utf8.count
                } else {
                    removedSSH += 1
                }
            }
            if removedSSH > 0 {
                profile.sshRemoteIPs = retainedSSH
                evictedSSHRemoteIPs &+= UInt64(removedSSH)
                markSSHHistorySaturated(&profile)
            }

            let orderedTools = profile.toolUsage.sorted {
                if $0.value == $1.value { return $0.key < $1.key }
                return $0.value > $1.value
            }
            var retainedTools: [String: Int] = [:]
            retainedTools.reserveCapacity(
                min(orderedTools.count, maxAggregateToolEntries)
            )
            var removedTools = 0
            for (path, count) in orderedTools {
                if aggregateToolEntries < maxAggregateToolEntries,
                   canFitEntityBytes(adding: path.utf8.count) {
                    retainedTools[path] = count
                    aggregateToolEntries += 1
                    aggregateEntityUTF8Bytes += path.utf8.count
                } else {
                    removedTools += 1
                }
            }
            if removedTools > 0 {
                profile.toolUsage = retainedTools
                evictedTools &+= UInt64(removedTools)
                markToolHistorySaturated(&profile)
            }

            if profile.toolHistorySaturated || profile.sshHistorySaturated {
                modelSaturated = true
            }
            profiles[profile.userName] = profile
        }
    }

    private func bounded(_ source: UserEntityProfile) -> UserEntityProfile {
        var profile = source
        if profile.toolUsage.count > maxToolsPerProfile {
            let retained = profile.toolUsage
                .sorted {
                    if $0.value == $1.value { return $0.key < $1.key }
                    return $0.value > $1.value
                }
                .prefix(maxToolsPerProfile)
            let removed = profile.toolUsage.count - retained.count
            profile.toolUsage = Dictionary(
                uniqueKeysWithValues: retained.map { ($0.key, $0.value) }
            )
            evictedTools &+= UInt64(removed)
            markToolHistorySaturated(&profile)
        }
        if profile.sshRemoteIPs.count > maxSSHRemoteIPsPerProfile {
            let retained = profile.sshRemoteIPs
                .sorted()
                .prefix(maxSSHRemoteIPsPerProfile)
            let removed = profile.sshRemoteIPs.count - retained.count
            profile.sshRemoteIPs = Set(retained)
            evictedSSHRemoteIPs &+= UInt64(removed)
            markSSHHistorySaturated(&profile)
        }
        return profile
    }

    private func canFitEntityBytes(adding: Int) -> Bool {
        canFitEntityBytes(base: aggregateEntityUTF8Bytes, adding: adding)
    }

    private func canFitEntityBytes(base: Int, adding: Int) -> Bool {
        base >= 0
            && adding >= 0
            && base <= maxAggregateEntityUTF8Bytes
            && adding <= maxAggregateEntityUTF8Bytes - base
    }

    private func markProfileHistorySaturated() {
        modelSaturated = true
        guard !profileHistorySaturated else { return }
        profileHistorySaturated = true
        saturationEvents &+= 1
    }

    private func markToolHistorySaturated(
        _ profile: inout UserEntityProfile
    ) {
        modelSaturated = true
        guard !profile.toolHistorySaturated else { return }
        profile.toolHistorySaturated = true
        saturationEvents &+= 1
    }

    private func markSSHHistorySaturated(
        _ profile: inout UserEntityProfile
    ) {
        modelSaturated = true
        guard !profile.sshHistorySaturated else { return }
        profile.sshHistorySaturated = true
        saturationEvents &+= 1
    }

    private nonisolated static func saturatingIncrement(_ value: Int) -> Int {
        value == Int.max ? value : value + 1
    }

    private nonisolated static func saturatingAdd(_ lhs: Int, _ rhs: Int) -> Int {
        guard rhs > 0 else { return lhs }
        return lhs > Int.max - rhs ? Int.max : lhs + rhs
    }

    // MARK: - Private assessment

    private func assess(
        profile: UserEntityProfile,
        hour: Int,
        isWeekend: Bool,
        sshIP: String?,
        toolPath: String
    ) -> [UEBAAnomaly] {
        // Cold start — no alerting yet, we're still gathering baseline.
        if profile.totalObservations < minObservationsForScoring {
            return []
        }

        var out: [UEBAAnomaly] = []

        // Unusual login hour — uses weekday/weekend-split frequency when
        // the split bucket is adequately sampled, combined otherwise.
        if (0..<24).contains(hour) {
            let freq = profile.hourFrequency(hour, isWeekend: isWeekend)
            if freq < hourAnomalyThreshold {
                let dayKind = isWeekend ? "weekend" : "weekday"
                out.append(UEBAAnomaly(
                    kind: .unusualLoginHour,
                    userName: profile.userName,
                    detail: "Activity at \(dayKind) hour \(hour):00 has \(String(format: "%.2f%%", freq * 100)) baseline frequency",
                    severity: offHoursSeverity(hour: hour)
                ))
            }
        }

        // New SSH source IP
        if let ip = sshIP,
           !profile.sshHistorySaturated,
           !profile.sshRemoteIPs.contains(ip) {
            out.append(UEBAAnomaly(
                kind: .newSSHSource,
                userName: profile.userName,
                detail: "First-ever SSH login from \(ip) for user \(profile.userName)",
                severity: .high
            ))
        }

        // Novel tool
        if profile.toolIsNovel(toolPath) {
            out.append(UEBAAnomaly(
                kind: .novelTool,
                userName: profile.userName,
                detail: "First-ever execution of \(toolPath) for user \(profile.userName)",
                severity: .low
            ))
        }

        return out
    }

    /// Maps hour-of-day to anomaly severity for unusual login-hour
    /// detections. Deep-night and late-night hours are escalated because
    /// autonomous/automated access at those times is rare on user machines
    /// and warrants faster triage.
    private func offHoursSeverity(hour: Int) -> Severity {
        switch hour {
        case 0..<5:   return .high    // Deep night (midnight–4 AM)
        case 5..<7:   return .medium  // Very early morning
        case 7..<19:  return .low     // Core hours — freq < 2% is already odd
        case 19..<22: return .medium  // Evening
        default:      return .high    // Late night (10 PM–midnight)
        }
    }
}
