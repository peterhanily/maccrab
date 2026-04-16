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
    /// bucket per hour of day. 168 buckets keyed `day * 24 + hour`
    /// would be more precise but adds cross-TZ complexity — 24 buckets
    /// captures the common "user works 9-5" signal well enough.
    public var loginHourCounts: [Int]

    /// Set of SSH source IPs this user has logged in from.
    public var sshRemoteIPs: Set<String>

    /// Per-executable launch counts.
    public var toolUsage: [String: Int]

    public var totalObservations: Int

    public init(userName: String, now: Date = Date()) {
        self.userName = userName
        self.firstSeen = now
        self.lastObserved = now
        self.loginHourCounts = Array(repeating: 0, count: 24)
        self.sshRemoteIPs = []
        self.toolUsage = [:]
        self.totalObservations = 0
    }

    /// Ratio of observations at this hour. Used for anomaly detection —
    /// a hour < 0.02 ratio after ≥ 100 observations is genuinely rare.
    public func hourFrequency(_ hour: Int) -> Double {
        guard (0..<24).contains(hour), totalObservations > 0 else { return 0 }
        return Double(loginHourCounts[hour]) / Double(totalObservations)
    }

    /// True when the tool has never (or almost never) been seen. Uses a
    /// flat minimum-count threshold rather than Welford for v1 since
    /// tool-usage distributions are heavy-tailed and z-score on counts
    /// is unstable for rare tools.
    public func toolIsNovel(_ path: String) -> Bool {
        (toolUsage[path] ?? 0) == 0
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

    public init(
        minObservationsForScoring: Int = 100,
        hourAnomalyThreshold: Double = 0.02
    ) {
        self.minObservationsForScoring = minObservationsForScoring
        self.hourAnomalyThreshold = hourAnomalyThreshold
    }

    // MARK: - Observation

    /// Absorb a process event into the appropriate user's profile.
    /// Returns any anomalies the observation surfaced — callers can
    /// turn those into Alerts or feed them into the detection pipeline.
    @discardableResult
    public func observe(event: Event, now: Date = Date()) -> [UEBAAnomaly] {
        // UEBA only cares about process-launch events — file/network
        // events roll up under their originating process.
        guard event.eventCategory == .process,
              event.eventAction == "exec" || event.eventAction == "fork" else {
            return []
        }
        let user = event.process.userName
        guard !user.isEmpty else { return [] }

        var profile = profiles[user] ?? UserEntityProfile(userName: user, now: now)
        let hour = Calendar.current.component(.hour, from: now)
        let sshIP = event.process.session?.sshRemoteIP
        let toolPath = event.process.executable

        // Anomaly assessment happens BEFORE the profile is updated so
        // the observation itself doesn't baseline away its own novelty.
        let anomalies = assess(
            profile: profile, hour: hour, sshIP: sshIP, toolPath: toolPath
        )

        // Fold the observation in.
        profile.totalObservations += 1
        profile.lastObserved = now
        if (0..<24).contains(hour) {
            profile.loginHourCounts[hour] += 1
        }
        if let ip = sshIP {
            profile.sshRemoteIPs.insert(ip)
        }
        profile.toolUsage[toolPath, default: 0] += 1
        profiles[user] = profile

        return anomalies
    }

    // MARK: - Queries

    public func profile(for userName: String) -> UserEntityProfile? {
        profiles[userName]
    }

    public func stats() -> (users: Int, totalObservations: Int) {
        let total = profiles.values.reduce(0) { $0 + $1.totalObservations }
        return (profiles.count, total)
    }

    public func allProfiles() -> [UserEntityProfile] {
        Array(profiles.values)
    }

    // MARK: - Private assessment

    private func assess(
        profile: UserEntityProfile,
        hour: Int,
        sshIP: String?,
        toolPath: String
    ) -> [UEBAAnomaly] {
        // Cold start — no alerting yet, we're still gathering baseline.
        if profile.totalObservations < minObservationsForScoring {
            return []
        }

        var out: [UEBAAnomaly] = []

        // Unusual login hour
        if (0..<24).contains(hour) {
            let freq = profile.hourFrequency(hour)
            if freq < hourAnomalyThreshold {
                out.append(UEBAAnomaly(
                    kind: .unusualLoginHour,
                    userName: profile.userName,
                    detail: "Activity at hour \(hour) has \(String(format: "%.2f%%", freq * 100)) baseline frequency",
                    severity: .medium
                ))
            }
        }

        // New SSH source IP
        if let ip = sshIP, !profile.sshRemoteIPs.contains(ip) {
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
}
