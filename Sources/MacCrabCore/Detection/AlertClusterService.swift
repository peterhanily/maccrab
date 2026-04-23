// AlertClusterService.swift
// MacCrabCore
//
// Groups related alerts by stable fingerprint so the analyst triages by
// cluster rather than by individual alert. A "cluster" is a set of
// alerts that share a rule ID and a process-name anchor — the single
// most predictive feature for "same underlying activity" in the field
// data we collected across v1.6.0-1.6.5.
//
// The clustering pass itself is deterministic, synchronous, and cheap
// (fingerprint hash + group by key). An optional second pass calls the
// LLM to attach a one-sentence rationale to each cluster — useful when
// a cluster has 5+ members and the analyst wants "what's happening here
// in plain English" without drilling into each alert. That second pass
// is on-demand (triggered by dashboard expansion) rather than eager, so
// idle polls don't hammer the LLM backend.

import Foundation
import CryptoKit

// MARK: - AlertCluster

/// A group of alerts sharing a fingerprint. Identity is stable across
/// refreshes: the same set of alerts will always produce the same
/// cluster `id`, which lets the dashboard track expanded/collapsed
/// state without a lookup table.
public struct AlertCluster: Identifiable, Sendable, Hashable {
    /// Deterministic cluster id derived from the fingerprint.
    public let id: String

    /// Human-readable fingerprint: `"<ruleId>::<processName-or-<unknown>>"`.
    public let fingerprint: String

    /// Rule ID shared by every member.
    public let ruleId: String

    /// Rule title (taken from the representative alert).
    public let ruleTitle: String

    /// Process name shared by every member, or `"<unknown>"` when the
    /// alert didn't carry one.
    public let processName: String

    /// Representative process path — the first non-nil processPath
    /// among the members. Surfaced so the dashboard can show a full
    /// path without iterating members.
    public let processPath: String?

    /// Maximum severity observed across members (a cluster containing
    /// one HIGH and three MEDIUM shows as HIGH).
    public let severity: Severity

    /// Member alert IDs, ordered newest-first.
    public let memberAlertIds: [String]

    /// Union of MITRE tactic IDs across all members.
    public let tactics: Set<String>

    /// Timestamp of the oldest member.
    public let firstSeen: Date

    /// Timestamp of the newest member.
    public let lastSeen: Date

    /// LLM-generated explanation of what the cluster represents, or
    /// nil if the rationale pass hasn't been run for this cluster.
    public var rationale: String?

    /// Number of alerts in the cluster.
    public var size: Int { memberAlertIds.count }
}

// MARK: - AlertClusterService

/// Deterministic clustering over a snapshot of alerts. Stateless —
/// every call re-clusters from scratch — so the service is safe to
/// share across callers and doesn't need a lifecycle. The optional
/// LLM backend is used only for the on-demand rationale refinement.
public actor AlertClusterService {

    private let llm: LLMService?

    public init(llm: LLMService? = nil) {
        self.llm = llm
    }

    // MARK: Clustering

    /// Group alerts into clusters. Ordering is max-severity desc, then
    /// newest-first by `lastSeen`; within a cluster, members are
    /// newest-first by alert timestamp.
    public func cluster(alerts: [Alert]) -> [AlertCluster] {
        guard !alerts.isEmpty else { return [] }

        var buckets: [String: [Alert]] = [:]
        for alert in alerts {
            let fp = Self.fingerprint(for: alert)
            buckets[fp, default: []].append(alert)
        }

        var clusters: [AlertCluster] = []
        clusters.reserveCapacity(buckets.count)
        for (fp, members) in buckets {
            let sorted = members.sorted { $0.timestamp > $1.timestamp }
            guard let representative = sorted.first,
                  let oldest = sorted.last else { continue }

            let firstSeen = oldest.timestamp
            let lastSeen = representative.timestamp
            let maxSev = sorted.map(\.severity).max() ?? representative.severity
            let processName = representative.processName
                ?? representative.processPath.map { ($0 as NSString).lastPathComponent }
                ?? "<unknown>"
            let processPath = sorted.compactMap(\.processPath).first
            let tactics: Set<String> = sorted.reduce(into: []) { acc, alert in
                alert.mitreTacticsList.forEach { acc.insert($0) }
            }

            clusters.append(AlertCluster(
                id: Self.stableId(fingerprint: fp),
                fingerprint: fp,
                ruleId: representative.ruleId,
                ruleTitle: representative.ruleTitle,
                processName: processName,
                processPath: processPath,
                severity: maxSev,
                memberAlertIds: sorted.map(\.id),
                tactics: tactics,
                firstSeen: firstSeen,
                lastSeen: lastSeen,
                rationale: nil
            ))
        }

        return clusters.sorted { lhs, rhs in
            if lhs.severity != rhs.severity { return lhs.severity > rhs.severity }
            return lhs.lastSeen > rhs.lastSeen
        }
    }

    // MARK: Fingerprint helpers

    /// Fingerprint used for bucketing. Exposed for the dashboard and
    /// tests so they can compute the same key without re-clustering.
    public static func fingerprint(for alert: Alert) -> String {
        let name = alert.processName
            ?? alert.processPath.map { ($0 as NSString).lastPathComponent }
            ?? "<unknown>"
        return "\(alert.ruleId)::\(name)"
    }

    /// Stable id derived from the fingerprint. 16 hex chars of SHA-256
    /// is collision-resistant enough for the cluster space.
    public static func stableId(fingerprint: String) -> String {
        let digest = SHA256.hash(data: Data(fingerprint.utf8))
        let hex = digest.map { String(format: "%02x", $0) }.joined()
        return "cluster.\(hex.prefix(16))"
    }

    // MARK: LLM rationale

    /// Ask the configured LLM backend for a one-sentence explanation
    /// of a cluster's activity. Returns the cluster with `rationale`
    /// set, or the original cluster unchanged when the LLM is not
    /// configured / the call failed / returned empty.
    public func refineRationale(
        _ cluster: AlertCluster,
        membersSnapshot: [Alert]
    ) async -> AlertCluster {
        guard let llm = llm else { return cluster }
        guard await llm.isAvailable() else { return cluster }

        let context = Self.rationaleContext(
            cluster: cluster,
            members: membersSnapshot.prefix(5)
        )
        let system = """
        You are a terse security analyst. Reply in ONE plain-English sentence. No preamble, no markdown, no restating the rule name.
        """
        let user = """
        Cluster of \(cluster.size) similar alerts:
        Rule: \(cluster.ruleTitle)
        Process: \(cluster.processName)\(cluster.processPath.map { " (\($0))" } ?? "")
        MITRE tactics: \(cluster.tactics.sorted().joined(separator: ", "))
        Severity: \(cluster.severity)

        Recent representative events:
        \(context)

        In one sentence, what is most likely happening? Lead with \"Likely\" / \"Possibly\" / \"Attacker\" as appropriate.
        """

        guard let response = await llm.query(
            systemPrompt: system,
            userPrompt: user,
            maxTokens: 120,
            temperature: 0.2
        ) else {
            return cluster
        }

        let trimmed = response.response.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return cluster }

        var refined = cluster
        refined.rationale = trimmed
        return refined
    }

    private static func rationaleContext(
        cluster: AlertCluster,
        members: ArraySlice<Alert>
    ) -> String {
        members.enumerated().map { (i, alert) in
            let ts = ISO8601DateFormatter().string(from: alert.timestamp)
            let desc = alert.description ?? "(no description)"
            return "#\(i + 1) @ \(ts): \(desc.prefix(200))"
        }.joined(separator: "\n")
    }
}
