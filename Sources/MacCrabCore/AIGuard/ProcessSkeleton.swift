// ProcessSkeleton.swift
// MacCrabCore
//
// v1.10 TraceGraph (PR-6a) — the skeleton view of a process for the
// rolling causal graph. Per §6.3 of the v1.10.0 spec, every observed
// process inside the active lineage window is tracked as a lightweight
// skeleton; only "interesting" entities (AI-attributed, sensitive-path
// touching, rule-referenced, etc.) get further enriched.
//
// This type is a public projection over the existing `ProcessLineage`
// `LineageNode` plus the `ProcessIdentity` machinery. It does not
// replace either — a `ProcessSkeleton` is constructed on demand from
// the canonical sources of truth.
//
// The candidate-edge ring buffer named in §6.3.2 is NOT a field on
// this type in PR-6a; PR-7 (entity + edge builders) is the PR that
// introduces it because the buffer's element type is `CandidateEdge`,
// which doesn't exist until then. Adding it now would mean a placeholder
// that PR-7 would have to rewrite, so we defer.

import Foundation

/// Lightweight skeleton view of a process inside the active lineage window.
public struct ProcessSkeleton: Sendable, Codable, Equatable {

    /// SHA-256-derived canonical identifier (see `ProcessIdentity.processKey`).
    public let processKey: String

    public let pid: pid_t

    public let ppid: pid_t

    /// Process start time as observed by the collector. Display + audit
    /// only; never used as an identity input (see §10.1).
    public let startTime: Date

    public let executablePath: String

    /// Canonical key of the parent skeleton, when known. Nil when the
    /// parent is outside the active window (e.g. launchd, or a parent
    /// that exited before TraceGraph started observing) or the parent
    /// chain has been truncated.
    public let parentProcessKey: String?

    /// Compact code-signing summary. Lifted from `CodeSignatureInfo` so
    /// the skeleton stays small but root-cause resolution can still
    /// distinguish trust transitions without dereferencing the full
    /// `CodeSignatureInfo` structure.
    public let signingSummary: SigningSummary?

    /// First time this skeleton was observed in the rolling graph.
    public let firstSeen: Date

    /// Most recent observation timestamp.
    public var lastSeen: Date

    public init(
        processKey: String,
        pid: pid_t,
        ppid: pid_t,
        startTime: Date,
        executablePath: String,
        parentProcessKey: String? = nil,
        signingSummary: SigningSummary? = nil,
        firstSeen: Date,
        lastSeen: Date
    ) {
        self.processKey = processKey
        self.pid = pid
        self.ppid = ppid
        self.startTime = startTime
        self.executablePath = executablePath
        self.parentProcessKey = parentProcessKey
        self.signingSummary = signingSummary
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen
    }

    /// Compact projection of `CodeSignatureInfo` carried on the skeleton.
    public struct SigningSummary: Sendable, Codable, Equatable {
        public let signerType: SignerType
        public let teamId: String?
        public let signingId: String?
        public let isAppleSigned: Bool
        public let isNotarized: Bool

        public init(
            signerType: SignerType,
            teamId: String? = nil,
            signingId: String? = nil,
            isAppleSigned: Bool,
            isNotarized: Bool
        ) {
            self.signerType = signerType
            self.teamId = teamId
            self.signingId = signingId
            self.isAppleSigned = isAppleSigned
            self.isNotarized = isNotarized
        }

        /// Convenience builder from the existing `CodeSignatureInfo`.
        public init(from info: CodeSignatureInfo) {
            self.signerType = info.signerType
            self.teamId = info.teamId
            self.signingId = info.signingId
            self.isAppleSigned = (info.signerType == .apple)
            self.isNotarized = info.isNotarized
        }
    }
}
