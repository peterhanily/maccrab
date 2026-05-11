// TracePolicy.swift
// MacCrabCore
//
// v1.10 TraceGraph (PR-8) — centralizes privacy, capture, enrichment,
// redaction, anchoring, trusted conduit, and rendering behaviour per
// §15.10 of the v1.10.0 spec.
//
// PR-8 ships the subset actively consumed by the materialization
// path: window sizes, budget caps, AI attribution threshold, and the
// trusted-conduit policy. The remaining fields named in §15.10
// (skeletonMemoryBudgetMB, candidateEdgeBufferPerSkeleton,
// storeCommandLine, materializationAnchors, bundleRedactionProfile,
// unifiedLogAnchoringEnabled) are stubbed with defaults here and
// wired into the relevant subsystems in their respective PRs
// (PR-10b for redaction, PR-10c for anchoring, etc.).

import Foundation

public struct TracePolicy: Sendable, Equatable {

    public let id: String
    public let version: String

    // MARK: - Window sizes

    /// Active lineage window (matches existing `ProcessLineage` retention).
    public let lineageWindow: TimeInterval

    /// Default UI materialization window — shorter than the lineage
    /// window per §6.2.
    public let materializationWindow: TimeInterval

    // MARK: - Materialization defaults (§14.2)

    public let ancestorDepth: Int
    public let descendantDepth: Int
    public let lookbackMinutes: Int
    public let lookaheadMinutes: Int

    // MARK: - Dynamic trace budget (§14.3)

    public let coreEntityCap: Int
    public let coreEdgeCap: Int
    public let contextEntityCap: Int
    public let contextEdgeCap: Int

    // MARK: - Rendering

    /// Threshold below which AI attribution is rendered as inferred
    /// rather than asserted (§11.3). Default 0.85.
    public let aiAttributionAssertionThreshold: Double

    // MARK: - Trust

    public let trustedConduitPolicy: TrustedConduitPolicy

    // MARK: - Snapshot fields (recorded on every materialized trace per §15.10.1)

    /// `"secure_enclave"` or `"filesystem_degraded"` per §19.1.
    public let traceSigningKeyMode: String

    /// `"declared_deterministic_subset"` or `"include_bundled_state"` per §17.1.
    public let replayScope: String

    /// `"include_as_human_annotation_do_not_apply_by_default"` or
    /// `"include_and_apply_on_replay_when_flagged"` per §18.5.
    public let attributionOverridePolicy: String

    public init(
        id: String = "default",
        version: String = "1",
        lineageWindow: TimeInterval = 3600,
        materializationWindow: TimeInterval = 1200,
        ancestorDepth: Int = 5,
        descendantDepth: Int = 4,
        lookbackMinutes: Int = 15,
        lookaheadMinutes: Int = 10,
        coreEntityCap: Int = 50,
        coreEdgeCap: Int = 100,
        contextEntityCap: Int = 250,
        contextEdgeCap: Int = 500,
        aiAttributionAssertionThreshold: Double = 0.85,
        trustedConduitPolicy: TrustedConduitPolicy = .default,
        traceSigningKeyMode: String = "filesystem_degraded",
        replayScope: String = "declared_deterministic_subset",
        attributionOverridePolicy: String = "include_as_human_annotation_do_not_apply_by_default"
    ) {
        self.id = id
        self.version = version
        self.lineageWindow = lineageWindow
        self.materializationWindow = materializationWindow
        self.ancestorDepth = ancestorDepth
        self.descendantDepth = descendantDepth
        self.lookbackMinutes = lookbackMinutes
        self.lookaheadMinutes = lookaheadMinutes
        self.coreEntityCap = coreEntityCap
        self.coreEdgeCap = coreEdgeCap
        self.contextEntityCap = contextEntityCap
        self.contextEdgeCap = contextEdgeCap
        self.aiAttributionAssertionThreshold = aiAttributionAssertionThreshold
        self.trustedConduitPolicy = trustedConduitPolicy
        self.traceSigningKeyMode = traceSigningKeyMode
        self.replayScope = replayScope
        self.attributionOverridePolicy = attributionOverridePolicy
    }

    public static let `default` = TracePolicy()
}

// MARK: - TrustedConduitPolicy

/// Per §12.1 of the v1.10.0 spec — defines what counts as a "trusted
/// conduit" process: one that is allowed to ferry untrusted code
/// without itself being treated as the root cause of a trace.
///
/// A process is a trusted conduit only when it satisfies the conjunction
/// of identity evidence, location evidence, and policy evidence (§12.1).
/// Names and argv are not enough — a malware-installed `node` in
/// `~/Downloads` is not a trusted conduit even if its process name is
/// `node`.
public struct TrustedConduitPolicy: Sendable, Equatable {

    public let trustedTeamIDs: Set<String>
    public let trustedSigningIdentifiers: Set<String>
    public let trustedPathPrefixes: Set<String>
    public let trustedExecutableHashes: Set<String>
    public let userAllowlistedProcessKeys: Set<String>
    public let userAllowlistedPathPrefixes: Set<String>
    public let denylistedPathPrefixes: Set<String>

    public init(
        trustedTeamIDs: Set<String> = [],
        trustedSigningIdentifiers: Set<String> = [],
        trustedPathPrefixes: Set<String> = [],
        trustedExecutableHashes: Set<String> = [],
        userAllowlistedProcessKeys: Set<String> = [],
        userAllowlistedPathPrefixes: Set<String> = [],
        denylistedPathPrefixes: Set<String> = []
    ) {
        self.trustedTeamIDs = trustedTeamIDs
        self.trustedSigningIdentifiers = trustedSigningIdentifiers
        self.trustedPathPrefixes = trustedPathPrefixes
        self.trustedExecutableHashes = trustedExecutableHashes
        self.userAllowlistedProcessKeys = userAllowlistedProcessKeys
        self.userAllowlistedPathPrefixes = userAllowlistedPathPrefixes
        self.denylistedPathPrefixes = denylistedPathPrefixes
    }

    /// Default policy — Apple-signed binaries from /bin, /usr/bin,
    /// /sbin, /System, /Applications, /opt/homebrew/bin,
    /// /usr/local/bin. Denylists ~/Downloads, /tmp, and browser
    /// caches per §12.1.
    public static let `default` = TrustedConduitPolicy(
        trustedTeamIDs: [],   // Apple-signed handled via signerType, not teamID
        trustedPathPrefixes: [
            "/usr/bin/",
            "/bin/",
            "/sbin/",
            "/usr/sbin/",
            "/usr/libexec/",
            "/System/",
            "/Library/Apple/",
            "/Applications/",
            "/opt/homebrew/bin/",
            "/usr/local/bin/",
        ],
        denylistedPathPrefixes: [
            "/tmp/",
            "/private/tmp/",
            "/var/tmp/",
            "/private/var/tmp/",
        ]
    )

    /// Decides whether a ProcessNode counts as a trusted conduit. Per
    /// §12.1, this is the conjunction of identity + location + policy
    /// evidence. All three must hold.
    public func isTrustedConduit(_ node: ProcessNode) -> Bool {
        // Policy evidence first — denylist always wins.
        if isInDenylist(node.executablePath) {
            return false
        }

        // Identity evidence — Apple-signed OR known team OR known hash
        // OR explicit user allowlist.
        let hasIdentityTrust =
            node.isAppleSigned
            || (node.signingTeamId.flatMap { trustedTeamIDs.contains($0) } ?? false)
            || (node.signingIdentifier.flatMap { trustedSigningIdentifiers.contains($0) } ?? false)
            || (node.executableHash.flatMap { trustedExecutableHashes.contains($0) } ?? false)
            || userAllowlistedProcessKeys.contains(node.processKey)

        // Location evidence — in a trusted prefix OR explicit user allowlist.
        let hasLocationTrust =
            isInTrustedPrefix(node.executablePath)
            || isInUserAllowlistPrefix(node.executablePath)

        return hasIdentityTrust && hasLocationTrust
    }

    /// Variant that takes a path explicitly — used when the caller
    /// has already decoded the ProcessNode attributes JSON or when
    /// classifying a non-Process entity.
    public func isPathInDenylist(_ path: String) -> Bool {
        isInDenylist(path)
    }

    private func isInDenylist(_ path: String) -> Bool {
        for prefix in denylistedPathPrefixes where path.hasPrefix(prefix) {
            return true
        }
        // ~/Downloads/ + similar — match against the user-home portion
        // of the path heuristically: any path under /Users/<x>/Downloads
        // is treated as a download location regardless of the user.
        if path.contains("/Downloads/") || path.contains("/Library/Caches/") {
            return true
        }
        return false
    }

    private func isInTrustedPrefix(_ path: String) -> Bool {
        for prefix in trustedPathPrefixes where path.hasPrefix(prefix) {
            return true
        }
        return false
    }

    private func isInUserAllowlistPrefix(_ path: String) -> Bool {
        for prefix in userAllowlistedPathPrefixes where path.hasPrefix(prefix) {
            return true
        }
        return false
    }
}
