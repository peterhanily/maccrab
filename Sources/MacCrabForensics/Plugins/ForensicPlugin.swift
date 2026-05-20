// ForensicPlugin — the base protocol every plugin conforms to,
// plus the four kind-specific sub-protocols.
//
// Plan reference: §3.3.

import Foundation

/// Base protocol. Every plugin advertises a static manifest and an
/// async failable initializer. The runtime constructs an instance
/// per case, invokes the type-specific method, then discards.
///
/// Plugins are intentionally instance-scoped rather than singleton
/// — keeps per-invocation state contained, avoids surprises when
/// multiple cases run in parallel.
public protocol ForensicPlugin: Sendable {
    /// Declares the plugin's identity, version, and IO contract.
    static var manifest: PluginManifest { get }

    /// Construct an instance. May fail if initial setup (e.g.
    /// loading a fixture corpus) errors. The runtime catches the
    /// throw and emits a load-failed invocation log entry.
    init() async throws
}

// MARK: - Collector

/// Extracts artifacts from a Mac-native data source into the
/// ArtifactStore. v1.13a's two real collectors are TCC-lite
/// (§4.1) and launchd-lite (§4.2).
public protocol Collector: ForensicPlugin {
    /// Invoked by `maccrabctl plugin run`, the case scheduler, or
    /// an AI agent via MCP.
    ///
    /// Receives:
    ///   - `case`: the unlocked CaseContext (DEK already applied
    ///     to SQLCipher; encryption_state available for plugin
    ///     decisioning).
    ///   - `window`: optional time window; plugins MAY ignore if
    ///     their source is point-in-time (TCC.db, launchd state).
    ///   - `output`: narrow write-only handle for committing
    ///     artifacts. The plugin calls `output.commit(_:)` for
    ///     each artifact discovered; the runtime tallies counts
    ///     into `CollectionResult.artifactsCommitted`.
    func collect(
        case: CaseContext,
        window: TimeWindow?,
        output: any CollectorOutput
    ) async throws -> CollectionResult
}

// MARK: - Enricher

/// Adds fields to an existing event / alert / artifact without
/// owning a primary data source. Wired into Track 1's event
/// pipeline at the `stage` it declares.
///
/// Plan §5. v1.13a-2 ships the codesign-resolve enricher
/// (`com.maccrab.enricher.codesign-resolve`) at `.preDetection`.
public protocol Enricher: ForensicPlugin {
    /// Which stage(s) of the event pipeline this enricher fires
    /// against. Most enrichers declare exactly one; a few (like
    /// codesign-resolve, which also runs `.onDemand` for ad-hoc
    /// path lookups) declare multiple.
    var stages: Set<EnrichmentStage> { get }

    /// Audit Pass 2026-C invariant: this function MUST be
    /// byte-identical on re-runs against the same
    /// `(subject, stage)` pair. Side-effects are forbidden;
    /// network calls and writes outside the returned struct are
    /// forbidden. The Pass enforces by re-running on a corpus and
    /// diffing.
    func enrich(
        _ subject: EnrichmentSubject,
        stage: EnrichmentStage
    ) async throws -> Enrichment
}

// MARK: - Fingerprinter

/// Computes a derived signature for a process / file / artifact.
/// v1.15 conditional plugin `com.maccrab.fingerprinter.mcfp` is
/// the first real Fingerprinter (gated on MCFP R2 ship criteria,
/// plan §6.4 R2).
public protocol Fingerprinter: ForensicPlugin {
    /// Compute the fingerprint for a target. Components in
    /// `FingerprintResult` carry per-component `Confidence`; the
    /// caller decides which to trust for a given use.
    func fingerprint(
        _ target: FingerprintTarget
    ) async throws -> FingerprintResult
}

// MARK: - Analyzer

/// Reads existing collected artifacts and emits findings — the
/// composition-proof for the platform. v1.15 ships
/// `com.maccrab.forensics.posture-analyzer` (plan §7 v1.15 card).
public protocol Analyzer: ForensicPlugin {
    /// Run analysis against a case. `scope` lets the caller narrow
    /// to a time window, a specific content type, or a tagged
    /// subset; defaults to whole-case scope.
    func analyze(
        case: CaseContext,
        scope: AnalyzerScope
    ) async throws -> [Finding]
}
