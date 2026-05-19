// Analyzer scope + Finding types. The v1.15 posture Analyzer
// (`com.maccrab.forensics.posture-analyzer`) is the first concrete
// Analyzer.
//
// Plan reference: §7 v1.15 card.

import Foundation

/// Scope passed to `Analyzer.analyze(...)`. Defaults to whole case
/// (no narrowing).
public struct AnalyzerScope: Sendable, Codable {

    /// Restrict to artifacts whose `observed_at` is within the
    /// window. `nil` means whole case.
    public let timeWindow: TimeWindow?

    /// Restrict to specific content types. `nil` means all content
    /// types present in the case.
    public let contentTypes: [String]?

    public init(
        timeWindow: TimeWindow? = nil,
        contentTypes: [String]? = nil
    ) {
        self.timeWindow = timeWindow
        self.contentTypes = contentTypes
    }

    public static let wholeCase = AnalyzerScope()
}

/// A structured finding produced by an Analyzer. The v1.15 posture
/// Analyzer emits, among others:
///   - `posture.unsigned_persistence`
///   - `posture.unfamiliar_team_persistence`
///   - `posture.privileged_dormant_app`
///   - `posture.fingerprint_drift`           (only if MCFP R2 ships)
///   - `posture.automation_to_sensitive_target`
///   - `posture.high_privilege_unsigned_combo`
///   - `posture.permissioned_persistence`
///   - `posture.suspicious_correlation`      (feature-flagged in v1.15)
///
/// Findings get committed back to the ArtifactStore as artifacts
/// (content_type = the finding name), so they're queryable +
/// exportable like every other artifact.
public struct Finding: Sendable, Codable {

    /// Finding type, e.g. `posture.unsigned_persistence`. Matches
    /// the content_type stamped on the committed artifact.
    public let findingType: String

    /// Severity. Drives dashboard sorting and MCP exposure
    /// prioritization.
    public let severity: Severity

    /// Operator-facing title; appears as the finding heading.
    public let title: String

    /// Long-form explanation; surfaced under "What does this mean"
    /// in the dashboard.
    public let explanation: String

    /// Optional pointers back to the artifacts that drove this
    /// finding. Each entry is a `(content_type, artifact_id)` pair
    /// resolvable inside the case.
    public let backedBy: [FindingEvidence]

    /// Confidence in the finding overall.
    public let confidence: Confidence

    public init(
        findingType: String,
        severity: Severity,
        title: String,
        explanation: String,
        backedBy: [FindingEvidence] = [],
        confidence: Confidence = .derived
    ) {
        self.findingType = findingType
        self.severity = severity
        self.title = title
        self.explanation = explanation
        self.backedBy = backedBy
        self.confidence = confidence
    }

    public enum Severity: String, Codable, Sendable, Comparable {
        case informational
        case low
        case medium
        case high
        case critical

        private var order: Int {
            switch self {
            case .informational: return 0
            case .low: return 1
            case .medium: return 2
            case .high: return 3
            case .critical: return 4
            }
        }

        public static func < (lhs: Severity, rhs: Severity) -> Bool {
            lhs.order < rhs.order
        }
    }
}

/// Reference to a single artifact that drove a finding. The
/// dashboard renders these as clickable links into the artifact
/// detail view.
public struct FindingEvidence: Sendable, Codable {
    public let contentType: String
    public let artifactID: Int64

    public init(contentType: String, artifactID: Int64) {
        self.contentType = contentType
        self.artifactID = artifactID
    }
}
