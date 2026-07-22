import Foundation

// assessment-framework (P0): imported solely to prove the MacCrabCore dependency
// resolves from the sub-package. No Core type is referenced yet — the seams land
// in P1+. Keeping the import here documents the intended coupling point.
import MacCrabCore

// Versioned Codable schemas — the interface a future public repo pins against.
// Swift stays camelCase; the wire format is snake_case via explicit CodingKeys.
// Every field the harness emits is optional-tolerant so older/newer readers do
// not hard-fail on a schema drift within the same major schema version.

/// Current on-disk schema version for assessment artifacts. Bump on breaking wire
/// changes; readers pin to this.
public let currentAssessmentSchemaVersion = 1

/// The three assessment lanes, in ascending order of environmental coupling.
public enum Lane: String, Codable, Sendable {
    case offlineReplay = "offline_replay"
    case seededStore = "seeded_store"
    case liveTrigger = "live_trigger"
}

/// The 5-axis detection-engineering score plus supporting counts. All fields are
/// optional so a lane that cannot measure an axis simply omits it.
public struct DetectionScore: Codable, Sendable {
    public var precision: Double?
    public var heldOutRecall: Double?
    public var obfuscationCoverage: Double?
    public var fpPerDay: Double?
    public var evalP95Ms: Double?
    public var peakPartialMatches: Int?
    public var tp: Int?
    public var fp: Int?
    public var fn: Int?
    public var metadataComplete: Bool?

    enum CodingKeys: String, CodingKey {
        case precision
        case heldOutRecall = "held_out_recall"
        case obfuscationCoverage = "obfuscation_coverage"
        case fpPerDay = "fp_per_day"
        case evalP95Ms = "eval_p95_ms"
        case peakPartialMatches = "peak_partial_matches"
        case tp
        case fp
        case fn
        case metadataComplete = "metadata_complete"
    }

    public init(
        precision: Double? = nil,
        heldOutRecall: Double? = nil,
        obfuscationCoverage: Double? = nil,
        fpPerDay: Double? = nil,
        evalP95Ms: Double? = nil,
        peakPartialMatches: Int? = nil,
        tp: Int? = nil,
        fp: Int? = nil,
        fn: Int? = nil,
        metadataComplete: Bool? = nil
    ) {
        self.precision = precision
        self.heldOutRecall = heldOutRecall
        self.obfuscationCoverage = obfuscationCoverage
        self.fpPerDay = fpPerDay
        self.evalP95Ms = evalP95Ms
        self.peakPartialMatches = peakPartialMatches
        self.tp = tp
        self.fp = fp
        self.fn = fn
        self.metadataComplete = metadataComplete
    }
}

/// Provenance for how a detection was triggered, so a verdict can be reproduced.
public struct TriggerRef: Codable, Sendable {
    public var source: String
    public var testGuid: String?
    public var cmdSha256: String?

    enum CodingKeys: String, CodingKey {
        case source
        case testGuid = "test_guid"
        case cmdSha256 = "cmd_sha256"
    }

    public init(source: String, testGuid: String? = nil, cmdSha256: String? = nil) {
        self.source = source
        self.testGuid = testGuid
        self.cmdSha256 = cmdSha256
    }
}

/// One feature's assessment outcome in one lane. `verdict` is set only by an
/// Oracle; the agent fills everything around it (observations, evidence pointers).
public struct VerdictRecord: Codable, Sendable {
    public var featureId: String
    public var lane: Lane
    public var triggerRef: TriggerRef?
    public var expectedRuleId: String?
    public var expectedMinSeverity: String?
    public var observedFired: Bool?
    public var observedAlertId: String?
    public var verdict: Verdict
    public var oracle: String
    public var measured: DetectionScore
    public var requiresRoot: Bool
    public var evidenceRef: String?
    public var timestamp: String

    enum CodingKeys: String, CodingKey {
        case featureId = "feature_id"
        case lane
        case triggerRef = "trigger_ref"
        case expectedRuleId = "expected_rule_id"
        case expectedMinSeverity = "expected_min_severity"
        case observedFired = "observed_fired"
        case observedAlertId = "observed_alert_id"
        case verdict
        case oracle
        case measured
        case requiresRoot = "requires_root"
        case evidenceRef = "evidence_ref"
        case timestamp
    }

    public init(
        featureId: String,
        lane: Lane,
        triggerRef: TriggerRef? = nil,
        expectedRuleId: String? = nil,
        expectedMinSeverity: String? = nil,
        observedFired: Bool? = nil,
        observedAlertId: String? = nil,
        verdict: Verdict,
        oracle: String,
        measured: DetectionScore,
        requiresRoot: Bool,
        evidenceRef: String? = nil,
        timestamp: String
    ) {
        self.featureId = featureId
        self.lane = lane
        self.triggerRef = triggerRef
        self.expectedRuleId = expectedRuleId
        self.expectedMinSeverity = expectedMinSeverity
        self.observedFired = observedFired
        self.observedAlertId = observedAlertId
        self.verdict = verdict
        self.oracle = oracle
        self.measured = measured
        self.requiresRoot = requiresRoot
        self.evidenceRef = evidenceRef
        self.timestamp = timestamp
    }
}

/// The privilege / entitlement context the assessment ran under. Lets a reader
/// tell a legitimately-skipped root-only check from a real failure.
public struct HostProfile: Codable, Sendable {
    public var privilegeLane: String
    public var esEntitled: Bool
    public var os: String

    enum CodingKeys: String, CodingKey {
        case privilegeLane = "privilege_lane"
        case esEntitled = "es_entitled"
        case os
    }

    public init(privilegeLane: String, esEntitled: Bool, os: String) {
        self.privilegeLane = privilegeLane
        self.esEntitled = esEntitled
        self.os = os
    }
}

/// Roll-up counts across all verdict records in a report.
public struct Summary: Codable, Sendable {
    public var pass: Int
    public var fail: Int
    public var skip: Int
    public var inconclusive: Int

    public init(pass: Int, fail: Int, skip: Int, inconclusive: Int) {
        self.pass = pass
        self.fail = fail
        self.skip = skip
        self.inconclusive = inconclusive
    }
}

/// A single-axis regression detected against a baseline run.
public struct Regression: Codable, Sendable {
    public var ruleId: String
    public var axis: String
    public var was: Double
    public var now: Double

    enum CodingKeys: String, CodingKey {
        case ruleId = "rule_id"
        case axis
        case was
        case now
    }

    public init(ruleId: String, axis: String, was: Double, now: Double) {
        self.ruleId = ruleId
        self.axis = axis
        self.was = was
        self.now = now
    }
}

/// The top-level assessment artifact. `signature` is populated in a later phase.
public struct AssessmentReport: Codable, Sendable {
    public var schemaVersion: Int
    public var maccrabVersion: String
    public var commit: String
    public var hostProfile: HostProfile
    public var lanesRun: [Lane]
    public var featureVerdicts: [VerdictRecord]
    public var summary: Summary
    public var regressions: [Regression]
    public var evidenceBundleRef: String?
    public var signature: String?

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case maccrabVersion = "maccrab_version"
        case commit
        case hostProfile = "host_profile"
        case lanesRun = "lanes_run"
        case featureVerdicts = "feature_verdicts"
        case summary
        case regressions
        case evidenceBundleRef = "evidence_bundle_ref"
        case signature
    }

    public init(
        schemaVersion: Int,
        maccrabVersion: String,
        commit: String,
        hostProfile: HostProfile,
        lanesRun: [Lane],
        featureVerdicts: [VerdictRecord],
        summary: Summary,
        regressions: [Regression],
        evidenceBundleRef: String? = nil,
        signature: String? = nil
    ) {
        self.schemaVersion = schemaVersion
        self.maccrabVersion = maccrabVersion
        self.commit = commit
        self.hostProfile = hostProfile
        self.lanesRun = lanesRun
        self.featureVerdicts = featureVerdicts
        self.summary = summary
        self.regressions = regressions
        self.evidenceBundleRef = evidenceBundleRef
        self.signature = signature
    }
}

/// Declarative description of an assessable feature — the input catalog the
/// harness walks to decide what to trigger and in which lanes.
public struct FeatureDescriptor: Codable, Sendable {
    public var id: String
    public var name: String
    public var category: String
    public var maturity: String
    public var defaultEnabled: Bool
    public var enableGate: String?
    public var probe: String
    public var assessmentLanes: [Lane]
    public var claimRefs: [String]

    enum CodingKeys: String, CodingKey {
        case id
        case name
        case category
        case maturity
        case defaultEnabled = "default_enabled"
        case enableGate = "enable_gate"
        case probe
        case assessmentLanes = "assessment_lanes"
        case claimRefs = "claim_refs"
    }

    public init(
        id: String,
        name: String,
        category: String,
        maturity: String,
        defaultEnabled: Bool,
        enableGate: String? = nil,
        probe: String,
        assessmentLanes: [Lane],
        claimRefs: [String]
    ) {
        self.id = id
        self.name = name
        self.category = category
        self.maturity = maturity
        self.defaultEnabled = defaultEnabled
        self.enableGate = enableGate
        self.probe = probe
        self.assessmentLanes = assessmentLanes
        self.claimRefs = claimRefs
    }
}

/// One cell of the feature × lane coverage matrix.
public struct CoverageMatrixEntry: Codable, Sendable {
    public var featureId: String
    public var lanes: [Lane]
    public var status: String
    public var reason: String?

    enum CodingKeys: String, CodingKey {
        case featureId = "feature_id"
        case lanes
        case status
        case reason
    }

    public init(featureId: String, lanes: [Lane], status: String, reason: String? = nil) {
        self.featureId = featureId
        self.lanes = lanes
        self.status = status
        self.reason = reason
    }
}
