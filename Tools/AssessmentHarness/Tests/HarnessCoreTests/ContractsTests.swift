import Testing
import Foundation
@testable import HarnessCore

// assessment-framework (P0): exercises the wire schema — round-trips, snake_case
// key mapping, and the enum raw values a future public repo pins against.

private func sampleVerdictRecord() -> VerdictRecord {
    VerdictRecord(
        featureId: "persistence.launchd",
        lane: .liveTrigger,
        triggerRef: TriggerRef(
            source: "redteam-sim",
            testGuid: "GUID-123",
            cmdSha256: "abc123"
        ),
        expectedRuleId: "launchd_persistence_root",
        expectedMinSeverity: "high",
        observedFired: true,
        observedAlertId: "alert-42",
        verdict: .pass,
        oracle: "SingleEventOracle",
        measured: DetectionScore(
            precision: 0.98,
            heldOutRecall: 0.91,
            obfuscationCoverage: 0.75,
            fpPerDay: 1.5,
            evalP95Ms: 12.0,
            peakPartialMatches: 3,
            tp: 49,
            fp: 1,
            fn: 5,
            metadataComplete: true
        ),
        requiresRoot: true,
        evidenceRef: "bundle://evidence/42",
        timestamp: "2026-07-22T00:00:00Z"
    )
}

private func sampleReport() -> AssessmentReport {
    AssessmentReport(
        schemaVersion: currentAssessmentSchemaVersion,
        maccrabVersion: "v1.21.5",
        commit: "ff4b14d",
        hostProfile: HostProfile(privilegeLane: "root", esEntitled: true, os: "macOS 15.0"),
        lanesRun: [.offlineReplay, .seededStore, .liveTrigger],
        featureVerdicts: [sampleVerdictRecord()],
        summary: Summary(pass: 1, fail: 0, skip: 0, inconclusive: 0),
        regressions: [Regression(ruleId: "launchd_persistence_root", axis: "precision", was: 0.99, now: 0.98)],
        evidenceBundleRef: "bundle://run/1",
        signature: "sig-xyz"
    )
}

@Test func verdictRecordRoundTrips() throws {
    let original = sampleVerdictRecord()
    let data = try JSONEncoder().encode(original)
    let decoded = try JSONDecoder().decode(VerdictRecord.self, from: data)

    #expect(decoded.featureId == original.featureId)
    #expect(decoded.lane == original.lane)
    #expect(decoded.verdict == original.verdict)
    #expect(decoded.oracle == original.oracle)
    #expect(decoded.requiresRoot == original.requiresRoot)
    #expect(decoded.triggerRef?.testGuid == original.triggerRef?.testGuid)
    #expect(decoded.measured.heldOutRecall == original.measured.heldOutRecall)
    #expect(decoded.measured.peakPartialMatches == original.measured.peakPartialMatches)
    #expect(decoded.timestamp == original.timestamp)
}

@Test func assessmentReportRoundTrips() throws {
    let original = sampleReport()
    let data = try JSONEncoder().encode(original)
    let decoded = try JSONDecoder().decode(AssessmentReport.self, from: data)

    #expect(decoded.schemaVersion == original.schemaVersion)
    #expect(decoded.maccrabVersion == original.maccrabVersion)
    #expect(decoded.commit == original.commit)
    #expect(decoded.hostProfile.privilegeLane == original.hostProfile.privilegeLane)
    #expect(decoded.lanesRun == original.lanesRun)
    #expect(decoded.featureVerdicts.count == original.featureVerdicts.count)
    #expect(decoded.summary.pass == original.summary.pass)
    #expect(decoded.regressions.first?.ruleId == original.regressions.first?.ruleId)
    #expect(decoded.signature == original.signature)
}

@Test func encodesSnakeCaseWireKeys() throws {
    let data = try JSONEncoder().encode(sampleReport())
    let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
    let unwrapped = try #require(json)

    // top-level report key
    #expect(unwrapped["schema_version"] != nil)

    // nested verdict-record key
    let verdicts = try #require(unwrapped["feature_verdicts"] as? [[String: Any]])
    let firstVerdict = try #require(verdicts.first)
    #expect(firstVerdict["feature_id"] != nil)

    // deeply-nested detection-score key
    let measured = try #require(firstVerdict["measured"] as? [String: Any])
    #expect(measured["held_out_recall"] != nil)
}

@Test func enumRawValuesAreStable() {
    #expect(Verdict.pass.rawValue == "pass")
    #expect(Lane.offlineReplay.rawValue == "offline_replay")
}
