// V2LiveDataProviderMapperTests.swift
// MacCrabAppTests
//
// Pin the mapper contract between MacCrabCore storage models and
// V2 view-model shapes. Covers toV2Alert + toV2Trace today;
// toV2Event + toV2Campaign deferred (Event constructor needs a real
// ProcessInfo; CampaignStore.Record is private).
//
// Why these matter: a silent regression here puts wrong PIDs, wrong
// MITRE chips, or stale severity badges in the dashboard. The
// alert inspector's `if let / !isEmpty` guards mean an unset
// llm/analyst field shouldn't render a UI section — these tests
// pin that pid/parent/user are zero-defaulted (the explicit
// design choice documented in the mapper body) so a future
// "let's helpfully populate those" change is caught immediately.

import Testing
import Foundation
@testable import MacCrabApp
@testable import MacCrabCore

@Suite("V2LiveDataProvider mappers")
struct V2LiveDataProviderMapperTests {

    // MARK: - toV2Alert

    @Test("toV2Alert preserves id, ruleId, title, severity, process name + path, suppressed")
    func toV2AlertCoreFields() {
        let alert = Alert(
            id: "alt-42",
            timestamp: Date(timeIntervalSince1970: 1_700_000_000),
            ruleId: "exec.osascript.suspicious",
            ruleTitle: "AppleScript spawned from a non-Apple parent",
            severity: .high,
            eventId: "evt-001",
            processPath: "/usr/bin/osascript",
            processName: "osascript",
            description: "AppleScript spawned by a non-Apple parent",
            suppressed: false
        )
        let v2 = V2LiveDataProvider.toV2Alert(alert)
        #expect(v2.id == "alt-42")
        #expect(v2.ruleId == "exec.osascript.suspicious")
        #expect(v2.title == "AppleScript spawned from a non-Apple parent")
        #expect(v2.severity == .high)
        #expect(v2.process == "osascript")
        #expect(v2.processPath == "/usr/bin/osascript")
        #expect(v2.description == "AppleScript spawned by a non-Apple parent")
        #expect(v2.suppressed == false)
        #expect(v2.timestamp == Date(timeIntervalSince1970: 1_700_000_000))
    }

    @Test("toV2Alert renders missing process name as the em-dash placeholder")
    func toV2AlertMissingProcess() {
        let alert = Alert(
            ruleId: "r.1",
            ruleTitle: "T",
            severity: .medium,
            eventId: "e.1"
        )
        let v2 = V2LiveDataProvider.toV2Alert(alert)
        #expect(v2.process == "—")
        #expect(v2.processPath == "")
    }

    @Test("toV2Alert pid/parent/user are zero-defaulted (process-side metadata lives on the Event)")
    func toV2AlertProcessMetadataDefaults() {
        // This is a contract test for the design choice documented at
        // V2LiveDataProvider.swift:883-887: Alert doesn't carry
        // pid/parent/user, and the mapper deliberately defaults them
        // so the inspector hides those rows rather than rendering
        // "PID: 0" / blank-parent fake data. If a future change adds
        // process metadata to Alert + populates it here, this test
        // is the canary.
        let alert = Alert(
            ruleId: "r.1", ruleTitle: "T", severity: .low, eventId: "e.1",
            processPath: "/usr/bin/x", processName: "x"
        )
        let v2 = V2LiveDataProvider.toV2Alert(alert)
        #expect(v2.pid == 0)
        #expect(v2.parent == "")
        #expect(v2.user == "")
        #expect(v2.actionsTaken.isEmpty)
    }

    @Test("toV2Alert maps mitreTechniques CSV into the mitre array")
    func toV2AlertMitreTechniques() {
        let alert = Alert(
            ruleId: "r.1", ruleTitle: "T", severity: .medium, eventId: "e.1",
            mitreTechniques: "T1059.004,T1547.001"
        )
        let v2 = V2LiveDataProvider.toV2Alert(alert)
        #expect(v2.mitre.contains("T1059.004"))
        #expect(v2.mitre.contains("T1547.001"))
    }

    @Test("toV2Alert pulls category from the first MITRE tactic, fallback em-dash")
    func toV2AlertCategoryFallback() {
        let withTactic = Alert(
            ruleId: "r.1", ruleTitle: "T", severity: .medium, eventId: "e.1",
            mitreTactics: "TA0003,TA0005"
        )
        let v2 = V2LiveDataProvider.toV2Alert(withTactic)
        #expect(v2.category == "TA0003")

        let noTactic = Alert(
            ruleId: "r.2", ruleTitle: "T", severity: .medium, eventId: "e.2"
        )
        let v2b = V2LiveDataProvider.toV2Alert(noTactic)
        #expect(v2b.category == "uncategorised")
    }

    @Test("toV2Alert maps all severity levels through the public V2Severity enum")
    func toV2AlertSeverityMatrix() {
        func mapsTo(_ s: MacCrabCore.Severity, _ expected: V2Severity) {
            let a = Alert(ruleId: "r", ruleTitle: "t", severity: s, eventId: "e")
            #expect(V2LiveDataProvider.toV2Alert(a).severity == expected)
        }
        mapsTo(.critical, .critical)
        mapsTo(.high, .high)
        mapsTo(.medium, .medium)
        mapsTo(.low, .low)
        mapsTo(.informational, .info)
    }

    // MARK: - toV2Trace

    private func makeTrace(
        id: String = "trc-1",
        title: String = "Trace 1",
        status: String = "open",
        severity: String = "high",
        rootEntityId: String? = "process:42"
    ) -> Trace {
        Trace(
            id: id, title: title,
            anchorEventId: "evt-anchor",
            rootEntityId: rootEntityId,
            severity: severity,
            confidence: 0.92,
            status: status,
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            updatedAt: Date(timeIntervalSince1970: 1_700_000_300),
            daemonVersion: "1.11.0",
            rulesetVersion: "rs-1",
            policyId: "default",
            policyVersion: "1",
            policySha256: "deadbeef",
            policySnapshotJson: "{}",
            traceSigningKeyMode: "filesystem_degraded",
            replayScope: "declared_deterministic_subset",
            attributionOverridePolicy: "include_as_human_annotation_do_not_apply_by_default"
        )
    }

    @Test("toV2Trace preserves id, title, status as anchorVerdict, and timestamps")
    func toV2TraceCoreFields() {
        let trace = makeTrace()
        let v2 = V2LiveDataProvider.toV2Trace(trace)
        #expect(v2.id == "trc-1")
        #expect(v2.title == "Trace 1")
        #expect(v2.anchorVerdict == "open")
        #expect(v2.firstSeen == Date(timeIntervalSince1970: 1_700_000_000))
        #expect(v2.lastUpdated == Date(timeIntervalSince1970: 1_700_000_300))
    }

    @Test("toV2Trace renders missing rootEntityId as the em-dash placeholder")
    func toV2TraceMissingRoot() {
        let trace = makeTrace(rootEntityId: nil)
        let v2 = V2LiveDataProvider.toV2Trace(trace)
        #expect(v2.rootProcess == "—")
    }

    @Test("toV2Trace.isDemo flips on [DEMO] title prefix (demo seeder discipline)")
    func toV2TraceIsDemoFlag() {
        let demo = makeTrace(title: "[DEMO] Lazarus stage-1")
        let real = makeTrace(title: "AppleScript credential access")
        #expect(V2LiveDataProvider.toV2Trace(demo).isDemo == true)
        #expect(V2LiveDataProvider.toV2Trace(real).isDemo == false)
    }

    @Test("toV2Trace severityHint maps recognized strings; unknown falls back gracefully")
    func toV2TraceSeverityHint() {
        // Severity strings come from the daemon ("critical"/"high"/"medium"/
        // "low"/"info") — anything else should land on a safe default.
        let crit = V2LiveDataProvider.toV2Trace(makeTrace(severity: "critical"))
        let high = V2LiveDataProvider.toV2Trace(makeTrace(severity: "high"))
        let unknown = V2LiveDataProvider.toV2Trace(makeTrace(severity: "tomatoes"))
        #expect(crit.severityHint == .critical)
        #expect(high.severityHint == .high)
        // Unknown string must not crash and must land on a defined V2Severity.
        #expect(V2Severity.allCases.contains(unknown.severityHint))
    }

    @Test("toV2Trace.nodeCount/edgeCount remain zero (full graph hydrate is a later phase)")
    func toV2TraceNodeEdgeCountsPlaceholder() {
        // Pin the v1.10/v1.11 contract: the mapper sets nodeCount=0 +
        // edgeCount=0 because the graph fan-out happens via a separate
        // loadTrace() round-trip. If a future change populates these
        // from Trace metadata directly, update the test alongside.
        let v2 = V2LiveDataProvider.toV2Trace(makeTrace())
        #expect(v2.nodeCount == 0)
        #expect(v2.edgeCount == 0)
    }
}

// Pin the composite-rule (sequence + graph) id→title reader that backs
// the Detection workspace's "no editable rule matches" note. Sequence
// rule ids are UUIDs and graph rule ids are `maccrab_` slugs — neither
// is a single-event Sigma rule, so an alert deep-linking one would land
// on a blank rules table without this map. Pre-fix only `maccrab.`-dot
// built-ins were explained; sequence/graph alerts showed nothing.
@Suite("V2LiveDataProvider composite rule labels")
struct V2CompositeRuleLabelsTests {

    /// Build a temp compiled_rules tree with the given sequence/graph
    /// file contents and return its sequences/ + graph/ dir paths.
    private func makeTempTree(
        sequences: [String: String] = [:],
        graph: [String: String] = [:]
    ) throws -> (seq: String, graph: String) {
        let fm = FileManager.default
        let root = NSTemporaryDirectory() + "maccrab-composite-test-"
            + UUID().uuidString + "/compiled_rules"
        let seqDir = root + "/sequences"
        let graphDir = root + "/graph"
        try fm.createDirectory(atPath: seqDir, withIntermediateDirectories: true)
        try fm.createDirectory(atPath: graphDir, withIntermediateDirectories: true)
        for (name, body) in sequences {
            try body.write(toFile: seqDir + "/" + name, atomically: true, encoding: .utf8)
        }
        for (name, body) in graph {
            try body.write(toFile: graphDir + "/" + name, atomically: true, encoding: .utf8)
        }
        return (seqDir, graphDir)
    }

    @Test("Reads sequence + graph ids, lowercases keys, preserves titles")
    func readsBothFamilies() throws {
        let dirs = try makeTempTree(
            sequences: ["s1.json": #"{"id":"e1f2a3b4-0007-4000-b000-000000000007","title":"AI Tool Reads Credentials Then Network","level":"high"}"#],
            graph: ["g1.json": #"{"id":"maccrab_worm_self_propagation","title":"Worm self-propagation","severity":"critical"}"#]
        )
        let map = V2LiveDataProvider.loadCompositeRuleLabels(
            sequencesDir: dirs.seq, graphDir: dirs.graph)
        #expect(map.count == 2)
        // Keys lowercased so they match the workspace's lowercased query.
        #expect(map["e1f2a3b4-0007-4000-b000-000000000007"] == "AI Tool Reads Credentials Then Network")
        #expect(map["maccrab_worm_self_propagation"] == "Worm self-propagation")
    }

    @Test("An uppercase id is matchable via its lowercased key")
    func lowercasesUppercaseIds() throws {
        let dirs = try makeTempTree(
            graph: ["g.json": #"{"id":"MacCrab_Mixed_Case","title":"Mixed"}"#]
        )
        let map = V2LiveDataProvider.loadCompositeRuleLabels(
            sequencesDir: dirs.seq, graphDir: dirs.graph)
        #expect(map["maccrab_mixed_case"] == "Mixed")
        #expect(map["MacCrab_Mixed_Case"] == nil)
    }

    @Test("Malformed or non-json files are skipped, not fatal")
    func skipsMalformed() throws {
        let dirs = try makeTempTree(
            sequences: [
                "ok.json": #"{"id":"seq-ok","title":"Good"}"#,
                "bad.json": "{ not valid json",
                "noid.json": #"{"title":"missing id"}"#,
                "notes.txt": #"{"id":"ignored","title":"wrong ext"}"#
            ]
        )
        let map = V2LiveDataProvider.loadCompositeRuleLabels(
            sequencesDir: dirs.seq, graphDir: dirs.graph)
        #expect(map == ["seq-ok": "Good"])
    }

    @Test("Missing directories return empty without throwing")
    func missingDirsAreEmpty() {
        let map = V2LiveDataProvider.loadCompositeRuleLabels(
            sequencesDir: "/nonexistent/seq", graphDir: "/nonexistent/graph")
        #expect(map.isEmpty)
    }
}
