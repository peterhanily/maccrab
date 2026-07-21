// V2LiveDataProviderMapperTests.swift
// MacCrabAppTests
//
// Pin the mapper contract between MacCrabCore storage models and
// V2 view-model shapes. Covers toV2Alert + toV2Trace + toV2Package
// (v1.21.5); toV2Event + toV2Campaign deferred (Event constructor
// needs a real ProcessInfo; CampaignStore.Record is private).
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

    // MARK: - toV2Package (v1.21.5 — package freshness honesty)

    @Test("toV2Package maps an unenriched scan to nil latest/staleness — 'Not scanned', never 'Up to date'")
    func toV2PackageUnenriched() {
        // Contract test for the v1.21.5 fix: PackageScanner's default
        // (inventory-only) output has NO registry data behind it. Pre-fix
        // latestVersion defaulted to installedVersion and stalenessSeconds
        // to 0, so out-of-box every package rendered "Up to date" /
        // "Behind <1m" — a false security posture. Nil must survive the
        // mapper so the UI can render "Not scanned" / "—".
        let info = PackageInfo(name: "left-pad", installedVersion: "1.3.0", manager: "npm")
        #expect(info.latestVersion == nil)
        #expect(info.stalenessSeconds == nil)
        let v2 = V2LiveDataProvider.toV2Package(info)
        #expect(v2.latest == nil)
        #expect(v2.staleness == nil)
        #expect(v2.isScanned == false)
        // Unknown is not "outdated" either — no posture claim at all.
        #expect(v2.isOutdated == false)
    }

    @Test("toV2Package passes a real registry result through unchanged")
    func toV2PackageEnriched() {
        let outdated = PackageInfo(
            name: "express", installedVersion: "4.18.2", manager: "npm",
            latestVersion: "4.19.2", stalenessSeconds: 14 * 86400)
        let v2 = V2LiveDataProvider.toV2Package(outdated)
        #expect(v2.installed == "4.18.2")
        #expect(v2.latest == "4.19.2")
        #expect(v2.staleness == TimeInterval(14 * 86400))
        #expect(v2.isScanned == true)
        #expect(v2.isOutdated == true)

        let current = PackageInfo(
            name: "git", installedVersion: "2.43.0", manager: "brew",
            latestVersion: "2.43.0", stalenessSeconds: 0)
        let v2b = V2LiveDataProvider.toV2Package(current)
        #expect(v2b.isScanned == true)
        #expect(v2b.isOutdated == false)
    }

    @Test("up-to-date summary counting excludes unscanned packages")
    func upToDateCountsExcludeUnscanned() {
        // Mirrors packageSummaryRow's tile math: unscanned rows contribute
        // to "Tracked" but never to "Outdated" / "Up to date".
        let pkgs = [
            V2MockPackage(id: "npm:a", name: "a", installed: "1.0.0", latest: nil,
                          manager: "npm", vulnCount: 0, staleness: nil),
            V2MockPackage(id: "npm:b", name: "b", installed: "1.0.0", latest: "1.0.0",
                          manager: "npm", vulnCount: 0, staleness: 0),
            V2MockPackage(id: "npm:c", name: "c", installed: "1.0.0", latest: "2.0.0",
                          manager: "npm", vulnCount: 0, staleness: 86400),
        ]
        let scanned = pkgs.filter(\.isScanned).count
        let outdated = pkgs.filter(\.isOutdated).count
        #expect(scanned == 2)
        #expect(outdated == 1)
        #expect(scanned - outdated == 1) // only the genuinely-current package
        // All-unscanned inventory → zero scanned, so the tiles show the
        // "Not scanned yet" state rather than "N up to date".
        let unscanned = [pkgs[0]]
        #expect(unscanned.filter(\.isScanned).isEmpty)
    }

    @Test("staleness(nil) renders the em-dash placeholder, never '<1m'")
    func stalenessNilNeverRendersUpToDate() {
        // Regression pin for the v1.21.5 fix: the pre-fix default of 0
        // seconds formatted as "<1m", presenting never-scanned packages
        // as essentially current. Nil must render as unknown.
        #expect(V2TimeFormat.staleness(nil) == "—")
        #expect(V2TimeFormat.staleness(nil) != "<1m")
        // Real values keep their pre-v1.21.5 formatting.
        #expect(V2TimeFormat.staleness(0) == "<1m")
        #expect(V2TimeFormat.staleness(3600) == "1h")
        #expect(V2TimeFormat.staleness(14 * 86400) == "14d")
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

// v1.21.5: the Intelligence workspace's package-table helpers. The
// auto-refresh merge exists because the provider's PackageScanner rows
// are ALWAYS unscanned (latest/staleness nil by design), so the old
// wholesale `self.packages = pkgsResult` replace discarded every manual
// scan's registry results five minutes after Run Scan.
@Suite("V2IntelligenceWorkspace package merge + manual-scan mapper")
struct V2IntelligencePackageMergeTests {

    private func scanned(
        _ id: String, name: String, latest: String, behindDays: Double
    ) -> V2MockPackage {
        V2MockPackage(id: id, name: name, installed: "1.0.0", latest: latest,
                      manager: String(id.split(separator: ":")[0]),
                      vulnCount: 0, staleness: behindDays * 86400)
    }

    private func unscanned(
        _ id: String, name: String, typosquatScore: Int? = nil
    ) -> V2MockPackage {
        V2MockPackage(id: id, name: name, installed: "1.0.0", latest: nil,
                      manager: String(id.split(separator: ":")[0]),
                      vulnCount: 0, staleness: nil,
                      typosquatScore: typosquatScore)
    }

    @Test("an all-unscanned provider refresh never clobbers scanned rows")
    func unscannedRefreshPreservesScannedData() {
        // Existing rows come from a manual scan → PackageFreshnessChecker
        // registry ids ("homebrew:", "pypi:"). The provider refresh uses
        // PackageScanner manager ids ("brew:", "pip:") — the merge must
        // match across the two namespaces or the carry-forward never fires.
        let existing = [
            scanned("homebrew:wget", name: "wget", latest: "1.25.0", behindDays: 400),
            scanned("pypi:requests", name: "requests", latest: "2.32.3", behindDays: 14),
            scanned("homebrew:gone", name: "gone", latest: "9.9.9", behindDays: 1),
        ]
        let incoming = [
            unscanned("brew:wget", name: "wget", typosquatScore: 55),
            unscanned("pip:requests", name: "requests"),
            unscanned("npm:left-pad", name: "left-pad"),   // genuinely new
        ]
        let merged = V2IntelligenceWorkspace.mergePackages(
            existing: existing, incoming: incoming)
        #expect(merged.count == 3)

        // Scanned registry data survives the unscanned refresh...
        let wget = merged.first { $0.name == "wget" }
        #expect(wget?.latest == "1.25.0")
        #expect(wget?.staleness == TimeInterval(400 * 86400))
        #expect(wget?.isScanned == true)
        #expect(wget?.isOutdated == true)
        // ...while the incoming row's identity + intelligence fields win.
        #expect(wget?.id == "brew:wget")
        #expect(wget?.typosquatScore == 55)

        let requests = merged.first { $0.name == "requests" }
        #expect(requests?.latest == "2.32.3")
        #expect(requests?.isScanned == true)

        // New ids append (still unscanned), missing ids drop.
        let leftPad = merged.first { $0.name == "left-pad" }
        #expect(leftPad?.isScanned == false)
        #expect(!merged.contains { $0.name == "gone" })
    }

    @Test("incoming SCANNED rows replace normally (future daemon enrichment wins)")
    func scannedIncomingReplaces() {
        let existing = [scanned("brew:wget", name: "wget", latest: "1.24.0", behindDays: 500)]
        let incoming = [scanned("brew:wget", name: "wget", latest: "1.25.0", behindDays: 30)]
        let merged = V2IntelligenceWorkspace.mergePackages(
            existing: existing, incoming: incoming)
        #expect(merged.count == 1)
        #expect(merged.first?.latest == "1.25.0")
        #expect(merged.first?.staleness == TimeInterval(30 * 86400))
    }

    @Test("canonical key folds registry and manager namespaces together")
    func canonicalKeyFoldsNamespaces() {
        #expect(V2IntelligenceWorkspace.canonicalPackageKey("homebrew:wget") == "brew:wget")
        #expect(V2IntelligenceWorkspace.canonicalPackageKey("brew:wget") == "brew:wget")
        #expect(V2IntelligenceWorkspace.canonicalPackageKey("pypi:requests") == "pip:requests")
        #expect(V2IntelligenceWorkspace.canonicalPackageKey("pip:requests") == "pip:requests")
        #expect(V2IntelligenceWorkspace.canonicalPackageKey("npm:left-pad") == "npm:left-pad")
        // Unknown namespaces pass through lowercased; no-colon ids untouched.
        #expect(V2IntelligenceWorkspace.canonicalPackageKey("cargo:ripgrep") == "cargo:ripgrep")
        #expect(V2IntelligenceWorkspace.canonicalPackageKey("ripgrep") == "ripgrep")
    }

    @Test("manual-scan mapper: latest=nil + ageInDays set maps to a fully unscanned row")
    func manualMapperUnpublishedStubIsUnscanned() {
        // The npm unpublished-stub edge: the registry's time map yields an
        // ageInDays but dist-tags (latestVersion) are gone. Nil-preserving
        // BOTH fields independently rendered "Not scanned" + "Behind 400d"
        // on one row, and the Behind sort treated it as scanned.
        let info = PackageFreshnessChecker.PackageInfo(
            name: "ghost", registry: .npm,
            publishedDate: nil, ageInDays: 400, downloadCount: nil,
            isFresh: false, isLowPopularity: false, riskLevel: .safe,
            description: "", latestVersion: nil)
        let row = V2IntelligenceWorkspace.manualScanRow(
            info, installed: "1.0.0", intelligence: nil)
        #expect(row.latest == nil)
        #expect(row.staleness == nil)
        #expect(row.isScanned == false)
        #expect(row.isOutdated == false)
    }

    @Test("manual-scan mapper: a real registry result keeps latest + seconds-scaled staleness")
    func manualMapperRealResult() {
        let info = PackageFreshnessChecker.PackageInfo(
            name: "express", registry: .npm,
            publishedDate: nil, ageInDays: 14, downloadCount: nil,
            isFresh: false, isLowPopularity: false, riskLevel: .safe,
            description: "", latestVersion: "4.19.2")
        let row = V2IntelligenceWorkspace.manualScanRow(
            info, installed: "4.18.2", intelligence: nil)
        #expect(row.id == "npm:express")
        #expect(row.latest == "4.19.2")
        #expect(row.staleness == TimeInterval(14 * 86400))
        #expect(row.isScanned == true)
        #expect(row.isOutdated == true)
    }
}
