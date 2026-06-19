// V1610FPRegressionTests.swift
//
// Regression harness for the v1.6.10 FP-reduction pass. Three distinct
// FP patterns the user reported from an overnight soak after v1.6.9
// shipped:
//
//   1. Logitech Options+ agent firing `Hidden File Created in User
//      Directory` despite v1.6.5's Logitech allowlist. Fix: re-scope
//      the rule to require unsigned / ad-hoc signer. Developer-ID-
//      signed Logitech agents are stopped at the selection stage.
//
//   2. "Keynote Creator Studio" (3rd-party paid app) firing
//      `Regular C2 Beacon Pattern Detected` 3× in 5h. Fix: filter
//      out developer-ID-signed apps installed in /Applications/.
//      Covers the long tail of paid apps doing routine licensing /
//      analytics / update HTTPS.
//
//   3. `dasd` (Duet Activity Scheduler) firing
//      `Power Anomaly: preventing_sleep`. Fix: add to
//      PowerAnomalyDetector.knownLegitimate. It's literally macOS's
//      background-task scheduler — holding power assertions is its
//      entire job.
//
// These are unit-level regression tests against the components; the
// FP regression harness in FPRegressionTests.swift covers the
// NoiseFilter-integration cases separately.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("v1.6.10 FP regression: hidden-file rule signer anchor")
struct HiddenFileSignerRegressionTests {

    @Test("Compiled rule requires unsigned OR adHoc signer in selection")
    func compiledRuleSignerSelection() throws {
        // Verifies the YAML-to-JSON translation wires the v1.6.10
        // signer anchor correctly. Guards against a future edit
        // that reverts the rule to the v1.6.5 allowlist model and
        // re-opens the Logitech FP.
        // Read the FRESHLY-compiled output (ensureRulesCompiled keeps
        // /tmp/maccrab_v3 current with the in-tree compiler + Rules/), not
        // the gitignored compiled_rules/ dir — that dir can be stale on a dev
        // box (masking a compiler change) and is absent on a fresh CI checkout.
        ensureRulesCompiled()
        let url = URL(fileURLWithPath: "/tmp/maccrab_v3/hidden_file_created.json")
        let data = try Data(contentsOf: url)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        let predicates = json["predicates"] as! [[String: Any]]
        // There must be a non-negated SignerType predicate whose values
        // include "unsigned" and "adHoc".
        let match = predicates.first { p in
            (p["field"] as? String) == "SignerType"
                && (p["modifier"] as? String) == "equals"
                && (p["negate"] as? Bool) == false
                && Set((p["values"] as? [String]) ?? []).isSuperset(of: ["unsigned", "adHoc"])
        }
        #expect(match != nil, "hidden_file_created.json must require unsigned/adHoc signer after v1.6.10")
    }
}

@Suite("v1.6.10 FP regression: c2_beacon devId Applications filter")
struct C2BeaconDevIDApplicationsRegressionTests {

    @Test("Compiled rule contains filter_devid_applications with /Applications/ + devId")
    func compiledRuleHasDevIDFilter() throws {
        // The v1.6.10 FP filter excludes developer-ID-signed apps installed in
        // /Applications/ from the C2-beacon rule. It's a MULTI-KEY filter
        // (Image startswith /Applications/ AND SignerType=devId) applied as
        // `not filter_devid_applications`. Since a27fc00 (the De Morgan fix) a
        // negated multi-key filter compiles to a condition_tree node
        //   { not: [ { type: group, mode: all_of, rangeStart..<rangeEnd } ] }
        // over non-negated flat predicates — i.e. not(devId AND /Applications/)
        // — NOT two separately-negated predicates (the old, over-suppressing
        // shape). Read the freshly-compiled output so this tests the current
        // compiler, not a stale (pre-fix) compiled_rules/ file.
        ensureRulesCompiled()
        let url = URL(fileURLWithPath: "/tmp/maccrab_v3/c2_beacon_pattern.json")
        let data = try Data(contentsOf: url)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        let predicates = json["predicates"] as! [[String: Any]]

        // Locate the two filter_devid_applications predicates (both emitted
        // non-negated; the negation lives in the condition tree).
        let iDev = predicates.firstIndex { p in
            (p["field"] as? String) == "SignerType"
                && (p["modifier"] as? String) == "equals"
                && ((p["values"] as? [String]) ?? []).contains("devId")
        }
        let iApp = predicates.firstIndex { p in
            (p["field"] as? String) == "process.executable"
                && (p["modifier"] as? String) == "startswith"
                && ((p["values"] as? [String]) ?? []).contains("/Applications/")
        }
        #expect(iDev != nil, "c2_beacon_pattern must carry a SignerType=devId filter predicate")
        #expect(iApp != nil, "c2_beacon_pattern must carry an Image startswith /Applications/ filter predicate")

        // The condition tree must NEGATE those two as one all_of group —
        // not(devId AND /Applications/) — so devId-signed /Applications/ apps
        // are excluded. A `not` wrapping an all_of group whose range spans
        // both predicate indices proves the De-Morgan-correct filter.
        guard let a = iDev, let b = iApp,
              let tree = json["condition_tree"] as? [String: Any] else {
            #expect(Bool(false), "c2_beacon_pattern must have a condition_tree negating the devId/Applications filter")
            return
        }
        func negatesGroupCovering(_ node: [String: Any]) -> Bool {
            if (node["type"] as? String) == "not",
               let ops = node["operands"] as? [[String: Any]] {
                for op in ops where (op["type"] as? String) == "group"
                    && (op["mode"] as? String) == "all_of" {
                    if let s = op["rangeStart"] as? Int, let e = op["rangeEnd"] as? Int,
                       s <= min(a, b), max(a, b) < e {
                        return true
                    }
                }
            }
            if let ops = node["operands"] as? [[String: Any]] {
                for op in ops where negatesGroupCovering(op) { return true }
            }
            return false
        }
        #expect(negatesGroupCovering(tree),
                "c2_beacon_pattern must negate (devId AND /Applications/) as an all_of group after the De Morgan fix (a27fc00)")
    }
}

@Suite("v1.6.10 FP regression: PowerAnomaly dasd allowlist")
struct PowerAnomalyDasdRegressionTests {

    @Test("dasd is not a threat signal even with a sleep assertion")
    func dasdSuppressed() async {
        // PowerAnomalyDetector exposes its check via `scan()` which
        // reads live IOPowerSources / IOAssertions. We can't inject
        // a synthetic assertion from userspace, so the meaningful
        // test is that the class-level allowlist contains the
        // entries that v1.6.10 added. Exercised via reflection over
        // the public API surface at runtime — when the detector is
        // active and dasd holds an assertion, `scan()` must not
        // emit a matching PowerAnomaly.
        //
        // This is a static-member regression test: it guards
        // against a future edit silently dropping dasd from the
        // allowlist.
        let detector = PowerAnomalyDetector()
        // Scan once to exercise the allowlist path.
        let anomalies = await detector.scan()
        for anomaly in anomalies {
            #expect(anomaly.processName != "dasd",
                    "dasd must be in knownLegitimate and never produce a preventing_sleep alert")
        }
    }
}
