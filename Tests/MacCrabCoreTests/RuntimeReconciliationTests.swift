// RuntimeReconciliationTests.swift
// MacCrabCoreTests
//
// Deep-audit rc.4 reconciliation coverage for two MacCrabAgentKit runtime
// invariants that have no live-daemon harness:
//
//   #2 (EventLoop.swift ~863) — the cross-process FILE chain must dedup on the
//      SHARED FILE PATH, not the triggering executable. Pinned here at the
//      AlertDeduplicator layer (the exact mechanism EventLoop now uses), since
//      EventLoop.run itself is only reachable with a fully-wired DaemonState.
//
//   #3 (DaemonTimers.swift) — a fresh AES-GCM decrypt failure (DB tamper) must
//      raise a rate-limited alert, driven by a rising-edge latch. The latch
//      (TamperAlertState) is exercised directly.

import Testing
import Foundation
@testable import MacCrabCore
@testable import MacCrabAgentKit

/// #2 — cross-process file-chain dedup contract.
///
/// Field symptom: 1344 mostly-benign cross-process file-chain alerts, because
/// each converging process's DISTINCT executable produced its own alert (the
/// AlertSink default dedups on the triggering executable). The fix keys the
/// dedup on the shared file the chain converged on — a mirror of the
/// network-convergence path, which dedups on the destination.
@Suite("Cross-process file-chain dedup (audit #237)")
struct CrossProcessFileChainDedupTests {

    private let ruleId = "maccrab.correlator.cross-process"

    @Test("converging processes on ONE shared file collapse to a single alert (file-path key)")
    func fileKeyCollapsesConvergence() async {
        let dedup = AlertDeduplicator(suppressionWindow: 60)
        let sharedFile = "/Users/x/Library/LaunchAgents/com.evil.target.plist"

        // Three distinct triggering executables all touch the same file inside
        // the correlator window — the fan-out scenario. EventLoop now keys the
        // dedup on `file.path`, so only the first emits.
        var emitted = 0
        for _ in 0..<3 {
            let suppressed = await dedup.shouldSuppressAndRecord(ruleId: ruleId, processPath: sharedFile)
            if !suppressed { emitted += 1 }
        }
        #expect(emitted == 1)
    }

    @Test("pre-fix executable key does NOT collapse — proving the file-path key is the fix")
    func executableKeyDoesNotCollapse() async {
        let dedup = AlertDeduplicator(suppressionWindow: 60)
        // Same chain, but keyed on each converging process's executable (the
        // pre-fix behavior). Each distinct executable is a fresh key → every
        // process emits, reproducing the 1344-alert fan-out.
        let executables = ["/bin/cp", "/bin/mv", "/usr/bin/tee"]
        var emitted = 0
        for exe in executables {
            let suppressed = await dedup.shouldSuppressAndRecord(ruleId: ruleId, processPath: exe)
            if !suppressed { emitted += 1 }
        }
        #expect(emitted == 3)
    }

    @Test("distinct shared files still alert independently (dedup doesn't over-collapse)")
    func distinctFilesStillAlert() async {
        let dedup = AlertDeduplicator(suppressionWindow: 60)
        var emitted = 0
        for path in ["/tmp/a.plist", "/tmp/b.plist", "/tmp/c.plist"] {
            let suppressed = await dedup.shouldSuppressAndRecord(ruleId: ruleId, processPath: path)
            if !suppressed { emitted += 1 }
        }
        #expect(emitted == 3)
    }
}

/// #3 — DB-tamper rising-edge latch.
///
/// `DatabaseEncryption.authenticatedDecryptFailures` is monotonic since boot.
/// The heartbeat surfaced it as a counter but raised no alert; the latch turns
/// a fresh increase into exactly one alert per tamper burst (AlertSink dedup
/// backstops the rate limit thereafter).
@Suite("DB tamper rising-edge latch (audit #38)")
struct TamperAlertStateTests {

    @Test("fires only on a rising tamper count, never on a flat or zero count")
    func firesOnRisingEdgeOnly() {
        let latch = TamperAlertState()
        #expect(latch.shouldAlert(current: 0) == false)  // no tamper yet
        #expect(latch.shouldAlert(current: 0) == false)  // still none
        #expect(latch.shouldAlert(current: 1) == true)   // first failure → alert
        #expect(latch.shouldAlert(current: 1) == false)  // same count → no re-alert
        #expect(latch.shouldAlert(current: 4) == true)   // more failures → alert
        #expect(latch.shouldAlert(current: 4) == false)
    }

    @Test("a counter reset (fresh DatabaseEncryption instance) re-seeds without firing")
    func resetReseedsWithoutFiring() {
        let latch = TamperAlertState()
        #expect(latch.shouldAlert(current: 5) == true)   // rose from 0
        #expect(latch.shouldAlert(current: 2) == false)  // reset lower → no alert, re-seed
        #expect(latch.shouldAlert(current: 3) == true)   // rises from the NEW watermark
        #expect(latch.shouldAlert(current: 3) == false)
    }
}
