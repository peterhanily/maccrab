// RuntimeReconciliationTests.swift
// MacCrabCoreTests
//
// Deep-audit rc.4 reconciliation coverage for two MacCrabAgentKit runtime
// invariants that have no live-daemon harness:
//
//   #2 (EventLoop.swift) — the cross-process FILE chain must dedup on the SET
//      of converging executables, neither the triggering executable nor the
//      file. Pinned here with the real correlator and the AlertDeduplicator
//      (the exact mechanism EventLoop uses), since EventLoop.run itself is only
//      reachable with a fully-wired DaemonState.
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
/// Two field floods bracket the key. Keyed on the triggering executable, each
/// converging process emitted its own alert (1344 mostly-benign alerts). Keyed
/// on the file, one bulk operation emitted one alert per file: `find` + `mv`
/// over a 3,000-file directory raised 3,000 alerts in 64 s, and 18,313 in a
/// week. The chain's `dedupIdentity` keys on the executable set instead.
@Suite("Cross-process file-chain dedup (audit #237, v1.22.2)")
struct CrossProcessFileChainDedupTests {

    private let ruleId = "maccrab.correlator.cross-process"

    private func emitted(_ chains: [CrossProcessCorrelator.CorrelationChain]) async -> Int {
        let dedup = AlertDeduplicator(suppressionWindow: 3_600)
        var count = 0
        for chain in chains {
            let suppressed = await dedup.shouldSuppressAndRecord(
                ruleId: ruleId, processPath: chain.dedupIdentity)
            if !suppressed { count += 1 }
        }
        return count
    }

    @Test("one bulk operation over thousands of files is one alert")
    func bulkOperationCollapses() async {
        let correlator = CrossProcessCorrelator()
        let now = Date()
        var chains: [CrossProcessCorrelator.CorrelationChain] = []
        for i in 0..<3_000 {
            let path = "/Users/Shared/Runtime/renamed-\(i).txt"
            let at = now.addingTimeInterval(Double(i) * 0.02)
            await correlator.recordFileEvent(path: path, action: "rename", pid: 100,
                processName: "mv", processPath: "/bin/mv", timestamp: at)
            if let chain = await correlator.recordFileEvent(path: path, action: "unlink", pid: 200,
                processName: "find", processPath: "/usr/bin/find", timestamp: at) {
                chains.append(chain)
            }
        }
        #expect(chains.count == 3_000)
        #expect(await emitted(chains) == 1)
    }

    @Test("re-evaluating one converged file does not re-alert")
    func stableConvergenceCollapses() async {
        let correlator = CrossProcessCorrelator()
        let now = Date()
        let path = "/Users/x/Library/LaunchAgents/com.evil.target.plist"
        var chains: [CrossProcessCorrelator.CorrelationChain] = []
        for i in 0..<6 {
            let (pid, name, exe): (Int32, String, String) = i.isMultiple(of: 2)
                ? (100, "cp", "/bin/cp") : (200, "tee", "/usr/bin/tee")
            if let chain = await correlator.recordFileEvent(path: path, action: i < 2 ? "write" : "read",
                pid: pid, processName: name, processPath: exe, timestamp: now.addingTimeInterval(Double(i))) {
                chains.append(chain)
            }
        }
        #expect(!chains.isEmpty)
        #expect(await emitted(chains) == 1)
    }

    @Test("a different executable set is a new finding, even in the same directory")
    func differentExecutablesStillAlert() async {
        let correlator = CrossProcessCorrelator()
        let now = Date()
        var chains: [CrossProcessCorrelator.CorrelationChain] = []
        for (i, pair) in [("/bin/mv", "/usr/bin/find"), ("/usr/bin/curl", "/bin/bash")].enumerated() {
            let path = "/tmp/shared/file-\(i)"
            await correlator.recordFileEvent(path: path, action: "write", pid: 100,
                processName: "a", processPath: pair.0, timestamp: now)
            if let chain = await correlator.recordFileEvent(path: path, action: "execute", pid: 200,
                processName: "b", processPath: pair.1, timestamp: now.addingTimeInterval(1)) {
                chains.append(chain)
            }
        }
        #expect(chains.count == 2)
        #expect(await emitted(chains) == 2)
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
