// RootkitDeRaceTests.swift
// MacCrabCoreTests
//
// The v1.6.22 de-race fix as pure set algebra. RootkitDetector cross-references
// proc_listallpids() against sysctl(KERN_PROC_ALL); the two are NOT snapshotted
// atomically, so a process exiting/starting between the back-to-back scans shows
// in one set but not the other. The fix reports a PID ONLY if the discrepancy
// PERSISTS across a verify pass — dropping that condition re-introduces the bulk
// false-"hidden-process" alert storm. confirmedHidden() makes it testable
// without live syscalls.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("Rootkit de-race confirmation")
struct RootkitDeRaceTests {
    typealias CH = RootkitDetector.ConfirmedHidden

    @Test("Persistent proc-only PID is reported")
    func persistentProcOnly() {
        let out = RootkitDetector.confirmedHidden(
            initialProc: [1, 2, 1000], initialSysctl: [1, 2],
            verifyProc: [1, 2, 1000], verifySysctl: [1, 2], selfPid: 99)
        #expect(out == [CH(pid: 1000, source: "proc_only")])
    }

    @Test("Persistent sysctl-only PID is reported")
    func persistentSysctlOnly() {
        let out = RootkitDetector.confirmedHidden(
            initialProc: [1, 2], initialSysctl: [1, 2, 2000],
            verifyProc: [1, 2], verifySysctl: [1, 2, 2000], selfPid: 99)
        #expect(out == [CH(pid: 2000, source: "sysctl_only")])
    }

    @Test("Exiting-process race is NOT reported (the v1.6.22 fix)")
    func exitingRaceNotReported() {
        // 1000 was proc-only initially but is gone entirely by the verify scan.
        let out = RootkitDetector.confirmedHidden(
            initialProc: [1, 2, 1000], initialSysctl: [1, 2],
            verifyProc: [1, 2], verifySysctl: [1, 2], selfPid: 99)
        #expect(out.isEmpty)
    }

    @Test("PID reconciled into both APIs by the verify pass is NOT reported")
    func reconciledNotReported() {
        // 1000 proc-only initially, but sysctl also sees it by the verify pass.
        let out = RootkitDetector.confirmedHidden(
            initialProc: [1, 2, 1000], initialSysctl: [1, 2],
            verifyProc: [1, 2, 1000], verifySysctl: [1, 2, 1000], selfPid: 99)
        #expect(out.isEmpty)
    }

    @Test("selfPid and pid 0 are never reported")
    func selfAndZeroExcluded() {
        let out = RootkitDetector.confirmedHidden(
            initialProc: [1, 0, 42], initialSysctl: [1],
            verifyProc: [1, 0, 42], verifySysctl: [1], selfPid: 42)
        #expect(out.isEmpty)  // 0 filtered, 42 == selfPid filtered
    }

    @Test("Identical sets → nothing reported")
    func identicalSets() {
        let out = RootkitDetector.confirmedHidden(
            initialProc: [1, 2, 3], initialSysctl: [1, 2, 3],
            verifyProc: [1, 2, 3], verifySysctl: [1, 2, 3], selfPid: 99)
        #expect(out.isEmpty)
    }

    @Test("Multiple confirmed hidden PIDs returned sorted by pid")
    func multipleSorted() {
        let out = RootkitDetector.confirmedHidden(
            initialProc: [1, 3000], initialSysctl: [1, 2000],
            verifyProc: [1, 3000], verifySysctl: [1, 2000], selfPid: 99)
        #expect(out == [CH(pid: 2000, source: "sysctl_only"), CH(pid: 3000, source: "proc_only")])
    }
}
