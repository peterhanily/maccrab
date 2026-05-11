// ProcessKeyTests.swift
// v1.10 TraceGraph (PR-6a) — tests for the canonical processKey
// derivation on `ProcessIdentity` per §10.1 of the spec.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("TraceGraph: ProcessKey")
struct ProcessKeyTests {

    private func makeIdentity(
        pid: Int32 = 1234,
        pidversion: UInt32 = 1,
        pathHash: UInt64 = 0xDEADBEEF,
        auid: UInt32 = 501,
        euid: UInt32 = 501,
        asid: Int32 = 100
    ) -> ProcessIdentity {
        ProcessIdentity(
            auditIdentity: AuditIdentity(
                auid: auid,
                euid: euid,
                egid: 20,
                ruid: euid,
                rgid: 20,
                pid: pid,
                pidversion: pidversion,
                asid: asid
            ),
            pathHash: pathHash,
            pid: pid,
            startTime: 1_700_000_000
        )
    }

    @Test("processKey is deterministic for the same identity")
    func deterministic() {
        let identity = makeIdentity()
        #expect(identity.processKey == identity.processKey)
    }

    @Test("processKey is 64 lowercase hex characters")
    func hexFormat() {
        let key = makeIdentity().processKey
        #expect(key.count == 64)
        let allowed = Set("0123456789abcdef")
        #expect(key.allSatisfy { allowed.contains($0) })
    }

    @Test("Different pidversion → different processKey")
    func pidversionChanges() {
        let a = makeIdentity(pidversion: 1)
        let b = makeIdentity(pidversion: 2)
        #expect(a.processKey != b.processKey)
    }

    @Test("Different pathHash → different processKey")
    func pathHashChanges() {
        let a = makeIdentity(pathHash: 0xAAAA)
        let b = makeIdentity(pathHash: 0xBBBB)
        #expect(a.processKey != b.processKey)
    }

    @Test("Different pid → different processKey")
    func pidChanges() {
        let a = makeIdentity(pid: 100)
        let b = makeIdentity(pid: 101)
        #expect(a.processKey != b.processKey)
    }

    @Test("Different asid → different processKey")
    func asidChanges() {
        let a = makeIdentity(asid: 100)
        let b = makeIdentity(asid: 200)
        #expect(a.processKey != b.processKey)
    }

    @Test("Different euid → different processKey")
    func euidChanges() {
        let a = makeIdentity(euid: 501)
        let b = makeIdentity(euid: 502)
        #expect(a.processKey != b.processKey)
    }

    @Test("startTime is NOT folded into processKey")
    func startTimeIgnored() {
        // ProcessIdentity excludes startTime from hash/equality (v1.9
        // anti-recycle invariant). processKey must respect that —
        // otherwise the same logical process resolves to different
        // canonical entities across collectors that round timestamps
        // differently.
        let identity1 = ProcessIdentity(
            auditIdentity: AuditIdentity(
                auid: 501, euid: 501, egid: 20,
                ruid: 501, rgid: 20,
                pid: 1234, pidversion: 1, asid: 100
            ),
            pathHash: 0xDEADBEEF,
            pid: 1234,
            startTime: 1_700_000_000
        )
        let identity2 = ProcessIdentity(
            auditIdentity: AuditIdentity(
                auid: 501, euid: 501, egid: 20,
                ruid: 501, rgid: 20,
                pid: 1234, pidversion: 1, asid: 100
            ),
            pathHash: 0xDEADBEEF,
            pid: 1234,
            startTime: 1_700_000_999  // different startTime
        )
        #expect(identity1 == identity2)
        #expect(identity1.processKey == identity2.processKey)
    }

    @Test("processKey changes when audit identity changes — even if pid is the same")
    func auditIdentitySensitivity() {
        let baseline = makeIdentity(pid: 100, pidversion: 5)
        let recycled = makeIdentity(pid: 100, pidversion: 6)
        // Same pid, different pidversion → different process per
        // ProcessIdentity equality, so different processKey.
        #expect(baseline.processKey != recycled.processKey)
    }
}
