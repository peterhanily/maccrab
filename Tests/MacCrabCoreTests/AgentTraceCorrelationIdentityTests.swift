// AgentTraceCorrelationIdentityTests.swift
// v1.21.4 (P6 fix) — regression guard for agent-trace direct correlation.
//
// The bug: the TraceRegistry binding is keyed on the FULL ProcessIdentity,
// whose equality is driven by AuditIdentity (auid/euid/egid/ruid/rgid/pid/
// pidversion/asid) + pathHash. The ES env-scan builds the binding from the
// process's REAL audit_token (non-zero pidversion). But the EventLoop direct
// correlation used to reconstruct the lookup identity from the normalized
// Event with hardcoded pidversion:0/asid:0/auid:0/egid:0/rgid:0 — which can
// NEVER equal the binding, so the lookup missed on every event and
// agent_trace_id was never stamped. On-device it was 0/0; unit tests missed it
// because they built BOTH sides with matching synthetic identities.
//
// The fix carries the real AuditIdentity on ProcessInfo.auditIdentity so the
// correlation reconstructs the SAME identity. These tests reproduce the real
// asymmetry (ES-token binding vs Event-reconstructed lookup) and prove the
// fixed path hits while the old zeroed path misses — without weakening the
// anti-pid-recycle guarantee.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("P6: agent-trace correlation identity match")
struct AgentTraceCorrelationIdentityTests {

    private static let executable = "/usr/local/bin/claude"
    private static let pid: pid_t = 4242

    /// The real audit identity the ES env-scan would extract from the exec
    /// target's audit_token — pidversion is NON-ZERO on every real process.
    private static let realAudit = AuditIdentity(
        auid: 501, euid: 501, egid: 20, ruid: 501, rgid: 20,
        pid: Int32(pid), pidversion: 7, asid: 100200
    )

    /// The binding identity, built the way ESCollector builds it from the
    /// exec target (real audit_token + fnv1a64 of the executable path).
    private static var bindingIdentity: ProcessIdentity {
        ProcessIdentity(
            auditIdentity: realAudit,
            pathHash: ProcessIdentity.fnv1a64(executable),
            pid: pid, startTime: 1_700_000_000
        )
    }

    /// A ProcessInfo as normalise() now produces it — carrying the real
    /// AuditIdentity (the P6 fix). Mirrors the EventLoop consumer's input.
    private static func eventProcess(withAudit audit: AuditIdentity?) -> MacCrabCore.ProcessInfo {
        MacCrabCore.ProcessInfo(
            pid: pid, ppid: 1, rpid: 0,
            name: "claude", executable: executable,
            commandLine: "claude", args: [], workingDirectory: "/",
            userId: 501, userName: "u", groupId: 20,
            startTime: Date(timeIntervalSince1970: 1_700_000_000),
            codeSignature: nil, ancestors: [], architecture: nil,
            isPlatformBinary: false, auditIdentity: audit
        )
    }

    /// The EventLoop direct-correlation reconstruction (fixed): use the real
    /// audit identity carried on the Event's process.
    private static func fixedLookupIdentity(_ p: MacCrabCore.ProcessInfo) -> ProcessIdentity? {
        guard let audit = p.auditIdentity else { return nil }
        return ProcessIdentity(
            auditIdentity: audit,
            pathHash: ProcessIdentity.fnv1a64(p.executable),
            pid: p.pid,
            startTime: UInt64(p.startTime.timeIntervalSince1970)
        )
    }

    /// The OLD (buggy) reconstruction: zeroed pidversion/asid/auid/egid/rgid.
    private static func buggyLookupIdentity(_ p: MacCrabCore.ProcessInfo) -> ProcessIdentity {
        ProcessIdentity(
            auditIdentity: AuditIdentity(
                auid: 0, euid: p.userId, egid: 0,
                ruid: p.userId, rgid: 0,
                pid: p.pid, pidversion: 0, asid: 0
            ),
            pathHash: ProcessIdentity.fnv1a64(p.executable),
            pid: p.pid,
            startTime: UInt64(p.startTime.timeIntervalSince1970)
        )
    }

    @Test("FIXED: real-audit reconstruction equals the ES binding identity")
    func fixedIdentityEqualsBinding() {
        let p = Self.eventProcess(withAudit: Self.realAudit)
        let lookup = Self.fixedLookupIdentity(p)
        #expect(lookup == Self.bindingIdentity, "the fixed lookup identity must equal the binding")
    }

    @Test("REGRESSION: the old zeroed reconstruction can NEVER equal the binding")
    func buggyIdentityNeverEqualsBinding() {
        let p = Self.eventProcess(withAudit: Self.realAudit)
        let buggy = Self.buggyLookupIdentity(p)
        #expect(buggy != Self.bindingIdentity, "zeroed pidversion/asid must not match — this is the bug")
    }

    @Test("FIXED path HITS the registry; OLD path MISSES")
    func registryHitFixedMissBuggy() async {
        let reg = TraceRegistry()
        await reg.bind(TraceRegistry.Binding(
            identity: Self.bindingIdentity,
            context: TraceContext(
                traceId: "4bf92f3577b34da6a3ce929d0e0e4736",
                parentSpanId: "00f067aa0ba902b7",
                flagsByte: 0x01, tracestatePresent: false
            ),
            agentTool: .claudeCode
        ))
        let p = Self.eventProcess(withAudit: Self.realAudit)

        // Fixed: hit.
        let fixed = Self.fixedLookupIdentity(p)!
        let hit = await reg.lookupDirect(identity: fixed)
        #expect(hit?.context.traceId == "4bf92f3577b34da6a3ce929d0e0e4736", "fixed lookup must stamp the trace")

        // Old: miss (the on-device symptom — agent_trace_id stays 0).
        let miss = await reg.lookupDirect(identity: Self.buggyLookupIdentity(p))
        #expect(miss == nil, "the pre-fix zeroed identity misses — reproduces the on-device 0/0")
    }

    @Test("a process without a carried audit identity yields no lookup (non-ES source)")
    func noAuditNoLookup() {
        let p = Self.eventProcess(withAudit: nil)
        #expect(Self.fixedLookupIdentity(p) == nil, "non-ES sources skip the direct lookup rather than guaranteed-miss")
    }

    @Test("anti-recycle preserved: a stale pidversion still misses even via the fixed path")
    func antiRecyclePreserved() async {
        let reg = TraceRegistry()
        await reg.bind(TraceRegistry.Binding(
            identity: Self.bindingIdentity, context: .init(
                traceId: "4bf92f3577b34da6a3ce929d0e0e4736",
                parentSpanId: "00f067aa0ba902b7", flagsByte: 0x01, tracestatePresent: false),
            agentTool: .claudeCode
        ))
        // Same pid + path but a DIFFERENT pidversion (a recycled pid) — must miss.
        let recycled = Self.eventProcess(withAudit: AuditIdentity(
            auid: 501, euid: 501, egid: 20, ruid: 501, rgid: 20,
            pid: Int32(Self.pid), pidversion: 99, asid: 100200))
        let id = Self.fixedLookupIdentity(recycled)!
        #expect(await reg.lookupDirect(identity: id) == nil, "the fix must not weaken anti-pid-recycle")
    }

    @Test("ProcessInfo.auditIdentity survives a Codable round-trip (it persists to events.db)")
    func auditIdentityRoundTrip() throws {
        let p = Self.eventProcess(withAudit: Self.realAudit)
        let data = try JSONEncoder().encode(p)
        let back = try JSONDecoder().decode(MacCrabCore.ProcessInfo.self, from: data)
        #expect(back.auditIdentity == Self.realAudit)
        // Backward-compat: a row without the field decodes to nil, not a throw.
        let legacy = Self.eventProcess(withAudit: nil)
        let legacyBack = try JSONDecoder().decode(
            MacCrabCore.ProcessInfo.self, from: try JSONEncoder().encode(legacy))
        #expect(legacyBack.auditIdentity == nil)
    }
}
