// TraceRegistryTests.swift
// Tests for v1.9 Agent Traces (PR-2) — TraceRegistry actor + TraceCorrelator.
//
// Plan v3 mandated test set: bind/lookup, ancestor walk hit + bound, exit
// eviction, PID-recycle stale identity rejected, capacity LRU, 50-concurrent
// TOCTOU pin (mirrors AlertSink v1.6.19 pattern), correlator flat
// enrichments, lineage fallback labels confidence=lineage, traceparent
// labels confidence=traceparent.

import Testing
import Foundation
@testable import MacCrabCore

// MARK: - Helpers

private extension AuditIdentity {
    /// Synthesise an AuditIdentity for tests. `pidversion` is the load-bearing
    /// anti-pid-recycle field; vary it deliberately in recycle tests.
    static func make(pid: Int32, pidversion: UInt32 = 1) -> AuditIdentity {
        AuditIdentity(
            auid: 501, euid: 501, egid: 20, ruid: 501, rgid: 20,
            pid: pid, pidversion: pidversion, asid: 100200
        )
    }
}

private extension ProcessIdentity {
    static func make(pid: pid_t, pidversion: UInt32 = 1, path: String = "/usr/local/bin/claude") -> ProcessIdentity {
        ProcessIdentity(
            auditIdentity: AuditIdentity.make(pid: Int32(pid), pidversion: pidversion),
            pathHash: ProcessIdentity.fnv1a64(path),
            pid: pid,
            startTime: 0
        )
    }
}

private extension TraceContext {
    static let canonical = TraceContext(
        traceId: "4bf92f3577b34da6a3ce929d0e0e4736",
        parentSpanId: "00f067aa0ba902b7",
        flagsByte: 0x01,
        tracestatePresent: false
    )
}

// MARK: - TraceRegistry: bind / lookup / evict

@Suite("TraceRegistry: direct lookup and eviction")
struct TraceRegistryDirectTests {

    @Test("Bind then direct-lookup returns the binding")
    func bindLookup() async {
        let reg = TraceRegistry()
        let id = ProcessIdentity.make(pid: 12345)
        let binding = TraceRegistry.Binding(
            identity: id, context: .canonical, agentTool: .claudeCode
        )
        await reg.bind(binding)
        let got = await reg.lookupDirect(identity: id)
        #expect(got?.context.traceId == "4bf92f3577b34da6a3ce929d0e0e4736")
        #expect(got?.agentTool == .claudeCode)
    }

    @Test("Lookup miss when nothing bound")
    func lookupMiss() async {
        let reg = TraceRegistry()
        let id = ProcessIdentity.make(pid: 99)
        let got = await reg.lookupDirect(identity: id)
        #expect(got == nil)
    }

    @Test("evict() removes the binding")
    func evictRemoves() async {
        let reg = TraceRegistry()
        let id = ProcessIdentity.make(pid: 12345)
        await reg.bind(TraceRegistry.Binding(
            identity: id, context: .canonical, agentTool: .claudeCode
        ))
        #expect(await reg.count() == 1)
        await reg.evict(pid: 12345)
        #expect(await reg.count() == 0)
        #expect(await reg.lookupDirect(identity: id) == nil)
    }
}

// MARK: - TraceRegistry: PID recycle defence

@Suite("TraceRegistry: PID-recycle stale-identity rejection")
struct TraceRegistryRecycleTests {

    @Test("Stale pidversion is rejected at lookup; metric increments")
    func staleIdentityRejected() async {
        let reg = TraceRegistry()
        let original = ProcessIdentity.make(pid: 12345, pidversion: 7)
        await reg.bind(TraceRegistry.Binding(
            identity: original, context: .canonical, agentTool: .claudeCode
        ))

        // Same pid, different pidversion → fresh process that recycled the pid.
        let recycled = ProcessIdentity.make(pid: 12345, pidversion: 8)
        let got = await reg.lookupDirect(identity: recycled)
        #expect(got == nil)

        let metrics = await reg.metricsSnapshot()
        #expect(metrics.pidRecycleRejected == 1)
    }

    @Test("Different path hash on same pid is rejected")
    func staleIdentityViaPathHash() async {
        let reg = TraceRegistry()
        let original = ProcessIdentity.make(pid: 12345, path: "/usr/local/bin/claude")
        await reg.bind(TraceRegistry.Binding(
            identity: original, context: .canonical, agentTool: .claudeCode
        ))
        let pathSwap = ProcessIdentity.make(pid: 12345, path: "/usr/bin/curl")
        #expect(await reg.lookupDirect(identity: pathSwap) == nil)
    }
}

// MARK: - TraceRegistry: ancestor lookup

@Suite("TraceRegistry: lookup with lineage fallback")
struct TraceRegistryLookupAncestorTests {

    @Test("Direct hit returns hopCount=0")
    func directHit() async {
        let reg = TraceRegistry()
        let id = ProcessIdentity.make(pid: 100)
        await reg.bind(TraceRegistry.Binding(
            identity: id, context: .canonical, agentTool: .claudeCode
        ))
        let res = await reg.lookup(
            forIdentity: id,
            ancestors: [],
            ancestorIdentity: { _ in nil }
        )
        #expect(res?.hopCount == 0)
        #expect(res?.matchedPid == 100)
    }

    @Test("Ancestor walk finds bound parent at hop 1")
    func ancestorHopOne() async {
        let reg = TraceRegistry()
        let parentId = ProcessIdentity.make(pid: 50, path: "/usr/local/bin/claude")
        await reg.bind(TraceRegistry.Binding(
            identity: parentId, context: .canonical, agentTool: .claudeCode
        ))
        let childId = ProcessIdentity.make(pid: 51, path: "/bin/bash")
        let parentAncestor = ProcessAncestor(pid: 50, executable: "/usr/local/bin/claude", name: "claude")
        let res = await reg.lookup(
            forIdentity: childId,
            ancestors: [parentAncestor],
            ancestorIdentity: { _ in parentId }
        )
        #expect(res?.hopCount == 1)
        #expect(res?.matchedPid == 50)
        #expect(res?.binding.context.traceId == TraceContext.canonical.traceId)
    }

    @Test("Ancestor walk stops at 8 hops")
    func ancestorWalkBound() async {
        let reg = TraceRegistry(cap: 64, maxAncestorHops: 8)
        // Bind something at hop 9, ensure it's not found.
        let deepIdentity = ProcessIdentity.make(pid: 909, path: "/bin/x")
        await reg.bind(TraceRegistry.Binding(
            identity: deepIdentity, context: .canonical, agentTool: .claudeCode
        ))
        let childId = ProcessIdentity.make(pid: 1, path: "/bin/y")
        let ancestors = (0..<10).map {
            ProcessAncestor(pid: pid_t(900 + $0), executable: "/bin/anc\($0)", name: "anc\($0)")
        }
        let res = await reg.lookup(
            forIdentity: childId,
            ancestors: ancestors,
            ancestorIdentity: { ancestor in
                ancestor.pid == 909 ? deepIdentity : nil
            }
        )
        // hop 9 is index 9 in zero-based ancestors; with maxAncestorHops=8
        // we walk indexes 0..7 only — so 909 (index 9) is unreachable.
        #expect(res == nil)
    }

    @Test("Ancestor with non-matching identity does not attribute")
    func ancestorIdentityMismatch() async {
        let reg = TraceRegistry()
        let realParent = ProcessIdentity.make(pid: 50, path: "/usr/local/bin/claude")
        await reg.bind(TraceRegistry.Binding(
            identity: realParent, context: .canonical, agentTool: .claudeCode
        ))
        let childId = ProcessIdentity.make(pid: 51, path: "/bin/bash")
        let parentAncestor = ProcessAncestor(pid: 50, executable: "/usr/local/bin/claude", name: "claude")
        // Resolver returns a fake identity with pid 50 but mismatched
        // pidversion — registry must refuse the attribution.
        let fake = ProcessIdentity.make(pid: 50, pidversion: 999, path: "/usr/local/bin/claude")
        let res = await reg.lookup(
            forIdentity: childId,
            ancestors: [parentAncestor],
            ancestorIdentity: { _ in fake }
        )
        #expect(res == nil)
        let metrics = await reg.metricsSnapshot()
        #expect(metrics.pidRecycleRejected >= 1)
    }
}

// MARK: - TraceRegistry: capacity & LRU

@Suite("TraceRegistry: capacity cap + LRU eviction")
struct TraceRegistryCapTests {

    @Test("Cap floor protects against absurd config")
    func capFloor() async {
        let reg = TraceRegistry(cap: 1)
        // The init clamps to a 64 floor so a pathological config can't
        // produce a 1-entry registry that thrashes on every bind.
        let metrics = await reg.metricsSnapshot()
        #expect(metrics.cap >= 64)
    }

    @Test("Inserting at cap evicts the oldest accessed entry")
    func lruEviction() async {
        let reg = TraceRegistry(cap: 64) // floored to 64
        // Fill cap+5 entries to force evictions.
        for i in 0..<69 {
            let id = ProcessIdentity.make(pid: pid_t(i + 1))
            await reg.bind(TraceRegistry.Binding(
                identity: id, context: .canonical, agentTool: .claudeCode
            ))
        }
        let metrics = await reg.metricsSnapshot()
        #expect(metrics.liveBindings <= 64)
        #expect(metrics.capEvictions >= 5)
    }
}

// MARK: - TraceRegistry: 50-concurrent-bind TOCTOU pin

@Suite("TraceRegistry: concurrency safety")
struct TraceRegistryConcurrencyTests {

    @Test("50 concurrent binds for distinct pids all land")
    func concurrentDistinctBinds() async {
        let reg = TraceRegistry(cap: 256)
        await withTaskGroup(of: Void.self) { group in
            for i in 0..<50 {
                group.addTask {
                    let id = ProcessIdentity.make(pid: pid_t(1000 + i))
                    await reg.bind(TraceRegistry.Binding(
                        identity: id, context: .canonical, agentTool: .claudeCode
                    ))
                }
            }
        }
        #expect(await reg.count() == 50)
    }

    @Test("50 concurrent binds for the same pid land idempotently")
    func concurrentSamePid() async {
        let reg = TraceRegistry()
        let id = ProcessIdentity.make(pid: 7777)
        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<50 {
                group.addTask {
                    await reg.bind(TraceRegistry.Binding(
                        identity: id, context: .canonical, agentTool: .claudeCode
                    ))
                }
            }
        }
        // Exactly one entry exists, regardless of concurrent insertion.
        #expect(await reg.count() == 1)
    }
}

// MARK: - TraceCorrelator

@Suite("TraceCorrelator: enrichment shape")
struct TraceCorrelatorTests {

    @Test("Direct registry hit produces traceparent confidence + flat enrichments")
    func directHitFlatEnrichments() async {
        let reg = TraceRegistry()
        let id = ProcessIdentity.make(pid: 100)
        await reg.bind(TraceRegistry.Binding(
            identity: id, context: .canonical, agentTool: .claudeCode
        ))
        let result = await TraceCorrelator.correlate(
            identity: id,
            ancestors: [],
            registry: reg,
            ancestorIdentityResolver: { _ in nil },
            aiToolForPath: { _ in nil }
        )
        #expect(result?.evidence.confidence == .traceparent)
        #expect(result?.evidence.source == .traceparentEnv)
        #expect(result?.evidence.agentTool == .claudeCode)
        #expect(result?.enrichments[TraceCorrelator.EnrichmentKey.traceId]
                == TraceContext.canonical.traceId)
        #expect(result?.enrichments[TraceCorrelator.EnrichmentKey.confidence] == "traceparent")
        #expect(result?.enrichments[TraceCorrelator.EnrichmentKey.evidenceJson] != nil)
    }

    @Test("Lineage fallback produces lineage confidence and no traceId")
    func lineageFallback() async {
        let reg = TraceRegistry() // empty — no bindings
        let id = ProcessIdentity.make(pid: 777, path: "/bin/bash")
        // Ancestor binary path matches AIToolRegistry's claudeCode pattern.
        let ancestor = ProcessAncestor(
            pid: 100,
            executable: "/Users/u/.local/bin/claude",
            name: "claude"
        )
        let result = await TraceCorrelator.correlate(
            identity: id,
            ancestors: [ancestor],
            registry: reg,
            ancestorIdentityResolver: { _ in nil },
            aiToolForPath: { path in
                AIToolRegistry().isAITool(executablePath: path)
            }
        )
        #expect(result?.evidence.confidence == .lineage)
        #expect(result?.evidence.source == .lineageRegistry)
        #expect(result?.evidence.agentTool == .claudeCode)
        #expect(result?.evidence.traceId == nil)
        #expect(result?.enrichments[TraceCorrelator.EnrichmentKey.traceId] == nil)
        #expect(result?.enrichments[TraceCorrelator.EnrichmentKey.confidence] == "lineage")
    }

    @Test("No registry hit and no AI ancestor produces no correlation")
    func noCorrelation() async {
        let reg = TraceRegistry()
        let id = ProcessIdentity.make(pid: 1, path: "/bin/bash")
        let result = await TraceCorrelator.correlate(
            identity: id,
            ancestors: [
                ProcessAncestor(pid: 2, executable: "/bin/zsh", name: "zsh"),
            ],
            registry: reg,
            ancestorIdentityResolver: { _ in nil },
            aiToolForPath: { _ in nil }
        )
        #expect(result == nil)
    }

    @Test("apply() copies all flat enrichments onto the event")
    func applyToEvent() async {
        let reg = TraceRegistry()
        let id = ProcessIdentity.make(pid: 100)
        await reg.bind(TraceRegistry.Binding(
            identity: id, context: .canonical, agentTool: .claudeCode
        ))
        guard let result = await TraceCorrelator.correlate(
            identity: id,
            ancestors: [],
            registry: reg,
            ancestorIdentityResolver: { _ in nil },
            aiToolForPath: { _ in nil }
        ) else {
            Issue.record("expected a correlation")
            return
        }
        var event = Event(
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: ProcessInfo(
                pid: 100, ppid: 1, rpid: 0,
                name: "claude", executable: "/usr/local/bin/claude",
                commandLine: "claude", args: [], workingDirectory: "/",
                userId: 501, userName: "u", groupId: 20,
                startTime: Date(), codeSignature: nil, ancestors: [],
                architecture: nil, isPlatformBinary: false
            )
        )
        TraceCorrelator.apply(result, to: &event)
        #expect(event.enrichments[TraceCorrelator.EnrichmentKey.traceId]
                == TraceContext.canonical.traceId)
        #expect(event.enrichments[TraceCorrelator.EnrichmentKey.confidence] == "traceparent")
    }
}
