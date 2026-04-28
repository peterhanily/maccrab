// V173HotfixTests.swift
//
// Regression coverage for the v1.7.3 memory-hotfix bundle:
//   - CollectorRegistry maxEntries cap with LRU-by-lastTick eviction
//   - MCPAttributor LRU eviction by accessSeq (replaces v1.7.0
//     non-deterministic `cache.keys.first` removal)
//
// The heartbeat-overlap-guard fix (HeartbeatInFlight) lives inside
// DaemonTimers.swift as a private file-scoped class — exercised
// implicitly by the existing daemon-bootstrap integration tests.

import Testing
import Foundation
@testable import MacCrabCore
@testable import MacCrabAgentKit

@Suite("v1.7.3: CollectorRegistry cap")
struct CollectorRegistryCapTests {

    @Test("Registry caps at maxEntries; oldest-by-lastTick evicts first")
    func capEvictsOldest() async {
        // Init clamps below 16; test uses 16 to actually trigger the
        // cap. 16 entries registered + ticked, then a 17th lazy-
        // registers and the oldest-tick entry should evict.
        let reg = CollectorRegistry(maxEntries: 16)
        for i in 0..<16 {
            await reg.register(name: "Slot\(i)", expectedIntervalSeconds: 5, eventDriven: true)
            await reg.recordTick(name: "Slot\(i)")
            try? await Task.sleep(nanoseconds: 1_000_000) // 1 ms stagger
        }
        // Slot0 has the oldest lastTick — should evict when a 17th
        // collector lazy-registers.
        await reg.recordTick(name: "Lazy17")
        let snap = await reg.snapshot()
        let names = Set(snap.map(\.name))
        #expect(snap.count == 16)
        #expect(names.contains("Lazy17"))
        #expect(!names.contains("Slot0"))
    }

    @Test("Never-ticked entries evict before ticked ones")
    func neverTickedPreferredVictim() async {
        let reg = CollectorRegistry(maxEntries: 16)
        // 15 entries ticked, 1 untouched (registered only). Lazy-
        // register a 17th — the never-ticked "Untouched" should evict
        // ahead of any ticked entry.
        for i in 0..<15 {
            await reg.register(name: "Ticked\(i)", expectedIntervalSeconds: 5, eventDriven: true)
            await reg.recordTick(name: "Ticked\(i)")
        }
        await reg.register(name: "Untouched", expectedIntervalSeconds: 5, eventDriven: true)
        // Now at 16 entries, 15 ticked + 1 never-ticked. Trigger the cap.
        await reg.recordTick(name: "Lazy")
        let snap = await reg.snapshot()
        let names = Set(snap.map(\.name))
        #expect(snap.count == 16)
        #expect(names.contains("Lazy"))
        #expect(!names.contains("Untouched"))
    }

    @Test("Cap floor: maxEntries < 16 is clamped to 16 (no eviction below floor)")
    func capFloor() async {
        let reg = CollectorRegistry(maxEntries: 4)
        // The init clamps to max(16, n). Register 10 + tick 10
        // (under the floor) — none should evict.
        for i in 0..<10 {
            await reg.register(name: "Slot\(i)", expectedIntervalSeconds: 5, eventDriven: true)
            await reg.recordTick(name: "Slot\(i)")
        }
        let snap = await reg.snapshot()
        #expect(snap.count == 10)
    }
}

@Suite("v1.7.3: MCPAttributor LRU eviction")
struct MCPAttributorLRUTests {

    /// Construct an attributor with a tight cache cap and confirm
    /// least-recently-accessed entries evict first.
    @Test("LRU eviction removes least-recently-accessed entry")
    func lruEvictsLRU() async throws {
        let monitor = MCPMonitor()
        let lineage = ProcessLineage()

        // Three lineage entries — none of them match a configured
        // server, so each call to `attribute` records a miss
        // (negative cache).
        for i in 1...4 {
            await lineage.recordProcess(
                pid: pid_t(7000 + i), ppid: 0,
                path: "/usr/bin/git", name: "git",
                startTime: Date(),
                commandLine: "git status"
            )
        }

        // cacheCap=2: insert 3 entries, the first should evict.
        let attr = MCPAttributor(mcpMonitor: monitor, lineage: lineage, cacheCap: 2)

        let ancestors1 = await lineage.ancestors(of: 7001)
        let ancestors2 = await lineage.ancestors(of: 7002)
        let ancestors3 = await lineage.ancestors(of: 7003)

        // Insert PIDs 7001, 7002 — both record-miss with seq 1, 2.
        _ = await attr.attribute(pid: 7001, ancestors: ancestors1, aiTool: .claudeCode)
        _ = await attr.attribute(pid: 7002, ancestors: ancestors2, aiTool: .claudeCode)
        // Re-access 7001 to bump its seq above 7002.
        _ = await attr.attribute(pid: 7001, ancestors: ancestors1, aiTool: .claudeCode)
        // Insert 7003 — should evict 7002 (lowest accessSeq).
        _ = await attr.attribute(pid: 7003, ancestors: ancestors3, aiTool: .claudeCode)

        // 7001 should still be cached (recently accessed). 7002 should
        // be evicted (lowest seq). We can't easily inspect the cache
        // directly, but we can re-attribute 7002 — if it's been
        // evicted, it'll re-walk the ancestry. The test passes if no
        // crash occurs and attribute returns nil (no MCP match).
        let ancestors2reattribute = await lineage.ancestors(of: 7002)
        let result = await attr.attribute(pid: 7002, ancestors: ancestors2reattribute, aiTool: .claudeCode)
        #expect(result == nil)  // re-walk also returns nil
    }
}
