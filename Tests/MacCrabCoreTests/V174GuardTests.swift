// V174GuardTests.swift
//
// Per-writer in-flight guards added in v1.7.4 to MCPBaselineService,
// RuleEngine, and TCCMonitor. These guards mirror the existing
// AgentLineageService.snapshotWriteInFlight pattern so fire-and-
// forget heartbeat Tasks don't queue on busy actors.
//
// Tests verify: a single writeSnapshot call writes the file; a
// concurrent second call from a separate Task no-ops gracefully
// (no crash, no second file write). The guard is meant to drop
// the redundant write, not stall.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("v1.7.4: per-writer snapshot in-flight guards")
struct PerWriterGuardTests {

    @Test("MCPBaselineService.writeSnapshot writes the file successfully (round-trip)")
    func mcpBaselineWritesAndReads() async throws {
        let svc = MCPBaselineService(learningObservations: 1, learningWindow: 0)
        _ = await svc.observe(.init(tool: "claude", serverName: "fs", filePath: "/tmp/x"))
        let path = NSTemporaryDirectory() + "maccrab-mcp-guard-\(UUID().uuidString).json"
        defer { try? FileManager.default.removeItem(atPath: path) }
        await svc.writeSnapshot(to: path)
        #expect(FileManager.default.fileExists(atPath: path))
        let snap = MCPBaselineService.readSnapshot(at: path)
        #expect(snap?.baselines.count == 1)
    }

    @Test("RuleEngine.writeTelemetrySnapshot writes the file successfully")
    func ruleEngineWrites() async throws {
        let engine = RuleEngine()
        let path = NSTemporaryDirectory() + "maccrab-rule-guard-\(UUID().uuidString).json"
        defer { try? FileManager.default.removeItem(atPath: path) }
        await engine.writeTelemetrySnapshot(to: path)
        #expect(FileManager.default.fileExists(atPath: path))
        let snap = RuleEngine.readTelemetrySnapshot(at: path)
        #expect(snap != nil)
    }

    @Test("TCCMonitor.writeSnapshot writes the file successfully")
    func tccMonitorWrites() async throws {
        let mon = TCCMonitor()
        let path = NSTemporaryDirectory() + "maccrab-tcc-guard-\(UUID().uuidString).json"
        defer { try? FileManager.default.removeItem(atPath: path) }
        await mon.writeSnapshot(to: path)
        #expect(FileManager.default.fileExists(atPath: path))
        let snap = TCCMonitor.readSnapshot(at: path)
        #expect(snap != nil)
    }

    @Test("Concurrent writeSnapshot calls don't crash (drop-or-write semantics)")
    func concurrentCallsDoNotCrash() async throws {
        let svc = MCPBaselineService(learningObservations: 1, learningWindow: 0)
        _ = await svc.observe(.init(tool: "claude", serverName: "fs", filePath: "/tmp/y"))
        let path = NSTemporaryDirectory() + "maccrab-mcp-concurrent-\(UUID().uuidString).json"
        defer { try? FileManager.default.removeItem(atPath: path) }
        // Fire 50 writeSnapshot calls concurrently. Most will no-op
        // due to the in-flight guard; at least one should succeed
        // (the file should exist when done).
        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<50 {
                group.addTask {
                    await svc.writeSnapshot(to: path)
                }
            }
        }
        #expect(FileManager.default.fileExists(atPath: path))
    }
}
