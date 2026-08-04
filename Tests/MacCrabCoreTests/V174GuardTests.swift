// V174GuardTests.swift
//
// Snapshot writers originally used synchronous actor methods plus an
// `inFlight` Bool. That Bool was unreachable during the blocking write because
// the actor could not re-enter, so live feature work stalled and later calls
// queued in its mailbox. Every runtime snapshot now shares the same off-owner-
// actor, one-active + latest-pending publication contract.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("Runtime snapshots: shared bounded writer")
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

    @Test("Concurrent writeSnapshot calls stay bounded and publish")
    func concurrentCallsDoNotCrash() async throws {
        let svc = MCPBaselineService(learningObservations: 1, learningWindow: 0)
        _ = await svc.observe(.init(tool: "claude", serverName: "fs", filePath: "/tmp/y"))
        let path = NSTemporaryDirectory() + "maccrab-mcp-concurrent-\(UUID().uuidString).json"
        defer { try? FileManager.default.removeItem(atPath: path) }
        // Fire 50 writes concurrently. One publication is active and only the
        // newest overlap is retained; at least one complete snapshot lands.
        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<50 {
                group.addTask {
                    await svc.writeSnapshot(to: path)
                }
            }
        }
        #expect(FileManager.default.fileExists(atPath: path))
        let telemetry = await svc.snapshotWriteTelemetry()
        #expect(telemetry.offered == 50)
        #expect(telemetry.conserved)
        #expect(telemetry.inFlight == 0)
        #expect(telemetry.pending == 0)
    }

    @Test("all runtime snapshot owners use the shared contract")
    func sharedWriterCannotDrift() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let files = [
            "Sources/MacCrabCore/AIGuard/AgentLineageService.swift",
            "Sources/MacCrabCore/AIGuard/MCPBehavioralBaseline.swift",
            "Sources/MacCrabCore/Detection/RuleEngine.swift",
            "Sources/MacCrabCore/Collectors/TCCMonitor.swift",
        ]
        for relative in files {
            let source = try String(
                contentsOf: root.appendingPathComponent(relative),
                encoding: .utf8
            )
            #expect(source.contains("CoalescingSnapshotWriter<"), "\(relative) must use the shared bounded writer")
            #expect(!source.contains("private var snapshotWriteInFlight"), "\(relative) must not restore the ineffective synchronous actor guard")
            #expect(source.contains("SecureFileIO.atomicReplace"), "\(relative) must publish through the descriptor-safe atomic writer")
        }
    }
}
