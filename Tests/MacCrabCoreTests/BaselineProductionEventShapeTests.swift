import Testing
import Foundation
@testable import MacCrabCore

@Suite("BaselineEngine production event shape")
struct BaselineProductionEventShapeTests {
    private var repositoryRoot: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()   // MacCrabCoreTests
            .deletingLastPathComponent()   // Tests
            .deletingLastPathComponent()   // repo root
    }

    /// Real eslogger JSON envelope for NOTIFY_EXEC. EsloggerParser is the
    /// entitlement-free collector path and intentionally emits the same Event
    /// shape as native ESCollector, which cannot be safely instantiated from a
    /// synthetic `es_message_t` in a unit test.
    private func collectorExecEnvelope(
        pid: Int,
        ppid: Int,
        sourcePath: String,
        targetPath: String
    ) -> [String: Any] {
        let source: [String: Any] = [
            "audit_token": ["pid": pid, "euid": 501],
            "ppid": ppid,
            "executable": ["path": sourcePath],
            "signing_id": "",
            "team_id": "",
            "codesigning_flags": 0,
            "is_platform_binary": false,
        ]
        let target: [String: Any] = [
            "audit_token": ["pid": pid, "euid": 501],
            "ppid": ppid,
            "executable": ["path": targetPath],
            "signing_id": "",
            "team_id": "",
            "codesigning_flags": 0,
            "is_platform_binary": false,
            "start_time": "2026-08-03T10:30:45.000000Z",
        ]
        let execPayload: [String: Any] = [
            "target": target,
            "args": [
                "count": 1,
                "items": [["value": targetPath]],
            ] as [String: Any],
            "cwd": ["path": "/private/tmp"],
            "image_cputype": 16_777_228,
        ]
        return [
            "schema_version": 1,
            "version": 7,
            "time": "2026-08-03T10:30:45.123456Z",
            "event_type": 9,
            "global_seq_num": pid,
            "seq_num": pid,
            "process": source,
            "event": ["exec": execPayload],
        ]
    }

    @Test("Collector exec survives enrichment and enters the production baseline")
    func collectorExecIsEvaluated() async throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("baseline-production-shape-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: path) }

        let engine = BaselineEngine(
            config: .init(
                learningPeriod: 3_600,
                sensitivity: .medium,
                enabled: true,
                focusPaths: [],
                exemptParents: [],
                exemptChildren: [],
                exemptEdges: []
            ),
            persistPath: path.path
        )

        // Feed the collector parity path two real-shaped exec envelopes so the
        // actual EventEnricher lineage graph can resolve the child's parent.
        // This covers the same parser → enrichment → EventLoop-input boundary
        // that was dark on the installed host, without fabricating ancestry.
        let enricher = EventEnricher()
        let rawParent = try #require(EsloggerParser.parse(collectorExecEnvelope(
            pid: 41_000,
            ppid: 1,
            sourcePath: "/bin/zsh",
            targetPath: "/usr/local/bin/runtime-parent"
        )))
        _ = await enricher.enrich(rawParent)

        let rawChild = try #require(EsloggerParser.parse(collectorExecEnvelope(
            pid: 41_001,
            ppid: 41_000,
            sourcePath: "/usr/local/bin/runtime-parent",
            targetPath: "/usr/bin/curl"
        )))
        let productionEvent = await enricher.enrich(rawChild)

        #expect(rawChild.eventCategory == .process)
        #expect(rawChild.eventType == .start)
        #expect(rawChild.eventAction == "exec")
        #expect(productionEvent.enrichments["enriched"] == "true")
        #expect(
            productionEvent.process.ancestors.first?.executable
                == "/usr/local/bin/runtime-parent",
            "baseline must receive the parent path resolved by production enrichment"
        )

        #expect(BaselineEngine.isProcessCreationEvent(productionEvent))
        #expect(await engine.evaluate(productionEvent) == nil)
        #expect(await engine.edgeCount == 1)
    }

    @Test("Non-exec start events do not pollute the process baseline")
    func nonExecStartIsIgnored() async {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("baseline-nonexec-shape-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: path) }
        let engine = BaselineEngine(
            config: .init(enabled: true),
            persistPath: path.path
        )
        let forkEvent = makeEvent(type: .start, action: "fork")

        #expect(!BaselineEngine.isProcessCreationEvent(forkEvent))
        #expect(await engine.evaluate(forkEvent) == nil)
        #expect(await engine.edgeCount == 0)
    }

    @Test("EventLoop uses the shared process-creation predicate")
    func eventLoopGateCannotDrift() throws {
        let eventLoop = try String(
            contentsOf: repositoryRoot.appendingPathComponent(
                "Sources/MacCrabAgentKit/EventLoop.swift"
            ),
            encoding: .utf8
        )
        #expect(eventLoop.contains(
            "BaselineEngine.isProcessCreationEvent(enrichedEvent)"
        ))
    }

    @Test("Native ESCollector exec normalization keeps the shared start/exec shape")
    func nativeCollectorShapeCannotDrift() throws {
        let collector = try String(
            contentsOf: repositoryRoot.appendingPathComponent(
                "Sources/MacCrabCore/Collectors/ESCollector.swift"
            ),
            encoding: .utf8
        )
        let processSectionStart = try #require(
            collector.range(of: "// MARK: Process Events")
        )
        let processSection = collector[processSectionStart.lowerBound...]
        let execStart = try #require(
            processSection.range(of: "case ES_EVENT_TYPE_NOTIFY_EXEC:")
        )
        let forkStart = try #require(
            processSection.range(
                of: "case ES_EVENT_TYPE_NOTIFY_FORK:",
                range: execStart.upperBound..<processSection.endIndex
            )
        )
        let execBlock = processSection[execStart.lowerBound..<forkStart.lowerBound]

        #expect(execBlock.contains("eventCategory: .process"))
        #expect(execBlock.contains("eventType: .start"))
        #expect(execBlock.contains("eventAction: \"exec\""))
    }
}
