// EventToRollingCausalGraphBridgeTests.swift
// v1.10 TraceGraph (production wiring) — verifies the v1.9 Event →
// NormalizedEventInput translation and end-to-end ingest.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("TraceGraph: EventToRollingCausalGraphBridge")
struct EventToRollingCausalGraphBridgeTests {

    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    private func makeStore() async throws -> (SQLiteCausalGraphStore, URL) {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("bridge-\(UUID().uuidString).db")
        return (try await SQLiteCausalGraphStore(databasePath: path.path), path)
    }

    private func processInfo(
        pid: Int32,
        executable: String,
        appleSigned: Bool = true
    ) -> MacCrabCore.ProcessInfo {
        MacCrabCore.ProcessInfo(
            pid: pid, ppid: 1, rpid: pid,
            name: (executable as NSString).lastPathComponent,
            executable: executable,
            commandLine: executable,
            args: [], workingDirectory: "/",
            userId: 501, userName: "test", groupId: 20,
            startTime: now,
            codeSignature: CodeSignatureInfo(
                signerType: appleSigned ? .apple : .unsigned,
                isNotarized: appleSigned
            ),
            isPlatformBinary: appleSigned
        )
    }

    @Test("Bridge ingests a process exec event and creates a ProcessNode")
    func processExecIngest() async throws {
        let (store, dbPath) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: dbPath) }
        let materializer = TraceMaterializer(store: store)
        let rollingGraph = RollingCausalGraph(store: store, materializer: materializer)
        let bridge = EventToRollingCausalGraphBridge(rollingGraph: rollingGraph)

        let event = Event(
            timestamp: now,
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: processInfo(pid: 100, executable: "/usr/bin/curl")
        )
        _ = await bridge.process(event)

        // Process entity should exist with synthesized processKey.
        // We don't know the exact key but we can confirm A process
        // entity for this executable + pid was upserted.
        // Compute the same key the bridge would have produced.
        let expectedKey: String = {
            let payload = "100|\(Int(now.timeIntervalSince1970))|/usr/bin/curl"
            let hash = SHA256_hex(payload)
            return hash
        }()
        let entity = try await store.entity(id: "process:\(expectedKey)")
        #expect(entity != nil)
        #expect(entity?.entityType == "process")
        #expect(entity?.displayName == "curl")
        await store.close()
    }

    @Test("Insert filter gates graph ingest — dropped events never reach the store (v1.17.4 perf)")
    func insertFilterGatesIngest() async throws {
        let (store, dbPath) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: dbPath) }
        let materializer = TraceMaterializer(store: store)
        let rollingGraph = RollingCausalGraph(store: store, materializer: materializer)
        // Filter drops any process named "curl" (stands in for self-monitoring/noise).
        let bridge = EventToRollingCausalGraphBridge(
            rollingGraph: rollingGraph,
            insertFilter: EventInsertFilter(processNames: ["curl"])
        )

        let dropped = Event(
            timestamp: now, eventCategory: .process, eventType: .start, eventAction: "exec",
            process: processInfo(pid: 100, executable: "/usr/bin/curl"))
        let traces = await bridge.process(dropped)
        #expect(traces.isEmpty)
        // Nothing ingested — the process entity must NOT exist.
        let droppedKey = SHA256_hex("100|\(Int(now.timeIntervalSince1970))|/usr/bin/curl")
        #expect(try await store.entity(id: "process:\(droppedKey)") == nil)

        // Control: an event the filter does NOT drop still ingests.
        let kept = Event(
            timestamp: now, eventCategory: .process, eventType: .start, eventAction: "exec",
            process: processInfo(pid: 200, executable: "/usr/bin/python3"))
        _ = await bridge.process(kept)
        let keptKey = SHA256_hex("200|\(Int(now.timeIntervalSince1970))|/usr/bin/python3")
        #expect(try await store.entity(id: "process:\(keptKey)") != nil)
        await store.close()
    }

    @Test("Bridge translates AI agent enrichments into an AIAgentNode")
    func agentEnrichmentTranslated() async throws {
        let (store, dbPath) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: dbPath) }
        let materializer = TraceMaterializer(store: store)
        let rollingGraph = RollingCausalGraph(store: store, materializer: materializer)
        let bridge = EventToRollingCausalGraphBridge(rollingGraph: rollingGraph)

        var enrichments: [String: String] = [
            TraceCorrelator.EnrichmentKey.traceId:    "trace-claude-1",
            TraceCorrelator.EnrichmentKey.spanId:     "span-1",
            TraceCorrelator.EnrichmentKey.confidence: "traceparent",
            TraceCorrelator.EnrichmentKey.agentTool:  "claude_code",
        ]
        // Force a known process_key via enrichment to make assertions deterministic.
        enrichments[EventToRollingCausalGraphBridge.processKeyEnrichmentKey] = "known-process-key"

        let event = Event(
            timestamp: now,
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: processInfo(pid: 200, executable: "/usr/bin/osascript"),
            enrichments: enrichments
        )
        _ = await bridge.process(event)

        // ProcessNode keyed by the supplied process_key
        let proc = try await store.entity(id: "process:known-process-key")
        #expect(proc != nil)

        // AIAgentNode keyed by lower(name):traceId
        let agent = try await store.entity(id: "ai_agent:claude code:trace-claude-1")
        #expect(agent != nil)
        #expect(agent?.entityType == "ai_agent")

        // associated_with_agent edge between them
        let edgeId = EdgeBuilder.edgeId(
            sourceEntityId: "ai_agent:claude code:trace-claude-1",
            targetEntityId: "process:known-process-key",
            relation: .associatedWithAgent
        )
        let edge = try await store.edge(id: edgeId)
        #expect(edge != nil)
        #expect(edge?.confidence == 0.95)
        await store.close()
    }

    @Test("Bridge maps file read on a credential file → triggers credential anchor")
    func credentialAccessAnchorViaBridge() async throws {
        let (store, dbPath) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: dbPath) }
        let materializer = TraceMaterializer(store: store)
        let rollingGraph = RollingCausalGraph(store: store, materializer: materializer)
        let bridge = EventToRollingCausalGraphBridge(rollingGraph: rollingGraph)

        let event = Event(
            timestamp: now,
            eventCategory: .file,
            eventType: .info,
            eventAction: "read",
            process: processInfo(pid: 300, executable: "/usr/bin/cat"),
            file: FileInfo(
                path: "/Users/me/.aws/credentials",
                name: "credentials",
                directory: "/Users/me/.aws",
                action: .write
            )
        )
        let traces = await bridge.process(event)
        #expect(traces.count == 1, "expected a credential-access anchor")
        #expect(traces.first?.title.contains("Credential") == true)
        await store.close()
    }

    @Test("Unknown event action is silently dropped (returns no traces, no error)")
    func unknownActionDropped() async throws {
        let (store, dbPath) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: dbPath) }
        let materializer = TraceMaterializer(store: store)
        let rollingGraph = RollingCausalGraph(store: store, materializer: materializer)
        let bridge = EventToRollingCausalGraphBridge(rollingGraph: rollingGraph)

        let event = Event(
            timestamp: now,
            eventCategory: .file,
            eventType: .info,
            eventAction: "fchmod",   // not in our action map
            process: processInfo(pid: 400, executable: "/usr/bin/chmod")
        )
        let traces = await bridge.process(event)
        #expect(traces.isEmpty)
        await store.close()
    }

    private func SHA256_hex(_ s: String) -> String {
        // Tiny shim so the test doesn't have to import CryptoKit just
        // to recompute the bridge's synthesized key.
        var hasher = Hasher()  // not deterministic across runs — placeholder
        _ = hasher
        // For determinism we use Foundation Insecure; but we want
        // SHA-256. Use the Data(sha256) helper from MacCrabCore if
        // any, otherwise compute via Process.
        // Simplest: cribbed from Apple's CryptoKit doc snippet.
        let data = Data(s.utf8)
        var hash = [UInt8](repeating: 0, count: 32)
        data.withUnsafeBytes { dataPtr in
            CC_SHA256_local(dataPtr.baseAddress, UInt32(data.count), &hash)
        }
        return hash.map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - CC_SHA256 shim for the test (avoids importing CryptoKit
// at test scope; the bridge itself uses CryptoKit).

import CommonCrypto

@discardableResult
private func CC_SHA256_local(_ data: UnsafeRawPointer?, _ len: UInt32, _ out: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8>? {
    return CC_SHA256(data, CC_LONG(len), out)
}
