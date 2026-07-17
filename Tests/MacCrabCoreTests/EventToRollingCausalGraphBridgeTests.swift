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
        appleSigned: Bool = true,
        startTime: Date? = nil,
        auditIdentity: AuditIdentity? = nil
    ) -> MacCrabCore.ProcessInfo {
        MacCrabCore.ProcessInfo(
            pid: pid, ppid: 1, rpid: pid,
            name: (executable as NSString).lastPathComponent,
            executable: executable,
            commandLine: executable,
            args: [], workingDirectory: "/",
            userId: 501, userName: "test", groupId: 20,
            startTime: startTime ?? now,
            codeSignature: CodeSignatureInfo(
                signerType: appleSigned ? .apple : .unsigned,
                isNotarized: appleSigned
            ),
            isPlatformBinary: appleSigned,
            auditIdentity: auditIdentity
        )
    }

    /// ES-sourced audit identity. `pidversion` is the kernel anti-recycle
    /// counter; `asid`/`pid` default to fixed values so the recomputed
    /// key payload ("pid|pidversion|asid|executable") is deterministic.
    private func audit(pidversion: UInt32, asid: Int32 = 42, pid: Int32 = 100) -> AuditIdentity {
        AuditIdentity(
            auid: 501, euid: 501, egid: 20, ruid: 501, rgid: 20,
            pid: pid, pidversion: pidversion, asid: asid
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

    @Test("Bare W3C traceparent (no AI-tool signal) is NOT asserted at 0.95 directTraceparent")
    func genericTraceparentNotAssertedAsAIAgent() async throws {
        // Pre-GA audit (LOW): a GENERIC W3C TRACEPARENT — the ESCollector
        // self-stamp of a process that merely INHERITED the header in its env,
        // with NO agent_tool match (TraceCorrelator.selfStampEnrichments sets
        // agentTool: nil) — could come from ANY OpenTelemetry producer (CI, a
        // distributed-tracing app), not an AI agent. It must NOT be rendered as a
        // high-confidence (0.95) asserted AI agent. Without an AI-tool signal the
        // bridge drops it below the §11.3 assertion threshold (0.85).
        let (store, dbPath) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: dbPath) }
        let materializer = TraceMaterializer(store: store)
        let rollingGraph = RollingCausalGraph(store: store, materializer: materializer)
        let bridge = EventToRollingCausalGraphBridge(rollingGraph: rollingGraph)

        var enrichments: [String: String] = [
            TraceCorrelator.EnrichmentKey.traceId:    "trace-generic-1",
            TraceCorrelator.EnrichmentKey.confidence: "traceparent",
            // NO agent_tool — the discriminator between an AI-agent traceparent
            // and a bare inherited one.
        ]
        enrichments[EventToRollingCausalGraphBridge.processKeyEnrichmentKey] = "known-process-key"

        let event = Event(
            timestamp: now, eventCategory: .process, eventType: .start, eventAction: "exec",
            process: processInfo(pid: 201, executable: "/usr/bin/curl"),
            enrichments: enrichments
        )
        _ = await bridge.process(event)

        // displayName falls back to "Unknown AI agent" when no agent_tool is set,
        // so the agent-node id is ai_agent:unknown ai agent:<traceId>.
        let edgeId = EdgeBuilder.edgeId(
            sourceEntityId: "ai_agent:unknown ai agent:trace-generic-1",
            targetEntityId: "process:known-process-key",
            relation: .associatedWithAgent
        )
        let edge = try await store.edge(id: edgeId)
        #expect(edge != nil)
        // Load-bearing: NOT the 0.95 directTraceparent confidence, and strictly
        // BELOW the assertion threshold so §11.3 renders it inferred, not fact.
        #expect(edge?.confidence != 0.95)
        #expect((edge?.confidence ?? 1.0) < AIAttributionRenderer.defaultAssertionThreshold)

        // The agent ENTITY confidence (what the §11.3 gate reads) is below the bar too.
        let agent = try await store.entity(id: "ai_agent:unknown ai agent:trace-generic-1")
        #expect(agent != nil)
        #expect((agent?.confidence ?? 1.0) < AIAttributionRenderer.defaultAssertionThreshold)
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

    @Test("mapAction wires the v1.17.4 file actions into the causal graph (ES-OPEN-3)")
    func mapActionCoversNewFileActions() async throws {
        let (store, dbPath) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: dbPath) }
        let materializer = TraceMaterializer(store: store)
        let rollingGraph = RollingCausalGraph(store: store, materializer: materializer)
        let bridge = EventToRollingCausalGraphBridge(rollingGraph: rollingGraph)

        func isFileRead(_ a: RollingCausalGraph.NormalizedEventInput.Action?) -> Bool {
            if case .fileRead = a { return true }; return false
        }
        func isFileWrite(_ a: RollingCausalGraph.NormalizedEventInput.Action?) -> Bool {
            if case .fileWrite = a { return true }; return false
        }

        // The headline regression: ESCollector emits "open" for credential
        // reads — it MUST map to a read leg, not be dropped.
        #expect(isFileRead(bridge.mapAction("open")))
        #expect(isFileRead(bridge.mapAction("read")))          // legacy alias still maps
        // A modified-close is a completed write session.
        #expect(isFileWrite(bridge.mapAction("close_modified")))
        #expect(isFileWrite(bridge.mapAction("write")))        // control
        #expect(bridge.mapAction("fchmod") == nil)             // genuinely-unknown still dropped
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

    // MARK: - Anti-recycle process identity (rc.4 CRITICAL)
    //
    // Guards the v1.21.4 P6/A2 invariant: when an event carries the ES
    // `AuditIdentity`, `synthesizeProcessKey` MUST fold `pidversion` (the
    // kernel anti-recycle counter) into the process key so a recycled pid +
    // same executable in the same wall-clock second maps to a DISTINCT graph
    // node — and MUST exclude `startTime` so collector timestamp jitter can't
    // split one logical process. A future contributor hashing pid+startTime
    // alone (as the non-ES fallback still does) would reintroduce the
    // cross-attribution these tests exist to catch.

    @Test("Anti-recycle: same pid+path+wall-second, DIFFERENT pidversion → DISTINCT process nodes")
    func antiRecyclePidversionDiscriminatesNodes() async throws {
        let (store, dbPath) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: dbPath) }
        let materializer = TraceMaterializer(store: store)
        let rollingGraph = RollingCausalGraph(store: store, materializer: materializer)
        let bridge = EventToRollingCausalGraphBridge(rollingGraph: rollingGraph)

        // Two DISTINCT processes: an attacker's process reuses a just-freed pid
        // (100) running the same executable inside the same wall-clock second.
        // Only `pidversion` tells them apart.
        func execEvent(pidversion: UInt32) -> Event {
            Event(
                timestamp: now,
                eventCategory: .process,
                eventType: .start,
                eventAction: "exec",
                process: processInfo(
                    pid: 100, executable: "/usr/bin/curl",
                    auditIdentity: audit(pidversion: pidversion)
                )
            )
        }
        _ = await bridge.process(execEvent(pidversion: 1))
        _ = await bridge.process(execEvent(pidversion: 2))

        // ES-branch key = SHA256("pid|pidversion|asid|executable").
        let keyV1 = SHA256_hex("100|1|42|/usr/bin/curl")
        let keyV2 = SHA256_hex("100|2|42|/usr/bin/curl")
        #expect(keyV1 != keyV2)   // sanity: the payloads really differ

        // Load-bearing: two DISTINCT graph nodes exist — the recycled pid did
        // NOT graft its events onto the prior process's node.
        #expect(try await store.entity(id: "process:\(keyV1)") != nil)
        #expect(try await store.entity(id: "process:\(keyV2)") != nil)

        // And the ES branch was actually taken (not the fallback): the old
        // (pid, startTime-second, executable) key must NOT have been produced —
        // if it were, BOTH observations would have collapsed onto one node.
        let fallbackKey = SHA256_hex("100|\(Int(now.timeIntervalSince1970))|/usr/bin/curl")
        #expect(try await store.entity(id: "process:\(fallbackKey)") == nil)
        await store.close()
    }

    @Test("Anti-recycle: identical pidversion across timestamp jitter → SAME process node")
    func antiRecycleSamePidversionCollapsesNode() async throws {
        let (store, dbPath) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: dbPath) }
        let materializer = TraceMaterializer(store: store)
        let rollingGraph = RollingCausalGraph(store: store, materializer: materializer)
        let bridge = EventToRollingCausalGraphBridge(rollingGraph: rollingGraph)

        // ONE logical process observed twice with 3s of collector timestamp
        // jitter. `pidversion` is stable for the process lifetime and
        // `startTime` is deliberately EXCLUDED from the ES-branch key, so both
        // observations must collapse onto a SINGLE node.
        func obs(at t: Date) -> Event {
            Event(
                timestamp: t,
                eventCategory: .process,
                eventType: .start,
                eventAction: "exec",
                process: processInfo(
                    pid: 100, executable: "/usr/bin/curl",
                    startTime: t,
                    auditIdentity: audit(pidversion: 7)
                )
            )
        }
        _ = await bridge.process(obs(at: now))
        _ = await bridge.process(obs(at: now.addingTimeInterval(3)))

        // Single node keyed by the audit identity (startTime excluded).
        let key = SHA256_hex("100|7|42|/usr/bin/curl")
        #expect(try await store.entity(id: "process:\(key)") != nil)

        // Timestamp jitter must NOT have split the process: neither would-be
        // startTime-based fallback key exists as a second node.
        let jitterKeyA = SHA256_hex("100|\(Int(now.timeIntervalSince1970))|/usr/bin/curl")
        let jitterKeyB = SHA256_hex("100|\(Int(now.addingTimeInterval(3).timeIntervalSince1970))|/usr/bin/curl")
        #expect(try await store.entity(id: "process:\(jitterKeyA)") == nil)
        #expect(try await store.entity(id: "process:\(jitterKeyB)") == nil)
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
