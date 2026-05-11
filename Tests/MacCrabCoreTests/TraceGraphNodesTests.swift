// TraceGraphNodesTests.swift
// v1.10 TraceGraph (PR-7) — tests for typed entity types in §8.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("TraceGraph: typed nodes")
struct TraceGraphNodesTests {

    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    @Test("ProcessNode: canonicalId is type:processKey")
    func processCanonicalId() {
        let node = ProcessNode(
            processKey: "abc123",
            pid: 100,
            ppid: 1,
            executablePath: "/usr/bin/example",
            isAppleSigned: true,
            isNotarized: true,
            startTime: now
        )
        #expect(node.canonicalId == "process:abc123")
        #expect(node.stableKey == "abc123")
        #expect(node.displayName == "example")
    }

    @Test("ProcessNode → TraceEntity roundtrip preserves attributes")
    func processToEntity() throws {
        let node = ProcessNode(
            processKey: "abc",
            pid: 100,
            ppid: 1,
            executablePath: "/usr/bin/x",
            executableHash: "deadbeef",
            commandLineRedacted: "x --flag REDACTED",
            signingTeamId: "TEAMID1234",
            signingIdentifier: "com.example.x",
            isAppleSigned: false,
            isNotarized: true,
            startTime: now,
            agentTraceId: "trace-1",
            agentSpanId: "span-1"
        )
        let entity = try node.toEntity(source: "test")
        #expect(entity.id == "process:abc")
        #expect(entity.entityType == "process")
        #expect(entity.stableKey == "abc")
        #expect(entity.displayName == "x")
        #expect(entity.firstSeen == now)
        #expect(entity.confidence == 1.0)
        // attributesJson is canonical: sorted keys
        #expect(entity.attributesJson.contains("\"agentTraceId\":\"trace-1\""))
        #expect(entity.attributesJson.contains("\"isNotarized\":true"))
    }

    @Test("FileNode stableKey is pathHash (not path)")
    func fileStableKey() {
        let file = FileNode(
            path: "/Users/me/.aws/credentials",
            pathHash: "h-aws-creds",
            fileKind: .credentialFile,
            firstSeen: now,
            lastSeen: now
        )
        #expect(file.stableKey == "h-aws-creds")
        #expect(file.displayName == "credentials")
    }

    @Test("NetworkNode stableKey encodes host:port/protocol")
    func networkStableKey() {
        let net = NetworkNode(
            destinationHost: "evil.example.com",
            destinationIP: "203.0.113.10",
            port: 443,
            protocolName: "tcp",
            reputation: .suspicious,
            firstSeen: now
        )
        #expect(net.stableKey == "evil.example.com:443/tcp")
        #expect(net.displayName == "evil.example.com:443")
    }

    @Test("NetworkNode falls back to IP when host is nil")
    func networkIPFallback() {
        let net = NetworkNode(
            destinationIP: "203.0.113.10",
            port: 443,
            protocolName: "tcp",
            firstSeen: now
        )
        #expect(net.stableKey == "203.0.113.10:443/tcp")
    }

    @Test("AIAgentNode → TraceEntity stamps confidence + method")
    func aiAgentToEntity() throws {
        let agent = AIAgentNode(
            agentId: "claude-desktop:user1",
            agentName: "Claude Desktop",
            sourceApp: "claude",
            toolName: "claude-code",
            traceId: "t1",
            spanId: "s1",
            confidence: 0.92,
            attributionMethod: .directTraceparent,
            firstSeen: now
        )
        let entity = try agent.toEntity(source: "trace-extractor", confidence: 0.92)
        #expect(entity.entityType == "ai_agent")
        #expect(entity.stableKey == "claude-desktop:user1")
        #expect(entity.confidence == 0.92)
        #expect(entity.attributesJson.contains("\"attributionMethod\":\"direct_traceparent\""))
    }

    @Test("PersistenceNode stableKey encodes type + path")
    func persistenceStableKey() {
        let persist = PersistenceNode(
            persistenceType: .launchAgent,
            path: "/Users/me/Library/LaunchAgents/com.fake.agent.plist",
            label: "com.fake.agent",
            firstSeen: now
        )
        #expect(persist.stableKey == "launch_agent:/Users/me/Library/LaunchAgents/com.fake.agent.plist")
        #expect(persist.displayName == "com.fake.agent")
    }

    @Test("MCPServerNode stableKey is server:transport")
    func mcpServerStableKey() {
        let mcp = MCPServerNode(
            serverName: "filesystem-mcp",
            transport: "stdio",
            command: "node /path/to/server.js",
            firstSeen: now
        )
        #expect(mcp.stableKey == "filesystem-mcp:stdio")
    }

    @Test("PackageScriptNode stableKey is manager:kind:name")
    func packageScriptStableKey() {
        let script = PackageScriptNode(
            packageManager: "npm",
            scriptKind: "postinstall",
            packageName: "evil-package",
            packageVersion: "1.2.3",
            firstSeen: now
        )
        #expect(script.stableKey == "npm:postinstall:evil-package")
    }

    @Test("CodeSignatureNode handles unsigned binaries")
    func codeSignatureUnsigned() {
        let sig = CodeSignatureNode(
            teamId: nil,
            signingId: nil,
            signerType: .unsigned,
            isNotarized: false,
            firstSeen: now
        )
        #expect(sig.stableKey == "-:-:unsigned")
    }

    @Test("UserSessionNode includes tty in display when present")
    func userSessionDisplay() {
        let s1 = UserSessionNode(userId: 501, userName: "alice", sessionId: 100, tty: "/dev/ttys001", firstSeen: now)
        let s2 = UserSessionNode(userId: 501, userName: "alice", firstSeen: now)
        #expect(s1.displayName == "alice (/dev/ttys001)")
        #expect(s2.displayName == "alice")
    }

    @Test("All entity types are registered with distinct entityType tags")
    func entityTypeTagsDistinct() {
        let tags = Set([
            ProcessNode.entityType,
            FileNode.entityType,
            NetworkNode.entityType,
            AIAgentNode.entityType,
            PersistenceNode.entityType,
            MCPServerNode.entityType,
            PackageScriptNode.entityType,
            BrowserDownloadNode.entityType,
            CodeSignatureNode.entityType,
            UserSessionNode.entityType,
            TCCPermissionNode.entityType,
            RuleNode.entityType,
            AlertNode.entityType,
        ])
        #expect(tags.count == 13)
    }

    @Test("toEntity uses canonical (sorted-key) JSON encoding")
    func canonicalEncoding() throws {
        let process = ProcessNode(
            processKey: "k",
            pid: 1, ppid: 0,
            executablePath: "/x",
            isAppleSigned: true,
            isNotarized: false,
            startTime: now
        )
        let e1 = try process.toEntity(source: "a")
        let e2 = try process.toEntity(source: "a")
        // Same input → byte-identical attributes_json (canonical encoding)
        #expect(e1.attributesJson == e2.attributesJson)
    }
}
