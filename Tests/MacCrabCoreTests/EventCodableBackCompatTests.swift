// EventCodableBackCompatTests.swift
// Ensures Phase 1 model additions (ProcessHashes, SessionInfo, CodeSignatureInfo
// extensions) don't break deserialization of pre-Phase-1 JSON rows in the
// `events.raw_json` column.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("Event Codable back-compat")
struct EventCodableBackCompatTests {

    /// A minimal v1-format JSON row that lacks every Phase 1 field.
    /// Shape matches what EventStore.insert used to write before the schema
    /// was enriched.
    private let v1JSON = #"""
    {
        "id": "11111111-2222-3333-4444-555555555555",
        "timestamp": 1712345678.0,
        "eventCategory": "process",
        "eventType": "start",
        "eventAction": "exec",
        "process": {
            "pid": 1234,
            "ppid": 5678,
            "rpid": 5678,
            "name": "ls",
            "executable": "/bin/ls",
            "commandLine": "/bin/ls -la",
            "args": ["/bin/ls", "-la"],
            "workingDirectory": "/tmp",
            "userId": 501,
            "userName": "alice",
            "groupId": 20,
            "startTime": 1712345600.0,
            "ancestors": [],
            "isPlatformBinary": true
        },
        "enrichments": {},
        "severity": "informational",
        "ruleMatches": []
    }
    """#

    /// A v1-format event whose process includes a pre-Phase-1 CodeSignatureInfo
    /// (authorities present, but no issuerChain / certHashes / isAdhocSigned /
    /// entitlements).
    private let v1JSONWithSig = #"""
    {
        "id": "99999999-0000-0000-0000-000000000000",
        "timestamp": 1712345678.0,
        "eventCategory": "process",
        "eventType": "start",
        "eventAction": "exec",
        "process": {
            "pid": 4321,
            "ppid": 1,
            "rpid": 1,
            "name": "curl",
            "executable": "/usr/bin/curl",
            "commandLine": "/usr/bin/curl https://example.com",
            "args": ["/usr/bin/curl", "https://example.com"],
            "workingDirectory": "/Users/alice",
            "userId": 501,
            "userName": "alice",
            "groupId": 20,
            "startTime": 1712345600.0,
            "codeSignature": {
                "signerType": "apple",
                "teamId": "APPLE",
                "signingId": "com.apple.curl",
                "authorities": ["Apple Code Signing CA", "Apple Root CA"],
                "flags": 0,
                "isNotarized": true
            },
            "ancestors": [],
            "isPlatformBinary": true
        },
        "enrichments": {},
        "severity": "informational",
        "ruleMatches": []
    }
    """#

    @Test("v1 JSON without Phase 1 fields decodes cleanly")
    func decodesV1() throws {
        let data = v1JSON.data(using: .utf8)!
        let event = try JSONDecoder().decode(Event.self, from: data)

        #expect(event.process.name == "ls")
        #expect(event.process.hashes == nil)
        #expect(event.process.session == nil)
        #expect(event.process.envVars == nil)
        #expect(event.process.codeSignature == nil)
    }

    @Test("v1 CodeSignatureInfo without Phase 1 fields decodes cleanly")
    func decodesV1WithSignature() throws {
        let data = v1JSONWithSig.data(using: .utf8)!
        let event = try JSONDecoder().decode(Event.self, from: data)

        let sig = try #require(event.process.codeSignature)
        #expect(sig.signerType == .apple)
        #expect(sig.authorities == ["Apple Code Signing CA", "Apple Root CA"])
        #expect(sig.isNotarized == true)

        // Phase 1 additions are nil for v1 data.
        #expect(sig.issuerChain == nil)
        #expect(sig.certHashes == nil)
        #expect(sig.isAdhocSigned == nil)
        #expect(sig.entitlements == nil)
    }

    @Test("Phase 1 enriched event round-trips through Codable")
    func roundTripEnriched() throws {
        let hashes = ProcessHashes(
            sha256: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            cdhash: "0000111122223333444455556666777788889999",
            md5: nil
        )
        let session = SessionInfo(
            sessionId: 100003,
            tty: "/dev/ttys001",
            loginUser: "alice",
            sshRemoteIP: "203.0.113.42",
            launchSource: .ssh
        )
        let sig = CodeSignatureInfo(
            signerType: .devId,
            teamId: "ABC1234567",
            signingId: "com.example.tool",
            authorities: ["Developer ID", "Apple"],
            flags: 0,
            isNotarized: true,
            issuerChain: ["Developer ID Certification Authority", "Apple Root CA"],
            certHashes: ["aaa", "bbb"],
            isAdhocSigned: false,
            entitlements: ["com.apple.security.app-sandbox"]
        )
        let process = ProcessInfo(
            pid: 1000,
            ppid: 1,
            rpid: 1,
            name: "tool",
            executable: "/usr/local/bin/tool",
            commandLine: "/usr/local/bin/tool arg",
            args: ["/usr/local/bin/tool", "arg"],
            workingDirectory: "/tmp",
            userId: 501,
            userName: "alice",
            groupId: 20,
            startTime: Date(timeIntervalSince1970: 1_712_345_600),
            codeSignature: sig,
            hashes: hashes,
            session: session,
            envVars: ["PATH": "/usr/bin:/bin", "SSH_CLIENT": "203.0.113.42 55234 22"]
        )
        let event = Event(
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: process
        )

        let encoded = try JSONEncoder().encode(event)
        let decoded = try JSONDecoder().decode(Event.self, from: encoded)

        #expect(decoded.process.hashes == hashes)
        #expect(decoded.process.session == session)
        #expect(decoded.process.envVars?["PATH"] == "/usr/bin:/bin")
        #expect(decoded.process.codeSignature?.issuerChain == sig.issuerChain)
        #expect(decoded.process.codeSignature?.certHashes == sig.certHashes)
        #expect(decoded.process.codeSignature?.isAdhocSigned == false)
        #expect(decoded.process.codeSignature?.entitlements == sig.entitlements)
    }

    @Test("LaunchSource enum covers expected cases")
    func launchSourceCases() {
        let allCases: Set<LaunchSource> = Set(LaunchSource.allCases)
        #expect(allCases.contains(.finder))
        #expect(allCases.contains(.terminal))
        #expect(allCases.contains(.ssh))
        #expect(allCases.contains(.launchd))
        #expect(allCases.contains(.cron))
        #expect(allCases.contains(.xpc))
        #expect(allCases.contains(.applescript))
        #expect(allCases.contains(.unknown))
    }

    // MARK: - Alert Phase 1 back-compat

    /// A legacy alert JSON row without any Phase 1 fields.
    private let legacyAlertJSON = #"""
    {
        "id": "alert-1",
        "timestamp": 1712345678.0,
        "ruleId": "rule.test",
        "ruleTitle": "Test rule",
        "severity": "high",
        "eventId": "event-1",
        "processPath": "/bin/ls",
        "processName": "ls",
        "description": "something happened",
        "mitreTactics": "TA0003,TA0005",
        "mitreTechniques": "T1059.004,T1547.001",
        "suppressed": false
    }
    """#

    @Test("Legacy Alert JSON without Phase 1 fields decodes cleanly")
    func decodesLegacyAlert() throws {
        let data = legacyAlertJSON.data(using: .utf8)!
        let alert = try JSONDecoder().decode(Alert.self, from: data)

        #expect(alert.ruleId == "rule.test")
        #expect(alert.campaignId == nil)
        #expect(alert.hostContext == nil)
        #expect(alert.analyst == nil)
        #expect(alert.d3fendTechniques == nil)
        #expect(alert.remediationHint == nil)
        #expect(alert.llmInvestigation == nil)
    }

    @Test("mitreTacticsList parses CSV into trimmed array")
    func mitreTacticsCSVParse() {
        let alert = Alert(
            ruleId: "r",
            ruleTitle: "t",
            severity: .medium,
            eventId: "e",
            mitreTactics: "TA0003, TA0005 ,TA0007",
            mitreTechniques: "T1059.004"
        )
        #expect(alert.mitreTacticsList == ["TA0003", "TA0005", "TA0007"])
        #expect(alert.mitreTechniquesList == ["T1059.004"])

        let empty = Alert(ruleId: "r", ruleTitle: "t", severity: .low, eventId: "e")
        #expect(empty.mitreTacticsList.isEmpty)
        #expect(empty.mitreTechniquesList.isEmpty)
    }

    @Test("Phase 1 enriched Alert round-trips through Codable")
    func roundTripEnrichedAlert() throws {
        let host = HostContext(
            hostname: "macbook-pro",
            osVersion: "macOS 15.4",
            hardwareUUID: "00000000-1111-2222-3333-444444444444",
            securityScore: 87
        )
        let analyst = AnalystMetadata(
            notes: "Looks like a false positive — vendor update rollout",
            owner: "alice",
            status: .investigating,
            ticketRef: "SEC-1234"
        )
        let investigation = LLMInvestigation(
            summary: "Likely benign vendor update",
            verdict: "likely_benign",
            confidence: 0.8,
            modelVersion: "llama3.1:8b",
            generatedAt: Date(timeIntervalSince1970: 1_712_500_000)
        )
        let alert = Alert(
            ruleId: "rule.x",
            ruleTitle: "Test",
            severity: .high,
            eventId: "evt",
            campaignId: "campaign-42",
            hostContext: host,
            analyst: analyst,
            d3fendTechniques: ["D3-EAL", "D3-PFV"],
            remediationHint: "Check persistence mechanisms in launchd.plist paths.",
            llmInvestigation: investigation
        )

        let encoded = try JSONEncoder().encode(alert)
        let decoded = try JSONDecoder().decode(Alert.self, from: encoded)

        #expect(decoded.campaignId == "campaign-42")
        #expect(decoded.hostContext == host)
        #expect(decoded.analyst?.status == .investigating)
        #expect(decoded.d3fendTechniques == ["D3-EAL", "D3-PFV"])
        #expect(decoded.remediationHint == alert.remediationHint)
        #expect(decoded.llmInvestigation?.verdict == "likely_benign")
    }
}
