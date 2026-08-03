// BundleRedactorTests.swift
// v1.10 TraceGraph (PR-10b) — tests for the export-time redactor.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("TraceGraph: BundleRedactor")
struct BundleRedactorTests {

    @Test("Replaces /Users/<currentUser>/ with ~/")
    func replacesCurrentUserPath() {
        let r = BundleRedactor(userName: "alice")
        let out = r.redact("/Users/alice/Downloads/payload")
        #expect(out == "~/Downloads/payload")
    }

    @Test("Replaces other /Users/X/ paths with /Users/[REDACTED]/")
    func replacesGenericUserPath() {
        let r = BundleRedactor(userName: "alice")
        let out = r.redact("/Users/bob/sensitive")
        #expect(out == "/Users/[REDACTED]/sensitive")
    }

    @Test("Replaces hostname")
    func replacesHostname() {
        let r = BundleRedactor(hostname: "alice-mbp")
        let out = r.redact("Connection from alice-mbp.local at 12:00")
        #expect(!out.contains("alice-mbp"))
        #expect(out.contains("[REDACTED-HOST]"))
    }

    @Test("Replaces private IPv4 ranges")
    func replacesPrivateIPs() {
        let r = BundleRedactor()
        #expect(r.redact("10.0.0.5 connected").contains("[REDACTED-IP]"))
        #expect(r.redact("server 192.168.1.42 reached").contains("[REDACTED-IP]"))
        #expect(r.redact("172.16.0.1 / 172.20.0.5 / 172.31.255.255").contains("[REDACTED-IP]"))
    }

    @Test("Public IP outside private ranges is preserved")
    func keepsPublicIPs() {
        let r = BundleRedactor()
        let result = r.redact("Connected to 203.0.113.10")
        #expect(result.contains("203.0.113.10"))
    }

    @Test("Disabled redactPrivateIPs leaves IPs alone")
    func toggleIPs() {
        let r = BundleRedactor(redactPrivateIPs: false)
        let result = r.redact("10.0.0.5 / 192.168.1.1")
        #expect(result.contains("10.0.0.5"))
    }

    @Test("Disabled redactHomePaths leaves /Users/X/ alone")
    func toggleHomePaths() {
        let r = BundleRedactor(redactHomePaths: false, userName: "alice")
        let result = r.redact("/Users/alice/Downloads/x")
        #expect(result == "/Users/alice/Downloads/x")
    }

    @Test("redactDirectory rewrites .json files but skips integrity/")
    func redactDirectorySweep() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("redact-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }

        let intDir = dir.appendingPathComponent("integrity")
        try FileManager.default.createDirectory(at: intDir, withIntermediateDirectories: true)
        let textURL = dir.appendingPathComponent("events.jsonl")
        try "{\"path\":\"/Users/alice/x\"}".write(to: textURL, atomically: true, encoding: .utf8)
        let intURL = intDir.appendingPathComponent("hash_chain.json")
        try "{\"path\":\"/Users/alice/x\"}".write(to: intURL, atomically: true, encoding: .utf8)

        let r = BundleRedactor(userName: "alice")
        try r.redactDirectory(dir)

        let textAfter = try String(contentsOf: textURL, encoding: .utf8)
        let intAfter = try String(contentsOf: intURL, encoding: .utf8)
        #expect(textAfter == "{\"path\":\"~/x\"}")
        // integrity/ contents are NOT touched — they commit to the post-redaction artifacts.
        #expect(intAfter == "{\"path\":\"/Users/alice/x\"}")
    }

    @Test("Only root-relative integrity metadata is exempt from redaction")
    func integrityExemptionIsRootRelative() throws {
        let scratch = FileManager.default.temporaryDirectory
            .appendingPathComponent("redact-policy-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: scratch) }
        let ancestor = scratch.appendingPathComponent("integrity", isDirectory: true)
        let bundle = ancestor.appendingPathComponent("sample.maccrabtrace", isDirectory: true)
        let rootIntegrity = bundle.appendingPathComponent("integrity", isDirectory: true)
        let nestedIntegrity = bundle.appendingPathComponent(
            "evidence/integrity",
            isDirectory: true
        )
        try FileManager.default.createDirectory(
            at: rootIntegrity,
            withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(
            at: nestedIntegrity,
            withIntermediateDirectories: true
        )

        let ordinary = bundle.appendingPathComponent("events.jsonl")
        let rootMetadata = rootIntegrity.appendingPathComponent("hash_chain.json")
        let nestedPayload = nestedIntegrity.appendingPathComponent("payload.json")
        let secret = #"{"path":"/Users/alice/private"}"#
        for url in [ordinary, rootMetadata, nestedPayload] {
            try secret.write(to: url, atomically: true, encoding: .utf8)
        }

        try BundleRedactor(userName: "alice").redactDirectory(bundle)

        #expect(try String(contentsOf: ordinary, encoding: .utf8) == #"{"path":"~/private"}"#)
        #expect(try String(contentsOf: nestedPayload, encoding: .utf8) == #"{"path":"~/private"}"#)
        #expect(try String(contentsOf: rootMetadata, encoding: .utf8) == secret,
                "Only the bundle-root integrity namespace is derived metadata")
    }
}
