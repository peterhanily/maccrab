// TrustedConduitPolicyTests.swift
// v1.10 TraceGraph (PR-8) — tests for TrustedConduitPolicy per §12.1.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("TraceGraph: TrustedConduitPolicy")
struct TrustedConduitPolicyTests {

    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    private func makeProcess(
        path: String,
        isAppleSigned: Bool = false,
        teamId: String? = nil,
        signingId: String? = nil
    ) -> ProcessNode {
        ProcessNode(
            processKey: "k-\(path)",
            pid: 100, ppid: 1,
            executablePath: path,
            signingTeamId: teamId,
            signingIdentifier: signingId,
            isAppleSigned: isAppleSigned,
            isNotarized: isAppleSigned,
            startTime: now
        )
    }

    @Test("Apple-signed binary in /usr/bin is a trusted conduit")
    func appleInUsrBin() {
        let node = makeProcess(path: "/usr/bin/curl", isAppleSigned: true)
        #expect(TrustedConduitPolicy.default.isTrustedConduit(node))
    }

    @Test("Apple-signed binary in /System is a trusted conduit")
    func appleInSystem() {
        let node = makeProcess(path: "/System/Library/Frameworks/CoreFoundation.framework/Foo", isAppleSigned: true)
        #expect(TrustedConduitPolicy.default.isTrustedConduit(node))
    }

    @Test("Unsigned binary in ~/Downloads is NOT a trusted conduit")
    func unsignedInDownloads() {
        let node = makeProcess(path: "/Users/me/Downloads/sketchy", isAppleSigned: false)
        #expect(!TrustedConduitPolicy.default.isTrustedConduit(node))
    }

    @Test("Apple-signed binary in ~/Downloads is NOT a trusted conduit (denylist wins)")
    func appleInDownloadsDenied() {
        // §12.1: a malware-installed `node` in ~/Downloads is not
        // trusted even if its signing claims Apple. Denylist always wins.
        let node = makeProcess(path: "/Users/me/Downloads/node", isAppleSigned: true)
        #expect(!TrustedConduitPolicy.default.isTrustedConduit(node))
    }

    @Test("Apple-signed binary in /tmp is NOT a trusted conduit")
    func appleInTmpDenied() {
        let node = makeProcess(path: "/tmp/temp-binary", isAppleSigned: true)
        #expect(!TrustedConduitPolicy.default.isTrustedConduit(node))
    }

    @Test("Unsigned binary in /usr/local/bin is NOT trusted (no identity evidence)")
    func unsignedInUsrLocalBin() {
        // Location is trusted but identity isn't. Both required.
        let node = makeProcess(path: "/usr/local/bin/some-tool", isAppleSigned: false)
        #expect(!TrustedConduitPolicy.default.isTrustedConduit(node))
    }

    @Test("Developer-ID-signed binary with allowlisted team is trusted in /opt/homebrew/bin")
    func allowlistedTeamInHomebrew() {
        let policy = TrustedConduitPolicy(
            trustedTeamIDs: ["TEAMID1234"],
            trustedPathPrefixes: TrustedConduitPolicy.default.trustedPathPrefixes,
            denylistedPathPrefixes: TrustedConduitPolicy.default.denylistedPathPrefixes
        )
        let node = makeProcess(
            path: "/opt/homebrew/bin/foo",
            isAppleSigned: false,
            teamId: "TEAMID1234"
        )
        #expect(policy.isTrustedConduit(node))
    }

    @Test("Unknown team ID is NOT trusted by default")
    func unknownTeamId() {
        let node = makeProcess(
            path: "/opt/homebrew/bin/foo",
            isAppleSigned: false,
            teamId: "RANDOM999"
        )
        #expect(!TrustedConduitPolicy.default.isTrustedConduit(node))
    }

    @Test("User-allowlisted processKey is trusted even outside trusted prefixes")
    func userAllowlistedKey() {
        let node = makeProcess(path: "/opt/homebrew/bin/custom-tool", isAppleSigned: false)
        let policy = TrustedConduitPolicy(
            trustedPathPrefixes: TrustedConduitPolicy.default.trustedPathPrefixes,
            userAllowlistedProcessKeys: [node.processKey],
            denylistedPathPrefixes: TrustedConduitPolicy.default.denylistedPathPrefixes
        )
        #expect(policy.isTrustedConduit(node))
    }

    @Test("Browser cache paths are denylisted")
    func browserCacheDenied() {
        let node = makeProcess(
            path: "/Users/me/Library/Caches/Chrome/something",
            isAppleSigned: true
        )
        #expect(!TrustedConduitPolicy.default.isTrustedConduit(node))
    }

    @Test("Empty / minimal default policy still rejects clearly suspicious paths")
    func minimalRejects() {
        let policy = TrustedConduitPolicy()  // truly empty policy
        let node = makeProcess(path: "/tmp/x", isAppleSigned: true)
        #expect(!policy.isTrustedConduit(node))
    }
}
