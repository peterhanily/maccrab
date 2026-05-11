// RootCauseResolverTests.swift
// v1.10 TraceGraph (PR-8) — tests for RootCauseResolver including
// Fixture 10 (trusted Apple chain with suspicious leaf).

import Testing
import Foundation
@testable import MacCrabCore

@Suite("TraceGraph: RootCauseResolver")
struct RootCauseResolverTests {

    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    private func makeProcessEntity(
        key: String,
        path: String,
        isAppleSigned: Bool = false,
        teamId: String? = nil
    ) throws -> TraceEntity {
        let node = ProcessNode(
            processKey: key,
            pid: 100, ppid: 1,
            executablePath: path,
            signingTeamId: teamId,
            isAppleSigned: isAppleSigned,
            isNotarized: isAppleSigned,
            startTime: now
        )
        return try node.toEntity(source: "test")
    }

    @Test("All-trusted chain → trustedAncestry kind")
    func trustedAncestry() throws {
        let anchor = try makeProcessEntity(
            key: "anchor", path: "/usr/bin/curl", isAppleSigned: true
        )
        let p1 = try makeProcessEntity(
            key: "shell", path: "/bin/zsh", isAppleSigned: true
        )
        let p2 = try makeProcessEntity(
            key: "term", path: "/Applications/Terminal.app/Contents/MacOS/Terminal", isAppleSigned: true
        )

        let result = RootCauseResolver.resolve(
            anchor: anchor,
            ancestors: [p1, p2],   // closest-first: parent, grandparent
            decoder: RootCauseResolver.defaultProcessNodeDecoder,
            policy: .default
        )
        #expect(result.kind == .trustedAncestry)
        #expect(result.rootEntityId == anchor.id)
    }

    @Test("Untrusted leaf → root cause is the leaf (anchor)")
    func untrustedLeaf() throws {
        // Trusted ancestors but anchor itself is untrusted.
        let anchor = try makeProcessEntity(
            key: "evil", path: "/Users/me/Downloads/sketchy", isAppleSigned: false
        )
        let p1 = try makeProcessEntity(
            key: "shell", path: "/bin/zsh", isAppleSigned: true
        )

        let result = RootCauseResolver.resolve(
            anchor: anchor,
            ancestors: [p1],
            decoder: RootCauseResolver.defaultProcessNodeDecoder,
            policy: .default
        )
        #expect(result.kind == .trustTransition)
        #expect(result.rootEntityId == anchor.id)
    }

    @Test("Untrusted middle ancestor → root cause is the first untrusted ancestor")
    func untrustedMiddle() throws {
        // launchd → xpcproxy → Safari → DownloadedFile → curl
        // Walking from oldest (launchd) toward anchor (curl):
        // first untrusted is DownloadedFile.
        let curl = try makeProcessEntity(
            key: "curl", path: "/usr/bin/curl", isAppleSigned: true
        )
        let downloadedFile = try makeProcessEntity(
            key: "dl", path: "/Users/me/Downloads/binary", isAppleSigned: false
        )
        let safari = try makeProcessEntity(
            key: "safari", path: "/Applications/Safari.app/Contents/MacOS/Safari", isAppleSigned: true
        )
        let xpcproxy = try makeProcessEntity(
            key: "xpcproxy", path: "/usr/libexec/xpcproxy", isAppleSigned: true
        )
        let launchd = try makeProcessEntity(
            key: "launchd", path: "/sbin/launchd", isAppleSigned: true
        )
        // ancestors closest-first: dl, safari, xpcproxy, launchd
        let result = RootCauseResolver.resolve(
            anchor: curl,
            ancestors: [downloadedFile, safari, xpcproxy, launchd],
            decoder: RootCauseResolver.defaultProcessNodeDecoder,
            policy: .default
        )
        #expect(result.kind == .trustTransition)
        #expect(result.rootEntityId == downloadedFile.id)
    }

    /// Fixture 10 from §27.2 — trusted Apple chain with suspicious leaf.
    @Test("Fixture 10: trusted Apple chain with suspicious download leaf")
    func fixture10() throws {
        // launchd → xpcproxy → Safari → downloaded file → unsigned binary → network
        // Per §27.2 expected: Root cause is the downloaded unsigned binary,
        // NOT Safari, NOT launchd.
        let unsignedBinary = try makeProcessEntity(
            key: "unsigned-leaf", path: "/Users/me/Downloads/payload", isAppleSigned: false
        )
        let downloaded = try makeProcessEntity(
            key: "downloaded-spawn", path: "/Users/me/Downloads/dropper", isAppleSigned: false
        )
        let safari = try makeProcessEntity(
            key: "safari", path: "/Applications/Safari.app/Contents/MacOS/Safari", isAppleSigned: true
        )
        let xpcproxy = try makeProcessEntity(
            key: "xpcproxy", path: "/usr/libexec/xpcproxy", isAppleSigned: true
        )
        let launchd = try makeProcessEntity(
            key: "launchd", path: "/sbin/launchd", isAppleSigned: true
        )

        let result = RootCauseResolver.resolve(
            anchor: unsignedBinary,
            // closest-first: dropper, safari, xpcproxy, launchd
            ancestors: [downloaded, safari, xpcproxy, launchd],
            decoder: RootCauseResolver.defaultProcessNodeDecoder,
            policy: .default
        )
        #expect(result.kind == .trustTransition)
        // The root is the FIRST untrusted in the oldest-first walk —
        // that's `downloaded` (the dropper), not the leaf.
        #expect(result.rootEntityId == downloaded.id)
        #expect(result.rootEntityId != safari.id)
        #expect(result.rootEntityId != launchd.id)
    }

    @Test("Empty ancestor chain → anchor is root")
    func emptyChain() throws {
        let anchor = try makeProcessEntity(
            key: "anchor", path: "/Users/me/Downloads/x"
        )
        let result = RootCauseResolver.resolve(
            anchor: anchor,
            ancestors: [],
            decoder: RootCauseResolver.defaultProcessNodeDecoder,
            policy: .default
        )
        #expect(result.kind == .anchorIsRoot)
        #expect(result.rootEntityId == anchor.id)
    }

    @Test("Explanation prose mentions download location for ~/Downloads root cause")
    func explanationDownloadLocation() throws {
        let unsigned = try makeProcessEntity(
            key: "u", path: "/Users/me/Downloads/x", isAppleSigned: false
        )
        let parent = try makeProcessEntity(
            key: "p", path: "/Applications/Safari.app/Contents/MacOS/Safari", isAppleSigned: true
        )
        let result = RootCauseResolver.resolve(
            anchor: unsigned,
            ancestors: [parent],
            decoder: RootCauseResolver.defaultProcessNodeDecoder,
            policy: .default
        )
        #expect(result.trustTransitionExplanation.contains("download location"))
        #expect(result.trustTransitionExplanation.contains("/Downloads/"))
    }
}
