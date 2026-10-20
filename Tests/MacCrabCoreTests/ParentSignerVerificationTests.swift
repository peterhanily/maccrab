import Foundation
import Testing
@testable import MacCrabCore

/// A non-platform binary that names itself com.apple.* is downgraded for its
/// own events; its children must not inherit the unverified Apple claim.
@Suite("ParentSignerType follows verified code signing")
struct ParentSignerVerificationTests {
    private func spoofer() throws -> (directory: URL, path: String) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("parent-signer-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let path = dir.appendingPathComponent("com.apple.helper").path
        try Data("#!/bin/sh\nexit 0\n".utf8).write(to: URL(fileURLWithPath: path))
        return (dir, path)
    }

    private func exec(pid: Int32, ppid: Int32, executable: String,
                      signer: SignerType, platform: Bool) -> Event {
        let process = MacCrabCore.ProcessInfo(
            pid: pid, ppid: ppid, rpid: ppid, name: (executable as NSString).lastPathComponent,
            executable: executable, commandLine: executable, args: [executable],
            workingDirectory: "/", userId: 501, userName: "user", groupId: 20,
            startTime: Date(),
            codeSignature: CodeSignatureInfo(signerType: signer, signingId: "com.apple.helper"),
            isPlatformBinary: platform)
        return Event(timestamp: Date(), eventCategory: .process, eventType: .start,
                     eventAction: "exec", process: process)
    }

    @Test("an unverified Apple claim does not vouch for children; a platform parent still does")
    func unverifiedAppleParentDoesNotVouch() async throws {
        let (dir, path) = try spoofer()
        defer { try? FileManager.default.removeItem(at: dir) }
        let lineage = ProcessLineage()
        let enricher = EventEnricher(lineage: lineage)
        _ = await enricher.enrich(exec(pid: 41_000, ppid: 1, executable: path,
                                        signer: .apple, platform: false))
        #expect(await lineage.signerType(of: 41_000) == nil)
        let child = await enricher.enrich(exec(pid: 41_001, ppid: 41_000,
            executable: "/usr/bin/security", signer: .apple, platform: true))
        #expect(child.enrichments["ParentSignerType"] != "apple")

        _ = await enricher.enrich(exec(pid: 41_002, ppid: 1, executable: "/usr/bin/login",
                                        signer: .apple, platform: true))
        let platformChild = await enricher.enrich(exec(pid: 41_003, ppid: 41_002,
            executable: "/usr/bin/security", signer: .apple, platform: true))
        #expect(platformChild.enrichments["ParentSignerType"] == "apple")
    }

    @Test("a verified verdict replaces the unknown on the parent's lineage node")
    func verifiedVerdictReachesChildren() async throws {
        let (dir, path) = try spoofer()
        defer { try? FileManager.default.removeItem(at: dir) }
        let cache = CodeSigningCache()
        let verified = await cache.evaluate(path: path)
        #expect(verified.signerType != .apple)
        let lineage = ProcessLineage()
        let enricher = EventEnricher(lineage: lineage, codeSigningCache: cache)
        _ = await enricher.enrich(exec(pid: 42_000, ppid: 1, executable: path,
                                        signer: .apple, platform: false))
        #expect(await lineage.signerType(of: 42_000) == verified.signerType.rawValue)
        let child = await enricher.enrich(exec(pid: 42_001, ppid: 42_000,
            executable: "/usr/bin/security", signer: .apple, platform: true))
        #expect(child.enrichments["ParentSignerType"] == verified.signerType.rawValue)
        // A pid reused by another executable keeps its own node.
        await lineage.recordVerifiedSignerType(pid: 42_000, path: "/other", signerType: "apple")
        #expect(await lineage.signerType(of: 42_000) == verified.signerType.rawValue)
    }
}
