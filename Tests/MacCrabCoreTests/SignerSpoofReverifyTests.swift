// SignerSpoofReverifyTests.swift
// v1.17.2 — end-to-end coverage for the anti-spoof re-verification in
// EventEnricher: a collector-side `.apple` classification derived from an
// attacker-controllable `com.apple.*` signing identifier must be downgraded to
// its cryptographically-verified signer (`anchor apple` SecRequirement).

import Testing
import Foundation
@testable import MacCrabCore

@Suite("v1.17.2: signer anti-spoof re-verification")
struct SignerSpoofReverifyTests {

    /// Build a ProcessInfo with a collector-provided codeSignature, mirroring
    /// what ESHelpers/EsloggerParser hand the enricher.
    private func process(
        executable: String,
        signerType: SignerType,
        signingId: String,
        teamId: String?,
        isPlatformBinary: Bool
    ) -> MacCrabCore.ProcessInfo {
        let sig = CodeSignatureInfo(
            signerType: signerType,
            teamId: teamId,
            signingId: signingId,
            flags: 0x1 /* CS_VALID */
        )
        return MacCrabCore.ProcessInfo(
            pid: 999_001,
            ppid: 1,
            rpid: 1,
            name: (executable as NSString).lastPathComponent,
            executable: executable,
            commandLine: executable,
            args: [executable],
            workingDirectory: "/tmp",
            userId: UInt32(getuid()),
            userName: "tester",
            groupId: 20,
            startTime: Date(),
            codeSignature: sig,
            isPlatformBinary: isPlatformBinary
        )
    }

    private func enrich(_ proc: MacCrabCore.ProcessInfo) async -> SignerType? {
        let event = Event(
            eventCategory: .process, eventType: .start, eventAction: "exec",
            process: proc
        )
        let enriched = await EventEnricher().enrich(event)
        return enriched.process.codeSignature?.signerType
    }

    /// Create a real ad-hoc-signed Mach-O at a temp path whose code-signature
    /// Identifier is `com.apple.spoofed` — the exact spoof. Returns nil (test
    /// skips) if the toolchain isn't available.
    private func makeAdhocSpoofBinary() -> String? {
        let dir = NSTemporaryDirectory() + "maccrab-spooftest-\(getpid())"
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        let bin = dir + "/spoof"
        // Copy a tiny real Mach-O (/usr/bin/true) so codesign has something to sign.
        try? FileManager.default.removeItem(atPath: bin)
        guard (try? FileManager.default.copyItem(atPath: "/usr/bin/true", toPath: bin)) != nil else { return nil }
        // Ad-hoc re-sign it with an Apple-looking identifier.
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        p.arguments = ["-f", "-s", "-", "-i", "com.apple.spoofed", bin]
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        guard (try? p.run()) != nil else { return nil }
        p.waitUntilExit()
        return p.terminationStatus == 0 ? bin : nil
    }

    @Test("collector .apple from com.apple.* identifier is downgraded when the cert chain is NOT Apple-anchored")
    func spoofDowngraded() async throws {
        guard let bin = makeAdhocSpoofBinary() else {
            // Toolchain unavailable (sandboxed CI) — skip rather than fail.
            return
        }
        defer { try? FileManager.default.removeItem(atPath: (bin as NSString).deletingLastPathComponent) }

        // Simulate the collector having promoted it to .apple via the spoofable
        // signing-id path (non-empty team_id, com.apple.* id, NOT platform).
        let proc = process(
            executable: bin,
            signerType: .apple,
            signingId: "com.apple.spoofed",
            teamId: "AB12CD34EF",
            isPlatformBinary: false
        )
        let result = await enrich(proc)
        // The ad-hoc signature does NOT satisfy `anchor apple`, so the enricher
        // must downgrade it off .apple.
        #expect(result != .apple,
                "a com.apple.*-named non-Apple-anchored binary must not stay .apple, got \(String(describing: result))")
    }

    @Test("genuine Apple platform binary keeps .apple without re-verification")
    func platformBinaryKeptApple() async throws {
        // /bin/ls is a real platform binary; isPlatformBinary short-circuits the
        // expensive check and it stays .apple.
        let proc = process(
            executable: "/bin/ls",
            signerType: .apple,
            signingId: "com.apple.ls",
            teamId: nil,
            isPlatformBinary: true
        )
        let result = await enrich(proc)
        #expect(result == .apple, "platform binary must remain .apple, got \(String(describing: result))")
    }

    @Test("genuine Apple-anchored non-platform binary stays .apple after re-verification")
    func realAppleBinaryStaysApple() async throws {
        // /usr/bin/codesign is Apple-signed and DOES satisfy `anchor apple`.
        // Marked non-platform here so the re-verification path runs; the crypto
        // check confirms .apple, so it is preserved.
        let proc = process(
            executable: "/usr/bin/codesign",
            signerType: .apple,
            signingId: "com.apple.codesign",
            teamId: nil,
            isPlatformBinary: false
        )
        let result = await enrich(proc)
        #expect(result == .apple,
                "real Apple-anchored binary must stay .apple, got \(String(describing: result))")
    }
}
