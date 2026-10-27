import Foundation
import Testing
@testable import MacCrabAgentKit
@testable import MacCrabCore

/// A Developer ID claim naming a team that buys an exemption is re-anchored
/// by Security before the engine believes the team. A chain rooted anywhere
/// but Apple is carried as ad-hoc and attests nothing; a genuine Developer
/// ID chain keeps its team, for the image Security judged.
@Suite("Exemption-team claims are re-verified", .serialized)
struct ExemptionTeamReverifyTests {
    /// `/usr/bin/codesign` signs the ad-hoc fixtures.
    static let codesignAvailable = FileManager.default.isExecutableFile(atPath: "/usr/bin/codesign")

    /// The installed Developer ID MacCrab.app's executable and the code
    /// directory hash the kernel reports for it running natively, which is
    /// the one `codesign` prints; nil when this host has no such install.
    static let installedMacCrab: (path: String, cdhash: String)? = {
        let app = "/Applications/MacCrab.app/Contents/MacOS/MacCrab"
        guard FileManager.default.isExecutableFile(atPath: app) else { return nil }
        let codesign = Process()
        codesign.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        codesign.arguments = ["-dvvv", app]
        let output = Pipe()
        codesign.standardOutput = output
        codesign.standardError = output
        guard (try? codesign.run()) != nil else { return nil }
        let text = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        codesign.waitUntilExit()
        guard text.contains("Authority=Developer ID Application"),
              text.contains("TeamIdentifier=" + NoiseFilter.macCrabTeamId),
              let line = text.split(separator: "\n").first(where: { $0.hasPrefix("CDHash=") }),
              let cdhash = CodeSignatureInfo.kernelCdhash(hex: String(line.dropFirst("CDHash=".count))) else {
            return nil
        }
        return (app, cdhash)
    }()

    private func process(_ executable: String, signer: SignerType, teamId: String?, signingId: String,
                         signature: CodeSignatureInfo? = nil, kernelCdhash: String? = nil) -> MacCrabCore.ProcessInfo {
        MacCrabCore.ProcessInfo(
            pid: 999_101, ppid: 1, rpid: 1, name: (executable as NSString).lastPathComponent,
            executable: executable, commandLine: executable, args: [executable], workingDirectory: "/tmp",
            userId: UInt32(getuid()), userName: "tester", groupId: 20, startTime: Date(),
            codeSignature: signature ?? CodeSignatureInfo(signerType: signer, teamId: teamId, signingId: signingId,
                                                          flags: 0x1, kernelCdhash: kernelCdhash),
            isPlatformBinary: false)
    }

    private func event(_ process: MacCrabCore.ProcessInfo, file: String? = nil) -> Event {
        Event(eventCategory: file == nil ? .process : .file, eventType: file == nil ? .start : .change,
              eventAction: file == nil ? "exec" : "open", process: process,
              file: file.map { FileInfo(path: $0, action: .open) })
    }

    private static func makeEnricher() -> EventEnricher {
        EventEnricher(heavyEnrichmentPlane: HeavyEnrichmentPlane(
            configuration: .init(operationTimeoutSeconds: 30),
            liveMemoryBudget: .isolatedProductionEquivalentForTesting()))
    }

    /// Enrich with `enricher` and wait for the deferred signature verdict, as
    /// the lane does.
    private func resolve(_ process: MacCrabCore.ProcessInfo, with enricher: EventEnricher) async -> CodeSignatureInfo? {
        let first = await enricher.enrich(event(process))
        if let signature = first.process.codeSignature { return signature }
        let deadline = DispatchTime.now().uptimeNanoseconds + 30_000_000_000
        while DispatchTime.now().uptimeNanoseconds < deadline {
            if let patch = await enricher.drainDeferredEnrichments(limit: 16).first(where: { $0.component == .codeSignature }),
               let applied = patch.applying(to: first) {
                return applied.process.codeSignature
            }
            try? await Task.sleep(nanoseconds: 5_000_000)
        }
        return nil
    }

    /// `resolve` on an enricher of its own.
    private func enriched(_ process: MacCrabCore.ProcessInfo) async -> CodeSignatureInfo? {
        let enricher = Self.makeEnricher()
        let signature = await resolve(process, with: enricher)
        _ = await enricher.shutdownHeavyEnrichment()
        return signature
    }

    /// A real ad-hoc-signed Mach-O named `name`, or nil when copying or signing it fails.
    private func adHocBinary(named name: String, identifier: String, in directory: String) -> String? {
        let path = directory + "/" + name
        try? FileManager.default.removeItem(atPath: path)
        guard (try? FileManager.default.copyItem(atPath: "/usr/bin/true", toPath: path)) != nil else { return nil }
        let codesign = Process()
        codesign.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        codesign.arguments = ["-f", "-s", "-", "-i", identifier, path]
        codesign.standardOutput = FileHandle.nullDevice
        codesign.standardError = FileHandle.nullDevice
        guard (try? codesign.run()) != nil else { return nil }
        codesign.waitUntilExit()
        return codesign.terminationStatus == 0 ? path : nil
    }

    @Test("only a claim that would buy trust is re-anchored")
    func reverificationScope() {
        func claim(_ signer: SignerType, team: String?, signingId: String = "x") -> CodeSignatureInfo {
            CodeSignatureInfo(signerType: signer, teamId: team, signingId: signingId, flags: 0x1)
        }
        for team in [NoiseFilter.macCrabTeamId, CredentialFence.appleDeveloperToolsTeamId,
                     CredentialFence.googleTeamId, CredentialFence.braveTeamId] {
            #expect(EventEnricher.needsCryptographicVerification(claim(.devId, team: team), isPlatformBinary: false), "\(team)")
            #expect(EventEnricher.needsCryptographicVerification(claim(.appStore, team: team), isPlatformBinary: false), "\(team)")
        }
        // An ordinary team or identifier, Sparkle's included, buys nothing,
        // so they are taken as reported.
        #expect(!EventEnricher.needsCryptographicVerification(claim(.devId, team: "ABCDE12345"), isPlatformBinary: false))
        #expect(!EventEnricher.needsCryptographicVerification(
            claim(.devId, team: "ABCDE12345", signingId: "org.sparkle-project.Sparkle.Autoupdate"), isPlatformBinary: false))
        #expect(!EventEnricher.needsCryptographicVerification(claim(.devId, team: nil), isPlatformBinary: false))
        #expect(!EventEnricher.needsCryptographicVerification(claim(.adHoc, team: NoiseFilter.macCrabTeamId), isPlatformBinary: false))
        #expect(!EventEnricher.needsCryptographicVerification(claim(.unsigned, team: NoiseFilter.macCrabTeamId), isPlatformBinary: false))
        #expect(EventEnricher.needsCryptographicVerification(claim(.apple, team: nil), isPlatformBinary: false))
        #expect(!EventEnricher.needsCryptographicVerification(claim(.apple, team: nil), isPlatformBinary: true))
        #expect(!EventEnricher.needsCryptographicVerification(nil, isPlatformBinary: false))
    }

    @Test("a self-signed chain naming MacCrab's or a browser's team is carried as ad-hoc and trusts nothing",
          .enabled(if: Self.codesignAvailable, "needs /usr/bin/codesign to sign the fixtures"))
    func selfSignedExemptionTeamIsDowngraded() async throws {
        let directory = NSTemporaryDirectory() + "maccrab-reverify-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: directory) }
        let daemon = try #require(adHocBinary(named: "maccrabd", identifier: "com.maccrab.agent", in: directory))
        let chrome = try #require(adHocBinary(named: "Google Chrome", identifier: "com.google.Chrome", in: directory))
        // The collector saw CS_VALID without CS_ADHOC and the team the code
        // directory names, as a self-signed certificate chain presents.
        let claim = process(daemon, signer: .devId, teamId: NoiseFilter.macCrabTeamId, signingId: "com.maccrab.agent")
        let verdict = await enriched(claim)
        #expect(verdict?.signerType == .adHoc)
        #expect(verdict?.attestedTeamId == nil)
        if let verdict {
            let judged = event(process(daemon, signer: .adHoc, teamId: nil, signingId: "", signature: verdict))
            #expect(!NoiseFilter.isMacCrabProcess(event: judged, developmentEngine: false))
            #expect(!NoiseFilter.isTrustedSigner(event: judged))
            #expect(!AlertSink.isVerifiedMacCrabActor(processPath: daemon, event: judged, developmentEngine: false))
            #expect(EventInsertFilter(macCrabProcessNames: ["maccrabd"]).shouldDrop(event: judged) == false)
        }
        let browserClaim = process(chrome, signer: .devId, teamId: "EQHXZ8M8AV", signingId: "com.google.Chrome")
        let browserVerdict = await enriched(browserClaim)
        #expect(browserVerdict?.signerType == .adHoc)
        if let browserVerdict {
            let read = event(process(chrome, signer: .adHoc, teamId: nil, signingId: "", signature: browserVerdict),
                             file: "/Users/u/Library/Keychains/login.keychain-db")
            #expect(EventLoop.credentialFenceFinding(
                event: read, fence: CredentialFence(), toolName: "Claude Code", toolType: .claudeCode,
                developmentEngine: false) != nil)
        }
    }

    @Test("the installed Developer ID MacCrab keeps its team for the image Security judged, and only for it",
          .enabled(if: Self.installedMacCrab != nil, "needs the installed Developer ID MacCrab.app"))
    func developerIDChainKeepsTeam() async throws {
        let installed = try #require(Self.installedMacCrab)
        let enricher = Self.makeEnricher()
        let claim = process(installed.path, signer: .devId, teamId: NoiseFilter.macCrabTeamId,
                            signingId: "com.maccrab.app", kernelCdhash: installed.cdhash)
        let verdict = try #require(await resolve(claim, with: enricher))
        #expect(verdict.signerType == .devId)
        #expect(verdict.attestedTeamId == NoiseFilter.macCrabTeamId)
        #expect(verdict.kernelCdhash == installed.cdhash)
        let judged = event(process(installed.path, signer: .devId, teamId: nil, signingId: "", signature: verdict))
        #expect(NoiseFilter.isMacCrabProcess(event: judged, developmentEngine: false))
        // The cached verdict, for a process running another image: no team.
        let other = process(installed.path, signer: .devId, teamId: NoiseFilter.macCrabTeamId,
                            signingId: "com.maccrab.app", kernelCdhash: String(repeating: "5a", count: 20))
        let unbound = try #require(await resolve(other, with: enricher))
        #expect(unbound.signerType == .adHoc)
        #expect(unbound.attestedTeamId == nil)
        _ = await enricher.shutdownHeavyEnrichment()
    }
}
