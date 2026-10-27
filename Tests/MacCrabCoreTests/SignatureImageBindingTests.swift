// SignatureImageBindingTests.swift
//
// A Security verdict describes the file at a path, not the process that path
// names. The enricher believes a trusted verdict for a process only when the
// file's code directory hashes include the one the kernel reports for the
// image the process runs. A seam stands in for Security where no signing
// identity on the test host can produce the verdict a case needs; the safe
// open, the file-identity binding and the heavy plane around it are real.

import Darwin
import Foundation
import Testing
@testable import MacCrabAgentKit
@testable import MacCrabCore

@Suite("Signature verdicts bind to the running image", .serialized)
struct SignatureImageBindingTests {
    private static let imageX = String(repeating: "a1", count: 20)
    private static let imageY = String(repeating: "b2", count: 20)
    private static let imageZ = String(repeating: "c3", count: 20)
    private static let keychain = "/Users/u/Library/Keychains/login.keychain-db"

    private static func chain(_ leaf: String) -> [String] {
        [leaf, "Developer ID Certification Authority", "Apple Root CA"]
    }

    /// A regular file named `name` under a fixture root, standing in for the
    /// executable at an event's path.
    private static func fixture(named name: String) throws -> (root: String, path: String) {
        let root = NSTemporaryDirectory() + "maccrab-image-binding-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: root, withIntermediateDirectories: true)
        let path = root + "/" + name
        try Data(repeating: 0xcf, count: 64).write(to: URL(fileURLWithPath: path))
        return (root, path)
    }

    private static func verdict(
        _ signer: SignerType, team: String?, signingId: String, authorities: [String], cdhashes: Set<String>
    ) -> CodeSigningCache.Verdict {
        CodeSigningCache.Verdict(
            info: CodeSignatureInfo(signerType: signer, teamId: team, signingId: signingId,
                                    authorities: authorities, flags: 0x1_0001, isNotarized: true),
            cdhashes: cdhashes)
    }

    /// The kernel's claim for a process, as Endpoint Security reports it.
    private static func claim(
        _ signer: SignerType, team: String?, signingId: String, kernelCdhash: String?
    ) -> CodeSignatureInfo {
        CodeSignatureInfo(signerType: signer, teamId: team, signingId: signingId, flags: 0x1, kernelCdhash: kernelCdhash)
    }

    /// An enricher whose Security evaluations return `verdict`.
    private static func enricher(_ verdict: CodeSigningCache.Verdict) -> EventEnricher {
        EventEnricher(
            codeSigningCache: CodeSigningCache(evaluatorForTesting: { _ in verdict }),
            heavyEnrichmentPlane: HeavyEnrichmentPlane(
                configuration: .init(operationTimeoutSeconds: 30),
                liveMemoryBudget: .isolatedProductionEquivalentForTesting()))
    }

    private static func event(
        _ path: String, pid: Int32 = 999_201, claim: CodeSignatureInfo?, file: String? = nil,
        enrichments: [String: String] = [:]
    ) -> Event {
        let process = MacCrabCore.ProcessInfo(
            pid: pid, ppid: 1, rpid: 1, name: (path as NSString).lastPathComponent,
            executable: path, commandLine: path, args: [path], workingDirectory: "/tmp",
            userId: UInt32(getuid()), userName: "tester", groupId: 20, startTime: Date(),
            codeSignature: claim, isPlatformBinary: false)
        return Event(eventCategory: file == nil ? .process : .file, eventType: file == nil ? .start : .change,
                     eventAction: file == nil ? "exec" : "open", process: process,
                     file: file.map { FileInfo(path: $0, action: .open) }, enrichments: enrichments)
    }

    struct Outcome {
        let event: Event
        /// The first pass already carried the outcome.
        let inline: Bool
        var signature: CodeSignatureInfo? { event.process.codeSignature }
        var coverage: HeavyEnrichmentCoverage? { DeferredEventEnrichment.coverage(in: event)[.codeSignature] }
    }

    /// Enriches `event` and waits for a deferred verdict as the lane does.
    private static func published(_ enricher: EventEnricher, _ event: Event) async -> Outcome? {
        let first = await enricher.enrich(event)
        guard DeferredEventEnrichment.coverage(in: first)[.codeSignature] == .pending else {
            return Outcome(event: first, inline: true)
        }
        let deadline = DispatchTime.now().uptimeNanoseconds + 30_000_000_000
        while DispatchTime.now().uptimeNanoseconds < deadline {
            if let patch = await enricher.drainDeferredEnrichments(limit: 16)
                .first(where: { $0.component == .codeSignature }),
               let applied = patch.applying(to: first) {
                return Outcome(event: applied, inline: false)
            }
            try? await Task.sleep(nanoseconds: 5_000_000)
        }
        return nil
    }

    private static func fenceFinding(_ event: Event) -> Bool {
        EventLoop.credentialFenceFinding(
            event: event, fence: CredentialFence(), toolName: "Claude Code", toolType: .claudeCode,
            developmentEngine: false) != nil
    }

    // MARK: - Collectors carry the kernel's hash

    @Test("the collectors carry the kernel's hash for the running image, and only a real one")
    func collectorsCarryKernelHash() {
        let es = esProcessInfo(from: ESProcessFields(
            pid: 41, ppid: 1, rpid: 0, euid: 501, executablePath: "/tmp/tool", signingId: "com.example.tool",
            teamId: "ABCDE12345", codesigningFlags: 0x1, isPlatformBinary: false, cdhash: Self.imageX))
        #expect(es.codeSignature?.kernelCdhash == Self.imageX)

        func logged(_ cdhash: String) -> String? {
            EsloggerParser.extractProcess(from: [
                "audit_token": ["pid": 42, "euid": 501], "ppid": 1,
                "executable": ["path": "/tmp/tool"], "signing_id": "com.example.tool",
                "team_id": "ABCDE12345", "codesigning_flags": 1, "is_platform_binary": false,
                "cdhash": cdhash,
            ] as [String: Any]).codeSignature?.kernelCdhash
        }
        #expect(logged(Self.imageX.uppercased()) == Self.imageX)
        #expect(logged(String(repeating: "0", count: 40)) == nil)
        #expect(logged("") == nil)

        #expect(CodeSignatureInfo.kernelCdhash(bytes: [UInt8](repeating: 0xab, count: 20)) == String(repeating: "ab", count: 20))
        #expect(CodeSignatureInfo.kernelCdhash(bytes: [UInt8](repeating: 0, count: 20)) == nil)
        #expect(CodeSignatureInfo.kernelCdhash(bytes: [UInt8](repeating: 0xab, count: 19)) == nil)
        #expect(CodeSignatureInfo.kernelCdhash(hex: "+" + String(repeating: "a", count: 39)) == nil)
    }

    @Test("the kernel's hash travels with a signature but is neither encoded nor compared")
    func kernelHashIsTransportOnly() throws {
        let carried = CodeSignatureInfo(signerType: .devId, teamId: "ABCDE12345", signingId: "com.example",
                                        flags: 0x1, kernelCdhash: Self.imageX)
        let plain = CodeSignatureInfo(signerType: .devId, teamId: "ABCDE12345", signingId: "com.example", flags: 0x1)
        #expect(carried == plain)
        #expect(carried.hashValue == plain.hashValue)
        let data = try JSONEncoder().encode(carried)
        #expect(!String(decoding: data, as: UTF8.self).contains(Self.imageX))
        let decoded = try JSONDecoder().decode(CodeSignatureInfo.self, from: data)
        #expect(decoded == carried)
        #expect(decoded.kernelCdhash == nil)
        #expect(carried.withSignerType(.adHoc).kernelCdhash == Self.imageX)
        // Equality and hashing list every other stored field by hand: a new
        // field must join them.
        #expect(Mirror(reflecting: carried).children.compactMap(\.label) == [
            "signerType", "teamId", "signingId", "authorities", "flags", "isNotarized",
            "issuerChain", "certHashes", "isAdhocSigned", "entitlements", "kernelCdhash",
        ])
    }

    // MARK: - Endpoint Security claims

    @Test("a verdict for another image buys no exemption team, no Apple, no MacCrab and no keychain")
    func verdictForAnotherImageGrantsNothing() async throws {
        // Security judged genuine code with hash X; the process runs image Y,
        // or reports no hash at all.
        for kernelCdhash in [Self.imageY, nil] {
            let maccrab = try Self.fixture(named: "maccrabd")
            defer { try? FileManager.default.removeItem(atPath: maccrab.root) }
            let enricher = Self.enricher(Self.verdict(
                .devId, team: NoiseFilter.macCrabTeamId, signingId: "com.maccrab.agent",
                authorities: Self.chain("Developer ID Application: MacCrab (79S425CW99)"), cdhashes: [Self.imageX]))
            let outcome = try #require(await Self.published(enricher, Self.event(
                maccrab.path, claim: Self.claim(.devId, team: NoiseFilter.macCrabTeamId, signingId: "com.maccrab.agent",
                                                kernelCdhash: kernelCdhash),
                file: Self.keychain)))
            let signature = try #require(outcome.signature)
            #expect(signature.signerType == .adHoc)
            #expect(signature.teamId == nil)
            #expect(signature.attestedTeamId == nil)
            #expect(signature.authorities.isEmpty)
            #expect(signature.signingId == "com.maccrab.agent", "the claim's identifier is kept, as for any ad-hoc code")
            #expect(signature.kernelCdhash == kernelCdhash)
            #expect(!NoiseFilter.isMacCrabProcess(event: outcome.event, developmentEngine: false))
            #expect(!NoiseFilter.isTrustedSigner(event: outcome.event))
            #expect(Self.fenceFinding(outcome.event), "an unverified maccrabd does not own the keychain")
            _ = await enricher.shutdownHeavyEnrichment()
        }

        let chrome = try Self.fixture(named: "Google Chrome")
        defer { try? FileManager.default.removeItem(atPath: chrome.root) }
        let google = Self.enricher(Self.verdict(
            .devId, team: CredentialFence.googleTeamId, signingId: "com.google.Chrome",
            authorities: Self.chain("Developer ID Application: Google LLC (EQHXZ8M8AV)"), cdhashes: [Self.imageX]))
        let read = try #require(await Self.published(google, Self.event(
            chrome.path, claim: Self.claim(.devId, team: CredentialFence.googleTeamId, signingId: "com.google.Chrome",
                                           kernelCdhash: Self.imageY),
            file: Self.keychain)))
        #expect(read.signature?.attestedTeamId == nil)
        #expect(Self.fenceFinding(read.event), "Google's verdict for another image does not own the keychain")
        _ = await google.shutdownHeavyEnrichment()

        let notarytool = try Self.fixture(named: "notarytool")
        defer { try? FileManager.default.removeItem(atPath: notarytool.root) }
        let apple = Self.enricher(Self.verdict(
            .apple, team: CredentialFence.appleDeveloperToolsTeamId, signingId: "com.apple.gke.notary.tool",
            authorities: ["Software Signing", "Apple Code Signing Certification Authority", "Apple Root CA"],
            cdhashes: [Self.imageX]))
        let tool = try #require(await Self.published(apple, Self.event(
            notarytool.path, claim: Self.claim(.apple, team: CredentialFence.appleDeveloperToolsTeamId,
                                               signingId: "com.apple.gke.notary.tool", kernelCdhash: Self.imageY),
            file: Self.keychain)))
        #expect(tool.signature?.signerType == .adHoc)
        #expect(!NoiseFilter.isAppleSystemBinary(event: tool.event))
        #expect(Self.fenceFinding(tool.event), "an unverified notarytool is no exempt Apple tool")
        _ = await apple.shutdownHeavyEnrichment()
    }

    @Test("a verdict for the running image keeps its trust, every field Security's")
    func verdictForRunningImageKeepsTrust() async throws {
        let chrome = try Self.fixture(named: "Google Chrome")
        defer { try? FileManager.default.removeItem(atPath: chrome.root) }
        let found = Self.verdict(
            .devId, team: CredentialFence.googleTeamId, signingId: "com.google.Chrome",
            authorities: Self.chain("Developer ID Application: Google LLC (EQHXZ8M8AV)"),
            cdhashes: [Self.imageX, Self.imageZ])
        // The kernel may report the hash of any digest the code carries.
        for kernelCdhash in [Self.imageX, Self.imageZ] {
            let enricher = Self.enricher(found)
            let outcome = try #require(await Self.published(enricher, Self.event(
                chrome.path,
                claim: Self.claim(.devId, team: CredentialFence.googleTeamId, signingId: "com.google.Chrome.claimed",
                                  kernelCdhash: kernelCdhash),
                file: Self.keychain)))
            let signature = try #require(outcome.signature)
            #expect(signature == found.info, "class, team, identifier, flags and notarization are Security's")
            #expect(signature.signingId == "com.google.Chrome")
            #expect(signature.kernelCdhash == kernelCdhash)
            #expect(!Self.fenceFinding(outcome.event), "Google's own browser owns its keychain items")
            _ = await enricher.shutdownHeavyEnrichment()
        }
    }

    @Test("a cached verdict is believed only for the image it judged")
    func cachedVerdictBindsToo() async throws {
        let maccrab = try Self.fixture(named: "maccrabd")
        defer { try? FileManager.default.removeItem(atPath: maccrab.root) }
        let enricher = Self.enricher(Self.verdict(
            .devId, team: NoiseFilter.macCrabTeamId, signingId: "com.maccrab.agent",
            authorities: Self.chain("Developer ID Application: MacCrab (79S425CW99)"), cdhashes: [Self.imageX]))
        func run(_ kernelCdhash: String) async throws -> Outcome {
            try #require(await Self.published(enricher, Self.event(
                maccrab.path, claim: Self.claim(.devId, team: NoiseFilter.macCrabTeamId,
                                                signingId: "com.maccrab.agent", kernelCdhash: kernelCdhash))))
        }
        let cold = try await run(Self.imageX)
        #expect(!cold.inline, "the first verdict comes from the heavy plane")
        #expect(cold.signature?.attestedTeamId == NoiseFilter.macCrabTeamId)
        let other = try await run(Self.imageY)
        #expect(other.inline, "the second event hits the cache")
        #expect(other.signature?.signerType == .adHoc)
        #expect(other.signature?.attestedTeamId == nil)
        let same = try await run(Self.imageX)
        #expect(same.inline)
        #expect(same.signature?.attestedTeamId == NoiseFilter.macCrabTeamId)
        _ = await enricher.shutdownHeavyEnrichment()
    }

    @Test("an Apple verdict confirms only an Apple claim; a downgrade is published as Security found it")
    func classMismatch() async throws {
        let fixture = try Self.fixture(named: "tool")
        defer { try? FileManager.default.removeItem(atPath: fixture.root) }
        let appleVerdict = Self.enricher(Self.verdict(
            .apple, team: nil, signingId: "com.apple.tool",
            authorities: ["Software Signing", "Apple Code Signing Certification Authority", "Apple Root CA"],
            cdhashes: [Self.imageX]))
        let raised = try #require(await Self.published(appleVerdict, Self.event(
            fixture.path, claim: Self.claim(.devId, team: NoiseFilter.macCrabTeamId, signingId: "com.maccrab.agent",
                                            kernelCdhash: Self.imageX))))
        #expect(raised.signature?.signerType == .adHoc)
        #expect(raised.signature?.attestedTeamId == nil)
        _ = await appleVerdict.shutdownHeavyEnrichment()

        // Xcode from the App Store names itself com.apple.dt.Xcode under
        // Apple's developer-tools team, which the kernel classes Apple, and
        // Security finds App Store signing.
        let storeVerdict = Self.verdict(
            .appStore, team: CredentialFence.appleDeveloperToolsTeamId, signingId: "com.apple.dt.Xcode",
            authorities: ["Apple Mac OS Application Signing",
                          "Apple Worldwide Developer Relations Certification Authority", "Apple Root CA"],
            cdhashes: [Self.imageX])
        let store = Self.enricher(storeVerdict)
        let downgraded = try #require(await Self.published(store, Self.event(
            fixture.path, claim: Self.claim(.apple, team: CredentialFence.appleDeveloperToolsTeamId,
                                            signingId: "com.apple.dt.Xcode", kernelCdhash: Self.imageX))))
        #expect(downgraded.signature == storeVerdict.info)
        #expect(downgraded.signature?.signerType == .appStore)
        _ = await store.shutdownHeavyEnrichment()
    }

    @Test("a verdict that grants nothing needs no binding")
    func untrustedVerdictNeedsNoBinding() async throws {
        let fixture = try Self.fixture(named: "maccrabd")
        defer { try? FileManager.default.removeItem(atPath: fixture.root) }
        let selfSigned = Self.verdict(.adHoc, team: NoiseFilter.macCrabTeamId, signingId: "com.maccrab.agent",
                                      authorities: ["MacCrab Self-Signed"], cdhashes: [Self.imageX])
        let enricher = Self.enricher(selfSigned)
        let outcome = try #require(await Self.published(enricher, Self.event(
            fixture.path, claim: Self.claim(.devId, team: NoiseFilter.macCrabTeamId, signingId: "com.maccrab.agent",
                                            kernelCdhash: Self.imageY))))
        #expect(outcome.signature == selfSigned.info)
        #expect(outcome.signature?.attestedTeamId == nil)
        _ = await enricher.shutdownHeavyEnrichment()
    }

    // MARK: - Producers without a signature

    @Test("a producer without a signature is bound through the live process's kernel hash")
    func pidBoundProducer() async throws {
        let live = try #require(await CDHashExtractor().extractCDHash(pid: getpid()))
        let fixture = try Self.fixture(named: "helper")
        defer { try? FileManager.default.removeItem(atPath: fixture.root) }
        let apple = ["Software Signing", "Apple Code Signing Certification Authority", "Apple Root CA"]

        let other = Self.enricher(Self.verdict(.apple, team: nil, signingId: "com.apple.helper",
                                               authorities: apple, cdhashes: [Self.imageX]))
        let unbound = try #require(await Self.published(other, Self.event(fixture.path, pid: getpid(), claim: nil)))
        #expect(unbound.signature?.signerType == .adHoc, "the file is not the image this process runs")
        #expect(unbound.signature?.kernelCdhash == live)
        _ = await other.shutdownHeavyEnrichment()

        let runningVerdict = Self.verdict(.apple, team: nil, signingId: "com.apple.helper",
                                          authorities: apple, cdhashes: [live])
        let running = Self.enricher(runningVerdict)
        let bound = try #require(await Self.published(running, Self.event(fixture.path, pid: getpid(), claim: nil)))
        #expect(bound.signature == runningVerdict.info)
        #expect(bound.signature?.signerType == .apple)
        _ = await running.shutdownHeavyEnrichment()

        // No live process to read: no trusted verdict, and nothing guessed.
        let gone = Self.enricher(runningVerdict)
        let unknown = try #require(await Self.published(gone, Self.event(fixture.path, pid: Int32.max, claim: nil)))
        #expect(unknown.signature == nil)
        #expect(unknown.coverage == .unavailable)
        _ = await gone.shutdownHeavyEnrichment()
    }

    @Test("an event without a process keeps its collector's verdict on the file")
    func eventWithoutProcess() async throws {
        let fixture = try Self.fixture(named: "Google Chrome")
        defer { try? FileManager.default.removeItem(atPath: fixture.root) }
        let collector = Self.verdict(
            .devId, team: CredentialFence.googleTeamId, signingId: "com.google.Chrome",
            authorities: Self.chain("Developer ID Application: Google LLC (EQHXZ8M8AV)"), cdhashes: [])
        let enricher = Self.enricher(Self.verdict(.unsigned, team: nil, signingId: "", authorities: [], cdhashes: []))
        let outcome = try #require(await Self.published(enricher, Self.event(fixture.path, pid: 0, claim: collector.info)))
        #expect(outcome.inline)
        #expect(outcome.signature == collector.info)
        _ = await enricher.shutdownHeavyEnrichment()
    }

    // MARK: - Kernel and Security agree

    private static let isTranslated: Bool = {
        var translated: Int32 = 0
        var size = MemoryLayout<Int32>.size
        return sysctlbyname("sysctl.proc_translated", &translated, &size, nil, 0) == 0 && translated == 1
    }()

    @Test("the kernel's hash for this process is among Security's hashes for its executable",
          .enabled(if: !Self.isTranslated, "a Rosetta process runs the slice Security does not judge"))
    func kernelAndSecurityAgree() async throws {
        let live = try #require(await CDHashExtractor().extractCDHash(pid: getpid()))
        var buffer = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let length = proc_pidpath(getpid(), &buffer, UInt32(buffer.count))
        try #require(length > 0)
        let executable = String(cString: buffer)
        let verdict = try #require(await CodeSigningCache().evaluateExecutableVerdict(path: executable))
        #expect(verdict.cdhashes.contains(live), "\(executable): \(verdict.cdhashes.sorted())")
    }
}
