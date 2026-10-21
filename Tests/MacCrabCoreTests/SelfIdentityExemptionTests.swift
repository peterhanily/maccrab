import Foundation
import Testing
@testable import MacCrabAgentKit
@testable import MacCrabCore

/// Exemptions keyed on MacCrab's own or Apple's tools must rest on identity
/// the actor cannot forge, not on a name or a user-writable path.
@Suite("Self-identity exemptions")
struct SelfIdentityExemptionTests {
    private func event(
        _ path: String,
        signer: SignerType? = nil,
        teamId: String? = nil,
        signingId: String? = nil,
        platform: Bool = false,
        file: String = "/Users/u/Library/Keychains/login.keychain-db"
    ) -> Event {
        let signature = signer.map {
            CodeSignatureInfo(signerType: $0, teamId: teamId, signingId: signingId,
                              authorities: [], flags: 0, isNotarized: false)
        }
        let process = MacCrabCore.ProcessInfo(
            pid: 4242, ppid: 1, rpid: 1, name: (path as NSString).lastPathComponent,
            executable: path, commandLine: path, args: [path], workingDirectory: "/tmp",
            userId: 501, userName: "u", groupId: 20, startTime: Date(),
            codeSignature: signature, isPlatformBinary: platform)
        return Event(eventCategory: .file, eventType: .change, eventAction: "write",
                     process: process,
                     file: FileInfo(path: file, action: .write))
    }

    @Test("AlertSink lowers severity only for a MacCrab actor it can verify")
    func alertSinkNeedsVerifiedActor() {
        let app = "/Applications/MacCrab.app/Contents/MacOS/MacCrab"
        // Without the event only the sysext location counts in a release engine.
        for path in [
            "/Applications/MacCrab.app/Contents/MacOS/payload",
            "/private/var/folders/hf/X/T/maccrab-tier-b-verified-Y/bin",
            "/Users/u/src/maccrab/.build/debug/maccrabd",
        ] {
            #expect(!AlertSink.isVerifiedMacCrabActor(processPath: path, event: nil, developmentEngine: false), "\(path)")
        }
        #expect(AlertSink.isVerifiedMacCrabActor(
            processPath: "/Library/SystemExtensions/ABC/com.maccrab.agent.systemextension/Contents/MacOS/com.maccrab.agent",
            event: nil, developmentEngine: false))
        #expect(AlertSink.isVerifiedMacCrabActor(
            processPath: "/Users/u/src/maccrab/.build/debug/maccrabd", event: nil, developmentEngine: true))
        // With the event the team signature decides, not the path.
        let forged = event(app)
        #expect(!AlertSink.isVerifiedMacCrabActor(processPath: app, event: forged, developmentEngine: false))
        let genuine = event(app, signer: .devId, teamId: NoiseFilter.macCrabTeamId)
        #expect(AlertSink.isVerifiedMacCrabActor(processPath: app, event: genuine, developmentEngine: false))
        // An alert attributed to another process is judged by its own path.
        #expect(!AlertSink.isVerifiedMacCrabActor(
            processPath: "/Applications/MacCrab.app/Contents/MacOS/payload", event: genuine, developmentEngine: false))
    }

    @Test("CredentialFence exemptions rest on the kernel-attested signing identity, not a name or location")
    func credentialFenceExemptionNeedsIdentity() {
        let xcodeTeam = CredentialFence.appleDeveloperToolsTeamId
        // Apple's tools: a platform binary, or Apple's developer-tools team,
        // carrying the tool's own identifier.
        #expect(EventLoop.isCredentialFenceExempt(event(
            "/usr/bin/security", signer: .apple, signingId: "com.apple.security", platform: true)))
        #expect(EventLoop.isCredentialFenceExempt(event(
            "/usr/bin/codesign", signer: .apple, signingId: "com.apple.security.codesign", platform: true)))
        #expect(EventLoop.isCredentialFenceExempt(event(
            "/Applications/Xcode.app/Contents/Developer/usr/bin/notarytool", signer: .apple,
            teamId: xcodeTeam, signingId: "com.apple.gke.notary.tool")))
        // A renamed copy of /bin/cp is still a platform binary, but keeps
        // com.apple.cp wherever it is placed.
        #expect(!EventLoop.isCredentialFenceExempt(event(
            "/tmp/security", signer: .apple, signingId: "com.apple.cp", platform: true)))
        #expect(!EventLoop.isCredentialFenceExempt(event(
            "/usr/bin/cp", signer: .apple, signingId: "com.apple.cp", platform: true)))
        // An admin can create /Applications/Xcode-x.app, and a copied Xcode
        // tool keeps its own identifier.
        #expect(!EventLoop.isCredentialFenceExempt(event(
            "/Applications/Xcode-x.app/Contents/Developer/usr/bin/security", signer: .apple,
            teamId: xcodeTeam, signingId: "com.apple.git")))
        // Another team cannot claim an Apple identifier, and a signature that
        // is not known yet is no identity.
        #expect(!EventLoop.isCredentialFenceExempt(event(
            "/Library/Developer/CommandLineTools/usr/bin/notarytool", signer: .devId,
            teamId: "ABCDE12345", signingId: "com.apple.gke.notary.tool")))
        #expect(!EventLoop.isCredentialFenceExempt(event("/Library/Developer/CommandLineTools/usr/bin/notarytool")))
        #expect(!EventLoop.isCredentialFenceExempt(event("/Users/u/bin/codesign", signer: .adHoc, signingId: "codesign")))
        // pkgbuild and productbuild archive whatever directory they are given.
        #expect(!EventLoop.isCredentialFenceExempt(event(
            "/usr/bin/pkgbuild", signer: .apple, signingId: "com.apple.pkgbuild", platform: true)))
        #expect(!EventLoop.isCredentialFenceExempt(event(
            "/usr/bin/productbuild", signer: .apple, signingId: "com.apple.productbuild", platform: true)))
        // MacCrab's own tools need MacCrab's team signature.
        #expect(!EventLoop.isCredentialFenceExempt(event("/Users/u/maccrabd"), developmentEngine: false))
        #expect(EventLoop.isCredentialFenceExempt(event(
            "/Applications/MacCrab.app/Contents/Resources/bin/maccrabctl",
            signer: .devId, teamId: NoiseFilter.macCrabTeamId), developmentEngine: false))
        // Sparkle ships its tools ad-hoc signed: a renamed platform tool or a
        // team-signed binary with the name is not Sparkle's.
        let sparkle = "/Users/u/src/.build/artifacts/sparkle/Sparkle/bin/sign_update"
        #expect(EventLoop.isCredentialFenceExempt(event(sparkle, signer: .adHoc, signingId: "sign_update")))
        #expect(!EventLoop.isCredentialFenceExempt(event(
            sparkle, signer: .apple, signingId: "com.apple.cp", platform: true)))
        #expect(!EventLoop.isCredentialFenceExempt(event(
            sparkle, signer: .devId, teamId: "ABCDE12345", signingId: "sign_update")))
        #expect(!EventLoop.isCredentialFenceExempt(event(sparkle)))
    }

    @Test("Only Apple's ssh and ssh-add read a keychain exempt; scp and sftp would transfer it")
    func sshKeychainExemption() {
        #expect(EventLoop.isCredentialFenceExempt(event(
            "/usr/bin/ssh", signer: .apple, signingId: "com.apple.ssh", platform: true)))
        #expect(EventLoop.isCredentialFenceExempt(event(
            "/usr/bin/ssh-add", signer: .apple, signingId: "com.apple.ssh-add", platform: true)))
        #expect(!EventLoop.isCredentialFenceExempt(event(
            "/usr/bin/scp", signer: .apple, signingId: "com.apple.scp", platform: true)))
        #expect(!EventLoop.isCredentialFenceExempt(event(
            "/usr/bin/sftp", signer: .apple, signingId: "com.apple.sftp", platform: true)))
        #expect(!EventLoop.isCredentialFenceExempt(event(
            "/tmp/ssh", signer: .apple, signingId: "com.apple.cp", platform: true)))
        #expect(!EventLoop.isCredentialFenceExempt(event("/opt/homebrew/bin/ssh", signer: .adHoc, signingId: "ssh")))
    }

    @Test("An agent copying the login keychain with scp, sftp or a renamed platform tool is reported")
    func keychainCopyIsReported() {
        let fence = CredentialFence()
        func reported(_ event: Event) -> Bool {
            EventLoop.credentialFenceFinding(
                event: event, fence: fence, toolName: "Claude Code", toolType: .claudeCode,
                developmentEngine: false) != nil
        }
        #expect(reported(event("/usr/bin/scp", signer: .apple, signingId: "com.apple.scp", platform: true)))
        #expect(reported(event("/usr/bin/sftp", signer: .apple, signingId: "com.apple.sftp", platform: true)))
        #expect(!reported(event("/usr/bin/ssh", signer: .apple, signingId: "com.apple.ssh", platform: true)))
        // Copies of /bin/cp named for each keychain owner or exempt tool.
        for name in ["git-credential-osxkeychain", "Google Chrome", "Google Chrome Helper",
                     "Brave Browser", "security", "sign_update"] {
            #expect(reported(event("/tmp/x/" + name, signer: .apple, signingId: "com.apple.cp", platform: true)), "\(name)")
        }
        // The genuine owners are not reported.
        #expect(!reported(event(
            "/opt/homebrew/Cellar/git/2.51.0/libexec/git-core/git-credential-osxkeychain",
            signer: .adHoc, signingId: "git-credential-osxkeychain-55554944ee8c")))
        #expect(!reported(event(
            "/Library/Developer/CommandLineTools/usr/libexec/git-core/git-credential-osxkeychain",
            signer: .apple, teamId: CredentialFence.appleDeveloperToolsTeamId,
            signingId: "com.apple.git-credential-osxkeychain")))
        #expect(!reported(event(
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            signer: .devId, teamId: "EQHXZ8M8AV", signingId: "com.google.Chrome")))
        #expect(reported(event("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")))
        // No signature is an unknown identity, not an ad-hoc one.
        #expect(reported(event("/opt/homebrew/bin/git-credential-osxkeychain")))
        #expect(reported(event("/tmp/Google Chrome", signer: .devId, teamId: "ABCDE12345", signingId: "com.google.Chrome")))
        // Deployed honeyfiles have their own detector.
        var honey = event("/usr/bin/scp", signer: .apple, signingId: "com.apple.scp", platform: true)
        honey.enrichments["IsHoneyfile"] = "true"
        #expect(!reported(honey))
    }

    @Test("Keychain ownership needs the owner's identity; per-tool stores stay keyed by name")
    func keychainOwnershipNeedsIdentity() {
        let fence = CredentialFence()
        let keychain = "/Users/u/Library/Keychains/login.keychain-db"
        func flagged(_ binary: String, _ identity: CredentialFence.AccessorIdentity?, path: String = keychain) -> Bool {
            fence.checkAccessDetailed(filePath: path, aiToolName: "Claude Code",
                                      accessingBinary: binary, accessorIdentity: identity) != nil
        }
        let xcodeTeam = CredentialFence.appleDeveloperToolsTeamId
        let cp = CredentialFence.AccessorIdentity(isPlatformBinary: true, teamId: nil, signingId: "com.apple.cp")
        let homebrew = CredentialFence.AccessorIdentity(
            isPlatformBinary: false, teamId: nil, signingId: "git-credential-osxkeychain-55554944ee8c")
        let commandLineTools = CredentialFence.AccessorIdentity(
            isPlatformBinary: false, teamId: xcodeTeam, signingId: "com.apple.git-credential-osxkeychain")
        let otherXcodeTool = CredentialFence.AccessorIdentity(
            isPlatformBinary: false, teamId: xcodeTeam, signingId: "com.apple.git")
        let google = CredentialFence.AccessorIdentity(
            isPlatformBinary: false, teamId: "EQHXZ8M8AV", signingId: "com.google.Chrome")
        let brave = CredentialFence.AccessorIdentity(
            isPlatformBinary: false, teamId: "KL8N8XSYF4", signingId: "com.brave.Browser")
        #expect(flagged("git-credential-osxkeychain", cp))
        #expect(!flagged("git-credential-osxkeychain", homebrew))
        #expect(!flagged("git-credential-osxkeychain", commandLineTools))
        #expect(flagged("git-credential-osxkeychain", otherXcodeTool))
        #expect(flagged("git-credential-osxkeychain", nil))
        #expect(!flagged("Google Chrome", google))
        #expect(!flagged("Google Chrome Helper", google))
        #expect(flagged("Google Chrome", cp))
        #expect(flagged("Google Chrome", nil))
        #expect(flagged("Google Chrome", brave))
        #expect(!flagged("Brave Browser", brave))
        #expect(flagged("Brave Browser", google))
        #expect(flagged("gh", google))
        // The per-tool stores keep name keying, and are credential paths.
        let ghHosts = "/Users/u/.config/gh/hosts.yml"
        #expect(flagged("node", nil, path: ghHosts))
        #expect(!flagged("gh", nil, path: ghHosts))
        #expect(flagged("node", nil, path: "/Users/u/.netrc"))
        #expect(!flagged("git-credential-osxkeychain", nil, path: "/Users/u/.netrc"))
    }

    @Test("A signature still being re-verified keeps the identity the kernel reported")
    func collectorIdentityCoversPendingVerification() {
        let fence = CredentialFence()
        let xcodeTeam = CredentialFence.appleDeveloperToolsTeamId
        func collector(_ signingId: String) -> CodeSignatureInfo {
            CodeSignatureInfo(signerType: .apple, teamId: xcodeTeam, signingId: signingId,
                              authorities: [], flags: 0, isNotarized: false)
        }
        func finding(_ event: Event, _ collectorSignature: CodeSignatureInfo?) -> Bool {
            EventLoop.credentialFenceFinding(
                event: event, fence: fence, toolName: "Claude Code", toolType: .claudeCode,
                developmentEngine: false, collectorSignature: collectorSignature) != nil
        }
        // Enrichment withholds these team-signed Apple tools' signatures until
        // `anchor apple` re-verification lands; the event carries none.
        let helper = event("/Library/Developer/CommandLineTools/usr/libexec/git-core/git-credential-osxkeychain")
        #expect(!finding(helper, collector("com.apple.git-credential-osxkeychain")))
        let notarytool = event("/Applications/Xcode.app/Contents/Developer/usr/bin/notarytool")
        #expect(EventLoop.isCredentialFenceExempt(
            notarytool, developmentEngine: false, collectorSignature: collector("com.apple.gke.notary.tool")))
        #expect(!finding(notarytool, collector("com.apple.gke.notary.tool")))
        // The kernel's identifier still names what the binary really is.
        let copiedTool = event("/Applications/Xcode-x.app/Contents/Developer/usr/bin/security")
        #expect(!EventLoop.isCredentialFenceExempt(
            copiedTool, developmentEngine: false, collectorSignature: collector("com.apple.git")))
        #expect(finding(copiedTool, collector("com.apple.git")))
        #expect(finding(helper, collector("com.apple.git")))
        // With neither signature the identity is unknown, not ad-hoc.
        #expect(!EventLoop.isCredentialFenceExempt(notarytool, developmentEngine: false))
        #expect(finding(helper, nil))
        // A verified signature on the event wins over the collector's.
        let downgraded = event("/tmp/git-credential-osxkeychain", signer: .devId, teamId: "ABCDE12345",
                               signingId: "com.apple.git-credential-osxkeychain")
        #expect(finding(downgraded, collector("com.apple.git-credential-osxkeychain")))
    }

    @Test("An ad-hoc kernel signature never stands in for a withheld one")
    func adHocCollectorNeverStandsIn() {
        let fence = CredentialFence()
        // CS_VALID | CS_ADHOC: an ad-hoc code directory can carry any team.
        let forged = { (signingId: String) in
            CodeSignatureInfo(signerType: .apple, teamId: CredentialFence.appleDeveloperToolsTeamId,
                              signingId: signingId, authorities: [], flags: 0x3, isNotarized: false)
        }
        let stapler = event("/tmp/x/stapler")
        #expect(!EventLoop.isCredentialFenceExempt(
            stapler, developmentEngine: false, collectorSignature: forged("com.apple.stapler")))
        #expect(EventLoop.credentialFenceFinding(
            event: stapler, fence: fence, toolName: "Claude Code", toolType: .claudeCode,
            developmentEngine: false, collectorSignature: forged("com.apple.stapler")) != nil)
        let helper = event("/tmp/x/git-credential-osxkeychain")
        #expect(EventLoop.credentialFenceFinding(
            event: helper, fence: fence, toolName: "Claude Code", toolType: .claudeCode,
            developmentEngine: false, collectorSignature: forged("com.apple.git-credential-osxkeychain")) != nil)
    }

    @Test("Unverified, an Apple tool's exemption covers only the keychain")
    func unverifiedAppleToolExemptionIsKeychainOnly() {
        let fence = CredentialFence()
        let collector = CodeSignatureInfo(
            signerType: .apple, teamId: CredentialFence.appleDeveloperToolsTeamId,
            signingId: "com.apple.gke.notary.tool", authorities: [], flags: 0x1, isNotarized: false)
        let path = "/Applications/Xcode.app/Contents/Developer/usr/bin/notarytool"
        func finding(_ file: String) -> Bool {
            EventLoop.credentialFenceFinding(
                event: event(path, file: file), fence: fence, toolName: "Claude Code", toolType: .claudeCode,
                developmentEngine: false, collectorSignature: collector) != nil
        }
        #expect(!finding("/Users/u/Library/Keychains/login.keychain-db"))
        #expect(finding("/Users/u/.aws/credentials"))
        // Once verified, the exemption is not limited to the keychain.
        let verified = event(path, signer: .apple, teamId: CredentialFence.appleDeveloperToolsTeamId,
                             signingId: "com.apple.gke.notary.tool", file: "/Users/u/.aws/credentials")
        #expect(EventLoop.isCredentialFenceExempt(verified, developmentEngine: false, collectorSignature: collector))
    }

    @Test("A verdict that downgraded the claim wins over the kernel's signature")
    func verifiedDowngradeWins() {
        let fence = CredentialFence()
        let team = CredentialFence.appleDeveloperToolsTeamId
        func claim(_ signingId: String) -> CodeSignatureInfo {
            CodeSignatureInfo(signerType: .apple, teamId: team, signingId: signingId,
                              authorities: [], flags: 0x1, isNotarized: false)
        }
        // Enrichment keeps the kernel's team and identifier and lowers only the
        // signer, so a failed `anchor apple` check looks like this.
        let notarytool = event("/tmp/x/notarytool", signer: .devId, teamId: team,
                               signingId: "com.apple.gke.notary.tool")
        #expect(!EventLoop.isCredentialFenceExempt(
            notarytool, developmentEngine: false, collectorSignature: claim("com.apple.gke.notary.tool")))
        #expect(EventLoop.credentialFenceFinding(
            event: notarytool, fence: fence, toolName: "Claude Code", toolType: .claudeCode,
            developmentEngine: false, collectorSignature: claim("com.apple.gke.notary.tool")) != nil)
        // Keychain ownership judges team and identifier, not the signer, so the
        // git helper with the same shape still owns the keychain.
        let helper = event("/tmp/x/git-credential-osxkeychain", signer: .devId, teamId: team,
                           signingId: "com.apple.git-credential-osxkeychain")
        #expect(EventLoop.credentialFenceFinding(
            event: helper, fence: fence, toolName: "Claude Code", toolType: .claudeCode,
            developmentEngine: false, collectorSignature: claim("com.apple.git-credential-osxkeychain")) == nil)
    }

    @Test("A cold code-signing cache does not report Apple's git credential helper")
    func coldCacheGitHelperIsNotReported() async {
        let path = "/private/tmp/maccrab-identity-\(UUID().uuidString)/git-credential-osxkeychain"
        let signature = CodeSignatureInfo(
            signerType: .apple, teamId: CredentialFence.appleDeveloperToolsTeamId,
            signingId: "com.apple.git-credential-osxkeychain", flags: 0x1)
        let process = MacCrabCore.ProcessInfo(
            pid: 4243, ppid: 1, rpid: 1, name: "git-credential-osxkeychain",
            executable: path, commandLine: path, args: [path], workingDirectory: "/tmp",
            userId: 501, userName: "u", groupId: 20, startTime: Date(),
            codeSignature: signature, isPlatformBinary: false)
        let raw = Event(eventCategory: .file, eventType: .change, eventAction: "open",
                        process: process,
                        file: FileInfo(path: "/Users/u/Library/Keychains/login.keychain-db", action: .open))
        let enricher = EventEnricher(heavyEnrichmentPlane: HeavyEnrichmentPlane(
            configuration: .init(operationTimeoutSeconds: 30),
            liveMemoryBudget: .isolatedProductionEquivalentForTesting()
        ))
        let enriched = await enricher.enrich(raw)
        _ = await enricher.shutdownHeavyEnrichment()
        // The `.apple`, non-platform claim waits for re-verification, so the
        // enriched event carries no signature on a cache miss.
        #expect(enriched.process.codeSignature == nil)
        let fence = CredentialFence()
        #expect(EventLoop.credentialFenceFinding(
            event: enriched, fence: fence, toolName: "Claude Code", toolType: .claudeCode,
            developmentEngine: false, collectorSignature: raw.process.codeSignature) == nil)
    }

    @Test("Sparkle's exemption covers only the keychain it signs with")
    func sparkleExemptionIsKeychainOnly() {
        let fence = CredentialFence()
        let sparkle = "/Users/u/src/.build/artifacts/sparkle/Sparkle/bin/sign_update"
        func reported(_ file: String) -> Bool {
            EventLoop.credentialFenceFinding(
                event: event(sparkle, signer: .adHoc, signingId: "sign_update", file: file),
                fence: fence, toolName: "Claude Code", toolType: .claudeCode, developmentEngine: false) != nil
        }
        #expect(!reported("/Users/u/Library/Keychains/login.keychain-db"))
        #expect(reported("/Users/u/.aws/credentials"))
        #expect(reported("/Users/u/.ssh/id_ed25519"))
        #expect(!EventLoop.isCredentialFenceExempt(
            event(sparkle, signer: .adHoc, signingId: "sign_update", file: "/Users/u/.aws/credentials")))
    }

    @Test("scp and sftp reading a private key are reported; ssh reading it is not")
    func scpReadingSSHKeyIsReported() {
        let fence = CredentialFence()
        let key = "/Users/u/.ssh/id_ed25519"
        func reported(_ path: String, _ signingId: String) -> Bool {
            EventLoop.credentialFenceFinding(
                event: event(path, signer: .apple, signingId: signingId, platform: true, file: key),
                fence: fence, toolName: "Claude Code", toolType: .claudeCode, developmentEngine: false) != nil
        }
        #expect(reported("/usr/bin/scp", "com.apple.scp"))
        #expect(reported("/usr/bin/sftp", "com.apple.sftp"))
        #expect(!reported("/usr/bin/ssh", "com.apple.ssh"))
        #expect(!reported("/usr/bin/ssh-add", "com.apple.ssh-add"))
    }

    @Test("The lane keeps the collector's signature for the AI guards")
    func laneKeepsCollectorSignature() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let eventLoop = try String(
            contentsOf: root.appendingPathComponent("Sources/MacCrabAgentKit/EventLoop.swift"), encoding: .utf8)
        let capture = try #require(eventLoop.range(of: "let collectorSignature = event.process.codeSignature"))
        let enrich = try #require(eventLoop.range(of: "var enrichedEvent = await state.enricher.enrich(event)"))
        #expect(capture.lowerBound < enrich.lowerBound)
        // Passed into the guard and on into the fence decision.
        let call = try #require(eventLoop.range(of: "await enforceAIFilesystemGuards("))
        #expect(eventLoop[call.upperBound...].prefix { $0 != ")" }
            .contains("collectorSignature: collectorSignature"))
        let guardStart = try #require(eventLoop.range(of: "private static func enforceAIFilesystemGuards("))
        let finding = try #require(eventLoop.range(
            of: "credentialFenceFinding(", range: guardStart.upperBound..<eventLoop.endIndex))
        #expect(eventLoop[finding.upperBound...].prefix { $0 != ")" }
            .contains("collectorSignature: collectorSignature"))
    }
}
