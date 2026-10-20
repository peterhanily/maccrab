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
        platform: Bool = false
    ) -> Event {
        let signature = signer.map {
            CodeSignatureInfo(signerType: $0, teamId: teamId, signingId: nil,
                              authorities: [], flags: 0, isNotarized: false)
        }
        let process = MacCrabCore.ProcessInfo(
            pid: 4242, ppid: 1, rpid: 1, name: (path as NSString).lastPathComponent,
            executable: path, commandLine: path, args: [path], workingDirectory: "/tmp",
            userId: 501, userName: "u", groupId: 20, startTime: Date(),
            codeSignature: signature, isPlatformBinary: platform)
        return Event(eventCategory: .file, eventType: .change, eventAction: "write",
                     process: process,
                     file: FileInfo(path: "/Users/u/Library/Keychains/login.keychain-db", action: .write))
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

    @Test("CredentialFence exempts Apple tools only where Apple installs them, and MacCrab's only when signed")
    func credentialFenceExemptionNeedsIdentity() {
        #expect(EventLoop.isCredentialFenceExempt(event("/usr/bin/security", signer: .apple, platform: true)))
        #expect(EventLoop.isCredentialFenceExempt(event("/usr/bin/codesign", platform: true)))
        #expect(EventLoop.isCredentialFenceExempt(event(
            "/Applications/Xcode.app/Contents/Developer/usr/bin/notarytool", signer: .apple)))
        #expect(EventLoop.isCredentialFenceExempt(event(
            "/Library/Developer/CommandLineTools/usr/bin/notarytool")), "signature still pending")
        // A renamed copy of /bin/cp is still a platform binary by cdhash.
        #expect(!EventLoop.isCredentialFenceExempt(event("/tmp/security", signer: .apple, platform: true)))
        #expect(!EventLoop.isCredentialFenceExempt(event("/Users/u/bin/codesign", signer: .adHoc)))
        #expect(!EventLoop.isCredentialFenceExempt(event(
            "/Library/Developer/CommandLineTools/usr/bin/notarytool", signer: .devId, teamId: "ABCDE12345")))
        #expect(!EventLoop.isCredentialFenceExempt(event("/Users/u/maccrabd"), developmentEngine: false))
        #expect(EventLoop.isCredentialFenceExempt(event(
            "/Applications/MacCrab.app/Contents/Resources/bin/maccrabctl",
            signer: .devId, teamId: NoiseFilter.macCrabTeamId), developmentEngine: false))
        #expect(EventLoop.isCredentialFenceExempt(event("/Users/u/src/.build/artifacts/sparkle/Sparkle/bin/sign_update")))
        #expect(!EventLoop.isCredentialFenceExempt(event("/usr/bin/cp", platform: true)))
    }
}
