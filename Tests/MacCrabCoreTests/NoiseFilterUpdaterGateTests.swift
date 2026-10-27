import Foundation
import Testing
@testable import MacCrabCore

/// Gate 6 quiets the auto-updater trees that legitimately span tactics. Its
/// markers name where each vendor installs, a location the user can write
/// also needs the vendor's signature on the subject, an ancestor counts only
/// from a root-owned location, and a credential read is never quieted.
@Suite("NoiseFilter: auto-updater gate anchoring")
struct NoiseFilterUpdaterGateTests {
    private static let systemUpdater =
        "/Library/Application Support/Google/GoogleUpdater/148.0/GoogleUpdater.app/Contents/MacOS/GoogleUpdater"
    private static let userUpdater =
        "/Users/u/Library/Application Support/Google/GoogleUpdater/148.0/GoogleUpdater.app/Contents/MacOS/GoogleUpdater"

    private func match(_ id: String, severity: Severity, techniques: [String] = []) -> RuleMatch {
        RuleMatch(ruleId: id, ruleName: id, severity: severity, description: "",
                  mitreTechniques: techniques, tags: [], suppressible: true)
    }

    private func event(
        _ path: String,
        signer: SignerType? = nil,
        teamId: String? = nil,
        flags: UInt32 = 0,
        ancestors: [ProcessAncestor] = []
    ) -> Event {
        let signature = signer.map {
            CodeSignatureInfo(signerType: $0, teamId: teamId, signingId: nil, authorities: [],
                              flags: flags, isNotarized: false)
        }
        let process = MacCrabCore.ProcessInfo(
            pid: 4242, ppid: ancestors.first?.pid ?? 1, rpid: 1,
            name: (path as NSString).lastPathComponent, executable: path,
            commandLine: path, args: [path], workingDirectory: "/",
            userId: 501, userName: "u", groupId: 20, startTime: Date(),
            codeSignature: signature, ancestors: ancestors,
            architecture: "arm64", isPlatformBinary: false)
        return Event(eventCategory: .process, eventType: .start, eventAction: "exec", process: process)
    }

    @Test("updater markers match the vendors' install locations, not any path containing the name")
    func markersAreAnchored() {
        for path in [
            Self.systemUpdater,
            "/Library/Google/GoogleSoftwareUpdate/GoogleSoftwareUpdate.bundle/Contents/MacOS/ksinstall",
            Self.userUpdater,
            "/Users/u/Library/Google/GoogleSoftwareUpdate/GoogleSoftwareUpdate.bundle/Contents/MacOS/ksfetch",
            "/Users/u/Library/Caches/com.google.Keystone/Installer/x",
            "/Library/Application Support/Microsoft/MAU2.0/Microsoft AutoUpdate.app/Contents/MacOS/Microsoft Update Assistant",
            "/Users/u/Library/Caches/com.example.app/org.sparkle-project.Sparkle/Installation/AbCd/Autoupdate",
            "/Applications/Example.app/Contents/Frameworks/Sparkle.framework/Versions/B/Autoupdate",
            "/Users/u/Applications/Example.app/Contents/Frameworks/Sparkle.framework/Versions/B/Autoupdate",
            "/System/Library/PrivateFrameworks/SoftwareUpdate.framework/Versions/A/Resources/softwareupdated",
            "/opt/homebrew/bin/brew",
            "/opt/homebrew/Library/Homebrew/brew.rb",
        ] {
            #expect(CampaignDetector.isAutoUpdater(processPath: path), "\(path)")
        }
        for path in [
            "/Users/u/Library/GoogleUpdater/zsh",
            "/tmp/GoogleUpdater/x",
            "/Users/u/GoogleUpdater/GoogleUpdater.app/Contents/MacOS/GoogleUpdater",
            "/Users/Library/Application Support/Google/GoogleUpdater/x",
            "/tmp/Microsoft AutoUpdate",
            "/Users/u/Microsoft AutoUpdate.app/Contents/MacOS/x",
            "/tmp/Sparkle.framework/Versions/B/Autoupdate",
            "/tmp/org.sparkle-project.Sparkle/Installation/x/Autoupdate",
            "/Users/u/Library/Caches/com.google.Keystone-x/y",
            "/tmp/softwareupdated",
            "/tmp/Homebrew/Library/Homebrew/x",
        ] {
            #expect(!CampaignDetector.isAutoUpdater(processPath: path), "\(path)")
        }
    }

    @Test("a user-writable updater location needs the vendor's signature on the subject")
    func userLocationNeedsVendorSignature() {
        let noise = [match("mdm_enrollment_check", severity: .medium)]
        var signed = noise
        NoiseFilter.apply(&signed, event: event(Self.userUpdater, signer: .devId, teamId: "EQHXZ8M8AV", flags: 0x1),
                          isWarmingUp: false)
        #expect(signed.isEmpty, "the vendor-signed updater in the user's Library is quieted")
        var unsigned = noise
        NoiseFilter.apply(&unsigned, event: event(Self.userUpdater), isWarmingUp: false)
        #expect(unsigned.count == 1, "an unsigned binary placed at the updater's path is not")
        var adHoc = noise
        NoiseFilter.apply(&adHoc, event: event(Self.userUpdater, signer: .adHoc, teamId: "EQHXZ8M8AV", flags: 0x3),
                          isWarmingUp: false)
        #expect(adHoc.count == 1, "an ad-hoc signature naming the vendor's team is not the vendor")
        var system = noise
        NoiseFilter.apply(&system, event: event(Self.systemUpdater), isWarmingUp: false)
        #expect(system.isEmpty, "only an administrator writes the system Library")
    }

    @Test("an ancestor quiets the tree only from a root-owned updater location")
    func ancestorsCountOnlyWhenRootAnchored() {
        let noise = [match("mdm_enrollment_check", severity: .medium)]
        var underUser = noise
        NoiseFilter.apply(&underUser, event: event("/tmp/stealer", ancestors: [
            ProcessAncestor(pid: 7001, executable: Self.userUpdater, name: "GoogleUpdater"),
        ]), isWarmingUp: false)
        #expect(underUser.count == 1, "a chain carries paths, not signatures; the user's Library is theirs to write")
        var underPlanted = noise
        NoiseFilter.apply(&underPlanted, event: event("/tmp/stealer", ancestors: [
            ProcessAncestor(pid: 7002, executable: "/Users/u/Library/GoogleUpdater/zsh", name: "zsh"),
        ]), isWarmingUp: false)
        #expect(underPlanted.count == 1)
        var underSystem = noise
        NoiseFilter.apply(&underSystem, event: event("/tmp/helper", ancestors: [
            ProcessAncestor(pid: 7003, executable: Self.systemUpdater, name: "GoogleUpdater"),
        ]), isWarmingUp: false)
        #expect(underSystem.isEmpty)
    }

    @Test("a credential read is never quieted by the updater gate")
    func credentialReadSurvives() {
        var matches = [
            match("keychain_file_accessed", severity: .high, techniques: ["attack.t1555.001"]),
            match("ssh_private_key_read", severity: .high, techniques: ["attack.t1552.004"]),
            match("mdm_enrollment_check", severity: .medium),
        ]
        NoiseFilter.apply(&matches, event: event("/tmp/helper", ancestors: [
            ProcessAncestor(pid: 7003, executable: Self.systemUpdater, name: "GoogleUpdater"),
        ]), isWarmingUp: false)
        #expect(matches.map(\.ruleId) == ["keychain_file_accessed", "ssh_private_key_read"])
        var subject = [match("keychain_file_accessed", severity: .high, techniques: ["attack.t1555.001"])]
        NoiseFilter.apply(&subject, event: event(Self.systemUpdater), isWarmingUp: false)
        #expect(subject.count == 1)
    }
}
