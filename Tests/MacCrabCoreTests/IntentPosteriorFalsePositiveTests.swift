// IntentPosteriorFalsePositiveTests.swift
// MacCrabCoreTests
//
// v1.21.4 — regression tests for the intent-posterior false-positive
// fix. An on-device audit of the live rc.4 sysext found the
// `maccrab.intent.bayesian-posterior` alert firing HIGH on routine
// developer tooling (git, gh, rm, sed, touch, bsdtar). Root cause:
//
//   1. The tree key anchors on the ROOT ancestor (the long-lived login
//      shell / terminal session), so weak, individually-benign evidence
//      from many UNRELATED processes pools into one posterior, crosses
//      the ≥3-distinct + 0.85 gate, and — the posterior being sticky —
//      re-fires on every subsequent evidence-producing leaf, attributed
//      to whichever benign tool ran.
//   2. There was no actor-trust gate: routine dev-tool actions (git
//      checking out `.github/workflows/*`, `rm -rf ~/build`, bsdtar
//      extracting a package's `.npmrc`) were scored at full weight as
//      persistence / config / destructive evidence.
//
// Fix (IntentEvidenceClassifier.extract): discount the low-specificity,
// write-shaped / destructive evidence types for a PLATFORM-TRUSTED actor
// only, while keeping the high-signal evidence (credentialRead,
// nonRegistryEgress, …) that a real worm relies on — and keeping full
// evidence for UNTRUSTED (unsigned / ad-hoc) actors.
//
// These tests pin:
//   (a) each reported FP tool, as a SOLE trusted actor, no longer crosses
//       the alert gate (let alone HIGH);
//   (b) a real credential-read → data-exfiltration chain from an
//       untrusted payload STILL crosses the gate;
//   (c) the discount is trust-scoped: the SAME actions from an untrusted
//       actor still produce the discounted evidence (not a feature kill).

import Foundation
import Testing
@testable import MacCrabCore
@testable import MacCrabAgentKit

@Suite("v1.21.4: Intent-posterior false-positive fix")
struct IntentPosteriorFalsePositiveTests {

    // MARK: - Trust helpers

    private enum Trust {
        case platform          // Apple platform binary (git, rm, sed, touch, bsdtar)
        case devIdNotarized    // Homebrew Developer-ID + notarized (gh)
        case unsigned          // worm payload / unknown binary
    }

    private static func signature(for trust: Trust) -> (platform: Bool, cs: CodeSignatureInfo?) {
        switch trust {
        case .platform:
            return (true, nil)
        case .devIdNotarized:
            return (false, CodeSignatureInfo(signerType: .devId, teamId: "AB12CD34EF", isNotarized: true))
        case .unsigned:
            return (false, CodeSignatureInfo(signerType: .unsigned, isNotarized: false))
        }
    }

    private static func process(exe: String, cmd: String, trust: Trust) -> MacCrabCore.ProcessInfo {
        let (platform, cs) = signature(for: trust)
        return MacCrabCore.ProcessInfo(
            pid: 4242,
            ppid: 900,
            rpid: 900,
            name: (exe as NSString).lastPathComponent,
            executable: exe,
            commandLine: cmd,
            args: cmd.split(separator: " ").map(String.init),
            workingDirectory: "/Users/dev/repo",
            userId: 501,
            userName: "dev",
            groupId: 20,
            startTime: Date(),
            exitCode: nil,
            codeSignature: cs,
            ancestors: [ProcessAncestor(pid: 900, executable: "/bin/zsh", name: "zsh")],
            architecture: "arm64",
            isPlatformBinary: platform
        )
    }

    private static func procExec(exe: String, cmd: String, trust: Trust) -> Event {
        Event(
            eventCategory: .process, eventType: .creation, eventAction: "exec",
            process: process(exe: exe, cmd: cmd, trust: trust)
        )
    }

    private static func fileEvent(exe: String, action: String, path: String, trust: Trust) -> Event {
        Event(
            eventCategory: .file, eventType: .change, eventAction: action,
            process: process(exe: exe, cmd: exe, trust: trust),
            file: FileInfo(path: path, action: .write)
        )
    }

    private static func netConnect(exe: String, host: String, ip: String, trust: Trust) -> Event {
        let net = NetworkInfo(
            sourceIp: "192.168.1.20", sourcePort: 51000,
            destinationIp: ip, destinationPort: 443,
            destinationHostname: host,
            direction: .outbound, transport: "tcp"
        )
        return Event(
            eventCategory: .network, eventType: .connection, eventAction: "connect",
            process: process(exe: exe, cmd: exe, trust: trust),
            network: net
        )
    }

    /// Mirrors the EventLoop alert gate (default thresholds: 0.85 top
    /// probability + 3 distinct evidence types + a non-benign top goal).
    /// Crossing this is what produces a `maccrab.intent.bayesian-posterior`
    /// alert at all; HIGH severity (≥0.95) is strictly stronger.
    private static func crossesAlertGate(_ p: BayesianIntentEngine.Posterior) -> Bool {
        p.topGoal != .benign && p.topProbability >= 0.85 && p.distinctEvidenceCount >= 3
    }

    /// Feed a batch of events (optionally repeated to simulate sustained
    /// routine use) through extract() + observe() under a single tree key,
    /// returning the final posterior — or nil if no evidence ever landed.
    private static func drive(_ events: [Event], repeatCount: Int = 5, treeKey: String) async -> BayesianIntentEngine.Posterior? {
        let engine = BayesianIntentEngine()
        var last: BayesianIntentEngine.Posterior?
        for _ in 0..<repeatCount {
            for e in events {
                for ev in IntentEvidenceClassifier.extract(e) {
                    last = await engine.observe(ev, treeKey: treeKey)
                }
            }
        }
        return last
    }

    // MARK: - (a) Reported FP tools, as sole trusted actor, do not cross

    @Test("git (platform) clone/checkout/push as sole actor never crosses the intent gate")
    func gitSoleActorNoCross() async {
        // git checkout writes a repo's workflows + .npmrc, then pushes to
        // github — raw evidence: workflowWrite + configFileTampered +
        // nonRegistryEgress. The two write-shaped ones are trust-discounted.
        let events = [
            Self.fileEvent(exe: "/usr/bin/git", action: "create", path: "/Users/dev/repo/.github/workflows/ci.yml", trust: .platform),
            Self.fileEvent(exe: "/usr/bin/git", action: "write", path: "/Users/dev/repo/.npmrc", trust: .platform),
            Self.netConnect(exe: "/usr/bin/git", host: "github.com", ip: "140.82.112.3", trust: .platform),
        ]
        // Extraction drops the discounted evidence for the trusted actor.
        #expect(!IntentEvidenceClassifier.extract(events[0]).contains(.workflowWrite))
        #expect(!IntentEvidenceClassifier.extract(events[1]).contains(.configFileTampered))
        // The egress signal is KEPT (a real worm needs it) — but one
        // distinct type can never satisfy the ≥3 floor.
        #expect(IntentEvidenceClassifier.extract(events[2]) == [.nonRegistryEgress])

        let posterior = await Self.drive(events, treeKey: "/usr/bin/git@4242")
        if let p = posterior {
            #expect(!Self.crossesAlertGate(p), "git sole-actor crossed the intent gate: \(p.topGoal) p=\(p.topProbability) distinct=\(p.distinctEvidenceCount)")
            #expect(p.distinctEvidenceCount < 3)
        }
    }

    @Test("gh (Developer-ID notarized) as sole actor never crosses the intent gate")
    func ghSoleActorNoCross() async {
        // gh reads its own config (a credential-shaped path) and talks to
        // the GitHub API. credentialRead + nonRegistryEgress are KEPT even
        // for a trusted actor, but that is only 2 distinct types.
        let events = [
            Self.fileEvent(exe: "/opt/homebrew/bin/gh", action: "read", path: "/Users/dev/.config/gh/hosts.yml", trust: .devIdNotarized),
            Self.netConnect(exe: "/opt/homebrew/bin/gh", host: "api.github.com", ip: "140.82.113.5", trust: .devIdNotarized),
        ]
        #expect(IntentEvidenceClassifier.extract(events[0]) == [.credentialRead])
        #expect(IntentEvidenceClassifier.extract(events[1]) == [.nonRegistryEgress])

        let posterior = await Self.drive(events, treeKey: "/opt/homebrew/bin/gh@4242")
        if let p = posterior {
            #expect(!Self.crossesAlertGate(p))
            #expect(p.distinctEvidenceCount < 3)
        }
    }

    @Test("rm -rf of a build/cache dir (platform) as sole actor never crosses the intent gate")
    func rmSoleActorNoCross() async {
        let events = [
            Self.procExec(exe: "/bin/rm", cmd: "rm -rf /Users/dev/repo/build", trust: .platform),
            Self.procExec(exe: "/bin/rm", cmd: "rm -rf ~/Library/Caches/dev", trust: .platform),
        ]
        // destructiveCmd is discounted for a trusted actor.
        #expect(IntentEvidenceClassifier.extract(events[0]).isEmpty)
        #expect(IntentEvidenceClassifier.extract(events[1]).isEmpty)

        let posterior = await Self.drive(events, treeKey: "/bin/rm@4242")
        #expect(posterior == nil, "trusted rm should emit no intent evidence at all")
    }

    @Test("sed rewriting a dotfile (platform) as sole actor never crosses the intent gate")
    func sedSoleActorNoCross() async {
        let events = [
            // sed is a "readlike" name; a credential-shaped arg yields
            // credentialRead (KEPT). The rc-file write yields shellRcWrite
            // (discounted).
            Self.procExec(exe: "/usr/bin/sed", cmd: "sed -i s/foo/bar/ /Users/dev/.gitconfig", trust: .platform),
            Self.fileEvent(exe: "/usr/bin/sed", action: "write", path: "/Users/dev/.zshrc", trust: .platform),
        ]
        #expect(IntentEvidenceClassifier.extract(events[0]) == [.credentialRead])
        #expect(IntentEvidenceClassifier.extract(events[1]).isEmpty)

        let posterior = await Self.drive(events, treeKey: "/usr/bin/sed@4242")
        if let p = posterior {
            #expect(!Self.crossesAlertGate(p))
            #expect(p.distinctEvidenceCount < 3)
        }
    }

    @Test("touch creating a LaunchAgent plist (platform) as sole actor never crosses the intent gate")
    func touchSoleActorNoCross() async {
        let events = [
            Self.fileEvent(exe: "/usr/bin/touch", action: "create", path: "/Users/dev/Library/LaunchAgents/com.dev.helper.plist", trust: .platform),
        ]
        #expect(IntentEvidenceClassifier.extract(events[0]).isEmpty)

        let posterior = await Self.drive(events, treeKey: "/usr/bin/touch@4242")
        #expect(posterior == nil)
    }

    @Test("bsdtar extracting a package (platform) as sole actor never crosses the intent gate")
    func bsdtarSoleActorNoCross() async {
        // npm/tar extraction of a package that happens to ship workflow,
        // npmrc and plist files — all write-shaped, all discounted.
        let events = [
            Self.fileEvent(exe: "/usr/bin/bsdtar", action: "create", path: "/Users/dev/node_modules/pkg/.github/workflows/x.yml", trust: .platform),
            Self.fileEvent(exe: "/usr/bin/bsdtar", action: "create", path: "/Users/dev/node_modules/pkg/.npmrc", trust: .platform),
            Self.fileEvent(exe: "/usr/bin/bsdtar", action: "create", path: "/Users/dev/Library/LaunchAgents/pkg.plist", trust: .platform),
        ]
        for e in events { #expect(IntentEvidenceClassifier.extract(e).isEmpty) }

        let posterior = await Self.drive(events, treeKey: "/usr/bin/bsdtar@4242")
        #expect(posterior == nil)
    }

    // MARK: - (b) A real credential-read → exfil chain still fires

    @Test("Untrusted worm: credential read + config tamper + repeated exfil STILL crosses HIGH")
    func untrustedExfilChainStillFires() async throws {
        // A dropped, unsigned payload steals credentials, tampers a package
        // config to self-propagate, and beacons stolen data to a webhook.
        // None of this evidence is discounted (actor is untrusted), and the
        // repeated egress concentrates the posterior on exfiltration well
        // past the gate. Pins current LikelihoodTable tuning — if that is
        // retuned, revisit this expectation deliberately.
        let payload = "/private/tmp/npm-x/postinstall.js"
        var events: [Event] = [
            Self.fileEvent(exe: payload, action: "read", path: "/Users/dev/.aws/credentials", trust: .unsigned),
            Self.fileEvent(exe: payload, action: "write", path: "/Users/dev/repo/.npmrc", trust: .unsigned),
        ]
        for _ in 0..<6 {
            events.append(Self.netConnect(exe: payload, host: "exfil.evil-webhook.example", ip: "203.0.113.7", trust: .unsigned))
        }
        // Evidence is fully retained for the untrusted actor.
        #expect(IntentEvidenceClassifier.extract(events[0]) == [.credentialRead])
        #expect(IntentEvidenceClassifier.extract(events[1]) == [.configFileTampered])
        #expect(IntentEvidenceClassifier.extract(events[2]) == [.nonRegistryEgress])

        let posterior = await Self.drive(events, repeatCount: 1, treeKey: payload + "@4242")
        let p = try #require(posterior)
        #expect(Self.crossesAlertGate(p), "real exfil chain failed to cross: \(p.topGoal) p=\(p.topProbability) distinct=\(p.distinctEvidenceCount)")
        #expect(p.topGoal == .exfiltration || p.topGoal == .credentialHarvest)
        #expect(p.distinctEvidenceCount >= 3)
        #expect(p.topProbability >= 0.85)
    }

    @Test("Untrusted worm reaches HIGH severity (>=0.95)")
    func untrustedExfilChainReachesHigh() async throws {
        // Same shape with more beacons: a genuine campaign should reach the
        // HIGH (≥0.95) severity band, not just the medium alert floor.
        let payload = "/private/tmp/npm-x/postinstall.js"
        var events: [Event] = [
            Self.fileEvent(exe: payload, action: "read", path: "/Users/dev/.aws/credentials", trust: .unsigned),
            Self.fileEvent(exe: payload, action: "write", path: "/Users/dev/repo/.npmrc", trust: .unsigned),
        ]
        for _ in 0..<10 {
            events.append(Self.netConnect(exe: payload, host: "exfil.evil-webhook.example", ip: "203.0.113.7", trust: .unsigned))
        }
        let p = try #require(await Self.drive(events, repeatCount: 1, treeKey: payload + "@hi"))
        #expect(p.topProbability >= 0.95)
    }

    // MARK: - (c) The discount is trust-scoped, not a feature kill

    @Test("The SAME dev-tool actions from an UNTRUSTED actor still produce full evidence")
    func untrustedActorEvidenceNotDiscounted() async {
        // Identical git-shape write actions, but performed by an unsigned
        // binary masquerading as git — every discounted type is retained.
        let workflow = Self.fileEvent(exe: "/private/tmp/evil/git", action: "create", path: "/Users/dev/repo/.github/workflows/ci.yml", trust: .unsigned)
        let npmrc = Self.fileEvent(exe: "/private/tmp/evil/git", action: "write", path: "/Users/dev/repo/.npmrc", trust: .unsigned)
        let rm = Self.procExec(exe: "/private/tmp/evil/rm", cmd: "rm -rf /Users/dev/data", trust: .unsigned)
        let plist = Self.fileEvent(exe: "/private/tmp/evil/touch", action: "create", path: "/Users/dev/Library/LaunchAgents/com.evil.plist", trust: .unsigned)

        #expect(IntentEvidenceClassifier.extract(workflow) == [.workflowWrite])
        #expect(IntentEvidenceClassifier.extract(npmrc) == [.configFileTampered])
        #expect(IntentEvidenceClassifier.extract(rm) == [.destructiveCmd])
        #expect(IntentEvidenceClassifier.extract(plist) == [.launchAgentWrite])
    }

    @Test("isTrustedPlatformActor classifies signer classes correctly")
    func trustClassification() {
        #expect(IntentEvidenceClassifier.isTrustedPlatformActor(
            Self.procExec(exe: "/usr/bin/git", cmd: "git status", trust: .platform)))
        #expect(IntentEvidenceClassifier.isTrustedPlatformActor(
            Self.procExec(exe: "/opt/homebrew/bin/gh", cmd: "gh pr list", trust: .devIdNotarized)))
        #expect(!IntentEvidenceClassifier.isTrustedPlatformActor(
            Self.procExec(exe: "/private/tmp/evil/x", cmd: "x", trust: .unsigned)))
        // An un-notarized Developer-ID binary is NOT trusted here.
        let unnotarized = Event(
            eventCategory: .process, eventType: .creation, eventAction: "exec",
            process: MacCrabCore.ProcessInfo(
                pid: 1, ppid: 0, rpid: 0, name: "x", executable: "/tmp/x", commandLine: "x",
                args: ["x"], workingDirectory: "/", userId: 501, userName: "dev", groupId: 20,
                startTime: Date(), codeSignature: CodeSignatureInfo(signerType: .devId, teamId: "T", isNotarized: false),
                isPlatformBinary: false
            )
        )
        #expect(!IntentEvidenceClassifier.isTrustedPlatformActor(unnotarized))
    }
}
