// KillChainFireTests.swift
// v1.21.5-rc.3 — locks mother-of-all-audits finding #10: the stable/must-fire
// kill-chain SEQUENCE rules were promoted to `status: stable` with NO genuine
// true-positive fire-test — check-promotion.sh's tp-trigger only checked that
// the rule id/title appeared SOMEWHERE in Tests/ or the red-team scripts, so a
// comment mention passed the gate. These tests drive each rule's real TP event
// sequence through the REAL SequenceEngine (loading the real compiled rules) and
// assert it fires. They double as the promotion evidence check-promotion.sh now
// requires (a Tests/ file that asserts `ruleId == "<id>"` under SequenceEngine).
//
// Lineage: most steps declare `process: descendant` of the initial step, so the
// later event's process must be an actual DESCENDANT (not the same pid). The
// tests register a real process tree — 100 ← 1, 101 ← 100 — so the initial step
// runs as pid 100 and descendant steps as pid 101 (a child of 100). Steps with a
// `.same` relation reuse pid 100.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("Phase 3 (10): kill-chain sequence true-positive fire-tests")
struct KillChainFireTests {

    private let seqDir = "/tmp/maccrab_v3/sequences"
    private let base = Date(timeIntervalSince1970: 1_700_000_000)
    private let rootPid: Int32 = 100      // initial step
    private let childPid: Int32 = 101     // descendant steps

    // MARK: - Event builders

    private func procInfo(pid: Int32, exec: String, cmd: String?, parent: String?, signer: SignerType?) -> MacCrabCore.ProcessInfo {
        let ancestors = parent.map {
            [ProcessAncestor(pid: pid - 1, executable: $0, name: ($0 as NSString).lastPathComponent)]
        } ?? []
        let sig = signer.map {
            CodeSignatureInfo(signerType: $0, teamId: nil, signingId: nil, authorities: [],
                              flags: 0, isNotarized: false, issuerChain: nil, certHashes: nil,
                              isAdhocSigned: nil, entitlements: nil)
        }
        return MacCrabCore.ProcessInfo(
            pid: pid, ppid: pid == childPid ? rootPid : 1, rpid: 1,
            name: (exec as NSString).lastPathComponent,
            executable: exec, commandLine: cmd ?? exec, args: [exec], workingDirectory: "/tmp",
            userId: 501, userName: "t", groupId: 20, startTime: base, codeSignature: sig,
            ancestors: ancestors, architecture: "arm64", isPlatformBinary: false)
    }

    private func proc(_ exec: String, pid: Int32? = nil, cmd: String? = nil, parent: String? = nil,
                      parentCmd: String? = nil, signer: SignerType? = nil, at offset: TimeInterval) -> Event {
        // process.parent.commandline resolves from the enrichments dict (there is
        // no ParentCommandLine field on the event itself).
        let enrich = parentCmd.map { ["parent.commandline": $0] } ?? [:]
        return Event(timestamp: base.addingTimeInterval(offset), eventCategory: .process,
              eventType: .start, eventAction: "exec",
              process: procInfo(pid: pid ?? rootPid, exec: exec, cmd: cmd, parent: parent, signer: signer),
              enrichments: enrich)
    }

    private func file(_ path: String, pid: Int32? = nil, action: FileAction = .write,
                      actor: String = "/tmp/child", at offset: TimeInterval) -> Event {
        Event(timestamp: base.addingTimeInterval(offset), eventCategory: .file,
              eventType: .creation, eventAction: "file",
              process: procInfo(pid: pid ?? childPid, exec: actor, cmd: nil, parent: nil, signer: nil),
              file: FileInfo(path: path, action: action))
    }

    private func net(pid: Int32? = nil, destIp: String = "93.184.216.34", hostname: String? = nil,
                     actor: String = "/tmp/child", at offset: TimeInterval) -> Event {
        Event(timestamp: base.addingTimeInterval(offset), eventCategory: .network,
              eventType: .creation, eventAction: "connect",
              process: procInfo(pid: pid ?? childPid, exec: actor, cmd: nil, parent: nil, signer: nil),
              network: NetworkInfo(sourceIp: "10.0.0.2", sourcePort: 51000,
                                   destinationIp: destIp, destinationPort: 443,
                                   destinationHostname: hostname, direction: .outbound, transport: "tcp"))
    }

    /// Loads the real compiled sequence rules against a lineage where pid 101 is a
    /// child of pid 100, then returns whether `ruleId` completes across the stream.
    private func fires(_ ruleId: String, _ events: [Event]) async throws -> Bool {
        ensureRulesCompiled()
        let lineage = ProcessLineage()
        await lineage.recordProcess(pid: rootPid, ppid: 1, path: "/bin/root", name: "root", startTime: base)
        await lineage.recordProcess(pid: childPid, ppid: rootPid, path: "/tmp/child", name: "child", startTime: base)
        let engine = SequenceEngine(lineage: lineage)
        _ = try await engine.loadRules(from: URL(fileURLWithPath: seqDir),
                                       enabledStatuses: ["stable", "experimental"])
        var fired = false
        for ev in events {
            let matches = await engine.evaluate(ev)
            if matches.contains(where: { $0.ruleId == ruleId }) { fired = true }
        }
        return fired
    }

    // MARK: - The kill chains

    @Test("reverse_shell_chain fires: non-terminal shell → outbound public connection")
    func reverseShellChain() async throws {
        // connect is `.same` as shell → reuse pid 100.
        #expect(try await fires("e1f2a3b4-0007-4000-b000-000000000007", [
            proc("/bin/bash", at: 0),
            net(pid: rootPid, at: 1),
        ]))
    }

    @Test("quarantine_remove_execute fires: xattr strip → run unsigned Downloads binary")
    func quarantineRemoveExecute() async throws {
        #expect(try await fires("e1f2a3b4-0006-4000-b000-000000000006", [
            proc("/usr/bin/xattr", cmd: "xattr -d com.apple.quarantine /Users/t/Downloads/app", at: 0),
            proc("/Users/t/Downloads/evilapp", pid: childPid, signer: nil, at: 1),
        ]))
    }

    @Test("ransomware_kill_chain fires: curl-spawned shell → tmutil disable → dd wipe")
    func ransomwareKillChain() async throws {
        #expect(try await fires("e1f2a3b4-0016-4000-b000-000000000016", [
            proc("/bin/bash", parent: "/usr/bin/curl", at: 0),
            proc("/usr/bin/tmutil", pid: childPid, cmd: "tmutil disable", at: 1),
            proc("/bin/dd", pid: childPid, cmd: "dd if=/dev/zero of=/Users/t/vault", at: 2),
        ]))
    }

    @Test("defense_evasion_kill_persist fires: kill a security tool → drop a LaunchAgent")
    func defenseEvasionKillPersist() async throws {
        #expect(try await fires("e1f2a3b4-0011-4000-b000-000000000011", [
            proc("/bin/kill", cmd: "kill -9 LuLu", at: 0),
            file("/Users/t/Library/LaunchAgents/evil.plist", at: 1),
        ]))
    }

    @Test("npm_postinstall_to_rat fires: npm-spawned shell → drop payload → C2 callback")
    func npmPostinstallToRat() async throws {
        #expect(try await fires("e1f2a3b4-0020-4000-b000-000000000020", [
            proc("/bin/sh", parent: "/usr/local/bin/npm", at: 0),
            file("/tmp/rat", actor: "/bin/sh", at: 1),
            net(at: 2),
        ]))
    }

    @Test("npm RAT rule does not journal unrelated compiler temp traffic")
    func npmRatIgnoresCompilerTempTraffic() async throws {
        ensureRulesCompiled()
        let engine = SequenceEngine(lineage: ProcessLineage())
        _ = try await engine.loadRules(
            from: URL(fileURLWithPath: seqDir),
            enabledStatuses: ["stable", "experimental"]
        )
        let ruleID = "e1f2a3b4-0020-4000-b000-000000000020"
        for index in 0..<2_048 {
            _ = await engine.evaluate(file(
                "/private/tmp/swift-build-\(index).o",
                actor: "/usr/bin/swift-frontend",
                at: TimeInterval(index) / 1_000
            ))
        }
        let ledger = await engine.pendingStepConservationByRule()[ruleID]
        #expect((ledger?.offered ?? 0) == 0)
        #expect((ledger?.queued ?? 0) == 0)
        #expect((ledger?.explicitlyShed ?? 0) == 0)
        #expect(await engine.pendingStepsEvictedTotal == 0)
    }

    @Test("pip_install_to_credential_harvest fires: pip install → read ~/.ssh key")
    func pipInstallToCredentialHarvest() async throws {
        #expect(try await fires("e1f2a3b4-0021-4000-b000-000000000021", [
            proc("/usr/bin/pip3", cmd: "pip3 install requests", at: 0),
            file("/Users/t/.ssh/id_rsa", action: .open, at: 1),
        ]))
    }

    @Test("package_typosquat_full_chain fires: pkg INSTALL → non-pkgmgr callhome → persist (#9 re-indent)")
    func packageTyposquatFullChain() async throws {
        #expect(try await fires("e1f2a3b4-0032-4000-b000-000000000032", [
            proc("/usr/local/bin/npm", cmd: "npm install evil-pkg", at: 0),
            net(actor: "/tmp/payload", at: 1),                 // NOT a package manager (filter_pkg_managers)
            file("/Users/t/Library/LaunchAgents/typo.plist", action: .write, at: 2),
        ]))
    }

    @Test("supply_chain_full_kill_chain fires: package install → persist → exfil")
    func supplyChainFullKillChain() async throws {
        #expect(try await fires("e1f2a3b4-0023-4000-b000-000000000023", [
            proc("/usr/local/bin/npm", cmd: "npm install evil", at: 0),
            file("/Users/t/Library/LaunchAgents/sc.plist", at: 1),
            net(at: 2),
        ]))
    }

    @Test("worm_self_propagation_signal fires: pkg-mgr descendant → cred read → registry egress")
    func wormSelfPropagationSignal() async throws {
        #expect(try await fires("e1f2a3b4-0040-4000-b000-000000000040", [
            proc("/tmp/stage", parent: "/usr/local/bin/npm", at: 0),
            file("/Users/t/.aws/credentials", action: .open, at: 1),   // credential read is NOTIFY_OPEN
            net(hostname: "registry.npmjs.org", at: 2),
        ]))
    }

    @Test("npm_module_require_then_bulk_credential_read fires: node in node_modules → cred read")
    func npmModuleRequireBulkCred() async throws {
        #expect(try await fires("9c2d052b-a8ce-43fc-a1a9-5ee9c86f0682", [
            proc("/usr/local/bin/node", cmd: "node /app/node_modules/evil/index.js", at: 0),
            file("/Users/t/.aws/credentials", action: .open, at: 1),   // credential read is NOTIFY_OPEN
        ]))
    }

    @Test("gh_token_revocation_polling_loop fires: npm-spawned runtime → api.github.com poll")
    func ghTokenRevocationPollingLoop() async throws {
        #expect(try await fires("14b34c1b-0487-4cdf-b11d-f37a3591c791", [
            proc("/usr/local/bin/node", parent: "/usr/local/bin/npm",
                 parentCmd: "npm install evil-pkg", at: 0),   // install_spawn wants parent cmdline "install"
            net(hostname: "api.github.com", at: 1),
        ]))
    }
}
