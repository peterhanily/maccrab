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

// Serialized: two capacity cases drive a full 8,192-entry pending table.
@Suite("Phase 3 (10): kill-chain sequence true-positive fire-tests", .serialized)
struct KillChainFireTests {

    private let seqDir = compiledRulesDirectory.appendingPathComponent("sequences").path
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
        try ensureRulesCompiled()
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

    private let npmRat = "e1f2a3b4-0020-4000-b000-000000000020"
    private let supplyChain = "e1f2a3b4-0023-4000-b000-000000000023"
    private let worm = "e1f2a3b4-0040-4000-b000-000000000040"

    /// The default (stable) profile over the same lineage as fires(_:_:).
    /// The periodic sweep runs only once an hour, so a slow debug run cannot
    /// retire history mid-test.
    private func stableEngine() async throws -> SequenceEngine {
        try ensureRulesCompiled()
        let lineage = ProcessLineage()
        await lineage.recordProcess(pid: rootPid, ppid: 1, path: "/bin/root", name: "root", startTime: base)
        await lineage.recordProcess(pid: childPid, ppid: rootPid, path: "/tmp/child", name: "child", startTime: base)
        let engine = SequenceEngine(lineage: lineage, sweepInterval: 3_600)
        _ = try await engine.loadRules(from: URL(fileURLWithPath: seqDir), enabledStatuses: ["stable"])
        return engine
    }

    /// A file event by a process carrying an ES audit identity, so one
    /// writer's repeated writes share a fold key.
    private func identifiedWrite(_ path: String, actor: String, pid: Int32, pidVersion: UInt32,
                                 action: FileAction, at offset: TimeInterval) -> Event {
        let process = MacCrabCore.ProcessInfo(
            pid: pid, ppid: 1, rpid: 1, name: (actor as NSString).lastPathComponent,
            executable: actor, commandLine: actor, args: [actor], workingDirectory: "/tmp",
            userId: 501, userName: "t", groupId: 20, startTime: base,
            auditIdentity: AuditIdentity(auid: 501, euid: 501, egid: 20, ruid: 501, rgid: 20,
                                         pid: pid, pidversion: pidVersion, asid: 100_001))
        return Event(timestamp: base.addingTimeInterval(offset), eventCategory: .file,
                     eventType: .creation, eventAction: "file", process: process,
                     file: FileInfo(path: path, action: action))
    }

    /// A toolchain node, as a Playwright browser download runs it.
    private func nodeWrite(_ path: String, pid: Int32, action: FileAction, at offset: TimeInterval) -> Event {
        identifiedWrite(path, actor: "/private/tmp/tc-toolchain/bin/node", pid: pid, pidVersion: 9,
                        action: action, at: offset)
    }

    private func bashWrite(_ path: String, pid: Int32, at offset: TimeInterval) -> Event {
        identifiedWrite(path, actor: "/bin/bash", pid: pid, pidVersion: 1, action: .write, at: offset)
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
        try ensureRulesCompiled()
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
        // npm is a Node script: a real `npm install` execs as node with the
        // npm CLI path in its arguments.
        #expect(try await fires("e1f2a3b4-0023-4000-b000-000000000023", [
            proc("/usr/local/bin/node", cmd: "node /usr/local/bin/npm install evil", at: 0),
            file("/Users/t/Library/LaunchAgents/sc.plist", at: 1),
            net(at: 2),
        ]))
        // Any other node process must not start the chain.
        #expect(!(try await fires("e1f2a3b4-0023-4000-b000-000000000023", [
            proc("/usr/local/bin/node", cmd: "node /Users/t/app/server.js", at: 0),
            file("/Users/t/Library/LaunchAgents/sc.plist", at: 1),
            net(at: 2),
        ])))
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

    // MARK: - Capacity on the shipped profile

    @Test("npm_postinstall_to_rat fires when its seed is evaluated after the drop and the callback")
    func npmPostinstallToRatSeedLate() async throws {
        let engine = try await stableEngine()
        _ = await engine.evaluate(file("/tmp/rat", actor: "/bin/sh", at: 1))
        _ = await engine.evaluate(net(at: 2))
        let matches = await engine.evaluate(proc("/bin/sh", parent: "/usr/local/bin/npm", at: 0))
        #expect(matches.contains { $0.ruleId == npmRat })
    }

    @Test("npm_postinstall_to_rat fires once across an early callback, a late drop and a later callback")
    func npmPostinstallToRatLaterCallback() async throws {
        let engine = try await stableEngine()
        var fires = 0
        for event in [proc("/bin/sh", parent: "/usr/local/bin/npm", at: 0), net(at: 2),
                      file("/tmp/rat", actor: "/bin/sh", at: 1), net(at: 3)] {
            fires += await engine.evaluate(event).filter { $0.ruleId == npmRat }.count
        }
        #expect(fires == 1)
    }

    @Test("A Playwright-like install burst folds instead of shedding any rule's history")
    func installBurstFoldsWithoutLoss() async throws {
        let engine = try await stableEngine()
        let persist = file("/Users/t/Library/LaunchAgents/sc.plist", at: 1)
        let exfil = net(at: 2)
        _ = await engine.evaluate(persist)
        _ = await engine.evaluate(exfil)
        let preBurst = await engine.pendingStepConservation().offered
        let actions: [FileAction] = [.create, .write, .close]
        for index in 0..<10_000 {
            _ = await engine.evaluate(nodeWrite("/private/tmp/pw-browsers/\(index)", pid: 201 + Int32(index % 4),
                                                action: actions[index % 3], at: 10 + Double(index) / 1_000))
        }

        #expect(await engine.pendingStepsEvictedTotal == 0)
        #expect(await engine.evictionIsOngoing(within: 300) == false)
        #expect(await engine.pendingStepConservationByRule().values.allSatisfy { $0.explicitlyShed == 0 })
        // One fold, when the burst passes the cap: every drop so far, less one
        // representative per node writer.
        let expectedFolded = UInt64(SequenceEngine.maxPendingTotal + 1) - preBurst - 4
        let pressure = await engine.pendingPressureDiagnostics()
        #expect(pressure.foldAttemptsTotal == 1 && pressure.foldedStepsTotal == expectedFolded)
        #expect(pressure.foldedStepsTotal >= 8_000 && pressure.lastPressure == nil)
        let fold = try #require(pressure.lastFold)
        #expect(fold.ruleID == npmRat && fold.stepID == "drop_payload" && fold.foldedGroups == 4)
        let capture = try await engine.checkpointCapture()
        let retained = Set(capture.pendingBuckets.first { $0.ruleID == supplyChain }?.steps.map(\.matched.eventID) ?? [])
        #expect(retained == [persist.id, exfil.id])
        let matches = await engine.evaluate(proc("/usr/local/bin/npm", cmd: "npm install evil", at: 0))
        #expect(matches.contains { $0.ruleId == supplyChain })
    }

    @Test("A flood of distinct writers sheds only npm_postinstall_to_rat's own history")
    func distinctWriterFloodShedsOnlyItsRule() async throws {
        let preFlood = [
            file("/Users/t/.ssh/id_rsa", action: .open, at: 1),
            file("/Users/t/Library/LaunchAgents/sc.plist", at: 1),
            net(at: 2),
            net(hostname: "registry.npmjs.org", at: 2),
        ]
        // Restored drop history fills the table so that it is exactly full
        // when the flood starts: count what the pre-flood events admit.
        let probe = try await stableEngine()
        for event in preFlood { _ = await probe.evaluate(event) }
        let preFloodAdmissions = Int(await probe.pendingStepConservation().offered)
        let engine = try await stableEngine()
        let reference = Date()
        let drops = (0..<(SequenceEngine.maxPendingTotal - preFloodAdmissions)).map { index in
            SequenceCheckpointPendingStep(
                ruleID: npmRat, stepID: "drop_payload",
                matched: SequenceCheckpointMatchedStep(
                    stepID: "drop_payload", eventID: UUID(), timestamp: base.addingTimeInterval(Double(index) / 1_000),
                    processPID: 9_999, processParentPID: 0, processParentWasTracked: false,
                    processAncestorPIDs: [], filePath: nil, networkDestination: nil
                ), arrivedAt: reference
            )
        }
        let payload = SequenceCheckpointPayload(
            schemaVersion: SequenceCheckpointPayload.currentSchemaVersion, capturedAt: reference,
            ruleFingerprint: try SequenceCheckpointCodec.ruleFingerprint(await engine.listRules()),
            sourceGeneration: 1, partialBuckets: [],
            pendingBuckets: [SequenceCheckpointPendingBucket(ruleID: npmRat, steps: drops)],
            evictionOrder: [],
            pendingEvictionOrder: drops.map {
                SequenceCheckpointPendingIdentity(ruleID: npmRat, stepID: "drop_payload", eventID: $0.matched.eventID)
            }
        )
        _ = try await engine.restoreCheckpoint(payload, now: reference)
        for event in preFlood { _ = await engine.evaluate(event) }
        let capacity = UInt64(SequenceEngine.maxPendingTotal)
        #expect(await engine.pendingStepConservation().queued == capacity)
        let flood = 1_000
        for index in 0..<flood {
            _ = await engine.evaluate(bashWrite("/private/tmp/flood/\(index)", pid: 30_000 + Int32(index),
                                                at: 10 + Double(index) / 1_000))
        }
        let installSeed = proc("/usr/local/bin/npm", cmd: "npm install evil", at: 0)
        let wormSeed = proc("/tmp/stage", parent: "/usr/local/bin/npm", at: 0)
        let pipSeed = proc("/usr/bin/pip3", cmd: "pip3 install requests", at: 0)
        let installMatches = await engine.evaluate(installSeed)
        let wormMatches = await engine.evaluate(wormSeed)
        _ = await engine.evaluate(pipSeed)

        let byRule = await engine.pendingStepConservationByRule()
        let evicted = await engine.pendingStepsEvictedTotal
        #expect(evicted == flood, "every flood write displaces one entry")
        #expect(byRule[npmRat]?.explicitlyShed == UInt64(evicted))
        for (ruleID, ledger) in byRule where ruleID != npmRat {
            #expect(ledger.explicitlyShed == 0, "\(ruleID) keeps its history")
        }
        let pressure = await engine.pendingPressureDiagnostics()
        #expect(pressure.journalExplicitlyShedTotal == UInt64(evicted))
        #expect(pressure.lastPressure?.representativeVictimRuleID == npmRat)
        #expect(pressure.foldedStepsTotal == 0, "distinct writers have nothing to fold")
        let attemptBound = UInt64(flood / 256 + 2)
        #expect(pressure.foldAttemptsTotal <= attemptBound, "low-yield attempts are throttled")
        // 0021 (30 s window) and 9c2d052b (5 s) are checked only for shed
        // history above: their processing-time windows can lapse on a slow host.
        #expect(installMatches.contains { $0.ruleId == supplyChain })
        #expect(wormMatches.contains { $0.ruleId == worm })
        #expect(await engine.pendingStepConservation().conservationMaintained)
    }

    @Test("The stable profile's fold-eligible steps are the reviewed set")
    func stableFoldEligibility() async throws {
        let rules = try await stableEngine().listRules()
        let eligible = Dictionary(uniqueKeysWithValues: rules.compactMap { rule in
            SequenceEngine.pendingFoldStepID(for: rule).map { (rule.id, $0) }
        })
        #expect(eligible == [
            "e1f2a3b4-0011-4000-b000-000000000011": "persist",
            npmRat: "drop_payload",
            "e1f2a3b4-0021-4000-b000-000000000021": "cred_access",
            supplyChain: "persist",
            "e1f2a3b4-0032-4000-b000-000000000032": "network_callhome",
            worm: "cred_read",
            "9c2d052b-a8ce-43fc-a1a9-5ee9c86f0682": "cred_read",
            "14b34c1b-0487-4cdf-b11d-f37a3591c791": "github_api_poll",
        ])
        // Every other stable rule is reviewed as ineligible; a new stable rule
        // must be added to one of the two sets.
        let ineligible: Set<String> = [
            "e1f2a3b4-0006-4000-b000-000000000006",
            "e1f2a3b4-0007-4000-b000-000000000007",
            "e1f2a3b4-0016-4000-b000-000000000016",
        ]
        #expect(Set(rules.map(\.id)) == Set(eligible.keys).union(ineligible))
    }
}
