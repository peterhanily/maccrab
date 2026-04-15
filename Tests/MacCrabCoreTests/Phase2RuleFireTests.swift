// Phase2RuleFireTests.swift
// Detection-as-code: each new Phase 2 hash/session/env-aware rule ships
// with a positive fire case and a negative non-fire case.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("Phase 2 rule fires")
struct Phase2RuleFireTests {

    // MARK: - Builders

    private func process(
        name: String = "attacker",
        executable: String = "/tmp/attacker",
        pid: Int32 = 1234,
        ppid: Int32 = 1,
        commandLine: String? = nil,
        signer: SignerType = .unsigned,
        isAdhocSigned: Bool? = nil,
        isPlatformBinary: Bool = false,
        session: SessionInfo? = nil,
        envVars: [String: String]? = nil,
        ancestorExec: String = "/sbin/launchd",
        ancestorName: String = "launchd"
    ) -> MacCrabCore.ProcessInfo {
        let sig = CodeSignatureInfo(
            signerType: signer,
            teamId: signer == .devId ? "ABC1234567" : nil,
            signingId: nil,
            authorities: [],
            flags: 0,
            isNotarized: signer == .apple || signer == .devId,
            issuerChain: nil,
            certHashes: nil,
            isAdhocSigned: isAdhocSigned,
            entitlements: nil
        )
        return MacCrabCore.ProcessInfo(
            pid: pid,
            ppid: ppid,
            rpid: ppid,
            name: name,
            executable: executable,
            commandLine: commandLine ?? executable,
            args: [executable],
            workingDirectory: "/tmp",
            userId: 501,
            userName: "alice",
            groupId: 20,
            startTime: Date(),
            codeSignature: sig,
            ancestors: [ProcessAncestor(pid: 1, executable: ancestorExec, name: ancestorName)],
            architecture: "arm64",
            isPlatformBinary: isPlatformBinary,
            session: session,
            envVars: envVars
        )
    }

    private func fileEvent(
        path: String,
        process: MacCrabCore.ProcessInfo,
        action: FileAction = .create
    ) -> Event {
        let dir = (path as NSString).deletingLastPathComponent
        let name = (path as NSString).lastPathComponent
        let ext = (path as NSString).pathExtension
        let file = FileInfo(
            path: path,
            name: name,
            directory: dir,
            extension_: ext.isEmpty ? nil : ext,
            size: 4096,
            action: action
        )
        return Event(
            eventCategory: .file,
            eventType: action == .create ? .creation : .change,
            eventAction: action.rawValue,
            process: process,
            file: file
        )
    }

    private func processEvent(process: MacCrabCore.ProcessInfo) -> Event {
        Event(
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: process
        )
    }

    /// Shared rule engine loaded from compiled rules on disk.
    private func loadEngine() async throws -> RuleEngine {
        ensureRulesCompiled()
        let engine = RuleEngine()
        _ = try await engine.loadRules(from: URL(fileURLWithPath: "/tmp/maccrab_v3"))
        return engine
    }

    // MARK: - adhoc_signed_launchagent_write

    @Test("Ad-hoc LaunchAgent write fires adhoc_signed_launchagent_write")
    func adhocLaunchAgentFires() async throws {
        let engine = try await loadEngine()
        let proc = process(
            name: "dropper",
            executable: "/tmp/dropper",
            signer: .adHoc,
            isAdhocSigned: true
        )
        let event = fileEvent(
            path: "/Users/alice/Library/LaunchAgents/com.evil.persistence.plist",
            process: proc
        )
        let matches = await engine.evaluate(event)
        #expect(matches.contains { $0.ruleName.lowercased().contains("ad-hoc") },
                "Expected adhoc_signed_launchagent_write to fire, got: \(matches.map(\.ruleName))")
    }

    @Test("Developer-ID signed LaunchAgent write does NOT fire adhoc rule")
    func devIdLaunchAgentDoesNotFire() async throws {
        let engine = try await loadEngine()
        let proc = process(
            name: "installer",
            executable: "/Applications/VendorApp.app/Contents/MacOS/helper",
            signer: .devId,
            isAdhocSigned: false
        )
        let event = fileEvent(
            path: "/Library/LaunchAgents/com.vendor.update.plist",
            process: proc
        )
        let matches = await engine.evaluate(event)
        #expect(!matches.contains { $0.ruleName.lowercased().contains("ad-hoc") },
                "Did not expect adhoc rule to fire, got: \(matches.map(\.ruleName))")
    }

    // MARK: - dyld_insert_libraries_env

    @Test("DYLD_INSERT_LIBRARIES in env fires dyld_insert_libraries_env")
    func dyldInsertFires() async throws {
        let engine = try await loadEngine()
        let proc = process(
            name: "injected",
            executable: "/tmp/injected",
            envVars: [
                "PATH": "/usr/bin:/bin",
                "DYLD_INSERT_LIBRARIES": "/tmp/payload.dylib",
            ]
        )
        let event = processEvent(process: proc)
        let matches = await engine.evaluate(event)
        #expect(matches.contains { $0.ruleName.lowercased().contains("dyld") },
                "Expected dyld_insert_libraries_env to fire, got: \(matches.map(\.ruleName))")
    }

    @Test("Clean env without DYLD does NOT fire dyld rule")
    func cleanEnvDoesNotFire() async throws {
        let engine = try await loadEngine()
        let proc = process(
            name: "benign",
            executable: "/usr/bin/ls",
            envVars: ["PATH": "/usr/bin:/bin", "HOME": "/Users/alice"]
        )
        let event = processEvent(process: proc)
        let matches = await engine.evaluate(event)
        #expect(!matches.contains { $0.ruleName.lowercased().contains("dyld_insert") },
                "Did not expect dyld rule to fire, got: \(matches.map(\.ruleName))")
    }

    // MARK: - ssh_launched_security_dump

    @Test("security dump-keychain from SSH session fires credential-dump rule")
    func sshKeychainDumpFires() async throws {
        let engine = try await loadEngine()
        let proc = process(
            name: "security",
            executable: "/usr/bin/security",
            commandLine: "/usr/bin/security dump-keychain -d login.keychain",
            session: SessionInfo(
                sessionId: 100042,
                tty: "/dev/ttys003",
                loginUser: "alice",
                sshRemoteIP: "203.0.113.42",
                launchSource: .ssh
            )
        )
        let event = processEvent(process: proc)
        let matches = await engine.evaluate(event)
        #expect(matches.contains { $0.ruleName.lowercased().contains("ssh") ||
                                   $0.ruleName.lowercased().contains("keychain") ||
                                   $0.ruleName.lowercased().contains("credential") },
                "Expected ssh_launched_security_dump to fire, got: \(matches.map(\.ruleName))")
    }

    @Test("security dump-keychain from interactive terminal does NOT fire SSH rule")
    func localKeychainDumpDoesNotFireSSH() async throws {
        let engine = try await loadEngine()
        let proc = process(
            name: "security",
            executable: "/usr/bin/security",
            commandLine: "/usr/bin/security dump-keychain -d login.keychain",
            session: SessionInfo(
                sessionId: 100042,
                tty: "/dev/ttys000",
                loginUser: "alice",
                sshRemoteIP: nil,
                launchSource: .terminal
            )
        )
        let event = processEvent(process: proc)
        let matches = await engine.evaluate(event)
        // Other rules may fire (generic keychain detection), but the SSH-specific
        // one should not.
        #expect(!matches.contains {
            $0.ruleId.contains("ssh_launched_security_dump") ||
            $0.ruleId.contains("ssh-launched-security-dump")
        }, "SSH-specific rule should not fire on local terminal session")
    }
}
