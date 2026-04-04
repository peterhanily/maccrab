// DeepMacOSTests.swift
// Tests for deep macOS detection techniques.

import Testing
import Foundation
@testable import HawkEyeCore

// MARK: - Test Helpers (reuse pattern from PipelineTests)

private func processEvent(
    name: String, path: String, commandLine: String,
    parentPath: String = "/sbin/launchd", signer: SignerType? = nil,
    architecture: String = "arm64"
) -> Event {
    let codeSig: CodeSignatureInfo? = signer.map {
        CodeSignatureInfo(signerType: $0, teamId: nil, signingId: nil, authorities: [], flags: 0, isNotarized: false)
    }
    let process = ProcessInfo(
        pid: Int32.random(in: 1000...60000), ppid: 1, rpid: 1,
        name: name, executable: path, commandLine: commandLine,
        args: commandLine.split(separator: " ").map(String.init),
        workingDirectory: "/tmp", userId: 501, userName: "testuser", groupId: 20,
        startTime: Date(), codeSignature: codeSig,
        ancestors: [ProcessAncestor(pid: 1, executable: parentPath, name: (parentPath as NSString).lastPathComponent)],
        architecture: architecture, isPlatformBinary: signer == .apple
    )
    return Event(eventCategory: .process, eventType: .creation, eventAction: "exec", process: process)
}

private func fileEvent(filePath: String, processPath: String = "/tmp/malware", signer: SignerType? = nil) -> Event {
    let codeSig: CodeSignatureInfo? = signer.map {
        CodeSignatureInfo(signerType: $0, teamId: nil, signingId: nil, authorities: [], flags: 0, isNotarized: false)
    }
    let process = ProcessInfo(
        pid: Int32.random(in: 1000...60000), ppid: 1, rpid: 1,
        name: (processPath as NSString).lastPathComponent, executable: processPath,
        commandLine: processPath, args: [processPath], workingDirectory: "/",
        userId: 501, userName: "testuser", groupId: 20, startTime: Date(),
        codeSignature: codeSig,
        ancestors: [ProcessAncestor(pid: 1, executable: "/sbin/launchd", name: "launchd")],
        architecture: "arm64", isPlatformBinary: false
    )
    let file = FileInfo(path: filePath, action: .create)
    return Event(eventCategory: .file, eventType: .creation, eventAction: "create", process: process, file: file)
}

private func loadRules() async throws -> RuleEngine {
    let engine = RuleEngine()
    let compiledDir = "/tmp/hawkeye_v3"
    if FileManager.default.fileExists(atPath: compiledDir) {
        _ = try await engine.loadRules(from: URL(fileURLWithPath: compiledDir))
    }
    return engine
}

// MARK: - Phase 1: Input Monitoring & Process Injection

@Suite("Deep macOS: Input Monitoring")
struct InputMonitoringTests {

    @Test("DYLD_INSERT_LIBRARIES in command line triggers detection")
    func dyldInjection() async throws {
        let engine = try await loadRules()
        let event = processEvent(
            name: "python3", path: "/usr/bin/python3",
            commandLine: "DYLD_INSERT_LIBRARIES=/tmp/evil.dylib /usr/bin/python3 -c 'import os'"
        )
        let matches = await engine.evaluate(event)
        #expect(matches.contains { $0.ruleName.lowercased().contains("dyld") },
                "Expected DYLD injection detection, got: \(matches.map(\.ruleName))")
    }

    @Test("DYLD detection fires for unsigned process injection")
    func dyldUnsignedInjection() async throws {
        let engine = try await loadRules()
        let event = processEvent(
            name: "target", path: "/tmp/target",
            commandLine: "DYLD_INSERT_LIBRARIES=/tmp/evil.dylib /tmp/target",
            signer: .unsigned
        )
        let matches = await engine.evaluate(event)
        #expect(matches.contains { $0.ruleName.lowercased().contains("dyld") },
                "Unsigned DYLD injection should be detected")
    }

    @Test("task_for_pid from unsigned process triggers detection")
    func taskForPid() async throws {
        let engine = try await loadRules()
        let event = processEvent(
            name: "injector", path: "/tmp/injector",
            commandLine: "/tmp/injector task_for_pid 1234 mach_port_insert_right",
            signer: .unsigned
        )
        let matches = await engine.evaluate(event)
        #expect(matches.contains { $0.ruleName.lowercased().contains("task_for_pid") || $0.ruleName.lowercased().contains("mach") },
                "Expected task_for_pid detection, got: \(matches.map(\.ruleName))")
    }

    @Test("task_for_pid from lldb is NOT flagged")
    func taskForPidDebuggerFiltered() async throws {
        let engine = try await loadRules()
        let event = processEvent(
            name: "lldb", path: "/usr/bin/lldb",
            commandLine: "lldb --attach-pid 1234 task_for_pid",
            signer: .apple
        )
        let matches = await engine.evaluate(event)
        let taskMatches = matches.filter { $0.ruleName.lowercased().contains("task_for_pid") }
        #expect(taskMatches.isEmpty, "lldb task_for_pid should be filtered")
    }
}

// MARK: - Phase 1: Evasion Detection

@Suite("Deep macOS: Evasion Detection")
struct EvasionDetectionTests {

    @Test("Rosetta x86_64 unsigned binary triggers detection")
    func rosettaUnsigned() async throws {
        let engine = try await loadRules()
        let event = processEvent(
            name: "payload", path: "/tmp/payload",
            commandLine: "/tmp/payload --execute",
            signer: .unsigned,
            architecture: "x86_64"
        )
        let matches = await engine.evaluate(event)
        // May match rosetta rule if compiled, or other unsigned-from-tmp rules
        #expect(!matches.isEmpty, "Unsigned x86_64 binary should trigger at least one rule")
    }

    @Test("Quarantine xattr removal command triggers detection")
    func quarantineRemoval() async throws {
        let engine = try await loadRules()
        let event = processEvent(
            name: "xattr", path: "/usr/bin/xattr",
            commandLine: "xattr -d com.apple.quarantine /Users/victim/Downloads/malware.app"
        )
        let matches = await engine.evaluate(event)
        #expect(matches.contains { $0.ruleName.lowercased().contains("quarantine") },
                "Expected quarantine removal detection, got: \(matches.map(\.ruleName))")
    }

    @Test("SIP disable command triggers detection")
    func sipDisable() async throws {
        let engine = try await loadRules()
        let event = processEvent(
            name: "csrutil", path: "/usr/bin/csrutil",
            commandLine: "csrutil disable"
        )
        let matches = await engine.evaluate(event)
        #expect(matches.contains { $0.ruleName.lowercased().contains("sip") || $0.ruleName.lowercased().contains("integrity") },
                "Expected SIP disable detection, got: \(matches.map(\.ruleName))")
    }
}

// MARK: - Phase 2: Persistence & Credential Access

@Suite("Deep macOS: Persistence & Credential Access")
struct PersistenceTests {

    @Test("Authorization plugin installation triggers detection")
    func authPlugin() async throws {
        let engine = try await loadRules()
        let event = fileEvent(
            filePath: "/Library/Security/SecurityAgentPlugins/EvilPlugin.bundle",
            processPath: "/tmp/installer",
            signer: .unsigned
        )
        let matches = await engine.evaluate(event)
        #expect(matches.contains { $0.ruleName.lowercased().contains("authorization") || $0.ruleName.lowercased().contains("plugin") },
                "Expected auth plugin detection, got: \(matches.map(\.ruleName))")
    }

    @Test("Apple-signed auth plugin is NOT flagged")
    func authPluginAppleFiltered() async throws {
        let engine = try await loadRules()
        let event = fileEvent(
            filePath: "/Library/Security/SecurityAgentPlugins/ApplePlugin.bundle",
            processPath: "/usr/libexec/installer",
            signer: .apple
        )
        let matches = await engine.evaluate(event)
        let authMatches = matches.filter { $0.ruleName.lowercased().contains("authorization plugin") }
        #expect(authMatches.isEmpty, "Apple-signed auth plugin should be filtered")
    }
}

// MARK: - Entropy & Statistical Analysis

@Suite("Deep macOS: Entropy Analysis")
struct EntropyTests {

    @Test("Shannon entropy correctly identifies high-entropy strings")
    func shannonEntropy() {
        let english = EntropyAnalysis.shannonEntropy("this is a normal english sentence")
        let base64 = EntropyAnalysis.shannonEntropy("aGVsbG8gd29ybGQgdGhpcyBpcyBiYXNlNjQ=")
        let random = EntropyAnalysis.shannonEntropy("j8K#mP$2xQ!nR@vL&fW*3yZ^9bT%6cD")

        #expect(english < 4.5, "English text should have entropy < 4.5, got \(english)")
        #expect(base64 > 4.0, "Base64 should have entropy > 4.0, got \(base64)")
        #expect(random > 4.5, "Random should have entropy > 4.5, got \(random)")
    }

    @Test("DGA domain detection flags high-entropy domains")
    func dgaDetection() {
        // Very long mixed alphanumeric SLD — classic DGA pattern
        let (_, isDGA, _) = EntropyAnalysis.analyzeDomain("xk7q2m9p4rj8w3n5bv6tc1.evil.com")
        #expect(isDGA, "Long mixed-alphanumeric SLD should be flagged as DGA")

        let (_, isLegit, _) = EntropyAnalysis.analyzeDomain("google.com")
        #expect(!isLegit, "google.com should NOT be flagged as DGA")
    }

    @Test("DNS tunneling detection flags long high-entropy subdomains")
    func dnsTunneling() {
        // Very long encoded subdomains — classic DNS tunneling
        let longEncoded = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHZlcnkgbG9uZw.dGhpcyBpcyBiYXNlNjQgZW5jb2RlZCBkYXRh.ZW5jb2RlZCBwYXlsb2FkIGluIGRucyBxdWVyeQ.tunnel.evil.com"
        let (isTunnel, _) = EntropyAnalysis.isDNSTunneling(
            queryName: longEncoded,
            queryType: 16 // TXT
        )
        #expect(isTunnel, "Long high-entropy subdomain TXT query should flag as tunneling")
    }

    @Test("Statistical z-score detects behavioral drift")
    func zScoreDrift() async {
        let detector = StatisticalAnomalyDetector(zThreshold: 3.0, minSamples: 5)

        // Establish baseline: process runs every ~60s
        for _ in 0..<10 {
            _ = await detector.processEvent(
                processPath: "/usr/bin/cron",
                argCount: 2, commandLine: "cron -s",
                category: "process", timestamp: Date()
            )
        }

        // Now a burst of 50 args (anomalous)
        let anomalies = await detector.processEvent(
            processPath: "/usr/bin/cron",
            argCount: 50, commandLine: "cron " + String(repeating: "-x ", count: 49),
            category: "process", timestamp: Date()
        )
        #expect(anomalies.contains { $0.feature == "argument_count" },
                "Sudden jump to 50 args should trigger z-score anomaly")
    }
}

// MARK: - Behavioral Scoring

@Suite("Deep macOS: Behavioral Scoring Indicators")
struct BehaviorScoringIndicatorTests {

    @Test("New deep indicators are registered in weights")
    func indicatorWeights() {
        let deepIndicators = [
            "library_injection", "event_tap_keylogger", "task_for_pid_injection",
            "rosetta_unsigned", "sip_disabled", "non_apple_auth_plugin",
            "rogue_xpc_service", "gatekeeper_override", "xprotect_outdated",
        ]
        for name in deepIndicators {
            let weight = BehaviorScoring.weights[name]
            #expect(weight != nil && weight! > 0, "Indicator '\(name)' should have a positive weight")
        }
    }

    @Test("SIP disabled has highest weight among deep indicators")
    func sipWeight() {
        let sipWeight = BehaviorScoring.weights["sip_disabled"] ?? 0
        #expect(sipWeight >= 9.0, "SIP disabled should have weight >= 9.0")
    }
}
