import Testing
import Foundation
@testable import MacCrabCore

@Suite("DNS Sinkhole")
struct DNSSinkholeTests {
    @Test("Enable and disable without crash")
    func lifecycle() async {
        let sinkhole = DNSSinkhole()
        let stats = await sinkhole.stats()
        #expect(stats.enabled == false)
        #expect(stats.domainCount == 0)
    }

    @Test("Add domains increments count")
    func addDomains() async {
        let sinkhole = DNSSinkhole()
        await sinkhole.addDomains(["evil.com", "malware.net"])
        let stats = await sinkhole.stats()
        #expect(stats.domainCount == 2)
    }
}

@Suite("Network Blocker")
struct NetworkBlockerTests {
    @Test("Stats show disabled by default")
    func defaultState() async {
        let blocker = NetworkBlocker()
        let stats = await blocker.stats()
        #expect(stats.enabled == false)
        #expect(stats.blockedCount == 0)
    }
}

@Suite("Persistence Guard")
struct PersistenceGuardTests {
    @Test("Stats show disabled by default")
    func defaultState() async {
        let guard_ = PersistenceGuard()
        let stats = await guard_.stats()
        #expect(stats.enabled == false)
    }
}

@Suite("Sandbox Analyzer")
struct SandboxAnalyzerTests {
    @Test("Returns nil for system binary")
    func skipSystemBinary() async {
        let analyzer = SandboxAnalyzer()
        let result = await analyzer.analyze(binaryPath: "/usr/bin/ls")
        #expect(result == nil)
    }

    @Test("Returns nil for nonexistent binary")
    func skipMissing() async {
        let analyzer = SandboxAnalyzer()
        let result = await analyzer.analyze(binaryPath: "/tmp/nonexistent_binary_12345")
        #expect(result == nil)
    }
}

@Suite("AI Containment")
struct AIContainmentTests {
    @Test("Stats show disabled by default")
    func defaultState() async {
        let containment = AIContainment()
        let stats = await containment.stats()
        #expect(stats.enabled == false)
        #expect(stats.protectedCount == 0)
    }

    @Test("wouldBlock returns false when disabled")
    func disabledNoBlock() async {
        let containment = AIContainment()
        let blocked = await containment.wouldBlock(filePath: "/Users/test/.ssh/id_rsa", aiToolName: "claude")
        #expect(blocked == false)
    }
}

@Suite("Supply Chain Gate")
struct SupplyChainGateTests {
    @Test("Stats show disabled by default")
    func defaultState() async {
        let gate = SupplyChainGate()
        let stats = await gate.stats()
        #expect(stats.enabled == false)
        #expect(stats.blocked == 0)
    }

    @Test("Gate returns nil when disabled")
    func disabledNoGate() async {
        let gate = SupplyChainGate()
        let result = await gate.gate(packageName: "evil", registry: "npm", ageInDays: 0.01, riskLevel: "critical", installerPid: 99999)
        #expect(result == nil)
    }

    @Test("Gate blocks critical package when enabled")
    func blocksWhenEnabled() async throws {
        // v1.6.19 hardening: gate() now requires the installer PID to
        // descend from a known package manager. Spawn a copy of /bin/sleep
        // renamed to "npm" so proc_pidpath reports a basename in the
        // packageManagerNames list.
        let tmpDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmpDir) }
        let fakeNpm = tmpDir.appendingPathComponent("npm")
        try FileManager.default.copyItem(
            at: URL(fileURLWithPath: "/bin/sleep"),
            to: fakeNpm
        )
        let proc = Process()
        proc.executableURL = fakeNpm
        proc.arguments = ["30"]
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = FileHandle.nullDevice
        try proc.run()
        defer {
            if proc.isRunning { proc.terminate() }
        }
        let pid = proc.processIdentifier
        // Wait for proc_pidpath to resolve before invoking gate().
        for _ in 0..<40 {
            if SupplyChainGate.processBasename(for: pid) == "npm" { break }
            try await Task.sleep(nanoseconds: 50_000_000)
        }

        let gate = SupplyChainGate(maxAgeHours: 24)
        await gate.enable()
        let result = await gate.gate(
            packageName: "evil-pkg",
            registry: "npm",
            ageInDays: 0.01,
            riskLevel: "critical",
            installerPid: pid
        )
        #expect(result != nil)
        #expect(result?.packageName == "evil-pkg")
        let stats = await gate.stats()
        #expect(stats.blocked == 1)
    }

    @Test("Gate allows old packages")
    func allowsOldPackages() async {
        let gate = SupplyChainGate(maxAgeHours: 24)
        await gate.enable()
        let result = await gate.gate(packageName: "lodash", registry: "npm", ageInDays: 365, riskLevel: "safe", installerPid: 99999)
        #expect(result == nil)
    }
}

@Suite("TCC Revocation")
struct TCCRevocationTests {
    @Test("Stats show disabled by default")
    func defaultState() async {
        let revocation = TCCRevocation()
        let stats = await revocation.stats()
        #expect(stats.enabled == false)
    }

    @Test("shouldRevoke returns false when disabled")
    func disabledNoRevoke() async {
        let revocation = TCCRevocation()
        let should = await revocation.shouldRevoke(service: "Camera", bundleId: "com.evil.app", signerType: "unsigned")
        #expect(should == false)
    }

    @Test("shouldRevoke returns true for unsigned app with sensitive service")
    func unsignedSensitive() async {
        let revocation = TCCRevocation()
        await revocation.enable()
        let should = await revocation.shouldRevoke(service: "Camera", bundleId: "com.evil.app", signerType: "unsigned")
        #expect(should == true)
    }

    @Test("shouldRevoke returns false for apple-signed app")
    func appleSigned() async {
        let revocation = TCCRevocation()
        await revocation.enable()
        let should = await revocation.shouldRevoke(service: "Camera", bundleId: "com.apple.Safari", signerType: "apple")
        #expect(should == false)
    }
}
