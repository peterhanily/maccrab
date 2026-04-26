// SupplyChainGateSafetyTests.swift
// MacCrabCoreTests
//
// Validates the v1.6.19 safety hardening of SupplyChainGate.gate():
// - SafePIDValidator integration (refuses to kill protected PIDs)
// - Package-manager ancestry check (refuses unrelated user processes)
// - Process-helper correctness for the recycled-PID protection

import Testing
import Foundation
import Darwin
@testable import MacCrabCore

@Suite("SupplyChainGate safety guards")
struct SupplyChainGateSafetyTests {

    // MARK: - Static helpers

    @Test("processPath returns the binary path for the current process")
    func processPathSelf() {
        let path = SupplyChainGate.processPath(for: getpid())
        #expect(path != nil)
        #expect(path?.isEmpty == false)
    }

    @Test("processBasename returns the binary basename for the current process")
    func processBasenameSelf() {
        let name = SupplyChainGate.processBasename(for: getpid())
        #expect(name != nil)
        #expect(name?.contains("/") == false)
    }

    @Test("processPath returns nil for an unresolvable PID")
    func processPathUnresolvable() {
        // PID 999999 is virtually guaranteed to not exist.
        #expect(SupplyChainGate.processPath(for: 999_999) == nil)
        #expect(SupplyChainGate.processBasename(for: 999_999) == nil)
    }

    @Test("parentPID returns a valid PPID for the current process")
    func parentPIDSelf() {
        let ppid = SupplyChainGate.parentPID(for: getpid())
        #expect(ppid > 0)
        // The actual ppid depends on the test runner — could be xctest,
        // swift-test, or similar. Just verify the lookup succeeded.
    }

    // MARK: - Ancestry walk

    @Test("descendsFromPackageManager returns false for /bin/sleep")
    func ancestryRejectsSleep() async throws {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/bin/sleep")
        proc.arguments = ["30"]
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = FileHandle.nullDevice
        try proc.run()
        defer {
            if proc.isRunning { proc.terminate() }
        }
        let pid = proc.processIdentifier
        try await Task.sleep(nanoseconds: 50_000_000)

        // /bin/sleep is not a package manager. Walking up from sleep,
        // the parent chain (xctest → swift-test → zsh → ...) also has
        // no package manager. Should reject.
        #expect(SupplyChainGate.descendsFromPackageManager(pid: pid) == false)
    }

    @Test("descendsFromPackageManager accepts a child whose binary basename is in the list")
    func ancestryAcceptsPackageManagerBasename() async throws {
        // Copy /bin/sleep to a temp file named "npm" so proc_pidpath
        // returns a path whose basename is "npm". (We can't use the
        // actual /usr/bin/python3 because on macOS it re-execs into
        // .../Python.framework/.../Python — basename "Python", not
        // "python3" — by the time the test checks it.)
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
        // Under heavy parallel-test load proc_pidpath can take longer than
        // a fixed sleep — poll up to 2s.
        for _ in 0..<40 {
            if SupplyChainGate.processBasename(for: pid) == "npm" { break }
            try await Task.sleep(nanoseconds: 50_000_000)
        }

        // basename "npm" is in packageManagerNames → match on hop 0.
        #expect(SupplyChainGate.processBasename(for: pid) == "npm")
        #expect(SupplyChainGate.descendsFromPackageManager(pid: pid) == true)
    }

    @Test("descendsFromPackageManager returns false for unresolvable PID")
    func ancestryUnresolvable() {
        #expect(SupplyChainGate.descendsFromPackageManager(pid: 999_999) == false)
    }

    @Test("descendsFromPackageManager returns false for PID 1 (launchd)")
    func ancestryRejectsPID1() {
        // launchd is not a package manager, and PID 1 has no parent → false.
        #expect(SupplyChainGate.descendsFromPackageManager(pid: 1) == false)
    }

    // MARK: - Package-manager name list

    @Test("packageManagerNames covers the common installers")
    func packageManagerListCovers() {
        let names = SupplyChainGate.packageManagerNames
        // macOS native
        #expect(names.contains("brew"))
        #expect(names.contains("installer"))
        // Node
        #expect(names.contains("npm"))
        #expect(names.contains("pnpm"))
        #expect(names.contains("yarn"))
        // Python
        #expect(names.contains("pip"))
        #expect(names.contains("pip3"))
        #expect(names.contains("python3"))
        #expect(names.contains("uv"))
        // Ruby
        #expect(names.contains("gem"))
        // Rust / Go
        #expect(names.contains("cargo"))
        #expect(names.contains("go"))
    }

    @Test("packageManagerNames deliberately excludes shells")
    func packageManagerListExcludesShells() {
        let names = SupplyChainGate.packageManagerNames
        // Shells are in every user-process ancestry; including them would
        // defeat the ancestry check. They must be excluded by design.
        #expect(names.contains("bash") == false)
        #expect(names.contains("sh") == false)
        #expect(names.contains("zsh") == false)
        #expect(names.contains("dash") == false)
        #expect(names.contains("fish") == false)
    }

    // MARK: - gate() rejection paths

    @Test("gate refuses when installerPid is on the safe-kill protect list")
    func gateRefusesSystemPID() async {
        let gate = SupplyChainGate(maxAgeHours: 24)
        await gate.enable()
        // PID 1 is launchd — must never be killed regardless of risk level.
        let blocked = await gate.gate(
            packageName: "evil-package",
            registry: "npm",
            ageInDays: 0.01,
            riskLevel: "critical",
            installerPid: 1
        )
        #expect(blocked == nil)
        let history = await gate.history()
        #expect(history.isEmpty)
    }

    @Test("gate refuses when installerPid does not descend from a package manager")
    func gateRefusesUnrelatedProcess() async throws {
        // Spawn /bin/sleep — not an installer. Gate must refuse to kill it
        // even if the caller insists it's an evil package.
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/bin/sleep")
        proc.arguments = ["30"]
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = FileHandle.nullDevice
        try proc.run()
        defer {
            if proc.isRunning { proc.terminate() }
        }
        let pid = proc.processIdentifier
        try await Task.sleep(nanoseconds: 50_000_000)

        let gate = SupplyChainGate(maxAgeHours: 24)
        await gate.enable()
        let blocked = await gate.gate(
            packageName: "evil-package",
            registry: "npm",
            ageInDays: 0.01,
            riskLevel: "critical",
            installerPid: pid
        )
        #expect(blocked == nil)
        let history = await gate.history()
        #expect(history.isEmpty)
        // Verify the sleep process is still running — gate did not kill it.
        #expect(proc.isRunning == true)
    }

    @Test("gate is a no-op when disabled")
    func gateNoOpWhenDisabled() async {
        let gate = SupplyChainGate(maxAgeHours: 24)
        // Don't call enable() — gate stays disabled.
        let blocked = await gate.gate(
            packageName: "evil-package",
            registry: "npm",
            ageInDays: 0.01,
            riskLevel: "critical",
            installerPid: 1
        )
        #expect(blocked == nil)
    }
}
