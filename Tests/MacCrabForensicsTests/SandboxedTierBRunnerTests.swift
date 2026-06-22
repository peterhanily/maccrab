// SandboxedTierBRunnerTests — the sandboxed third-party lane's pure + guard
// behaviour. The REAL containment proof (a non-allowlisted read returns EPERM
// under the trampoline) is the adversarial-corpus client-test run on a physical
// macOS host — out of scope here and explicitly deferred. These tests pin the
// fail-closed guards, the trampoline argv construction, the runtime-availability
// check, and the trampoline SBPL shape — everything writable + assertable
// without spawning under a sandbox.

import Testing
import Foundation
@testable import MacCrabForensics

@Suite("SandboxedTierBRunner (sandboxed lane: guards + pure helpers)")
struct SandboxedTierBRunnerTests {

    static func verified(isSandboxed: Bool, isFirstParty: Bool, binaryPath: String = "/tmp/does-not-need-to-exist") -> TierBRegistry.VerifiedPlugin {
        var v = TierBRegistry.VerifiedPlugin(
            pluginID: "com.x.p",
            manifest: TierBManifest(id: "com.x.p", displayName: "P", version: "1.0", schemaVersion: 1, description: "d",
                                    fileReadSubpaths: ["/Users/x/Library/Safari"]),
            bundleRoot: "/tmp/bundle",
            binaryPath: binaryPath,
            publicKeyHex: String(repeating: "a", count: 64),
            publicKeySHA256: String(repeating: "b", count: 64))
        v.isSandboxed = isSandboxed
        v.isFirstParty = isFirstParty
        return v
    }

    // MARK: - Fail-closed guards (no spawn reached)

    @Test("run refuses a non-sandbox-gated plugin")
    func refusesNotSandboxed() {
        let runner = SandboxedTierBRunner(trampolinePath: "/bin/sh")
        let v = Self.verified(isSandboxed: false, isFirstParty: false)
        do { _ = try runner.run(verified: v, scratchDir: "/tmp"); Issue.record("expected throw") }
        catch let e as SandboxedTierBRunner.RunnerError { if case .notSandboxed = e {} else { Issue.record("wrong error: \(e)") } }
        catch { Issue.record("wrong error type: \(error)") }
    }

    @Test("run refuses a first-party plugin (lanes never cross)")
    func refusesFirstParty() {
        let runner = SandboxedTierBRunner(trampolinePath: "/bin/sh")
        let v = Self.verified(isSandboxed: true, isFirstParty: true)
        do { _ = try runner.run(verified: v, scratchDir: "/tmp"); Issue.record("expected throw") }
        catch let e as SandboxedTierBRunner.RunnerError { if case .isFirstParty = e {} else { Issue.record("wrong error: \(e)") } }
        catch { Issue.record("wrong error type: \(error)") }
    }

    @Test("run fail-closes when the trampoline is unavailable (never spawns uncontained)")
    func refusesNoTrampoline() {
        let runner = SandboxedTierBRunner(trampolinePath: "/nonexistent/maccrab-tierb-sandbox-host")
        let v = Self.verified(isSandboxed: true, isFirstParty: false)
        do { _ = try runner.run(verified: v, scratchDir: "/tmp"); Issue.record("expected throw") }
        catch let e as SandboxedTierBRunner.RunnerError { if case .sandboxRuntimeUnavailable = e {} else { Issue.record("wrong error: \(e)") } }
        catch { Issue.record("wrong error type: \(error)") }
    }

    // MARK: - Runtime availability (pure filesystem check)

    @Test("isRuntimeAvailable: exists+executable (override on); false for missing / dir / non-exec")
    func runtimeAvailability() throws {
        // Use the allowUnsigned core for a deterministic positive (the strict
        // signature path depends on how the test runner itself is signed).
        #expect(SandboxedTierBRunner.isRuntimeAvailable(trampolinePath: "/bin/sh", allowUnsigned: true))
        #expect(!SandboxedTierBRunner.isRuntimeAvailable(trampolinePath: "/nonexistent/x", allowUnsigned: true))
        #expect(!SandboxedTierBRunner.isRuntimeAvailable(trampolinePath: "/tmp", allowUnsigned: true))  // directory
        let f = NSTemporaryDirectory() + "nonexec-\(UUID().uuidString)"
        try Data("x".utf8).write(to: URL(fileURLWithPath: f))
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: f)
        defer { try? FileManager.default.removeItem(atPath: f) }
        #expect(!SandboxedTierBRunner.isRuntimeAvailable(trampolinePath: f, allowUnsigned: true))
        // Strict path: an ad-hoc (non-Apple-anchored) binary is refused when
        // unsigned is NOT allowed. (A 0o755 script under /tmp is ad-hoc/unsigned.)
        let script = NSTemporaryDirectory() + "adhoc-\(UUID().uuidString).sh"
        try "#!/bin/sh\n".write(toFile: script, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: script)
        defer { try? FileManager.default.removeItem(atPath: script) }
        #expect(!SandboxedTierBRunner.isRuntimeAvailable(trampolinePath: script, allowUnsigned: false))
    }

    // MARK: - Trampoline argv construction (pure)

    @Test("trampolineArguments carries --profile, --exec and every set rlimit")
    func argvFull() {
        let argv = SandboxedTierBRunner.trampolineArguments(
            trampolinePath: "/T", profilePath: "/P.sb", execPath: "/E", limits: .default)
        #expect(argv.first == "/T")
        #expect(argv.contains("--profile")); #expect(argv.contains("/P.sb"))
        #expect(argv.contains("--exec")); #expect(argv.contains("/E"))
        // Default limits set every rlimit EXCEPT AS (0 by default — RLIMIT_AS is
        // unreliable on macOS, the corpus showed a finite cap aborts startup).
        for flag in ["--rlimit-cpu", "--rlimit-fsize", "--rlimit-nofile", "--rlimit-nproc"] {
            #expect(argv.contains(flag), "missing \(flag)")
        }
        #expect(!argv.contains("--rlimit-as"))   // AS not set by default
        // fork-deny default is NPROC=1
        if let i = argv.firstIndex(of: "--rlimit-nproc") { #expect(argv[i + 1] == "1") }
        // …but an explicit AS limit IS carried.
        let withAS = SandboxedTierBRunner.trampolineArguments(
            trampolinePath: "/T", profilePath: "/P.sb", execPath: "/E",
            limits: SandboxedTierBRunner.ResourceLimits(addressSpaceBytes: 1 << 30))
        #expect(withAS.contains("--rlimit-as"))
    }

    @Test("trampolineArguments omits a flag whose limit is 0 (leave inherited)")
    func argvOmitsZero() {
        let limits = SandboxedTierBRunner.ResourceLimits(
            cpuSeconds: 0, addressSpaceBytes: 0, maxProcesses: 0, maxOpenFiles: 0, maxFileSizeBytes: 0)
        let argv = SandboxedTierBRunner.trampolineArguments(
            trampolinePath: "/T", profilePath: "/P.sb", execPath: "/E", limits: limits)
        #expect(!argv.contains("--rlimit-cpu"))
        #expect(!argv.contains("--rlimit-nproc"))
        #expect(argv == ["/T", "--profile", "/P.sb", "--exec", "/E"])
    }

    // MARK: - Trampoline SBPL shape

    @Test("compileTrampolineDenyDefault is deny-default AND grants exec of the self-exec target")
    func trampolineProfileShape() {
        let spec = SandboxProfileSpec(fileReadSubpaths: ["/Users/x/Library/Safari"])
        let sbpl = SandboxProfileBuilder.compileTrampolineDenyDefault(spec, selfExecPath: "/tmp/verified-binary")
        #expect(sbpl.contains("(deny default)"))
        #expect(sbpl.contains("(allow process-exec* (literal \"/tmp/verified-binary\"))"))
        #expect(sbpl.contains("(allow file-read* (literal \"/tmp/verified-binary\"))"))
        // manifest read still flows through
        #expect(sbpl.contains("/Users/x/Library/Safari"))
        // fork/network stay denied by default (no fork allow, no manifest network)
        #expect(!sbpl.contains("(allow process-fork)"))
    }

    @Test("trampoline self-exec path is SBPL-quoted (no literal break-out)")
    func trampolineProfileQuoting() {
        let sbpl = SandboxProfileBuilder.compileTrampolineDenyDefault(
            SandboxProfileSpec(), selfExecPath: "/tmp/ev\"il")
        // The embedded quote must be escaped, not left to close the literal.
        #expect(sbpl.contains("\\\""))
        #expect(!sbpl.contains("(literal \"/tmp/ev\"il\")"))
    }
}
