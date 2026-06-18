// SandboxDenyDefaultTests — Stream-0/1 foundation for third-party containment.
//
// Covers (a) the TierBManifest capability mapping that closes the "decorative
// manifest" gap (the manifest previously decoded only 3 of 6 capability fields
// and hardcoded allowProcessFork=true), and (b) the TEXT contract of
// SandboxProfileBuilder.compileDenyDefault — the genuine deny-default ("Model B")
// profile for UNTRUSTED third-party plugins.
//
// SCOPE: these assert the profile/spec SHAPE. The RUNTIME containment — that a
// non-allowlisted read returns EPERM while an allowlisted read succeeds when the
// profile is applied post-startup by the sandbox-host trampoline — was proven by
// the Stream-0 on-device spike (sandbox_init after startup) and becomes a corpus
// client-test once the trampoline is wired. Nothing here is wired into an
// execution path; third-party execution stays fail-closed.

import Testing
import Foundation
@testable import MacCrabForensics

@Suite("Sandbox deny-default (Model B) + manifest capability mapping")
struct SandboxDenyDefaultTests {

    static func decode(_ json: String) throws -> TierBManifest {
        try JSONDecoder().decode(TierBManifest.self, from: Data(json.utf8))
    }

    // MARK: - TierBManifest: all six capability fields (decorative-manifest fix)

    @Test("manifest decodes ALL six capability fields (was 3/6)")
    func decodesAllCapabilities() throws {
        let m = try Self.decode(#"""
        {"id":"com.x.p","displayName":"P","version":"1.0","schemaVersion":1,"description":"d",
         "fileReadSubpaths":["/a"],"fileWriteSubpaths":["/b"],"networkConnectAllowlist":["1.2.3.4:443"],
         "machServiceConnects":["com.apple.x"],"processExecPaths":["/usr/bin/true"],"allowProcessFork":true}
        """#)
        #expect(m.fileReadSubpaths == ["/a"])
        #expect(m.fileWriteSubpaths == ["/b"])
        #expect(m.networkConnectAllowlist == ["1.2.3.4:443"])
        #expect(m.machServiceConnects == ["com.apple.x"])
        #expect(m.processExecPaths == ["/usr/bin/true"])
        #expect(m.allowProcessFork == true)
    }

    @Test("omitted allowProcessFork defaults to FALSE (fail-closed)")
    func forkDefaultsFalse() throws {
        let m = try Self.decode(#"{"id":"com.x.p","displayName":"P","version":"1.0","schemaVersion":1,"description":"d"}"#)
        #expect(m.allowProcessFork == false)
        #expect(m.processExecPaths.isEmpty)
        #expect(m.machServiceConnects.isEmpty)
    }

    @Test("toSandboxProfileSpec maps all six faithfully (no hardcoded fork=true)")
    func specMappingFaithful() throws {
        let m = try Self.decode(#"""
        {"id":"com.x.p","displayName":"P","version":"1.0","schemaVersion":1,"description":"d",
         "processExecPaths":["/usr/bin/true"],"allowProcessFork":false,"machServiceConnects":["com.apple.x"]}
        """#)
        let s = m.toSandboxProfileSpec()
        #expect(s.allowAllByDefault == false)
        #expect(s.allowProcessFork == false)   // before the fix this was hardcoded true
        #expect(s.processExecPaths == ["/usr/bin/true"])
        #expect(s.machServiceConnects == ["com.apple.x"])
    }

    // MARK: - compileDenyDefault (Model B) text contract

    @Test("deny-default profile is (deny default), NOT (allow default)")
    func denyDefaultBaseline() {
        let out = SandboxProfileBuilder.compileDenyDefault(SandboxProfileSpec())
        #expect(out.contains("(deny default)"))
        #expect(!out.contains("(allow default)"))
    }

    @Test("empty spec denies fork/exec/network by omission")
    func emptyDeniesEverything() {
        let out = SandboxProfileBuilder.compileDenyDefault(SandboxProfileSpec())
        #expect(!out.contains("(allow process-fork)"))
        #expect(!out.contains("(allow process-exec"))
        #expect(!out.contains("(allow network"))
    }

    @Test("manifest allows appear; fork present only when declared")
    func manifestAllows() {
        let s = SandboxProfileSpec(
            fileReadSubpaths: ["/home/x/Library/Safari"],
            networkConnectAllowlist: ["1.2.3.4:443"],
            processExecPaths: ["/usr/bin/codesign"],
            allowProcessFork: true)
        let out = SandboxProfileBuilder.compileDenyDefault(s)
        #expect(out.contains("(deny default)"))
        #expect(out.contains(#"(allow file-read* (subpath "/home/x/Library/Safari"))"#))
        #expect(out.contains(#"(allow network-outbound (remote ip "1.2.3.4:443"))"#))
        #expect(out.contains(#"(allow process-exec (literal "/usr/bin/codesign"))"#))
        #expect(out.contains("(allow process-fork)"))
    }

    @Test("fork stays denied when not declared, even with other caps present")
    func forkDeniedUnlessDeclared() {
        let s = SandboxProfileSpec(fileReadSubpaths: ["/a"], networkConnectAllowlist: ["1.2.3.4:443"], allowProcessFork: false)
        let out = SandboxProfileBuilder.compileDenyDefault(s)
        #expect(out.contains(#"(allow file-read* (subpath "/a"))"#))
        #expect(!out.contains("(allow process-fork)"))
    }

    @Test("a malicious newline in a manifest path can't break out of the SBPL literal")
    func quotingDefendsInjection() {
        let s = SandboxProfileSpec(fileReadSubpaths: ["/a\n(allow default)"])
        let out = SandboxProfileBuilder.compileDenyDefault(s)
        // the injected (allow default) must NOT appear as a standalone directive
        #expect(!out.contains("\n(allow default)"))
        #expect(out.contains("(deny default)"))
    }
}
