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

    // MARK: - audit #4 — tightened runtime base (no escape/enumeration surface)

    @Test("no unscoped mach-lookup or system-wide process-info; named runtime base only (audit #4)")
    func tightenedRuntimeBase() {
        let out = SandboxProfileBuilder.compileDenyDefault(SandboxProfileSpec())
        // The former global escape surfaces are GONE (the named/scoped forms never
        // contain these bare substrings — they're followed by " (global"/" (target").
        #expect(!out.contains("(allow mach-lookup)"))
        #expect(!out.contains("(allow process-info*)"))
        // process-info is scoped to self; mach is a named base set.
        #expect(out.contains("(allow process-info* (target self))"))
        #expect(out.contains(#"(allow mach-lookup (global-name "com.apple.system.notification_center"))"#))
        #expect(out.contains(#"(allow mach-lookup (global-name "com.apple.trustd"))"#))
        // Exfil-adjacent services are NOT in the base.
        #expect(!out.contains("pasteboard"))
    }

    @Test("manifest mach services are ENFORCED as global-name allows (audit #4)")
    func machServicesEnforced() {
        let s = SandboxProfileSpec(machServiceConnects: ["com.acme.helper"])
        let out = SandboxProfileBuilder.compileDenyDefault(s)
        #expect(out.contains(#"(allow mach-lookup (global-name "com.acme.helper"))"#))
    }

    @Test("metadata is denied on user crown-jewels, AFTER the global allow (last-match-wins) (audit #4)")
    func crownJewelMetadataDenied() {
        let out = SandboxProfileBuilder.compileDenyDefault(SandboxProfileSpec())
        #expect(out.contains(#"(deny file-read-metadata (subpath "/Library/Keychains"))"#))
        let home = NSHomeDirectory()
        #expect(out.contains("(deny file-read-metadata (subpath \"\(home)/Library/Messages\"))"))
        #expect(out.contains("(deny file-read-metadata (subpath \"\(home)/.ssh\"))"))
        // The deny must come AFTER the global metadata allow so it wins.
        guard let allowR = out.range(of: "(allow file-read-metadata)"),
              let denyR = out.range(of: "(deny file-read-metadata") else {
            Issue.record("expected both the global metadata allow and a crown-jewel deny"); return
        }
        #expect(allowR.lowerBound < denyR.lowerBound)
    }

    // MARK: - GA-blocker: sandboxed writes are PINNED to the case/scratch dir

    @Test("brokered spec DROPS an out-of-case write (a LaunchAgent = persistence escape)")
    func brokeredWriteContainmentDropsPersistencePath() {
        // A hostile manifest declares a LaunchAgents write path. If granted verbatim
        // in the deny-default SBPL the sandboxed plugin could plant a LaunchAgent =
        // persistence, escaping the sandbox's intent. The brokered spec must pin
        // writes to the plugin's own scratch dir and DROP the persistence path.
        let m = TierBManifest(
            id: "com.x.p", displayName: "P", version: "1.0", schemaVersion: 1,
            description: "d", fileWriteSubpaths: ["/Users/victim/Library/LaunchAgents"])
        let scratch = "/private/var/folders/xx/T/maccrab-tierb-scratch-ABC"
        let spec = m.toBrokeredSandboxProfileSpec(scratchDir: scratch)
        #expect(spec.fileWriteSubpaths == [scratch])   // LaunchAgents dropped; only scratch remains
        // And it never reaches the emitted SBPL.
        let sbpl = SandboxProfileBuilder.compileDenyDefault(spec)
        #expect(!sbpl.contains("LaunchAgents"))
        #expect(sbpl.contains("(allow file-write* (subpath \"\(scratch)\"))"))
    }

    @Test("brokered spec KEEPS a legit in-case write subpath (under the scratch root)")
    func brokeredWriteContainmentKeepsInCasePath() {
        let scratch = "/private/var/folders/xx/T/maccrab-tierb-scratch-ABC"
        let inCase = scratch + "/out"
        let m = TierBManifest(
            id: "com.x.p", displayName: "P", version: "1.0", schemaVersion: 1,
            description: "d", fileWriteSubpaths: [inCase])
        let spec = m.toBrokeredSandboxProfileSpec(scratchDir: scratch)
        #expect(spec.fileWriteSubpaths.contains(inCase))   // in-case write survives
        #expect(spec.fileWriteSubpaths.contains(scratch))  // scratch is always granted
    }

    @Test("brokered spec drops system + other-user + credential writes, keeps only scratch")
    func brokeredWriteContainmentDropsAllOutOfCase() {
        let scratch = "/private/var/folders/xx/T/maccrab-tierb-scratch-ABC"
        let m = TierBManifest(
            id: "com.x.p", displayName: "P", version: "1.0", schemaVersion: 1,
            description: "d",
            fileWriteSubpaths: ["/System/Library/x", "/Users/other/Documents/x",
                                "/Users/victim/.ssh/authorized_keys", "/etc/x"])
        let spec = m.toBrokeredSandboxProfileSpec(scratchDir: scratch)
        #expect(spec.fileWriteSubpaths == [scratch])   // every out-of-case write dropped
    }
}
