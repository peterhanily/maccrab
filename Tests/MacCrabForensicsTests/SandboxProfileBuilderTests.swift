// SandboxProfileBuilder tests — verifies the SBPL output for
// known shape variants. The actual macOS sandbox acceptance test
// requires loading the profile via App Sandbox + XPC, which is
// beyond pure unit-test scope.

import Foundation
import Testing
@testable import MacCrabForensics

@Suite("SandboxProfileBuilder")
struct SandboxProfileBuilderTests {

    @Test("Default-deny profile produces (deny default) directive")
    func defaultDeny() {
        let spec = SandboxProfileSpec(allowAllByDefault: false)
        let out = SandboxProfileBuilder.compile(spec)
        #expect(out.contains("(deny default)"))
        #expect(!out.contains("(allow default)"))
    }

    @Test("Default-allow profile produces (allow default) directive")
    func defaultAllow() {
        let spec = SandboxProfileSpec(allowAllByDefault: true)
        let out = SandboxProfileBuilder.compile(spec)
        #expect(out.contains("(allow default)"))
        #expect(!out.contains("(deny default)"))
    }

    @Test("File-read subpath compiles to file-read* allow")
    func fileReadCompiles() {
        let spec = SandboxProfileSpec(fileReadSubpaths: ["/tmp/maccrab-test"])
        let out = SandboxProfileBuilder.compile(spec)
        #expect(out.contains("(allow file-read* (subpath \"/tmp/maccrab-test\"))"))
    }

    @Test("Process-exec allow + process-fork enables when set")
    func processExecCompiles() {
        let spec = SandboxProfileSpec(
            processExecPaths: ["/usr/bin/codesign", "/usr/bin/otool"],
            allowProcessFork: true
        )
        let out = SandboxProfileBuilder.compile(spec)
        #expect(out.contains("(allow process-fork)"))
        #expect(out.contains("(allow process-exec (literal \"/usr/bin/codesign\"))"))
        #expect(out.contains("(allow process-exec (literal \"/usr/bin/otool\"))"))
    }

    @Test("Network endpoint allowlist produces network-outbound rules")
    func networkAllowlist() {
        let spec = SandboxProfileSpec(networkConnectAllowlist: ["api.example.com:443"])
        let out = SandboxProfileBuilder.compile(spec)
        #expect(out.contains("(allow network-outbound (remote ip \"api.example.com:443\"))"))
    }

    @Test("Mach service connects produce mach-lookup rules")
    func machServiceConnects() {
        let spec = SandboxProfileSpec(machServiceConnects: ["com.apple.distnoted.service"])
        let out = SandboxProfileBuilder.compile(spec)
        #expect(out.contains("(allow mach-lookup (global-name \"com.apple.distnoted.service\"))"))
    }

    @Test("Embedded quote in path is escaped")
    func quotedPathEscaping() {
        let spec = SandboxProfileSpec(fileReadSubpaths: ["/tmp/path with \"quote\""])
        let out = SandboxProfileBuilder.compile(spec)
        #expect(out.contains("\\\"quote\\\""))
    }

    @Test("Example Safari read-only profile compiles to a complete SBPL document")
    func exampleProfile() {
        let spec = SandboxProfileBuilder.exampleSafariReadOnlyProfile()
        let out = SandboxProfileBuilder.compile(spec)
        #expect(out.hasPrefix("(version 1)"))
        #expect(out.contains("Library/Safari"))
        #expect(out.contains("(deny default)"))
    }
}
