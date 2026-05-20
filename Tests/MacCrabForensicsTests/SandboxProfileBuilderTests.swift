// SandboxProfileBuilder tests — verifies the SBPL output for
// known shape variants. The actual macOS sandbox acceptance test
// requires loading the profile via App Sandbox + XPC, which is
// beyond pure unit-test scope.

import Foundation
import Testing
@testable import MacCrabForensics

@Suite("SandboxProfileBuilder")
struct SandboxProfileBuilderTests {

    @Test("Strict profile emits (allow default) + targeted denies")
    func strictProfile() {
        // SBPL is last-match-wins and a pure (deny default) at
        // the top blocks execvp before the profile takes effect.
        // The builder uses (allow default) as a baseline + emits
        // targeted denies for sensitive paths (login keychain,
        // /etc, /var/db). Manifest-declared allows come last so
        // they override the denies on overlap.
        let spec = SandboxProfileSpec(allowAllByDefault: false)
        let out = SandboxProfileBuilder.compile(spec)
        #expect(out.contains("(allow default)"))
        #expect(out.contains("/Library/Keychains"))
        #expect(out.contains("/private/etc"))
        #expect(out.contains("(deny network*)"))
    }

    @Test("Permissive profile emits only (allow default)")
    func permissiveProfile() {
        let spec = SandboxProfileSpec(allowAllByDefault: true)
        let out = SandboxProfileBuilder.compile(spec)
        #expect(out.contains("(allow default)"))
        // Permissive profile must NOT contain the targeted-deny
        // sensitive-area block — those are strict-only.
        #expect(!out.contains("(deny file-read*"))
        #expect(!out.contains("(deny network*)"))
    }

    @Test("File-read subpath compiles to file-read* allow")
    func fileReadCompiles() {
        let spec = SandboxProfileSpec(fileReadSubpaths: ["/tmp/maccrab-test"])
        let out = SandboxProfileBuilder.compile(spec)
        #expect(out.contains("(allow file-read* (subpath \"/tmp/maccrab-test\"))"))
    }

    @Test("Process-exec allowlist compiles when set")
    func processExecCompiles() {
        let spec = SandboxProfileSpec(
            processExecPaths: ["/usr/bin/codesign", "/usr/bin/otool"],
            allowProcessFork: true
        )
        let out = SandboxProfileBuilder.compile(spec)
        // process-fork is permitted by (allow default); the
        // manifest-declared process-exec allowlist appears
        // explicitly.
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
        // Strict profile baseline.
        #expect(out.contains("(allow default)"))
        #expect(out.contains("(deny file-read*"))
    }
}
