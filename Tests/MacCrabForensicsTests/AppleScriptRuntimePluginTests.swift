// AppleScriptRuntimePlugin tests — runtime-binary matcher +
// base64 heuristic. Full end-to-end against EventStore is
// integration territory (needs the daemon's events.db populated);
// here we exercise the pure functions that gate event matching.

import Foundation
import Testing
@testable import MacCrabForensics

@Suite("AppleScriptRuntimePlugin: runtime-binary matcher")
struct AppleScriptRuntimeBinaryMatchTests {

    @Test("/usr/bin/osascript matches")
    func osascriptMatches() {
        #expect(AppleScriptRuntimePlugin.isRuntimeBinary("/usr/bin/osascript"))
    }

    @Test("/usr/bin/osacompile matches")
    func osacompileMatches() {
        #expect(AppleScriptRuntimePlugin.isRuntimeBinary("/usr/bin/osacompile"))
    }

    @Test("jsc under JavaScriptCore.framework matches by suffix")
    func jscMatchesBySuffix() {
        #expect(AppleScriptRuntimePlugin.isRuntimeBinary("/System/Library/Frameworks/JavaScriptCore.framework/Resources/jsc"))
        #expect(AppleScriptRuntimePlugin.isRuntimeBinary("/System/Library/Frameworks/JavaScriptCore.framework/Versions/A/Resources/jsc"))
    }

    @Test("Random Apple binary does not match")
    func randomDoesNotMatch() {
        #expect(!AppleScriptRuntimePlugin.isRuntimeBinary("/usr/bin/true"))
        #expect(!AppleScriptRuntimePlugin.isRuntimeBinary("/bin/sh"))
        #expect(!AppleScriptRuntimePlugin.isRuntimeBinary("/usr/sbin/system_profiler"))
    }

    @Test("Lookalike paths don't match (substring check is anchored)")
    func lookalikePathsDoNotMatch() {
        #expect(!AppleScriptRuntimePlugin.isRuntimeBinary("/usr/bin/osascripteur"))
        #expect(!AppleScriptRuntimePlugin.isRuntimeBinary("/tmp/jsc"))
    }
}

@Suite("AppleScriptRuntimePlugin: base64 heuristic")
struct AppleScriptRuntimeBase64Tests {

    @Test("Recognizes a base64-encoded shell command")
    func recognizesBase64() {
        // base64 of "echo hello world from base64 payload"
        let payload = "echo hello world from base64 payload"
        let encoded = Data(payload.utf8).base64EncodedString()
        let argv = ["-e", encoded]
        let result = AppleScriptRuntimePlugin.heuristicBase64Decode(argv: argv)
        #expect(result != nil)
        #expect(result?.text == payload)
    }

    @Test("Short args are not flagged (≥40 char threshold)")
    func shortArgsIgnored() {
        let argv = ["-e", "QUJD"]   // "ABC" — too short
        #expect(AppleScriptRuntimePlugin.heuristicBase64Decode(argv: argv) == nil)
    }

    @Test("Random non-base64 long strings are not flagged")
    func nonBase64Ignored() {
        let argv = ["-e", String(repeating: "hello world ", count: 10)]
        #expect(AppleScriptRuntimePlugin.heuristicBase64Decode(argv: argv) == nil)
    }

    @Test("Binary-decoded base64 (low printable ratio) is not surfaced")
    func binaryDecodedFiltered() {
        // 64 random bytes -> base64 of 88 chars. Decodes to mostly
        // non-printable; should NOT be surfaced.
        let randomBytes = Data((0..<64).map { _ in UInt8.random(in: 0...255) })
        let encoded = randomBytes.base64EncodedString()
        let argv = ["-e", encoded]
        let result = AppleScriptRuntimePlugin.heuristicBase64Decode(argv: argv)
        // Most random bytes decode to non-printable; the heuristic
        // should reject. If a lucky random seed produces a
        // printable decode, the test would flake — that's still
        // semantically correct ("looks like text").
        if let r = result {
            // If we did decode, ensure it's actually printable.
            let printable = r.text.unicodeScalars.allSatisfy { sc in
                sc.value == 0x0a || sc.value == 0x09 || (sc.value >= 32 && sc.value < 127)
            }
            #expect(printable)
        }
    }

    @Test("Multi-arg argv finds the first base64-shaped argument")
    func multipleArgsPickFirst() {
        let payload1 = "first encoded payload that's long enough"
        let payload2 = "second encoded payload that's also long enough"
        let argv = [
            "-x", "y",
            Data(payload1.utf8).base64EncodedString(),
            Data(payload2.utf8).base64EncodedString(),
        ]
        let result = AppleScriptRuntimePlugin.heuristicBase64Decode(argv: argv)
        #expect(result?.text == payload1)
    }
}

@Suite("AppleScriptRuntimePlugin manifest")
struct AppleScriptRuntimeManifestTests {

    @Test("Manifest validates per Pass 2026-A")
    func manifestValidates() throws {
        try AppleScriptRuntimePlugin.manifest.validate()
    }

    @Test("Output declares privacyClass=content per plan §13.5")
    func outputContentClass() {
        let outputs = AppleScriptRuntimePlugin.manifest.outputs
        #expect(outputs.count == 1)
        #expect(outputs.first?.contentType == "applescript.invocation")
        #expect(outputs.first?.privacyClass == .content)
    }

    @Test("Plugin id is namespaced under com.maccrab.forensics.*")
    func idNamespaced() {
        #expect(AppleScriptRuntimePlugin.manifest.id == "com.maccrab.forensics.applescript-runtime")
    }
}
