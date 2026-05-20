// MCFPStatic tests — exercises arch detection, the canonical
// string format, and the per-component stability invariant
// (plan §6.4 R1 kill criterion: ≥95% same-binary stability).

import Foundation
import Testing
@testable import MacCrabForensics

@Suite("MCFPStatic")
struct MCFPStaticTests {

    @Test("Returns a canonical mcfp1/static/... string on a real binary")
    func canonicalFormat() async throws {
        let result = try await MCFPStatic.fingerprint(path: "/usr/bin/true")
        #expect(result.scheme == "mcfp1")
        #expect(result.canonical.hasPrefix("mcfp1/static/"))
        let components = result.canonical.split(separator: "/").map(String.init)
        // mcfp1, static, arch, lc, cs, ent  → 6 segments.
        #expect(components.count == 6)
        #expect(components[0] == "mcfp1")
        #expect(components[1] == "static")
    }

    @Test("Arch component is one of the known enum values")
    func archEnumerated() async throws {
        let result = try await MCFPStatic.fingerprint(path: "/usr/bin/true")
        let known: Set<String> = ["arm64", "arm64e", "x86_64", "i386", "universal", "unknown"]
        #expect(known.contains(result.archToken))
    }

    @Test("LC / CS / ENT components are 12-hex-char prefixes")
    func componentLengths() async throws {
        let result = try await MCFPStatic.fingerprint(path: "/usr/bin/true")
        #expect(result.lc.count == 12)
        #expect(result.cs.count == 12)
        #expect(result.ent.count == 12)
        // Each is hex.
        let hex = CharacterSet(charactersIn: "0123456789abcdef")
        for comp in [result.lc, result.cs, result.ent] {
            #expect(comp.unicodeScalars.allSatisfy { hex.contains($0) })
        }
    }

    @Test("Same-binary stability: two runs produce identical fingerprint (R1 kill criterion)")
    func stableAcrossRuns() async throws {
        // Plan §6.4 R1 kill criterion: ≥95% same-binary stability
        // across reboots. We don't reboot in CI; we re-run twice
        // and assert byte-identical. The cross-reboot test lives
        // in docs/mcfp-research/corpus.jsonl which is collected by
        // a nightly job, not the unit test suite.
        let first = try await MCFPStatic.fingerprint(path: "/usr/bin/true")
        let second = try await MCFPStatic.fingerprint(path: "/usr/bin/true")
        #expect(first.canonical == second.canonical)
        #expect(first.lc == second.lc)
        #expect(first.cs == second.cs)
        #expect(first.ent == second.ent)
    }

    @Test("Different system binaries produce different fingerprints")
    func differentBinariesDifferentFingerprints() async throws {
        // Two distinct Apple-shipped binaries. Their LC + CS + ENT
        // components should differ at least in `lc` (different
        // dylib dependencies) — even if CS happens to match (both
        // Apple-signed), the ENT or LC would diverge.
        let trueResult = try await MCFPStatic.fingerprint(path: "/usr/bin/true")
        let lsResult = try await MCFPStatic.fingerprint(path: "/bin/ls")
        #expect(trueResult.canonical != lsResult.canonical)
    }

    @Test("Throws fileNotFound for an absent path")
    func throwsOnMissingFile() async throws {
        await #expect(throws: MCFPStaticError.self) {
            _ = try await MCFPStatic.fingerprint(path: "/var/empty/no-such-binary-\(UUID().uuidString)")
        }
    }

    @Test("hex12 helper returns a 12-char hex string")
    func hex12HelperLength() {
        let h = MCFPStatic.hex12(of: "hello")
        #expect(h.count == 12)
        let hex = CharacterSet(charactersIn: "0123456789abcdef")
        #expect(h.unicodeScalars.allSatisfy { hex.contains($0) })
    }

    @Test("hex12 helper is deterministic")
    func hex12HelperDeterministic() {
        #expect(MCFPStatic.hex12(of: "abc") == MCFPStatic.hex12(of: "abc"))
        #expect(MCFPStatic.hex12(of: "abc") != MCFPStatic.hex12(of: "abd"))
    }

    @Test("Empty string hashes to the well-known sha256 prefix")
    func emptyStringHash() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4...
        #expect(MCFPStatic.hex12(of: "") == "e3b0c44298fc")
    }
}
