// RuleChannelFetchTests.swift
// Unit coverage for the CLIENT half of the rule-update (OTA detection) channel,
// Sources/maccrabctl/RuleChannelFetch.swift — a remote-code-of-detection path
// into the root engine whose fail-closed gates previously had no Swift unit
// tests (only scripts/test-rule-channel-e2e.sh).
//
// SCOPE / REACHABILITY NOTE. `RuleChannelFetcher` (and RuleChannelError /
// RuleChannelManifest) live in the `maccrabctl` EXECUTABLE target, which has no
// test target and cannot be @testable-imported; its verify/parse/sanitize logic
// is inline in the network-bound `fetchVerifiedManifest()`. So those methods are
// not directly callable from a unit test without a production refactor (extract
// a pure `parse+verify(manifestData:sig:) -> RuleChannelManifest`) — see the
// follow-up list. What IS reachable, and what this file pins, are the real,
// importable building blocks the channel composes, at the exact seams it uses:
//
//   - the per-rule DECODE gate — JSONDecoder().decode(CompiledRule.self, from:)
//     over the JSONSerialization bytes the manifest carries. A valid rule is
//     accepted (and its id — which becomes the on-disk `<id>.json` filename —
//     surfaced); a malformed rule THROWS, which in the channel is the fail-closed
//     `.ruleValidationFailed` that refuses the WHOLE manifest (no partial corpus).
//   - the fact that CompiledRule decode does NOT itself sanitize the rule id —
//     which is WHY the channel adds an explicit path-traversal guard before it
//     writes `<id>.json` into the pushed/ directory.
//   - the Ed25519 detached-signature contract the channel's signature gate rests
//     on: a good signature over the manifest bytes verifies; a tampered manifest
//     OR a tampered signature fails (fail-closed).
//
// ALREADY COVERED ELSEWHERE (the gates the channel delegates to — not duplicated
// here):
//   - anti-rollback serial (evaluateRulesManifest / recordRulesManifest):
//     MacCrabForensicsTests/RaveTrustStateTests.swift (rulesManifestSerial,
//     rulesSerialIndependentOfCatalog).
//   - version-floor (RaveVersionFloor.enforce):
//     MacCrabForensicsTests/RaveVersionFloorTests.swift.
//   - engine-side pushed-rule containment (additive-only, detection-only):
//     MacCrabCoreTests/RuleEnginePushedRulesTests.swift.

import Testing
import Foundation
import CryptoKit
@testable import MacCrabCore

@Suite("Rule-update channel: client verification building blocks")
struct RuleChannelFetchTests {

    private struct NoCompiledRuleFound: Error {}

    /// The JSON object of the first compiled single-event rule that decodes as a
    /// CompiledRule. Mirrors RuleEnginePushedRulesTests: compile the real corpus
    /// and operate on real rule JSON through the same JSONSerialization seam the
    /// channel uses — higher fidelity than a hand-built fixture. (Skips any
    /// non-rule top-level json such as a manifest/index file.)
    private func firstRealRuleObject() throws -> [String: Any] {
        ensureRulesCompiled()
        let dir = URL(fileURLWithPath: "/tmp/maccrab_v3")
        let files = try FileManager.default
            .contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "json" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
        for f in files {
            guard let obj = try? JSONSerialization.jsonObject(with: Data(contentsOf: f)) as? [String: Any],
                  let data = try? JSONSerialization.data(withJSONObject: obj),
                  (try? JSONDecoder().decode(CompiledRule.self, from: data)) != nil
            else { continue }
            return obj
        }
        throw NoCompiledRuleFound()
    }

    /// Re-encode + decode a mutated rule object through EXACTLY the seam
    /// fetchVerifiedManifest() uses per rule:
    ///   JSONSerialization.data(withJSONObject:) → JSONDecoder().decode(CompiledRule.self)
    private func decodeThroughChannelSeam(_ obj: [String: Any]) throws -> CompiledRule {
        let json = try JSONSerialization.data(withJSONObject: obj)
        return try JSONDecoder().decode(CompiledRule.self, from: json)
    }

    // MARK: - Per-rule decode gate (valid manifest → accepted half)

    @Test("a valid rule decodes and surfaces its id (the id becomes the <id>.json filename)")
    func validRuleDecodesAndSurfacesID() throws {
        var obj = try firstRealRuleObject()
        obj["id"] = "pushed.test.valid_rule"
        let rule = try decodeThroughChannelSeam(obj)
        #expect(rule.id == "pushed.test.valid_rule")
        // The channel writes each rule to `<id>.json`; a safe id yields a safe,
        // flat basename with no path separator to escape the pushed/ dir.
        let basename = "\(rule.id).json"
        #expect(basename == "pushed.test.valid_rule.json")
        #expect(!basename.contains("/"))
    }

    // MARK: - Per-rule decode gate (fail-closed: one bad rule refuses the manifest)

    @Test("a rule missing a required field is REJECTED by the decode gate (fail-closed)")
    func missingRequiredFieldRejected() throws {
        var obj = try firstRealRuleObject()
        obj.removeValue(forKey: "title")   // `title` is a required, non-optional field
        // In the channel this throw becomes .ruleValidationFailed → the WHOLE
        // manifest is refused (no partial corpus).
        #expect(throws: DecodingError.self) {
            _ = try decodeThroughChannelSeam(obj)
        }
    }

    @Test("a rule with an invalid severity value is REJECTED by the decode gate (fail-closed)")
    func invalidSeverityRejected() throws {
        var obj = try firstRealRuleObject()
        obj["level"] = "not-a-real-severity"   // Severity is a closed String enum
        #expect(throws: DecodingError.self) {
            _ = try decodeThroughChannelSeam(obj)
        }
    }

    // MARK: - Rule-id is not self-sanitizing (motivates the channel's path guard)

    @Test("CompiledRule decode does NOT sanitize unsafe/traversal ids — so the channel's explicit id guard is load-bearing")
    func decodeDoesNotSanitizeUnsafeIDs() throws {
        // Each of these decodes CLEANLY as a CompiledRule — the decoder places no
        // constraint on the id. The channel therefore MUST reject them itself
        // before writing `<id>.json`, or a signed-but-hostile manifest could
        // escape the pushed/ directory. This pins the contract that guard depends
        // on; the guard itself lives in maccrabctl and is a listed follow-up.
        let unsafeIDs = ["../../etc/evil", "a/b", "..\\evil", "..", ""]
        for unsafe in unsafeIDs {
            var obj = try firstRealRuleObject()
            obj["id"] = unsafe
            let rule = try decodeThroughChannelSeam(obj)
            #expect(rule.id == unsafe, "decoder should surface the id verbatim")
        }
        // Concretely: a forward-slash id yields a filename that a naive write
        // would treat as a nested path — the exact escape the guard's
        // `!id.contains("/")` check closes.
        #expect("\("a/b").json".contains("/"))
    }

    // MARK: - Ed25519 signature contract (the fail-closed signature gate)

    @Test("Ed25519 detached signature: valid over the manifest verifies; tampered manifest OR signature fails")
    func ed25519SignatureFailsClosed() throws {
        // Mirrors the channel's gate:
        //   guard rulesPublicKey.isValidSignature(sig, for: manifestData) else { throw ... }
        let priv = Curve25519.Signing.PrivateKey()
        let pub = priv.publicKey
        let manifest = Data(#"{"serial":7,"corpus_version":"x","rules":[]}"#.utf8)
        let sig = try priv.signature(for: manifest)

        // Happy path: the genuine signature over the genuine bytes verifies.
        #expect(pub.isValidSignature(sig, for: manifest))

        // Tampered manifest (one appended byte) → verification fails (fail-closed).
        var tamperedManifest = manifest
        tamperedManifest.append(0x00)
        #expect(!pub.isValidSignature(sig, for: tamperedManifest))

        // Tampered signature (one flipped byte) → verification fails (fail-closed).
        var tamperedSig = Data(sig)
        tamperedSig[0] ^= 0xFF
        #expect(!pub.isValidSignature(tamperedSig, for: manifest))

        // A DIFFERENT key's signature over the same bytes is rejected — a leaked/
        // wrong key cannot push rules (blast-radius separation of rules.pub).
        let otherSig = try Curve25519.Signing.PrivateKey().signature(for: manifest)
        #expect(!pub.isValidSignature(otherSig, for: manifest))
    }
}
