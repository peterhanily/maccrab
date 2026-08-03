// RuleChannelSecurityTests.swift
// Direct adversarial coverage of the shipped maccrabctl rule-channel verifier.
// The test target imports the executable target, so these tests exercise the
// production parser/staging policy rather than a copied approximation.

import Testing
import Foundation
import CryptoKit
import MacCrabCore
import MacCrabForensics
@testable import maccrabctl

@Suite("maccrabctl: signed rule-channel security policy")
struct RuleChannelSecurityTests {

    private let manifestURL = URL(string: "https://rave.maccrab.invalid/rules/rules-manifest.json")!

    private func rule(_ id: String) -> [String: Any] {
        [
            "id": id,
            "title": "Rule-channel fixture \(id)",
            "description": "direct verifier fixture",
            "level": "low",
            "suppressible": true,
            "tags": ["attack.discovery"],
            "logsource": ["category": "file_event", "product": "macos"],
            "predicates": [[
                "field": "file.path",
                "modifier": "contains",
                "values": ["/maccrab-rule-channel-fixture/"],
                "negate": false,
            ]],
            "condition": "all_of",
            "falsepositives": ["test fixture"],
            "enabled": true,
            "status": "experimental",
        ]
    }

    private func manifestData(serial: Any = 7, ruleIDs: [String]) throws -> Data {
        let rules = ruleIDs.map(rule)
        return try JSONSerialization.data(withJSONObject: [
            "serial": serial,
            "corpus_version": "security-test",
            "rules": rules,
        ], options: [.sortedKeys])
    }

    private func manifestData(serial: Int = 7, ruleCount: Int) throws -> Data {
        try manifestData(
            serial: serial,
            ruleIDs: (0..<ruleCount).map { "pushed.test.\($0)" }
        )
    }

    private func expectManifestTooLarge(
        _ operation: () throws -> RuleChannelManifest,
        maximum: Int,
        actual: Int
    ) {
        do {
            _ = try operation()
            Issue.record("oversized signed manifest unexpectedly passed")
        } catch let error as RuleChannelError {
            guard case .manifestTooLarge(let gotMaximum, let gotActual) = error else {
                Issue.record("expected manifestTooLarge, got \(error)")
                return
            }
            #expect(gotMaximum == maximum)
            #expect(gotActual == actual)
        } catch {
            Issue.record("expected RuleChannelError.manifestTooLarge, got \(error)")
        }
    }

    private func expectRuleCountExceeded(
        _ operation: () throws -> RuleChannelManifest,
        maximum: Int,
        actual: Int
    ) {
        do {
            _ = try operation()
            Issue.record("over-count signed manifest unexpectedly passed")
        } catch let error as RuleChannelError {
            guard case .ruleCountExceeded(let gotMaximum, let gotActual) = error else {
                Issue.record("expected ruleCountExceeded, got \(error)")
                return
            }
            #expect(gotMaximum == maximum)
            #expect(gotActual == actual)
        } catch {
            Issue.record("expected RuleChannelError.ruleCountExceeded, got \(error)")
        }
    }

    @Test("production ceilings are explicit and a signed manifest exactly at injected boundaries verifies")
    func manifestLimitBoundaryAccepted() throws {
        #expect(RuleChannelLimits.production.maximumManifestBytes == 8_388_608)
        #expect(RuleChannelLimits.production.maximumRuleCount == 2_048)

        let privateKey = Curve25519.Signing.PrivateKey()
        let data = try manifestData(ruleCount: 2)
        let signature = try privateKey.signature(for: data)
        let parsed = try RuleChannelFetcher.verifyAndParseManifest(
            manifestData: data,
            signature: signature,
            publicKey: privateKey.publicKey,
            manifestURL: manifestURL,
            limits: RuleChannelLimits(
                maximumManifestBytes: data.count,
                maximumRuleCount: 2
            )
        )
        #expect(parsed.serial == 7)
        #expect(parsed.rules.count == 2)
    }

    @Test("network body accumulator refuses max+1 without retaining the excess byte")
    func streamingAccumulatorIsHardBounded() {
        var body = RuleChannelBodyAccumulator(maximumBytes: 2)
        let acceptedFirst = body.append(0x41)
        let acceptedSecond = body.append(0x42)
        let acceptedExcess = body.append(0x43)
        #expect(acceptedFirst)
        #expect(acceptedSecond)
        #expect(!acceptedExcess)
        #expect(body.data == Data([0x41, 0x42]))
    }

    @Test("detached signature must be exactly 64 bytes before CryptoKit verification")
    func signatureLengthIsExact() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let data = try manifestData(ruleCount: 1)
        let shortSignature = Data(repeating: 0, count: 63)
        do {
            _ = try RuleChannelFetcher.verifyAndParseManifest(
                manifestData: data,
                signature: shortSignature,
                publicKey: privateKey.publicKey,
                manifestURL: manifestURL
            )
            Issue.record("63-byte signature unexpectedly passed")
        } catch let error as RuleChannelError {
            guard case .signatureSizeInvalid(let expected, let actual) = error else {
                Issue.record("expected signatureSizeInvalid, got \(error)")
                return
            }
            #expect(expected == 64)
            #expect(actual == 63)
        }
    }

    @Test("a cryptographically valid manifest one byte over the byte ceiling is refused before parse/staging")
    func signedOversizedManifestRejected() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let data = try manifestData(ruleCount: 1)
        let signature = try privateKey.signature(for: data)
        let maximum = data.count - 1

        expectManifestTooLarge({
            try RuleChannelFetcher.verifyAndParseManifest(
                manifestData: data,
                signature: signature,
                publicKey: privateKey.publicKey,
                manifestURL: manifestURL,
                limits: RuleChannelLimits(
                    maximumManifestBytes: maximum,
                    maximumRuleCount: 10
                )
            )
        }, maximum: maximum, actual: data.count)
    }

    @Test("a cryptographically valid manifest above the decoded-rule ceiling is refused as one unit")
    func signedOverCountManifestRejected() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let data = try manifestData(ruleCount: 2)
        let signature = try privateKey.signature(for: data)

        expectRuleCountExceeded({
            try RuleChannelFetcher.verifyAndParseManifest(
                manifestData: data,
                signature: signature,
                publicKey: privateKey.publicKey,
                manifestURL: manifestURL,
                limits: RuleChannelLimits(
                    maximumManifestBytes: data.count,
                    maximumRuleCount: 1
                )
            )
        }, maximum: 1, actual: 2)
    }

    @Test("serial must be a nonnegative JSON integer, not bool, float, or negative")
    func serialShapeRejected() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let invalidSerials: [Any] = [true, 1.5, -1]
        for invalid in invalidSerials {
            let data = try manifestData(serial: invalid, ruleIDs: ["pushed.test.serial"])
            let signature = try privateKey.signature(for: data)
            do {
                _ = try RuleChannelFetcher.verifyAndParseManifest(
                    manifestData: data,
                    signature: signature,
                    publicKey: privateKey.publicKey,
                    manifestURL: manifestURL
                )
                Issue.record("invalid serial \(invalid) unexpectedly passed")
            } catch let error as RuleChannelError {
                guard case .manifestParseFailed(let reason) = error else {
                    Issue.record("invalid serial \(invalid): expected manifestParseFailed, got \(error)")
                    continue
                }
                #expect(reason.contains("nonnegative JSON integer"))
            }
        }

        // Zero is a real, nonnegative integer and remains a valid bootstrap
        // serial even though publication policy normally starts above zero.
        let zeroData = try manifestData(serial: 0, ruleIDs: ["pushed.test.zero"])
        let zeroSignature = try privateKey.signature(for: zeroData)
        let zero = try RuleChannelFetcher.verifyAndParseManifest(
            manifestData: zeroData,
            signature: zeroSignature,
            publicKey: privateKey.publicKey,
            manifestURL: manifestURL
        )
        #expect(zero.serial == 0)
    }

    @Test("duplicate rule ids reject the entire signed manifest before staging")
    func duplicateRuleIDsRejected() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let data = try manifestData(serial: 8, ruleIDs: ["pushed.test.duplicate", "pushed.test.duplicate"])
        let signature = try privateKey.signature(for: data)
        do {
            _ = try RuleChannelFetcher.verifyAndParseManifest(
                manifestData: data,
                signature: signature,
                publicKey: privateKey.publicKey,
                manifestURL: manifestURL
            )
            Issue.record("duplicate rule ids unexpectedly passed")
        } catch let error as RuleChannelError {
            guard case .ruleValidationFailed(let index, let reason) = error else {
                Issue.record("expected ruleValidationFailed, got \(error)")
                return
            }
            #expect(index == 1)
            #expect(reason.contains("duplicate rule id"))
        }
    }

    @Test("rules-channel serial policy distinguishes equal from shared >= semantics")
    func rulesSerialDisposition() {
        #expect(RuleChannelFetcher.serialDisposition(stored: nil, incoming: 4) == .firstSeen)
        #expect(RuleChannelFetcher.serialDisposition(stored: 4, incoming: 5) == .newer)
        #expect(RuleChannelFetcher.serialDisposition(stored: 4, incoming: 4) == .unchanged)
        #expect(RuleChannelFetcher.serialDisposition(stored: 4, incoming: 3)
                == .rollback(stored: 4, incoming: 3))
    }

    @Test("different bytes reusing an accepted serial leave staged rules and trust state byte-identical")
    func equalSerialIsNoOp() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-rule-equal-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let trust = RaveTrustStateStore(path: root.appendingPathComponent("trust.json").path)
        try trust.recordRulesManifest(serial: 41)

        let pushed = root.appendingPathComponent("pushed", isDirectory: true)
        try FileManager.default.createDirectory(at: pushed, withIntermediateDirectories: true)
        let originalURL = pushed.appendingPathComponent("original.json")
        let originalBytes = Data(#"{"id":"original","sentinel":"must-survive"}"#.utf8)
        try originalBytes.write(to: originalURL)

        let privateKey = Curve25519.Signing.PrivateKey()
        let fetcher = RuleChannelFetcher(
            rulesBase: manifestURL.deletingLastPathComponent(),
            rulesPublicKey: privateKey.publicKey,
            trustState: trust
        )
        let replacementBytes = try JSONSerialization.data(withJSONObject: rule("replacement"))
        let incoming = RuleChannelManifest(
            serial: 41,
            corpusVersion: "different-same-serial",
            minMaccrabVersion: nil,
            rules: [(id: "replacement", json: replacementBytes)]
        )

        let result = try fetcher.applyVerifiedManifest(incoming, into: pushed)
        #expect(result == .unchanged(serial: 41))
        #expect(trust.load().rulesManifestSerial == 41)
        #expect(try FileManager.default.contentsOfDirectory(atPath: pushed.path) == ["original.json"])
        #expect(try Data(contentsOf: originalURL) == originalBytes)
        #expect(!FileManager.default.fileExists(atPath: pushed.appendingPathComponent("replacement.json").path))
    }

    @Test("an injected directory-replacement failure preserves prior bytes and serial")
    func replacementFailureRollsBackCleanly() throws {
        struct InjectedFailure: Error {}

        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-rule-replace-fail-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let trust = RaveTrustStateStore(path: root.appendingPathComponent("trust.json").path)
        try trust.recordRulesManifest(serial: 9)
        let pushed = root.appendingPathComponent("pushed", isDirectory: true)
        try FileManager.default.createDirectory(at: pushed, withIntermediateDirectories: true)
        let originalURL = pushed.appendingPathComponent("original.json")
        let originalBytes = Data("prior accepted corpus".utf8)
        try originalBytes.write(to: originalURL)

        let privateKey = Curve25519.Signing.PrivateKey()
        let fetcher = RuleChannelFetcher(
            rulesBase: manifestURL.deletingLastPathComponent(),
            rulesPublicKey: privateKey.publicKey,
            trustState: trust
        )
        let incoming = RuleChannelManifest(
            serial: 10,
            corpusVersion: "replacement-must-fail",
            minMaccrabVersion: nil,
            rules: [(id: "new", json: Data(#"{"id":"new"}"#.utf8))]
        )

        do {
            _ = try fetcher.applyVerifiedManifest(
                incoming,
                into: pushed,
                replacingDirectoryWith: { _, _, _ in throw InjectedFailure() }
            )
            Issue.record("injected replacement failure unexpectedly succeeded")
        } catch is InjectedFailure {
            // expected
        }

        #expect(trust.load().rulesManifestSerial == 9)
        #expect(try FileManager.default.contentsOfDirectory(atPath: pushed.path) == ["original.json"])
        #expect(try Data(contentsOf: originalURL) == originalBytes)
    }

    @Test("native atomic directory swap installs a newer corpus and advances serial")
    func nativeAtomicSwapHappyPath() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-rule-swap-ok-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let trust = RaveTrustStateStore(path: root.appendingPathComponent("trust.json").path)
        try trust.recordRulesManifest(serial: 3)
        let pushed = root.appendingPathComponent("pushed", isDirectory: true)
        try FileManager.default.createDirectory(at: pushed, withIntermediateDirectories: true)
        try Data("old".utf8).write(to: pushed.appendingPathComponent("old.json"))

        let privateKey = Curve25519.Signing.PrivateKey()
        let fetcher = RuleChannelFetcher(
            rulesBase: manifestURL.deletingLastPathComponent(),
            rulesPublicKey: privateKey.publicKey,
            trustState: trust
        )
        let newBytes = Data(#"{"id":"new","sentinel":"new-corpus"}"#.utf8)
        let incoming = RuleChannelManifest(
            serial: 4,
            corpusVersion: "new",
            minMaccrabVersion: nil,
            rules: [(id: "new", json: newBytes)]
        )

        let result = try fetcher.applyVerifiedManifest(incoming, into: pushed)
        #expect(result == .installed(serial: 4, ruleCount: 1))
        #expect(trust.load().rulesManifestSerial == 4)
        #expect(try FileManager.default.contentsOfDirectory(atPath: pushed.path) == ["new.json"])
        #expect(try Data(contentsOf: pushed.appendingPathComponent("new.json")) == newBytes)
    }

    @Test("production constructor fails closed before input, key, or network work")
    func productionChannelIsDisabledBeforeFetch() {
        #expect(!RuleChannelPolicy.productionEnabled)
        do {
            _ = try RuleChannelFetcher(rulesBase: "://deliberately-invalid")
            Issue.record("disabled production rule channel unexpectedly constructed a fetcher")
        } catch let error as RuleChannelError {
            guard case .channelDisabled = error else {
                Issue.record("expected channelDisabled before URL/key lookup, got \(error)")
                return
            }
            #expect(error.description.contains("before key lookup or any network request"))
            #expect(error.description.contains("preserved but ignored"))
        } catch {
            Issue.record("expected RuleChannelError.channelDisabled, got \(error)")
        }
    }

    @Test("network boundary rejects even an internally injected fetcher while disabled")
    func injectedFetcherCannotReachNetwork() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-rule-disabled-fetch-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let privateKey = Curve25519.Signing.PrivateKey()
        let fetcher = RuleChannelFetcher(
            rulesBase: URL(string: "https://network-must-not-run.invalid/")!,
            rulesPublicKey: privateKey.publicKey,
            trustState: RaveTrustStateStore(path: root.appendingPathComponent("trust.json").path)
        )

        do {
            _ = try await fetcher.fetchVerifiedManifest()
            Issue.record("disabled network boundary unexpectedly fetched")
        } catch let error as RuleChannelError {
            guard case .channelDisabled = error else {
                Issue.record("expected channelDisabled at network boundary, got \(error)")
                return
            }
        } catch {
            Issue.record("expected RuleChannelError.channelDisabled, got \(error)")
        }
    }

    @Test("unreachable missing-key diagnostic refuses substitution of unknown authority")
    func missingAnchorDiagnosticIsHonest() {
        let message = RuleChannelError.noRulesPublicKey.description
        #expect(message.contains("enabled the signed rule-update channel"))
        #expect(message.contains("internally inconsistent or corrupt"))
        #expect(message.contains("Do not substitute an unverified key"))
    }
}
