// RaveSignerPin (O1b publisher-key pin, S2-01/02) policy tests.
//
// The pin binds the catalog-endorsed signer_public_key_sha256 to the bundle's
// own signing.key.pub hash. Cases:
//   - pin matches the bundle key → install proceeds
//   - pin mismatches → reject (.mismatch)
//   - pin absent on an official channel → reject (.absentOnOfficial)  [FAIL-CLOSED]
//   - pin absent on a pre-release entry WITH opt-in → proceeds
//   - pin absent on a pre-release entry WITHOUT opt-in → reject [FAIL-CLOSED]
//   - pin set but bundle key unreadable → reject (.missingBundleKey)
//   - empty-string pin treated as absent
//   - isSHA256Hex shape validation

import Testing
import Foundation
import CryptoKit
@testable import MacCrabForensics

@Suite("RaveSignerPin (O1b publisher-key pin)")
struct RaveSignerPinTests {

    /// A real Ed25519 public key's raw bytes + the hex-lower sha256 of those
    /// bytes (which is what the catalog pin encodes).
    static func keyAndPin() -> (keyData: Data, pin: String) {
        let key = Curve25519.Signing.PrivateKey().publicKey.rawRepresentation
        let pin = RaveSignerPin.sha256Hex(key)
        return (key, pin)
    }

    @Test("pin matches bundle key → proceeds")
    func matchProceeds() throws {
        let (keyData, pin) = Self.keyAndPin()
        // Must not throw.
        try RaveSignerPin.enforce(
            expectedPin: pin,
            status: "official",
            pluginID: "com.test.match",
            bundleKeyData: keyData,
            allowUnpinnedPrerelease: false
        )
    }

    @Test("pin mismatch → reject")
    func mismatchRejected() {
        let (keyData, _) = Self.keyAndPin()
        let wrongPin = String(repeating: "a", count: 64)
        #expect(throws: RaveSignerPinError.self) {
            try RaveSignerPin.enforce(
                expectedPin: wrongPin,
                status: "official",
                pluginID: "com.test.mismatch",
                bundleKeyData: keyData,
                allowUnpinnedPrerelease: false
            )
        }
        // Confirm the specific error shape carries expected/actual.
        do {
            try RaveSignerPin.enforce(
                expectedPin: wrongPin, status: "official", pluginID: "x",
                bundleKeyData: keyData, allowUnpinnedPrerelease: false)
            Issue.record("expected mismatch to throw")
        } catch let e as RaveSignerPinError {
            guard case .mismatch(let expected, let actual) = e else {
                Issue.record("expected .mismatch, got \(e)"); return
            }
            #expect(expected == wrongPin)
            #expect(actual == RaveSignerPin.sha256Hex(keyData))
        } catch { Issue.record("unexpected error \(error)") }
    }

    @Test("pin absent on official channel → FAIL-CLOSED")
    func absentOfficialFailsClosed() {
        let (keyData, _) = Self.keyAndPin()
        for status in [nil, "official", "stable", "released"] as [String?] {
            #expect(throws: RaveSignerPinError.self) {
                try RaveSignerPin.enforce(
                    expectedPin: nil,
                    status: status,
                    pluginID: "com.test.absent",
                    bundleKeyData: keyData,
                    allowUnpinnedPrerelease: true  // opt-in is irrelevant off pre-release
                )
            }
        }
    }

    @Test("pin absent on pre-release WITH opt-in → proceeds")
    func absentPrereleaseOptInProceeds() throws {
        let (keyData, _) = Self.keyAndPin()
        try RaveSignerPin.enforce(
            expectedPin: nil,
            status: "pre-release",
            pluginID: "com.test.prerelease",
            bundleKeyData: keyData,
            allowUnpinnedPrerelease: true
        )
    }

    @Test("pin absent on pre-release WITHOUT opt-in → FAIL-CLOSED")
    func absentPrereleaseNoOptInFails() {
        let (keyData, _) = Self.keyAndPin()
        #expect(throws: RaveSignerPinError.self) {
            try RaveSignerPin.enforce(
                expectedPin: nil,
                status: "pre-release",
                pluginID: "com.test.prerelease",
                bundleKeyData: keyData,
                allowUnpinnedPrerelease: false
            )
        }
    }

    @Test("empty-string pin treated as absent (fail-closed on official)")
    func emptyPinIsAbsent() {
        let (keyData, _) = Self.keyAndPin()
        #expect(throws: RaveSignerPinError.self) {
            try RaveSignerPin.enforce(
                expectedPin: "",
                status: "official",
                pluginID: "com.test.empty",
                bundleKeyData: keyData,
                allowUnpinnedPrerelease: false
            )
        }
    }

    @Test("pin set but bundle key unreadable → reject")
    func missingBundleKeyRejected() {
        let (_, pin) = Self.keyAndPin()
        #expect(throws: RaveSignerPinError.self) {
            try RaveSignerPin.enforce(
                expectedPin: pin,
                status: "official",
                pluginID: "com.test.nokey",
                bundleKeyData: nil,
                allowUnpinnedPrerelease: false
            )
        }
    }

    @Test("isSHA256Hex validates shape")
    func sha256HexShape() {
        #expect(RaveSignerPin.isSHA256Hex(String(repeating: "0", count: 64)))
        #expect(RaveSignerPin.isSHA256Hex("07e39eb12c15b8052f5249134ea3337a0789ebc799d1c58d097aaa548a8aaae3"))
        #expect(!RaveSignerPin.isSHA256Hex(String(repeating: "0", count: 63)))  // too short
        #expect(!RaveSignerPin.isSHA256Hex(String(repeating: "0", count: 65)))  // too long
        #expect(!RaveSignerPin.isSHA256Hex("07E39EB12C15B8052F5249134EA3337A0789EBC799D1C58D097AAA548A8AAAE3")) // uppercase
        #expect(!RaveSignerPin.isSHA256Hex(String(repeating: "g", count: 64)))  // non-hex
    }
}
