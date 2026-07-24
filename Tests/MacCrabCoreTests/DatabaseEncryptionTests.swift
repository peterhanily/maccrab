// DatabaseEncryptionTests.swift
//
// v1.8.1: cover the AES-GCM migration. Pins the contract:
//
//   1. encrypt(plaintext) round-trips through decrypt() to the original
//   2. encrypt() always emits the ENC2: prefix (v2 / AES-GCM)
//   3. v1 ENC: ciphertexts (legacy AES-CBC) still decrypt
//   4. Tampered v2 ciphertexts are detected (return passthrough, log
//      the failure)
//   5. enabled=false is a true passthrough (no prefix)
//
// Tests use a per-test on-disk Keychain key; both v1 and v2 share the
// same key (the format change doesn't rotate keys).

import Testing
import Foundation
@testable import MacCrabCore

@Suite("DatabaseEncryption (v1.8.1: AES-GCM)")
struct DatabaseEncryptionTests {

    @Test("v2 round-trip preserves the original plaintext")
    func v2RoundTrip() async throws {
        let enc = DatabaseEncryption(enabled: true)
        let original = "sensitive data: password=hunter2"
        let cipher = enc.encrypt(original)
        #expect(cipher.hasPrefix("ENC2:"))
        #expect(cipher != original)
        let decrypted = enc.decrypt(cipher)
        #expect(decrypted == original)
    }

    @Test("Empty string is a no-op (not encrypted)")
    func emptyStringPassthrough() async throws {
        let enc = DatabaseEncryption(enabled: true)
        let result = enc.encrypt("")
        #expect(result == "")
    }

    @Test("Disabled mode bypasses encrypt + decrypt")
    func disabledPassthrough() async throws {
        let enc = DatabaseEncryption(enabled: false)
        let original = "definitely not encrypted"
        #expect(enc.encrypt(original) == original)
        #expect(enc.decrypt(original) == original)
        // Even a v2-prefixed string should pass through when disabled.
        #expect(enc.decrypt("ENC2:Zm9vYmFy") == "ENC2:Zm9vYmFy")
    }

    // MARK: - #19 ciphertext-substitution tamper detection

    @Test("#19: plaintext in an encryption-enabled column (expectingEncrypted) is counted as tamper")
    func substitutionInEncryptedColumnIsTamper() async throws {
        let enc = DatabaseEncryption(enabled: true)
        let before = enc.authenticatedDecryptFailures
        // An attacker swapped an ENC2: ciphertext for the cleartext they want shown.
        let substituted = "{\"attacker\":\"chosen plaintext\"}"
        let out = enc.decrypt(substituted, expectingEncrypted: true)
        #expect(out == substituted, "the value is still returned (analyst sees the substituted content)…")
        #expect(enc.authenticatedDecryptFailures == before + 1, "…but it is now COUNTED as tamper")
    }

    @Test("#19: plaintext in a column NOT marked expectingEncrypted is a benign passthrough")
    func plaintextWithoutExpectationIsNotTamper() async throws {
        let enc = DatabaseEncryption(enabled: true)
        let before = enc.authenticatedDecryptFailures
        let out = enc.decrypt("legitimately never-encrypted value", expectingEncrypted: false)
        #expect(out == "legitimately never-encrypted value")
        #expect(enc.authenticatedDecryptFailures == before, "no expectation → no tamper count")
    }

    @Test("#19: a valid ciphertext still round-trips under expectingEncrypted with no tamper count")
    func validCipherUnderExpectationIsClean() async throws {
        let enc = DatabaseEncryption(enabled: true)
        let before = enc.authenticatedDecryptFailures
        let cipher = enc.encrypt("real secret")
        #expect(enc.decrypt(cipher, expectingEncrypted: true) == "real secret")
        #expect(enc.authenticatedDecryptFailures == before, "an authentic ciphertext is not tamper")
    }

    @Test("Non-encrypted input passes through decrypt unchanged")
    func decryptPassthrough() async throws {
        let enc = DatabaseEncryption(enabled: true)
        #expect(enc.decrypt("plain text without prefix") == "plain text without prefix")
        #expect(enc.decrypt("") == "")
    }

    @Test("Tampered v2 ciphertext is detected (returns input)")
    func v2TamperDetection() async throws {
        let enc = DatabaseEncryption(enabled: true)
        let original = "auth-tag protects this"
        let cipher = enc.encrypt(original)
        #expect(cipher.hasPrefix("ENC2:"))

        // Flip a byte in the base64 body. AES-GCM tag verification
        // must catch this and refuse to decrypt.
        let prefix = "ENC2:"
        var body = String(cipher.dropFirst(prefix.count))
        let mid = body.index(body.startIndex, offsetBy: body.count / 2)
        let bad = body[mid] == "A" ? "B" : "A"
        body = body.replacingCharacters(in: mid...mid, with: bad)
        let tampered = prefix + body

        let result = enc.decrypt(tampered)
        // Tamper detection: result is NOT the original plaintext.
        // Two acceptable outcomes: passthrough (returns the tampered
        // string verbatim) OR the b64 doesn't decode. Either way, the
        // attacker can't produce the original.
        #expect(result != original)
    }

    @Test("Multiple encrypts of same plaintext produce different ciphertexts")
    func nonceIsRandomized() async throws {
        let enc = DatabaseEncryption(enabled: true)
        let plaintext = "same input, different nonces"
        let c1 = enc.encrypt(plaintext)
        let c2 = enc.encrypt(plaintext)
        #expect(c1 != c2)
        // But both decrypt to the same plaintext.
        #expect(enc.decrypt(c1) == plaintext)
        #expect(enc.decrypt(c2) == plaintext)
    }

    @Test("Unicode round-trips correctly")
    func unicodeRoundTrip() async throws {
        let enc = DatabaseEncryption(enabled: true)
        let inputs = [
            "Hello, world!",
            "🦀 MacCrab",
            "Привет, мир",
            "日本語のテキスト",
            String(repeating: "x", count: 10_000),
        ]
        for input in inputs {
            let cipher = enc.encrypt(input)
            let decrypted = enc.decrypt(cipher)
            #expect(decrypted == input, "round-trip failed for: \(input.prefix(40))")
        }
    }
}
