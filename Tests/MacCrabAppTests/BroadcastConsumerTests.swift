// BroadcastConsumerTests.swift
// MacCrabAppTests
//
// Proves the (dormant) broadcast consumer's safety pipeline before any store
// broadcast is ever rendered: Ed25519 verify-before-parse, strict unknown-field
// rejection, caps, sanitization (bidi/zero-width/confusable/length),
// link-validation (scheme/host/IDN/userinfo), anti-rollback, expiry, and the
// fail-closed contract (every bad input → nil / throw → bundled feed kept).

import Testing
import Foundation
import CryptoKit
@testable import MacCrabApp

// MARK: - Test helpers

private func tempPath(_ name: String) -> String {
    NSTemporaryDirectory() + "maccrab-bcast-test-\(name)-\(UUID().uuidString).json"
}

private func sign(_ json: String, with key: Curve25519.Signing.PrivateKey) -> (Data, Data) {
    let data = Data(json.utf8)
    let sig = try! key.signature(for: data)
    return (data, sig)
}

private func makeClient(key: Curve25519.Signing.PublicKey?,
                        statePath: String,
                        enabled: Bool = true) -> BroadcastClient {
    BroadcastClient(
        baseURL: URL(string: "https://rave.maccrab.com/")!,
        publicKey: key,
        transport: SecureBroadcastTransport(),   // unused — tests call makeItems directly
        trustState: BroadcastTrustStateStore(path: statePath),
        isEnabled: enabled)
}

private let validFeed = """
{"feedVersion":1,"sequence":10,"issuedAt":"2026-06-24T10:00:00Z",\
"expiresAt":"2026-07-08T10:00:00Z",\
"items":[{"id":"a","title":"Signed plugin catalog","summary":"Browse the catalog.","badge":"Update"}]}
"""
private let refNow = ISO8601DateFormatter().date(from: "2026-06-24T11:00:00Z")!

// MARK: - Signature gate

@Suite("Broadcast: signature gate")
struct BroadcastSignatureTests {
    @Test("valid signature → items returned")
    func validSig() throws {
        let priv = Curve25519.Signing.PrivateKey()
        let (data, sig) = sign(validFeed, with: priv)
        let client = makeClient(key: priv.publicKey, statePath: tempPath("sig"))
        let items = try client.makeItems(from: data, signature: sig, now: refNow)
        #expect(items.count == 1)
        #expect(items.first?.title == "Signed plugin catalog")
        #expect(items.first?.badge == "Update")
    }

    @Test("wrong key → signatureInvalid (fail closed)")
    func wrongKey() {
        let priv = Curve25519.Signing.PrivateKey()
        let (data, sig) = sign(validFeed, with: priv)
        let attacker = Curve25519.Signing.PrivateKey()
        let client = makeClient(key: attacker.publicKey, statePath: tempPath("wrongkey"))
        #expect(throws: BroadcastError.self) {
            _ = try client.makeItems(from: data, signature: sig, now: refNow)
        }
    }

    @Test("tampered body after signing → rejected")
    func tamperedBody() {
        let priv = Curve25519.Signing.PrivateKey()
        let (_, sig) = sign(validFeed, with: priv)
        let tampered = Data(validFeed.replacingOccurrences(of: "Browse the catalog.",
                                                           with: "Re-authenticate now!").utf8)
        let client = makeClient(key: priv.publicKey, statePath: tempPath("tamper"))
        #expect(throws: BroadcastError.self) {
            _ = try client.makeItems(from: tampered, signature: sig, now: refNow)
        }
    }

    @Test("no key → noKey (dormant build path)")
    func noKey() {
        let priv = Curve25519.Signing.PrivateKey()
        let (data, sig) = sign(validFeed, with: priv)
        let client = makeClient(key: nil, statePath: tempPath("nokey"))
        #expect(throws: BroadcastError.self) {
            _ = try client.makeItems(from: data, signature: sig, now: refNow)
        }
    }
}

// MARK: - Strict decode

@Suite("Broadcast: strict decode")
struct BroadcastDecodeTests {
    private func signedClient() -> (Curve25519.Signing.PrivateKey, BroadcastClient) {
        let priv = Curve25519.Signing.PrivateKey()
        return (priv, makeClient(key: priv.publicKey, statePath: tempPath("decode")))
    }

    @Test("unknown top-level field → rejected (no smuggled action field)")
    func unknownTopLevel() {
        let (priv, client) = signedClient()
        let json = """
        {"feedVersion":1,"sequence":1,"issuedAt":"2026-06-24T10:00:00Z","action":"install","items":[]}
        """
        let (data, sig) = sign(json, with: priv)
        #expect(throws: BroadcastError.self) {
            _ = try client.makeItems(from: data, signature: sig, now: refNow)
        }
    }

    @Test("unknown per-item field → rejected")
    func unknownItemField() {
        let (priv, client) = signedClient()
        let json = """
        {"feedVersion":1,"sequence":1,"issuedAt":"2026-06-24T10:00:00Z",\
        "items":[{"id":"a","title":"t","summary":"s","onTap":"evil"}]}
        """
        let (data, sig) = sign(json, with: priv)
        #expect(throws: BroadcastError.self) {
            _ = try client.makeItems(from: data, signature: sig, now: refNow)
        }
    }

    @Test("unknown feedVersion → rejected")
    func unknownVersion() {
        let (priv, client) = signedClient()
        let json = """
        {"feedVersion":99,"sequence":1,"issuedAt":"2026-06-24T10:00:00Z","items":[]}
        """
        let (data, sig) = sign(json, with: priv)
        #expect(throws: BroadcastError.self) {
            _ = try client.makeItems(from: data, signature: sig, now: refNow)
        }
    }

    @Test("too many items → rejected")
    func tooManyItems() {
        let (priv, client) = signedClient()
        let itemsArr = (0..<11).map { "{\"id\":\"\($0)\",\"title\":\"t\",\"summary\":\"s\"}" }.joined(separator: ",")
        let json = """
        {"feedVersion":1,"sequence":1,"issuedAt":"2026-06-24T10:00:00Z","items":[\(itemsArr)]}
        """
        let (data, sig) = sign(json, with: priv)
        #expect(throws: BroadcastError.self) {
            _ = try client.makeItems(from: data, signature: sig, now: refNow)
        }
    }

    @Test("bad timestamp → rejected")
    func badTimestamp() {
        let (priv, client) = signedClient()
        let json = """
        {"feedVersion":1,"sequence":1,"issuedAt":"yesterday","items":[]}
        """
        let (data, sig) = sign(json, with: priv)
        #expect(throws: BroadcastError.self) {
            _ = try client.makeItems(from: data, signature: sig, now: refNow)
        }
    }
}

// MARK: - Sanitizer

@Suite("Broadcast: sanitizer")
struct BroadcastSanitizerTests {
    @Test("strips bidi override + zero-width")
    func stripsBidi() {
        let raw = "Hello\u{202E}dlrow\u{200B}!"
        let out = BroadcastSanitizer.stripDangerous(raw)
        #expect(!out.unicodeScalars.contains { $0.value == 0x202E })
        #expect(!out.unicodeScalars.contains { $0.value == 0x200B })
    }

    @Test("refuses Latin/Cyrillic confusable mix")
    func refusesConfusable() {
        // "аpple" — leading Cyrillic 'а' (U+0430) mixed with Latin.
        #expect(BroadcastSanitizer.sanitizeTitle("\u{0430}pple security") == nil)
    }

    @Test("allows ordinary Latin + CJK")
    func allowsNormal() {
        #expect(BroadcastSanitizer.sanitizeTitle("What's new") != nil)
        #expect(BroadcastSanitizer.sanitizeTitle("新着情報") != nil)
    }

    @Test("caps by grapheme and byte length")
    func caps() {
        let zalgo = String(repeating: "a\u{0301}\u{0301}\u{0301}\u{0301}", count: 200)
        let out = BroadcastSanitizer.sanitizeTitle(zalgo)
        #expect(out != nil)
        #expect(out!.utf8.count <= BroadcastLimits.maxTitleBytes)
        #expect(out!.count <= BroadcastLimits.maxTitleGraphemes)
    }
}

// MARK: - Link validator

@Suite("Broadcast: link validator")
struct BroadcastLinkTests {
    @Test("allows exact allow-listed https host")
    func allows() {
        let v = BroadcastLinkValidator.validate("https://maccrab.com/store")
        #expect(v?.host == "maccrab.com")
    }

    @Test("rejects non-https scheme")
    func rejectsScheme() {
        #expect(BroadcastLinkValidator.validate("http://maccrab.com/") == nil)
        #expect(BroadcastLinkValidator.validate("maccrab://install") == nil)
    }

    @Test("rejects userinfo @ trick")
    func rejectsUserinfo() {
        #expect(BroadcastLinkValidator.validate("https://evil.com@maccrab.com/x") == nil)
    }

    @Test("rejects non-allow-listed + suffix tricks")
    func rejectsHostTricks() {
        #expect(BroadcastLinkValidator.validate("https://evil.com/") == nil)
        #expect(BroadcastLinkValidator.validate("https://maccrab.com.evil.com/") == nil)
        #expect(BroadcastLinkValidator.validate("https://evil-maccrab.com/") == nil)
        #expect(BroadcastLinkValidator.validate("https://support.apple.com/") == nil)
    }

    @Test("rejects non-default port")
    func rejectsPort() {
        #expect(BroadcastLinkValidator.validate("https://maccrab.com:8443/") == nil)
    }
}

// MARK: - Anti-rollback + expiry

@Suite("Broadcast: anti-rollback + expiry")
struct BroadcastRollbackTests {
    @Test("rejects a lower sequence after a higher one was accepted")
    func rejectsRollback() throws {
        let priv = Curve25519.Signing.PrivateKey()
        let statePath = tempPath("rollback")
        let client = makeClient(key: priv.publicKey, statePath: statePath)

        // Accept sequence 10.
        let (d10, s10) = sign(validFeed, with: priv)
        _ = try client.makeItems(from: d10, signature: s10, now: refNow)

        // Replay sequence 5 → rollback.
        let lower = validFeed.replacingOccurrences(of: "\"sequence\":10", with: "\"sequence\":5")
        let (d5, s5) = sign(lower, with: priv)
        #expect(throws: BroadcastError.self) {
            _ = try client.makeItems(from: d5, signature: s5, now: refNow)
        }
    }

    @Test("same sequence re-accepted (idempotent)")
    func sameSequence() throws {
        let priv = Curve25519.Signing.PrivateKey()
        let client = makeClient(key: priv.publicKey, statePath: tempPath("same"))
        let (d, s) = sign(validFeed, with: priv)
        _ = try client.makeItems(from: d, signature: s, now: refNow)
        let items = try client.makeItems(from: d, signature: s, now: refNow)
        #expect(items.count == 1)
    }

    @Test("expired feed → no items")
    func expired() throws {
        let priv = Curve25519.Signing.PrivateKey()
        let client = makeClient(key: priv.publicKey, statePath: tempPath("exp"))
        let (d, s) = sign(validFeed, with: priv)
        let wayLater = ISO8601DateFormatter().date(from: "2026-09-01T10:00:00Z")!
        let items = try client.makeItems(from: d, signature: s, now: wayLater)
        #expect(items.isEmpty)
    }

    @Test("future-skewed issuedAt → rejected")
    func futureSkew() {
        let priv = Curve25519.Signing.PrivateKey()
        let client = makeClient(key: priv.publicKey, statePath: tempPath("skew"))
        let (d, s) = sign(validFeed, with: priv)
        let earlier = ISO8601DateFormatter().date(from: "2026-06-24T09:00:00Z")!  // before issuedAt
        #expect(throws: BroadcastError.self) {
            _ = try client.makeItems(from: d, signature: s, now: earlier)
        }
    }
}

// MARK: - Dormant contract

/// Records whether the transport was ever asked to fetch — proves the dormant
/// guards short-circuit BEFORE any network attempt.
private final class SpyTransport: BroadcastTransport, @unchecked Sendable {
    private(set) var called = false
    func fetch(_ url: URL, maxBytes: Int) async throws -> Data {
        called = true
        throw BroadcastError.fetchFailed(0)
    }
}

@Suite("Broadcast: dormant contract")
struct BroadcastDormantTests {
    @Test("disabled → fetchNews returns nil and the transport is never called")
    func disabled() async {
        let priv = Curve25519.Signing.PrivateKey()
        let spy = SpyTransport()
        let client = BroadcastClient(
            baseURL: URL(string: "https://rave.maccrab.com/")!,
            publicKey: priv.publicKey, transport: spy,
            trustState: BroadcastTrustStateStore(path: tempPath("off")), isEnabled: false)
        let result = await client.fetchNews(now: refNow)
        #expect(result == nil)
        #expect(spy.called == false)
    }

    @Test("enabled but no key → fetchNews returns nil and the transport is never called")
    func enabledNoKey() async {
        let spy = SpyTransport()
        let client = BroadcastClient(
            baseURL: URL(string: "https://rave.maccrab.com/")!,
            publicKey: nil, transport: spy,
            trustState: BroadcastTrustStateStore(path: tempPath("offkey")), isEnabled: true)
        let result = await client.fetchNews(now: refNow)
        #expect(result == nil)
        #expect(spy.called == false)
    }

    @Test("no broadcast.pub bundled in this build (feature stays dormant)")
    func noBundledKey() {
        #expect(BroadcastClient.loadBundledKey(bundle: .main) == nil)
    }

    @Test("badge outside the closed enum is dropped")
    func badgeAllowList() throws {
        let priv = Curve25519.Signing.PrivateKey()
        let client = makeClient(key: priv.publicKey, statePath: tempPath("badge"))
        let json = validFeed.replacingOccurrences(of: "\"badge\":\"Update\"", with: "\"badge\":\"Security\"")
        let (d, s) = sign(json, with: priv)
        let items = try client.makeItems(from: d, signature: s, now: refNow)
        #expect(items.first?.badge == nil)
    }
}
