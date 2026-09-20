import Foundation
import Testing
@testable import MacCrabCore

@Suite("Event privacy ASCII matcher policy equivalence")
struct EventPrivacySanitizerASCIIMatcherTests {
    // Deliberately retain the pre-optimization search policy as an independent,
    // slow oracle. A matcher implementation must not decide privacy policy.
    private static let hints = [
        "password", "passwd", "secret", "token", "credential",
        "bearer", "authorization", "api-key", "api_key", "apikey",
        "access-key", "access_key", "private-key", "private_key",
        "key", "auth", "://", "-p", "sk-", "aiza", "akia",
        "asia", "agpa", "aida", "aroa", "aipa", "anpa", "anva",
        "asca", "ghp_", "gho_", "ghu_", "ghs_", "ghr_",
        "github_pat_", "xoxa-", "xoxb-", "xoxo-", "xoxp-",
        "xoxr-", "xoxs-", "npm_", "pmak-", "whsec_", "sg.",
        "key-", "cf", "dop_v1_", "hrku-", "vrcl_", "vercel_", "eyj",
        "sk_live_", "sk_test_", "pk_live_", "pk_test_", "rk_live_", "rk_test_",
    ]
    private static let sensitiveKeys = [
        "password", "passwd", "secret", "token", "apikey", "authorization",
        "credential", "privatekey", "accesskey", "cookie",
    ]

    private func referenceHint(_ value: String) -> Bool {
        let lowered = value.lowercased()
        if value.utf8.count < 8 {
            return lowered.contains("-p") || lowered.contains("key")
                || lowered.contains("auth") || lowered.contains("://")
        }
        if value.utf8.allSatisfy({ $0 < 128 }) {
            let search = lowered as NSString
            let original = value as NSString
            return Self.hints.contains { search.range(of: $0, options: .literal).location != NSNotFound }
                || original.range(of: "SK", options: .literal).location != NSNotFound
                || original.range(of: "AC", options: .literal).location != NSNotFound
        }
        return Self.hints.contains { lowered.contains($0) }
            || lowered.hasPrefix("-p") || value.contains("SK") || value.contains("AC")
    }

    private func referenceSensitiveKey(_ key: String) -> Bool {
        let normalized = key.lowercased().filter { $0.isLetter || $0.isNumber }
        return Self.sensitiveKeys.contains { normalized.contains($0) }
    }

    private func check(_ value: String) {
        #expect(EventPrivacySanitizer.mayContainCredential(value) == referenceHint(value))
        #expect(EventPrivacySanitizer.isSensitiveKey(value) == referenceSensitiveKey(value))
    }

    @Test("all hints preserve short boundaries, overlaps, ASCII case and embedded NUL")
    func hintBoundaries() {
        for hint in Self.hints + ["SK", "AC", "sk", "ac"] {
            for spelling in [hint, hint.uppercased(), "a" + hint, hint + hint] {
                for prefix in ["", "x", "xxxxxxx", "ordinary\0", String(repeating: "x", count: 64)] {
                    for suffix in ["", "x", "\0ordinary"] { check(prefix + spelling + suffix) }
                }
            }
        }
        for value in ["", "\r\n", "SKxxxxx", "SKxxxxxx", "ACxxxxx", "ACxxxxxx",
                      "xxx-pxx", "xxx-pxxx", "pass\0word", "pass\r\nword",
                      "aaaaapikey", "privateprivatekey", "authorizationauth"] { check(value) }
        for key in Self.sensitiveKeys {
            for separator in ["_", "-", ".", "\0", "\r\n", " "] {
                check(key.uppercased().map(String.init).joined(separator: separator))
            }
        }
    }

    @Test("deterministic ASCII corpus agrees with the prior predicates")
    func asciiDifferentialCorpus() {
        var seed: UInt64 = 0x4d616343726162
        func next() -> UInt64 {
            seed = seed &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
            return seed
        }
        for index in 0..<4_096 {
            let length = Int(next() >> 32) % 128
            var bytes = (0..<length).map { _ in UInt8(truncatingIfNeeded: next() >> 32) & 127 }
            if index % 4 == 0 {
                let hint = Self.hints[Int(next() >> 32) % Self.hints.count]
                bytes.insert(contentsOf: hint.utf8, at: Int(next() >> 32) % (bytes.count + 1))
            }
            check(String(decoding: bytes, as: UTF8.self))
        }
    }

    @Test("Unicode anywhere selects the original whole-string policy")
    func unicodeFallback() {
        let fragments = ["caf\u{00e9}", "cafe\u{0301}", "\u{212a}", "\u{0130}",
                         "🦀", "\u{00a0}", "ＰＡＳＳＷＯＲＤ", "\u{0301}"]
        for hint in Self.hints + ["SK", "AC", "ordinary", "api_key"] {
            for unicode in fragments {
                for value in [unicode + hint, hint + unicode, "prefix " + hint + "\0" + unicode,
                              "xxx" + unicode + hint + "suffix"] { check(value) }
            }
        }
    }

    @Test("dynamic maps retain redaction and deterministic sanitized-key collisions")
    func mapPolicy() {
        let first = "Bearer " + String(repeating: "A", count: 24)
        let second = "Bearer " + String(repeating: "B", count: 24)
        let source = [first: "first", second: "second", "api_\u{212a}ey": "fixture-value",
                      "ordinary": "caf\u{00e9} --password=fixture-value", "path": "/ordinary/path"]
        let safe = EventPrivacySanitizer.sanitizeDynamicMap(source)
        #expect(safe["Bearer [REDACTED]"] == "first")
        #expect(safe["api_\u{212a}ey"] == "[REDACTED]")
        #expect(safe.keys.contains { Array($0.utf8) == Array("api_\u{212a}ey".utf8) })
        #expect(safe["ordinary"] == "caf\u{00e9} --password=[REDACTED]")
        #expect(safe["path"] == "/ordinary/path")
        #expect(safe.count == 4)
    }
}
