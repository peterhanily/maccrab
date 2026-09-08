import Foundation
import Testing
@testable import MacCrabCore

@Suite("Event privacy literal-search compatibility")
struct EventPrivacySanitizerLiteralSearchTests {
    private func directRedaction(_ value: String) -> String {
        OTLPAttributeSanitizer.redactCredentialShapes(CommandSanitizer.sanitize(value))
    }

    @Test("ASCII credentials reach both redactors at the beginning, middle and end of long values")
    func asciiCredentialPositions() {
        let padding = String(repeating: "ordinary observation ", count: 100)
        let fixtures: [(String, String)] = [
            ("--PaSsWoRd='fixture-value'", "--PaSsWoRd=[REDACTED]"),
            ("Bearer\tFixtureToken42", "Bearer\t[REDACTED]"),
            ("KEY='x'", "KEY=[REDACTED]"),
            ("AKIA" + String(repeating: "Z", count: 16), "[REDACTED_AWS_KEY]"),
            ("sk_live_" + String(repeating: "F", count: 24), "[STRIPE_KEY]"),
            ("SK" + String(repeating: "a", count: 32), "[TWILIO_KEY]"),
            ("AC" + String(repeating: "b", count: 32), "[TWILIO_SID]"),
        ]
        for (raw, replacement) in fixtures {
            for (prefix, suffix) in [("", " " + padding), (padding, " " + padding),
                                     (padding, ""), (padding + "\0 ", " \0" + padding)] {
                let input = prefix + raw + suffix
                let expected = prefix + replacement + suffix
                // Explicit output checks keep this fixture independent of the
                // candidate gate and prove that a real redactor was exercised.
                #expect(directRedaction(input) == expected)
                #expect(EventPrivacySanitizer.sanitizeString(input) == expected)
            }
        }
    }

    @Test("long ordinary ASCII and near-miss credentials remain byte exact")
    func ordinaryASCIIIsPreserved() {
        let nearMisses = ["authentication keychain -port", "SK" + String(repeating: "a", count: 31),
                          "ac" + String(repeating: "b", count: 32), "pass\0word", "KEY=short"]
        let values = [0, 7, 8, 2_048, 65_536].map { String(repeating: "x", count: $0) }
            + nearMisses.map { String(repeating: "/ordinary/path ", count: 150) + $0 }
        for value in values {
            #expect(directRedaction(value) == value)
            #expect(Array(EventPrivacySanitizer.sanitizeString(value).utf8) == Array(value.utf8))
        }
    }

    @Test("Unicode normalization, case folding and whitespace retain existing redactor behavior")
    func unicodeFallbackPreservesPolicyAndBytes() {
        let contexts = ["caf\u{00e9} ", "cafe\u{0301} ", "\u{0130} 🦀\0 "]
        let credentials = ["--PASSWORD=fixture-value", "--api_\u{212a}ey=fixture-value",
                           "Bearer\u{00a0}FixtureToken42"]
        for context in contexts {
            for credential in credentials {
                let input = context + credential + " " + context
                let expected = directRedaction(input)
                #expect(expected.contains("[REDACTED]"))
                #expect(Array(EventPrivacySanitizer.sanitizeString(input).utf8) == Array(expected.utf8))
            }
        }
        for value in ["caf\u{00e9}", "cafe\u{0301}", "--passwörd=value", "ＰＡＳＳＷＯＲＤ=value"] {
            #expect(directRedaction(value) == value)
            #expect(Array(EventPrivacySanitizer.sanitizeString(value).utf8) == Array(value.utf8))
        }
    }

    @Test("credentials beyond embedded NUL cannot survive canonical event preparation")
    func canonicalEventRedactsAfterNUL() throws {
        let now = Date(timeIntervalSince1970: 1_780_000_000)
        let raw = "ASIA" + String(repeating: "Z", count: 16)
        let prefix = String(repeating: "ordinary observation ", count: 100) + "\0 "
        let value = prefix + raw
        let expected = prefix + "[AWS_ACCESS_KEY]"
        #expect(directRedaction(value) == expected)
        let event = Event(timestamp: now, eventCategory: .process, eventType: .creation,
            eventAction: "exec", process: ProcessInfo(pid: 4_242, ppid: 1, rpid: 4_242,
                name: "fixture", executable: "/usr/bin/fixture", commandLine: value,
                args: ["fixture", value], workingDirectory: "/private/tmp", userId: 501,
                userName: "tester", groupId: 20, startTime: now, envVars: ["OBSERVATION": value]),
            enrichments: ["detail": value, "unicode_detail": "cafe\u{0301} " + value])
        let result = try EventPrivacySanitizer.sanitize(event)
        let decoded = try JSONDecoder().decode(Event.self, from: result.canonicalJSON)
        #expect(decoded == result.event)
        #expect(decoded.process.commandLine == expected)
        #expect(decoded.process.args == ["fixture", expected])
        #expect(decoded.process.envVars?["OBSERVATION"] == expected)
        #expect(decoded.enrichments["detail"] == expected)
        #expect(Array((decoded.enrichments["unicode_detail"] ?? "").utf8)
                == Array(("cafe\u{0301} " + expected).utf8))
        #expect(!String(decoding: result.canonicalJSON, as: UTF8.self).contains(raw))
    }
}
