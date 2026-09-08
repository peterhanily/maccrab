import Foundation
import Testing
@testable import MacCrabCore

@Suite("Event privacy Stripe coverage")
struct EventPrivacySanitizerStripeTests {
    // Frozen preceding policy reproduces the missed admission without
    // changing the production predicate's private access.
    private let originalHints = [
        "password", "passwd", "secret", "token", "credential",
        "bearer ", "authorization", "api-key", "api_key", "apikey",
        "access-key", "access_key", "private-key", "private_key",
        "key=", "auth=", "://", " -p", "sk-", "aiza", "akia",
        "asia", "agpa", "aida", "aroa", "aipa", "anpa", "anva",
        "asca", "ghp_", "gho_", "ghu_", "ghs_", "ghr_",
        "github_pat_", "xoxa-", "xoxb-", "xoxo-", "xoxp-",
        "xoxr-", "xoxs-", "npm_", "pmak-", "whsec_", "sg.",
        "key-", "cf", "dop_v1_", "hrku-", "vrcl_", "vercel_",
        "eyj",
    ]

    private func originalGate(_ value: String) -> Bool {
        guard value.utf8.count >= 8 else {
            return value.hasPrefix("-p") || value.contains(" -p")
        }
        let lowered = value.lowercased()
        return originalHints.contains { lowered.contains($0) }
            || lowered.hasPrefix("-p")
            || value.contains("SK") || value.contains("AC")
    }

    @Test("the explicit Stripe policy expansion admits all six existing redactor prefixes")
    func stripePrefixPolicyExpansion() {
        for kind in ["sk", "pk", "rk"] {
            for mode in ["live", "test"] {
                // Build deliberately invalid synthetic token shapes at runtime.
                let prefix = kind + "_" + mode + "_"
                let raw = prefix + String(repeating: "F", count: 24)
                #expect(!originalGate(raw), "This fixture must reproduce the preceding gate omission")
                let direct = OTLPAttributeSanitizer.redactCredentialShapes(CommandSanitizer.sanitize(raw))
                #expect(direct == "[STRIPE_KEY]")
                for context in ["", "ordinary\0 ", "🦀 "] {
                    let input = context + raw
                    let expected = OTLPAttributeSanitizer.redactCredentialShapes(CommandSanitizer.sanitize(input))
                    let actual = EventPrivacySanitizer.sanitizeString(input)
                    #expect(actual == expected && actual == context + direct)
                    #expect(!actual.contains(raw))
                }
                // The gate admits a candidate; the unchanged redactor still
                // owns the complete token shape and its minimum length.
                let tooShort = prefix + String(repeating: "F", count: 23)
                #expect(EventPrivacySanitizer.sanitizeString(tooShort) == tooShort)
            }
        }
    }

    @Test("previously missed Stripe values cannot survive canonical event preparation")
    func stripeCanonicalEventRedaction() throws {
        let tokens = ["sk", "pk", "rk"].flatMap { kind in
            ["live", "test"].map { mode in kind + "_" + mode + "_" + String(repeating: "F", count: 24) }
        }
        let joined = tokens.joined(separator: " ")
        #expect(!originalGate(joined))
        let now = Date(timeIntervalSince1970: 1_780_000_000)
        let source = Event(timestamp: now, eventCategory: .process, eventType: .creation,
            eventAction: "exec", process: ProcessInfo(pid: 4_242, ppid: 1, rpid: 4_242,
                name: "fixture", executable: "/usr/bin/fixture", commandLine: "fixture " + joined,
                args: ["fixture"] + tokens, workingDirectory: "/private/tmp", userId: 501,
                userName: "tester", groupId: 20, startTime: now, ancestors: [],
                isPlatformBinary: false, envVars: ["OBSERVATION": joined]),
            enrichments: ["detail": joined, "unicode_detail": "🦀 " + joined])
        let prepared = try EventJournalAdmissionValidator.prepare(source)
        let markers = Array(repeating: "[STRIPE_KEY]", count: tokens.count)
        #expect(prepared.overflow == nil)
        #expect(prepared.event.process.commandLine == "fixture " + markers.joined(separator: " "))
        #expect(prepared.event.process.args == ["fixture"] + markers)
        #expect(prepared.event.process.envVars?["OBSERVATION"] == markers.joined(separator: " "))
        #expect(prepared.event.enrichments["detail"] == markers.joined(separator: " "))
        #expect(prepared.event.enrichments["unicode_detail"] == "🦀 " + markers.joined(separator: " "))
        let canonical = String(decoding: prepared.canonicalJSON, as: UTF8.self)
        for raw in tokens { #expect(!canonical.contains(raw)) }
        #expect(try JSONDecoder().decode(Event.self, from: prepared.canonicalJSON) == prepared.event)
    }
}
