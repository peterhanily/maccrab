import Foundation
import Testing
@testable import MacCrabCore

@Suite("Event privacy supported credential syntax")
struct EventPrivacySanitizerSyntaxTests {
    private var fixtures: [String] {
        [
            "Bearer\t" + String(repeating: "X", count: 24),
            "Bearer\n" + String(repeating: "X", count: 24),
            "Bearer\tx", // Minimum eight-byte bearer form.
            "--auth hunter2", "--auth = hunter2", "--key = hunter2",
            "--accesskey hunter2", "--accesskey = hunter2",
            "KEY_NAME=huntertwo", "AUTH_NAME=huntertwo", "KEY = huntertwo",
            "AUTH = huntertwo", "KEY2=huntertwo", "AUTH2=huntertwo",
            "--key " + String(repeating: "X", count: 24),
            "mysql\t-pS3cret!", "mysql\n-pS3cret!", "mysql\t-p'hunter2'",
            "mysql\t-p\"hunter2\"", "prefix-p'hunter2'", "\t-p'x'",
            "--key=x", "KEY='x'", "KEY=\"x\"", "://a:b@",
        ]
    }

    private func directRedaction(_ value: String) -> String {
        OTLPAttributeSanitizer.redactCredentialShapes(CommandSanitizer.sanitize(value))
    }

    @Test("every identified gate omission reaches the existing redactors")
    func supportedSyntaxReachesRedactors() {
        for (index, value) in fixtures.enumerated() {
            let expected = directRedaction(value)
            #expect(expected != value, "Fixture \(index) must exercise an actual existing redactor")
            #expect(expected.contains("[REDACTED]"))
            #expect(EventPrivacySanitizer.sanitizeString(value) == expected,
                    "Candidate gate omitted supported fixture \(index)")
        }
        // Broader admission must not itself blank ordinary evidence.
        for value in ["monkey", "keychain", "authentication", "bearer", "-port",
                      "/Users/fixture/keynotes.txt", "KEY=short", "AUTH=short"] {
            #expect(directRedaction(value) == value)
            #expect(EventPrivacySanitizer.sanitizeString(value) == value)
        }
    }

    @Test("supported syntax is redacted from free-form canonical event fields")
    func supportedSyntaxAtRest() throws {
        let now = Date(timeIntervalSince1970: 1_780_000_000)
        for (index, value) in fixtures.enumerated() {
            let expected = directRedaction(value)
            let source = Event(timestamp: now, eventCategory: .process, eventType: .creation,
                eventAction: "exec", process: ProcessInfo(pid: 4_242, ppid: 1, rpid: 4_242,
                    name: "fixture", executable: "/usr/bin/fixture", commandLine: value,
                    args: [], workingDirectory: "/private/tmp", userId: 501, userName: "tester",
                    groupId: 20, startTime: now, envVars: ["OBSERVATION": value]),
                enrichments: ["detail": value])
            let prepared = try EventJournalAdmissionValidator.prepare(source)
            #expect(prepared.overflow == nil)
            let decoded = try JSONDecoder().decode(Event.self, from: prepared.canonicalJSON)
            #expect(decoded == prepared.event)
            #expect(decoded.process.commandLine == expected, "Command fixture \(index)")
            #expect(decoded.process.envVars?["OBSERVATION"] == expected, "Environment fixture \(index)")
            #expect(decoded.enrichments["detail"] == expected, "Enrichment fixture \(index)")
        }
    }
}
