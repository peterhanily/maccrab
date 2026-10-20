import Foundation
import Testing
@testable import MacCrabCore

/// The redactor memo replays only what the pure redactors produce, stays
/// bounded, and never stores a raw input.
@Suite("Digest-keyed redaction memo")
struct DigestKeyedStringMemoTests {
    private static let samples: [String] = [
        "mysql -uroot -p'hunter2' -h db.internal", "mysql -uroot -p\"hunter2\"", "mysql -uroot -pS3cret!",
        "curl --password=hunter2 https://example.com", "tool --token abcdefghijklmnop",
        "git clone https://user:pa55word@github.com/org/repo.git", "export AWS=AKIAABCDEFGHIJKLMNOP", // secret-scan:allow synthetic AWS-key-shaped fixture, not a credential
        "gh auth ghp_abcdefghijklmnopqrstuvwxyz0123456789AB", "curl -H 'Authorization: Bearer abc.def-ghi'", // secret-scan:allow synthetic GitHub-token-shaped fixture, not a credential
        "API_KEY=abcdefgh12345678 ./run.sh", "deploy --secret=QUJDREVGR0hJSktMTU5PUFFSU1RVVg==",
        "--ſecret=hunter2", "--\u{212A}EY=hunter2", "node build.js --mode production", "/usr/bin/true",
        "sk-proj-abcdefghijklmnopqrstuvwxyz", "postgres://admin:pw@10.0.0.5:5432/app", "",
        String(repeating: "x --password=hunter2 ", count: 300),  // above the memo's input bound
    ]

    /// The argv walk over the uncached redactor suite, so memoized argv
    /// output is checked against the suite rather than against itself.
    private static func referenceArguments(_ arguments: [String]) -> [String] {
        CommandSanitizer.sanitize(arguments: arguments, leaf: CommandSanitizer.applyRedactors)
    }

    @Test("command redaction replays exactly what the redactor suite produces")
    func commandParity() {
        for sample in Self.samples {
            let expected = CommandSanitizer.applyRedactors(sample)
            #expect(CommandSanitizer.sanitize(sample) == expected, "\(sample.prefix(60))")
            #expect(CommandSanitizer.sanitize(sample) == expected, "replay: \(sample.prefix(60))")
            let arguments = sample.split(separator: " ").map(String.init) + ["--", "user:pw@x", "AKIAABCDEFGHIJKLMNOP"] // secret-scan:allow synthetic AWS-key-shaped fixture, not a credential
            let expectedArguments = Self.referenceArguments(arguments)
            #expect(CommandSanitizer.sanitize(arguments: arguments) == expectedArguments, "\(sample.prefix(60))")
            #expect(CommandSanitizer.sanitize(arguments: arguments) == expectedArguments, "replay")
        }
    }

    @Test("an output larger than the input bound is returned but not retained")
    func expandingOutputIsNotRetained() {
        let memo = DigestKeyedStringMemo(capacity: 4, maximumInputBytes: 16)
        var calls = 0
        let expand: (String) -> String = { calls += 1; return String(repeating: $0, count: 4) }
        #expect(memo.value(for: "abcdef", transform: expand) == "abcdefabcdefabcdefabcdef")
        #expect(memo.count == 0)
        _ = memo.value(for: "abcdef", transform: expand)
        #expect(calls == 2)
        #expect(memo.value(for: "abc", transform: expand) == "abcabcabcabc")
        #expect(memo.count == 1)
        // The real redactor expands, e.g. `-p''` to `-p'[REDACTED]'`.
        #expect(CommandSanitizer.applyRedactors("mysql -p''").utf8.count > "mysql -p''".utf8.count)
    }

    @Test("field redaction replays both suites exactly for hinted values")
    func fieldParity() {
        for sample in Self.samples {
            let expected = EventPrivacySanitizer.mayContainCredential(sample)
                ? OTLPAttributeSanitizer.redactCredentialShapes(CommandSanitizer.applyRedactors(sample))
                : sample
            #expect(EventPrivacySanitizer.sanitizeString(sample) == expected, "\(sample.prefix(60))")
            #expect(EventPrivacySanitizer.sanitizeString(sample) == expected, "replay: \(sample.prefix(60))")
        }
    }

    @Test("bounded first-in-first-out replacement and an input-size bypass")
    func boundsAndBypass() {
        let memo = DigestKeyedStringMemo(capacity: 4, maximumInputBytes: 16)
        var calls = 0
        let transform: (String) -> String = { calls += 1; return "<" + $0 + ">" }
        for value in ["a", "b", "c", "d", "e"] { #expect(memo.value(for: value, transform: transform) == "<\(value)>") }
        #expect(memo.count == 4)
        #expect(calls == 5)
        _ = memo.value(for: "e", transform: transform)  // retained
        #expect(calls == 5)
        _ = memo.value(for: "a", transform: transform)  // first inserted, replaced first
        #expect(calls == 6)
        let long = String(repeating: "z", count: 17)
        _ = memo.value(for: long, transform: transform)
        _ = memo.value(for: long, transform: transform)
        #expect(calls == 8)
        #expect(memo.count == 4)
    }

    @Test("keys are SHA-256 digests, distinct for distinct inputs")
    func digestKeys() {
        let a = DigestKeyedStringMemo.key(for: "--password=hunter2")
        #expect(a == DigestKeyedStringMemo.key(for: "--password=hunter2"))
        #expect(a != DigestKeyedStringMemo.key(for: "--password=hunter3"))
        // Canonically equivalent spellings are different byte inputs and must
        // not share a remembered output.
        #expect(DigestKeyedStringMemo.key(for: "caf\u{e9}") != DigestKeyedStringMemo.key(for: "cafe\u{301}"))
    }

    @Test("concurrent callers always observe the transform's output")
    func concurrentReplay() async {
        let memo = DigestKeyedStringMemo(capacity: 64, maximumInputBytes: 256)
        await withTaskGroup(of: Bool.self) { group in
            for worker in 0..<16 {
                group.addTask {
                    var ok = true
                    for index in 0..<2_000 {
                        let input = "value-\((index * 7 + worker) % 200)"
                        ok = ok && memo.value(for: input) { $0.uppercased() } == input.uppercased()
                    }
                    return ok
                }
            }
            for await ok in group { #expect(ok) }
        }
        #expect(memo.count == 64)
    }
}
