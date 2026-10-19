import Foundation
import Testing
@testable import MacCrabCore

/// Differential oracles for `ExactSubstringSearch`. Foundation's own
/// `contains` is the reference; NSString and a naive Character-array search
/// independently confirm that the byte path is answered only where every
/// supported Foundation definition agrees.
@Suite("Exact substring search parity")
struct ExactSubstringSearchTests {
    private struct Generator {
        var state: UInt64
        mutating func next() -> UInt64 {
            state &+= 0x9E37_79B9_7F4A_7C15
            var z = state
            z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
            z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
            return z ^ (z >> 31)
        }
        mutating func below(_ bound: Int) -> Int { Int(next() % UInt64(bound)) }
    }

    private static let plainPieces: [String] = [
        "a", "b", "c", "A", "Z", "/", ".", "-", "_", " ", "0", "9", "\n", "\t",
        "/users/", "library/", ".app/contents/", "node_modules", "id_rsa", ".env",
    ]
    private static let hazardPieces: [String] = [
        "\r", "\r\n", "e\u{301}", "\u{e9}", "\u{301}", "\u{0600}", "\u{200D}",
        "\u{1F44D}", "\u{1F3FB}", "\u{212A}", "\u{df}", "\u{fb01}", "\u{fe0f}",
    ]

    private func naiveCharacterSearch(_ haystack: String, _ needle: String) -> Bool {
        let h = Array(haystack), n = Array(needle)
        guard !n.isEmpty, n.count <= h.count else { return false }
        for start in 0...(h.count - n.count) where Array(h[start..<(start + n.count)]) == n {
            return true
        }
        return false
    }

    private func randomString(_ g: inout Generator, hazards: Bool, maxPieces: Int) -> String {
        var s = ""
        for _ in 0..<g.below(maxPieces + 1) {
            if hazards, g.below(5) == 0 {
                s += Self.hazardPieces[g.below(Self.hazardPieces.count)]
            } else {
                s += Self.plainPieces[g.below(Self.plainPieces.count)]
            }
        }
        return s
    }

    @Test("fixed hazards match Foundation exactly")
    func fixedHazards() {
        let cases: [(String, String)] = [
            ("a\r\nb", "\n"), ("a\r\nb", "\r"), ("a\r\nb", "\r\n"), ("a\r\nb", "a\r"),
            ("a\r\nb", "\nb"), ("a\r\r\nb", "\r"), ("a\n\rb", "\n\r"),
            ("abc", ""), ("", ""), ("", "a"), ("ab", "abc"),
            ("e\u{301}x", "e"), ("caf\u{e9}", "cafe\u{301}"), ("cafe\u{301}", "caf\u{e9}"),
            ("\u{0600}abc", "abc"), ("ab\u{200D}c", "ab"), ("ABC", "abc"),
            ("aaab", "aab"), ("/a/b/c", "/c"), ("/a/b/c", "/a/"), ("x", "x"),
            ("\u{212A}elvin", "kelvin"), ("stra\u{df}e", "strasse"),
        ]
        for (haystack, needle) in cases {
            #expect(ExactSubstringSearch.contains(haystack, needle) == haystack.contains(needle),
                    "\(haystack.debugDescription) / \(needle.debugDescription)")
        }
        // Outside the plain-ASCII, CR-free, non-empty domain the byte path abstains.
        #expect(ExactSubstringSearch.plainASCIIContains("a\r\nb", "\n") == nil)
        #expect(ExactSubstringSearch.plainASCIIContains("abc", "") == nil)
        #expect(ExactSubstringSearch.plainASCIIContains("e\u{301}x", "e") == nil)
        #expect(ExactSubstringSearch.plainASCIIContains("abc", "\u{e9}") == nil)
        #expect(ExactSubstringSearch.plainASCIIContains("/a/b/c", "/b/") == true)
        #expect(ExactSubstringSearch.plainASCIIContains("ab", "abc") == false)
    }

    @Test("randomized differential parity with Foundation, NSString and Characters")
    func randomizedParity() {
        var g = Generator(state: 0x5EED_2026_1019_0001)
        var fastAnswered = 0
        var matches = 0
        for iteration in 0..<60_000 {
            let hazards = iteration % 3 != 0
            let haystack = randomString(&g, hazards: hazards, maxPieces: 18)
            let needle: String
            if g.below(2) == 0, !haystack.isEmpty {
                // Slice on Unicode scalars, not Characters, so needles can
                // split clusters and CR LF pairs exactly where they are hazardous.
                let scalars = Array(haystack.unicodeScalars)
                let start = g.below(scalars.count)
                let end = start + g.below(min(8, scalars.count - start) + 1)
                var view = String.UnicodeScalarView()
                view.append(contentsOf: scalars[start..<end])
                needle = String(view)
            } else {
                needle = randomString(&g, hazards: hazards, maxPieces: 3)
            }
            let expected = haystack.contains(needle)
            let actual = ExactSubstringSearch.contains(haystack, needle)
            #expect(actual == expected, "\(haystack.debugDescription) / \(needle.debugDescription)")
            if expected { matches += 1 }
            if let fast = ExactSubstringSearch.plainASCIIContains(haystack, needle) {
                fastAnswered += 1
                // Inside the domain every independent definition agrees.
                #expect(fast == expected)
                #expect(fast == ((haystack as NSString).range(of: needle).location != NSNotFound))
                #expect(fast == naiveCharacterSearch(haystack, needle))
            }
        }
        // The byte path and both verdicts are genuinely exercised.
        #expect(fastAnswered > 15_000)
        #expect(matches > 15_000)
        #expect(matches < 60_000)
    }
}
