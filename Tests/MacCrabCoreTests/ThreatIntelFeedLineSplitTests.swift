import Testing
@testable import MacCrabCore

/// Regression guard for the CRLF feed-parsing bug: the abuse.ch feeds
/// ship CRLF line endings, and Swift treats "\r\n" as one grapheme
/// cluster — so `split(separator: "\n")` returned the whole body as a
/// single line and every feed parsed to 0 records. `splitFeedLines`
/// must split CRLF / LF / CR uniformly and never leave a trailing "\r".
@Suite("ThreatIntelFeed line splitting")
struct ThreatIntelFeedLineSplitTests {

    @Test("CRLF body splits into individual lines (the real abuse.ch bug)")
    func crlfSplits() {
        let body = "# header\r\n1.2.3.4,2026-01-01,malware\r\n5.6.7.8,2026-01-02,bot\r\n"
        let lines = ThreatIntelFeed.splitFeedLines(body)
        #expect(lines.count == 3)
        #expect(lines[0] == "# header")
        // No trailing CR must survive (would pollute the last CSV field).
        #expect(lines.allSatisfy { !$0.contains("\r") })
        #expect(lines[1] == "1.2.3.4,2026-01-01,malware")
    }

    @Test("LF-only body still splits correctly")
    func lfSplits() {
        let lines = ThreatIntelFeed.splitFeedLines("a\nb\nc")
        #expect(lines == ["a", "b", "c"])
    }

    @Test("CR-only body splits correctly")
    func crSplits() {
        let lines = ThreatIntelFeed.splitFeedLines("a\rb\rc")
        #expect(lines == ["a", "b", "c"])
    }

    @Test("the buggy split(separator:) collapses CRLF — proves the regression")
    func provesRegression() {
        let crlf = "a,1\r\nb,2\r\nc,3\r\n"
        // What the old code did — one grapheme cluster, no standalone \n.
        #expect(crlf.split(separator: "\n").count == 1)
        // What the fix does.
        #expect(ThreatIntelFeed.splitFeedLines(crlf).count == 3)
    }
}
