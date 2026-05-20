// BAMParser — exercises the type-tokenization helper + parser
// resilience to missing files. Real-format fixture parsing is
// integration territory (needs a captured .btm file); the unit
// tests below cover the pure-function surface.

import Foundation
import Testing
@testable import MacCrabForensics

@Suite("BAMParser: type tokenization")
struct BAMTypeTokenizationTests {

    @Test("Type 4 maps to launch_agent")
    func type4LaunchAgent() {
        #expect(BAMParser.tokenizeType(4) == "launch_agent")
    }

    @Test("Type 8 maps to launch_daemon")
    func type8LaunchDaemon() {
        #expect(BAMParser.tokenizeType(8) == "launch_daemon")
    }

    @Test("Type 16 maps to login_item")
    func type16LoginItem() {
        #expect(BAMParser.tokenizeType(16) == "login_item")
    }

    @Test("Type 32 maps to login_item_privileged")
    func type32Privileged() {
        #expect(BAMParser.tokenizeType(32) == "login_item_privileged")
    }

    @Test("Type 128 maps to application")
    func type128Application() {
        #expect(BAMParser.tokenizeType(128) == "application")
    }

    @Test("Unknown type values surface as other_<n>")
    func unknownTypeFallback() {
        #expect(BAMParser.tokenizeType(999) == "other_999")
    }
}

@Suite("BAMParser: resilience")
struct BAMParserResilienceTests {

    @Test("Throws fileMissing for an absent path")
    func absentPathThrows() {
        #expect(throws: BAMParser.ParseError.self) {
            _ = try BAMParser.parse(path: "/var/empty/no-such-bam-\(UUID().uuidString).btm")
        }
    }

    @Test("Returns empty list for an empty / non-keyed plist file")
    func emptyPlistReturnsEmpty() throws {
        let path = NSTemporaryDirectory() + "bam-empty-\(UUID().uuidString).btm"
        let emptyDict: [String: Any] = [:]
        let data = try PropertyListSerialization.data(
            fromPropertyList: emptyDict, format: .xml, options: 0
        )
        try data.write(to: URL(fileURLWithPath: path))
        defer { try? FileManager.default.removeItem(atPath: path) }
        let result = try BAMParser.parse(path: path)
        #expect(result.isEmpty)
    }

    @Test("Default path resolves under ~/Library/Application Support/")
    func defaultPathShape() {
        let p = BAMParser.defaultPath()
        #expect(p.hasSuffix("Library/Application Support/com.apple.backgroundtaskmanagement/BackgroundItems-v9.btm"))
    }
}
