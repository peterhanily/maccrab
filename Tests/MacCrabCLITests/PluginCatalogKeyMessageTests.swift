import Foundation
import Testing
@testable import maccrabctl

@Suite("maccrabctl: missing catalog key message")
struct PluginCatalogKeyMessageTests {

    /// Release builds read the catalog key only from the MacCrab.app bundle in
    /// /Applications and ignore MACCRAB_RAVE_CATALOG_PUB_PATH, so the message
    /// must point there and may offer the variable only as a debug-build option.
    @Test("names the bundled key location and offers the env path only for debug builds")
    func missingKeyMessageIsTrueForReleaseBuilds() throws {
        let message = PluginCatalogFetchError.noCatalogPublicKey.description
        #expect(message.contains("/Applications/MacCrab.app"))
        let envRange = try #require(message.range(of: "MACCRAB_RAVE_CATALOG_PUB_PATH"))
        #expect(message[..<envRange.lowerBound].contains("Debug builds"),
                "the env override must be introduced as debug-only: \(message)")
        #expect(!message.contains("Set MACCRAB_RAVE_CATALOG_PUB_PATH"))
    }
}
