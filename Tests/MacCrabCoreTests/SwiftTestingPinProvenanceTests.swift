// SwiftTestingPinProvenanceTests.swift
//
// v1.17 (DEPS-03): regression guard for the swift-testing dependency pin.
//
// The swift-testing test dep was previously pinned to a bare git
// revision (revision: "5ee435b...") with no version tag, which leaves
// no verifiable provenance in the manifest. It is now pinned to the
// exact tagged release 6.2.4 (== that revision == swift-6.2.4-RELEASE).
//
// This test reads Package.swift and asserts the pin is expressed as an
// exact tagged version and NOT as a bare `revision:` pin, so a future
// edit can't silently regress back to a provenance-free revision pin.

import Testing
import Foundation

@Suite("swift-testing pin provenance (DEPS-03, v1.17)")
struct SwiftTestingPinProvenanceTests {

    /// Walk up from this test file's location to find the project root
    /// (the directory containing Package.swift).
    private func projectRootURL() -> URL {
        var url = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<10 {
            if FileManager.default.fileExists(atPath: url.appendingPathComponent("Package.swift").path) {
                return url
            }
            url = url.deletingLastPathComponent()
        }
        return URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
    }

    private func packageManifest() throws -> String {
        let url = projectRootURL().appendingPathComponent("Package.swift")
        return try String(contentsOf: url, encoding: .utf8)
    }

    /// The swift-testing dependency must be pinned to the exact tagged
    /// release 6.2.4, not a bare revision.
    @Test("swift-testing pinned to exact tag 6.2.4")
    func swiftTestingPinnedToExactTag() throws {
        let manifest = try packageManifest()
        #expect(manifest.contains("swift-testing.git"))
        #expect(manifest.contains("exact: \"6.2.4\""))
    }

    /// Guard against regressing to a provenance-free bare-revision pin.
    /// The old bare revision must not reappear as a `revision:` pin.
    @Test("no bare-revision pin for swift-testing")
    func noBareRevisionPin() throws {
        let manifest = try packageManifest()
        #expect(!manifest.contains("revision: \"5ee435b15ad40ec1f644b5eb9d247f263ccd2170\""))
    }
}
