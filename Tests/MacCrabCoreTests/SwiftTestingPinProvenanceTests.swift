// SwiftTestingPinProvenanceTests.swift
//
// Swift Testing comes from the release Swift toolchain. An independent source
// package can pair older compiler-plugin code with a newer compiler. CI must
// verify the full compiler build identity; these guards reject reintroducing
// independently versioned source packages in the manifest or resolution.

import Testing
import Foundation

@Suite("Toolchain-provided Swift Testing provenance")
struct SwiftTestingPinProvenanceTests {
    private func projectRootURL() throws -> URL {
        var url = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<10 {
            if FileManager.default.fileExists(atPath: url.appendingPathComponent("Package.swift").path) {
                return url
            }
            url = url.deletingLastPathComponent()
        }
        throw CocoaError(.fileNoSuchFile)
    }

    @Test("Testing and its macros are supplied by the toolchain")
    func testingHasNoIndependentSourcePackage() throws {
        let root = try projectRootURL()
        let manifest = try String(contentsOf: root.appendingPathComponent("Package.swift"), encoding: .utf8)
        #expect(!manifest.contains("swift-testing.git"))
        #expect(!manifest.contains("swift-syntax.git"))
        #expect(!manifest.contains("package: \"swift-testing\""))
        #expect(!manifest.contains("package: \"swift-syntax\""))

    }

    @Test("Resolution contains no independent testing compiler plugins")
    func testingResolutionMatchesToolchainImports() throws {
        let root = try projectRootURL()
        struct Resolution: Decodable {
            struct Pin: Decodable { let identity: String }
            let pins: [Pin]
        }
        let resolution = try JSONDecoder().decode(
            Resolution.self,
            from: Data(contentsOf: root.appendingPathComponent("Package.resolved"))
        )
        let independentTestingPackages = resolution.pins.filter {
            $0.identity == "swift-testing" || $0.identity == "swift-syntax"
        }
        #expect(independentTestingPackages.isEmpty)
    }

}
