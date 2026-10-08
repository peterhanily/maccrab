// RavePluginIconTests.swift
// MacCrabAppTests
//
// Pin the Rave store icon atlas the catalog browser draws from: the image the
// app ships, its geometry, and which tile belongs to which plugin. A tile order
// that drifts from the image would put one plugin's artwork on another, so the
// atlas hash and the order are recorded together; scripts/build-rave-icon-atlas.sh
// prints both when the atlas is rebuilt.

import CryptoKit
import Foundation
import ImageIO
import Testing
@testable import MacCrabApp

@Suite("Rave plugin icon atlas")
@MainActor
struct RavePluginIconTests {
    static let atlasSHA256 = "e1e0b27f63b982d69274287cefa9b5238db7cca3e8baaa84eb87e6e8a03aea42"
    static let storePlugins = [
        "agent-exposure", "browser-trust", "build-witness", "clickfix-review", "decoy",
        "dependency-autopsy", "exit-check", "first-hour", "identity-aftershock", "last-good",
        "localhost-lens", "posture-pro", "remote-hands", "repo-tripwire", "script-trace",
        "secret-trail", "side-door", "skill-check", "trust-delta",
    ].map { "com.maccrab.forensics.\($0)" }

    @Test("The shipped atlas is the one the tile order was recorded for")
    func atlasMatchesRecordedOrder() throws {
        let url = try #require(RavePluginIconAtlas.atlasURL)
        let data = try Data(contentsOf: url)
        let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        #expect(digest == Self.atlasSHA256)
        #expect(RavePluginIconAtlas.order == Self.storePlugins + [RavePluginIconAtlas.fallbackName])
    }

    @Test("The atlas is found in the shipped app's Contents/Resources layout, not via Bundle.module")
    func atlasFoundInShippedLayout() throws {
        let shipped = try #require(RavePluginIconAtlas.atlasURL)
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("rave-icon-layout-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let resources = root.appendingPathComponent("MacCrab.app/Contents/Resources", isDirectory: true)
        let bundle = resources.appendingPathComponent("MacCrab_MacCrabApp.bundle", isDirectory: true)
        try FileManager.default.createDirectory(at: bundle, withIntermediateDirectories: true)
        try FileManager.default.copyItem(at: shipped, to: bundle.appendingPathComponent("RaveIcons.heic"))

        let executableDir = root.appendingPathComponent("MacCrab.app/Contents/MacOS", isDirectory: true)
        let found = try #require(RavePluginIconAtlas.atlasURL(searching: [resources, executableDir]))
        #expect(found.resolvingSymlinksInPath().path
                == bundle.appendingPathComponent("RaveIcons.heic").resolvingSymlinksInPath().path)
        #expect(RavePluginIconAtlas.atlasURL(searching: [executableDir]) == nil)
    }

    @Test("The atlas decodes with alpha at the size its grid implies")
    func atlasGeometry() throws {
        let atlas = try #require(RavePluginIconAtlas.atlas)
        let pitch = RavePluginIconAtlas.tilePixels + RavePluginIconAtlas.gutterPixels
        let rows = (RavePluginIconAtlas.order.count + RavePluginIconAtlas.columns - 1) / RavePluginIconAtlas.columns
        #expect(atlas.width == RavePluginIconAtlas.columns * pitch - RavePluginIconAtlas.gutterPixels)
        #expect(atlas.height == rows * pitch - RavePluginIconAtlas.gutterPixels)
        #expect(![CGImageAlphaInfo.none, .noneSkipFirst, .noneSkipLast].contains(atlas.alphaInfo))
    }

    @Test("Every tile is cropped to its squircle: opaque centre, transparent corners")
    func tilesAreAligned() throws {
        for name in RavePluginIconAtlas.order {
            let image = try #require(RavePluginIconAtlas.tile(named: name), "no tile for \(name)")
            let cg = try #require(image.cgImage(forProposedRect: nil, context: nil, hints: nil))
            #expect(cg.width == RavePluginIconAtlas.tilePixels && cg.height == RavePluginIconAtlas.tilePixels)
            let alpha = try Self.alphaChannel(cg)
            let side = RavePluginIconAtlas.tilePixels
            let centre = alpha[(side / 2) * side + side / 2]
            #expect(centre > 240, "\(name) centre alpha \(centre)")
            for (x, y) in [(1, 1), (side - 2, 1), (1, side - 2), (side - 2, side - 2)] {
                #expect(alpha[y * side + x] < 16, "\(name) corner (\(x),\(y)) alpha \(alpha[y * side + x])")
            }
        }
    }

    @Test("Only store plugins have artwork; others fall back")
    func artworkLookup() {
        for id in Self.storePlugins {
            #expect(RavePluginIconAtlas.image(forPluginID: id) != nil, "\(id) has no artwork")
        }
        #expect(RavePluginIconAtlas.image(forPluginID: "com.maccrab.forensics.tcc-lite") == nil)
        #expect(RavePluginIconAtlas.image(forPluginID: "com.example.community.plugin") == nil)
        #expect(RavePluginIconAtlas.tile(named: RavePluginIconAtlas.fallbackName) != nil)
    }

    private static func alphaChannel(_ image: CGImage) throws -> [UInt8] {
        let side = image.width
        var pixels = [UInt8](repeating: 0, count: side * side * 4)
        let drawn = pixels.withUnsafeMutableBytes { buffer -> Bool in
            guard let context = CGContext(data: buffer.baseAddress, width: side, height: side,
                                          bitsPerComponent: 8, bytesPerRow: side * 4,
                                          space: CGColorSpace(name: CGColorSpace.sRGB)!,
                                          bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else { return false }
            context.draw(image, in: CGRect(x: 0, y: 0, width: side, height: side))
            return true
        }
        try #require(drawn)
        // Row 0 of the buffer is the top row of the image.
        return stride(from: 3, to: pixels.count, by: 4).map { pixels[$0] }
    }
}
