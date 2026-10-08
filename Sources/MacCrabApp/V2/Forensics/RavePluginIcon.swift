import AppKit
import ImageIO
import SwiftUI

/// The Rave store's plugin artwork, shipped inside the app so the catalog
/// browser shows the same Mac-style icons as rave.maccrab.com. The signed
/// catalog has no icon field, so the art travels under the app's own code
/// signature rather than being fetched.
///
/// `RaveIcons.heic` is one atlas: 160-pixel tiles cropped to the squircle
/// (the 1024-pixel source drawings' 100-pixel icon-grid margin removed),
/// 8-pixel transparent gutters, five columns, in `order` row by row. One file
/// rather than twenty keeps the installed footprint to the image's own size.
/// Rebuild it with `scripts/build-rave-icon-atlas.sh` when the store's icons
/// change, and update `order` to match.
@MainActor
enum RavePluginIconAtlas {
    static let order: [String] = [
        "com.maccrab.forensics.agent-exposure",
        "com.maccrab.forensics.browser-trust",
        "com.maccrab.forensics.build-witness",
        "com.maccrab.forensics.clickfix-review",
        "com.maccrab.forensics.decoy",
        "com.maccrab.forensics.dependency-autopsy",
        "com.maccrab.forensics.exit-check",
        "com.maccrab.forensics.first-hour",
        "com.maccrab.forensics.identity-aftershock",
        "com.maccrab.forensics.last-good",
        "com.maccrab.forensics.localhost-lens",
        "com.maccrab.forensics.posture-pro",
        "com.maccrab.forensics.remote-hands",
        "com.maccrab.forensics.repo-tripwire",
        "com.maccrab.forensics.script-trace",
        "com.maccrab.forensics.secret-trail",
        "com.maccrab.forensics.side-door",
        "com.maccrab.forensics.skill-check",
        "com.maccrab.forensics.trust-delta",
        fallbackName,
    ]
    /// The store's neutral crab, shown for a plugin that has no artwork.
    static let fallbackName = "_fallback"
    static let tilePixels = 160
    static let gutterPixels = 8
    static let columns = 5

    static let atlasURL: URL? = atlasURL(searching: [
        Bundle.main.resourceURL,
        Bundle.main.bundleURL,
        Bundle(for: BundleToken.self).bundleURL.deletingLastPathComponent(),
    ].compactMap { $0 })

    /// Finds the atlas in SwiftPM's `MacCrab_MacCrabApp.bundle` under the first
    /// directory that holds one: Contents/Resources in the shipped app (where
    /// build-release.sh and bundle-app.sh copy it), beside the executable under
    /// `swift run`, and beside the test bundle under `swift test`.
    /// `Bundle.module` is deliberately not used: its generated accessor looks
    /// only beside the executable and then at the build machine's .build path,
    /// and calls fatalError when neither exists, which is the shipped app's
    /// case (KitLoader avoids it for the same reason).
    nonisolated static func atlasURL(searching directories: [URL]) -> URL? {
        for directory in directories {
            let bundleURL = directory.appendingPathComponent("MacCrab_MacCrabApp.bundle", isDirectory: true)
            if let url = Bundle(url: bundleURL)?.url(forResource: "RaveIcons", withExtension: "heic") {
                return url
            }
        }
        return nil
    }

    private final class BundleToken {}

    static let atlas: CGImage? = {
        guard let url = atlasURL,
              let source = CGImageSourceCreateWithURL(url as CFURL, nil) else { return nil }
        return CGImageSourceCreateImageAtIndex(source, 0, nil)
    }()

    private static var tiles: [String: NSImage] = [:]

    static func image(forPluginID id: String) -> NSImage? { tile(named: id) }

    static func tile(named name: String) -> NSImage? {
        if let hit = tiles[name] { return hit }
        guard let index = order.firstIndex(of: name), let atlas else { return nil }
        let pitch = tilePixels + gutterPixels
        let rect = CGRect(x: (index % columns) * pitch, y: (index / columns) * pitch,
                          width: tilePixels, height: tilePixels)
        guard let cropped = atlas.cropping(to: rect) else { return nil }
        let image = NSImage(cgImage: cropped, size: NSSize(width: tilePixels / 2, height: tilePixels / 2))
        tiles[name] = image
        return image
    }
}

/// A catalog entry's icon in the Rave store's style. A store plugin shows its
/// artwork; a built-in scanner gets the same squircle drawn around its symbol;
/// any other plugin gets the store's crab. Decorative, because the entry's
/// name always sits beside it.
struct RavePluginIcon: View {
    struct BuiltInStyle {
        let tint: Color
        /// An SF Symbol the running OS has, or nil to draw `monogram`.
        let symbol: String?
        let monogram: String
    }

    let pluginID: String
    let size: CGFloat
    /// Non-nil for a built-in scanner, which has no store artwork.
    let builtInStyle: BuiltInStyle?

    var body: some View {
        Group {
            if let art = RavePluginIconAtlas.image(forPluginID: pluginID) {
                Image(nsImage: art).resizable().interpolation(.high)
            } else if let style = builtInStyle {
                RaveSquircle(style: style, size: size)
            } else if let crab = RavePluginIconAtlas.tile(named: RavePluginIconAtlas.fallbackName) {
                Image(nsImage: crab).resizable().interpolation(.high)
            } else {
                RaveSquircle(style: BuiltInStyle(tint: .gray, symbol: nil, monogram: ""), size: size)
            }
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}

/// The store icons' frame drawn natively: an 824-unit squircle with a
/// top-to-bottom fill, a white lift from the top edge, a darker lower half and
/// a rim that is light at the top and dark at the bottom.
private struct RaveSquircle: View {
    let style: RavePluginIcon.BuiltInStyle
    let size: CGFloat

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: size * 184 / 824, style: .continuous)
        ZStack {
            shape.fill(style.tint)
            shape.fill(LinearGradient(colors: [.white.opacity(0.16), .black.opacity(0.14)],
                                      startPoint: .top, endPoint: .bottom))
            shape.fill(RadialGradient(colors: [.white.opacity(0.18), .white.opacity(0)],
                                      center: UnitPoint(x: 0.5, y: 10.0 / 824),
                                      startRadius: 0, endRadius: size * 620 / 824))
            shape.fill(LinearGradient(stops: [.init(color: .black.opacity(0), location: 420.0 / 824),
                                              .init(color: .black.opacity(0.14), location: 1)],
                                      startPoint: .top, endPoint: .bottom))
            shape.strokeBorder(LinearGradient(stops: [.init(color: .white.opacity(0.55), location: 0),
                                                      .init(color: .white.opacity(0), location: 0.22),
                                                      .init(color: .black.opacity(0), location: 0.8),
                                                      .init(color: .black.opacity(0.16), location: 1)],
                                              startPoint: .top, endPoint: .bottom),
                               lineWidth: max(0.5, size * 5 / 824))
            glyph
                .foregroundStyle(.white)
                .shadow(color: .black.opacity(0.22), radius: size * 0.02, y: size * 0.015)
        }
        .frame(width: size, height: size)
    }

    @ViewBuilder
    private var glyph: some View {
        if let symbol = style.symbol {
            Image(systemName: symbol)
                .resizable()
                .scaledToFit()
                .fontWeight(.semibold)
                .padding(size * 0.26)
        } else {
            Text(verbatim: style.monogram)
                .font(.system(size: size * 0.36, weight: .bold, design: .rounded))
                .minimumScaleFactor(0.5)
                .lineLimit(1)
                .padding(size * 0.12)
        }
    }
}
