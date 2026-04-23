// MacCrabTheme.swift
// MacCrabApp
//
// Color palette that mirrors maccrab.com's dark-with-orange-accent look.
// Every value here corresponds 1:1 to a CSS custom property in
// maccrab-site/index.html, so the dashboard and marketing site stay
// visually consistent without either having to "know about" the other.
//
// Light / dark pairs are provided so the app respects the user's system
// appearance setting. The app is dark-first (matches the site's default)
// but light mode is implemented faithfully to the same spec.
//
// Accent usage:
//   - Apply `.tint(MacCrabTheme.accent)` at the app scene root. SwiftUI
//     cascades this into native buttons, links, toggles, date pickers,
//     progress views, etc. — no per-view plumbing required.
//   - For custom UI (severity chips, stat cards), reach into the palette
//     directly: `.foregroundStyle(MacCrabTheme.accent)` or
//     `.background(MacCrabTheme.bgCard)`.
//
// Severity intentionally does NOT use accent — you want clear visual
// distinction between "attention signal" (orange accent) and "alert
// severity" (red/amber/blue/green). Same reason the site keeps the two
// palettes separate.

import SwiftUI
import AppKit

public enum MacCrabTheme {

    // MARK: - Base chrome (backgrounds, borders, separators)

    /// Outermost window background. Dark: near-black matching the site's
    /// `--bg`. Light: warm off-white (`--bg` in the light theme).
    public static let bg = Color(light: 0xFAFAF7, dark: 0x0A0A0B)

    /// First-elevation surfaces: toolbar, sidebar, card container.
    public static let bgElev = Color(light: 0xFFFFFF, dark: 0x131317)

    /// Second-elevation surfaces: stat cards, list rows, modal bodies.
    public static let bgCard = Color(light: 0xFFFFFF, dark: 0x17171C)

    /// Hover / pressed states on interactive backgrounds.
    public static let bgHover = Color(light: 0xF4F4F0, dark: 0x1E1E24)

    /// Default border for cards, section dividers, input outlines.
    public static let border = Color(light: 0xE5E5E0, dark: 0x26262D)

    /// Emphasized borders (focus ring, selected row).
    public static let borderStrong = Color(light: 0xCFCFC8, dark: 0x34343C)

    // MARK: - Text

    /// Primary text — body copy, headlines.
    public static let text = Color(light: 0x0A0A0B, dark: 0xF4F4F5)

    /// Dimmed text — secondary labels, timestamps, captions.
    public static let textDim = Color(light: 0x52525B, dark: 0xA1A1AA)

    /// Muted text — tertiary metadata, placeholder copy.
    public static let textMute = Color(light: 0x71717A, dark: 0x6B6B75)

    // MARK: - Accent (brand orange)

    /// Primary brand accent. Apply via `.tint(MacCrabTheme.accent)` at the
    /// scene root; prefer that over direct use so native controls pick it
    /// up consistently. Site value: `--accent`.
    public static let accent = Color(light: 0xE04820, dark: 0xFF5E3A)

    /// Hotter variant used for hero gradients and site CTAs. Site:
    /// `--accent-hot`.
    public static let accentHot = Color(light: 0xFF5E3A, dark: 0xFF7A5A)

    /// Darker variant for hover/pressed accent surfaces. Site:
    /// `--accent-dim`.
    public static let accentDim = Color(light: 0xA03010, dark: 0xC13E20)

    /// Subtle orange tint — used on card hovers, toast backgrounds, any
    /// surface that should feel branded without being loud. Matches the
    /// site's `--accent-ghost` alpha layer.
    public static let accentGhost = Color(
        light: NSColor(red: 0xE0/255, green: 0x48/255, blue: 0x20/255, alpha: 0.06),
        dark: NSColor(red: 0xFF/255, green: 0x5E/255, blue: 0x3A/255, alpha: 0.08)
    )

    /// Slightly stronger ghost — for tagged chips, highlighted rows. Site:
    /// `--accent-ghost-strong`.
    public static let accentGhostStrong = Color(
        light: NSColor(red: 0xE0/255, green: 0x48/255, blue: 0x20/255, alpha: 0.12),
        dark: NSColor(red: 0xFF/255, green: 0x5E/255, blue: 0x3A/255, alpha: 0.15)
    )

    // MARK: - Severity (distinct from accent — clarity matters)

    /// Critical: red. Matches site `--crit`.
    public static let severityCritical = Color(light: 0xDC2626, dark: 0xEF4444)

    /// High: warm orange that doesn't collide with the brand accent.
    public static let severityHigh = Color(light: 0xEA580C, dark: 0xF97316)

    /// Medium: amber. Site: `--warn`.
    public static let severityMedium = Color(light: 0xCA8A04, dark: 0xFBBF24)

    /// Low / informational: cool blue. Site: `--info`.
    public static let severityLow = Color(light: 0x2563EB, dark: 0x60A5FA)

    /// Informational / healthy state. Site: `--ok`.
    public static let ok = Color(light: 0x16A34A, dark: 0x4ADE80)
}

// MARK: - Color convenience initializers

extension Color {

    /// Convenience for mixing two hex values that auto-switch on system
    /// appearance. Takes a 6-digit RGB value for each, decodes, hands to
    /// NSColor's dynamic provider which resolves per-appearance at render
    /// time — no manual colorScheme observation needed in views.
    ///
    /// Values are 0xRRGGBB 24-bit literals for readability.
    fileprivate init(light: UInt32, dark: UInt32) {
        let lightNS = NSColor(hex: light)
        let darkNS = NSColor(hex: dark)
        self = Color(nsColor: NSColor(name: nil, dynamicProvider: { appearance in
            let isDark = appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua
            return isDark ? darkNS : lightNS
        }))
    }

    /// Same idea but for values that already include alpha (the ghost
    /// overlays). Takes NSColors directly because tacking alpha onto a
    /// hex literal in Swift is ugly.
    fileprivate init(light: NSColor, dark: NSColor) {
        self = Color(nsColor: NSColor(name: nil, dynamicProvider: { appearance in
            let isDark = appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua
            return isDark ? dark : light
        }))
    }
}

extension NSColor {
    /// Decode a 0xRRGGBB literal into an opaque NSColor in the sRGB space.
    /// Not public: this is an implementation detail of the theme file.
    fileprivate convenience init(hex: UInt32) {
        let r = CGFloat((hex >> 16) & 0xFF) / 255
        let g = CGFloat((hex >> 8) & 0xFF) / 255
        let b = CGFloat(hex & 0xFF) / 255
        self.init(srgbRed: r, green: g, blue: b, alpha: 1)
    }
}
