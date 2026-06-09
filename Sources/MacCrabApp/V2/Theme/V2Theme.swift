// V2Theme.swift
// MacCrabApp — Dashboard v2
//
// Visual design tokens per the v2 implementation spec §4. Colors
// auto-switch with light/dark via NSColor dynamic providers so the
// top-bar sun/moon toggle actually changes the whole shell.

import SwiftUI
import AppKit

public enum V2Theme {

    // MARK: - Dynamic color helper

    private static func dyn(dark: NSColor, light: NSColor) -> Color {
        Color(NSColor(name: nil) { appearance in
            let isDark = appearance.bestMatch(from: [.darkAqua, .vibrantDark, .accessibilityHighContrastDarkAqua, .accessibilityHighContrastVibrantDark]) != nil
            return isDark ? dark : light
        })
    }
    private static func srgb(_ r: CGFloat, _ g: CGFloat, _ b: CGFloat, _ a: CGFloat = 1) -> NSColor {
        NSColor(srgbRed: r, green: g, blue: b, alpha: a)
    }

    // MARK: - Canvas + surfaces

    /// Full-window background — subtle warm dark, just enough red
    /// to not feel cold. Not aggressive.
    public static var canvasBackground: Color {
        dyn(
            dark:  srgb(0.105, 0.085, 0.085),   // warm-grey, faint red lean
            light: srgb(0.985, 0.975, 0.972)    // warm cream
        )
    }

    /// Sidebar background — subtly deeper than canvas.
    public static var sidebarBackground: Color {
        dyn(
            dark:  srgb(0.085, 0.065, 0.065),
            light: srgb(0.962, 0.948, 0.942)
        )
    }

    /// Inspector background.
    public static var inspectorBackground: Color {
        dyn(
            dark:  srgb(0.120, 0.100, 0.100),
            light: srgb(0.978, 0.968, 0.962)
        )
    }

    /// Panel / card background.
    public static var panelBackground: Color {
        dyn(
            dark:  NSColor.white.withAlphaComponent(0.038),
            light: NSColor.black.withAlphaComponent(0.030)
        )
    }

    /// Panel border (very subtle).
    public static var panelBorder: Color {
        dyn(
            dark:  NSColor.white.withAlphaComponent(0.07),
            light: NSColor.black.withAlphaComponent(0.10)
        )
    }

    /// Kept for back-compat.
    public static var canvasGradient: LinearGradient {
        LinearGradient(colors: [canvasBackground, canvasBackground],
                       startPoint: .top, endPoint: .bottom)
    }

    // MARK: - Semantic accents

    // RC H3 (a11y): severity accents are adaptive. The bright dark-mode values
    // (kept below) fail WCAG AA as text/icons on the light cream canvas
    // (#FBF9F8) — measured 1.4–3.0:1. The `light:` variants are darkened so
    // each clears AA 4.5:1 on that canvas (computed: critical 6.3, high 5.3,
    // medium 5.3, low 5.5, healthy 5.4, ai 6.3, data 5.0). Used as chip text,
    // dot fill, and accent throughout — making them adaptive fixes the chip
    // contrast (V2StatusChip) at the same time.
    public static var critical: Color   { dyn(dark: srgb(0.96, 0.39, 0.27), light: srgb(0.72, 0.10, 0.05)) }
    public static var high: Color       { dyn(dark: srgb(0.99, 0.62, 0.30), light: srgb(0.66, 0.30, 0.02)) }
    public static var medium: Color     { dyn(dark: srgb(0.98, 0.78, 0.39), light: srgb(0.55, 0.37, 0.00)) }
    public static var low: Color        { dyn(dark: srgb(0.55, 0.65, 0.78), light: srgb(0.32, 0.40, 0.54)) }
    public static var healthy: Color    { dyn(dark: srgb(0.22, 0.72, 0.40), light: srgb(0.10, 0.46, 0.24)) }
    public static var warning: Color    { dyn(dark: srgb(0.96, 0.65, 0.27), light: srgb(0.66, 0.30, 0.02)) }
    public static var aiAccent: Color   { dyn(dark: srgb(0.55, 0.36, 0.92), light: srgb(0.46, 0.24, 0.74)) }
    public static var dataAccent: Color { dyn(dark: srgb(0.20, 0.55, 0.92), light: srgb(0.10, 0.42, 0.74)) }

    /// Highest-emphasis text — white in dark, near-black in light.
    public static var primaryText: Color {
        dyn(dark: srgb(1.00, 1.00, 1.00),
            light: srgb(0.10, 0.07, 0.07))
    }
    public static var neutral: Color {
        dyn(dark: srgb(0.78, 0.74, 0.74),
            light: srgb(0.25, 0.20, 0.20))
    }
    public static var mutedText: Color {
        dyn(dark: srgb(0.65, 0.60, 0.60),
            light: srgb(0.42, 0.36, 0.36))
    }
    public static var tertiaryText: Color {
        // Pre-fix dark srgb(0.46, 0.42, 0.42) on canvasBackground was
        // 3.49:1 — fails WCAG AA body-text 4.5:1. Bumped lightness to
        // achieve ≥4.5:1 in dark mode against canvasBackground +
        // panelBackground while keeping the visual hierarchy with
        // mutedText. Light mode tightened similarly. Used by histogram
        // x-axis labels, trace counter, panel borders, palette section
        // titles, KPI footers — dozens of dashboard surfaces.
        dyn(dark: srgb(0.62, 0.58, 0.58),
            light: srgb(0.42, 0.36, 0.36))
    }

    /// Brand color — defers to the shared v1 `MacCrabTheme.accent` so
    /// the v2 surfaces stay locked to the same orange used in the
    /// status-bar icon, app icon, and maccrab.com.
    public static var brand: Color { MacCrabTheme.accent }

    /// Darker brand variant for filled buttons that carry white text. White on
    /// `brand` is 3.04:1 (dark) / 4.10:1 (light) — both fail WCAG AA 4.5:1;
    /// `accentDim` (0xC13E20 dark = 5.28:1) passes. Used by V2ActionButton.primary.
    public static var brandDim: Color { MacCrabTheme.accentDim }

    // MARK: - Interaction overlays (theme-aware)

    /// Subtle background fill for hover states — adapts so it shows
    /// up against either canvas tone.
    public static var hoverBackground: Color {
        dyn(dark:  NSColor.white.withAlphaComponent(0.05),
            light: NSColor.black.withAlphaComponent(0.05))
    }
    /// Stronger fill for active / pressed / selected states.
    public static var activeBackground: Color {
        dyn(dark:  NSColor.white.withAlphaComponent(0.10),
            light: NSColor.black.withAlphaComponent(0.08))
    }

    // MARK: - Geometry

    public static let cornerRadius: CGFloat = 10
    public static let smallCornerRadius: CGFloat = 6
    public static let chipCornerRadius: CGFloat = 4
    public static let sidebarWidth: CGFloat = 220
    public static let inspectorWidth: CGFloat = 340
    public static let topBarHeight: CGFloat = 48
    public static let tabStripHeight: CGFloat = 30
    public static let workspaceHeaderHeight: CGFloat = 40
    public static let footerHeight: CGFloat = 28

    // MARK: - Typography
    //
    // Pre-fix: every helper used an absolute pt size, so 96 callsites
    // across the V2 dashboard were unreachable for AX1+ Dynamic Type
    // users (200%-310% text). Now bound to semantic styles so SwiftUI
    // applies user-preferred scaling. Each helper picks the closest
    // semantic equivalent of the original pt size to avoid regressing
    // visual proportions at the default 100% Dynamic Type setting.

    public static func workspaceTitle() -> Font { .system(.title2, weight: .semibold) }
    public static func sectionTitle() -> Font   { .system(.headline, weight: .semibold) }
    public static func cardTitle() -> Font      { .system(.caption, weight: .medium) }
    public static func kpiValue() -> Font       { .system(.largeTitle, weight: .bold) }
    public static func body() -> Font           { .system(.body) }
    public static func chip() -> Font           { .system(.caption, weight: .semibold) }
    public static func meta() -> Font           { .system(.caption) }
    public static func micro() -> Font          { .system(.caption2) }
    public static func mono() -> Font           { .system(.caption, design: .monospaced) }

    // No public panel(fill:) helper — use the `.v2Panel()` view modifier
    // below instead. The earlier convenience version used a `as!`
    // default-argument cast which is unsafe under generic resolution
    // and was unused.
}

// MARK: - View modifiers

extension View {

    /// Apply the standard v2 panel chrome (rounded corner + subtle border + glass-like fill).
    public func v2Panel(padding: CGFloat = 12) -> some View {
        self
            .padding(padding)
            .background(V2Theme.panelBackground)
            .overlay(
                RoundedRectangle(cornerRadius: V2Theme.cornerRadius)
                    .stroke(V2Theme.panelBorder, lineWidth: 1)
            )
            .clipShape(RoundedRectangle(cornerRadius: V2Theme.cornerRadius))
    }

    /// Apply the inspector chrome — slightly more opaque.
    public func v2Inspector(padding: CGFloat = 12) -> some View {
        self
            .padding(padding)
            .background(V2Theme.inspectorBackground)
            .overlay(
                RoundedRectangle(cornerRadius: V2Theme.cornerRadius)
                    .stroke(V2Theme.panelBorder, lineWidth: 1)
            )
            .clipShape(RoundedRectangle(cornerRadius: V2Theme.cornerRadius))
    }
}


