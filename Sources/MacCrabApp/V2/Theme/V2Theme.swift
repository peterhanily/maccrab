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
    // medium 5.3, low 5.5, healthy 5.4, ai 6.3, data 5.0).
    //
    // CORRECTION: the previous version of this comment went on to claim that
    // "making them adaptive fixes the chip contrast (V2StatusChip) at the same
    // time". It does not, and believing it is how the chip bug survived.
    // These figures are for the accent as PLAIN text on the bare canvas.
    // V2StatusChip draws its text in the same hue as its own 13% wash, so the
    // effective background is not the canvas — re-measured over that composite
    // on `panelBackground`, 9 of the 18 kind x mode combinations land at
    // 3.28–4.42:1, i.e. under AA. Chip text therefore uses the dedicated
    // *ChipText variants below, NOT these accents.
    public static var critical: Color   { dyn(dark: srgb(0.96, 0.39, 0.27), light: srgb(0.72, 0.10, 0.05)) }
    public static var high: Color       { dyn(dark: srgb(0.99, 0.62, 0.30), light: srgb(0.66, 0.30, 0.02)) }
    public static var medium: Color     { dyn(dark: srgb(0.98, 0.78, 0.39), light: srgb(0.55, 0.37, 0.00)) }
    public static var low: Color        { dyn(dark: srgb(0.55, 0.65, 0.78), light: srgb(0.32, 0.40, 0.54)) }
    public static var healthy: Color    { dyn(dark: srgb(0.22, 0.72, 0.40), light: srgb(0.10, 0.46, 0.24)) }
    public static var warning: Color    { dyn(dark: srgb(0.96, 0.65, 0.27), light: srgb(0.66, 0.30, 0.02)) }
    public static var aiAccent: Color   { dyn(dark: srgb(0.55, 0.36, 0.92), light: srgb(0.46, 0.24, 0.74)) }
    public static var dataAccent: Color { dyn(dark: srgb(0.20, 0.55, 0.92), light: srgb(0.10, 0.42, 0.74)) }

    // MARK: - Chip text (WCAG 1.4.3)
    //
    // V2StatusChip renders its label in `kind.color` on a 13% wash of that
    // SAME colour, so the text/background pair is near-isoluminant no matter
    // how the base hue is tuned against the canvas. Measured over the wash on
    // `panelBackground`: light high 4.20, medium 4.22, low 4.36, healthy 4.27,
    // warning 4.20, data 4.05; dark critical 4.42, ai 3.28, data 4.04 — all
    // under AA 4.5:1, and `V2Theme.chip()` is .caption semibold (10pt on
    // macOS), far below the 18pt / 14pt-bold large-text exemption.
    //
    // Each variant below is its base hue blended 30% toward the mode's text
    // extreme (black in light, white in dark). That lifts the worst case to
    // 5.34:1 (aiAccent, dark) while leaving the wash, the border, and the
    // overall chip silhouette byte-identical — a pure text-colour fix.
    public static var criticalChipText: Color { dyn(dark: srgb(0.97, 0.57, 0.49), light: srgb(0.50, 0.07, 0.04)) }
    public static var highChipText: Color     { dyn(dark: srgb(0.99, 0.73, 0.51), light: srgb(0.46, 0.21, 0.01)) }
    public static var mediumChipText: Color   { dyn(dark: srgb(0.99, 0.85, 0.57), light: srgb(0.39, 0.26, 0.00)) }
    public static var lowChipText: Color      { dyn(dark: srgb(0.69, 0.76, 0.85), light: srgb(0.22, 0.28, 0.38)) }
    public static var healthyChipText: Color  { dyn(dark: srgb(0.45, 0.80, 0.58), light: srgb(0.07, 0.32, 0.17)) }
    public static var warningChipText: Color  { dyn(dark: srgb(0.97, 0.76, 0.49), light: srgb(0.46, 0.21, 0.01)) }
    public static var aiChipText: Color       { dyn(dark: srgb(0.69, 0.55, 0.94), light: srgb(0.32, 0.17, 0.52)) }
    public static var dataChipText: Color     { dyn(dark: srgb(0.44, 0.69, 0.94), light: srgb(0.07, 0.29, 0.52)) }
    public static var neutralChipText: Color  { dyn(dark: srgb(0.85, 0.82, 0.82), light: srgb(0.18, 0.14, 0.14)) }

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

    /// Brand tint for TEXT. `brand` as a foreground measures 5.91:1 in dark
    /// but only 3.90:1 on `canvasBackground` / 3.65:1 on `panelBackground` in
    /// light — under WCAG AA 4.5:1 for body copy. That is the text telling the
    /// user why their list is filtered (the echoed search string, the time
    /// window), i.e. exactly the copy someone squints at when the alert count
    /// drops unexpectedly. This swaps in the dim variant for light only
    /// (6.83:1) and keeps `brand` in dark (5.91:1).
    ///
    /// Keep using `brand` itself for fills, strokes, selection bars, and small
    /// glyphs: those are graphical objects under 1.4.11, whose bar is 3:1, and
    /// 3.90:1 already clears it. Hex values mirror MacCrabTheme.accentDim
    /// (light, 0xA03010) and MacCrabTheme.accent (dark, 0xFF5E3A); they are
    /// restated as sRGB because Color(light:dark:) is fileprivate to
    /// MacCrabTheme.swift.
    public static var brandText: Color { dyn(dark: srgb(1.000, 0.369, 0.227), light: srgb(0.627, 0.188, 0.063)) }

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

    /// WCAG 2.2 SC 2.5.8 Target Size (Minimum), AA: a pointer target is at
    /// least 24x24. Several icon buttons shipped at 22x22 (and the toast
    /// dismiss at 20x20), which matters most for the Detection table's
    /// enable/disable dot — a stray click there silently turns a detection
    /// rule off. Defined once so the floor is greppable rather than a literal
    /// repeated across a dozen call sites.
    public static let minHitTarget: CGFloat = 24

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


