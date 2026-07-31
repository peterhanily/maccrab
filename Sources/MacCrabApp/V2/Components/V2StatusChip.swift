// V2StatusChip.swift
// Severity / health / status label component per spec §5.1.

import SwiftUI

public enum V2ChipKind: Sendable, Equatable {
    case critical, high, medium, low
    case healthy, warning, degraded, down
    case info, neutral
    case ai, data
    case custom(Color)

    public var color: Color {
        switch self {
        case .critical:        return V2Theme.critical
        case .high:            return V2Theme.high
        case .medium:          return V2Theme.medium
        case .low:             return V2Theme.low
        case .healthy:         return V2Theme.healthy
        case .warning:         return V2Theme.warning
        case .degraded:        return V2Theme.warning
        case .down:            return V2Theme.critical
        case .info:            return V2Theme.dataAccent
        case .neutral:         return V2Theme.neutral
        case .ai:              return V2Theme.aiAccent
        case .data:            return V2Theme.dataAccent
        case .custom(let c):   return c
        }
    }

    /// Text/glyph colour for V2StatusChip. NOT the same as `color`.
    ///
    /// The chip paints its label in the kind's hue on a 13% wash of that same
    /// hue, so foreground and background move together and the pair stays
    /// near-isoluminant however the base accent is tuned. Measured over the
    /// wash on `panelBackground`, 9 of the 18 kind x mode combinations sat at
    /// 3.28–4.42:1 — under WCAG AA 4.5:1 for the chip's 10pt semibold font.
    /// These variants (base hue blended 30% toward the mode's text extreme)
    /// lift the worst case to 5.34:1 without touching the wash or border.
    var chipTextColor: Color {
        switch self {
        case .critical, .down:        return V2Theme.criticalChipText
        case .high:                   return V2Theme.highChipText
        case .medium:                 return V2Theme.mediumChipText
        case .low:                    return V2Theme.lowChipText
        case .healthy:                return V2Theme.healthyChipText
        case .warning, .degraded:     return V2Theme.warningChipText
        case .info, .data:            return V2Theme.dataChipText
        case .neutral:                return V2Theme.neutralChipText
        case .ai:                     return V2Theme.aiChipText
        // Caller-supplied: no derived variant exists, so this one is on the
        // call site. Only used by ad-hoc chips, none of which are severity.
        case .custom(let c):          return c
        }
    }
}

public struct V2StatusChip: View {
    public let label: String
    public let kind: V2ChipKind
    public let icon: String?

    public init(_ label: String, kind: V2ChipKind, icon: String? = nil) {
        self.label = label
        self.kind = kind
        self.icon = icon
    }

    public var body: some View {
        HStack(spacing: 4) {
            if let icon {
                Image(systemName: icon)
                    .scaledSystem(10, weight: .semibold)
            }
            Text(label.localizedUppercase)
                .font(V2Theme.chip())
        }
        // WCAG 1.4.3: was `kind.color`, which is also the colour of the 13%
        // wash two lines below — foreground and background moved together, so
        // 9 of 18 kind x mode combinations measured 3.28–4.42:1 on a panel.
        // `chipTextColor` is the same hue pushed 30% toward the mode's text
        // extreme; worst case is now 5.34:1. The wash and border deliberately
        // stay on `kind.color` so the chip looks unchanged.
        .foregroundStyle(kind.chipTextColor)
        .padding(.horizontal, 7)
        .padding(.vertical, 3)
        .background(kind.color.opacity(0.13))
        .clipShape(RoundedRectangle(cornerRadius: V2Theme.chipCornerRadius))
        .overlay(
            RoundedRectangle(cornerRadius: V2Theme.chipCornerRadius)
                .stroke(kind.color.opacity(0.25), lineWidth: 1)
        )
        // v1.12.0 RC28 audit fix (UX a11y): include the semantic
        // status name in the accessibility label. Pre-fix VoiceOver
        // read just the user-visible text (e.g., "Connected"), losing
        // the kind context that sighted users get from the color
        // (red/critical, amber/warning, green/healthy). Now VO reads
        // "Healthy: Connected" so the severity is part of the line.
        .accessibilityLabel("\(kind.accessibilityName): \(label)")
    }
}

extension V2ChipKind {
    /// Spoken-form severity name for VoiceOver. v1.12.0 RC28.
    ///
    /// i18n (2026-07): these were bare English literals while the app ships 14
    /// localizations, and V2StatusChip splices this straight onto an already
    /// localized `label` — so a French VoiceOver user heard "High severity:
    /// Élevé", a half-translated line that breaks shared vocabulary with a
    /// sighted colleague reading the same row. This is the highest-frequency
    /// accessibility string in the product (every alert, trace, KPI and rule
    /// row carries a chip), so it goes first. The 13 untranslated catalogs
    /// fall back to `defaultValue`, which is correct behaviour and makes the
    /// gap visible to translators instead of silent.
    var accessibilityName: String {
        switch self {
        case .critical:   return String(localized: "ax.chip.critical", defaultValue: "Critical")
        case .high:       return String(localized: "ax.chip.high", defaultValue: "High severity")
        case .medium:     return String(localized: "ax.chip.medium", defaultValue: "Medium severity")
        case .low:        return String(localized: "ax.chip.low", defaultValue: "Low severity")
        case .healthy:    return String(localized: "ax.chip.healthy", defaultValue: "Healthy")
        case .warning:    return String(localized: "ax.chip.warning", defaultValue: "Warning")
        case .degraded:   return String(localized: "ax.chip.degraded", defaultValue: "Degraded")
        case .down:       return String(localized: "ax.chip.down", defaultValue: "Down")
        case .info:       return String(localized: "ax.chip.info", defaultValue: "Informational")
        case .neutral:    return String(localized: "ax.chip.neutral", defaultValue: "Neutral")
        case .ai:         return String(localized: "ax.chip.ai", defaultValue: "AI")
        case .data:       return String(localized: "ax.chip.data", defaultValue: "Data")
        case .custom:     return String(localized: "ax.chip.custom", defaultValue: "Custom")
        }
    }

    /// RC H3 (a11y): a distinct SHAPE per severity so the dot doesn't encode
    /// meaning by color alone (color-blind users). Severity tiers get clearly
    /// different geometry: octagon (critical) / triangle (high) / diamond
    /// (medium) / circle (low/info).
    var shapeSymbol: String {
        switch self {
        case .critical, .down:            return "octagon.fill"
        case .high, .warning, .degraded:  return "triangle.fill"
        case .medium:                     return "diamond.fill"
        case .healthy:                    return "checkmark.circle.fill"
        case .low, .info, .neutral, .ai, .data, .custom:
            return "circle.fill"
        }
    }
}

// MARK: - Severity dot

public struct V2SeverityDot: View {
    public let kind: V2ChipKind
    public init(_ kind: V2ChipKind) { self.kind = kind }
    public var body: some View {
        // RC H3 (a11y): shape-encode severity (not color alone) so color-blind
        // users can distinguish it, and expose it to VoiceOver — this dot is
        // sometimes the SOLE severity indicator in a row (was a plain Circle +
        // accessibilityHidden). Footprint kept at ~8pt.
        Image(systemName: kind.shapeSymbol)
            .scaledSystem(8)
            .foregroundStyle(kind.color)
            .frame(width: 9, height: 9)
            .accessibilityLabel(kind.accessibilityName)
    }
}
