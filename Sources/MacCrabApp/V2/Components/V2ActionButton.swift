// V2ActionButton.swift
// Primary / secondary / danger / ghost button variants per spec
// §5.4. Supports an explicit `disabled:` flag + tooltip so the
// preview shell can render unwired actions honestly (greyed out
// with a hover hint) instead of firing fake-success toasts.

import SwiftUI

public enum V2ActionStyle: Sendable {
    case primary
    case secondary
    case danger
    case ghost
    /// Subtle semantic tint for inline row actions: colored text on a
    /// 10%-alpha wash of the same color (the History Unsuppress/Delete
    /// look, promoted to a reusable style in v1.18.1).
    case tinted(Color)
}

public enum V2ActionSize: Sendable {
    case regular
    /// Inline / table-row density: smaller type + padding (v1.18.1).
    case compact
}

public struct V2ActionButton: View {
    public let label: String
    public let icon: String?
    public let style: V2ActionStyle
    public let size: V2ActionSize
    /// Expands the button's VISUAL surface (background included) to the
    /// available width — `.frame(maxWidth:)` applied outside the button
    /// only widens the hit area while the drawn button stays intrinsic,
    /// which is what made stacked inspector verbs look ragged (v1.18.1).
    public let fullWidth: Bool
    public let disabled: Bool
    public let tooltip: String?
    public let action: () -> Void

    /// Optional stable XCUITest identifier (v1.21.4 harness foundation).
    public let axId: String?

    public init(
        _ label: String,
        icon: String? = nil,
        style: V2ActionStyle = .secondary,
        size: V2ActionSize = .regular,
        fullWidth: Bool = false,
        disabled: Bool = false,
        tooltip: String? = nil,
        axId: String? = nil,
        action: @escaping () -> Void
    ) {
        self.label = label
        self.icon = icon
        self.style = style
        self.size = size
        self.fullWidth = fullWidth
        self.disabled = disabled
        self.tooltip = tooltip
        self.axId = axId
        self.action = action
    }

    private var compact: Bool { size == .compact }
    private var cornerRadius: CGFloat {
        compact ? V2Theme.chipCornerRadius : V2Theme.smallCornerRadius
    }

    public var body: some View {
        Button(action: action) {
            HStack(spacing: compact ? 4 : 6) {
                if let icon {
                    Image(systemName: icon).scaledSystem(compact ? 10 : 12, weight: .semibold)
                }
                Text(label).scaledSystem(compact ? 12 : 13, weight: .semibold)
            }
            .frame(maxWidth: fullWidth ? .infinity : nil)
            .foregroundStyle(foreground.opacity(disabled ? 0.5 : 1.0))
            .padding(.horizontal, compact ? 8 : 14)
            .padding(.vertical, compact ? 4 : 10)
            .frame(minHeight: compact ? 22 : 32)
            .background(background.opacity(disabled ? 0.5 : 1.0))
            .overlay(
                RoundedRectangle(cornerRadius: cornerRadius)
                    .stroke(border.opacity(disabled ? 0.5 : 1.0), lineWidth: 1)
            )
            .clipShape(RoundedRectangle(cornerRadius: cornerRadius))
            // HIG: 44×44pt minimum tap target. We can't always reach 44
            // because action buttons sit in compact toolbars, but 32pt
            // is the maximum we can bring to tab strips and inspector
            // verb stacks without breaking layout. 32 + intrinsic
            // padding of the parent typically reaches 40-44. (.compact
            // is for inline table-row actions where the row itself is
            // the larger target.)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(disabled)
        .help(tooltip ?? "")
        .v2AXID(axId)
    }

    private var foreground: Color {
        switch style {
        case .primary: return .white
        case .secondary: return V2Theme.primaryText
        case .danger: return .white
        case .ghost: return V2Theme.mutedText
        case .tinted(let color): return color
        }
    }

    private var background: Color {
        switch style {
        // WCAG AA: white-on-brand is 3.04:1; brandDim (accentDim) is 5.28:1 — pass.
        case .primary: return V2Theme.brandDim
        case .secondary: return V2Theme.hoverBackground
        case .danger: return V2Theme.critical
        case .ghost: return .clear
        case .tinted(let color): return color.opacity(0.10)
        }
    }

    private var border: Color {
        switch style {
        case .primary: return V2Theme.brand.opacity(0.4)
        case .secondary: return V2Theme.panelBorder
        case .danger: return V2Theme.critical.opacity(0.4)
        case .ghost: return V2Theme.panelBorder.opacity(0.6)
        case .tinted(let color): return color.opacity(0.25)
        }
    }
}
