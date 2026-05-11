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
}

public struct V2ActionButton: View {
    public let label: String
    public let icon: String?
    public let style: V2ActionStyle
    public let disabled: Bool
    public let tooltip: String?
    public let action: () -> Void

    public init(
        _ label: String,
        icon: String? = nil,
        style: V2ActionStyle = .secondary,
        disabled: Bool = false,
        tooltip: String? = nil,
        action: @escaping () -> Void
    ) {
        self.label = label
        self.icon = icon
        self.style = style
        self.disabled = disabled
        self.tooltip = tooltip
        self.action = action
    }

    public var body: some View {
        Button(action: action) {
            HStack(spacing: 6) {
                if let icon {
                    Image(systemName: icon).font(.system(size: 12, weight: .semibold))
                }
                Text(label).font(.system(size: 13, weight: .semibold))
            }
            .foregroundStyle(foreground.opacity(disabled ? 0.5 : 1.0))
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
            .frame(minHeight: 32)
            .background(background.opacity(disabled ? 0.5 : 1.0))
            .overlay(
                RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius)
                    .stroke(border.opacity(disabled ? 0.5 : 1.0), lineWidth: 1)
            )
            .clipShape(RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius))
            // HIG: 44×44pt minimum tap target. We can't always reach 44
            // because action buttons sit in compact toolbars, but 32pt
            // is the maximum we can bring to tab strips and inspector
            // verb stacks without breaking layout. 32 + intrinsic
            // padding of the parent typically reaches 40-44.
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(disabled)
        .help(tooltip ?? "")
    }

    private var foreground: Color {
        switch style {
        case .primary: return .white
        case .secondary: return V2Theme.primaryText
        case .danger: return .white
        case .ghost: return V2Theme.mutedText
        }
    }

    private var background: Color {
        switch style {
        case .primary: return V2Theme.brand
        case .secondary: return V2Theme.hoverBackground
        case .danger: return V2Theme.critical
        case .ghost: return .clear
        }
    }

    private var border: Color {
        switch style {
        case .primary: return V2Theme.brand.opacity(0.4)
        case .secondary: return V2Theme.panelBorder
        case .danger: return V2Theme.critical.opacity(0.4)
        case .ghost: return V2Theme.panelBorder.opacity(0.6)
        }
    }
}
