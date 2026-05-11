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
                    .font(.system(size: 10, weight: .semibold))
            }
            Text(label.localizedUppercase)
                .font(V2Theme.chip())
        }
        .foregroundStyle(kind.color)
        .padding(.horizontal, 7)
        .padding(.vertical, 3)
        .background(kind.color.opacity(0.13))
        .clipShape(RoundedRectangle(cornerRadius: V2Theme.chipCornerRadius))
        .overlay(
            RoundedRectangle(cornerRadius: V2Theme.chipCornerRadius)
                .stroke(kind.color.opacity(0.25), lineWidth: 1)
        )
        .accessibilityLabel(label)
    }
}

// MARK: - Severity dot

public struct V2SeverityDot: View {
    public let kind: V2ChipKind
    public init(_ kind: V2ChipKind) { self.kind = kind }
    public var body: some View {
        Circle()
            .fill(kind.color)
            .frame(width: 8, height: 8)
            .accessibilityHidden(true)
    }
}
