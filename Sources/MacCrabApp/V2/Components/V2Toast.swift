// V2Toast.swift
// Transient notification surface. State manages a single active
// toast at a time; the shell renders it bottom-right and dismisses
// after `displayFor` seconds.

import SwiftUI
import AppKit

public struct V2Toast: Identifiable, Equatable, Sendable {
    public enum Kind: Sendable { case success, info, warning, error }
    public let id = UUID()
    public let kind: Kind
    public let title: String
    public let detail: String?
    public let displayFor: TimeInterval

    public init(kind: Kind, title: String, detail: String? = nil, displayFor: TimeInterval = 3.0) {
        self.kind = kind
        self.title = title
        self.detail = detail
        self.displayFor = displayFor
    }

    public var icon: String {
        switch kind {
        case .success: return "checkmark.circle.fill"
        case .info:    return "info.circle.fill"
        case .warning: return "exclamationmark.triangle.fill"
        case .error:   return "xmark.octagon.fill"
        }
    }

    public var color: Color {
        switch kind {
        case .success: return V2Theme.healthy
        case .info:    return V2Theme.dataAccent
        case .warning: return V2Theme.warning
        case .error:   return V2Theme.critical
        }
    }
}

public struct V2ToastView: View {
    public let toast: V2Toast
    public let onDismiss: () -> Void

    public init(toast: V2Toast, onDismiss: @escaping () -> Void) {
        self.toast = toast
        self.onDismiss = onDismiss
    }

    public var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: toast.icon)
                .foregroundStyle(toast.color)
                .font(.system(size: 16, weight: .semibold))
            VStack(alignment: .leading, spacing: 2) {
                Text(toast.title)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(V2Theme.primaryText)
                if let detail = toast.detail {
                    Text(detail)
                        .font(V2Theme.meta())
                        .foregroundStyle(V2Theme.mutedText)
                }
            }
            Spacer(minLength: 12)
            Button(action: onDismiss) {
                Image(systemName: "xmark")
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundStyle(V2Theme.mutedText)
                    .frame(width: 20, height: 20)
                    .background(V2Theme.panelBackground)
                    .clipShape(Circle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Dismiss notification")
        }
        .padding(12)
        .frame(width: 360, alignment: .leading)
        .background(V2Theme.sidebarBackground)
        .overlay(
            RoundedRectangle(cornerRadius: V2Theme.cornerRadius)
                .stroke(toast.color.opacity(0.4), lineWidth: 1)
        )
        .clipShape(RoundedRectangle(cornerRadius: V2Theme.cornerRadius))
        .shadow(color: Color.black.opacity(0.4), radius: 18, x: 0, y: 6)
        // VoiceOver: toasts are time-sensitive feedback. Without an
        // explicit announcement, sighted users see the toast but VO
        // users get nothing — a per-action result that arrives as
        // visible chrome AND as text means the surface is the only
        // accessible signal of success/failure.
        .onAppear {
            let body = toast.detail.map { "\(toast.title) — \($0)" } ?? toast.title
            NSAccessibility.post(
                element: NSApp.mainWindow ?? NSApp,
                notification: .announcementRequested,
                userInfo: [
                    .announcement: body,
                    .priority: NSAccessibilityPriorityLevel.high.rawValue
                ]
            )
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(toast.detail.map { "\(toast.title), \($0)" } ?? toast.title)
        .accessibilityAddTraits(.isStaticText)
    }
}
