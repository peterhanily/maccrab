// V2StateViews.swift
// Empty / Loading / Error states per spec §6.3. Every workspace
// and major component must render these four states cleanly.

import SwiftUI

public struct V2EmptyState: View {
    public let title: String
    public let message: String?
    public let icon: String
    public let action: (label: String, handler: () -> Void)?

    public init(
        title: String,
        body: String? = nil,
        icon: String = "tray",
        action: (label: String, handler: () -> Void)? = nil
    ) {
        self.title = title
        self.message = body
        self.icon = icon
        self.action = action
    }

    public var body: some View {
        VStack(spacing: 14) {
            Image(systemName: icon)
                .scaledSystem(36, weight: .light)
                .foregroundStyle(V2Theme.mutedText)
                .padding(20)
                .background(V2Theme.panelBackground)
                .clipShape(Circle())
                .overlay(Circle().stroke(V2Theme.panelBorder, lineWidth: 1))
            Text(title)
                .scaledSystem(16, weight: .semibold)
                .foregroundStyle(V2Theme.primaryText)
            if let message {
                Text(message)
                    .font(V2Theme.body())
                    .foregroundStyle(V2Theme.mutedText)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 360)
            }
            if let action {
                V2ActionButton(action.label, style: .secondary, action: action.handler)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

public struct V2LoadingState: View {
    public let title: String?
    public init(title: String? = nil) { self.title = title }

    public var body: some View {
        VStack(spacing: 12) {
            ProgressView()
                .controlSize(.regular)
                .tint(V2Theme.dataAccent)
            if let title {
                Text(title)
                    .font(V2Theme.body())
                    .foregroundStyle(V2Theme.mutedText)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

public struct V2ErrorState: View {
    public let title: String
    public let message: String
    public let retry: (() -> Void)?

    public init(title: String, body: String, retry: (() -> Void)? = nil) {
        self.title = title
        self.message = body
        self.retry = retry
    }

    public var body: some View {
        VStack(spacing: 14) {
            Image(systemName: "exclamationmark.triangle.fill")
                .scaledSystem(36)
                .foregroundStyle(V2Theme.warning)
            Text(title)
                .scaledSystem(16, weight: .semibold)
                .foregroundStyle(V2Theme.primaryText)
            Text(message)
                .font(V2Theme.body())
                .foregroundStyle(V2Theme.mutedText)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 360)
            if let retry {
                V2ActionButton("Retry", icon: "arrow.clockwise", style: .secondary, action: retry)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

// MARK: - Skeleton placeholder

public struct V2Skeleton: View {
    public let width: CGFloat?
    public let height: CGFloat
    public init(width: CGFloat? = nil, height: CGFloat = 12) {
        self.width = width
        self.height = height
    }
    public var body: some View {
        RoundedRectangle(cornerRadius: 4)
            .fill(V2Theme.hoverBackground)
            .frame(width: width, height: height)
    }
}
