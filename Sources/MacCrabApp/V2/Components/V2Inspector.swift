// V2Inspector.swift
// Right-side inspector container + reusable section/row primitives.
// Per spec §5.3.

import SwiftUI

public struct V2Inspector<Content: View>: View {
    public let title: String
    public let subtitle: String?
    public let onClose: (() -> Void)?
    @ViewBuilder public let content: () -> Content

    public init(
        title: String,
        subtitle: String? = nil,
        onClose: (() -> Void)? = nil,
        @ViewBuilder content: @escaping () -> Content
    ) {
        self.title = title
        self.subtitle = subtitle
        self.onClose = onClose
        self.content = content
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .top, spacing: 8) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .scaledSystem(15, weight: .semibold)
                        .foregroundStyle(V2Theme.primaryText)
                        .lineLimit(2)
                    if let subtitle {
                        Text(subtitle)
                            .font(V2Theme.meta())
                            .foregroundStyle(V2Theme.mutedText)
                    }
                }
                Spacer()
                if let onClose {
                    Button(action: onClose) {
                        Image(systemName: "xmark")
                            .scaledSystem(11, weight: .semibold)
                            .foregroundStyle(V2Theme.mutedText)
                            .frame(width: 22, height: 22)
                            .background(V2Theme.panelBackground)
                            .clipShape(Circle())
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("Close inspector")
                }
            }
            .padding(14)
            Divider().background(V2Theme.panelBorder)

            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    content()
                }
                .padding(14)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .frame(width: V2Theme.inspectorWidth)
        .frame(maxHeight: .infinity)
        .background(V2Theme.inspectorBackground)
        .overlay(
            Rectangle().fill(V2Theme.panelBorder).frame(width: 1),
            alignment: .leading
        )
    }
}

public struct V2InspectorSection<Content: View>: View {
    public let title: String
    @ViewBuilder public let content: () -> Content
    public init(_ title: String, @ViewBuilder content: @escaping () -> Content) {
        self.title = title
        self.content = content
    }
    public var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title.localizedUppercase)
                .font(V2Theme.cardTitle())
                .foregroundStyle(V2Theme.tertiaryText)
            content()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

public struct V2InspectorKeyValue: View {
    public let key: String
    public let value: String
    public let mono: Bool
    public init(_ key: String, _ value: String, mono: Bool = false) {
        self.key = key
        self.value = value
        self.mono = mono
    }
    public var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Text(key)
                .font(V2Theme.meta())
                .foregroundStyle(V2Theme.mutedText)
                .frame(width: 100, alignment: .leading)
            Text(value)
                .font(mono ? V2Theme.mono() : V2Theme.body())
                .foregroundStyle(V2Theme.primaryText)
                .frame(maxWidth: .infinity, alignment: .leading)
                .textSelection(.enabled)
        }
    }
}
