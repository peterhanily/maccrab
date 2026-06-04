// V2WorkspaceHeader.swift
// Workspace title + optional subtitle + optional trailing actions.

import SwiftUI

public struct V2WorkspaceHeader<Trailing: View>: View {
    public let title: String
    public let subtitle: String?
    public let trailing: () -> Trailing

    public init(
        title: String,
        subtitle: String? = nil,
        @ViewBuilder trailing: @escaping () -> Trailing = { EmptyView() }
    ) {
        self.title = title
        self.subtitle = subtitle
        self.trailing = trailing
    }

    public var body: some View {
        HStack(alignment: .center, spacing: 10) {
            Text(title).font(V2Theme.workspaceTitle()).foregroundStyle(V2Theme.primaryText)
            if let subtitle {
                Text(subtitle)
                    .font(V2Theme.meta())
                    .foregroundStyle(V2Theme.tertiaryText)
                    .padding(.leading, 2)
            }
            Spacer()
            trailing()
        }
        .padding(.horizontal, 18)
        .padding(.vertical, 8)
    }
}

// MARK: - Tab strip

public struct V2WorkspaceTabStrip: View {
    public let tabs: [V2WorkspaceTab]
    @Binding public var selected: V2WorkspaceTab?

    public init(tabs: [V2WorkspaceTab], selected: Binding<V2WorkspaceTab?>) {
        self.tabs = tabs
        self._selected = selected
    }

    public var body: some View {
        HStack(spacing: 4) {
            ForEach(tabs) { tab in
                let isOn = selected == tab
                Button {
                    selected = tab
                } label: {
                    Text(tab.title)
                        .scaledSystem(13, weight: isOn ? .semibold : .medium)
                        .foregroundStyle(isOn ? V2Theme.primaryText : V2Theme.mutedText)
                        .padding(.horizontal, 12)
                        .padding(.vertical, 6)
                        .background(isOn ? V2Theme.panelBackground : .clear)
                        .overlay(
                            RoundedRectangle(cornerRadius: 6)
                                .stroke(isOn ? V2Theme.panelBorder : .clear, lineWidth: 1)
                        )
                        .clipShape(RoundedRectangle(cornerRadius: 6))
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityAddTraits(isOn ? [.isSelected] : [])
                .accessibilityLabel("\(tab.title) tab")
            }
            Spacer()
        }
        .padding(.horizontal, 24)
        .padding(.bottom, 8)
    }
}
