// ArtifactLayoutView — renders a plugin-supplied LayoutNode
// template against each artifact. Escape hatch for plugins whose
// output doesn't fit the four built-in viewers.
//
// The DSL is deliberately small (section / row / headerKV /
// list / badge / text). If a plugin author needs more, the
// right answer is to propose a new ViewerKind to the host
// repo; that addition benefits every plugin.

import SwiftUI
import MacCrabForensics

struct ArtifactLayoutView: View {
    let artifacts: [CommittedArtifact]
    let hint: ViewerHint

    @State private var selectedID: Int64? = nil

    private var template: LayoutNode? { hint.template }

    private var selected: CommittedArtifact? {
        if let id = selectedID, let a = artifacts.first(where: { $0.id == id }) {
            return a
        }
        return artifacts.first
    }

    var body: some View {
        Group {
            if template == nil {
                Text("Plugin selected viewer=.layout but didn't supply a template. Falling back to JSON tree.")
                    .font(.system(size: 11))
                    .foregroundStyle(.orange)
                    .padding(10)
                JSONTreeView(artifacts: artifacts)
            } else if artifacts.count > 1 {
                HStack(spacing: 0) {
                    pickerColumn
                        .frame(width: 240)
                    Divider()
                    detailColumn
                }
            } else if let a = selected, let t = template {
                ScrollView {
                    LayoutNodeView(node: t, artifact: a)
                        .padding(14)
                }
            }
        }
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(8)
    }

    private var pickerColumn: some View {
        ScrollView {
            VStack(spacing: 0) {
                ForEach(artifacts.prefix(200), id: \.id) { a in
                    Button {
                        selectedID = a.id
                    } label: {
                        Text(a.record.summary ?? a.record.contentType)
                            .font(.system(size: 11))
                            .lineLimit(1)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.horizontal, 10).padding(.vertical, 6)
                            .background(selected?.id == a.id ? Color.accentColor.opacity(0.12) : Color.clear)
                    }
                    .buttonStyle(.plain)
                }
            }
        }
    }

    @ViewBuilder
    private var detailColumn: some View {
        if let a = selected, let t = template {
            ScrollView {
                LayoutNodeView(node: t, artifact: a)
                    .padding(14)
            }
        }
    }
}

// MARK: - Recursive renderer

struct LayoutNodeView: View {
    let node: LayoutNode
    let artifact: CommittedArtifact

    var body: some View {
        switch node {
        case .section(let title, let children):
            VStack(alignment: .leading, spacing: 6) {
                if let t = title {
                    Text(t)
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundStyle(.tertiary)
                        .textCase(.uppercase)
                }
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(Array(children.enumerated()), id: \.offset) { _, child in
                        LayoutNodeView(node: child, artifact: artifact)
                    }
                }
            }
            .padding(.bottom, 6)

        case .row(let label, let field, let format):
            HStack(alignment: .top, spacing: 12) {
                Text(label)
                    .font(.system(size: 11, weight: .medium))
                    .foregroundStyle(.tertiary)
                    .frame(width: 110, alignment: .trailing)
                Text(FieldResolver.resolve(artifact, field: field).displayString(format: format))
                    .font(font(for: format))
                    .foregroundStyle(color(for: format))
                    .textSelection(.enabled)
                Spacer()
            }

        case .headerKV(let label, let field, let format):
            VStack(alignment: .leading, spacing: 2) {
                Text(label)
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundStyle(.tertiary)
                    .textCase(.uppercase)
                Text(FieldResolver.resolve(artifact, field: field).displayString(format: format))
                    .font(.system(size: 18, weight: .semibold, design: .rounded))
                    .textSelection(.enabled)
            }
            .padding(.bottom, 4)

        case .list(let label, let field):
            VStack(alignment: .leading, spacing: 3) {
                Text(label)
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundStyle(.tertiary)
                    .textCase(.uppercase)
                listItems(forField: field)
            }

        case .badge(let label, let field, let colorName):
            HStack(spacing: 6) {
                Text(label)
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
                Text(FieldResolver.resolve(artifact, field: field).displayString())
                    .font(.system(size: 10, weight: .medium))
                    .padding(.horizontal, 6).padding(.vertical, 1)
                    .background(badgeBackground(colorName))
                    .foregroundStyle(badgeForeground(colorName))
                    .cornerRadius(3)
            }

        case .text(let content):
            Text(content)
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
        }
    }

    @ViewBuilder
    private func listItems(forField field: String) -> some View {
        let v = FieldResolver.resolve(artifact, field: field)
        if case .array(let arr) = v {
            ForEach(Array(arr.prefix(50).enumerated()), id: \.offset) { _, item in
                HStack(alignment: .top, spacing: 4) {
                    Text("•").font(.system(size: 11)).foregroundStyle(.tertiary)
                    Text(FieldResolver.wrap(item).displayString())
                        .font(.system(size: 11))
                        .textSelection(.enabled)
                }
            }
        } else {
            Text("(not a list)")
                .font(.system(size: 10))
                .foregroundStyle(.tertiary)
        }
    }

    private func font(for format: LayoutFormat?) -> Font {
        switch format ?? .plain {
        case .monospace, .path: return .system(size: 11, design: .monospaced)
        case .bold:             return .system(size: 12, weight: .semibold)
        case .muted:            return .system(size: 11)
        default:                return .system(size: 12)
        }
    }

    private func color(for format: LayoutFormat?) -> Color {
        switch format ?? .plain {
        case .muted:    return .secondary
        case .urlLink:  return .accentColor
        default:        return .primary
        }
    }

    private func badgeBackground(_ name: String?) -> Color {
        switch (name ?? "").lowercased() {
        case "red":     return Color.red.opacity(0.18)
        case "orange":  return Color.orange.opacity(0.18)
        case "blue":    return Color.blue.opacity(0.18)
        case "green":   return Color.green.opacity(0.18)
        case "purple":  return Color.purple.opacity(0.18)
        default:        return Color.secondary.opacity(0.15)
        }
    }

    private func badgeForeground(_ name: String?) -> Color {
        switch (name ?? "").lowercased() {
        case "red":     return .red
        case "orange":  return .orange
        case "blue":    return .blue
        case "green":   return .green
        case "purple":  return .purple
        default:        return .secondary
        }
    }
}
