// JSONTreeView — universal fallback. Renders a list of
// artifacts as collapsible JSON trees. Used when a plugin's
// OutputSpec doesn't declare a viewerHint, or when no plugin
// is registered for the content type (orphaned legacy
// artifacts).
//
// Each artifact is a top-level DisclosureGroup. Nested
// objects + arrays are recursively collapsible.

import SwiftUI
import MacCrabForensics

struct JSONTreeView: View {
    let artifacts: [CommittedArtifact]
    @State private var openedID: Int64? = nil

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 6) {
                ForEach(artifacts.prefix(200), id: \.id) { a in
                    // Custom disclosure: the whole summary row toggles,
                    // not just the triangle. SwiftUI's DisclosureGroup
                    // only flips on a click of the chevron itself, which
                    // operators found fiddly — the full block should work.
                    let isOpen = openedID == a.id
                    VStack(alignment: .leading, spacing: 0) {
                        Button {
                            withAnimation(.easeInOut(duration: 0.15)) {
                                openedID = isOpen ? nil : a.id
                            }
                        } label: {
                            HStack(spacing: 6) {
                                Image(systemName: isOpen ? "chevron.down" : "chevron.right")
                                    .scaledSystem(9, weight: .semibold)
                                    .foregroundStyle(.secondary)
                                    .frame(width: 10)
                                artifactSummary(a)
                            }
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        if isOpen {
                            artifactDetail(a)
                                .padding(.top, 4)
                                .padding(.leading, 16)
                        }
                    }
                    .padding(.vertical, 4)
                    Divider()
                }
                if artifacts.count > 200 {
                    Text("Showing first 200 of \(artifacts.count) artifacts.")
                        .scaledSystem(11)
                        .foregroundStyle(.tertiary)
                        .padding(.top, 6)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(12)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(8)
    }

    private func artifactSummary(_ a: CommittedArtifact) -> some View {
        HStack(spacing: 6) {
            Text(a.record.summary ?? a.record.contentType)
                .scaledSystem(12, weight: .medium)
                .lineLimit(1)
            Spacer()
            Text(a.record.observedAt.formatted(date: .abbreviated, time: .shortened))
                .scaledSystem(10)
                .foregroundStyle(.tertiary)
        }
        .contentShape(Rectangle())
    }

    private func artifactDetail(_ a: CommittedArtifact) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            recordFields(a)
            if !a.record.data.isEmpty {
                Text("data:")
                    .scaledSystem(10, weight: .semibold, design: .monospaced)
                    .foregroundStyle(.tertiary)
                    .padding(.top, 4)
                JSONNodeView(value: .object(a.record.data), depth: 1)
            }
        }
        .padding(8)
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(4)
    }

    private func recordFields(_ a: CommittedArtifact) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            kvLine("content_type", a.record.contentType)
            kvLine("plugin_id",    a.record.pluginID)
            kvLine("observed_at",  ISO8601DateFormatter().string(from: a.record.observedAt))
            if let sp = a.record.sourcePath {
                kvLine("source_path", sp)
            }
            kvLine("sha256",      a.record.sha256)
            kvLine("privacy",     a.record.privacyClass.rawValue)
        }
    }

    private func kvLine(_ k: String, _ v: String) -> some View {
        HStack(alignment: .top, spacing: 6) {
            Text(k).scaledSystem(10, design: .monospaced)
                .foregroundStyle(.secondary)
                .frame(width: 100, alignment: .trailing)
            Text(v).scaledSystem(10, design: .monospaced)
                .foregroundStyle(.primary)
                .lineLimit(1)
                .truncationMode(.middle)
                .textSelection(.enabled)
        }
    }
}

/// Recursive renderer for one JSONValue node.
struct JSONNodeView: View {
    let value: JSONValue
    let depth: Int

    private let leafFont = Font.system(size: 10, design: .monospaced)

    var body: some View {
        switch value {
        case .string(let s):
            Text("\"\(s)\"").font(leafFont).foregroundStyle(.green).textSelection(.enabled)
        case .integer(let i):
            Text("\(i)").font(leafFont).foregroundStyle(.blue).textSelection(.enabled)
        case .double(let d):
            Text(String(format: "%g", d)).font(leafFont).foregroundStyle(.blue)
        case .bool(let b):
            Text(b ? "true" : "false").font(leafFont).foregroundStyle(.purple)
        case .null:
            Text("null").font(leafFont).foregroundStyle(.tertiary)
        case .array(let arr):
            VStack(alignment: .leading, spacing: 1) {
                ForEach(Array(arr.enumerated()), id: \.offset) { idx, item in
                    HStack(alignment: .top, spacing: 4) {
                        Text("[\(idx)]").font(leafFont).foregroundStyle(.tertiary)
                        JSONNodeView(value: item, depth: depth + 1)
                    }
                }
            }
            .padding(.leading, 8)
        case .object(let obj):
            VStack(alignment: .leading, spacing: 1) {
                ForEach(obj.keys.sorted(), id: \.self) { k in
                    HStack(alignment: .top, spacing: 6) {
                        Text("\(k):").font(leafFont).foregroundStyle(.orange).textSelection(.enabled)
                        JSONNodeView(value: obj[k]!, depth: depth + 1)
                    }
                }
            }
            .padding(.leading, depth > 1 ? 8 : 0)
        }
    }
}
