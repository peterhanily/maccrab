// V2RaveCatalogBrowserView.swift — rc.9 in-workspace catalog panel.
//
// Bambu-Studio-shape browse experience, now mounted as the third
// Forensics tab (Scans / Findings / Catalog) instead of a buried
// Settings sheet.
//
// Layout:
//   - Hero header with catalog source + refresh
//   - Left sidebar: All / Featured / Categories
//   - Center grid: plugin cards with icon + name + tags
//   - Right detail panel when a card is selected: description,
//     install command
//
// Source data is RaveCatalogClient (Ed25519-verified fetch).
// Rich fields (icon URL, screenshots, long description) are
// optional per the rave catalog schema — we degrade to a
// monogram icon + the description that is in the manifest.

import SwiftUI

struct V2RaveCatalogBrowserView: View {
    @State private var entries: [RaveCatalogEntry] = []
    @State private var loading = true
    @State private var error: String? = nil
    @State private var baseURL: String = ""
    @State private var selectedID: String? = nil
    @State private var selectedCategory: String? = nil  // nil = All
    @State private var showFeaturedOnly = false
    @State private var copiedID: String? = nil

    private let client = RaveCatalogClient()

    private var categories: [String] {
        let set = Set(entries.compactMap { $0.category })
        return set.sorted()
    }

    private var visibleEntries: [RaveCatalogEntry] {
        entries.filter { e in
            if showFeaturedOnly, e.trustTier != "first-party" { return false }
            if let cat = selectedCategory, e.category != cat { return false }
            return true
        }
    }

    private var selectedEntry: RaveCatalogEntry? {
        entries.first { $0.id == selectedID }
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            if loading {
                loadingView
            } else if let err = error {
                errorView(err)
            } else if entries.isEmpty {
                emptyView
            } else {
                HStack(spacing: 0) {
                    sidebar
                    Divider()
                    grid
                    Divider()
                    detailPanel
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .task { await reload() }
    }

    // MARK: - Header

    private var header: some View {
        HStack(spacing: 14) {
            Image(systemName: "shippingbox.fill")
                .font(.system(size: 22))
                .foregroundStyle(.tint)
                .padding(8)
                .background(Color.accentColor.opacity(0.12))
                .cornerRadius(8)
            VStack(alignment: .leading, spacing: 2) {
                Text("Plugin catalog")
                    .font(.title2).fontWeight(.semibold)
                Text(baseURL.isEmpty ? "maccrab.com/rave" : baseURL)
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button {
                Task { await reload() }
            } label: {
                Image(systemName: "arrow.clockwise")
            }
            .help("Refresh")
        }
        .padding(.horizontal, 20).padding(.vertical, 16)
    }

    // MARK: - Sidebar

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 4) {
            sidebarHeader("Browse")
            sidebarRow("All scanners",
                       icon: "square.grid.2x2",
                       isSelected: selectedCategory == nil && !showFeaturedOnly,
                       count: entries.count) {
                selectedCategory = nil
                showFeaturedOnly = false
            }
            sidebarRow("Featured (first-party)",
                       icon: "sparkles",
                       isSelected: showFeaturedOnly,
                       count: entries.filter { $0.trustTier == "first-party" }.count) {
                showFeaturedOnly.toggle()
                if showFeaturedOnly { selectedCategory = nil }
            }
            if !categories.isEmpty {
                sidebarHeader("Categories").padding(.top, 16)
                ForEach(categories, id: \.self) { cat in
                    sidebarRow(cat.capitalized,
                               icon: categoryIcon(cat),
                               isSelected: selectedCategory == cat,
                               count: entries.filter { $0.category == cat }.count) {
                        selectedCategory = (selectedCategory == cat) ? nil : cat
                        showFeaturedOnly = false
                    }
                }
            }
            Spacer()
        }
        .padding(14)
        .frame(width: 220)
        .background(Color(NSColor.controlBackgroundColor).opacity(0.5))
    }

    private func sidebarHeader(_ s: String) -> some View {
        Text(s)
            .font(.system(size: 10, weight: .semibold))
            .foregroundStyle(.tertiary)
            .textCase(.uppercase)
            .padding(.bottom, 4)
    }

    private func sidebarRow(_ label: String, icon: String, isSelected: Bool, count: Int, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 8) {
                Image(systemName: icon)
                    .font(.system(size: 11))
                    .frame(width: 14)
                Text(label).font(.system(size: 12))
                Spacer()
                Text("\(count)")
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
            }
            .padding(.horizontal, 8).padding(.vertical, 5)
            .background(isSelected ? Color.accentColor.opacity(0.15) : Color.clear)
            .foregroundStyle(isSelected ? Color.accentColor : .primary)
            .cornerRadius(4)
        }
        .buttonStyle(.plain)
    }

    // MARK: - Grid

    private var grid: some View {
        ScrollView {
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 220, maximum: 280), spacing: 14)], spacing: 14) {
                ForEach(visibleEntries, id: \.id) { e in
                    catalogCard(e)
                }
            }
            .padding(18)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func catalogCard(_ e: RaveCatalogEntry) -> some View {
        Button {
            selectedID = e.id
        } label: {
            VStack(alignment: .leading, spacing: 10) {
                ZStack {
                    Rectangle()
                        .fill(LinearGradient(
                            colors: [colorFor(category: e.category), colorFor(category: e.category).opacity(0.6)],
                            startPoint: .topLeading, endPoint: .bottomTrailing
                        ))
                        .frame(height: 80)
                    Text(monogram(e.id))
                        .font(.system(size: 32, weight: .bold, design: .rounded))
                        .foregroundStyle(.white)
                }
                .cornerRadius(6)
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 6) {
                        Text(friendlyName(e.id))
                            .font(.system(size: 13, weight: .semibold))
                            .lineLimit(1)
                        trustBadge(e.trustTier)
                    }
                    if let cat = e.category {
                        Text(cat.capitalized)
                            .font(.system(size: 10))
                            .foregroundStyle(.secondary)
                    }
                    Text("v\(e.currentVersion)")
                        .font(.system(size: 10))
                        .foregroundStyle(.tertiary)
                }
            }
            .padding(10)
            .background(Color(NSColor.controlBackgroundColor))
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .strokeBorder(selectedID == e.id ? Color.accentColor : Color.clear, lineWidth: 2)
            )
            .cornerRadius(8)
        }
        .buttonStyle(.plain)
    }

    // MARK: - Detail panel

    private var detailPanel: some View {
        Group {
            if let e = selectedEntry {
                detailContent(e)
            } else {
                placeholderDetail
            }
        }
        .frame(width: 320)
        .background(Color(NSColor.controlBackgroundColor).opacity(0.5))
    }

    private var placeholderDetail: some View {
        VStack(spacing: 8) {
            Image(systemName: "arrow.left.circle")
                .font(.system(size: 30))
                .foregroundStyle(.tertiary)
            Text("Select a scanner")
                .font(.system(size: 13, weight: .medium))
                .foregroundStyle(.secondary)
            Text("Click a card on the left to see what it does + how to install.")
                .font(.system(size: 11))
                .foregroundStyle(.tertiary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 24)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func detailContent(_ e: RaveCatalogEntry) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                ZStack {
                    Rectangle()
                        .fill(LinearGradient(
                            colors: [colorFor(category: e.category), colorFor(category: e.category).opacity(0.6)],
                            startPoint: .topLeading, endPoint: .bottomTrailing
                        ))
                        .frame(height: 120)
                    Text(monogram(e.id))
                        .font(.system(size: 48, weight: .bold, design: .rounded))
                        .foregroundStyle(.white)
                }
                .cornerRadius(8)

                VStack(alignment: .leading, spacing: 6) {
                    Text(friendlyName(e.id))
                        .font(.headline)
                    HStack(spacing: 6) {
                        trustBadge(e.trustTier)
                        channelBadge(e.channel)
                    }
                    Text(e.id)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(.tertiary)
                        .textSelection(.enabled)
                }

                Divider()
                detailSection("What it does", body: longDescription(e))
                if !e.tags.isEmpty {
                    detailSection("Tags", view: tagWrap(e.tags))
                }
                detailSection("Version", body: "v\(e.currentVersion)")
                if let min = e.minMaccrabVersion {
                    detailSection("Requires", body: "MacCrab v\(min) or newer")
                }
                detailSection("Signed by", body: e.signerIdentity.isEmpty ? "—" : e.signerIdentity)

                Divider()
                installCommand(e)
            }
            .padding(18)
        }
    }

    private func detailSection<V: View>(_ title: String, view: V) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.system(size: 10, weight: .semibold))
                .foregroundStyle(.tertiary).textCase(.uppercase)
            view
        }
    }

    private func detailSection(_ title: String, body: String) -> some View {
        detailSection(title, view: Text(body).font(.system(size: 12)))
    }

    private func tagWrap(_ tags: [String]) -> some View {
        FlowLayout(spacing: 4) {
            ForEach(tags, id: \.self) { t in
                Text(t)
                    .font(.system(size: 10))
                    .padding(.horizontal, 6).padding(.vertical, 2)
                    .background(Color.secondary.opacity(0.12))
                    .cornerRadius(3)
            }
        }
    }

    private func installCommand(_ e: RaveCatalogEntry) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Install")
                .font(.system(size: 10, weight: .semibold))
                .foregroundStyle(.tertiary).textCase(.uppercase)
            HStack(spacing: 6) {
                Text("maccrabctl plugin install \(e.id)")
                    .font(.system(size: 10, design: .monospaced))
                    .padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.black.opacity(0.06))
                    .cornerRadius(4)
                    .textSelection(.enabled)
            }
            Button {
                let cmd = "maccrabctl plugin install \(e.id)"
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(cmd, forType: .string)
                copiedID = e.id
                DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                    if copiedID == e.id { copiedID = nil }
                }
            } label: {
                if copiedID == e.id {
                    Label("Copied", systemImage: "checkmark")
                } else {
                    Label("Copy install command", systemImage: "doc.on.clipboard")
                }
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.small)
            Text("In-dashboard install lands in v1.18. Run this in Terminal to install today.")
                .font(.system(size: 10))
                .foregroundStyle(.tertiary)
        }
    }

    // MARK: - Empty / loading / error

    private var loadingView: some View {
        VStack(spacing: 10) {
            ProgressView()
            Text("Fetching catalog…")
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func errorView(_ err: String) -> some View {
        VStack(spacing: 12) {
            Image(systemName: "wifi.exclamationmark")
                .font(.system(size: 40))
                .foregroundStyle(.orange)
            Text("Catalog not reachable")
                .font(.headline)
            Text("The rave plugin catalog at \(baseURL.isEmpty ? "maccrab.com/rave" : baseURL) couldn't be fetched. This usually means the catalog is still being built out (Phase 0b → Phase 1) or you're offline.")
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 420)
            Text(err).font(.system(size: 10, design: .monospaced))
                .foregroundStyle(.tertiary).padding(.top, 8)
            Button("Try again") { Task { await reload() } }
                .padding(.top, 8)
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var emptyView: some View {
        VStack(spacing: 10) {
            Image(systemName: "shippingbox").font(.system(size: 36)).foregroundStyle(.tertiary)
            Text("Catalog has no scanners yet.")
                .font(.system(size: 13, weight: .medium))
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - Helpers

    private func trustBadge(_ tier: String) -> some View {
        let (label, color): (String, Color) = {
            switch tier {
            case "first-party":         return ("First-party", .green)
            case "verified-community":  return ("Verified", .blue)
            default:                    return ("Unverified", .orange)
            }
        }()
        return Text(label)
            .font(.system(size: 9, weight: .medium))
            .padding(.horizontal, 5).padding(.vertical, 1)
            .background(color.opacity(0.18))
            .foregroundStyle(color)
            .cornerRadius(3)
    }

    private func channelBadge(_ ch: String) -> some View {
        Text(ch.capitalized)
            .font(.system(size: 9))
            .padding(.horizontal, 5).padding(.vertical, 1)
            .background(Color.secondary.opacity(0.12))
            .cornerRadius(3)
    }

    private func friendlyName(_ id: String) -> String {
        ScannerDisplay.name(forPluginID: id)
    }

    private func longDescription(_ e: RaveCatalogEntry) -> String {
        // Detail panel text — manifest descriptions live in the
        // plugin manifests once those land in the catalog; for
        // now the friendly name is enough until the rave catalog
        // emits descriptions in its JSON.
        return "\(friendlyName(e.id)) — \(e.category ?? "scanner") published via the rave catalog. Install via the command shown below to add it to this Mac's scanner registry; from there it'll appear in any kit that references its id."
    }

    private func monogram(_ id: String) -> String {
        // Use the last meaningful segment + first letter.
        let parts = id.split(separator: ".")
        guard let last = parts.last else { return "?" }
        let words = last.split(separator: "-")
        if words.count >= 2 {
            return String(words[0].prefix(1) + words[1].prefix(1)).uppercased()
        }
        return String(last.prefix(2)).uppercased()
    }

    private func colorFor(category: String?) -> Color {
        switch category ?? "" {
        case "collector":  return .blue
        case "analyzer":   return .purple
        case "enricher":   return .teal
        case "fingerprinter": return .indigo
        default:           return .accentColor
        }
    }

    private func categoryIcon(_ cat: String) -> String {
        switch cat {
        case "collector":     return "tray.and.arrow.down"
        case "analyzer":      return "chart.bar"
        case "enricher":      return "wand.and.stars"
        case "fingerprinter": return "barcode.viewfinder"
        default:              return "square.grid.2x2"
        }
    }

    // MARK: - Load

    private func reload() async {
        loading = true
        error = nil
        baseURL = await client.baseURL.absoluteString
        do {
            entries = try await client.fetchEntries()
            if selectedID == nil { selectedID = entries.first?.id }
        } catch {
            self.error = "\(error)"
            entries = []
        }
        loading = false
    }
}

// MARK: - FlowLayout

/// Lightweight wrap layout for tag chips. Lays out children
/// left-to-right, wrapping when out of horizontal space.
struct FlowLayout: Layout {
    var spacing: CGFloat = 8

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let maxWidth = proposal.width ?? .infinity
        var x: CGFloat = 0
        var y: CGFloat = 0
        var lineHeight: CGFloat = 0
        for sv in subviews {
            let size = sv.sizeThatFits(.unspecified)
            if x + size.width > maxWidth {
                x = 0
                y += lineHeight + spacing
                lineHeight = 0
            }
            x += size.width + spacing
            lineHeight = max(lineHeight, size.height)
        }
        return CGSize(width: maxWidth, height: y + lineHeight)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var x = bounds.minX
        var y = bounds.minY
        var lineHeight: CGFloat = 0
        for sv in subviews {
            let size = sv.sizeThatFits(.unspecified)
            if x + size.width > bounds.maxX {
                x = bounds.minX
                y += lineHeight + spacing
                lineHeight = 0
            }
            sv.place(at: CGPoint(x: x, y: y), proposal: ProposedViewSize(size))
            x += size.width + spacing
            lineHeight = max(lineHeight, size.height)
        }
    }
}
