// V2RaveCatalogBrowserSheet.swift
//
// rc.7 — operator-facing browse view for maccrab.com/rave/.
// Fetches catalog.json + signature via RaveCatalogClient,
// verifies against the bundled Ed25519 key, presents the
// plugin list with friendly metadata. "Install" copies the
// matching CLI command to the clipboard (in-dashboard install
// flow is v1.18 once we can verify Keychain-prompt UX end-to-
// end).
//
// When the rave server isn't reachable (catalog not yet live
// or local network failure) the sheet shows a clear "Catalog
// not reachable" empty state with the base URL it tried.

import SwiftUI

struct V2RaveCatalogBrowserSheet: View {
    @Binding var isPresented: Bool

    @State private var entries: [RaveCatalogEntry] = []
    @State private var loading = true
    @State private var error: String? = nil
    @State private var baseURL: String = ""
    @State private var copiedID: String? = nil

    private let client = RaveCatalogClient()

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    if loading {
                        ProgressView("Fetching catalog…")
                            .frame(maxWidth: .infinity)
                            .padding(40)
                    } else if let err = error {
                        catalogUnreachable(err)
                    } else if entries.isEmpty {
                        emptyState
                    } else {
                        catalogList
                    }
                }
                .padding(20)
            }
        }
        .frame(width: 640, height: 540)
        .task { await reload() }
    }

    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text("Plugin catalog").font(.headline)
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
            Button("Close") { isPresented = false }
                .keyboardShortcut(.cancelAction)
        }
        .padding(.horizontal, 20).padding(.vertical, 14)
    }

    private func catalogUnreachable(_ err: String) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                Text("Catalog not reachable")
                    .font(.headline)
            }
            Text(err)
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
            Text("The rave plugin catalog at \(baseURL.isEmpty ? "maccrab.com/rave" : baseURL) couldn't be fetched. This usually means the rave site is still being built out (Phase 0b → Phase 1) or you're offline.")
                .font(.system(size: 11))
                .foregroundStyle(.tertiary)
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.orange.opacity(0.08))
        .cornerRadius(8)
    }

    private var emptyState: some View {
        Text("Catalog returned no plugins.")
            .font(.system(size: 12))
            .foregroundStyle(.secondary)
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(NSColor.controlBackgroundColor))
            .cornerRadius(8)
    }

    private var catalogList: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("\(entries.count) plugin\(entries.count == 1 ? "" : "s") available")
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
            ForEach(entries, id: \.id) { entry in
                entryRow(entry)
                Divider()
            }
        }
    }

    private func entryRow(_ e: RaveCatalogEntry) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Text(friendlyName(e.id))
                    .font(.system(size: 13, weight: .semibold))
                trustBadge(e.trustTier)
                channelBadge(e.channel)
                Spacer()
                Text("v\(e.currentVersion)")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
            }
            Text(e.id)
                .font(.system(size: 10, design: .monospaced))
                .foregroundStyle(.tertiary)
            if !e.tags.isEmpty {
                HStack(spacing: 6) {
                    ForEach(e.tags, id: \.self) { t in
                        Text(t)
                            .font(.system(size: 9))
                            .padding(.horizontal, 5).padding(.vertical, 1)
                            .background(Color.secondary.opacity(0.12))
                            .cornerRadius(3)
                    }
                }
            }
            HStack {
                Spacer()
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
                        Label("Copied install command", systemImage: "checkmark")
                            .font(.system(size: 11))
                    } else {
                        Label("Copy install command", systemImage: "doc.on.clipboard")
                            .font(.system(size: 11))
                    }
                }
                .controlSize(.small)
            }
        }
        .padding(.vertical, 8)
    }

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
        let map: [String: String] = [
            "com.maccrab.hosts-collector":         "Hosts file baseline",
            "com.maccrab.launch-agents-collector": "Launch agents inventory",
        ]
        if let n = map[id] { return n }
        let parts = id.split(separator: ".")
        guard let last = parts.last else { return id }
        return last.replacingOccurrences(of: "-", with: " ").capitalized
    }

    private func reload() async {
        loading = true
        error = nil
        baseURL = await client.baseURL.absoluteString
        do {
            entries = try await client.fetchEntries()
        } catch {
            self.error = "\(error)"
            entries = []
        }
        loading = false
    }
}
