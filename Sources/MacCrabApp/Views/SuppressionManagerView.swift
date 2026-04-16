// SuppressionManagerView.swift
// MacCrabApp
//
// Allowlist v2 dashboard view. Loads Suppression records directly from
// the shared suppressions.json via SuppressionManager, shows each entry's
// scope kind, expiry countdown, reason, and source, and lets the
// operator remove entries. For adding new entries see
// `maccrabctl allow add --ttl ... --reason ...`.

import SwiftUI
import MacCrabCore

struct SuppressionManagerView: View {
    @ObservedObject var appState: AppState

    @State private var entries: [Suppression] = []
    @State private var scopeFilter: String? = nil    // nil = all kinds
    @State private var includeExpired: Bool = false
    @State private var confirmRemoveAll: Bool = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            header
            scopeFilterBar
            Divider()
            content
        }
        .padding()
        .frame(width: 520, height: 440)
        .onAppear { Task { await reload() } }
    }

    // MARK: - Sections

    private var header: some View {
        HStack {
            Text("Allowlist (v2)")
                .font(.headline)
            Text("\(visibleEntries.count)/\(entries.count)")
                .font(.caption)
                .foregroundColor(.secondary)
            Spacer()
            Toggle("Show expired", isOn: $includeExpired)
                .toggleStyle(.switch)
                .controlSize(.mini)
            Button {
                Task { await reload() }
            } label: {
                Image(systemName: "arrow.clockwise")
            }
            .buttonStyle(.borderless)
            .help("Reload from disk")
            if !entries.isEmpty {
                Button(role: .destructive) {
                    confirmRemoveAll = true
                } label: {
                    Text("Remove all").font(.caption)
                }
                .confirmationDialog(
                    "Remove all allowlist entries?",
                    isPresented: $confirmRemoveAll
                ) {
                    Button("Remove all", role: .destructive) {
                        Task { await removeAll() }
                    }
                } message: {
                    Text("Every suppression is removed. Alerts will re-flow to the dashboard.")
                }
            }
        }
    }

    private var scopeFilterBar: some View {
        HStack(spacing: 8) {
            ForEach(scopeKinds, id: \.self) { kind in
                Button {
                    scopeFilter = (scopeFilter == kind) ? nil : kind
                } label: {
                    Text(scopeLabel(kind))
                        .font(.caption)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 4)
                        .background(scopeFilter == kind ? Color.accentColor.opacity(0.25) : Color.secondary.opacity(0.1))
                        .cornerRadius(10)
                }
                .buttonStyle(.plain)
            }
            Spacer()
        }
    }

    @ViewBuilder
    private var content: some View {
        if entries.isEmpty {
            VStack(spacing: 8) {
                Image(systemName: "eye")
                    .font(.title2)
                    .foregroundColor(.secondary.opacity(0.5))
                Text("No allowlist entries")
                    .font(.subheadline)
                    .foregroundColor(.secondary)
                Text("Add one via `maccrabctl allow add --rule <id> --path <p> --ttl 7d --reason \"why\"`")
                    .font(.caption2)
                    .foregroundColor(.secondary.opacity(0.8))
            }
            .frame(maxWidth: .infinity)
            .padding()
        } else if visibleEntries.isEmpty {
            Text("No entries match current filter.")
                .font(.subheadline)
                .foregroundColor(.secondary)
                .frame(maxWidth: .infinity)
                .padding()
        } else {
            ScrollView {
                VStack(spacing: 6) {
                    ForEach(visibleEntries, id: \.id) { entry in
                        entryRow(entry)
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func entryRow(_ e: Suppression) -> some View {
        let expired = e.isExpired()
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: expired ? "clock.badge.exclamationmark" : "eye.slash")
                .foregroundColor(expired ? .orange : .secondary)
                .font(.subheadline)

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(scopeLabel(e.scope.kind))
                        .font(.caption2).fontWeight(.semibold)
                        .padding(.horizontal, 5).padding(.vertical, 1)
                        .background(Color.secondary.opacity(0.15))
                        .cornerRadius(3)
                    Text(expiryText(e))
                        .font(.caption2)
                        .foregroundColor(expired ? .orange : .secondary)
                    Text("source: \(e.source.rawValue)")
                        .font(.caption2)
                        .foregroundColor(.secondary.opacity(0.7))
                }
                Text(e.scope.summary)
                    .font(.caption).fontWeight(.medium)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Text(e.reason)
                    .font(.caption2)
                    .foregroundColor(.secondary)
                    .lineLimit(2)
            }

            Spacer()

            Button {
                Task { await remove(id: e.id) }
            } label: {
                Image(systemName: "trash")
                    .foregroundColor(.red.opacity(0.8))
            }
            .buttonStyle(.borderless)
            .help("Remove this allow")
        }
        .padding(8)
        .background(Color.secondary.opacity(expired ? 0.10 : 0.05))
        .cornerRadius(8)
    }

    // MARK: - Derived

    private var visibleEntries: [Suppression] {
        entries.filter { e in
            if !includeExpired && e.isExpired() { return false }
            if let kind = scopeFilter, e.scope.kind != kind { return false }
            return true
        }
        .sorted { $0.createdAt > $1.createdAt }
    }

    private let scopeKinds = ["rule_path", "rule_hash", "rule", "path", "host"]

    private func scopeLabel(_ kind: String) -> String {
        switch kind {
        case "rule_path": return "rule+path"
        case "rule_hash": return "rule+hash"
        case "rule":      return "rule"
        case "path":      return "path"
        case "host":      return "host"
        default:          return kind
        }
    }

    private func expiryText(_ e: Suppression) -> String {
        guard let ex = e.expiresAt else { return "permanent" }
        if e.isExpired() {
            return "expired"
        }
        let remaining = ex.timeIntervalSinceNow
        if remaining < 3600 {
            return "\(Int(remaining / 60))m left"
        } else if remaining < 86400 {
            return "\(Int(remaining / 3600))h left"
        } else {
            return "\(Int(remaining / 86400))d left"
        }
    }

    // MARK: - Actions

    private func maccrabDataDir() -> String {
        let env = ProcessInfo.processInfo.environment["MACCRAB_DATA_DIR"]
        let home = NSHomeDirectory() + "/Library/Application Support/MacCrab"
        let system = "/Library/Application Support/MacCrab"
        if let e = env, FileManager.default.fileExists(atPath: e) { return e }
        if FileManager.default.fileExists(atPath: system) { return system }
        return home
    }

    private func reload() async {
        let mgr = SuppressionManager(dataDir: maccrabDataDir())
        await mgr.load()
        let list = await mgr.list(includeExpired: true)
        await MainActor.run { self.entries = list }
    }

    private func remove(id: String) async {
        let mgr = SuppressionManager(dataDir: maccrabDataDir())
        await mgr.load()
        _ = await mgr.remove(id: id)
        await reload()
    }

    private func removeAll() async {
        let mgr = SuppressionManager(dataDir: maccrabDataDir())
        await mgr.load()
        _ = await mgr.removeAll()
        await reload()
    }
}
