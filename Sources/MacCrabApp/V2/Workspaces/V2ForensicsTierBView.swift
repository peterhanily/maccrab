// V2ForensicsTierBView.swift
// MacCrabApp — Dashboard v2 — Forensics → Tier B.
//
// Operator-facing surface for the Tier B plugin platform.
// Mirrors `maccrabctl plugin daemon-status` + `verify-all` +
// `trust-list` + `installed-list` + revoke action. The CLI is
// the primary surface; this view gives operators visibility
// without leaving the dashboard.

import SwiftUI
import MacCrabForensics

struct V2ForensicsTierBView: View {
    @State private var status: TierBBootstrap.Status? = nil
    @State private var trustedKeys: [String] = []
    @State private var revokedKeys: [String] = []
    @State private var loading = false
    @State private var lastRefresh: Date = .distantPast
    @State private var error: String? = nil

    private let bootstrap = TierBBootstrap()
    private let installer = PluginInstaller()
    private let isoFmt: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f
    }()

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                header
                if let s = status {
                    statusCard(s)
                    verifiedSection(s.verified)
                    if !s.failed.isEmpty {
                        failedSection(s.failed)
                    }
                    trustListSection
                } else if loading {
                    ProgressView("Loading Tier B status...")
                        .frame(maxWidth: .infinity)
                        .padding(40)
                } else if let e = error {
                    Text("Error: \(e)")
                        .foregroundStyle(.red)
                        .padding()
                }
            }
            .padding(16)
        }
        .task { await refresh(force: false) }
    }

    // MARK: - Sections

    private var header: some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Tier B Plugins")
                    .font(.title2).fontWeight(.semibold)
                Text("Third-party signed plugins. Install + verify + trust + revoke.")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button {
                Task { await refresh(force: true) }
            } label: {
                Label("Verify all", systemImage: "arrow.clockwise")
            }
            .disabled(loading)
        }
    }

    private func statusCard(_ s: TierBBootstrap.Status) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 24) {
                metric(label: "Verified", value: "\(s.verified.count)", color: .green)
                metric(label: "Failed", value: "\(s.failed.count)", color: s.failed.isEmpty ? .secondary : .red)
                metric(label: "Trusted keys", value: "\(s.trustedKeyCount)", color: .blue)
                metric(label: "Revoked keys", value: "\(s.revokedKeyCount)", color: .secondary)
            }
            Text("Plugins root: \(s.pluginsRoot)")
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
            Text("Last verified: \(isoFmt.string(from: s.verifiedAt))")
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
        }
        .padding(12)
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(8)
    }

    private func metric(label: String, value: String, color: Color) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(value)
                .font(.system(size: 22, weight: .semibold, design: .rounded))
                .foregroundStyle(color)
            Text(label)
                .font(.system(size: 10))
                .foregroundStyle(.secondary)
        }
    }

    private func verifiedSection(_ verified: [TierBBootstrap.VerifiedSummary]) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Verified plugins").font(.headline)
            if verified.isEmpty {
                Text("No Tier B plugins installed.")
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
                    .padding(.vertical, 8)
            } else {
                ForEach(verified, id: \.pluginID) { p in
                    verifiedRow(p)
                    Divider()
                }
            }
        }
    }

    private func verifiedRow(_ p: TierBBootstrap.VerifiedSummary) -> some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 3) {
                Text(p.pluginID)
                    .font(.system(size: 13, design: .monospaced))
                    .fontWeight(.semibold)
                Text("v\(p.version)").font(.system(size: 11)).foregroundStyle(.secondary)
                Text("key=\(p.publicKeyHex.prefix(16))…")
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 4) {
                Button(role: .destructive) {
                    Task { await revoke(key: p.publicKeyHex) }
                } label: {
                    Label("Revoke", systemImage: "xmark.shield")
                }
                .buttonStyle(.borderless)
                .controlSize(.small)
                .disabled(loading)
            }
        }
        .padding(.vertical, 4)
    }

    private func failedSection(_ failed: [TierBBootstrap.FailedSummary]) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Failed verification").font(.headline)
            ForEach(failed, id: \.pluginID) { f in
                VStack(alignment: .leading, spacing: 2) {
                    Text(f.pluginID)
                        .font(.system(size: 13, design: .monospaced))
                        .fontWeight(.semibold)
                    Text(f.reason)
                        .font(.system(size: 11))
                        .foregroundStyle(.red)
                        .textSelection(.enabled)
                }
                .padding(8)
                .background(Color.red.opacity(0.06))
                .cornerRadius(6)
            }
        }
    }

    private var trustListSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Trust list").font(.headline)
                Spacer()
                Text("Read-only here; manage via maccrabctl plugin trust / revoke")
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
            }
            if trustedKeys.isEmpty && revokedKeys.isEmpty {
                Text("No keys in trust or revocation list.")
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
                    .padding(.vertical, 4)
            } else {
                if !trustedKeys.isEmpty {
                    DisclosureGroup("Trusted keys (\(trustedKeys.count))") {
                        ForEach(trustedKeys, id: \.self) { k in
                            Text(k)
                                .font(.system(size: 10, design: .monospaced))
                                .textSelection(.enabled)
                                .padding(.vertical, 2)
                        }
                    }
                }
                if !revokedKeys.isEmpty {
                    DisclosureGroup("Revoked keys (\(revokedKeys.count))") {
                        ForEach(revokedKeys, id: \.self) { k in
                            Text(k)
                                .font(.system(size: 10, design: .monospaced))
                                .textSelection(.enabled)
                                .foregroundStyle(.secondary)
                                .padding(.vertical, 2)
                        }
                    }
                }
            }
        }
    }

    // MARK: - Actions

    private func refresh(force: Bool) async {
        loading = true
        error = nil
        let s = await bootstrap.status(force: force)
        let trusted = await installer.currentTrustedKeys()
        let revoked = await installer.currentRevokedKeys()
        status = s
        trustedKeys = Array(trusted).sorted()
        revokedKeys = Array(revoked).sorted()
        lastRefresh = Date()
        loading = false
    }

    private func revoke(key: String) async {
        loading = true
        do {
            try await installer.revokeKey(key)
            await refresh(force: true)
        } catch {
            self.error = "Revoke failed: \(error)"
            loading = false
        }
    }
}
