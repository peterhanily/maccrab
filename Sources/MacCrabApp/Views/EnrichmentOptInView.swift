// EnrichmentOptInView.swift
// MacCrabApp
//
// One-time first-run prompt for the (off-by-default) network-enrichment feeds.
// MacCrab is on-device by default; these four optional lookups each reach a
// public service to enrich detection. Dismissing this enables NOTHING — the
// daemon defaults are already off, and "Keep everything off" writes nothing.

import SwiftUI

struct EnrichmentOptInView: View {
    @Binding var isPresented: Bool
    @AppStorage("hasSeenEnrichmentPrompt") private var hasSeenEnrichmentPrompt = false

    // Draft selection — a LOCAL working copy. Nothing is persisted or sent to
    // the daemon until "Enable selected"; the same `enrich.*` UserDefaults keys
    // Settings + the Intel card bind are written only on confirm.
    @State private var threatIntel = false
    @State private var vulnScan = false
    @State private var packageFreshness = false
    @State private var certTransparency = false

    private var anySelected: Bool { threatIntel || vulnScan || packageFreshness || certTransparency }

    var body: some View {
        VStack(spacing: 16) {
            Text("🦀").scaledSystem(44).accessibilityHidden(true)

            Text(String(localized: "enrich.title", defaultValue: "Optional network enrichment"))
                .font(.title2).fontWeight(.bold)

            Text(String(localized: "enrich.intro", defaultValue: "MacCrab runs fully on-device by default — nothing about your Mac leaves it. Detection (rules, sequences, campaigns, bundled threat-intel) works offline. These four optional lookups each reach a public service to add extra context. They stay off until you turn them on, and you can change this anytime in Settings."))
                .font(.callout).foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.horizontal, 24)

            VStack(alignment: .leading, spacing: 10) {
                EnrichToggleRow(icon: "shield.lefthalf.filled",
                    title: String(localized: "enrich.threatIntel", defaultValue: "Threat-intel feeds (abuse.ch)"),
                    detail: String(localized: "enrich.threatIntelDetail", defaultValue: "Download IOC lists every 4h. Download-only — nothing about your Mac is uploaded."),
                    isOn: $threatIntel)
                EnrichToggleRow(icon: "ladybug",
                    title: String(localized: "enrich.vulnScan", defaultValue: "Vulnerability scan (osv.dev)"),
                    detail: String(localized: "enrich.vulnScanDetail", defaultValue: "Look up CVEs for installed software. Sends your software inventory (anonymous)."),
                    isOn: $vulnScan)
                EnrichToggleRow(icon: "shippingbox",
                    title: String(localized: "enrich.packageFreshness", defaultValue: "Package freshness (npm / PyPI / …)"),
                    detail: String(localized: "enrich.packageFreshnessDetail", defaultValue: "Check a package's age on install. Reveals the package name you install."),
                    isOn: $packageFreshness)
                EnrichToggleRow(icon: "checkmark.seal",
                    title: String(localized: "enrich.certTransparency", defaultValue: "Certificate transparency (crt.sh)"),
                    detail: String(localized: "enrich.certTransparencyDetail", defaultValue: "Look up certs for domains you connect to. Reveals the domain."),
                    isOn: $certTransparency)
            }
            .padding(14)
            .background(Color(nsColor: .controlBackgroundColor))
            .cornerRadius(12)
            .padding(.horizontal, 20)

            HStack {
                Button(String(localized: "enrich.keepOff", defaultValue: "Keep everything off")) {
                    // Writes nothing — the daemon defaults are already off.
                    dismiss()
                }
                .controlSize(.large)

                Spacer()

                Button(String(localized: "enrich.enable", defaultValue: "Enable selected")) {
                    UserDefaults.standard.set(threatIntel, forKey: "enrich.threatIntel")
                    UserDefaults.standard.set(vulnScan, forKey: "enrich.vulnScan")
                    UserDefaults.standard.set(packageFreshness, forKey: "enrich.packageFreshness")
                    UserDefaults.standard.set(certTransparency, forKey: "enrich.certTransparency")
                    _ = V2DaemonControl.applyEnrichmentFlags(
                        threatIntel: threatIntel, vulnScan: vulnScan,
                        packageFreshness: packageFreshness, certTransparency: certTransparency)
                    dismiss()
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .disabled(!anySelected)
            }
            .padding(20)
        }
        .frame(width: 520, height: 560)
        // Any dismiss path (buttons OR Esc / window close) marks the one-time
        // prompt as seen so it never re-appears — without enabling anything.
        .onDisappear { hasSeenEnrichmentPrompt = true }
    }

    private func dismiss() {
        hasSeenEnrichmentPrompt = true
        isPresented = false
    }
}

private struct EnrichToggleRow: View {
    let icon: String
    let title: String
    let detail: String
    @Binding var isOn: Bool

    var body: some View {
        Toggle(isOn: $isOn) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: icon)
                    .font(.title3).foregroundColor(.accentColor)
                    .frame(width: 24).accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(.callout).fontWeight(.medium)
                    Text(detail).font(.caption).foregroundColor(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }
}
