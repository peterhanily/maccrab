// PluginDetailInspector — the single reusable plugin-detail surface (issue #5).
// Presented as an overlaid sheet from My Plugins and Run-a-scan when the operator
// clicks a scanner: who published it, what it does, its capabilities/consent,
// version, provenance, and when it was added. Built once from a built-in
// PluginManifest or an installed third-party plugin so every surface agrees.

import SwiftUI
import MacCrabForensics

/// Value model for the inspector. Identifiable so it drives `.sheet(item:)`.
struct PluginDetailModel: Identifiable, Equatable {
    let id: String
    let displayName: String
    let summary: String                 // "what it does"
    let provenance: PluginProvenance     // built-in / third-party / store
    let version: String
    let publisher: String
    let reads: [String]                  // declared read-set / data sources
    let emits: [String]                  // artifact types it produces
    let networkLabel: String
    let privacyLabel: String
    let tcc: [String]                    // TCC requirements / personal-comms
    let installedLabel: String           // "Ships with MacCrab" / "Added <date>"
    let runnable: Bool

    static func builtIn(_ m: PluginManifest) -> PluginDetailModel {
        // Prefer the curated ScannerCatalog fact (rich purpose / data-sources /
        // emits) over the bare manifest description so the panel has substance.
        let fact = ScannerCatalog.fact(forPluginID: m.id)
        let summary = fact?.purpose ?? (m.description.isEmpty ? "First-party \(m.type.rawValue)." : m.description)
        let tcc = fact?.tccRequirements ?? m.tccRequirements.map { $0.rawValue }
        return PluginDetailModel(
            id: m.id,
            displayName: m.displayName,
            summary: summary,
            provenance: .builtIn,
            version: m.version,
            publisher: "MacCrab — first-party, ships in the app",
            reads: fact?.dataSources ?? [],
            emits: fact?.emits ?? m.outputs.map { $0.contentType },
            networkLabel: "Runs in-process (no third-party network)",
            privacyLabel: (fact?.privacyClass.rawValue ?? m.type.rawValue).capitalized,
            tcc: tcc,
            installedLabel: "Ships with MacCrab",
            runnable: m.type == .collector || m.type == .analyzer)
    }

    static func thirdParty(pluginID: String, publicKeyHex: String, manifest: TierBManifest?,
                           provenance: PluginProvenance, installedLabel: String) -> PluginDetailModel {
        let consent = manifest?.consentSummary()
        let endpoints = consent?.networkEndpoints ?? []
        return PluginDetailModel(
            id: pluginID,
            displayName: manifest?.displayName ?? pluginID,
            summary: (manifest?.description.isEmpty == false) ? manifest!.description : "Third-party forensic plugin.",
            provenance: provenance,
            version: manifest?.version ?? "—",
            publisher: provenance == .store
                ? "Catalog (signed) · key \(publicKeyHex.prefix(12))…"
                : "Operator-trusted · key \(publicKeyHex.prefix(12))…",
            reads: consent?.fileReads ?? [],
            emits: [],
            networkLabel: endpoints.isEmpty ? "No network egress" : "Network: " + endpoints.joined(separator: ", "),
            privacyLabel: (consent?.derivedHighestPrivacy ?? "metadata").capitalized,
            tcc: consent?.tccReads ?? [],
            installedLabel: installedLabel,
            runnable: true)
    }
}

struct PluginDetailInspector: View {
    let model: PluginDetailModel
    /// Optional run handler — shows a "Run on this Mac" button when present.
    var onRun: (() -> Void)? = nil
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    section("What it does") {
                        Text(model.summary).scaledSystem(12).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    section("Publisher") {
                        Text(model.publisher).scaledSystem(12).foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }
                    section("Capabilities") { capabilities }
                    section("Details") { details }
                }
                .padding(20)
            }
            Divider()
            footer
        }
        .frame(width: 440, height: 540)
    }

    // MARK: - Header

    private var header: some View {
        HStack(spacing: 12) {
            Image(systemName: model.provenance.symbolName)
                .scaledSystem(22).foregroundStyle(.tint)
                .frame(width: 30).accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(model.displayName).font(.headline)
                HStack(spacing: 6) {
                    provenanceBadge
                    Text("v\(model.version)").scaledSystem(11).foregroundStyle(.tertiary)
                }
            }
            Spacer()
        }
        .padding(.horizontal, 20).padding(.vertical, 14)
    }

    private var provenanceBadge: some View {
        Text(model.provenance.displayName)
            .scaledSystem(9, weight: .semibold)
            .padding(.horizontal, 6).padding(.vertical, 1)
            .background(Color.secondary.opacity(0.15)).cornerRadius(3)
            .foregroundStyle(.secondary)
    }

    // MARK: - Capabilities

    private var capabilities: some View {
        VStack(alignment: .leading, spacing: 6) {
            chipRow("Privacy", model.privacyLabel)
            chipRow("Network", model.networkLabel)
            if !model.tcc.isEmpty {
                chipRow(model.provenance == .builtIn ? "Needs" : "Personal data", model.tcc.joined(separator: ", "))
            }
            if !model.reads.isEmpty {
                chipRow("Reads", model.reads.joined(separator: "\n"))
            }
            if !model.emits.isEmpty {
                chipRow("Emits", model.emits.joined(separator: ", "))
            }
        }
    }

    private func chipRow(_ label: String, _ value: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Text(label).scaledSystem(11, weight: .medium).foregroundStyle(.secondary)
                .frame(width: 92, alignment: .leading)
            Text(value).scaledSystem(11).foregroundStyle(.primary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    // MARK: - Details (installed / last run / id)

    private var details: some View {
        VStack(alignment: .leading, spacing: 6) {
            chipRow("Installed", model.installedLabel)
            // No global per-plugin run index yet — honest rather than wrong.
            chipRow("Last run", "Not tracked yet")
            chipRow("Identifier", model.id)
        }
    }

    // MARK: - Footer

    private var footer: some View {
        HStack {
            if model.runnable, let onRun {
                Button {
                    onRun(); dismiss()
                } label: {
                    Label("Run on this Mac", systemImage: "play.fill")
                }
                .buttonStyle(.borderedProminent)
            }
            Spacer()
            Button("Close") { dismiss() }.keyboardShortcut(.cancelAction)
        }
        .padding(.horizontal, 20).padding(.vertical, 14)
    }

    // MARK: - Helpers

    private func section<Content: View>(_ title: String, @ViewBuilder _ content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title.uppercased()).scaledSystem(10, weight: .semibold).foregroundStyle(.tertiary)
            content()
        }
    }
}
