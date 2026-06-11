// RaveInstallConsentSheet — O3c (S2-07) the consent UI a `maccrab://install/...`
// deep link drives. Shows the facts resolved from the PINNED catalog (signer
// hash, trust tier, version floor) and requires an explicit confirm. The sheet
// never installs anything by itself — confirm surfaces the verified install
// command (resolved id only).

import SwiftUI
import MacCrabForensics

struct RaveInstallConsentSheet: View {
    let link: RaveInstallLink
    let onClose: () -> Void

    @State private var facts: RaveInstallConsentFacts?
    @State private var loadError: String?
    @State private var loading = true
    @State private var copied = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 8) {
                Image(systemName: "shield.lefthalf.filled")
                    .foregroundStyle(.orange)
                Text("Install from MacCrab link")
                    .font(.headline)
                Spacer()
            }

            if loading {
                ProgressView("Verifying catalog…")
                    .frame(maxWidth: .infinity, alignment: .center)
                    .padding(.vertical, 20)
            } else if let loadError {
                errorBody(loadError)
            } else if let facts {
                factsBody(facts)
            }

            Divider()
            HStack {
                Button("Cancel", role: .cancel) { onClose() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                if let facts, facts.canConfirm {
                    Button {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(facts.verifiedInstallCommand, forType: .string)
                        copied = true
                    } label: {
                        Label(copied ? "Copied" : "Confirm & copy install command",
                              systemImage: copied ? "checkmark" : "checkmark.shield")
                    }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                }
            }
        }
        .padding(20)
        .frame(width: 460)
        .task { await load() }
    }

    @ViewBuilder
    private func factsBody(_ f: RaveInstallConsentFacts) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("You're about to install a \(f.kind.rawValue) from the MacCrab catalog. Review the verified details below before confirming.")
                .font(.callout)
                .foregroundStyle(.secondary)

            row("Plugin", f.id)
            row("Version", "v\(f.resolvedVersion)")
            row("Trust tier", f.trustTier)
            row("Signed by", f.signerIdentity.isEmpty ? "—" : f.signerIdentity)
            row("Signer key", f.signerPublicKeySHA256.isEmpty ? "(unpinned)" : String(f.signerPublicKeySHA256.prefix(16)) + "…", mono: true)
            if let min = f.declaredMinVersion {
                row("Requires", "MacCrab v\(min) or newer")
            }

            if let refusal = f.versionFloorRefusal {
                HStack(alignment: .top, spacing: 6) {
                    Image(systemName: "exclamationmark.octagon.fill").foregroundStyle(.red)
                    Text(refusal).font(.caption).foregroundStyle(.red)
                }
                .padding(8)
                .background(Color.red.opacity(0.08))
                .cornerRadius(6)
            }

            if !f.officialSource {
                HStack(spacing: 6) {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.yellow)
                    Text("Catalog source is NOT the official rave.maccrab.com.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }

            Text("This link can only name a catalog id — every install detail above was resolved from the signed catalog, not the link.")
                .font(.caption2)
                .foregroundStyle(.tertiary)
        }
    }

    @ViewBuilder
    private func errorBody(_ msg: String) -> some View {
        HStack(alignment: .top, spacing: 6) {
            Image(systemName: "xmark.octagon.fill").foregroundStyle(.red)
            Text(msg).font(.callout).foregroundStyle(.primary)
        }
        .padding(.vertical, 8)
    }

    private func row(_ label: String, _ value: String, mono: Bool = false) -> some View {
        HStack(alignment: .firstTextBaseline) {
            Text(label)
                .font(.caption).foregroundStyle(.tertiary)
                .frame(width: 90, alignment: .leading)
            Text(value)
                .font(mono ? .system(.caption, design: .monospaced) : .caption)
                .textSelection(.enabled)
            Spacer()
        }
    }

    private func load() async {
        loading = true
        defer { loading = false }
        do {
            let resolver = RaveInstallConsentResolver()
            facts = try await resolver.resolve(link)
        } catch {
            loadError = "\(error)"
        }
    }
}
