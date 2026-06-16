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
    /// C-B: explicit operator acknowledgement required before a non-first-party
    /// install can be confirmed.
    @State private var thirdPartyAck = false

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
                    // C-B: a non-first-party install stays disabled until the
                    // operator ticks the trust acknowledgement above.
                    .disabled(facts.requiresThirdPartyConsent && !thirdPartyAck)
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

            // Why this entry can't be installed (operator-signed binary required /
            // pre-release / version floor / impersonation) — the SAME gate the
            // catalog browser applies. Shown in place of an enabled Confirm so the
            // deep-link path can't over-claim availability (storefront honesty).
            if !f.isInstallable, let reason = f.installBlockReason {
                HStack(alignment: .top, spacing: 6) {
                    Image(systemName: "exclamationmark.octagon.fill").foregroundStyle(.orange)
                    Text(reason).font(.caption).foregroundStyle(.orange)
                }
                .padding(8)
                .background(Color.orange.opacity(0.10))
                .cornerRadius(6)
            }

            if !f.officialSource {
                HStack(spacing: 6) {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.yellow)
                    Text("Catalog source is NOT the official rave.maccrab.com.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }

            // C-B: first-party affirmation — only when a real signed, installable
            // binary exists; otherwise downgrade (storefront honesty: never claim
            // "reviewed & signed" for a pre-release/awaiting-binary entry).
            if f.isFirstParty {
                if f.isInstallable {
                    Label("First-party — reviewed & signed by the MacCrab maintainer.",
                          systemImage: "checkmark.seal.fill")
                        .font(.caption2).foregroundStyle(.green)
                } else {
                    Label("First-party plugin — not yet available for one-click install.",
                          systemImage: "seal")
                        .font(.caption2).foregroundStyle(.secondary)
                }
            }

            // C-D: honest capability/enforcement disclosure. Plugin execution is
            // NOT yet sandboxed, so be explicit about what installing grants.
            VStack(alignment: .leading, spacing: 4) {
                Label("What installing this grants", systemImage: "lock.open.trianglebadge.exclamationmark")
                    .font(.caption.weight(.semibold))
                Text("MacCrab does not yet sandbox plugins. A plugin you install can run with the same access MacCrab has — including any Full-Disk-Access or privacy permissions granted to it. Install only plugins from a publisher you trust.")
                    .font(.caption2).foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(8)
            .background(Color.orange.opacity(0.08))
            .cornerRadius(6)

            // C-E: warn when the client's revocation data is stale/never-fetched.
            if let stale = f.revocationStalenessWarning {
                HStack(alignment: .top, spacing: 6) {
                    Image(systemName: "clock.badge.exclamationmark").foregroundStyle(.yellow)
                    Text(stale).font(.caption).foregroundStyle(.secondary)
                }
                .padding(8)
                .background(Color.yellow.opacity(0.08))
                .cornerRadius(6)
            }

            // C-B: a non-first-party install requires explicit acknowledgement.
            if f.requiresThirdPartyConsent {
                Toggle(isOn: $thirdPartyAck) {
                    Text("This is not a first-party MacCrab plugin. I trust “\(f.signerIdentity.isEmpty ? f.trustTier : f.signerIdentity)” and understand it will run with full access.")
                        .font(.caption)
                }
                .toggleStyle(.checkbox)
                .padding(.top, 2)
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
