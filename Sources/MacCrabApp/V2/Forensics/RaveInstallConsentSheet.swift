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
    /// True when this is an UPDATE of an already-installed plugin (the store sets
    /// it for an installed entry with a newer catalog version). The deep-link
    /// path leaves it false. Drives the --force re-install + the button copy.
    var isUpdate: Bool = false
    /// The currently-installed version, for the update diff disclosure (P6.2).
    var installedVersion: String? = nil

    @State private var facts: RaveInstallConsentFacts?
    @State private var loadError: String?
    @State private var loading = true
    /// C-B: explicit operator acknowledgement required before a non-first-party
    /// install can be confirmed.
    @State private var thirdPartyAck = false
    // In-app install (P4): drives the bundled, verified maccrabctl install path.
    @State private var installing = false
    @State private var installOutput: String?
    @State private var installOK: Bool?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 8) {
                Image(systemName: "shield.lefthalf.filled")
                    .foregroundStyle(.orange)
                Text(isUpdate
                     ? String(localized: "rave.consent.titleUpdate", defaultValue: "Update plugin")
                     : String(localized: "rave.consent.titleInstall", defaultValue: "Install from MacCrab link"))
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

            // In-app install result (the verified maccrabctl path's output).
            if let installOutput {
                ScrollView {
                    Text(installOutput)
                        .font(.system(.caption2, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxHeight: 120)
                .padding(8)
                .background((installOK == true ? Color.green : Color.orange).opacity(0.08))
                .cornerRadius(6)
            }

            Divider()
            HStack {
                Button(installOK == true ? "Close" : "Cancel", role: .cancel) { onClose() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                if let facts, facts.canConfirm {
                    if installing {
                        ProgressView().controlSize(.small)
                        Text(String(localized: "rave.consent.installing", defaultValue: "Installing…")).font(.caption).foregroundStyle(.secondary)
                    } else {
                        Button {
                            installing = true
                            installOutput = nil
                            Task {
                                let r = await installViaBundledCLI(id: facts.id)
                                installOK = r.ok
                                installOutput = r.output
                                installing = false
                            }
                        } label: {
                            Label(installButtonTitle,
                                  systemImage: installOK == true ? "checkmark.circle.fill"
                                    : (isUpdate ? "arrow.up.circle" : "arrow.down.circle"))
                        }
                        .buttonStyle(.borderedProminent)
                        .keyboardShortcut(.defaultAction)
                        // C-B: stays disabled for a non-first-party plugin until the
                        // trust acknowledgement is ticked; disabled once installed.
                        .disabled((facts.requiresThirdPartyConsent && !thirdPartyAck) || installOK == true)
                    }
                }
            }
        }
        .padding(20)
        .frame(width: 460)
        .task { await load() }
    }

    /// Run the BUNDLED maccrabctl's verified install path (`plugin install <id>`)
    /// as the user. The app is not sandboxed; the install + (later) any spawn run
    /// inside maccrabctl, which ignores SIGPIPE. All fail-closed gates (serial,
    /// signer pin, version floor, revocation, artifact hash) are re-enforced there,
    /// so on the pre-release catalog this refuses cleanly and reports why.
    private func installViaBundledCLI(id: String) async -> (ok: Bool, output: String) {
        guard let cli = Self.bundledMaccrabctlPath() else {
            return (false, "Bundled maccrabctl not found. Install from a terminal:\n  maccrabctl plugin install \(id)")
        }
        let argv = Self.installArguments(id: id, isUpdate: isUpdate)
        return await withCheckedContinuation { cont in
            DispatchQueue.global().async {
                let p = Process()
                p.executableURL = URL(fileURLWithPath: cli)
                p.arguments = argv
                let pipe = Pipe()
                p.standardOutput = pipe
                p.standardError = pipe
                do {
                    try p.run()
                } catch {
                    cont.resume(returning: (false, "Failed to launch maccrabctl: \(error.localizedDescription)"))
                    return
                }
                let data = pipe.fileHandleForReading.readDataToEndOfFile()  // read then reap
                p.waitUntilExit()
                let out = String(data: data, encoding: .utf8) ?? ""
                cont.resume(returning: (p.terminationStatus == 0,
                                        out.isEmpty ? "maccrabctl exited \(p.terminationStatus)" : out))
            }
        }
    }

    /// The verified install argv. An update re-installs over the existing copy
    /// (`--force`); a fresh install does not. Every fail-closed gate (serial,
    /// signer pin, version floor, revocation, artifact hash) is re-enforced by
    /// maccrabctl regardless of `--force` — the flag only permits overwriting an
    /// already-present destination, never bypasses trust. Pure + static so the
    /// arg construction is unit-testable without launching a Process.
    static func installArguments(id: String, isUpdate: Bool) -> [String] {
        ["plugin", "install", id] + (isUpdate ? ["--force"] : [])
    }

    /// Confirm-button copy. "Update plugin" / "Updated" for an in-place update,
    /// "Install plugin" / "Installed" for a fresh install.
    private var installButtonTitle: String {
        if installOK == true {
            return isUpdate ? String(localized: "rave.consent.updated", defaultValue: "Updated")
                            : String(localized: "rave.consent.installed", defaultValue: "Installed")
        }
        return isUpdate ? String(localized: "rave.consent.updatePlugin", defaultValue: "Update plugin")
                        : String(localized: "rave.consent.installPlugin", defaultValue: "Install plugin")
    }

    /// Locate the maccrabctl bundled into the app at Resources/bin/maccrabctl.
    static func bundledMaccrabctlPath() -> String? {
        let fm = FileManager.default
        var candidates: [String] = []
        if let res = Bundle.main.resourceURL {
            candidates.append(res.appendingPathComponent("bin/maccrabctl").path)
        }
        candidates.append("/Applications/MacCrab.app/Contents/Resources/bin/maccrabctl")
        return candidates.first { fm.isExecutableFile(atPath: $0) }
    }

    @ViewBuilder
    private func factsBody(_ f: RaveInstallConsentFacts) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(isUpdate
                 ? String(localized: "rave.consent.introUpdate", defaultValue: "You're about to update a \(f.kind.rawValue) from the MacCrab catalog. Review the changes + verified details below before confirming.")
                 : String(localized: "rave.consent.introInstall", defaultValue: "You're about to install a \(f.kind.rawValue) from the MacCrab catalog. Review the verified details below before confirming."))
                .font(.callout)
                .foregroundStyle(.secondary)

            // P6.2: update diff + re-vetting disclosure. An update re-installs over
            // the existing copy and re-runs every trust gate; surface the version
            // change + that the capabilities below are the NEW version's.
            if isUpdate, let old = installedVersion {
                VStack(alignment: .leading, spacing: 3) {
                    Label(String(localized: "rave.consent.updatingTitle", defaultValue: "Updating this plugin"),
                          systemImage: "arrow.triangle.2.circlepath")
                        .font(.caption.weight(.semibold))
                    HStack(spacing: 6) {
                        Text("v\(old)").foregroundStyle(.secondary)
                        Image(systemName: "arrow.right").font(.caption2).foregroundStyle(.secondary)
                        Text("v\(f.resolvedVersion)").fontWeight(.semibold)
                        if old == f.resolvedVersion {
                            Text(String(localized: "rave.consent.reinstall", defaultValue: "(re-install)"))
                                .font(.caption2).foregroundStyle(.secondary)
                        }
                    }.font(.callout)
                    Text(String(localized: "rave.consent.updateRevet", defaultValue: "The update is re-verified against the signed catalog and re-vetted. The capabilities and access shown below are for the NEW version — review them as you would a fresh install."))
                        .font(.caption2).foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(8)
                .background(Color.blue.opacity(0.06))
                .cornerRadius(6)
            }

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
                    Text(String(localized: "rave.consent.nonOfficial", defaultValue: "Catalog source is NOT the official rave.maccrab.com."))
                        .font(.caption).foregroundStyle(.secondary)
                }
            }

            // C-B: first-party affirmation — only when a real signed, installable
            // binary exists; otherwise downgrade (storefront honesty: never claim
            // "reviewed & signed" for a pre-release/awaiting-binary entry).
            if f.isFirstParty {
                if f.isInstallable {
                    Label("Verified by MacCrab — reviewed & signed by the maintainer.",
                          systemImage: "checkmark.seal.fill")
                        .font(.caption2).foregroundStyle(.green)
                } else {
                    Label("First-party plugin — not available for one-click install.",
                          systemImage: "seal")
                        .font(.caption2).foregroundStyle(.secondary)
                }
            }

            // C-D-pre: concrete per-plugin capability chips from the local facts
            // (first-party only; nil → this block is omitted and the generic C-D
            // disclosure below still carries the honest baseline). Chips read
            // first, then the "what this grants" caveat.
            if let pf = PluginFactsLookup.facts(forPluginID: f.id) {
                VStack(alignment: .leading, spacing: 4) {
                    Label("What this scanner accesses", systemImage: "doc.text.magnifyingglass")
                        .font(.caption.weight(.semibold))
                    consentChipRow("Reads", pf.reads)
                    if !pf.needs.isEmpty { consentChipRow("TCC", pf.needs) }
                    consentChipRow("Emits", pf.emits)
                    HStack(spacing: 6) {
                        Image(systemName: "network.slash").font(.caption2).foregroundStyle(.secondary)
                        Text("\(pf.networkChip) · \(pf.sandboxChip)")
                            .font(.caption2).foregroundStyle(.secondary)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(8)
                .background(Color.secondary.opacity(0.06))
                .cornerRadius(6)
            }

            // C-D: honest capability/enforcement disclosure reflecting the
            // sandboxed third-party lane (deny-default; brokered reads).
            VStack(alignment: .leading, spacing: 4) {
                Label(String(localized: "rave.consent.howItRuns.title", defaultValue: "How this plugin runs"),
                      systemImage: "shield.lefthalf.filled")
                    .font(.caption.weight(.semibold))
                Text(String(localized: "rave.consent.howItRuns.body", defaultValue: "Third-party plugins run SANDBOXED (deny-default): they can read only the paths they declare — served through a host broker — and cannot reach the network or launch processes unless they declare it and you consent. Personal/TCC stores (Messages, Mail, …) are served as frozen snapshots, never your live data. First-party (MacCrab-signed) plugins run with MacCrab's own access. Install only from a publisher you trust."))
                    .font(.caption2).foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(8)
            .background(Color.secondary.opacity(0.08))
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
            // Emphasised as an orange warning block (matching the install-block /
            // non-official patterns above) so the FINAL consent gate for running
            // third-party code doesn't read as just another caption among the
            // disclosures — it's the decision the whole sheet builds toward.
            if f.requiresThirdPartyConsent {
                VStack(alignment: .leading, spacing: 6) {
                    HStack(spacing: 6) {
                        Image(systemName: "exclamationmark.shield.fill").foregroundStyle(.orange)
                        Text(String(localized: "rave.consent.thirdPartyAck.title", defaultValue: "Third-party plugin — your consent required"))
                            .font(.caption.weight(.semibold)).foregroundStyle(.orange)
                    }
                    Toggle(isOn: $thirdPartyAck) {
                        Text(String(localized: "rave.consent.thirdPartyAck", defaultValue: "This is not a first-party MacCrab plugin. I trust “\(f.signerIdentity.isEmpty ? f.trustTier : f.signerIdentity)” and understand it runs sandboxed — reading only what it declares (brokered), with no network or process launch unless declared."))
                            .font(.caption)
                    }
                    .toggleStyle(.checkbox)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(8)
                .background(Color.orange.opacity(0.10))
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.orange.opacity(0.35), lineWidth: 1))
                .cornerRadius(6)
            }

            Text(String(localized: "rave.consent.resolvedFromCatalog",
                        defaultValue: "Every install detail above was resolved by id from the signed catalog — not from a link or any local input."))
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

    /// Compact "Reads / TCC / Emits" capability row for the consent chips block.
    private func consentChipRow(_ label: String, _ values: [String]) -> some View {
        HStack(alignment: .top, spacing: 6) {
            Text(label).font(.caption2.weight(.medium))
                .foregroundStyle(.tertiary).frame(width: 42, alignment: .trailing)
            VStack(alignment: .leading, spacing: 1) {
                ForEach(values.indices, id: \.self) { i in Text(values[i]).font(.caption2) }
            }
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
