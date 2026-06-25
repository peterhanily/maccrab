// `maccrabctl plugin` subcommands — list / info / run.
//
// Plan reference: §3.7 v1.13a CLI surface.

import Foundation
import MacCrabForensics

func dispatchPlugin(args: [String]) async {
    guard let sub = args.first else {
        printPluginUsage()
        exit(0)
    }
    let rest = Array(args.dropFirst())

    do {
        try await MacCrabForensicsBootstrap.registerBuiltins()
        switch sub {
        case "list":
            await pluginList(args: rest)
        case "info":
            try await pluginInfo(args: rest)
        case "run":
            try await pluginRun(args: rest)
        case "keygen":
            try await pluginKeygen(args: rest)
        case "sign":
            try await pluginSign(args: rest)
        case "test":
            try await pluginTest(args: rest)
        case "install":
            try await pluginInstall(args: rest)
        case "uninstall":
            try await pluginUninstall(args: rest)
        case "installed-list":
            printPluginAliasWarning("installed-list", "list --filter installed")
            try await pluginInstalledList()
        case "trust":
            try await pluginTrust(args: rest)
        case "revoke":
            try await pluginRevoke(args: rest)
        case "trust-list":
            try await pluginTrustList()
        case "verify-all":
            printPluginAliasWarning("verify-all", "verify")
            try await pluginVerifyAll()
        case "verify":
            // v1.17 — `verify` covers all-installed by default;
            // future: `verify <plugin-id>` for a single plugin.
            try await pluginVerifyAll()
        case "daemon-status":
            printPluginAliasWarning("daemon-status", "status")
            try await pluginDaemonStatus()
        case "status":
            try await pluginDaemonStatus()
        // Rave catalog store commands — refuse cleanly until the catalog
        // index is published (install still works against a configured catalog).
        case "search":
            try await pluginSearch(args: rest)
        case "update":
            try await pluginUpdate(args: rest)
        case "pin":
            try await pluginPin(args: rest)
        case "help", "-h", "--help":
            printPluginUsage()
        default:
            print("Unknown plugin subcommand: \(sub)")
            printPluginUsage()
            exit(1)
        }
    } catch let CaseCommandError.usage(msg) {
        print(msg)
        exit(1)
    } catch {
        print("Error: \(error)")
        exit(1)
    }
}

func printPluginUsage() {
    print("""
    Usage: maccrabctl plugin <subcommand>

    Browse, install, manage, and audit MacCrab plugins.

    Subcommands:
      list [--filter built-in|installed|all]
                                      List plugins. Default: all.
      info <plugin-id>                Show manifest detail.
      search "<query>"                Search the rave catalog at rave.maccrab.com.
      install <bundle-dir>            Install a signed plugin bundle.
        [--trust-on-install]          Trust this publisher for future installs.
        [--force]                     Overwrite if already installed.
      install <plugin-id>             Install from the rave catalog. Fetches
                                      <catalog-base>/catalog.json + per-plugin
                                      entry, verifies Ed25519 signatures
                                      against the bundled rave catalog key,
                                      downloads the bundle .zip, verifies
                                      artifact_sha256, then delegates to the
                                      local install + verify path.
        [--catalog-base <url>]        Default: https://rave.maccrab.com/
                                      (or env MACCRAB_RAVE_BASE_URL).
        [--version <semver>]          Pin to a specific version.
      install --local <path>          Sideload an unvetted local bundle.
                                      Persistent "Sideloaded · Unverified" badge.
      update <plugin-id>              Update to the catalog's current_version.
                                      [--yes] permitted ONLY for patch updates
                                      with no capability / TCC / network /
                                      privacy / signing-identity change.
      pin <plugin-id>                 Freeze at current installed version.
      uninstall <plugin-id>           Remove an installed plugin.
      verify [<plugin-id>]            Verify all installed (or one by id) against
                                      the current trust + revocation lists.
      status                          Structured summary: plugins root,
                                      trusted/revoked counts, verified/failed
                                      buckets, last-verified timestamp.
      trust <key-hex>                 Add a publisher public key (64-hex / 32 bytes).
      revoke <key-hex>                Revoke a publisher key (preempts trust).
      trust-list                      Show trusted + revoked publisher keys.
      run <plugin-id> --case <id>     Invoke a built-in or installed plugin
                                      against a case (Tier-B plugins run sandboxed).

    Authoring (contributor SDK):
      keygen [--out <dir>]            Generate an Ed25519 plugin-signing keypair
                                      (signing.key + signing.key.pub). Keep the
                                      private key OFFLINE.
      sign <bundle-dir> [--key <k>]   Sign a bundle (manifest + binary) in place.
      test <bundle-dir>               Run the bundle LOCALLY under the real
                                      sandbox and show its containment + outcome.

    Renamed in v1.17 (aliases work through v1.18, removed v1.19):
      installed-list  → list --filter installed
      verify-all      → verify
      daemon-status   → status
    """)
}

private func pluginList(args: [String] = []) async {
    // v1.17 — `--filter built-in|installed|all` lets operators
    // separate first-party (Tier A) plugins from third-party
    // (installed via PluginInstaller). Default is `all`.
    var filter: String = "all"
    var includeResidue = false
    var i = 0
    while i < args.count {
        switch args[i] {
        case "--filter" where i + 1 < args.count:
            filter = args[i + 1]; i += 2
        case "--include-residue":
            includeResidue = true; i += 1   // engineering escape hatch: show dev/test leftovers
        default:
            i += 1
        }
    }
    let showBuiltIn = filter == "all" || filter == "built-in"
    let showInstalled = filter == "all" || filter == "installed"

    if showBuiltIn {
        let manifests = await PluginRegistry.shared.manifests()
        if manifests.isEmpty {
            print("No built-in plugins registered.")
        } else {
            print("Built-in plugins:")
            let idWidth = max(manifests.map { $0.id.count }.max() ?? 0, "ID".count)
            let typeWidth = "fingerprinter".count
            let stabilityWidth = "stability".count
            print(rowAligned([
                ("ID", idWidth),
                ("Type", typeWidth),
                ("Version", 9),
                ("Stability", stabilityWidth),
            ]))
            print(String(repeating: "-", count: idWidth + typeWidth + 9 + stabilityWidth + 6))
            for m in manifests {
                print(rowAligned([
                    (m.id, idWidth),
                    (m.type.rawValue, typeWidth),
                    (m.version, 9),
                    (m.stability.rawValue, stabilityWidth),
                ]))
            }
            if showInstalled { print("") }
        }
    }
    if showInstalled {
        do {
            let installer = PluginInstaller()
            let rawInstalled = try await installer.list()
            // Hide dev/test/rehearsal residue by default (same classifier the
            // dashboard + MCP use); `--include-residue` shows it for engineering.
            let builtinIDs = Set(await PluginRegistry.shared.manifests().map { $0.id })
            let installed = includeResidue ? rawInstalled
                : PluginVisibility.filterInstalled(rawInstalled, builtinIDs: builtinIDs)
            if installed.isEmpty {
                if filter == "installed" {
                    print("No third-party plugins installed.")
                }
                // Don't double-print under filter=all if there are none
            } else {
                // v1.19.0: label each install by provenance — store (signed
                // rave-catalog receipt) vs operator-trusted third-party sideload.
                // Receipts live at <supportDir>/plugin_receipts.
                let receiptsDir = URL(fileURLWithPath: (installer.pluginsRootPath as NSString).deletingLastPathComponent)
                    .appendingPathComponent("plugin_receipts")
                print("Installed plugins:")
                for p in installed {
                    let prov = PluginProvenance.forInstalled(pluginID: p.pluginID, receiptsDir: receiptsDir)
                    print("  \(p.pluginID)  [\(prov.displayName)]  key=\(p.publicKeyHex.prefix(16))…")
                    print("    Root: \(p.installRoot)")
                }
            }
        } catch {
            print("(could not list installed plugins: \(error))")
        }
    }
}

/// Emit a deprecation hint when an operator hits an old plugin
/// subcommand name. v1.17 renames a few without breaking aliases.
func printPluginAliasWarning(_ oldName: String, _ newName: String) {
    let msg = "WARNING: 'maccrabctl plugin \(oldName)' is renamed 'maccrabctl plugin \(newName)' in v1.17. Aliases work through v1.18; removed in v1.19.\n"
    FileHandle.standardError.write(Data(msg.utf8))
}

// MARK: - rave catalog store stubs
//
// `search` is live (fetches + Ed25519-verifies the published catalog). `update`
// and `pin` are not yet wired — they return honest, accurate messages (the
// catalog IS live; install works via `plugin install <id>`).

private func pluginSearch(args: [String]) async throws {
    var query = ""
    var catalogBase: String? = nil
    var i = 0
    while i < args.count {
        if args[i] == "--catalog-base", i + 1 < args.count { catalogBase = args[i + 1]; i += 2 }
        else { if !args[i].hasPrefix("--") { query = args[i] }; i += 1 }
    }
    let base = catalogBase
        ?? ProcessInfo.processInfo.environment["MACCRAB_RAVE_BASE_URL"]
        ?? "https://rave.maccrab.com/"
    let fetcher = try PluginCatalogFetcher(catalogBase: base)
    let entries: [PluginCatalogFetcher.CatalogListEntry]
    do {
        entries = try await fetcher.listCatalog()
    } catch {
        print("plugin search: could not fetch or verify the rave catalog: \(error)")
        exit(2)
    }
    let q = query.lowercased()
    let matches = q.isEmpty ? entries : entries.filter {
        $0.id.lowercased().contains(q)
            || $0.displayName.lowercased().contains(q)
            || $0.shortDescription.lowercased().contains(q)
    }
    if matches.isEmpty {
        print(q.isEmpty ? "The rave catalog is empty." : "No catalog plugins match '\(query)'.")
        return
    }
    print("Rave catalog — \(matches.count) plugin\(matches.count == 1 ? "" : "s"):\n")
    for e in matches {
        print("  \(e.id)  v\(e.currentVersion)  [\(e.channel)]")
        if !e.displayName.isEmpty { print("    \(e.displayName)") }
        if !e.shortDescription.isEmpty { print("    \(e.shortDescription)") }
        print("")
    }
    print("Install with: maccrabctl plugin install <id>")
}

private func pluginUpdate(args: [String]) async throws {
    guard let id = args.first else {
        print("Usage: maccrabctl plugin update <plugin-id> [--yes]")
        exit(1)
    }
    print("plugin update is not yet wired. The rave catalog is live and carries current_version —")
    print("update by reinstalling the latest:  maccrabctl plugin install \(id) --force")
    exit(2)
}

private func pluginPin(args: [String]) async throws {
    guard let id = args.first else {
        print("Usage: maccrabctl plugin pin <plugin-id>")
        exit(1)
    }
    print("plugin pin is not yet wired (version pinning is a local operation; tracked as a follow-up). Plugin: \(id)")
    exit(2)
}

private func pluginInfo(args: [String]) async throws {
    guard let id = args.first else {
        throw CaseCommandError.usage("Usage: maccrabctl plugin info <plugin-id>")
    }
    guard let reg = await PluginRegistry.shared.registration(forID: id) else {
        throw CaseCommandError.underlying("No plugin registered with id '\(id)'.")
    }
    let m = reg.manifest
    print("""
    Plugin: \(m.id)
      Display name:    \(m.displayName)
      Version:         \(m.version)
      Schema version:  \(m.schemaVersion)
      Type:            \(m.type.rawValue)
      Runtime:         \(m.runtime.rawValue)
      Stability:       \(m.stability.rawValue)
      Description:     \(m.description)
    """)
    if !m.tccRequirements.isEmpty {
        print("  TCC requirements:")
        for t in m.tccRequirements { print("    - \(t.rawValue)") }
    }
    if !m.inputs.isEmpty {
        print("  Inputs:")
        for input in m.inputs {
            let defaultMarker = input.default.map { " (default \($0))" } ?? ""
            let reqMarker = input.required ? " [required]" : ""
            print("    --\(input.name)  (\(input.type.rawValue))\(defaultMarker)\(reqMarker)")
            print("        \(input.description)")
        }
    }
    if !m.outputs.isEmpty {
        print("  Outputs:")
        for output in m.outputs {
            let optMarker = output.optInRequired ? " [opt-in]" : ""
            print("    \(output.contentType)  (privacy=\(output.privacyClass.rawValue))\(optMarker)")
        }
    }
    if !m.mcpTools.isEmpty {
        print("  MCP tools:")
        for tool in m.mcpTools {
            print("    \(tool.name)  (privacy=\(tool.exposesPrivacyClass.rawValue))")
            print("        \(tool.description)")
        }
    }
}

private func pluginRun(args: [String]) async throws {
    guard let id = args.first else {
        throw CaseCommandError.usage("Usage: maccrabctl plugin run <plugin-id> --case <id> [--window <dur>] [--since YYYY-MM-DD] [--<input>=<value>]")
    }
    var caseID: String? = nil
    var window: MacCrabForensics.TimeWindow? = nil
    var inputValues: [String: InputValue] = [:]
    var i = 1
    while i < args.count {
        let arg = args[i]
        switch arg {
        case "--case" where i + 1 < args.count:
            caseID = args[i+1]; i += 2
        case "--window" where i + 1 < args.count:
            if let dur = parseDurationForPlugin(args[i+1]) {
                window = MacCrabForensics.TimeWindow.relative(dur)
            }
            i += 2
        case "--since" where i + 1 < args.count:
            if let date = parseISODateForPlugin(args[i+1]) {
                window = MacCrabForensics.TimeWindow.since(date)
            }
            i += 2
        default:
            // Generic --<key>=<value> and --<key> <value> input parsing.
            // Skips already-known flags above; anything else is treated
            // as plugin-supplied input.
            if arg.hasPrefix("--"), let eq = arg.firstIndex(of: "=") {
                let key = String(arg[arg.index(arg.startIndex, offsetBy: 2)..<eq])
                let raw = String(arg[arg.index(after: eq)...])
                inputValues[key] = parseInputValue(raw)
                i += 1
            } else if arg.hasPrefix("--"), i + 1 < args.count {
                let key = String(arg.dropFirst(2))
                inputValues[key] = parseInputValue(args[i + 1])
                i += 2
            } else {
                i += 1
            }
        }
    }
    guard let resolvedCase = caseID else {
        throw CaseCommandError.usage("Missing --case <id>")
    }

    let mgr = makeCaseManager()
    let handle = try await mgr.openCase(id: resolvedCase)
    let runner = PluginRunner()
    let inputs = PluginInvocationInputs(values: inputValues)

    // Dispatch by plugin type. Collectors get the case+window
    // surface; Analyzers get the analyze() surface (and findings
    // round-trip back through the ArtifactStore as artifacts).
    guard let registration = await PluginRegistry.shared.registration(forID: id) else {
        // Not a Tier-A (built-in) plugin. Try the first-party Tier-B path: an
        // INSTALLED, publisher-key-signed bundle run OUT-OF-PROCESS (Shape 2).
        // Fail-closed — until the operator bakes the publisher fingerprint into
        // FirstPartyTrustRoot this refuses cleanly (anchor unset); third-party
        // bundles always refuse. The spawn runs inside maccrabctl, which ignores
        // SIGPIPE (the host requirement for FirstPartyTierBRunner).
        try await runTierBCollector(id: id, handle: handle, window: window)
        return
    }
    switch registration.manifest.type {
    case .collector:
        let (result, invocationID) = try await runner.runCollector(
            id: id,
            handle: handle,
            window: window,
            inputs: inputs
        )
        print("Ran collector \(id) on case \(resolvedCase)")
        print("  Invocation id:        \(invocationID)")
        print("  Status:               \(result.status.rawValue)")
        print("  Artifacts committed:  \(result.artifactsCommitted)")
        print("  Artifacts rejected:   \(result.artifactsRejected)")
        if !result.notes.isEmpty {
            print("  Notes:")
            for note in result.notes {
                print("    - \(note)")
            }
        }
    case .analyzer:
        let (findings, invocationID) = try await runner.runAnalyzer(
            id: id,
            handle: handle,
            inputs: inputs
        )
        print("Ran analyzer \(id) on case \(resolvedCase)")
        print("  Invocation id:        \(invocationID)")
        print("  Findings emitted:     \(findings.count)")
        for f in findings.prefix(20) {
            print("    [\(f.severity.rawValue)] \(f.findingType): \(f.title)")
        }
        if findings.count > 20 {
            print("    ... \(findings.count - 20) more")
        }
    case .enricher:
        guard case .string(let p)? = inputs.values["path"], !p.isEmpty else {
            throw CaseCommandError.usage(
                "Enricher '\(id)' needs --path <url-or-file> (e.g. --path https://example.com/ or --path /usr/bin/foo)")
        }
        let url: URL = p.contains("://") ? (URL(string: p) ?? URL(fileURLWithPath: p)) : URL(fileURLWithPath: p)
        let (enrichment, invocationID) = try await runner.runEnricher(
            id: id,
            handle: handle,
            subject: .path(url),
            stage: .onDemand,
            inputs: inputs
        )
        print("Ran enricher \(id) on case \(resolvedCase)")
        print("  Invocation id:        \(invocationID)")
        if enrichment.fields.isEmpty {
            print("  (no enrichment fields produced)")
        } else {
            print("  Fields:")
            for (k, v) in enrichment.fields.sorted(by: { $0.key < $1.key }) {
                print("    \(k) = \(describeEnrichmentValue(v))")
            }
        }
    case .fingerprinter:
        throw CaseCommandError.underlying(
            "Plugin '\(id)' is a fingerprinter; use 'maccrabctl fingerprint' instead.")
    }
}

/// Render an EnrichmentValue for CLI output.
private func describeEnrichmentValue(_ v: EnrichmentValue) -> String {
    switch v {
    case .bool(let b):        return String(b)
    case .integer(let i):     return String(i)
    case .double(let d):      return String(d)
    case .string(let s):      return s
    case .stringArray(let a): return a.joined(separator: ", ")
    case .nil:                return "(nil)"
    }
}


// MARK: - first-party Tier-B run (Shape 2)

/// Run an installed FIRST-PARTY Tier-B collector out-of-process and commit its
/// artifacts to the open case. The execution authority is the Phase-1 gate
/// (resolveForFirstPartyExecution → publisher-fingerprint match); this is its
/// production caller. Fail-closed: a non-installed id, a third-party bundle, or
/// the unset publisher anchor all refuse here. The spawn (FirstPartyTierBRunner)
/// runs in maccrabctl, which ignores SIGPIPE.
private func runTierBCollector(id: String, handle: CaseHandle, window: TimeWindow?) async throws {
    // Defense-in-depth catalog-context flags for the execution gate.
    let ctx = TierBCollectorExecutor.catalogContextFromEnv()

    // S2: headless/CLI boxes don't get the dashboard's revocation sweep — run the
    // staleness reconcile before the run so a since-revoked-or-stale third-party
    // plugin is quarantined (resolve refuses a quarantined plugin before verify).
    _ = try? await RevocationReverifyService.reconcileDefaults()

    let caseRow = try await handle.store.fetchCase(id: handle.caseID)
    let allowsSensitive = (caseRow?.encryptionState ?? .plaintext) != .plaintext

    let scratch = NSTemporaryDirectory() + "maccrab-tierb-scratch-\(UUID().uuidString)"
    try FileManager.default.createDirectory(atPath: scratch, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(atPath: scratch) }

    let startU = window?.start.map { Int64($0.timeIntervalSince1970) }
    let endU = window?.end.map { Int64($0.timeIntervalSince1970) }

    // Shared two-lane dispatch (first-party → sandboxed; fail-closed).
    let exec: TierBExecutionResult
    do {
        exec = try await TierBCollectorExecutor.runInstalled(
            pluginID: id, scratchDir: scratch, windowStartUnix: startU, windowEndUnix: endU,
            officialSource: ctx.officialSource, catalogOverrideActive: ctx.catalogOverrideActive)
    } catch let e as TierBRegistry.RegistryError {
        if case .notInstalled = e {
            throw CaseCommandError.underlying(
                "Plugin '\(id)' is not a built-in (Tier A) plugin and is not installed (Tier B).")
        }
        throw CaseCommandError.underlying("\(e)")
    } catch let e as TierBCollectorExecutorError {
        throw CaseCommandError.underlying("\(e)")
    }

    // The run is recorded in plugin_invocations for the same audit trail Tier-A
    // runs get; artifacts commit through the host-stamped bridge.
    let invID = try await handle.store.recordInvocationStart(
        caseID: handle.caseID, pluginID: id,
        pluginVersion: exec.manifest.version, inputsJSON: "{}")
    let result = await TierBArtifactBridge.commit(
        outcome: exec.outcome, caseID: handle.caseID, manifest: exec.manifest,
        caseAllowsSensitive: allowsSensitive, output: StoreCollectorOutput(store: handle.store))
    try? await handle.store.recordInvocationEnd(
        id: invID, exitStatus: result.status.rawValue,
        artifactsCommitted: Int64(result.artifactsCommitted),
        artifactsRejected: Int64(result.artifactsRejected),
        errorMessage: result.notes.isEmpty ? nil : result.notes.joined(separator: "; "),
        snapshotHash: nil)

    print("Ran \(exec.lane.rawValue) Tier-B collector \(id) on case \(handle.caseID)")
    print("  Invocation id:        \(invID)")
    print("  Status:               \(result.status.rawValue)")
    print("  Artifacts committed:  \(result.artifactsCommitted)")
    print("  Artifacts rejected:   \(result.artifactsRejected)")
    if !result.notes.isEmpty {
        print("  Notes:")
        for note in result.notes.prefix(20) { print("    - \(note)") }
    }
}


// MARK: - keygen / sign / test  (contributor SDK)

private func pluginKeygen(args: [String]) async throws {
    var outDir = FileManager.default.currentDirectoryPath
    var i = 0
    while i < args.count { if args[i] == "--out", i + 1 < args.count { outDir = args[i + 1]; i += 2 } else { i += 1 } }
    let (priv, pub, hex) = CryptoSigning.newSigningKey()
    let keyPath = (outDir as NSString).appendingPathComponent("signing.key")
    let pubPath = (outDir as NSString).appendingPathComponent("signing.key.pub")
    try priv.write(to: URL(fileURLWithPath: keyPath), options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyPath)
    try pub.write(to: URL(fileURLWithPath: pubPath), options: .atomic)
    print("Generated Tier-B signing keypair:")
    print("  Private key:  \(keyPath)  (0600 — KEEP OFFLINE; never commit or place in a bundle)")
    print("  Public key:   \(pubPath)")
    print("  Public hex:   \(hex)")
    print("  Operators trust your plugins with:  maccrabctl plugin trust \(hex)")
}

private func pluginSign(args: [String]) async throws {
    var keyPath = "signing.key"
    var bundle: String?
    var i = 0
    while i < args.count {
        if args[i] == "--key", i + 1 < args.count { keyPath = args[i + 1]; i += 2 }
        else if !args[i].hasPrefix("--") { bundle = args[i]; i += 1 }
        else { i += 1 }
    }
    guard let bundle else {
        throw CaseCommandError.usage("Usage: maccrabctl plugin sign <bundle-dir> [--key signing.key]")
    }
    guard let privData = try? Data(contentsOf: URL(fileURLWithPath: keyPath)) else {
        throw CaseCommandError.underlying("Cannot read signing key at '\(keyPath)'. Generate one with: maccrabctl plugin keygen")
    }
    let hex = try CryptoSigning.signBundle(atPath: bundle, privateKeyRaw: privData)
    print("Signed bundle \(bundle)")
    print("  Wrote signature + signing.key.pub.")
    print("  Publisher key: \(hex)")
}

private func pluginTest(args: [String]) async throws {
    guard let bundle = args.first(where: { !$0.hasPrefix("--") }) else {
        throw CaseCommandError.usage("Usage: maccrabctl plugin test <bundle-dir>")
    }
    // Run the plugin LOCALLY under the real sandbox so the author SEES containment.
    // The dev trampoline (`swift build`) is ad-hoc-signed; allow it for THIS run
    // via an explicit value (not a process-global env var that could leak).
    let manifest = try TierBManifest.load(fromBundlePath: bundle)
    let tmpRoot = URL(fileURLWithPath: NSTemporaryDirectory() + "maccrab-plugintest-\(UUID().uuidString)")
    let installer = PluginInstaller(pluginsRoot: tmpRoot)
    defer { try? FileManager.default.removeItem(at: tmpRoot) }
    _ = try await installer.install(sourceDir: URL(fileURLWithPath: bundle), trustOnInstall: true)

    let scratch = NSTemporaryDirectory() + "maccrab-plugintest-scratch-\(UUID().uuidString)"
    try FileManager.default.createDirectory(atPath: scratch, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(atPath: scratch) }

    let consent = manifest.consentSummary()
    print("Testing \(manifest.id) v\(manifest.version)")
    print("  Declared reads:   \(consent.fileReads.isEmpty ? "(none)" : consent.fileReads.joined(separator: ", "))")
    print("  TCC (brokered):   \(consent.tccReads.isEmpty ? "(none)" : consent.tccReads.joined(separator: ", "))")
    print("  Network:          \(consent.networkEndpoints.isEmpty ? "deny" : consent.networkEndpoints.joined(separator: ", "))")
    print("  Privacy class:    \(consent.derivedHighestPrivacy)\(consent.privacyUnderdeclared ? "  (⚠ author under-declared!)" : "")")

    let registry = TierBRegistry(installer: installer)
    do {
        let exec = try await TierBCollectorExecutor.runInstalled(
            pluginID: manifest.id, scratchDir: scratch,
            officialSource: true, catalogOverrideActive: false, registry: registry,
            allowUnsignedTrampoline: true)   // local author test; DEBUG-honored only
        print("Ran under the \(exec.lane.rawValue) lane:")
        print("  Exit code:    \(exec.outcome.exitCode)")
        print("  Result:       \(exec.outcome.result?.status ?? "(no terminal result)")")
        print("  Artifacts:    \(exec.outcome.artifacts.count)")
        for a in exec.outcome.artifacts.prefix(10) { print("    - \(a.contentType): \(a.summary ?? "")") }
        if !exec.outcome.stderrTail.isEmpty { print("  stderr tail:  \(exec.outcome.stderrTail.prefix(400))") }
        if exec.lane == .sandboxed { print("  ✓ ran CONTAINED (deny-default sandbox; file reads brokered over fd 3).") }
    } catch {
        throw CaseCommandError.underlying("Run failed (fail-closed): \(error)")
    }
}

// MARK: - daemon-status

private func pluginDaemonStatus() async throws {
    let bootstrap = TierBBootstrap()
    let status = await bootstrap.refresh()
    let isoFmt = ISO8601DateFormatter()
    print("Plugin catalog status")
    print("=====================")
    print("Plugins root:       \(status.pluginsRoot)")
    print("Verified at:        \(isoFmt.string(from: status.verifiedAt))")
    print("Trusted keys:       \(status.trustedKeyCount)")
    print("Revoked keys:       \(status.revokedKeyCount)")
    print("Verified plugins:   \(status.verified.count)")
    print("Failed plugins:     \(status.failed.count)")
    print("Quarantined:        \(status.quarantined.count)")
    if !status.verified.isEmpty {
        print("")
        print("Verified:")
        for p in status.verified {
            print("  \(p.pluginID)  v\(p.version)  key=\(p.publicKeyHex.prefix(16))…")
        }
    }
    if !status.failed.isEmpty {
        print("")
        print("Failed:")
        for f in status.failed {
            print("  \(f.pluginID)")
            print("    Reason: \(f.reason)")
        }
    }
    if !status.quarantined.isEmpty {
        print("")
        print("Quarantined (revoked — on disk, refused load):")
        for q in status.quarantined {
            print("  \(q.pluginID)  v\(q.installedVersion)  [\(q.code)]")
            print("    Reason: \(q.reason)")
            if let serial = q.revocationsSerial {
                print("    Revoked as of revocations serial \(serial)")
            }
            if let url = q.advisoryURL {
                print("    Advisory: \(url)")
            }
        }
    }
}

// MARK: - install / uninstall / trust list

private func pluginInstall(args: [String]) async throws {
    var trustOnInstall = false
    var force = false
    var catalogBase: String?
    var version: String?
    var allowUnpinnedPrerelease = false
    var assumeYes = false
    var target: String?
    var i = 0
    while i < args.count {
        let arg = args[i]
        switch arg {
        case "--trust-on-install":
            trustOnInstall = true
        case "--force":
            force = true
        case "--local":
            break   // explicit sideload intent; a local path is auto-detected anyway
        case "--yes", "-y":
            assumeYes = true
        case "--allow-unpinned-prerelease":
            allowUnpinnedPrerelease = true
        case "--catalog-base":
            i += 1
            guard i < args.count else { throw CaseCommandError.usage("--catalog-base requires a URL") }
            catalogBase = args[i]
        case "--version":
            i += 1
            guard i < args.count else { throw CaseCommandError.usage("--version requires a version") }
            version = args[i]
        default:
            if target == nil && !arg.hasPrefix("-") { target = arg }
        }
        i += 1
    }
    guard let first = target else {
        throw CaseCommandError.usage("Usage: maccrabctl plugin install <bundle-dir>|<plugin-id> [--local] [--yes] [--trust-on-install] [--force] [--catalog-base <url>] [--version <ver>]")
    }

    // Plugin-id (reverse-DNS, no slashes) → HTTP catalog-fetch path.
    // Path / URL / anything-else → local bundle-dir SIDELOAD path.
    let installed: InstalledPlugin
    if isLikelyPluginID(first) {
        let base = catalogBase
            ?? ProcessInfo.processInfo.environment["MACCRAB_RAVE_BASE_URL"]
            ?? "https://rave.maccrab.com/"
        let fetcher = try PluginCatalogFetcher(catalogBase: base)
        installed = try await fetcher.installPluginByID(
            pluginID: first,
            version: version,
            trustOnInstall: trustOnInstall,
            force: force,
            allowUnpinnedPrerelease: allowUnpinnedPrerelease
        )
        print("Installed plugin '\(installed.pluginID)' from \(base)")
    } else {
        // Local bundle = a SIDELOAD: operator-vouched, UNVETTED code. Hard-refuse
        // namespace impersonation, then TOFU-disclose its capabilities before
        // trusting it. It will run sandboxed regardless.
        // S1: honor the operator kill-switch on the sideload (install) path too —
        // the catalog `frozen` flag covers the catalog path; this local flag is
        // the immediate incident lever for non-catalog installs. (A frozen remote
        // catalog is the cross-repo signed equivalent.)
        if TierBCollectorExecutor.thirdPartyExecutionDisabled() {
            throw CaseCommandError.underlying("Third-party plugins are disabled by the operator kill-switch — refusing to sideload.")
        }
        let manifest = try TierBManifest.load(fromBundlePath: first)
        let builtinNames = await PluginRegistry.shared.manifests().map { $0.displayName }
        switch RaveNamespaceGuard.evaluate(
            id: manifest.id, displayName: manifest.displayName,
            isFirstParty: false, firstPartyDisplayNames: builtinNames
        ) {
        case .reservedNamespaceImpersonation(let id):
            throw CaseCommandError.underlying("Refusing to install '\(id)': the com.maccrab.* namespace is reserved for first-party plugins.")
        case .confusableDisplayName(let name, let matches):
            throw CaseCommandError.underlying("Refusing to install: display name '\(name)' is confusable with first-party '\(matches)'.")
        case .ok:
            break
        }
        let consent = manifest.consentSummary()
        print("⚠ Sideloading UNVETTED third-party plugin '\(manifest.id)' v\(manifest.version)")
        print("  Operator-vouched code with NO rave-catalog vetting. It runs sandboxed; review its access:")
        print("    File reads:     \(consent.fileReads.isEmpty ? "(none)" : consent.fileReads.joined(separator: ", "))")
        if !consent.tccReads.isEmpty { print("    ⚠ Personal/TCC: \(consent.tccReads.joined(separator: ", "))  (served as brokered snapshots)") }
        print("    Network:        \(consent.networkEndpoints.isEmpty ? "deny" : consent.networkEndpoints.joined(separator: ", "))")
        print("    Exec/fork:      \((consent.execPaths.isEmpty && !consent.allowsFork) ? "deny" : "ALLOWED")")
        print("    Privacy class:  \(consent.derivedHighestPrivacy)\(consent.privacyUnderdeclared ? "  (⚠ author under-declared)" : "")")
        if consent.isDisclosedExfilSurface {
            print("  ⚠⚠ HIGH RISK: reads personal data AND has network egress (disclosed exfil surface).")
        }
        if !assumeYes {
            FileHandle.standardOutput.write(Data("  Type 'sideload' to proceed (or anything else to cancel): ".utf8))
            guard (readLine() ?? "") == "sideload" else { throw CaseCommandError.underlying("Sideload cancelled.") }
        }
        let installer = PluginInstaller()
        installed = try await installer.install(
            sourceDir: URL(fileURLWithPath: first),
            trustOnInstall: trustOnInstall,
            force: force
        )
        print("Installed (sideloaded) plugin '\(installed.pluginID)' — provenance: third-party · sideloaded · unverified")
    }
    print("  Root:            \(installed.installRoot)")
    print("  Publisher key:   \(installed.publicKeyHex.prefix(16))…")
    // Report ACTUAL persisted trust, not the user's --trust-on-install flag: an
    // official catalog entry whose signer pin verified is auto-trusted (its key is
    // added to the trust store), so the flag alone would mislead.
    let isTrusted = await PluginInstaller().currentTrustedKeys().contains(installed.publicKeyHex)
    print("  Trusted:         \(isTrusted ? "yes" : "no (run 'maccrabctl plugin trust \(installed.publicKeyHex.prefix(16))…' to trust)")")
}

// Treat as a plugin-id if it looks like reverse-DNS and contains no path
// separator. Anything with a `/` or starting with `.` is a local path.
private func isLikelyPluginID(_ s: String) -> Bool {
    if s.contains("/") || s.contains("\\") { return false }
    if s.hasPrefix(".") || s.hasPrefix("~") { return false }
    let parts = s.split(separator: ".")
    return parts.count >= 2 && parts.allSatisfy { p in
        p.allSatisfy { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" }
    }
}

private func pluginUninstall(args: [String]) async throws {
    guard let pluginID = args.first else {
        throw CaseCommandError.usage("Usage: maccrabctl plugin uninstall <plugin-id>")
    }
    let installer = PluginInstaller()
    try await installer.uninstall(pluginID: pluginID)
    print("Uninstalled \(pluginID).")
}

private func pluginInstalledList() async throws {
    let installer = PluginInstaller()
    let plugins = try await installer.list()
    guard !plugins.isEmpty else {
        print("No third-party plugins installed.")
        print("  (Plugins root: \(installer.pluginsRootPath))")
        return
    }
    for p in plugins {
        print("\(p.pluginID)")
        print("  Root:           \(p.installRoot)")
        print("  Publisher key:  \(p.publicKeyHex.prefix(16))…")
    }
}

private func pluginTrust(args: [String]) async throws {
    guard let key = args.first else {
        throw CaseCommandError.usage("Usage: maccrabctl plugin trust <key-hex>")
    }
    let cleaned = key.replacingOccurrences(of: " ", with: "").lowercased()
    guard cleaned.count == 64, cleaned.allSatisfy({ $0.isHexDigit }) else {
        throw CaseCommandError.usage("Public key must be 64-char hex (32 bytes raw Ed25519). Got: \(key)")
    }
    let installer = PluginInstaller()
    try await installer.addTrustedKey(cleaned)
    print("Added publisher key to trust list:")
    print("  \(cleaned)")
}

private func pluginRevoke(args: [String]) async throws {
    guard let key = args.first else {
        throw CaseCommandError.usage("Usage: maccrabctl plugin revoke <key-hex>")
    }
    let cleaned = key.replacingOccurrences(of: " ", with: "").lowercased()
    guard cleaned.count == 64, cleaned.allSatisfy({ $0.isHexDigit }) else {
        throw CaseCommandError.usage("Public key must be 64-char hex (32 bytes raw Ed25519). Got: \(key)")
    }
    let installer = PluginInstaller()
    try await installer.revokeKey(cleaned)
    print("Revoked publisher key (removed from trust list, added to revocation list):")
    print("  \(cleaned)")
}

private func pluginTrustList() async throws {
    let installer = PluginInstaller()
    let trusted = await installer.currentTrustedKeys()
    let revoked = await installer.currentRevokedKeys()
    if trusted.isEmpty && revoked.isEmpty {
        print("No keys in trust or revocation list.")
        return
    }
    if !trusted.isEmpty {
        print("Trusted publisher keys (\(trusted.count)):")
        for k in trusted.sorted() {
            print("  \(k)")
        }
    }
    if !revoked.isEmpty {
        print("Revoked publisher keys (\(revoked.count)):")
        for k in revoked.sorted() {
            print("  \(k)")
        }
    }
}

// MARK: - verify-all

private func pluginVerifyAll() async throws {
    let registry = TierBRegistry()
    let report = await registry.verifyAll()
    print("Plugin verification (\(report.total) installed)")
    print("======================================================")
    if !report.verified.isEmpty {
        print("Verified (\(report.verified.count)):")
        for p in report.verified {
            print("  \(p.pluginID)  v\(p.manifest.version)  key=\(p.publicKeyHex.prefix(16))…")
        }
    }
    if !report.failed.isEmpty {
        print("")
        print("Failed (\(report.failed.count)):")
        for f in report.failed {
            print("  \(f.pluginID)")
            print("    Reason: \(f.reason)")
        }
    }
    if report.failed.isEmpty && report.verified.isEmpty {
        print("(no plugins installed)")
    }
    // resolve() stamps a temp verified-binary on disk per plugin.
    // This is the verify-only path — nothing spawns them — so discard
    // every one before returning, or each invocation leaks one
    // executable into NSTemporaryDirectory(). Mirrors
    // TierBBootstrap.refresh()'s cleanup.
    for p in report.verified {
        registry.cleanupVerifiedBinary(p)
    }
}

// MARK: - Local helpers (mirrors CaseCommands; kept small)

/// Parse an operator-supplied CLI value into the typed InputValue
/// shape PluginInvocationInputs accepts. Honors the literal
/// strings "true" / "false" → .bool, integer parse → .integer,
/// everything else → .string.
private func parseInputValue(_ raw: String) -> InputValue {
    if raw == "true" || raw == "TRUE" { return .bool(true) }
    if raw == "false" || raw == "FALSE" { return .bool(false) }
    if let i = Int(raw) { return .integer(i) }
    return .string(raw)
}

private func parseDurationForPlugin(_ raw: String) -> TimeInterval? {
    let s = raw.lowercased()
    guard let suffix = s.last else { return nil }
    let body = String(s.dropLast())
    guard let value = Double(body) else { return nil }
    switch suffix {
    case "h": return value * 3600
    case "m": return value * 60
    case "d": return value * 86_400
    case "s": return value
    default: return nil
    }
}

private func parseISODateForPlugin(_ raw: String) -> Date? {
    if let d = ISO8601DateFormatter().date(from: raw) { return d }
    let f = DateFormatter()
    f.dateFormat = "yyyy-MM-dd"
    f.timeZone = TimeZone(secondsFromGMT: 0)
    return f.date(from: raw)
}
