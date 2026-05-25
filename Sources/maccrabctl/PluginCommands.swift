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
        // v1.17 rc.1: store-side commands. Stubbed until rc.4
        // brings up the rave catalog fetcher + Sigstore verifier.
        case "search":
            try await pluginSearchStub(args: rest)
        case "update":
            try await pluginUpdateStub(args: rest)
        case "pin":
            try await pluginPinStub(args: rest)
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
      search "<query>"                Search the rave catalog at maccrab.com/rave/.
                                      (Catalog fetcher lands v1.17.0-rc.4.)
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
        [--catalog-base <url>]        Default: https://maccrab.com/rave/
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
      run <plugin-id> --case <id>     Invoke a built-in plugin against a case.

    Renamed in v1.17 (aliases work through v1.18, removed v1.19):
      installed-list  → list --filter installed
      verify-all      → verify
      daemon-status   → status

    Third-party plugin Run is disabled until subprocess spawn ships
    in a future release (rave Phase 1 dependency). Built-in (Tier A)
    Run via `maccrabctl plugin run` continues to work as today.
    """)
}

private func pluginList(args: [String] = []) async {
    // v1.17 — `--filter built-in|installed|all` lets operators
    // separate first-party (Tier A) plugins from third-party
    // (installed via PluginInstaller). Default is `all`.
    var filter: String = "all"
    var i = 0
    while i < args.count {
        switch args[i] {
        case "--filter" where i + 1 < args.count:
            filter = args[i + 1]; i += 2
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
            let installed = try await installer.list()
            if installed.isEmpty {
                if filter == "installed" {
                    print("No third-party plugins installed.")
                }
                // Don't double-print under filter=all if there are none
            } else {
                print("Installed third-party plugins:")
                for p in installed {
                    print("  \(p.pluginID)  key=\(p.publicKeyHex.prefix(16))…")
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

// MARK: - v1.17 rc.1 store stubs
//
// search/update/pin all touch the rave catalog at maccrab.com/rave/,
// which doesn't yet have a publicly served catalog index. These
// stubs return a clear "lands in rc.4" message so operators
// (and any scripts) get a documented signal.

private func pluginSearchStub(args: [String]) async throws {
    let q = args.first ?? ""
    print("plugin search: catalog lookup lands in v1.17.0-rc.4.")
    print("Until then: maccrabctl plugin list --filter installed (for local).")
    print("Search query was: \(q.isEmpty ? "(none)" : q)")
    exit(2)
}

private func pluginUpdateStub(args: [String]) async throws {
    guard let id = args.first else {
        print("Usage: maccrabctl plugin update <plugin-id> [--yes]")
        exit(1)
    }
    print("plugin update: catalog lookup lands in v1.17.0-rc.4. (plugin-id: \(id))")
    print("Until then: reinstall manually via maccrabctl plugin install <bundle>.")
    exit(2)
}

private func pluginPinStub(args: [String]) async throws {
    guard let id = args.first else {
        print("Usage: maccrabctl plugin pin <plugin-id>")
        exit(1)
    }
    print("plugin pin: version pinning lands in v1.17.0-rc.4 alongside catalog lookup. (plugin-id: \(id))")
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
        throw CaseCommandError.underlying("Plugin '\(id)' is not registered.")
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
    case .enricher, .fingerprinter:
        throw CaseCommandError.underlying(
            "Plugin '\(id)' is type=\(registration.manifest.type.rawValue); use 'maccrabctl fingerprint' for fingerprinters or the forensics.* MCP tool surface for enrichers."
        )
    }
}


// MARK: - daemon-status

private func pluginDaemonStatus() async throws {
    let bootstrap = TierBBootstrap()
    let status = await bootstrap.refresh()
    let isoFmt = ISO8601DateFormatter()
    print("Tier B daemon status")
    print("=====================")
    print("Plugins root:       \(status.pluginsRoot)")
    print("Verified at:        \(isoFmt.string(from: status.verifiedAt))")
    print("Trusted keys:       \(status.trustedKeyCount)")
    print("Revoked keys:       \(status.revokedKeyCount)")
    print("Verified plugins:   \(status.verified.count)")
    print("Failed plugins:     \(status.failed.count)")
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
}

// MARK: - install / uninstall / trust list

private func pluginInstall(args: [String]) async throws {
    guard let first = args.first else {
        throw CaseCommandError.usage("Usage: maccrabctl plugin install <bundle-dir>|<plugin-id> [--trust-on-install] [--force] [--catalog-base <url>] [--version <ver>]")
    }
    var trustOnInstall = false
    var force = false
    var catalogBase: String?
    var version: String?
    var i = 1
    while i < args.count {
        let arg = args[i]
        switch arg {
        case "--trust-on-install":
            trustOnInstall = true
        case "--force":
            force = true
        case "--catalog-base":
            i += 1
            guard i < args.count else { throw CaseCommandError.usage("--catalog-base requires a URL") }
            catalogBase = args[i]
        case "--version":
            i += 1
            guard i < args.count else { throw CaseCommandError.usage("--version requires a version") }
            version = args[i]
        default:
            break
        }
        i += 1
    }

    // Plugin-id (reverse-DNS, no slashes) → HTTP catalog-fetch path.
    // Path / URL / anything-else → existing local bundle-dir path.
    let installed: InstalledPlugin
    if isLikelyPluginID(first) {
        let base = catalogBase
            ?? ProcessInfo.processInfo.environment["MACCRAB_RAVE_BASE_URL"]
            ?? "https://maccrab.com/rave/"
        let fetcher = try PluginCatalogFetcher(catalogBase: base)
        installed = try await fetcher.installPluginByID(
            pluginID: first,
            version: version,
            trustOnInstall: trustOnInstall,
            force: force
        )
        print("Installed Tier B plugin '\(installed.pluginID)' from \(base)")
    } else {
        let installer = PluginInstaller()
        installed = try await installer.install(
            sourceDir: URL(fileURLWithPath: first),
            trustOnInstall: trustOnInstall,
            force: force
        )
        print("Installed Tier B plugin '\(installed.pluginID)'")
    }
    print("  Root:            \(installed.installRoot)")
    print("  Publisher key:   \(installed.publicKeyHex.prefix(16))…")
    print("  Trusted:         \(trustOnInstall ? "yes (added on install)" : "no (run 'maccrabctl plugin trust <hex>' to trust)")")
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
        print("No Tier B plugins installed.")
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
    print("Tier B plugin verification (\(report.total) installed)")
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
