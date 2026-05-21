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
            await pluginList()
        case "info":
            try await pluginInfo(args: rest)
        case "run":
            try await pluginRun(args: rest)
        case "run-tierb":
            try await pluginRunTierB(args: rest)
        case "install":
            try await pluginInstall(args: rest)
        case "uninstall":
            try await pluginUninstall(args: rest)
        case "installed-list":
            try await pluginInstalledList()
        case "trust":
            try await pluginTrust(args: rest)
        case "revoke":
            try await pluginRevoke(args: rest)
        case "trust-list":
            try await pluginTrustList()
        case "verify-all":
            try await pluginVerifyAll()
        case "run-installed":
            try await pluginRunInstalled(args: rest)
        case "daemon-status":
            try await pluginDaemonStatus()
        case "run-all-installed":
            try await pluginRunAllInstalled(args: rest)
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

    Subcommands:
      list                            List registered plugins.
      info <plugin-id>                Show manifest detail for one plugin.
      run <plugin-id> --case <id>     Invoke a plugin against a case.
        [--window <dur>]              Optional time window (e.g. --window 24h).
        [--since YYYY-MM-DD]          Open-ended time window.
      run-tierb <binary-path>         (Research) Spawn a Tier B plugin binary
        --case <id>                   via subprocess + JSON-RPC, commit
        [--plugin-id <id>]            artifacts. Default plugin-id is the
        [--ticks <N>]                 binary basename. --ticks N requests N
                                      fixture heartbeats.
      install <bundle-dir>            Install a signed Tier B plugin bundle.
        [--trust-on-install]          Add bundle's publisher key to trust list.
        [--force]                     Overwrite if already installed.
      uninstall <plugin-id>           Remove an installed Tier B plugin.
      installed-list                  List installed Tier B plugins.
      trust <key-hex>                 Add a publisher public key (64-hex
                                      / 32 bytes) to the trust store.
      revoke <key-hex>                Revoke a publisher key (preempts trust
                                      list; refused at install + load).
      trust-list                      Show trusted + revoked publisher keys.
      verify-all                      Verify every installed Tier B plugin
                                      against the current trust/revocation lists.
      run-installed <plugin-id>       Spawn an installed + verified Tier B
        --case <id>                   plugin under its manifest's sandbox
        [--ticks <N>]                 profile. Refuses to spawn on signature
        [--probe-read <path>]         failure or revoked key.
      daemon-status                   Structured summary of the verified plugin
                                      set, trust + revocation list sizes,
                                      plugins root path, and last-verified
                                      timestamp. Use to confirm the daemon
                                      sees the installed plugins.
      run-all-installed --case <id>   Run every verified Tier B plugin against
        [--scheduled]                 the case. Per-plugin status reported.
        [--ticks <N>]                 With --scheduled, refuses unless the
                                      case is marked scheduled-trusted (§10.5).
    """)
}

private func pluginList() async {
    let manifests = await PluginRegistry.shared.manifests()
    guard !manifests.isEmpty else {
        print("No plugins registered.")
        return
    }
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

// MARK: - Tier B run

/// `maccrabctl plugin run-tierb <binary> --case <id>` — spawns
/// the Tier B subprocess plugin, runs collect, commits artifacts
/// via the case's ArtifactStore. Research-grade — surface for
/// validating the IPC contract end-to-end.
private func pluginRunTierB(args: [String]) async throws {
    guard let binaryPath = args.first else {
        throw CaseCommandError.usage("Usage: maccrabctl plugin run-tierb <binary> --case <id> [--plugin-id <id>] [--ticks <N>] [--sandbox] [--allow-read <path>] [--probe-read <path>]")
    }
    var caseID: String? = nil
    var pluginID: String? = nil
    var ticks: Int = 1
    var sandbox = false
    var allowReads: [String] = []
    var probeRead: String? = nil
    var i = 1
    while i < args.count {
        let arg = args[i]
        switch arg {
        case "--case" where i + 1 < args.count:
            caseID = args[i + 1]; i += 2
        case "--plugin-id" where i + 1 < args.count:
            pluginID = args[i + 1]; i += 2
        case "--ticks" where i + 1 < args.count:
            ticks = Int(args[i + 1]) ?? 1; i += 2
        case "--sandbox":
            sandbox = true; i += 1
        case "--allow-read" where i + 1 < args.count:
            allowReads.append(args[i + 1]); i += 2
        case "--probe-read" where i + 1 < args.count:
            probeRead = args[i + 1]; i += 2
        default:
            i += 1
        }
    }
    guard let resolvedCase = caseID else {
        throw CaseCommandError.usage("Missing --case <id>")
    }
    let resolvedID = pluginID ?? (binaryPath as NSString).lastPathComponent

    let mgr = makeCaseManager()
    let handle = try await mgr.openCase(id: resolvedCase)
    let loader = TierBSubprocessLoader()
    // Build the sandbox profile (deny-default + supplied allow
    // reads + binary dir auto-added by the loader).
    let profile: SandboxProfileSpec? = sandbox
        ? SandboxProfileSpec(
            allowAllByDefault: false,
            fileReadSubpaths: allowReads,
            fileWriteSubpaths: [],
            networkConnectAllowlist: [],
            machServiceConnects: [],
            processExecPaths: [],
            allowProcessFork: true
        )
        : nil

    let (committed, rejected, result) = try await loader.runCollectAndCommit(
        binaryPath: binaryPath,
        pluginID: resolvedID,
        pluginVersion: "research",
        schemaVersion: 1,
        caseID: resolvedCase,
        caseName: handle.caseID,
        encryptionState: handle.encryptionState,
        store: handle.store,
        tickCount: ticks,
        probeRead: probeRead,
        sandboxProfile: profile
    )
    print("Ran Tier B subprocess plugin \(resolvedID) on case \(resolvedCase)")
    print("  Binary:               \(binaryPath)")
    print("  Sandbox enforced:     \(sandbox ? "yes" : "no")")
    print("  Subprocess exit:      \(result.subprocessExitCode)")
    print("  Status:               \(result.status)")
    print("  Artifacts received:   \(result.artifacts.count)")
    print("  Artifacts committed:  \(committed)")
    print("  Artifacts rejected:   \(rejected)")
    if !result.notes.isEmpty {
        print("  Notes:")
        for note in result.notes { print("    - \(note)") }
    }
}

// MARK: - daemon-status + run-all-installed

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

private func pluginRunAllInstalled(args: [String]) async throws {
    var caseID: String? = nil
    var ticks: Int = 1
    var scheduledOnly = false
    var i = 0
    while i < args.count {
        let arg = args[i]
        switch arg {
        case "--case" where i + 1 < args.count:
            caseID = args[i + 1]; i += 2
        case "--ticks" where i + 1 < args.count:
            ticks = Int(args[i + 1]) ?? 1; i += 2
        case "--scheduled":
            scheduledOnly = true; i += 1
        default:
            i += 1
        }
    }
    guard let resolvedCase = caseID else {
        throw CaseCommandError.usage("Usage: maccrabctl plugin run-all-installed --case <id> [--scheduled] [--ticks <N>]")
    }
    let mgr = makeCaseManager()
    let handle = try await mgr.openCase(id: resolvedCase)

    // Scheduled-mode gating per plan §10.5.
    if scheduledOnly {
        let caseRow = try await handle.store.fetchCase(id: resolvedCase)
        guard caseRow?.scheduledTrusted == true else {
            throw CaseCommandError.underlying(
                "--scheduled refused: case '\(resolvedCase)' is not marked scheduled-trusted. " +
                "Run 'maccrabctl case mark-trusted-scheduled \(resolvedCase)' first."
            )
        }
    }

    let bootstrap = TierBBootstrap()
    let status = await bootstrap.refresh()
    guard !status.verified.isEmpty else {
        print("No verified Tier B plugins installed under \(status.pluginsRoot).")
        if !status.failed.isEmpty {
            print("(\(status.failed.count) installed but failed verification — run 'plugin daemon-status' for detail.)")
        }
        return
    }

    let registry = TierBRegistry()
    var ranOK = 0
    var ranFailed = 0
    print("Running \(status.verified.count) verified Tier B plugin(s) against case \(resolvedCase)\(scheduledOnly ? " [--scheduled]" : "")")
    print("=========================================================")
    for p in status.verified {
        do {
            let (committed, rejected, _) = try await registry.runCollectAndCommit(
                pluginID: p.pluginID,
                caseID: resolvedCase,
                caseName: handle.caseID,
                encryptionState: handle.encryptionState,
                store: handle.store,
                tickCount: ticks
            )
            print("  ✓ \(p.pluginID) — committed=\(committed) rejected=\(rejected)")
            ranOK += 1
        } catch {
            print("  ✗ \(p.pluginID) — \(error)")
            ranFailed += 1
        }
    }
    print("---")
    print("Plugins succeeded:  \(ranOK)")
    print("Plugins failed:     \(ranFailed)")
}

// MARK: - install / uninstall / trust list

private func pluginInstall(args: [String]) async throws {
    guard let sourceDir = args.first else {
        throw CaseCommandError.usage("Usage: maccrabctl plugin install <bundle-dir> [--trust-on-install] [--force]")
    }
    var trustOnInstall = false
    var force = false
    for arg in args.dropFirst() {
        if arg == "--trust-on-install" { trustOnInstall = true }
        if arg == "--force" { force = true }
    }
    let installer = PluginInstaller()
    let installed = try await installer.install(
        sourceDir: URL(fileURLWithPath: sourceDir),
        trustOnInstall: trustOnInstall,
        force: force
    )
    print("Installed Tier B plugin '\(installed.pluginID)'")
    print("  Root:            \(installed.installRoot)")
    print("  Publisher key:   \(installed.publicKeyHex.prefix(16))…")
    print("  Trusted:         \(trustOnInstall ? "yes (added on install)" : "no (run 'maccrabctl plugin trust <hex>' to trust)")")
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

// MARK: - verify-all + run-installed

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

private func pluginRunInstalled(args: [String]) async throws {
    guard let pluginID = args.first else {
        throw CaseCommandError.usage("Usage: maccrabctl plugin run-installed <plugin-id> --case <id> [--ticks <N>] [--probe-read <path>]")
    }
    var caseID: String? = nil
    var ticks: Int = 1
    var probeRead: String? = nil
    var i = 1
    while i < args.count {
        let arg = args[i]
        switch arg {
        case "--case" where i + 1 < args.count:
            caseID = args[i + 1]; i += 2
        case "--ticks" where i + 1 < args.count:
            ticks = Int(args[i + 1]) ?? 1; i += 2
        case "--probe-read" where i + 1 < args.count:
            probeRead = args[i + 1]; i += 2
        default:
            i += 1
        }
    }
    guard let resolvedCase = caseID else {
        throw CaseCommandError.usage("Missing --case <id>")
    }

    let mgr = makeCaseManager()
    let handle = try await mgr.openCase(id: resolvedCase)
    let registry = TierBRegistry()
    let (committed, rejected, plugin) = try await registry.runCollectAndCommit(
        pluginID: pluginID,
        caseID: resolvedCase,
        caseName: handle.caseID,
        encryptionState: handle.encryptionState,
        store: handle.store,
        tickCount: ticks,
        probeRead: probeRead
    )
    print("Ran installed Tier B plugin \(pluginID) on case \(resolvedCase)")
    print("  Manifest version:     \(plugin.manifest.version)")
    print("  Bundle root:          \(plugin.bundleRoot)")
    print("  Publisher key:        \(plugin.publicKeyHex.prefix(16))…")
    print("  Artifacts committed:  \(committed)")
    print("  Artifacts rejected:   \(rejected)")
    if let probe = probeRead {
        print("  Probed path:          \(probe) (see artifacts for result)")
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
