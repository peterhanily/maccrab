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
        throw CaseCommandError.usage("Usage: maccrabctl plugin run <plugin-id> --case <id> [--window <dur>] [--since YYYY-MM-DD]")
    }
    var caseID: String? = nil
    var window: MacCrabForensics.TimeWindow? = nil
    var i = 1
    while i < args.count {
        switch args[i] {
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
            i += 1
        }
    }
    guard let resolvedCase = caseID else {
        throw CaseCommandError.usage("Missing --case <id>")
    }

    let mgr = makeCaseManager()
    let handle = try await mgr.openCase(id: resolvedCase)
    let runner = PluginRunner()

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
            window: window
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
            handle: handle
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

// MARK: - Local helpers (mirrors CaseCommands; kept small)

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
