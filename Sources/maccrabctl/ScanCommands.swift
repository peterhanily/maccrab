// ScanCommands.swift
// maccrabctl — v1.17 customer-shaped rename of `case`.
//
// Per docs/forensics-ia-redesign-plan.md §4.2. The CLI uses
// 'scan' because customers come with the job "scan this Mac",
// not "create a forensic case." 'case' continues to work as a
// deprecation-warned alias through v1.18.
//
// Most subcommands delegate to the existing CaseCommands
// implementations — the underlying SQLite + ArtifactStore +
// CaseManager are unchanged. This layer is rename + the new
// reason-preset wizard.

import Foundation
import MacCrabForensics

/// Print a one-time deprecation hint when an operator uses
/// `maccrabctl case ...` instead of `maccrabctl scan ...`.
func printScanAliasWarning(_ command: String) {
    let msg = "WARNING: 'maccrabctl \(command)' is renamed 'maccrabctl scan' in v1.17. Aliases work through v1.18; removed in v1.19.\n"
    FileHandle.standardError.write(Data(msg.utf8))
}

func dispatchScan(args: [String]) async {
    guard let sub = args.first else {
        printScanUsage()
        exit(0)
    }
    let rest = Array(args.dropFirst())
    // Delegate to existing case handlers for the shared
    // lifecycle (new / list / show / delete). Two scan-specific
    // verbs (run / run-all / export) wrap PluginRunner + the
    // existing artifact export bundler.
    switch sub {
    case "new":
        await dispatchCase(args: ["new"] + rest)
    case "list":
        await dispatchCase(args: ["list"])
    case "show":
        await dispatchCase(args: ["show"] + rest)
    case "run":
        await scanRun(args: rest)
    case "run-all":
        await scanRunAll(args: rest)
    case "export":
        await scanExport(args: rest)
    // The forensic read loop (findings / explain / timeline / artifacts) and the
    // AI-disclosure verbs are part of the canonical `scan` namespace, not just
    // the deprecated `case` alias. Delegate to the shared CaseCommands handlers
    // so `maccrabctl scan findings <id>` works as `--help` advertises.
    case "findings", "explain", "timeline", "artifacts", "allow-ai", "mark-trusted-scheduled":
        await dispatchCase(args: [sub] + rest)
    case "delete":
        await dispatchCase(args: ["delete"] + rest)
    case "help", "-h", "--help":
        printScanUsage()
    default:
        print("Unknown scan subcommand: \(sub)")
        printScanUsage()
        exit(1)
    }
}

func printScanUsage() {
    print("""
    Usage: maccrabctl scan <subcommand>

    Run, schedule, and review scans of this Mac.

    Subcommands:
      new "<name>"                      Create a new scan.
        [--reason triage|routine|ir|explore]
                                        Preselects an appropriate plugin set
                                        + privacy ceiling.
        [--window <dur>]                Bound the scan's evidence window.
        [--encrypt]                     Attempt an encrypted case (dashboard only;
                                        the CLI is metadata-tier plaintext by default).
      list                              List scans (newest first).
      show <scan-id>                    Show scan metadata + run history.
      run <scan-id>                     Run one or more plugins on a scan.
        --plugin <plugin-id>            Repeatable.
      run-all <scan-id>                 Run every applicable plugin.
        [--scheduled]                   Only proceed if scheduled-trusted.
      export <scan-id>                  Export evidence bundle.
        [--output <path>.maccrabevidence]
      delete <scan-id> [--shred]        Remove a scan.

    Equivalent legacy command: maccrabctl case ...
    """)
}

// MARK: - scan run / run-all / export
//
// These are the new scan-shaped verbs that didn't exist as
// `case` subcommands. They wrap PluginRunner + the export
// bundle flow respectively.

private func scanRun(args: [String]) async {
    var scanID: String? = nil
    var pluginIDs: [String] = []
    var i = 0
    if !args.isEmpty, !args[0].hasPrefix("--") {
        scanID = args[0]
        i = 1
    }
    var passthrough: [String] = []
    while i < args.count {
        switch args[i] {
        case "--plugin" where i + 1 < args.count:
            pluginIDs.append(args[i + 1]); i += 2
        default:
            // Forward any other `--key value` pair to the plugin dispatcher
            // (e.g. `--path <file>` for file-analyzer plugins). Pre-this they
            // were silently dropped, so an operator path never reached the plugin.
            if args[i].hasPrefix("--"), i + 1 < args.count, !args[i + 1].hasPrefix("--") {
                passthrough.append(args[i]); passthrough.append(args[i + 1]); i += 2
            } else {
                i += 1
            }
        }
    }
    guard let resolvedID = scanID else {
        print("Usage: maccrabctl scan run <scan-id> --plugin <plugin-id> [--plugin ...] [--path <file>]")
        exit(1)
    }
    guard !pluginIDs.isEmpty else {
        print("Specify at least one --plugin <plugin-id>")
        exit(1)
    }
    // Delegate per-plugin to the existing plugin run dispatcher, forwarding any
    // passthrough flags (--path, etc.) into PluginInvocationInputs.
    for pluginID in pluginIDs {
        await dispatchPlugin(args: ["run", pluginID, "--case", resolvedID] + passthrough)
    }
}

private func scanRunAll(args: [String]) async {
    guard let scanID = args.first, !scanID.hasPrefix("--") else {
        print("Usage: maccrabctl scan run-all <scan-id>")
        exit(1)
    }
    // Register the built-ins so the registry is populated, then run every
    // applicable plugin: collectors first, then analyzers (which read the
    // artifacts collectors just committed). Enrichers are excluded — they
    // require an explicit --path input, so they aren't part of a bare run-all.
    try? await MacCrabForensicsBootstrap.registerBuiltins()
    let manifests = await PluginRegistry.shared.manifests()
    let ordered = manifests.filter { $0.type == .collector } + manifests.filter { $0.type == .analyzer }
    guard !ordered.isEmpty else {
        print("No built-in collectors or analyzers are registered.")
        exit(1)
    }
    print("Running \(ordered.count) applicable plugins on case \(scanID) (enrichers need --path; run them individually)…\n")
    for m in ordered {
        print("── \(m.id) ──")
        await dispatchPlugin(args: ["run", m.id, "--case", scanID])
        print("")
    }
}

private func scanExport(args: [String]) async {
    var scanID: String? = nil
    var output: String? = nil
    var i = 0
    while i < args.count {
        switch args[i] {
        case "--output" where i + 1 < args.count: output = args[i + 1]; i += 2
        default:
            if scanID == nil, !args[i].hasPrefix("--") { scanID = args[i] }
            i += 1
        }
    }
    guard let sid = scanID else {
        print("Usage: maccrabctl scan export <scan-id> [--output <path>.maccrabevidence]")
        exit(1)
    }
    // Shared implementation with `evidence export` (EvidenceCommands.swift).
    await exportEvidenceBundle(scanID: sid, output: output)
}
