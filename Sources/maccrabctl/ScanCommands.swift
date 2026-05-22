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
        [--no-encrypt]                  Plaintext scan (rare; metadata only).
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
    while i < args.count {
        switch args[i] {
        case "--plugin" where i + 1 < args.count:
            pluginIDs.append(args[i + 1]); i += 2
        default:
            i += 1
        }
    }
    guard let resolvedID = scanID else {
        print("Usage: maccrabctl scan run <scan-id> --plugin <plugin-id> [--plugin ...]")
        exit(1)
    }
    guard !pluginIDs.isEmpty else {
        print("Specify at least one --plugin <plugin-id>")
        exit(1)
    }
    // Delegate per-plugin to the existing plugin run dispatcher.
    for pluginID in pluginIDs {
        await dispatchPlugin(args: ["run", pluginID, "--case", resolvedID])
    }
}

private func scanRunAll(args: [String]) async {
    // v1.17 rc.1: scan run-all is a placeholder that hints at
    // the unified plugin invocation. Full implementation lands
    // in rc.3 alongside the wizard.
    print("scan run-all: not yet implemented (lands in v1.17.0-rc.3 alongside the 'Start a scan' wizard).")
    print("Until then: maccrabctl scan run <scan-id> --plugin <plugin-id> per plugin.")
    exit(2)
}

private func scanExport(args: [String]) async {
    // v1.17 rc.1: scan export hints at the evidence bundle flow
    // that lands in rc.3 (the .maccrabevidence container is the
    // rename of the existing .maccrabtrace bundle format).
    print("scan export: not yet implemented (lands in v1.17.0-rc.3).")
    print("Until then: maccrabctl trace bundle export <case-id> produces a .maccrabtrace bundle.")
    exit(2)
}
