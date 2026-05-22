// EvidenceCommands.swift
// maccrabctl — v1.17 namespace for artifact list / search /
// show / export. Per docs/forensics-ia-redesign-plan.md §4.2.
//
// Operators understand "evidence" — what you ship in an
// incident response engagement. The underlying primitives are
// the same ArtifactStore queries the case namespace already
// exposes; this layer renames + restores scan context to
// every row.

import Foundation
import MacCrabForensics

func dispatchEvidence(args: [String]) async {
    guard let sub = args.first else {
        printEvidenceUsage()
        exit(0)
    }
    let rest = Array(args.dropFirst())
    switch sub {
    case "list":
        await evidenceList(args: rest)
    case "search":
        await evidenceSearch(args: rest)
    case "show":
        await evidenceShow(args: rest)
    case "export":
        await evidenceExport(args: rest)
    case "help", "-h", "--help":
        printEvidenceUsage()
    default:
        print("Unknown evidence subcommand: \(sub)")
        printEvidenceUsage()
        exit(1)
    }
}

func printEvidenceUsage() {
    print("""
    Usage: maccrabctl evidence <subcommand>

    List, search, and export evidence collected during scans.

    Subcommands:
      list --scan <scan-id>             List evidence rows for a scan.
        [--type <content-type>]         Filter by content type.
        [--limit <N>]                   Page size (default 100).
      search "<query>"                  Search evidence across all scans.
      show <evidence-id>                Show one evidence row.
      export --scan <scan-id>           Export an evidence bundle.
        [--output <path>.maccrabevidence]

    Equivalent legacy commands:
      maccrabctl case artifacts <case-id>        → evidence list --scan <case-id>
      maccrabctl trace bundle export <case-id>   → evidence export --scan <case-id>
    """)
}

private func evidenceList(args: [String]) async {
    var scanID: String? = nil
    var contentType: String? = nil
    var limit = 100
    var i = 0
    while i < args.count {
        switch args[i] {
        case "--scan" where i + 1 < args.count:
            scanID = args[i + 1]; i += 2
        case "--type" where i + 1 < args.count:
            contentType = args[i + 1]; i += 2
        case "--limit" where i + 1 < args.count:
            limit = Int(args[i + 1]) ?? 100; i += 2
        default:
            i += 1
        }
    }
    guard let resolved = scanID else {
        print("Usage: maccrabctl evidence list --scan <scan-id> [--type <content-type>] [--limit <N>]")
        exit(1)
    }
    // Delegate to existing case artifacts handler. Args shape:
    // case artifacts <case-id> [--type <ct>] [--limit N]
    var pass: [String] = ["artifacts", resolved]
    if let ct = contentType { pass += ["--type", ct] }
    pass += ["--limit", String(limit)]
    await dispatchCase(args: pass)
}

private func evidenceSearch(args: [String]) async {
    guard let query = args.first else {
        print("Usage: maccrabctl evidence search \"<query>\"")
        exit(1)
    }
    // v1.17 rc.1: cross-scan search lands in rc.3 alongside the
    // wizard. For now hint at the existing per-case hunt.
    print("evidence search: cross-scan search lands in v1.17.0-rc.3.")
    print("Until then: maccrabctl hunt \(query) (event-side search) or")
    print("            maccrabctl evidence list --scan <scan-id> (per-scan listing).")
    exit(2)
}

private func evidenceShow(args: [String]) async {
    guard args.first != nil else {
        print("Usage: maccrabctl evidence show <evidence-id>")
        exit(1)
    }
    print("evidence show: lands in v1.17.0-rc.3 alongside the unified Evidence tab.")
    exit(2)
}

private func evidenceExport(args: [String]) async {
    print("evidence export: lands in v1.17.0-rc.3 alongside the .maccrabevidence bundle format.")
    print("Until then: maccrabctl trace bundle export <case-id> produces a .maccrabtrace bundle.")
    exit(2)
}
