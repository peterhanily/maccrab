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
    guard let query = args.first, !query.hasPrefix("--") else {
        print("Usage: maccrabctl evidence search \"<query>\" [--limit N]")
        exit(1)
    }
    var limit = 200
    var i = 1
    while i < args.count {
        if args[i] == "--limit", i + 1 < args.count { limit = Int(args[i + 1]) ?? 200; i += 2 } else { i += 1 }
    }
    let needle = query.lowercased()
    let mgr = makeCaseManager()
    let cases: [CaseManifest]
    do { cases = try await mgr.listCases() } catch {
        print("Error listing scans: \(error)"); exit(1)
    }
    guard !cases.isEmpty else { print("No scans yet."); return }

    var hits = 0
    for c in cases {
        // Best-effort: skip scans that don't open (e.g. an encrypted case whose
        // key isn't available to this process) rather than aborting the search.
        guard let handle = try? await mgr.openCase(id: c.id),
              let rows = try? await handle.store.query(ArtifactQuery(caseID: c.id, limit: 10_000)) else { continue }
        for a in rows {
            let hay = ((a.record.summary ?? "") + " " + a.record.contentType + " " + a.record.sha256).lowercased()
            guard hay.contains(needle) else { continue }
            print("[\(c.id)] #\(a.id) \(a.record.contentType) — \(a.record.summary ?? "(no summary)")")
            hits += 1
            if hits >= limit { print("... (limit \(limit) reached)"); print("\n\(hits) match(es)."); return }
        }
    }
    print(hits == 0 ? "No evidence matched \"\(query)\"." : "\n\(hits) match(es).")
}

private func evidenceShow(args: [String]) async {
    var scanID: String? = nil
    var evidenceID: Int64? = nil
    var i = 0
    while i < args.count {
        switch args[i] {
        case "--scan" where i + 1 < args.count:
            scanID = args[i + 1]; i += 2
        default:
            if evidenceID == nil, let n = Int64(args[i]) { evidenceID = n }
            i += 1
        }
    }
    guard let eid = evidenceID else {
        print("Usage: maccrabctl evidence show [--scan <scan-id>] <evidence-id>")
        exit(1)
    }
    let mgr = makeCaseManager()
    let scanIDs: [String]
    if let s = scanID { scanIDs = [s] }
    else { scanIDs = ((try? await mgr.listCases()) ?? []).map { $0.id } }

    for sid in scanIDs {
        guard let handle = try? await mgr.openCase(id: sid),
              let rows = try? await handle.store.query(ArtifactQuery(caseID: sid, limit: 100_000)),
              let a = rows.first(where: { $0.id == eid }) else { continue }
        print("Evidence #\(a.id)  (scan \(sid))")
        print("  content_type: \(a.record.contentType)")
        print("  summary:      \(a.record.summary ?? "(none)")")
        print("  observed_at:  \(ISO8601DateFormatter().string(from: a.record.observedAt))")
        print("  privacy:      \(a.record.privacyClass.rawValue)")
        print("  sha256:       \(a.record.sha256)")
        if !a.record.data.isEmpty {
            print("  data:")
            for (k, v) in a.record.data.sorted(by: { $0.key < $1.key }) {
                print("    \(k) = \(String(describing: v.foundationValue))")
            }
        }
        return
    }
    print("Evidence #\(eid) not found\(scanID.map { " in scan \($0)" } ?? " in any scan").")
    exit(2)
}

private func evidenceExport(args: [String]) async {
    print("evidence export: not yet implemented.")
    exit(2)
}
