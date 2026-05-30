// `maccrabctl case` subcommands — operator-facing entry point to
// the Mac Context Plugin Platform case lifecycle.
//
// Plan reference: §3.7 v1.13a CLI surface.

import Foundation
import os
import MacCrabCore
import MacCrabForensics

/// Audit sink for state-modifying case operations. Mirrors the MCP
/// server's audit mechanism (maccrab-mcp emits `logger.notice("MCP AUDIT: …")`
/// at subsystem "com.maccrab.mcp"); the CLI uses the same os.log `.notice`
/// + "AUDIT" convention under "com.maccrab.ctl". os.log records the timestamp.
private let caseAuditLogger = Logger(subsystem: "com.maccrab.ctl", category: "case-audit")

enum CaseCommandError: Error, CustomStringConvertible {
    case usage(String)
    case underlying(String)

    var description: String {
        switch self {
        case .usage(let msg): return msg
        case .underlying(let msg): return msg
        }
    }
}

/// Dispatch `maccrabctl case <subcommand> ...`. Called from
/// MacCrabCtl.main when args[1] == "case".
func dispatchCase(args: [String]) async {
    guard let sub = args.first else {
        printCaseUsage()
        exit(0)
    }
    let rest = Array(args.dropFirst())

    do {
        try await MacCrabForensicsBootstrap.registerBuiltins()
        let mgr = makeCaseManager()
        switch sub {
        case "new":
            try await caseNew(mgr: mgr, args: rest)
        case "list":
            try await caseList(mgr: mgr)
        case "show":
            try await caseShow(mgr: mgr, args: rest)
        case "artifacts":
            try await caseArtifacts(mgr: mgr, args: rest)
        case "allow-ai":
            try await caseAllowAI(mgr: mgr, args: rest)
        case "mark-trusted-scheduled":
            try await caseMarkTrustedScheduled(mgr: mgr, args: rest)
        case "delete":
            try await caseDelete(mgr: mgr, args: rest)
        case "help", "-h", "--help":
            printCaseUsage()
        default:
            print("Unknown case subcommand: \(sub)")
            printCaseUsage()
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

func printCaseUsage() {
    print("""
    Usage: maccrabctl case <subcommand>

    Subcommands:
      new <name> [--window 24h | --since YYYY-MM-DD] [--notes "<text>"] [--no-encrypt]
                                          Create a new case. Encrypted by default.
      list                                List all cases (newest first).
      show <case-id>                      Show case metadata.
      artifacts <case-id> [--type <ct>] [--limit N]
                                          List committed artifacts for a case.
      allow-ai --content <case-id>        Grant AI agents access to non-metadata
                                          artifacts in this case (default off).
      mark-trusted-scheduled <case-id>    Opt this case into auto-proceeding
                                          scheduled runs (toast still emits).
      delete [--shred] <case-id>          Delete a case. --shred overwrites
                                          case.sqlite with random bytes first.
    """)
}

// MARK: - Subcommand implementations

private func caseNew(mgr: CaseManager, args: [String]) async throws {
    guard let name = args.first, !name.hasPrefix("--") else {
        throw CaseCommandError.usage("Usage: maccrabctl case new <name> [--window <dur>] [--since <date>] [--notes \"<text>\"] [--no-encrypt]")
    }
    var window: MacCrabForensics.TimeWindow? = nil
    var notes: String? = nil
    var encrypted = true
    var i = 1
    while i < args.count {
        switch args[i] {
        case "--window" where i + 1 < args.count:
            if let duration = parseDuration(args[i+1]) {
                window = MacCrabForensics.TimeWindow.relative(duration)
            }
            i += 2
        case "--since" where i + 1 < args.count:
            if let date = parseISODate(args[i+1]) {
                window = MacCrabForensics.TimeWindow.since(date)
            }
            i += 2
        case "--notes" where i + 1 < args.count:
            notes = args[i+1]
            i += 2
        case "--no-encrypt":
            encrypted = false
            i += 1
        default:
            i += 1
        }
    }

    if !encrypted {
        print("⚠️  Plaintext case requested.")
        print("    Plaintext cases cannot contain content, personalComms, credentialAdjacent, or secret")
        print("    artifacts (audit Pass 2026-D enforces at INSERT time). If you might later want to opt")
        print("    into content collection, create an encrypted case instead.")
    }

    let handle = try await mgr.createCase(
        name: name,
        timeWindow: window,
        notes: notes,
        encrypted: encrypted
    )
    print("Created case '\(name)'")
    print("  ID:         \(handle.caseID)")
    print("  Encryption: \(handle.encryptionState.rawValue)")
    print("  Directory:  \(handle.layout.caseDirectory.path)")
}

private func caseList(mgr: CaseManager) async throws {
    let manifests = try await mgr.listCases()
    guard !manifests.isEmpty else {
        print("No cases yet. Create one with: maccrabctl case new <name>")
        return
    }
    let dateFmt = ISO8601DateFormatter()
    let widthID = manifests.map { $0.id.count }.max() ?? 36
    let widthName = max(manifests.map { $0.name.count }.max() ?? 16, "Name".count)
    print(rowAligned([
        ("ID", widthID), ("Name", widthName),
        ("Encryption", 20), ("Created", 25),
    ]))
    print(String(repeating: "-", count: widthID + widthName + 20 + 25 + 6))
    for m in manifests {
        print(rowAligned([
            (m.id, widthID),
            (m.name, widthName),
            (m.encryptionState.rawValue, 20),
            (dateFmt.string(from: m.createdAt), 25),
        ]))
    }
}

private func caseShow(mgr: CaseManager, args: [String]) async throws {
    guard let id = args.first else {
        throw CaseCommandError.usage("Usage: maccrabctl case show <case-id>")
    }
    let manifests = try await mgr.listCases()
    guard let m = manifests.first(where: { $0.id == id }) else {
        throw CaseCommandError.underlying("Case not found: \(id)")
    }
    // For more detail, open the case to fetch the in-store fields.
    do {
        let handle = try await mgr.openCase(id: id)
        if let row = try await handle.store.fetchCase(id: id) {
            print("Case:")
            print("  ID:                  \(row.id)")
            print("  Name:                \(row.name)")
            print("  Created:             \(ISO8601DateFormatter().string(from: row.createdAt))")
            print("  Encryption:          \(row.encryptionState.rawValue)")
            print("  AI content allowed:  \(row.aiContentAllowed ? "yes" : "no")")
            print("  Scheduled trusted:   \(row.scheduledTrusted ? "yes" : "no")")
            if let s = row.timeWindowStart {
                print("  Window start:        \(ISO8601DateFormatter().string(from: s))")
            }
            if let e = row.timeWindowEnd {
                print("  Window end:          \(ISO8601DateFormatter().string(from: e))")
            }
            if let n = row.notes {
                print("  Notes:               \(n)")
            }
        } else {
            // Manifest exists but cases row doesn't — show what
            // we have from the manifest.
            print("Case (manifest-only — open failed):")
            print("  ID:         \(m.id)")
            print("  Name:       \(m.name)")
            print("  Encryption: \(m.encryptionState.rawValue)")
        }
    } catch {
        // Open failed (e.g. plaintext case from a different DEKVault).
        // Surface manifest summary so operator can still see something.
        print("Case (manifest only):")
        print("  ID:         \(m.id)")
        print("  Name:       \(m.name)")
        print("  Encryption: \(m.encryptionState.rawValue)")
        print("  Open error: \(error)")
    }
}

private func caseArtifacts(mgr: CaseManager, args: [String]) async throws {
    guard let id = args.first else {
        throw CaseCommandError.usage("Usage: maccrabctl case artifacts <case-id> [--type <ct>] [--limit N]")
    }
    var contentType: String? = nil
    var limit = 50
    var i = 1
    while i < args.count {
        switch args[i] {
        case "--type" where i + 1 < args.count:
            contentType = args[i+1]; i += 2
        case "--limit" where i + 1 < args.count:
            limit = Int(args[i+1]) ?? 50; i += 2
        default:
            i += 1
        }
    }
    let handle = try await mgr.openCase(id: id)
    let q = ArtifactQuery(
        caseID: id,
        contentType: contentType,
        limit: limit
    )
    let rows = try await handle.store.query(q)
    guard !rows.isEmpty else {
        print("No artifacts in case \(id)\(contentType.map { " for content_type=\($0)" } ?? "").")
        return
    }
    let fmt = ISO8601DateFormatter()
    print("Artifacts (\(rows.count)):")
    for a in rows {
        print("  [\(a.id)] \(a.record.contentType) — \(a.record.summary ?? "(no summary)")")
        print("        observed=\(fmt.string(from: a.record.observedAt)) class=\(a.record.privacyClass.rawValue) sha256=\(String(a.record.sha256.prefix(12)))…")
    }
}

private func caseAllowAI(mgr: CaseManager, args: [String]) async throws {
    guard args.first == "--content", args.count >= 2 else {
        throw CaseCommandError.usage("Usage: maccrabctl case allow-ai --content <case-id>")
    }
    let id = args[1]
    let handle = try await mgr.openCase(id: id)
    try await handle.store.setAIContentAllowed(caseID: id, allowed: true)
    // Audit log: highest-privilege privacy transition. Recorded only after
    // the store write succeeds so a failed UPDATE never yields a false grant
    // record. Same os.log .notice/"AUDIT" sink the MCP suppress handlers use.
    caseAuditLogger.notice("CTL AUDIT: case_allow_ai — user=\(NSUserName(), privacy: .public) pid=\(getpid()) case=\(id, privacy: .public)")
    print("AI content access granted for case \(id).")
    print("This case's MCP tools may now expose non-metadata artifacts to AI agents.")
}

private func caseMarkTrustedScheduled(mgr: CaseManager, args: [String]) async throws {
    guard let id = args.first else {
        throw CaseCommandError.usage("Usage: maccrabctl case mark-trusted-scheduled <case-id>")
    }
    let handle = try await mgr.openCase(id: id)
    try await handle.store.setScheduledTrusted(caseID: id, trusted: true)
    print("Case \(id) is now marked trusted for scheduled runs.")
    print("Scheduled invocations on this case will auto-proceed after the visibility toast.")
}

private func caseDelete(mgr: CaseManager, args: [String]) async throws {
    var shred = false
    var id: String? = nil
    for a in args {
        if a == "--shred" { shred = true }
        else if !a.hasPrefix("--") { id = a }
    }
    guard let resolved = id else {
        throw CaseCommandError.usage("Usage: maccrabctl case delete [--shred] <case-id>")
    }
    try await mgr.deleteCase(id: resolved, shred: shred)
    print("Deleted case \(resolved)\(shred ? " (shredded)" : "").")
}

// MARK: - Helpers shared with PluginCommands

/// Construct a CaseManager pointing at the default cases root,
/// backed by KeychainDEKVault for production.
func makeCaseManager() -> CaseManager {
    CaseManager(
        casesRoot: CaseDirectoryLayout.defaultCasesRoot,
        dekVault: KeychainDEKVault()
    )
}

private func parseDuration(_ raw: String) -> TimeInterval? {
    // Accepts: "24h", "30m", "7d". No upper validation; operators
    // can ask for "9999h" if they want.
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

private func parseISODate(_ raw: String) -> Date? {
    let isoFull = ISO8601DateFormatter()
    if let d = isoFull.date(from: raw) { return d }
    // Fall back to YYYY-MM-DD.
    let f = DateFormatter()
    f.dateFormat = "yyyy-MM-dd"
    f.timeZone = TimeZone(secondsFromGMT: 0)
    return f.date(from: raw)
}

func rowAligned(_ cols: [(String, Int)]) -> String {
    cols.map { (text, width) in
        text.padding(toLength: max(text.count, width), withPad: " ", startingAt: 0)
    }.joined(separator: "  ")
}
