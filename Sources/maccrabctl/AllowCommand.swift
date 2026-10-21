// AllowCommand.swift
// maccrabctl
//
// CLI for the Allowlist v2 surface — TTL, scope, audit trail.
// Subcommands: add, list, remove.

import Foundation
import MacCrabCore

extension MacCrabCtl {

    static func runAllow(args: [String]) async {
        guard args.count >= 3 else {
            printAllowUsage()
            return
        }
        let sub = args[2]
        switch sub {
        case "add":    await allowAdd(args: args)
        case "list":   await allowList(args: args)
        case "remove": await allowRemove(args: args)
        case "stats":  await allowStats()
        default:       printAllowUsage()
        }
    }

    // MARK: - Subcommands

    private static func allowAdd(args: [String]) async {
        // Parse flags from args[3...]
        var rule: String?
        var path: String?
        var hash: String?
        var host: String?
        var ttlSec: TimeInterval?
        var reason: String = ""
        var idx = 3
        while idx < args.count {
            switch args[idx] {
            case "--rule" where idx + 1 < args.count:
                rule = args[idx + 1]; idx += 2
            case "--path" where idx + 1 < args.count:
                path = args[idx + 1]; idx += 2
            case "--hash" where idx + 1 < args.count:
                hash = args[idx + 1]; idx += 2
            case "--host" where idx + 1 < args.count:
                host = args[idx + 1]; idx += 2
            case "--ttl" where idx + 1 < args.count:
                if let s = parseTTL(args[idx + 1]) {
                    ttlSec = s
                } else {
                    print("✗ Invalid --ttl value '\(args[idx + 1])' (use e.g. 7d, 24h, 30m)")
                    exit(1)
                }
                idx += 2
            case "--reason" where idx + 1 < args.count:
                reason = args[idx + 1]; idx += 2
            default:
                print("✗ Unknown flag: \(args[idx])")
                printAllowUsage()
                exit(1)
            }
        }

        if let digest = hash {
            guard let normalized = normalizedSHA256(digest) else {
                print("✗ --hash must be a 64-character SHA-256 hex digest")
                exit(1)
            }
            guard rule != nil else {
                print("✗ --hash needs --rule: a hash entry suppresses one rule for one binary")
                exit(1)
            }
            hash = normalized
        }

        // Determine scope from which flags were provided.
        let scope: SuppressionScope
        if let r = rule, let p = path {
            scope = .rulePath(ruleId: r, path: p)
        } else if let r = rule, let h = hash {
            scope = .ruleHash(ruleId: r, sha256: h)
        } else if let r = rule {
            scope = .rule(r)
        } else if let p = path {
            scope = .path(p)
        } else if let h = host {
            scope = .host(h)
        } else {
            print("✗ Must provide at least one of: --rule, --path, --host")
            printAllowUsage()
            exit(1)
        }

        if reason.isEmpty {
            print("✗ --reason is required (so analysts know why this allow exists)")
            exit(1)
        }

        let expiresAt = ttlSec.map { Date(timeIntervalSinceNow: $0) }
        let suppression = Suppression(
            expiresAt: expiresAt,
            scope: scope,
            source: .cli,
            reason: reason
        )

        let mgr = SuppressionManager(dataDir: maccrabDataDir())
        await mgr.load()
        _ = await mgr.add(suppression)

        // The store lives under root-owned /Library on a release install, so a
        // uid-501 write fails. It used to fail SILENTLY — this printed success
        // while nothing persisted, so an operator believed their false positives
        // were allowlisted and the engine never saw an entry.
        if let err = await mgr.lastPersistError {
            let path = await mgr.storePath
            FileHandle.standardError.write(Data("""
            ✘ Suppression NOT saved — the allowlist could not be written.
                path:   \(path)
                reason: \(err)
                The suppression store is root-owned on a release install. Re-run with
                sudo, or add the allowlist entry from the dashboard, which routes the
                change through the privileged daemon.

            """.utf8))
            exit(1)
        }

        print("✓ Added suppression \(suppression.id)")
        print("    scope:   \(scope.summary)")
        print("    reason:  \(reason)")
        if let e = expiresAt {
            print("    expires: \(e.formatted(date: .abbreviated, time: .shortened))")
        } else {
            print("    expires: never")
        }
    }

    private static func allowList(args: [String]) async {
        let includeExpired = args.contains("--expired")
        var scopeFilter: String?
        var idx = 3
        while idx < args.count {
            if args[idx] == "--scope", idx + 1 < args.count {
                scopeFilter = args[idx + 1]
                idx += 2
            } else {
                idx += 1
            }
        }

        let now = Date()
        var entries: [Suppression]
        var fromSnapshot = false
        switch await readAllowlist(dataDir: maccrabDataDir()) {
        case let .entries(all, snapshot):
            entries = includeExpired ? all : all.filter { !$0.isExpired(at: now) }
            fromSnapshot = snapshot
        case let .unreadable(path, reason):
            failUnreadableAllowlist(path: path, reason: reason)
        }
        if let kind = scopeFilter {
            entries = entries.filter { $0.scope.kind == kind }
        }

        if entries.isEmpty {
            print("No suppressions\(includeExpired ? "" : " (active)") found\(fromSnapshot ? " in the engine's published snapshot" : "").")
            return
        }

        print("MacCrab Allowlist (\(entries.count) \(includeExpired ? "total" : "active"))")
        if fromSnapshot { print("From the engine's published snapshot; the store itself needs sudo.") }
        print("────────────────────────────────────────────────")

        let sorted = entries.sorted { $0.createdAt < $1.createdAt }
        for e in sorted {
            let expStr: String
            if let ex = e.expiresAt {
                if e.isExpired(at: now) {
                    expStr = "EXPIRED \(ex.formatted(date: .abbreviated, time: .shortened))"
                } else {
                    expStr = "expires \(ex.formatted(date: .abbreviated, time: .shortened))"
                }
            } else {
                expStr = "permanent"
            }
            print("  \(e.id.prefix(8))  \(e.scope.kind.padding(toLength: 10, withPad: " ", startingAt: 0))  \(expStr)")
            print("              \(e.scope.summary)")
            print("              reason: \(e.reason)  source: \(e.source.rawValue)")
        }
    }

    private static func allowRemove(args: [String]) async {
        guard args.count >= 4 else {
            cliFailure("Usage: maccrabctl allow remove <id>")
        }
        let id = args[3]
        let dataDir = maccrabDataDir()

        // Allow partial-id match (first 8 chars) for operator convenience.
        let all: [Suppression]
        switch await readAllowlist(dataDir: dataDir) {
        case let .entries(entries, _): all = entries
        case let .unreadable(path, reason): failUnreadableAllowlist(path: path, reason: reason)
        }
        let candidates = all.filter { $0.id.hasPrefix(id) }
        switch candidates.count {
        case 0:
            cliFailure("allow remove: no suppression matching '\(id)'")
        case 1:
            let match = candidates[0]
            // The engine holds the allowlist in memory and rewrites the file
            // from it, so a removal saved to the file alone came back at its
            // next save. Ask the engine, as the dashboard does: it updates both.
            let request: UUID
            do {
                request = try submitAllowRemoval(id: match.id, dataDir: dataDir,
                                                 inboxDirectory: requestInboxDirectory(dataDir: dataDir))
            } catch { cliFailure("allow remove: \(error.localizedDescription)") }
            let receipt = await awaitTerminalReceipt(directory: dataDir, requestID: request, timeout: 15)
            switch receipt?.state {
            case .applied?:
                print("Removed \(match.id) — \(match.scope.summary).")
            case .rejected?, .superseded?:
                cliFailure("allow remove: the engine did not remove \(match.id): \(receipt?.reason ?? "")")
            default:
                print("Removal of \(match.id) is queued as request \(request.uuidString), but the engine "
                      + "has not confirmed it yet (is it running?). It applies when the engine reads its inbox. "
                      + "Check: maccrabctl config status \(request.uuidString)")
            }
        default:
            cliFailure("allow remove: '\(id)' is ambiguous (\(candidates.count) matches). Use a longer prefix.")
        }
    }

    private static func allowStats() async {
        let mgr = SuppressionManager(dataDir: maccrabDataDir())
        await mgr.load()
        let s = await mgr.stats()
        print("MacCrab Allowlist Stats")
        print("────────────────────────")
        print("Total entries:   \(s.totalEntries)")
        print("Active:          \(s.totalEntries - s.expired)")
        print("Expired:         \(s.expired)")
        print("Rule-path rules: \(s.ruleCount)")
        print("Total paths:     \(s.pathCount)")
    }

    // MARK: - Helpers

    /// What `allow list` and `allow remove` read.
    enum AllowlistRead {
        case entries([Suppression], fromSnapshot: Bool)
        case unreadable(path: String, reason: String)
    }

    /// The engine's store when this user can read it, else the snapshot the
    /// engine publishes for admins after every change. The store is root-only
    /// on a release install, and a refused read used to print "No
    /// suppressions" while entries were in force.
    static func readAllowlist(dataDir: String) async -> AllowlistRead {
        let manager = SuppressionManager(dataDir: dataDir)
        await manager.load()
        guard let failure = await manager.lastLoadError else {
            return .entries(await manager.list(includeExpired: true), fromSnapshot: false)
        }
        if let snapshot = try? SuppressionFile.read(at: dataDir + "/suppressions_snapshot.json") {
            return .entries(snapshot.entries, fromSnapshot: true)
        }
        return .unreadable(path: manager.storePath, reason: failure)
    }

    private static func failUnreadableAllowlist(path: String, reason: String) -> Never {
        cliFailure("✘ The allowlist could not be read, so it is not shown as empty.\n"
                   + "    path:   \(path)\n"
                   + "    reason: \(reason)\n"
                   + "    The store is root-only on a release install. Re-run with sudo, or use the\n"
                   + "    dashboard's Suppressions list.")
    }

    /// Queue the engine's removal request for one exact suppression id.
    static func submitAllowRemoval(id: String, dataDir: String, inboxDirectory: String) throws -> UUID {
        try RuntimeConfigurationFiles.submit(operation: "remove-suppression", payload: ["id": id],
                                             directory: dataDir, inboxDirectory: inboxDirectory)
    }

    /// The request's receipt once it is applied, rejected or superseded, or
    /// its last state when `timeout` passes first (nil if none was written).
    private static func awaitTerminalReceipt(directory: String, requestID: UUID,
                                             timeout: TimeInterval) async -> RuntimeRequestReceipt? {
        let deadline = Date().addingTimeInterval(timeout)
        var latest: RuntimeRequestReceipt?
        while true {
            latest = (try? RuntimeConfigurationFiles.readReceipt(directory: directory, requestID: requestID)) ?? latest
            if let state = latest?.state, state != .accepted { return latest }
            guard Date() < deadline else { return latest }
            try? await Task.sleep(nanoseconds: 250_000_000)
        }
    }

    /// A SHA-256 digest in FileHasher's lowercase hex, or nil.
    static func normalizedSHA256(_ value: String) -> String? {
        guard value.count == 64, value.allSatisfy(\.isHexDigit) else { return nil }
        return value.lowercased()
    }

    /// Parse a TTL string like `7d`, `24h`, `30m`, `90s`, `2w`.
    private static func parseTTL(_ s: String) -> TimeInterval? {
        guard s.count >= 2 else { return nil }
        let body = String(s.dropLast())
        guard let n = Double(body) else { return nil }
        switch s.last {
        case "s": return n
        case "m": return n * 60
        case "h": return n * 3600
        case "d": return n * 86400
        case "w": return n * 86400 * 7
        default: return nil
        }
    }

    private static func printAllowUsage() {
        print("""
        Usage: maccrabctl allow <subcommand>

        Subcommands:
            add     Add a new allowlist entry
            list    List active (or all) entries
            remove  Remove an entry by id (prefix match OK)
            stats   Print summary counters

        Add flags:
            --rule <id>        Suppress this rule (+--path or +--hash narrows)
            --path <p>         Suppress all alerts from process path
            --host <h>         Suppress alerts from a hostname
            --hash <sha256>    Combined with --rule, matches by process SHA-256
            --ttl <DUR>        Expire after e.g. 7d / 24h / 30m / 2w
                               (optional — omit for permanent)
            --reason "<text>"  Required — why this allow exists

        Examples:
            maccrabctl allow add --rule maccrab.foo --path /usr/local/bin/bar \\
                --ttl 7d --reason "vendor update rollout"
            maccrabctl allow add --host build-agent-42 --ttl 30d \\
                --reason "CI host — high alert volume expected"
            maccrabctl allow list
            maccrabctl allow list --expired --scope path
            maccrabctl allow remove 3a4b
        """)
    }
}
