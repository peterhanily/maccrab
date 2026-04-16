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
                    return
                }
                idx += 2
            case "--reason" where idx + 1 < args.count:
                reason = args[idx + 1]; idx += 2
            default:
                print("✗ Unknown flag: \(args[idx])")
                printAllowUsage()
                return
            }
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
            return
        }

        if reason.isEmpty {
            print("✗ --reason is required (so analysts know why this allow exists)")
            return
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

        let mgr = SuppressionManager(dataDir: maccrabDataDir())
        await mgr.load()
        var entries = await mgr.list(includeExpired: includeExpired)
        if let kind = scopeFilter {
            entries = entries.filter { $0.scope.kind == kind }
        }

        if entries.isEmpty {
            print("No suppressions\(includeExpired ? "" : " (active)") found.")
            return
        }

        print("MacCrab Allowlist (\(entries.count) \(includeExpired ? "total" : "active"))")
        print("────────────────────────────────────────────────")

        let now = Date()
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
            print("Usage: maccrabctl allow remove <id>")
            return
        }
        let id = args[3]

        let mgr = SuppressionManager(dataDir: maccrabDataDir())
        await mgr.load()

        // Allow partial-id match (first 8 chars) for operator convenience.
        let all = await mgr.list(includeExpired: true)
        let candidates = all.filter { $0.id.hasPrefix(id) }
        switch candidates.count {
        case 0:
            print("✗ No suppression matching '\(id)'")
        case 1:
            let match = candidates[0]
            _ = await mgr.remove(id: match.id)
            print("✓ Removed \(match.id) — \(match.scope.summary)")
        default:
            print("✗ '\(id)' is ambiguous (\(candidates.count) matches). Use a longer prefix.")
            for c in candidates {
                print("    \(c.id)  \(c.scope.summary)")
            }
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
