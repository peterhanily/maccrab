// RuleChannelCommands.swift
// maccrabctl — the `rules` subcommand: the signed, app-decoupled rule-update
// channel. Lets the maintainer push detection rules without an app release.

import Foundation
import MacCrabForensics

private func resolveRulesBase(_ explicit: String?) -> String {
    explicit
        ?? ProcessInfo.processInfo.environment["MACCRAB_RULES_BASE_URL"]
        ?? "https://rave.maccrab.com/rules/"
}

func dispatchRules(args: [String]) async {
    let sub = args.first ?? "help"
    let rest = Array(args.dropFirst())
    do {
        switch sub {
        case "update":                 try await rulesUpdate(args: rest)
        case "check-updates", "check": try await rulesCheckUpdates(args: rest)
        case "status":                 try await rulesStatus()
        case "help", "-h", "--help":   printRulesUsage()
        default:
            print("Unknown rules subcommand: \(sub)")
            printRulesUsage()
            exit(1)
        }
    } catch {
        print("Error: \(error)")
        exit(1)
    }
}

func printRulesUsage() {
    print("""
    Usage: maccrabctl rules <subcommand>

    Update detection rules out-of-band from the signed rule-update channel — no
    app update, no reinstall. Pushed rules are DETECTION-ONLY: they can add new
    detections but never override a built-in rule or arm a response action.

    Subcommands:
      update [--rules-base <url>]      Fetch + verify + install the latest signed
                                       rules manifest into compiled_rules/pushed.
      check-updates [--json]           Report whether a newer rules corpus exists.
      status                           Show the installed pushed-rules state.

    Trust: the manifest is Ed25519-signed (separate rules.pub key), anti-rollback
    (monotonic serial), version-floored, and every rule is re-validated before
    install. A bad manifest leaves the prior pushed corpus intact (fail-closed).
    Default base: https://rave.maccrab.com/rules/  (or env MACCRAB_RULES_BASE_URL).
    """)
}

private func rulesUpdate(args: [String]) async throws {
    var base: String? = nil
    var i = 0
    while i < args.count {
        if args[i] == "--rules-base", i + 1 < args.count { base = args[i + 1]; i += 2 } else { i += 1 }
    }
    let fetcher: RuleChannelFetcher
    do { fetcher = try RuleChannelFetcher(rulesBase: resolveRulesBase(base)) }
    catch { print("rules update: \(error)"); exit(2) }

    let pushedDir = URL(fileURLWithPath: maccrabDataDir())
        .appendingPathComponent("compiled_rules").appendingPathComponent("pushed")
    do {
        let n = try await fetcher.update(into: pushedDir)
        print("✓ Installed \(n) pushed detection rule(s) → \(pushedDir.path)")
        print("  These load DETECTION-ONLY on the engine's next reload (SIGHUP / reload tick).")
    } catch let e as RuleChannelError {
        print("rules update refused: \(e)")
        exit(2)
    } catch {
        // The most common non-trust failure: the engine's compiled_rules dir is
        // root-owned (release System Extension), so a non-root CLI can't write it.
        print("rules update failed: \(error)")
        print("  (If this is a permissions error, the engine's compiled_rules dir is root-owned;")
        print("   run with sudo, or push the verified rules via the privileged daemon path.)")
        exit(2)
    }
}

private func rulesCheckUpdates(args: [String]) async throws {
    let json = args.contains("--json")
    var base: String? = nil
    var i = 0
    while i < args.count {
        if args[i] == "--rules-base", i + 1 < args.count { base = args[i + 1]; i += 2 } else { i += 1 }
    }
    let fetcher = try RuleChannelFetcher(rulesBase: resolveRulesBase(base))
    let s: RuleChannelFetcher.UpdateStatus
    do { s = try await fetcher.check() }
    catch { print("rules check-updates: could not fetch or verify the rules manifest: \(error)"); exit(2) }

    if json {
        let payload: [String: Any] = [
            "installed_serial": s.installedSerial as Any? ?? NSNull(),
            "available_serial": s.availableSerial,
            "corpus_version": s.corpusVersion,
            "rule_count": s.ruleCount,
            "update_available": s.updateAvailable,
        ]
        let data = try JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted, .sortedKeys])
        print(String(data: data, encoding: .utf8) ?? "{}")
        return
    }
    if s.updateAvailable {
        print("Update available: rules corpus \(s.corpusVersion) (serial \(s.availableSerial), \(s.ruleCount) rules).")
        print("  Installed serial: \(s.installedSerial.map(String.init) ?? "none"). Install with: maccrabctl rules update")
    } else {
        print("Up to date: rules corpus \(s.corpusVersion) (serial \(s.availableSerial)).")
    }
}

private func rulesStatus() async throws {
    let store = RaveTrustStateStore.default(supportDir: maccrabUserWritableDataDir())
    let serial = store.load().rulesManifestSerial
    let pushedDir = URL(fileURLWithPath: maccrabDataDir())
        .appendingPathComponent("compiled_rules").appendingPathComponent("pushed")
    let installed = (try? FileManager.default.contentsOfDirectory(atPath: pushedDir.path))?
        .filter { $0.hasSuffix(".json") }.count ?? 0
    print("Pushed rules:")
    print("  Accepted manifest serial: \(serial.map(String.init) ?? "none")")
    print("  Installed pushed rules:   \(installed) (at \(pushedDir.path))")
    print("  Pushed rules are detection-only — they never arm a response action.")
}
