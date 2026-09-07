// RuleChannelCommands.swift
// maccrabctl — the `rules` subcommand: the signed, app-decoupled rule-update
// channel. Lets the maintainer push detection rules without an app release.

import Foundation
import MacCrabForensics
import MacCrabCore

private func resolveRulesBase(_ explicit: String?) -> String {
    explicit
        ?? Foundation.ProcessInfo.processInfo.environment["MACCRAB_RULES_BASE_URL"]
        ?? "https://rave.maccrab.com/rules/"
}

func dispatchRules(args: [String]) async {
    let sub = args.first ?? "help"
    let rest = Array(args.dropFirst())
    do {
        switch sub {
        case "reload":
            guard rest.isEmpty || rest == ["--json"] else {
                throw RuntimeConfigContractError("Usage: maccrabctl rules reload [--json]")
            }
            let id = try RuntimeConfigurationFiles.submit(operation: "reload-rules", payload: [:], directory: maccrabDataDir())
            if rest.contains("--json") {
                try printCLIJSONObject(["schema_version": 1, "state": "pending", "operation": "reload-rules", "request_id": id.uuidString])
            } else {
                print("Submitted reload request \(id.uuidString). Check: maccrabctl config status \(id.uuidString)")
            }
        case "update":                 try await rulesUpdate(args: rest)
        case "check-updates", "check": try await rulesCheckUpdates(args: rest)
        case "status":                 try await rulesStatus()
        case "help", "-h", "--help":   printRulesUsage()
        default:
            cliFailure("Unknown rules subcommand: \(sub)")
        }
    } catch {
        cliFailure("rules \(sub): \(error.localizedDescription)")
    }
}

func printRulesUsage() {
    print("""
    Usage: maccrabctl rules <subcommand>

    The out-of-band signed rule-update channel is DISABLED in this release
    pending owner-approved offline key rotation and custody proof. `update` and
    `check-updates` refuse before key lookup or any network request. Existing
    files under compiled_rules/pushed are preserved but ignored by the engine.

    Subcommands:
      update [--rules-base <url>]      Fetch + verify + install the latest signed
                                       rules manifest into compiled_rules/pushed.
      check-updates [--json]           Report whether a newer rules corpus exists.
      status                           Show the installed pushed-rules state.
      reload [--json]                   Submit a reload request and return its status ID.
      list [--json]                     List the compiled corpus with current coverage provenance.
      count [--json]                    Count the readable compiled single-event corpus.

    The dormant parser retains Ed25519 verification, anti-rollback, version-floor,
    byte/count limits, and atomic staging defenses for a future approved channel.
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
    catch { cliFailure("rules update: \(error)", code: 2) }

    let pushedDir = URL(fileURLWithPath: maccrabDataDir())
        .appendingPathComponent("compiled_rules").appendingPathComponent("pushed")
    do {
        switch try await fetcher.update(into: pushedDir) {
        case .installed(let serial, let ruleCount):
            print("✓ Installed \(ruleCount) pushed detection rule(s) from serial \(serial) → \(pushedDir.path)")
            print("  These load DETECTION-ONLY on the engine's next reload (SIGHUP / reload tick).")
        case .unchanged(let serial):
            print("✓ Rules serial \(serial) is already installed; no files or trust state changed.")
        }
    } catch let e as RuleChannelError {
        cliFailure("rules update refused: \(e)", code: 2)
    } catch {
        // The most common non-trust failure: the engine's compiled_rules dir is
        // root-owned (release System Extension), so a non-root CLI can't write it.
        cliFailure("rules update failed: \(error.localizedDescription)", code: 2)
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
    catch { cliFailure("rules check-updates: \(error.localizedDescription)", code: 2) }

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
    let installed = FileManager.default.fileExists(atPath: pushedDir.path)
        ? try FileManager.default.contentsOfDirectory(atPath: pushedDir.path).filter { $0.hasSuffix(".json") }.count : 0
    print("Pushed rules:")
    print("  Accepted manifest serial: \(serial.map(String.init) ?? "none")")
    print("  Preserved on-disk rules:   \(installed) (at \(pushedDir.path))")
    print("  Active pushed rules:       0 (rule-update channel disabled; on-disk corpus ignored)")
}
