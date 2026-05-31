import Foundation
import MacCrabCore

@main
struct MacCrabCtl {
    static func main() async {
        // Ignore SIGPIPE — we read + write pipes for Tier B
        // subprocess plugins, and a hostile (or buggy) subprocess
        // can close its end mid-conversation. Default SIGPIPE
        // handler terminates the process with exit code 141; we
        // want graceful EPIPE handling via try? instead.
        signal(SIGPIPE, SIG_IGN)
        let args = CommandLine.arguments

        guard args.count >= 2 else {
            printUsage()
            exit(0)
        }

        let command = args[1]

        switch command {
        case "status":
            await showStatus()
        case "rules":
            if args.count >= 3 && args[2] == "list" {
                await listRules()
            } else if args.count >= 3 && args[2] == "count" {
                await countRules()
            } else {
                print("Usage: maccrabctl rules [list|count]")
            }
        case "events":
            if args.count >= 3 && args[2] == "tail" {
                var limit = 20
                var hours: Double? = nil
                var category: EventCategory? = nil
                var idx = 3
                while idx < args.count {
                    switch args[idx] {
                    case "--hours" where idx + 1 < args.count:
                        hours = Double(args[idx + 1]); idx += 2
                    case "--category" where idx + 1 < args.count:
                        category = EventCategory(rawValue: args[idx + 1]); idx += 2
                    default:
                        if let n = Int(args[idx]) { limit = n }
                        idx += 1
                    }
                }
                await tailEvents(limit: limit, hours: hours, category: category)
            } else if args.count >= 3 && args[2] == "search" && args.count >= 4 {
                let query = args[3...].joined(separator: " ")
                await searchEvents(query: query)
            } else if args.count >= 3 && args[2] == "stats" {
                await eventStats()
            } else {
                print("Usage: maccrabctl events [tail [N]|search <query>|stats]")
            }
        case "alerts":
            var limit = 20
            var hours: Double? = nil
            var severityFilter: Severity? = nil
            var idx = 2
            while idx < args.count {
                switch args[idx] {
                case "--hours" where idx + 1 < args.count:
                    hours = Double(args[idx + 1]); idx += 2
                case "--severity" where idx + 1 < args.count:
                    severityFilter = Severity(rawValue: args[idx + 1].lowercased()); idx += 2
                default:
                    if let n = Int(args[idx]) { limit = n }
                    idx += 1
                }
            }
            await listAlerts(limit: limit, hours: hours, severityFilter: severityFilter)
        case "compile":
            if args.count >= 4 {
                compileRules(inputDir: args[2], outputDir: args[3])
            } else {
                print("Usage: maccrabctl compile <input-rules-dir> <output-compiled-dir>")
            }
        case "export":
            let format = args.count >= 3 ? args[2] : "json"
            let limit = args.count >= 4 ? Int(args[3]) ?? 1000 : 1000
            await exportAlerts(format: format, limit: limit)
        case "rule":
            if args.count >= 3 && args[2] == "create" {
                let category = args.count >= 4 ? args[3] : "process_creation"
                createRuleTemplate(category: category)
            } else if args.count >= 4 && (args[2] == "enable" || args[2] == "disable") {
                // Persist the enable/disable state on disk so the change
                // survives SIGHUP rule reload and sysext restarts. The
                // RuleEngine respects this on load.
                setRuleEnabled(ruleId: args[3], enabled: args[2] == "enable")
            } else {
                print("Usage:")
                print("  maccrabctl rule create [category]   # Scaffold a new rule YAML")
                print("  maccrabctl rule enable <id>         # Re-enable a rule that was disabled")
                print("  maccrabctl rule disable <id>        # Disable a noisy rule without deleting the YAML")
                print("  Categories: process_creation, file_event, network_connection, tcc_event")
            }
        case "suppress":
            if args.count >= 4 {
                await suppressRule(ruleId: args[2], processPath: args[3])
            } else {
                print("Usage: maccrabctl suppress <rule-id> <process-path>")
                print("  Adds a process to the allowlist for a specific rule.")
            }
        case "unsuppress":
            if args.count >= 3 {
                let processPath = args.count >= 4 ? args[3] : nil
                await unsuppressRule(ruleId: args[2], processPath: processPath)
            } else {
                print("Usage: maccrabctl unsuppress <rule-id> [<process-path>]")
                print("  Removes a specific process path, or all suppressions for the rule.")
            }
        case "suppression":
            if args.count >= 3 && args[2] == "list" {
                listSuppressions()
            } else {
                print("Usage: maccrabctl suppression list")
            }
        case "campaigns":
            if args.count >= 3 && args[2] == "watch" {
                await watchCampaigns()
            } else {
                let limit = args.count >= 3 ? Int(args[2]) ?? 10 : 10
                await listCampaigns(limit: limit)
            }
        case "watch":
            await watchAlerts()
        case "hunt":
            if args.count >= 3 {
                let query = args[2...].joined(separator: " ")
                await huntThreats(query: query)
            } else {
                print("Usage: maccrabctl hunt <natural language query>")
                print("Examples:")
                print("  maccrabctl hunt \"show critical alerts from last hour\"")
                print("  maccrabctl hunt \"find unsigned processes with network connections\"")
            }
        case "report":
            await generateReport(args: Array(args.dropFirst(2)))
        case "cdhash":
            if args.count >= 3 {
                if args[2] == "--all" {
                    await extractAllCDHashes()
                } else if let pid = Int32(args[2]) {
                    await extractCDHash(pid: pid)
                } else {
                    print("Usage: maccrabctl cdhash <PID> | --all")
                }
            } else {
                print("Usage: maccrabctl cdhash <PID> | --all")
            }
        case "tree-score":
            let limit = args.count >= 3 ? Int(args[2]) ?? 10 : 10
            await showTreeScore(limit: limit)
        case "mcp":
            if args.count >= 3 && args[2] == "list" {
                let suspiciousOnly = args.contains("--suspicious")
                listMCPServers(suspiciousOnly: suspiciousOnly)
            } else {
                print("Usage: maccrabctl mcp list [--suspicious]")
            }
        case "extensions":
            let suspiciousOnly = args.contains("--suspicious")
            listExtensions(suspiciousOnly: suspiciousOnly)
        case "vulns":
            var hours: Double? = nil
            var severityFilter: Severity? = nil
            var idx = 2
            while idx < args.count {
                switch args[idx] {
                case "--hours" where idx + 1 < args.count:
                    hours = Double(args[idx + 1]); idx += 2
                case "--severity" where idx + 1 < args.count:
                    severityFilter = Severity(rawValue: args[idx + 1].lowercased()); idx += 2
                default:
                    idx += 1
                }
            }
            await listVulns(hours: hours, severityFilter: severityFilter)
        case "privacy":
            let hours = args.count >= 4 && args[2] == "--hours" ? Double(args[3]) : nil
            await listPrivacyAlerts(hours: hours)
        case "security":
            await showSecurityScore()
        case "deception":
            await runDeception(args: args)
        case "allow":
            await runAllow(args: args)
        case "why":
            await runWhy(args: args)
        case "repair":
            await runRepair(args: args)
        case "rollup":
            // v1.8.0: force the tier-rollup-and-prune sweep immediately,
            // outside the daemon's 6h timer. Useful for ops + first-launch
            // verification against an oversized v1.7-era events.db.
            // Pass --hours N to roll up everything older than N hours
            // (default 24, matching the daemon).
            // Pass --db <path> to operate against an arbitrary events.db
            // file (testing against a copy without touching the live one).
            var hours: Double = 24
            var dbPathOverride: String? = nil
            if let h = args.firstIndex(of: "--hours"), h + 1 < args.count, let n = Double(args[h + 1]) {
                hours = n
            }
            if let d = args.firstIndex(of: "--db"), d + 1 < args.count {
                dbPathOverride = args[d + 1]
            }
            await runRollup(olderThanHours: hours, dbPathOverride: dbPathOverride)
        case "trace":
            await dispatchTrace(args: Array(args.dropFirst(2)))
        case "debug":
            await dispatchDebug(args: Array(args.dropFirst(2)))
        case "intel":
            // Threat-intel maintenance subcommands. Today's only verb
            // is `refresh`, which sends SIGHUP to the running daemon
            // (handled by SignalHandlers.swift) — that triggers an
            // immediate `ThreatIntelFeed.refreshNow` and a rule reload
            // as a side effect. Used by the dashboard's Refresh button.
            let sub = args.dropFirst(2).first ?? "refresh"
            switch sub {
            case "refresh":
                // v1.17 fix: drop a `refresh-intel` request into the root
                // daemon's inbox (the file-IPC channel the sysext already
                // polls every 5s) instead of `pkill -USR1`. A user-context
                // process cannot signal a uid-0 sysext — pkill -USR1
                // returned EPERM and refreshNow() never fired. The inbox
                // dir is mode 1777 and the daemon authorizes the request
                // by its file owner uid (console user / root).
                let inboxDir = maccrabDataDir() + "/inbox"
                let fm = FileManager.default
                if !fm.fileExists(atPath: inboxDir) {
                    try? fm.createDirectory(atPath: inboxDir, withIntermediateDirectories: true)
                }
                let path = inboxDir + "/refresh-intel-\(UUID().uuidString).json"
                let payload: [String: Any] = [
                    "queuedAt": ISO8601DateFormatter().string(from: Date()),
                    "source": "maccrabctl"
                ]
                let wrote = (try? JSONSerialization.data(withJSONObject: payload))
                    .map { (try? $0.write(to: URL(fileURLWithPath: path), options: .atomic)) != nil } ?? false
                if wrote {
                    print("Refresh queued. The engine will fetch URLhaus / MalwareBazaar / Feodo within ~10s.")
                } else {
                    // Could not write the inbox request (engine never run,
                    // or no permission). Fall back to the dev daemon
                    // SIGUSR1 path (same-uid, so no EPERM there).
                    let dev = Process()
                    dev.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
                    dev.arguments = ["-USR1", "-x", "maccrabd"]
                    dev.standardOutput = FileHandle.nullDevice
                    dev.standardError = FileHandle.nullDevice
                    try? dev.run()
                    dev.waitUntilExit()
                    if dev.terminationStatus == 0 {
                        print("Refresh requested (SIGUSR1) on dev daemon.")
                    } else {
                        print("Could not queue a refresh (the engine may not be running, or this shell can't write its inbox).")
                        print("Tip: open MacCrab.app → Intelligence → Threat Intel to confirm feed status, or trigger refresh from the dashboard's Refresh button.")
                    }
                }
            case "matches":
                // Recent IOC-feed matches. Part A records each match as
                // an Alert whose ruleId starts with `maccrab.threat-intel.`
                // — read them via the alert store (read-only; no signal).
                var hours: Double = 24
                let mArgs = Array(args.dropFirst(3))
                if let h = mArgs.firstIndex(of: "--hours"), h + 1 < mArgs.count, let n = Double(mArgs[h + 1]) {
                    hours = n
                }
                await listIntelMatches(hours: hours)
            case "status":
                listIntelStatus()
            case "help", "-h", "--help":
                print("usage: maccrabctl intel <subcommand>")
                print("  refresh              trigger an immediate feed fetch (SIGUSR1)")
                print("  matches [--hours N]  list recent IOC-feed matches (default 24h)")
                print("  status               feed freshness / last pull per feed")
            default:
                print("Unknown intel subcommand: \(sub)")
                print("usage: maccrabctl intel refresh | matches [--hours N] | status")
                exit(1)
            }
        case "case":
            // v1.13a-1 Mac Context Plugin Platform — case lifecycle.
            // v1.17 deprecation: 'case' renamed to 'scan'. Alias
            // continues to work through v1.18; removed v1.19.
            printScanAliasWarning("case")
            await dispatchCase(args: Array(args.dropFirst(2)))
        case "scan":
            // v1.17 — customer-shaped rename of 'case'. Per
            // docs/forensics-ia-redesign-plan.md §4.2.
            await dispatchScan(args: Array(args.dropFirst(2)))
        case "evidence":
            // v1.17 — operator-facing namespace for artifact
            // export + search. Per plan §4.2.
            await dispatchEvidence(args: Array(args.dropFirst(2)))
        case "plugin":
            // v1.13a-1 Mac Context Plugin Platform — plugin runtime.
            // v1.17 adds search/info/update/pin/verify/status.
            await dispatchPlugin(args: Array(args.dropFirst(2)))
        case "fingerprint":
            // v1.14-1 — MCFP v1 static fingerprint.
            await dispatchFingerprint(args: Array(args.dropFirst(2)))
        case "mcfp":
            // research/post-v15 — MCFP R2 corpus + diff + imposter
            // tooling.
            await dispatchMCFP(args: Array(args.dropFirst(2)))
        case "version":
            printVersion()
        case "help", "-h", "--help":
            printUsage()
        default:
            print("Unknown command: \(command)")
            printUsage()
            exit(1)
        }
    }

    // MARK: - trace dispatch (PR-9)

    static func dispatchTrace(args: [String]) async {
        guard let sub = args.first else {
            printTraceUsage()
            exit(0)
        }
        let rest = Array(args.dropFirst())
        switch sub {
        case "list":
            let limit = rest.first.flatMap { Int($0) } ?? 20
            await traceList(limit: limit)
        case "show":
            guard let id = rest.first else { print("Usage: maccrabctl trace show <trace-id>"); exit(1) }
            await traceShow(id: id)
        case "explain":
            guard let id = rest.first else { print("Usage: maccrabctl trace explain <trace-id>"); exit(1) }
            await traceExplain(id: id)
        case "graph":
            guard let id = rest.first else { print("Usage: maccrabctl trace graph <trace-id> [--json]"); exit(1) }
            let asJson = rest.contains("--json")
            await traceGraph(id: id, asJson: asJson)
        case "from-agent":
            guard let name = rest.first else { print("Usage: maccrabctl trace from-agent <name> [--window N]"); exit(1) }
            let window = parseWindowArg(rest) ?? 20
            await traceFromAgent(name: name, windowMinutes: window)
        case "from-process":
            guard let pidString = rest.first, let pid = Int32(pidString) else {
                print("Usage: maccrabctl trace from-process <pid> [--window N]"); exit(1)
            }
            let window = parseWindowArg(rest) ?? 20
            await traceFromProcess(pid: pid, windowMinutes: window)
        case "from-process-key":
            guard let key = rest.first else { print("Usage: maccrabctl trace from-process-key <process-key>"); exit(1) }
            await traceFromProcessKey(key)
        case "export":
            guard let id = rest.first else {
                print("Usage: maccrabctl trace export <trace-id> [--out <dir>] [--include-raw-paths] [--include-hostname]")
                exit(1)
            }
            let includeRawPaths = rest.contains("--include-raw-paths")
            let includeHostname = rest.contains("--include-hostname")
            var outURL: URL?
            if let outIdx = rest.firstIndex(of: "--out"), outIdx + 1 < rest.count {
                outURL = URL(fileURLWithPath: rest[outIdx + 1])
            }
            await traceExport(
                traceId: id,
                outputDir: outURL,
                includeRawPaths: includeRawPaths,
                includeHostname: includeHostname
            )
        case "validate":
            guard let path = rest.first else { print("Usage: maccrabctl trace validate <bundle>"); exit(1) }
            await traceValidate(bundlePath: path)
        case "inspect":
            guard let path = rest.first else { print("Usage: maccrabctl trace inspect <bundle>"); exit(1) }
            await traceInspect(bundlePath: path)
        case "verify":
            guard let path = rest.first else { print("Usage: maccrabctl trace verify <bundle> [--check-unified-log]"); exit(1) }
            let checkUnifiedLog = rest.contains("--check-unified-log")
            await traceVerify(bundlePath: path, checkUnifiedLog: checkUnifiedLog)
        case "replay":
            guard let path = rest.first else {
                print("Usage: maccrabctl trace replay <bundle> [--normalization <version>] [--compare-rules <a> <b>]"); exit(1)
            }
            var normVersion = "1"
            if let idx = rest.firstIndex(of: "--normalization"), idx + 1 < rest.count {
                normVersion = rest[idx + 1]
            }
            // v1.11.1 (audit backlog): --compare-rules <a> <b> runs
            // the replay twice (once with each ruleset identifier) and
            // diffs the resulting alert sets. The diff is meaningful
            // once a non-echo RulesetReplayer is wired (v1.11.x);
            // until then BundleEmbeddedRulesetReplayer is identity on
            // matched_rules so the alert diff is empty + only the
            // result_sha256 changes. Useful as the v1.11.x landing
            // hook so the CLI surface is stable.
            if let cmpIdx = rest.firstIndex(of: "--compare-rules"),
               cmpIdx + 2 < rest.count {
                let a = rest[cmpIdx + 1]
                let b = rest[cmpIdx + 2]
                await traceReplayCompare(bundlePath: path,
                                          rulesetA: a,
                                          rulesetB: b,
                                          expectedNormalizationVersion: normVersion)
            } else {
                await traceReplay(bundlePath: path, expectedNormalizationVersion: normVersion)
            }
        case "demo":
            let scenario = rest.first
            await traceDemo(scenario: scenario)
        case "replay-batch":
            guard let dir = rest.first else {
                print("Usage: maccrabctl trace replay-batch <dir> [--report <html-path>] [--normalization <version>]"); exit(1)
            }
            var normVersion = "1"
            var reportPath: String? = nil
            if let idx = rest.firstIndex(of: "--normalization"), idx + 1 < rest.count {
                normVersion = rest[idx + 1]
            }
            if let idx = rest.firstIndex(of: "--report"), idx + 1 < rest.count {
                reportPath = rest[idx + 1]
            }
            await traceReplayBatch(
                directoryPath: dir,
                reportPath: reportPath,
                expectedNormalizationVersion: normVersion
            )
        case "to-prov":
            guard let path = rest.first else { print("Usage: maccrabctl trace to-prov <bundle>"); exit(1) }
            await traceToProv(bundlePath: path)
        case "to-otel":
            guard let path = rest.first else { print("Usage: maccrabctl trace to-otel <bundle>"); exit(1) }
            await traceToOtel(bundlePath: path)
        case "help", "-h", "--help":
            printTraceUsage()
        default:
            print("Unknown trace subcommand: \(sub)")
            printTraceUsage()
            exit(1)
        }
    }

    static func dispatchDebug(args: [String]) async {
        guard let sub = args.first else {
            printDebugUsage()
            exit(0)
        }
        let rest = Array(args.dropFirst())
        switch sub {
        case "entity-merge":
            guard let pidString = rest.first, let pid = Int32(pidString) else {
                print("Usage: maccrabctl debug entity-merge <pid>"); exit(1)
            }
            await debugEntityMerge(pid: pid)
        case "trust-substrate":
            await debugTrustSubstrate()
        case "help", "-h", "--help":
            printDebugUsage()
        default:
            print("Unknown debug subcommand: \(sub)")
            printDebugUsage()
            exit(1)
        }
    }

    private static func parseWindowArg(_ args: [String]) -> Int? {
        guard let idx = args.firstIndex(of: "--window"), idx + 1 < args.count else { return nil }
        let raw = args[idx + 1]
        // Accept "20", "20m", "1h" — minutes is the canonical unit.
        if raw.hasSuffix("m"), let n = Int(raw.dropLast()) { return n }
        if raw.hasSuffix("h"), let n = Int(raw.dropLast()) { return n * 60 }
        return Int(raw)
    }

    static func printTraceUsage() {
        print("""
        maccrabctl trace - TraceGraph commands (v1.10.0)

        Investigation:
          trace list [N]                           List recent traces (default 20)
          trace show <trace-id>                    Show trace details + members
          trace explain <trace-id>                 Print structured explanation
          trace graph <trace-id> [--json]          Print entities + edges
          trace from-agent <name> [--window 20m]   Find traces involving an agent
          trace from-process <pid> [--window 20m]  Find traces involving a pid
          trace from-process-key <key>             Find traces involving a processKey
          trace demo [scenario]                    Materialize a synthetic demo trace into tracegraph.db
                                                   (no daemon required; scenario: fixture1 | persistence | list)

        Bundle pipeline (.maccrabtrace files):
          trace export <trace-id> [--out <dir>] [--include-raw-paths] [--include-hostname]
                                                   Export trace as a .maccrabtrace bundle
          trace validate <bundle>                  Structural conformance check (exits 0,1,5,7,9,10)
          trace inspect <bundle>                   Print manifest + stats
          trace verify <bundle> [--check-unified-log]
                                                   Tamper-evidence check (exits 0,2,3,4)
          trace replay <bundle> [--normalization <version>] [--compare-rules <a> <b>]
                                                   Deterministic replay (exits 0,1,6,11)
          trace replay-batch <dir> [--report <html>] [--normalization <version>]
                                                   Replay every bundle in a directory; emit HTML report.
          trace to-prov <bundle>                   Print prov/prov.jsonld
          trace to-otel <bundle>                   Print otel/spans.json

        Bundle exit codes are stable per §18.9 of the v1.10.0 spec.
        Bundles may be passed as either a directory or a .tar.gz / .maccrabtrace archive.
        """)
    }

    static func printDebugUsage() {
        print("""
        maccrabctl debug - TraceGraph debugging helpers

          debug entity-merge <pid>     Show process entities seen for a pid
          debug trust-substrate        Print TrustSubstrate mode + public key
        """)
    }
}
