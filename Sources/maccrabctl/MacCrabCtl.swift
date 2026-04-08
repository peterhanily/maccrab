import Foundation
import MacCrabCore

@main
struct MacCrabCtl {
    static func main() async {
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
                let limit = args.count >= 4 ? Int(args[3]) ?? 20 : 20
                await tailEvents(limit: limit)
            } else if args.count >= 3 && args[2] == "search" && args.count >= 4 {
                let query = args[3...].joined(separator: " ")
                await searchEvents(query: query)
            } else if args.count >= 3 && args[2] == "stats" {
                await eventStats()
            } else {
                print("Usage: maccrabctl events [tail [N]|search <query>|stats]")
            }
        case "alerts":
            let limit = args.count >= 3 ? Int(args[2]) ?? 20 : 20
            await listAlerts(limit: limit)
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
            } else {
                print("Usage: maccrabctl rule create [category]")
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
}
