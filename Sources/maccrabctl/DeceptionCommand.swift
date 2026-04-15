// DeceptionCommand.swift
// maccrabctl
//
// CLI for managing the deception tier (honeyfiles).
// Subcommands: deploy, status, remove.

import Foundation
import MacCrabCore

extension MacCrabCtl {

    static func runDeception(args: [String]) async {
        guard args.count >= 3 else {
            printDeceptionUsage()
            return
        }
        let sub = args[2]
        switch sub {
        case "deploy":  await deploymentCommand()
        case "status":  await statusCommand()
        case "remove":  await removeCommand()
        default:
            printDeceptionUsage()
        }
    }

    // MARK: - Subcommands

    private static func deploymentCommand() async {
        let mgr = HoneyfileManager()
        do {
            let written = try await mgr.deploy()
            print("✓ Deployed \(written.count) honeyfile\(written.count == 1 ? "" : "s")")
            for entry in written.sorted(by: { $0.type.rawValue < $1.type.rawValue }) {
                print("    \(entry.type.rawValue.padding(toLength: 22, withPad: " ", startingAt: 0))  \(shorten(entry.path))")
            }
            print("")
            print("Enable detection for daemon sessions: export MACCRAB_DECEPTION=1")
            print("Then restart the daemon so file event enrichment picks up the canaries.")
        } catch {
            print("✗ Deploy failed: \(error.localizedDescription)")
            exit(1)
        }
    }

    private static func statusCommand() async {
        let mgr = HoneyfileManager()
        // Wait briefly for manifest load in init's Task.
        try? await Task.sleep(nanoseconds: 50_000_000)

        let status = await mgr.status()
        if status.total == 0 {
            print("No honeyfiles deployed.")
            print("Run `maccrabctl deception deploy` to plant canaries.")
            return
        }

        print("MacCrab Deception Status")
        print("────────────────────────")
        print("Deployed:  \(status.deployed.count)")
        print("Missing:   \(status.missing.count)")
        print("Tampered:  \(status.tampered.count)")
        print("")

        if !status.deployed.isEmpty {
            print("Present (\(status.deployed.count)):")
            for entry in status.deployed.sorted(by: { $0.path < $1.path }) {
                print("  ✓ \(entry.type.rawValue.padding(toLength: 22, withPad: " ", startingAt: 0))  \(shorten(entry.path))")
            }
        }

        if !status.missing.isEmpty {
            print("")
            print("Missing (\(status.missing.count)) — file removed since deploy:")
            for entry in status.missing.sorted(by: { $0.path < $1.path }) {
                print("  ✗ \(entry.type.rawValue.padding(toLength: 22, withPad: " ", startingAt: 0))  \(shorten(entry.path))")
            }
        }

        if !status.tampered.isEmpty {
            print("")
            print("Tampered (\(status.tampered.count)) — content changed:")
            for entry in status.tampered.sorted(by: { $0.path < $1.path }) {
                print("  ! \(entry.type.rawValue.padding(toLength: 22, withPad: " ", startingAt: 0))  \(shorten(entry.path))")
            }
        }
    }

    private static func removeCommand() async {
        let mgr = HoneyfileManager()
        try? await Task.sleep(nanoseconds: 50_000_000)
        let removed = await mgr.remove()
        print("✓ Removed \(removed.count) honeyfile\(removed.count == 1 ? "" : "s")")
    }

    // MARK: - Helpers

    private static func shorten(_ path: String) -> String {
        let home = NSHomeDirectory()
        if path.hasPrefix(home) {
            return "~" + String(path.dropFirst(home.count))
        }
        return path
    }

    private static func printDeceptionUsage() {
        print("""
        Usage: maccrabctl deception <subcommand>

        Subcommands:
            deploy    Plant canary files at standard credential locations
            status    Show which honeyfiles are present / missing / tampered
            remove    Delete every MacCrab-deployed honeyfile

        After `deploy`, set MACCRAB_DECEPTION=1 in the daemon environment so the
        event enricher tags file-event reads of canary paths for detection.

        Honeyfiles are deployed into the running user's home directory:
            ~/.aws/credentials.bak, ~/.ssh/id_rsa.old, ~/.kube/config.backup,
            ~/.netrc.backup, ~/.docker/config.json.bak, etc.
        """)
    }
}
