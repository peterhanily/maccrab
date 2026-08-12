import Foundation
import MacCrabCore

// PARITY-03 — headless parity for the MCP `get_ai_alerts` and `scan_text`
// tools. These mirror the exact API calls in Sources/maccrab-mcp/main.swift
// (handleGetAIAlerts / handleScanText) so a CLI-only operator gets the same
// AI-Guard alert view and prompt-injection scan, including the LLMSanitizer
// pass over Forensicate reason strings (paths / credential shapes / private
// IPs must never round-trip back out).

extension MacCrabCtl {
    /// Mirror of MCP `get_ai_alerts`: AI-Guard alert stream (credential fence,
    /// boundary, injection, MCP) via `AlertStore.aiAlerts(since:limit:)`.
    static func listAIAlerts(hours: Double, limit: Int) async {
        // Clamp to the same bounds the MCP handler enforces.
        let clampedLimit = min(max(limit, 1), 100)
        guard hours.isFinite, hours > 0 else {
            print("Error: hours must be a positive finite number"); exit(1)
        }
        let boundedHours = min(hours, 8_760)
        do {
            let store = try openAlertStoreForReading(directory: maccrabDataDir())
            let since = Date().addingTimeInterval(-boundedHours * 3600)
            let aiAlerts = try await store.aiAlerts(since: since, limit: clampedLimit)

            if aiAlerts.isEmpty {
                print("No matching persisted AI Guard alerts were found in the accessible alert store for the last \(Int(boundedHours))h. This bounded absence is not proof that AI activity was safe or fully observed.")
                return
            }

            print("\(aiAlerts.count) AI safety alert(s) — last \(Int(boundedHours))h:")
            for alert in aiAlerts {
                print()
                print("\(alert.severity.coloredLabel) \(alert.ruleTitle)")
                print("   Time:    \(formatDate(alert.timestamp))")
                print("   ID:      \(alert.id)")
                if let proc = alert.processName { print("   Process: \(proc)") }
                if let desc = alert.description { print("   Detail:  \(desc)") }
            }
        } catch {
            print("Error reading AI alerts: \(error)"); exit(1)
        }
    }

    /// Mirror of MCP `scan_text`: prompt-injection scan.
    ///
    /// v1.21.6: backed by the native `ClipboardInjectionDetector` (24 weighted
    /// patterns across instruction-override, jailbreak, prompt-extraction,
    /// role-manipulation, tool-poisoning, structural-injection and exfiltration,
    /// plus an invisible-unicode check) instead of shelling out to a `forensicate`
    /// CLI. That CLI was never installable — the advertised `pip install
    /// forensicate-ai` 404s on PyPI — so this command could only ever print an
    /// install hint. It now actually scans. Pattern strings are still routed
    /// through `LLMSanitizer.sanitize` in case one echoes scanned input.
    static func scanText(_ text: String) async {
        guard !text.isEmpty else {
            usageError("Usage: maccrabctl scan-text <text>   (or pipe text on stdin)")
        }
        guard text.count <= 10_000 else {
            print("Error: text too long (max 10000 characters)"); exit(1)
        }
        guard text.count >= 10 else {
            print("Prompt-injection marker scan (bounded heuristic)")
            print("═══════════════════════════════════")
            print("Known literal marker match: not evaluated")
            print("Heuristic score: not produced")
            print("Input is shorter than the scanner's 10-character minimum. No safety verdict was made.")
            return
        }

        let result = await ClipboardInjectionDetector().scan(text)

        print("Prompt-injection marker scan (bounded heuristic)")
        print("═══════════════════════════════════")
        print("Known literal marker match: \(result == nil ? "no" : "yes")")
        print("Heuristic score (uncalibrated): \(result?.confidence ?? 0)/100")

        if let result {
            print("⚠️  POTENTIAL PROMPT-INJECTION MARKER MATCH")
            print("Heuristic severity band: \(String(describing: result.severity).uppercased())")
            print("Patterns:")
            for p in result.patterns.prefix(10) { print("  - \(LLMSanitizer.sanitize(p))") }
            // Non-zero exit so the scan is scriptable in a CI / pre-flight gate.
            exit(2)
        } else {
            print("No known literal marker found within the scanner's stated coverage. This is not proof the text is safe.")
        }
    }

    /// Read the scan-text payload: positional args joined, else stdin.
    static func scanTextPayload(from args: [String]) -> String {
        if args.count >= 3 {
            return args[2...].joined(separator: " ")
        }
        // No positional arg — read all of stdin (supports `echo ... | maccrabctl scan-text`).
        let data = FileHandle.standardInput.readDataToEndOfFile()
        return String(data: data, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    }
}
