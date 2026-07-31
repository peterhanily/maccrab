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
        do {
            let store = try AlertStore(directory: maccrabDataDir())
            let since = Date().addingTimeInterval(-hours * 3600)
            let aiAlerts = try await store.aiAlerts(since: since, limit: clampedLimit)

            if aiAlerts.isEmpty {
                print("No AI safety alerts in the last \(Int(hours))h. AI tools are operating within safe boundaries.")
                return
            }

            print("\(aiAlerts.count) AI safety alert(s) — last \(Int(hours))h:")
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

        let result = await ClipboardInjectionDetector().scan(text)

        print("Prompt Injection Scan")
        print("═══════════════════════════════════")
        print("Safe:       \(result == nil)")
        print("Confidence: \(result?.confidence ?? 0)%")

        if let result {
            print("⚠️  INJECTION DETECTED")
            print("Severity:   \(String(describing: result.severity).uppercased())")
            print("Patterns:")
            for p in result.patterns.prefix(10) { print("  - \(LLMSanitizer.sanitize(p))") }
            // Non-zero exit so the scan is scriptable in a CI / pre-flight gate.
            exit(2)
        } else {
            print("✓ No injection patterns detected")
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
