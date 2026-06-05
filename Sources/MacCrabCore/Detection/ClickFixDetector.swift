// ClickFixDetector.swift
// v1.18 — ClickFix detection: correlate a clipboard payload that looks like a
// "paste this into Terminal" shell one-liner with a subsequent shell/Terminal
// exec carrying that same payload. ClickFix (fake-CAPTCHA / "run this to fix")
// is the dominant 2026 macOS infostealer delivery vector and sidesteps
// Gatekeeper entirely — nothing is downloaded-and-launched, the user pastes and
// runs a command, so quarantine/notarization checks never apply. The only
// durable signal is the clipboard-content → shell-exec correlation.
//
// This component is pure and deterministic (clock is injected) so the
// correlation can be unit-tested without the live clipboard or ES exec stream.

import Foundation

public actor ClickFixDetector {

    public struct Match: Sendable, Equatable {
        public let clipboardPayload: String
        public let execCommandLine: String
        public let ageSeconds: Double
    }

    private struct Entry {
        let normalized: String
        let raw: String
        let at: Date
    }

    private var recent: [Entry] = []
    private let window: TimeInterval
    private let maxEntries: Int

    public init(window: TimeInterval = 60, maxEntries: Int = 32) {
        self.window = window
        self.maxEntries = maxEntries
    }

    /// Does this clipboard text look like a remote-fetch-piped-into-a-shell
    /// one-liner (the ClickFix delivery shape)? Requires BOTH a fetch and a
    /// route into an interpreter, so a bare URL or a lone `bash` does not trip.
    public static func looksLikeShellDelivery(_ text: String) -> Bool {
        let t = text.lowercased()
        guard !t.isEmpty, t.count < 8192 else { return false }
        let fetch = ["curl ", "wget ", "nscurl ", "fetch "].contains { t.contains($0) }
        let pipeToShell = ["| bash", "|bash", "| sh", "|sh", "| zsh", "|zsh"].contains { t.contains($0) }
        let cmdSubToShell = (t.contains("bash -c") || t.contains("sh -c") || t.contains("zsh -c"))
            && (t.contains("$(") || t.contains("`") || fetch)
        let b64ToShell = t.contains("base64") && pipeToShell
        let osascriptShell = t.contains("osascript") && (fetch || t.contains("do shell script"))
        return (fetch && pipeToShell) || cmdSubToShell || b64ToShell || osascriptShell
    }

    private static func normalize(_ s: String) -> String {
        s.lowercased()
            .components(separatedBy: .whitespacesAndNewlines)
            .filter { !$0.isEmpty }
            .joined(separator: " ")
    }

    /// Record a clipboard text. Stored only if it matches the delivery shape;
    /// returns whether it was recorded.
    @discardableResult
    public func recordClipboard(_ text: String, at: Date) -> Bool {
        guard Self.looksLikeShellDelivery(text) else { return false }
        recent.append(Entry(normalized: Self.normalize(text), raw: text, at: at))
        if recent.count > maxEntries { recent.removeFirst(recent.count - maxEntries) }
        return true
    }

    /// On a shell/Terminal exec, return a Match if its command line actually
    /// carries a recently-copied delivery payload within the window. Matching
    /// the payload (not merely "a shell launched") is what keeps this specific
    /// to a paste-and-run and out of the way of normal shell use.
    public func correlateExec(commandLine: String, at: Date) -> Match? {
        let exec = Self.normalize(commandLine)
        guard !exec.isEmpty else { return nil }
        for entry in recent.reversed() {
            let age = at.timeIntervalSince(entry.at)
            guard age >= 0, age <= window else { continue }
            if exec.contains(entry.normalized) || entry.normalized.contains(exec) {
                return Match(clipboardPayload: entry.raw, execCommandLine: commandLine, ageSeconds: age)
            }
        }
        return nil
    }
}
