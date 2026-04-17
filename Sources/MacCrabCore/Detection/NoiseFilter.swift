// NoiseFilter.swift
// MacCrabCore
//
// Shared low-signal match filters. Applied at every rule-evaluation entry
// point (main event loop, FSEvents fallback loop, SIGHUP retroactive
// scan) so noise suppression stays consistent and can't be bypassed by a
// new integration forgetting to call it.
//
// Every fix we've shipped between 1.2.1 and 1.2.3 to cut the alert rate
// on real dev workstations has landed here, so this file is also the
// regression-test surface — see FPRegressionTests.swift.

import Foundation

/// Low-signal match filters applied before alert emission. Stateless —
/// every input is passed in; no singleton, no hidden global state. This
/// makes the filter trivially testable from the FP-regression harness.
public enum NoiseFilter {

    /// Apply all three gates to a batch of rule matches. Mutates in place.
    /// Each gate drops non-`.critical` matches; critical rules (ransomware,
    /// SIP disabled, known-malicious-hash) always fire regardless of gate.
    ///
    /// - Parameters:
    ///   - matches: rule matches to filter; mutated in place.
    ///   - event: the event that produced these matches. Process attribution
    ///     and executable path drive the unknown-process and trusted-browser
    ///     gates.
    ///   - isWarmingUp: `true` during the daemon's first 60 seconds of
    ///     operation, when inventory scans produce a one-shot burst.
    public static func apply(
        _ matches: inout [RuleMatch],
        event: Event,
        isWarmingUp: Bool
    ) {
        // Gate 1: unattributable event. FSEvents fires file events without
        // a process; Sigma rules with `Image|contains` filters designed to
        // exclude trusted system processes fail open in that case. Dropping
        // non-critical matches here means we never alert on activity we
        // cannot triage.
        if event.process.name == "unknown" || event.process.executable.isEmpty {
            matches.removeAll { $0.severity != .critical }
        }

        // Gate 2: startup warm-up window. Inventory scans (browser
        // extensions, quarantine baseline, process-tree model hydration)
        // complete in the first 60 s and generate a one-shot burst that
        // isn't live-threat signal. Critical still fires so a ransomware
        // note at T+10s isn't missed.
        if isWarmingUp {
            matches.removeAll { $0.severity != .critical }
        }

        // Gate 3: trusted browser / Electron helper. Chromium apps spawn
        // large helper trees that fire individual Sigma rules in isolation
        // (reading their own cookie DB, writing their own cache, opening
        // long-lived HTTPS, spawning child tools for profile migration).
        // A single bundle-prefix short-circuit drops non-critical matches
        // without needing per-rule-per-helper allowlists.
        if isTrustedBrowserHelper(path: event.process.executable) {
            matches.removeAll { $0.severity != .critical }
        }
    }

    /// True when the given executable path is inside a trusted browser or
    /// Electron-helper app bundle. Public so rule-level allowlists can
    /// reuse the same definition.
    public static func isTrustedBrowserHelper(path: String) -> Bool {
        for prefix in trustedBrowserPrefixes where path.hasPrefix(prefix) {
            return true
        }
        return false
    }

    /// Known browser / Electron app-bundle prefixes whose helper processes
    /// do a lot of activity individual Sigma rules flag in isolation.
    /// Adding an entry here turns every rule into a non-critical skip for
    /// processes under that bundle — use sparingly and only for widely-
    /// deployed first-party software.
    public static let trustedBrowserPrefixes: [String] = [
        // Browsers
        "/Applications/Google Chrome.app/",
        "/Applications/Google Chrome Canary.app/",
        "/Applications/Chromium.app/",
        "/Applications/Microsoft Edge.app/",
        "/Applications/Microsoft Edge Canary.app/",
        "/Applications/Microsoft Edge Dev.app/",
        "/Applications/Microsoft Edge Beta.app/",
        "/Applications/Brave Browser.app/",
        "/Applications/Brave Browser Nightly.app/",
        "/Applications/Brave Browser Dev.app/",
        "/Applications/Arc.app/",
        "/Applications/Vivaldi.app/",
        "/Applications/Opera.app/",
        "/Applications/Firefox.app/",
        "/Applications/Firefox Nightly.app/",
        "/Applications/Firefox Developer Edition.app/",
        "/Applications/Safari.app/",
        "/Applications/Orion.app/",
        // Electron apps that ship a Chromium helper tree and behave
        // identically to browsers from the detection engine's perspective.
        "/Applications/Slack.app/",
        "/Applications/Discord.app/",
        "/Applications/Microsoft Teams.app/",
        "/Applications/Visual Studio Code.app/",
        "/Applications/Code.app/",
        "/Applications/Cursor.app/",
        "/Applications/Claude.app/",
        "/Applications/ChatGPT Atlas.app/",
        "/Applications/Codex.app/",
        "/Applications/GitHub Desktop.app/",
        "/Applications/Signal.app/",
        "/Applications/Telegram.app/",
        "/Applications/WhatsApp.app/",
    ]
}
