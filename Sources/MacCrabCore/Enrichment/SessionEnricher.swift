// SessionEnricher.swift
// MacCrabCore
//
// Derives SessionInfo for an event from its process ancestry. Primary job
// is assigning a LaunchSource so downstream rules (e.g. ssh_launched_*)
// know whether a process came from an SSH session, a terminal, Finder,
// launchd, cron, or AppleScript.
//
// Pure logic — no syscalls, no cache. A future version will add TTY
// resolution via proc_pidinfo and SSH remote IP via TCP connection
// inspection; for v1, ancestor-chain inference alone unlocks every rule
// added in Phase 2 that references IsSSHLaunched / LaunchSource.

import Foundation

public enum SessionEnricher {

    /// Build a SessionInfo from the process's pid + ancestor chain.
    /// Returns nil only when the chain is empty (no inference possible).
    public static func enrich(pid: Int32, ancestors: [ProcessAncestor]) -> SessionInfo? {
        let source = inferLaunchSource(ancestors: ancestors)
        // Return nil only if we learned nothing — prevents plastering every
        // event with an empty SessionInfo.
        guard source != .unknown || !ancestors.isEmpty else { return nil }
        return SessionInfo(
            sessionId: nil,
            tty: nil,
            loginUser: nil,
            sshRemoteIP: nil,
            launchSource: source
        )
    }

    // MARK: - Launch-source inference

    /// Walk the ancestor chain, nearest-parent first, and return the most
    /// specific launch source we recognize. Skips `launchd` since every
    /// macOS process eventually traces to it — we want the meaningful
    /// intermediate (Terminal, sshd, cron, etc.).
    ///
    /// If only `launchd` is found, returns `.launchd`. Unknown shells fall
    /// through to `.unknown`.
    static func inferLaunchSource(ancestors: [ProcessAncestor]) -> LaunchSource {
        var sawLaunchd = false
        for a in ancestors {
            if let src = classifyAncestor(name: a.name, executable: a.executable) {
                if src == .launchd {
                    sawLaunchd = true
                    continue
                }
                return src
            }
        }
        return sawLaunchd ? .launchd : .unknown
    }

    /// Classify a single ancestor by name + executable path. Returns nil if
    /// the ancestor is something we don't recognize (e.g. a shell, a helper
    /// process) so the walker keeps climbing.
    static func classifyAncestor(name: String, executable: String) -> LaunchSource? {
        let lowerName = name.lowercased()
        let lowerPath = executable.lowercased()

        // SSH — both the remote-login daemon and the `ssh` client itself
        // trigger the signal; anything running under either is SSH-sourced.
        if lowerName == "sshd" || lowerName.hasPrefix("sshd-") ||
           lowerPath.hasSuffix("/sshd") {
            return .ssh
        }

        // Terminal emulators (Apple + third-party + developer-popular).
        let terminals: Set<String> = [
            "terminal", "iterm2", "iterm", "alacritty", "kitty",
            "ghostty", "wezterm", "warp", "tabby", "hyper",
        ]
        if terminals.contains(lowerName) {
            return .terminal
        }
        if lowerPath.contains("/terminal.app/") ||
           lowerPath.contains("/iterm.app/") ||
           lowerPath.contains("/ghostty.app/") ||
           lowerPath.contains("/alacritty.app/") {
            return .terminal
        }

        // Finder — explicitly user-initiated via double-click.
        if lowerName == "finder" || lowerPath.contains("/finder.app/") {
            return .finder
        }

        // AppleScript / automation.
        if lowerName == "osascript" || lowerPath.hasSuffix("/osascript") {
            return .applescript
        }

        // Cron / scheduled jobs.
        if lowerName == "cron" || lowerName == "crond" || lowerName == "at" {
            return .cron
        }

        // XPC services — spawned by xpcproxy / launchd for app extensions.
        if lowerName == "xpcproxy" || lowerPath.contains("xpcservices/") {
            return .xpc
        }

        // launchd: noted but not returned — we keep walking to find a more
        // specific source. Everything on macOS eventually descends from pid 1.
        if lowerName == "launchd" {
            return .launchd
        }

        // Shells are pass-through — a bash spawned inside Terminal should
        // still resolve to .terminal. Returning nil lets the walker continue.
        let shells: Set<String> = [
            "bash", "zsh", "sh", "fish", "dash", "tcsh", "ksh",
            "login", "su", "sudo",
        ]
        if shells.contains(lowerName) {
            return nil
        }

        return nil
    }
}
