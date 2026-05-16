// IntentBriefBuilder.swift
// MacCrabAgentKit
//
// v1.12.0 — assembles an `IntentClassifier.BehaviorBrief` from a
// package-manager install exec event + the Bayesian engine's posterior
// for the same process tree. The brief feeds the synchronous heuristic
// classifier in EventLoop so the downstream Sigma rule
// (`Rules/ai_safety/llm_classifier_high_risk_intent.yml`) can fire on
// the same event that produced the install signal.
//
// Brief shape is deliberately thin — the heuristic classifier converts
// the categorical evidence log into label scores without needing raw
// file paths or hostnames. LLM-backed deep classification stays on the
// MCP `classify_package_intent` tool, which can construct a richer
// brief out-of-band.

import Foundation
import MacCrabCore

enum IntentBriefBuilder {

    /// Returns a brief if-and-only-if the event looks like a package-
    /// manager install exec; returns nil otherwise. EventLoop short-
    /// circuits on nil so the heuristic classifier never runs on
    /// random events.
    static func brief(
        for event: Event,
        posterior: BayesianIntentEngine.Posterior?
    ) -> IntentClassifier.BehaviorBrief? {
        // v1.12.0 RC6 (Perf-R6-N2): caseInsensitiveCompare avoids the
        // per-call String allocation of `.lowercased()` — matches the
        // pattern used in IntentEvidenceClassifier.
        guard event.eventCategory == .process,
              event.eventAction.caseInsensitiveCompare("exec") == .orderedSame else {
            return nil
        }
        let exe = event.process.executable
        let exeName = (exe as NSString).lastPathComponent
        guard let registry = registryForInstaller(exeName) else { return nil }

        let cmd = event.process.commandLine
        // Only stamp on install / add / global / upgrade commands. A
        // bare `npm` exec without an install subcommand is the user
        // running `npm --version` or `npm test` — not a candidate.
        //
        // v1.12.0 RC2 fix (M-Perf-N2): use case-insensitive substring
        // probes instead of `cmd.lowercased()`. The prior impl
        // allocated a full lowercase copy of the commandLine (50-300
        // bytes typical) for every package-installer exec event,
        // which on a dev Mac means hundreds of allocations per minute
        // for innocent `npm --version` / `pip list` / `brew doctor`
        // calls. The case-insensitive range probe avoids the alloc.
        let installVerbs = [" install", " i ", " add", " global", " upgrade", " update"]
        let isInstall = installVerbs.contains { verb in
            cmd.range(of: verb, options: .caseInsensitive) != nil
        }
        guard isInstall else { return nil }

        let packageName = extractPackageName(from: cmd, exeName: exeName) ?? "<unknown>"
        let lineage = event.process.ancestors.map { ($0.executable as NSString).lastPathComponent }

        // Pull categorical evidence from the Bayesian engine's per-tree
        // log so the heuristic sees an actual history (credentialRead,
        // launchAgentWrite, etc.) and not just the current install
        // event. Without this, the brief is always thin and the
        // heuristic always returns .benign.
        let evidenceSet: Set<BayesianIntentEngine.Evidence> = Set(posterior?.evidenceLog ?? [])
        let credPaths: [String] = evidenceSet.contains(.credentialRead) ? ["~/.aws/credentials or .npmrc or .ssh/id_*"] : []
        let networkEgress: [String] = {
            var hosts: [String] = []
            if evidenceSet.contains(.registryEgress) {
                switch registry {
                case "npm":  hosts.append("registry.npmjs.org")
                case "pypi": hosts.append("upload.pypi.org")
                default:     hosts.append("<registry>")
                }
            }
            if evidenceSet.contains(.nonRegistryEgress) {
                hosts.append("<non-registry endpoint>")
            }
            return hosts
        }()
        let persistencePaths: [String] = {
            var paths: [String] = []
            if evidenceSet.contains(.launchAgentWrite) { paths.append("~/Library/LaunchAgents/<file>") }
            if evidenceSet.contains(.shellRcWrite)      { paths.append("~/.zshrc or .bashrc") }
            if evidenceSet.contains(.workflowWrite)     { paths.append(".github/workflows/<file>.yml") }
            return paths
        }()
        let processesSpawned: [String] = {
            var procs: [String] = []
            if evidenceSet.contains(.destructiveCmd)    { procs.append("rm") }
            if evidenceSet.contains(.vmDetectionProbe)  { procs.append("sysctl") }
            return procs
        }()
        let hasObfuscatedContent = evidenceSet.contains(.obfuscatedContent)
        let hasBundledRuntime = evidenceSet.contains(.runtimeDrop)
        // Cross-ecosystem mismatch is not directly an evidence type;
        // leave false until a future enricher computes it.
        let hasLanguageMismatch = false
        // AI agent attribution comes from existing TraceCorrelator enrichments
        // ("agent_tool" key) OR the AIProcessTracker ("ai_tool" key) — pre-fix
        // the builder read "AgentTool" which no writer produces.
        let aiAgentTriggered = event.enrichments["agent_tool"] != nil
            || event.enrichments["ai_tool"] != nil

        return IntentClassifier.BehaviorBrief(
            packageName: packageName,
            packageRegistry: registry,
            packageVersion: nil,
            installerLineage: lineage,
            credentialsRead: credPaths,
            networkEgress: networkEgress,
            filesWritten: persistencePaths,
            processesSpawned: processesSpawned,
            hasObfuscatedContent: hasObfuscatedContent,
            hasBundledRuntime: hasBundledRuntime,
            hasLanguageMismatch: hasLanguageMismatch,
            aiAgentTriggered: aiAgentTriggered
        )
    }

    // MARK: - Helpers

    /// Map an installer basename to its registry tag. Returns nil for
    /// non-installers so brief() short-circuits.
    private static func registryForInstaller(_ exeName: String) -> String? {
        switch exeName {
        case "npm", "pnpm", "yarn", "bun":         return "npm"
        case "pip", "pip3", "uv", "poetry", "pipenv": return "pypi"
        case "cargo":                                return "cargo"
        case "gem":                                  return "rubygems"
        case "brew":                                 return "homebrew"
        default:                                     return nil
        }
    }

    /// Extract the package name from a command line. Best-effort —
    /// returns nil when we can't confidently parse one. The classifier
    /// works without an exact name (only used for human-facing reasons).
    private static func extractPackageName(from cmd: String, exeName: String) -> String? {
        let tokens = cmd.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
        guard tokens.count >= 3 else { return nil }
        // Find the install verb, take the next non-flag token.
        let installVerbs = Set(["install", "i", "add", "upgrade", "update", "global"])
        guard let verbIdx = tokens.firstIndex(where: { installVerbs.contains($0) }) else { return nil }
        for token in tokens.dropFirst(verbIdx + 1) {
            if !token.hasPrefix("-") {
                return token
            }
        }
        return nil
    }
}
