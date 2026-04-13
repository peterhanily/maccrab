import Foundation
import MacCrabCore
import os.log

/// Prints the startup banner with system status summary.
enum StartupBanner {
    static func print(state: DaemonState) async {
        let singleRuleCount = await state.ruleEngine.ruleCount
        let seqRuleCount = await state.sequenceEngine.ruleCount
        let bannerTreeStats = await state.processTreeAnalyzer.stats()
        let esHealth = await state.esHealthMonitor.currentStatus()
        let scannerStatus = await state.injectionScanner.isAvailable ? "active" : "unavailable (pip install forensicate)"

        Swift.print("""

        \u{2554}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2557}
        \u{2551}         MacCrab Detection Engine         \u{2551}
        \u{2551}       Local-First macOS Security         \u{2551}
        \u{2551}                  v1.1.1                   \u{2551}
        \u{255A}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{255D}

        Status: Active
        PID: \(Foundation.ProcessInfo.processInfo.processIdentifier)

        Event Sources:
          - Endpoint Security (ES): \(state.esMode)
          - Unified Log (\(14) subsystems): \(state.ulCollector != nil ? "active" : "unavailable")
          - TCC permission monitor: active
          - Network connection collector: active
          - DNS collector (BPF): active
          - Event tap monitor: active
          - System policy monitor: active
          - MCP server monitor: active
          - ES client health monitor: \(esHealth.isHealthy ? "healthy" : "DEGRADED")

        Detection Stack:
          - Single-event Sigma rules (\(singleRuleCount) loaded)
          - Temporal sequence rules (\(seqRuleCount) loaded)
          - Baseline anomaly engine
          - Cross-process correlator
          - Process tree ML: \(bannerTreeStats.mode.rawValue) (\(bannerTreeStats.transitions) transitions)
          - Statistical anomaly detector
          - Behavioral scoring (70+ indicators)

        AI Guard:
          - Tool monitoring: Claude Code, Codex, OpenClaw, Cursor + 4 more
          - Credential fence: \(CredentialFence.defaultPaths.count) sensitive paths
          - Project boundary enforcement
          - AI network sandbox
          - MCP server monitoring
          - Prompt injection scanner: \(scannerStatus)

        Enrichment:
          - Process lineage graph
          - Code signing cache
          - Notarization checker
          - Quarantine provenance
          - Threat intelligence (abuse.ch)
          - YARA file scanning (if available)

        Prevention: \(state.preventionEnabled ? "ACTIVE" : "standby (MACCRAB_PREVENTION=1)")
          \(state.preventionEnabled ? "- DNS sinkhole, PF blocker, persistence guard" : "")
          \(state.preventionEnabled ? "- AI containment, supply chain gate, TCC revocation" : "")
          \(state.preventionEnabled ? "- Sandbox analysis for suspicious binaries" : "")

        Forensics:
          - Rootkit detection (dual-API cross-reference)
          - Crash report mining (exploitation indicators)
          - Power/thermal anomaly detection
          - Library injection scanning

        Storage: \(state.supportDir)/events.db
        Rules:   \(state.compiledRulesDir)

        Press Ctrl+C to stop.
        """)
    }
}
