import Foundation
import MacCrabCore

// MARK: - ANSI Terminal Colors

/// Whether stdout is a terminal (enables color output).
/// Falls back to plain text when output is piped or redirected.
let isTerminal = isatty(STDOUT_FILENO) != 0

enum ANSIColor: String {
    case red = "\u{001B}[31m"
    case orange = "\u{001B}[33m"      // yellow in most terminals
    case yellow = "\u{001B}[93m"      // bright yellow
    case blue = "\u{001B}[34m"
    case gray = "\u{001B}[90m"
    case bold = "\u{001B}[1m"
    case reset = "\u{001B}[0m"

    static func wrap(_ text: String, _ color: ANSIColor) -> String {
        guard isTerminal else { return text }
        return "\(color.rawValue)\(text)\(ANSIColor.reset.rawValue)"
    }
}

extension Severity {
    /// Colored severity label for CLI output.
    var coloredLabel: String {
        switch self {
        case .critical:      return ANSIColor.wrap("[CRITICAL]", .red)
        case .high:          return ANSIColor.wrap("[HIGH]    ", .orange)
        case .medium:        return ANSIColor.wrap("[MEDIUM]  ", .yellow)
        case .low:           return ANSIColor.wrap("[LOW]     ", .blue)
        case .informational: return ANSIColor.wrap("[INFO]    ", .gray)
        }
    }
}

/// Resolve the MacCrab data directory.
/// Prefers the system dir (root daemon) when its DB is newer, since the
/// user dir may contain stale data from a previous non-root run.
func maccrabDataDir() -> String {
    let fm = FileManager.default
    let userDir = fm.urls(
        for: .applicationSupportDirectory,
        in: .userDomainMask
    ).first.map { $0.appendingPathComponent("MacCrab").path }
        ?? NSHomeDirectory() + "/Library/Application Support/MacCrab"
    let systemDir = "/Library/Application Support/MacCrab"

    let userDB = userDir + "/events.db"
    let systemDB = systemDir + "/events.db"
    let userExists = fm.fileExists(atPath: userDB)
    let systemReadable = fm.isReadableFile(atPath: systemDB)

    // v1.21.6 (audit DL-08): freshness must include the `-wal` sidecar. In WAL
    // mode a main `.db` file's mtime only advances at CHECKPOINT, so a store
    // being written to right now can look weeks stale — field-observed on this
    // host: campaigns.db dated 24 Jun beside campaigns.db-wal dated 22 Jul, a
    // four-week lag. Comparing bare `.db` mtimes therefore resolved to whichever
    // store checkpointed most recently rather than whichever is LIVE, so the CLI
    // could answer from a stale dev store for hours at a time with no
    // indication. max(db, db-wal) tracks actual writes.
    func lastWrite(_ path: String) -> Date? {
        let main = (try? fm.attributesOfItem(atPath: path))?[.modificationDate] as? Date
        let wal = (try? fm.attributesOfItem(atPath: path + "-wal"))?[.modificationDate] as? Date
        guard let main else { return wal }
        guard let wal else { return main }
        return max(main, wal)
    }

    if userExists && systemReadable {
        let userMod = lastWrite(userDB)
        let sysMod = lastWrite(systemDB)
        if let s = sysMod, let u = userMod, s >= u {
            return systemDir
        }
        return userDir
    }
    if systemReadable { return systemDir }
    if userExists { return userDir }
    return systemDir
}

/// The USER-domain MacCrab data dir, ALWAYS (never the root-owned system dir).
///
/// `maccrabDataDir()` prefers the root `/Library/Application Support/MacCrab`
/// whenever its `events.db` is newer — which is always true on a machine with
/// the root daemon running. That's correct for READING daemon state, but WRONG
/// for client-owned artifacts the non-root CLI (uid 501) must WRITE: the rave
/// anti-rollback high-water mark and the signed install receipts. Writing them
/// under the root dir silently no-ops (best-effort `try?`), so anti-rollback
/// wasn't durable across CLI installs and no receipt trail was left (v1.19
/// dry-run Finding 2). These artifacts co-locate with the user-domain install
/// tree that `PluginInstaller` writes to, and the CLI's P256 receipt keys live
/// here in filesystem mode (no dependence on the root daemon's Secure-Enclave
/// key, which the CLI can't reach).
func maccrabUserWritableDataDir() -> String {
    FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)
        .first.map { $0.appendingPathComponent("MacCrab").path }
        ?? NSHomeDirectory() + "/Library/Application Support/MacCrab"
}

extension MacCrabCtl {

    /// CLI-4: write a usage/argument error to stderr and exit non-zero, so
    /// callers (scripts, CI) can detect a malformed invocation. Bare
    /// `maccrabctl` and explicit `help` stay exit 0; this is for the
    /// "wrong arguments to a real command" path.
    static func usageError(_ message: String) -> Never {
        FileHandle.standardError.write(Data((message + "\n").utf8))
        exit(1)
    }

    /// CLI-4: an unknown top-level command — stderr + usage + exit 1.
    static func unknownCommand(_ command: String) -> Never {
        FileHandle.standardError.write(Data(("Unknown command: \(command)\n").utf8))
        printUsage()
        exit(1)
    }

    /// CLI-5: research/diagnostic verbs (`debug`, `mcfp`) are hidden from the
    /// operator surface unless MACCRAB_DEV=1. Keeps experimental tooling off
    /// the shipped help + dispatch by default.
    static var devModeEnabled: Bool {
        ProcessInfo.processInfo.environment["MACCRAB_DEV"] == "1"
    }

    /// CLI-1: the canonical hidden-command set (dev-only; gated by
    /// devModeEnabled). The usage/parity test asserts these never appear in
    /// printed help.
    static let hiddenCommands: Set<String> = ["debug", "mcfp"]

    static func printUsage() { print(usageText()) }

    /// The full help text. Extracted (CLI-1) so CLIUsageParityTests can assert
    /// every dispatched top-level command (except the dev-hidden ones) is
    /// documented here. LOCALIZE: candidate for future localization; in a CLI
    /// without a resource bundle NSLocalizedString is impractical.
    static func usageText() -> String {
        return """
        maccrabctl - MacCrab Detection Engine CLI

        Usage: maccrabctl <command> [options]

        Monitoring:
          status              Show daemon status and statistics
          events tail [N] [--hours H] [--category C]  Show recent events
          events search <q>   Full-text search over events
          events stats        Show event statistics
          alerts [N] [--hours H] [--severity S]  Show alerts (N=count, H=hours, S=critical|high|medium|low)
          ai-alerts [--hours H] [--limit N]  AI-Guard alerts (credential fence, boundary, injection, MCP)
          scan-text <text>    Prompt-injection scan (native); reads stdin if no arg
          agent-capabilities <show|set|disable-all>
                              Inspect MCP mutation tiers; grants require explicit sudo.
          agent-spans [--search Q] [--trace ID] [--limit N]
                              Unauthenticated/self-reported OTLP spans from AI tools.
                              Distinct from `trace` (TraceGraph causal provenance).
          campaigns [N]       Show last N campaigns (default: 10)
          campaigns watch     Live stream campaigns as they are detected
          watch               Live stream alerts as they happen

        Rules:
          rules list          List all loaded detection rules
          rules count         Count rules by category
          rule create [cat]   Generate a rule YAML template
          rule enable|disable <id>   Toggle a rule without deleting its YAML
          rule delete <id>    Remove a user-authored rule (not maccrab.*)
          rule severity <id> <level>  Override a rule's severity (critical|high|medium|low|informational|default)
          compile <in> <out>  Compile Sigma YAML rules to JSON

        Response:
          suppress <rule> <path>  Allowlist a process for a rule (v1 API)
          unsuppress <rule> [path]  Remove a suppression (all paths if no path given)
          suppression list        Show all configured suppressions
          allow <sub>             Allowlist v2 — TTL, scope, audit
                                  (add / list / remove / stats)
          actions list            Show default + per-rule response actions
          actions set [--rule R] --action A [--min-severity S] [--script P]
                      [--confirm|--no-confirm] [--block-duration N]
                                  Add/replace a response action (kill/quarantine/
                                  blockNetwork default to confirmation-gated)
          actions delete [--rule R] [--action A]  Remove response action(s)
          export [format] [N]     Export alerts (json|csv, default: json)

        Config:
          config get [<key>]      Show daemon_config.json value(s)
          config set <key> <val>  Queue a daemon_config change (safe tunables only)
          audit [N]               Tail the privileged-mutation audit trail (default 50)

        Triage:
          why <alert_id>          Explain which rule fired, predicates + captured fields

        Deception (opt-in):
          deception <sub>         Honeyfile canaries
                                  (deploy / status / remove)

        Forensics:
          hunt <query>            Natural language threat hunting
          report [--hours N] [--output file]  Generate HTML incident report

        Forensic Scans:
          scan <subcommand>       Scan this Mac (new / list / show / run / findings /
                                  explain / timeline / allow-ai / mark-trusted-scheduled / delete)
          plugin <subcommand>     Plugin runtime (list / info / run)
          package <subcommand>    Supply-chain package intelligence
                                  (typosquat / content / metadata / attestation / intent)
          session <subcommand>    AI-agent session timeline + signed bundle
                                  (list / show / export / verify)
          (Run `maccrabctl scan help` or `maccrabctl plugin help` for detail.
           `case` is a deprecated v1.17 alias for `scan`.)
          cdhash <PID>            Extract CDHash for a process
          cdhash --all            Extract CDHashes for all processes
          tree-score [N]          Top-N suspicious processes (behavioral + Markov scoring)
          mcp list [--suspicious] List user-scope MCP server configs (not project .mcp.json)
          extensions [--suspicious]  Scan browser extensions for dangerous permissions
          vulns [--hours H] [--severity S]  Vulnerability alerts from the CVE scanner
          privacy [--hours H]  Privacy anomaly alerts (bulk egress, trackers, domain spikes)
          security            Full security posture breakdown with recommendations
          modules             List subsystems with maturity (stable / experimental / opt-in)

        Investigation & maintenance:
          trace <subcommand>      Causal TraceGraph (list / show / explain / graph /
                                  export / verify / replay). See `trace help`.
          intel <subcommand>      Threat-intel feeds (refresh / matches / status)
          evidence <subcommand>   Forensic evidence (list / search / show / export)
          rollup [--hours N]      Force the storage tier-rollup + prune sweep now
          repair <subcommand>     Storage / index repair helpers
          fingerprint <subcommand>  MCFP v1 static process fingerprint

        Other:
          version             Show version information
          help                Show this help message

        Examples:
          maccrabctl status
          maccrabctl watch
          maccrabctl alerts --hours 24
          maccrabctl alerts --severity critical
          maccrabctl campaigns
          maccrabctl campaigns watch
          maccrabctl events search "curl Downloads"
          maccrabctl export csv 500
          maccrabctl rule create network_connection
          maccrabctl suppress my-rule-id /usr/bin/safe-process
          maccrabctl unsuppress my-rule-id /usr/bin/safe-process
          maccrabctl suppression list
          maccrabctl hunt "show critical alerts from last hour"
          maccrabctl report --hours 48 --output incident.html
          maccrabctl cdhash 1234
          maccrabctl tree-score 20
          maccrabctl mcp list
          maccrabctl extensions --suspicious
          maccrabctl vulns
          maccrabctl vulns --hours 24 --severity critical
          maccrabctl privacy
          maccrabctl privacy --hours 24
          maccrabctl security
          maccrabctl allow add --rule rule.noisy --path /usr/local/bin/vendor --ttl 7d --reason "vendor rollout"
          maccrabctl allow list --expired
          maccrabctl deception deploy
          maccrabctl deception status
          maccrabctl actions list
          maccrabctl config get statistical_z_threshold
          maccrabctl package typosquat requests --registry pypi
          maccrabctl session list
          maccrabctl ai-alerts --hours 24
        """
    }

    static func printVersion() {
        // v1.9.0: dynamic version via MacCrabVersion. Bundle.main
        // resolves to the .app bundle when maccrabctl is invoked from
        // inside MacCrab.app; falls back to the build-time string for
        // the bare-binary path (Homebrew install, swift run).
        // LOCALIZE: "MacCrab Detection Engine vX.Y.Z"
        print("MacCrab Detection Engine v\(MacCrabVersion.current)")
        // LOCALIZE: "License: Apache 2.0 (code), DRL 1.1 (rules)"
        print("License: Apache 2.0 (code), DRL 1.1 (rules)")
        print("https://github.com/maccrab-detection/maccrab")
    }

    static func formatBytes(_ bytes: UInt64) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file)
    }

    static func formatDate(_ date: Date) -> String {
        "\(Self._datePart.string(from: date).uppercased()) \(Self._timePart.string(from: date))"
    }

    private static let _datePart: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "ddMMMyyyy"
        return f
    }()
    private static let _timePart: DateFormatter = {
        let f = DateFormatter()
        f.timeStyle = .medium
        f.dateStyle = .none
        return f
    }()

    /// Create a transient LLM service for CLI use.
    ///
    /// Resolution order (highest priority first):
    ///   1. Env vars — legacy / CI path, kept for backward compat
    ///   2. Keychain (SecretsStore) — authoritative in v1.3.5+, written
    ///      by the dashboard's Settings > AI Backend tab
    ///   3. llm_config.json — non-secret provider/model/URL settings only
    ///
    /// Env vars intentionally win over Keychain so CI / one-off invocations
    /// can override without disturbing the user's stored credentials.
    static func createCLILLMService() -> LLMService? {
        var config = LLMConfig()
        var hasConfig = false

        // Settings owns the user-home non-secret config. Prefer it even when
        // event-store resolution selects the root support directory (whose
        // 0600 config an unprivileged CLI cannot read), then fall back to the
        // resolved/installed paths. An explicit data-dir remains hermetic.
        let environment = ProcessInfo.processInfo.environment
        let userSupportDir = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first?.appendingPathComponent("MacCrab").path
            ?? NSHomeDirectory() + "/Library/Application Support/MacCrab"
        let configPaths = LLMConfigFile.runtimeConfigReadPaths(
            explicitDataDirectory: environment["MACCRAB_DATA_DIR"],
            userDataDirectory: userSupportDir,
            resolvedDataDirectory: maccrabDataDir()
        )
        for configPath in configPaths {
            guard let json = try? LLMConfigFile.loadAndScrub(
                atPath: configPath,
                legacySecretMigration: .sharedKeychain(interaction: .allowed)
            ) else { continue }
            LLMConfigFile.applyNonSecretValues(json, to: &config)
            hasConfig = config.enabled
            break
        }

        // Best-effort only: the shipped bare CLI intentionally has no shared-
        // group entitlement because a restricted entitlement without its own
        // provisioning bundle is an AMFI launch failure. Dashboard-stored cloud
        // keys are therefore normally app-only; env keys and local Ollama keep
        // the CLI inference paths usable. The loader handles missing access.
        LLMSecretLoader.applyKeychainSecrets(to: &config, interaction: .allowed)

        // Env vars override everything (explicit ephemeral override + CI).
        if LLMSecretLoader.applyEnvironmentOverrides(
            environment,
            to: &config,
            providerSelectionEnables: true
        ) {
            hasConfig = true
        }

        guard hasConfig else { return nil }

        let backend: any LLMBackend
        switch config.provider {
        case .ollama:
            backend = OllamaBackend(baseURL: config.ollamaURL, model: config.ollamaModel, apiKey: config.ollamaAPIKey)
        case .claude:
            guard let key = config.claudeAPIKey, !key.isEmpty else { return nil }
            backend = ClaudeBackend(apiKey: key, model: config.claudeModel)
        case .openai:
            guard let key = config.openaiAPIKey, !key.isEmpty else { return nil }
            backend = OpenAIBackend(baseURL: config.openaiURL, apiKey: key, model: config.openaiModel)
        case .mistral:
            guard let key = config.mistralAPIKey, !key.isEmpty else { return nil }
            backend = MistralBackend(apiKey: key, model: config.mistralModel)
        case .gemini:
            guard let key = config.geminiAPIKey, !key.isEmpty else { return nil }
            backend = GeminiBackend(apiKey: key, model: config.geminiModel)
        }

        return LLMService(backend: backend, config: config)
    }
}
