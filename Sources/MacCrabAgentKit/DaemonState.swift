import Foundation
import MacCrabCore
import os.log

/// Holds all engine and component references shared across the daemon.
/// Created once during initialization and passed to all subsystems.
final class DaemonState {
    // MARK: - Paths
    let isRoot: Bool
    let supportDir: String
    let compiledRulesDir: String
    let rulesDir: String
    let rulesURL: URL
    let sequenceRulesDir: String
    let effectiveRulesDir: String

    // MARK: - Storage
    let eventStore: EventStore
    let alertStore: AlertStore
    /// Single chokepoint for all alert insertion. Routes everything through
    /// AlertDeduplicator before reaching AlertStore, closing the v1.6.9
    /// NoiseFilter-layering bug class architecturally. All call sites that
    /// previously called `state.alertStore.insert(...)` directly should now
    /// call `state.alertSink.submit(...)` instead.
    let alertSink: AlertSink

    /// v1.11.0 (audit stability HIGH): reentrancy guard for the v1.10.1
    /// inbox file-IPC poller. Pre-fix the 5s DispatchSourceTimer fired
    /// a fresh Task every tick — if the previous tick's Task was still
    /// draining a campaign suppress fan-out (worst case 30+ seconds at
    /// 5K alerts × 6ms per write), the next tick spawned a parallel
    /// Task that re-listed the same dir + raced for the same files.
    /// `withLock` provides correct mutual exclusion across the
    /// DispatchSource thread and any spawned Task.
    let inboxPollerLock = OSAllocatedUnfairLock<Bool>(initialState: false)

    // MARK: - Core Engines
    let enricher: EventEnricher
    let ruleEngine: RuleEngine
    let sequenceEngine: SequenceEngine
    let baselineEngine: BaselineEngine
    let behaviorScoring: BehaviorScoring
    let deduplicator: AlertDeduplicator
    let suppressionManager: SuppressionManager
    let statisticalDetector: StatisticalAnomalyDetector
    let crossProcessCorrelator: CrossProcessCorrelator
    let processTreeAnalyzer: ProcessTreeAnalyzer
    let topologyAnomalyDetector: TopologyAnomalyDetector

    // MARK: - Outputs
    let notifier: NotificationOutput
    let responseEngine: ResponseEngine
    let webhookOutput: WebhookOutput?
    let syslogOutput: SyslogOutput?
    /// Phase 7 outputs built from daemon_config.json.outputs[]. Each alert
    /// is fanned out to every entry here via the Output protocol.
    let additionalOutputs: [any Output]
    let notificationIntegrations: NotificationIntegrations

    // MARK: - Self-Defense
    let selfDefense: SelfDefense
    let esHealthMonitor: ESClientMonitor

    // MARK: - Threat Intelligence
    let threatIntel: ThreatIntelFeed
    let ctMonitor: CertTransparency
    let mispClient: MISPClient

    // MARK: - AI Guard
    let aiRegistry: AIToolRegistry
    let aiTracker: AIProcessTracker
    let credentialFence: CredentialFence
    let projectBoundary: ProjectBoundary
    let injectionScanner: PromptInjectionScanner
    let aiNetworkSandbox: AINetworkSandbox
    let fileInjectionScanner: FileInjectionScanner

    // MARK: - MCP attribution + baseline (v1.7.0)
    let mcpAttributor: MCPAttributor
    let mcpBaseline: MCPBaselineService

    // MARK: - Agent trace registry (v1.9 PR-2)
    //
    // Optional so a daemon binary running with `MACCRAB_AGENT_TRACES`
    // unset (default) doesn't allocate or schedule the consumer Task.
    // Set by DaemonSetup post-construction via `installTraceRegistry`,
    // mirroring how `var collector: ESCollector?` is wired (see line ~91).
    var traceRegistry: TraceRegistry?

    // MARK: - OTLP receiver + trace store (v1.9 PR-4)
    //
    // Both optional and post-construction-set. Allocated when
    // `MACCRAB_OTLP_RECEIVER=1` is in the daemon env. The receiver
    // listens on 127.0.0.1:4318, the trace store persists ingested
    // spans into `<supportDir>/traces.db`. PR-5 will wire a Settings
    // toggle that SIGHUPs the daemon to start/stop the receiver
    // dynamically; PR-4 ships env-var-only auto-start.
    var traceStore: TraceStore?
    var otlpReceiver: OTLPReceiver?

    // MARK: - Collector registry (v1.7.2)
    let collectorRegistry: CollectorRegistry

    // MARK: - Monitors
    let mcpMonitor: MCPMonitor
    let usbMonitor: USBMonitor
    let clipboardMonitor: ClipboardMonitor
    /// Shared with `clipboardMonitor` (which records delivery-shaped clipboard
    /// payloads) so the event loop can correlate a subsequent shell/Terminal
    /// exec against them — the ClickFix paste-and-run detection. Optional: nil
    /// disables the correlation (e.g. in tests / non-clipboard daemons).
    let clickFix: ClickFixDetector?
    let clipboardInjectionDetector: ClipboardInjectionDetector
    let browserExtMonitor: BrowserExtensionMonitor
    let ultrasonicMonitor: UltrasonicMonitor
    let eventTapMonitor: EventTapMonitor
    let systemPolicyMonitor: SystemPolicyMonitor
    let rootkitDetector: RootkitDetector
    let tccMonitor: TCCMonitor
    let edrMonitor: EDRMonitor
    let tempestMonitor: TEMPESTMonitor
    let fsEventsCollector: FSEventsCollector

    // MARK: - Collectors
    var collector: ESCollector?
    var esloggerCollector: EsloggerCollector?
    var kdebugCollector: KdebugCollector?
    var ulCollector: UnifiedLogCollector?
    let networkCollector: NetworkCollector
    let dnsCollector: DNSCollector
    let esMode: String

    // MARK: - Network Analysis
    let dohDetector: DoHDetector
    let tlsFingerprinter: TLSFingerprinter

    // MARK: - Forensics
    let crashReportMiner: CrashReportMiner
    let powerAnomalyDetector: PowerAnomalyDetector
    let libraryInventory: LibraryInventory
    let cdhashExtractor: CDHashExtractor
    let quarantineEnricher: QuarantineEnricher

    // MARK: - Enrichment
    let yaraEnricher: YARAEnricher
    let dbEncryption: DatabaseEncryption

    // MARK: - Prevention
    let preventionEnabled: Bool
    let dnsSinkhole: DNSSinkhole
    let networkBlocker: NetworkBlocker
    let persistenceGuard: PersistenceGuard
    let sandboxAnalyzer: SandboxAnalyzer
    let aiContainment: AIContainment
    let supplyChainGate: SupplyChainGate
    let tccRevocation: TCCRevocation

    // MARK: - User Security Features
    let securityScorer: SecurityScorer
    let appPrivacyAuditor: AppPrivacyAuditor
    let vulnScanner: VulnerabilityScanner
    // PanicButton was removed from DaemonState in v1.6.19. The actor was
    // instantiated and stored but `activate()` had zero callers in
    // production code — the dashboard never exposed a Panic button surface.
    // PanicButton.swift remains in MacCrabCore for reintroduction once
    // the UI surface ships.
    let travelMode: TravelMode
    let securityDigest: SecurityDigest
    let alertExporter: AlertExporter
    let scheduledReports: ScheduledReports

    // MARK: - Grouping & Campaigns
    let incidentGrouper: IncidentGrouper
    let campaignDetector: CampaignDetector
    /// Persistent campaign store — nil when storage init failed.
    /// Detected campaigns are written here so the dashboard can query
    /// across restarts and analysts can attach notes/suppression.
    let campaignStore: CampaignStore?
    let ruleGenerator: RuleGenerator

    // MARK: - TraceGraph
    /// Per-event causal-graph bridge. nil when SQLiteCausalGraphStore
    /// init failed (rare — only on disk-full or perms issues). When
    /// set, the EventLoop feeds every event through this bridge so
    /// AnchorDetector can materialize traces of interest.
    let causalGraphBridge: EventToRollingCausalGraphBridge?

    /// Causal-graph store used by TraceMaterializer. Held on
    /// DaemonState so the daily retention timer in DaemonTimers can
    /// drive prune + size-cap. Pre-fix the store was scope-locked
    /// inside DaemonSetup's `do { }` block — only the bridge
    /// survived, so timers had no way to call pruneTraces /
    /// pruneOldestTraces / databaseSizeBytes. nil whenever
    /// SQLiteCausalGraphStore init failed.
    let causalStore: SQLiteCausalGraphStore?

    /// Graph rule evaluator for v1.10.0 §23 multi-entity rules. Loaded
    /// once at daemon startup from `Rules/graph/*.json`. EventLoop runs
    /// every materialized Trace through `evaluate(entities:edges:)`
    /// and routes matches into the standard alert sink. nil when the
    /// causal store failed to initialize or no graph rules were found.
    /// v1.12.0 RC3 (Int-HSig1): `var` so SIGHUP can swap in a fresh
    /// evaluator with reloaded `Rules/graph/*.json` content. The
    /// evaluator itself holds rules as `let`, so we rebuild rather
    /// than mutate.
    ///
    /// TODO(v1.12.1) Sec-R5-N4: This `var` on a non-actor `final
    /// class DaemonState` is technically a data race — SIGHUP writes
    /// from `.main` queue (SignalHandlers.swift), EventLoop reads
    /// from a detached Task. Benign on Darwin (pointer-aligned
    /// reference swap is atomic) but Swift 6 strict-concurrency will
    /// flag it. Fix: wrap in `OSAllocatedUnfairLock<GraphRuleEvaluator?>`
    /// or make DaemonState an actor. Deferred from v1.12.0 because
    /// the runtime behaviour is correct today.
    var graphEvaluator: GraphRuleEvaluator?

    // MARK: - Intent posterior (v1.12.0)
    /// Bayesian belief network maintaining a posterior over attacker
    /// goals per process tree. EventLoop translates each event into
    /// zero or more `Evidence` values and feeds them in. When the top
    /// non-benign goal probability crosses `intentAlertThreshold`
    /// (default 0.85) with sufficient evidence, an alert is emitted.
    let bayesianIntent: BayesianIntentEngine

    /// LLM-backed classifier for package-install intent. Held on
    /// DaemonState so MCP handlers + PackageScanner share a single
    /// instance with the daemon's `LLMService`. Not invoked on every
    /// event — only on explicit package-install signals.
    let intentClassifier: IntentClassifier

    /// v1.12.6 — budget cap + result cache for `intentClassifier` when
    /// EventLoop fires it as a tie-breaker on AI-attributed installs
    /// with low heuristic confidence. Bounds LLM dispatches at one per
    /// process tree per 10 minutes and stores the verdict so subsequent
    /// events in the same tree see the refined label without paying
    /// another LLM call. LRU-bounded at 256 entries.
    let intentRefinementCache: IntentRefinementCache = IntentRefinementCache()

    /// v1.12.0 post-audit (M-Int1): correlates an AI agent's recent
    /// context reads with package installs to label the install as
    /// user-initiated / autonomous / slopsquat / injectionContext /
    /// vagueDestructive. EventLoop fires it in a detached Task when a
    /// package-install exec carries an AgentTool enrichment.
    let promptIntentBridge: PromptIntentBridge

    // MARK: - Package Security
    let packageChecker: PackageFreshnessChecker
    let notarizationChecker: NotarizationChecker

    // MARK: - Git Security
    let gitSecurityMonitor: GitSecurityMonitor

    // MARK: - Misc
    let reportGenerator: ReportGenerator
    let threatHunter: ThreatHunter
    let toolIntegrations: SecurityToolIntegrations
    let fleetClient: FleetClient?

    // MARK: - LLM
    let llmService: LLMService?

    // MARK: - Lifecycle
    /// Wall-clock timestamp captured when this state object is constructed —
    /// i.e., at daemon startup. Used by the event loop to gate alerting
    /// during the initial warm-up window, when one-shot inventory scans
    /// (browser extensions, quarantine stripping, process tree baseline)
    /// generate a burst of events that aren't live threat signals.
    let daemonStartTime: Date = Date()

    /// `true` during the first 60 seconds after daemon start. Inventory
    /// scans complete within this window; gating non-critical alerts here
    /// prevents startup noise from landing in the alert list as if it were
    /// real-time activity.
    var isWarmingUp: Bool {
        Date().timeIntervalSince(daemonStartTime) < 60
    }

    /// v1.8.0 per-tier retention budgets for events / alerts / campaigns.
    /// Populated by DaemonSetup from `DaemonConfig.storage`. DaemonTimers
    /// reads each knob live so a SIGHUP-driven config reload is honored on
    /// the next sweep without a daemon restart.
    ///
    /// Pre-v1.8 used a single `retentionDays` + `maxDatabaseSizeMB` pair
    /// shared across all three tiers. The split here lets event-firehose
    /// churn coexist with multi-year alert/campaign history.
    var storage: DaemonConfig.StorageConfig = DaemonConfig.StorageConfig()

    // v1.12.0 post-audit (M-Cfg1): intent posterior thresholds from
    // daemon_config.json. EventLoop reads these instead of hardcoded
    // 0.85 / 3 so an operator can tune false-positive aggressiveness.
    var intentPosteriorThreshold: Double = 0.85
    var intentPosteriorMinDistinctEvidence: Int = 3

    // MARK: - v1.6.6 AI Suite
    //
    // These six services ship as the AI Suite. Stateless-or-internally-
    // stateful ones are constructed with defaults here; the ones that
    // depend on `llmService` are optional and populated by DaemonSetup
    // after the LLM service is wired. Exposed via the DaemonState bag
    // so EventLoop, dashboard pollers, and the MCP server can reach
    // them without touching the designated initialiser.

    // Sysext-side AI Suite services. Only `AgentLineageService` is
    // genuinely sysext-bound — it weaves live ES events into per-AI-
    // tool session timelines and is consumed by `EventLoop`.
    //
    // The four orphans that previously lived here were removed in
    // v1.6.15 after the audit found them declared but unconsumed:
    //
    //   `triageService`, `llmConsensusService`, `agenticInvestigator`
    //     → moved to `AppState`. Outbound HTTPS with vendor API keys
    //       does not belong at ES-entitlement root privilege when the
    //       dashboard already owns the LLM config and is the natural
    //       consumer of triage results.
    //
    //   `alertClusterService`
    //     → ClusterSheet instantiates its own copy. Fingerprint state
    //       is per-render, not durable; nothing benefits from a single
    //       sysext-side instance.
    //
    //   `mcpBaselineService`
    //     → service is implemented but the producer half (per-event
    //       MCP-server-name attribution from process ancestry) is not
    //       yet built. Reintroduce when the producer lands; today the
    //       observation API has no caller.
    var agentLineageService: AgentLineageService = AgentLineageService()

    /// Wave-3 Phase 1: durable agent-session ids. Mints a UUID per
    /// AI-tool root and resolves it for the root's own events + all
    /// descendants, so EventLoop can stamp events.ai_tool_session_id
    /// (today provably always NULL — no producer).
    var agentSessionRegistry: AgentSessionRegistry = AgentSessionRegistry()

    init(
        isRoot: Bool,
        supportDir: String,
        compiledRulesDir: String,
        rulesDir: String,
        rulesURL: URL,
        sequenceRulesDir: String,
        effectiveRulesDir: String,
        eventStore: EventStore,
        alertStore: AlertStore,
        enricher: EventEnricher,
        ruleEngine: RuleEngine,
        sequenceEngine: SequenceEngine,
        baselineEngine: BaselineEngine,
        behaviorScoring: BehaviorScoring,
        deduplicator: AlertDeduplicator,
        suppressionManager: SuppressionManager,
        statisticalDetector: StatisticalAnomalyDetector,
        crossProcessCorrelator: CrossProcessCorrelator,
        processTreeAnalyzer: ProcessTreeAnalyzer,
        topologyAnomalyDetector: TopologyAnomalyDetector,
        notifier: NotificationOutput,
        responseEngine: ResponseEngine,
        webhookOutput: WebhookOutput?,
        syslogOutput: SyslogOutput?,
        additionalOutputs: [any Output] = [],
        notificationIntegrations: NotificationIntegrations,
        selfDefense: SelfDefense,
        esHealthMonitor: ESClientMonitor,
        threatIntel: ThreatIntelFeed,
        ctMonitor: CertTransparency,
        mispClient: MISPClient,
        aiRegistry: AIToolRegistry,
        aiTracker: AIProcessTracker,
        credentialFence: CredentialFence,
        projectBoundary: ProjectBoundary,
        injectionScanner: PromptInjectionScanner,
        aiNetworkSandbox: AINetworkSandbox,
        fileInjectionScanner: FileInjectionScanner,
        mcpAttributor: MCPAttributor,
        mcpBaseline: MCPBaselineService,
        collectorRegistry: CollectorRegistry,
        mcpMonitor: MCPMonitor,
        usbMonitor: USBMonitor,
        clipboardMonitor: ClipboardMonitor,
        clipboardInjectionDetector: ClipboardInjectionDetector,
        browserExtMonitor: BrowserExtensionMonitor,
        ultrasonicMonitor: UltrasonicMonitor,
        eventTapMonitor: EventTapMonitor,
        systemPolicyMonitor: SystemPolicyMonitor,
        rootkitDetector: RootkitDetector,
        tccMonitor: TCCMonitor,
        edrMonitor: EDRMonitor,
        tempestMonitor: TEMPESTMonitor,
        fsEventsCollector: FSEventsCollector,
        collector: ESCollector?,
        esloggerCollector: EsloggerCollector?,
        kdebugCollector: KdebugCollector?,
        ulCollector: UnifiedLogCollector?,
        networkCollector: NetworkCollector,
        dnsCollector: DNSCollector,
        esMode: String,
        dohDetector: DoHDetector,
        tlsFingerprinter: TLSFingerprinter,
        crashReportMiner: CrashReportMiner,
        powerAnomalyDetector: PowerAnomalyDetector,
        libraryInventory: LibraryInventory,
        cdhashExtractor: CDHashExtractor,
        quarantineEnricher: QuarantineEnricher,
        yaraEnricher: YARAEnricher,
        dbEncryption: DatabaseEncryption,
        preventionEnabled: Bool,
        dnsSinkhole: DNSSinkhole,
        networkBlocker: NetworkBlocker,
        persistenceGuard: PersistenceGuard,
        sandboxAnalyzer: SandboxAnalyzer,
        aiContainment: AIContainment,
        supplyChainGate: SupplyChainGate,
        tccRevocation: TCCRevocation,
        securityScorer: SecurityScorer,
        appPrivacyAuditor: AppPrivacyAuditor,
        vulnScanner: VulnerabilityScanner,
        travelMode: TravelMode,
        securityDigest: SecurityDigest,
        alertExporter: AlertExporter,
        scheduledReports: ScheduledReports,
        incidentGrouper: IncidentGrouper,
        campaignDetector: CampaignDetector,
        campaignStore: CampaignStore?,
        ruleGenerator: RuleGenerator,
        causalGraphBridge: EventToRollingCausalGraphBridge? = nil,
        causalStore: SQLiteCausalGraphStore? = nil,
        graphEvaluator: GraphRuleEvaluator? = nil,
        bayesianIntent: BayesianIntentEngine,
        intentClassifier: IntentClassifier,
        promptIntentBridge: PromptIntentBridge,
        packageChecker: PackageFreshnessChecker,
        notarizationChecker: NotarizationChecker,
        gitSecurityMonitor: GitSecurityMonitor,
        reportGenerator: ReportGenerator,
        threatHunter: ThreatHunter,
        toolIntegrations: SecurityToolIntegrations,
        fleetClient: FleetClient?,
        llmService: LLMService?,
        clickFix: ClickFixDetector? = nil
    ) {
        self.isRoot = isRoot
        self.supportDir = supportDir
        self.compiledRulesDir = compiledRulesDir
        self.rulesDir = rulesDir
        self.rulesURL = rulesURL
        self.sequenceRulesDir = sequenceRulesDir
        self.effectiveRulesDir = effectiveRulesDir
        self.eventStore = eventStore
        self.alertStore = alertStore
        // Build AlertSink from the already-stored alertStore + deduplicator so
        // we don't need a new initializer parameter. Construction is cheap
        // (the actor is empty); first use is what triggers any work.
        // v1.8.0: pass eventStore so the sink can snapshot the ±60s
        // event window into `alert_evidence` on every alert insert.
        // Backs the dashboard's alert detail view after the 24h hot
        // tier drops the originating events.
        self.alertSink = AlertSink(
            alertStore: alertStore,
            deduplicator: deduplicator,
            eventStore: eventStore,
            builtinSettingsDir: supportDir
        )
        self.enricher = enricher
        self.ruleEngine = ruleEngine
        self.sequenceEngine = sequenceEngine
        self.baselineEngine = baselineEngine
        self.behaviorScoring = behaviorScoring
        self.deduplicator = deduplicator
        self.suppressionManager = suppressionManager
        self.statisticalDetector = statisticalDetector
        self.crossProcessCorrelator = crossProcessCorrelator
        self.processTreeAnalyzer = processTreeAnalyzer
        self.topologyAnomalyDetector = topologyAnomalyDetector
        self.notifier = notifier
        self.responseEngine = responseEngine
        self.webhookOutput = webhookOutput
        self.syslogOutput = syslogOutput
        self.additionalOutputs = additionalOutputs
        self.notificationIntegrations = notificationIntegrations
        self.selfDefense = selfDefense
        self.esHealthMonitor = esHealthMonitor
        self.threatIntel = threatIntel
        self.ctMonitor = ctMonitor
        self.mispClient = mispClient
        self.aiRegistry = aiRegistry
        self.aiTracker = aiTracker
        self.credentialFence = credentialFence
        self.projectBoundary = projectBoundary
        self.injectionScanner = injectionScanner
        self.aiNetworkSandbox = aiNetworkSandbox
        self.fileInjectionScanner = fileInjectionScanner
        self.mcpAttributor = mcpAttributor
        self.mcpBaseline = mcpBaseline
        self.collectorRegistry = collectorRegistry
        self.mcpMonitor = mcpMonitor
        self.usbMonitor = usbMonitor
        self.clipboardMonitor = clipboardMonitor
        self.clipboardInjectionDetector = clipboardInjectionDetector
        self.browserExtMonitor = browserExtMonitor
        self.ultrasonicMonitor = ultrasonicMonitor
        self.eventTapMonitor = eventTapMonitor
        self.systemPolicyMonitor = systemPolicyMonitor
        self.rootkitDetector = rootkitDetector
        self.tccMonitor = tccMonitor
        self.edrMonitor = edrMonitor
        self.tempestMonitor = tempestMonitor
        self.fsEventsCollector = fsEventsCollector
        self.collector = collector
        self.esloggerCollector = esloggerCollector
        self.kdebugCollector = kdebugCollector
        self.ulCollector = ulCollector
        self.networkCollector = networkCollector
        self.dnsCollector = dnsCollector
        self.esMode = esMode
        self.dohDetector = dohDetector
        self.tlsFingerprinter = tlsFingerprinter
        self.crashReportMiner = crashReportMiner
        self.powerAnomalyDetector = powerAnomalyDetector
        self.libraryInventory = libraryInventory
        self.cdhashExtractor = cdhashExtractor
        self.quarantineEnricher = quarantineEnricher
        self.yaraEnricher = yaraEnricher
        self.dbEncryption = dbEncryption
        self.preventionEnabled = preventionEnabled
        self.dnsSinkhole = dnsSinkhole
        self.networkBlocker = networkBlocker
        self.persistenceGuard = persistenceGuard
        self.sandboxAnalyzer = sandboxAnalyzer
        self.aiContainment = aiContainment
        self.supplyChainGate = supplyChainGate
        self.tccRevocation = tccRevocation
        self.securityScorer = securityScorer
        self.appPrivacyAuditor = appPrivacyAuditor
        self.vulnScanner = vulnScanner
        self.travelMode = travelMode
        self.securityDigest = securityDigest
        self.alertExporter = alertExporter
        self.scheduledReports = scheduledReports
        self.incidentGrouper = incidentGrouper
        self.campaignDetector = campaignDetector
        self.campaignStore = campaignStore
        self.ruleGenerator = ruleGenerator
        self.causalGraphBridge = causalGraphBridge
        self.causalStore = causalStore
        self.graphEvaluator = graphEvaluator
        self.bayesianIntent = bayesianIntent
        self.intentClassifier = intentClassifier
        self.promptIntentBridge = promptIntentBridge
        self.packageChecker = packageChecker
        self.notarizationChecker = notarizationChecker
        self.gitSecurityMonitor = gitSecurityMonitor
        self.reportGenerator = reportGenerator
        self.threatHunter = threatHunter
        self.toolIntegrations = toolIntegrations
        self.fleetClient = fleetClient
        self.llmService = llmService
        self.clickFix = clickFix
    }

    private let mergedStreamLogger = Logger(subsystem: "com.maccrab.agent", category: "EventStream")

    /// Upper bound on in-flight events queued to the detection pipeline.
    /// Past this depth, AsyncStream's `.bufferingNewest` policy drops the
    /// *oldest* event to make room. At 10k events/sec this cap represents
    /// ~10 seconds of buffered backlog, which is an order of magnitude more
    /// than any healthy enrichment + rule-match cycle, so normal workloads
    /// never reach the cap. Bursts above it lose the oldest events rather
    /// than growing the resident set unboundedly — an explicit choice because
    /// an OOM'd daemon detects nothing. Sequence rules tolerate a sparse
    /// drop via the partial-match timeout; a memory blow-up wouldn't.
    private static let mergedStreamCap = 100_000

    /// Merges all event sources into a single async stream.
    /// Each source runs in a restart loop — if the underlying AsyncStream ends
    /// (subprocess exit, actor error, buffer overflow), the Task re-attaches
    /// after a 2-second back-off so the source recovers without a daemon restart.
    func mergedEventStream() -> AsyncStream<Event> {
        AsyncStream<Event>(bufferingPolicy: .bufferingNewest(Self.mergedStreamCap)) { continuation in
            let logger = mergedStreamLogger
            let yield: @Sendable (Event) -> Void = { continuation.yield($0) }
            // v1.18: each source runs an independent backoff + escalation loop.
            // A source whose AsyncStream ends PERMANENTLY (ES client invalidated,
            // eslogger subprocess gone) no longer hot-spins at a fixed 2s logging
            // a warning forever while the heartbeat stays green — it backs off
            // exponentially and escalates ONCE to a CRITICAL fault, so the host
            // can't go silently blind on its highest-fidelity sensor.
            // (Re-establishing the underlying client — es_new_client — remains a
            // deeper follow-up; this stops the silent-spin + raises the alarm.)
            // v1.18: the primary process/file sensors (ES + its eslogger
            // fallback) are ESSENTIAL — when one dies permanently (the post-
            // Sparkle-update case: the kext is replaced out from under the old
            // process and its es_client_t is invalidated, so the stream ends
            // and never recovers), driveSource asks for a guarded daemon
            // relaunch instead of sitting silently at 0 ev/s until the user
            // reboots. The OS keeps an ES system extension alive, so exiting
            // yields a fresh process that re-runs es_new_client.
            let sd = supportDir
            if let es = collector {
                Task { await driveSource("ESCollector", logger: logger, essential: true, supportDir: sd, events: { es.events }, yield: yield) }
            }
            if let kdebug = kdebugCollector {
                Task { await driveSource("KdebugCollector", logger: logger, events: { kdebug.events }, yield: yield) }
            }
            if let eslogger = esloggerCollector {
                Task { await driveSource("EsloggerCollector", logger: logger, essential: true, supportDir: sd, events: { eslogger.events }, yield: yield) }
            }
            if let ul = ulCollector {
                Task { await driveSource("UnifiedLogCollector", logger: logger, events: { ul.events }, yield: yield) }
            }
            let tcc = tccMonitor
            Task { await driveSource("TCCMonitor", logger: logger, events: { tcc.events }, yield: yield) }
            let net = networkCollector
            Task { await driveSource("NetworkCollector", logger: logger, events: { net.events }, yield: yield) }
        }
    }
}

/// Drive one collector stream with exponential backoff + one-shot down
/// escalation (SourceRestartState), replacing the fixed-2s re-iterate-forever
/// spin. A re-attach that yields ≥1 event resets the backoff; repeated empty
/// re-attaches back off (capped) and, past the threshold, escalate once to a
/// CRITICAL fault so a permanently-dead source can't go unnoticed.
private func driveSource(
    _ name: String,
    logger: Logger,
    policy: SourceRestartPolicy = SourceRestartPolicy(),
    essential: Bool = false,
    supportDir: String? = nil,
    events: @escaping @Sendable () -> AsyncStream<Event>,
    yield: @escaping @Sendable (Event) -> Void
) async {
    var state = SourceRestartState(policy: policy)
    while !Task.isCancelled {
        var produced = false
        for await event in events() {
            produced = true
            yield(event)
        }
        let delay: TimeInterval
        switch state.record(produced: produced) {
        case .retry(let d):
            delay = d
        case .recovered(let d):
            delay = d
            logger.notice("\(name) RECOVERED — event source producing again")
        case .escalate(let d):
            delay = d
            logger.fault("\(name) is DOWN — \(state.consecutiveEmpty) consecutive empty re-attaches; host detection degraded on this source")
            // v1.18: an essential sensor that's confirmed dead can't recover
            // in-process (the ES client is invalidated). Request a guarded
            // daemon relaunch so a fresh process re-establishes es_new_client.
            if essential, let supportDir {
                recoverEssentialSourceOrStayDegraded(name: name, supportDir: supportDir, logger: logger)
            }
        }
        try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
    }
}

/// Process start time, captured at first reference, for the min-uptime guard.
private let daemonProcessStart = Date()

/// When an essential event source (ES / eslogger) is confirmed dead, exit so
/// the OS relaunches a fresh daemon that re-runs the full collector init
/// (es_new_client). Two guards prevent a crash loop:
///   • min uptime — never exit within the first 180 s, so a boot-time ES
///     failure (e.g. entitlement not yet granted) doesn't loop;
///   • cross-restart rate limit — a marker file records recent relaunches; if
///     we've already relaunched ≥3 times in the last 10 min, give up and stay
///     degraded (the CRITICAL fault is already logged) rather than thrash.
/// NEEDS ON-DEVICE VERIFICATION: relies on the system relaunching the ES
/// extension after exit (standard for kept-alive security extensions).
private func recoverEssentialSourceOrStayDegraded(name: String, supportDir: String, logger: Logger) {
    // Only a supervised, non-interactive process is relaunched on exit (the
    // sysext / LaunchDaemon). A developer running `swift run maccrabd` from a
    // terminal would just have it quit — so never exit when stdin is a TTY;
    // stay degraded instead.
    guard isatty(STDIN_FILENO) == 0 else {
        logger.fault("\(name) DOWN in an interactive session — not relaunching (no supervisor); staying degraded")
        return
    }
    let uptime = Date().timeIntervalSince(daemonProcessStart)
    guard uptime > 180 else {
        logger.fault("\(name) DOWN \(Int(uptime))s after start — within startup guard window; staying up, not relaunching")
        return
    }
    let markerPath = supportDir + "/.collector_restart"
    let now = Date().timeIntervalSince1970
    let recent: [Double] = {
        guard let text = try? String(contentsOfFile: markerPath, encoding: .utf8) else { return [] }
        return text.split(whereSeparator: { $0 == "\n" }).compactMap { Double($0) }
            .filter { now - $0 < 600 }
    }()
    guard recent.count < 3 else {
        logger.fault("\(name) DOWN but already relaunched \(recent.count)× in 10 min — giving up auto-recovery to avoid a restart loop; host stays degraded until manual restart")
        return
    }
    let updated = (recent + [now]).map { String($0) }.joined(separator: "\n") + "\n"
    // Atomic write (temp + rename): if ES + eslogger escalate concurrently and
    // both reach here in the same process, the marker can't be left corrupt by
    // interleaved writes. (Semantically one entry per process death is correct —
    // exit() below ends the process before a second writer matters.)
    try? updated.data(using: .utf8)?.write(to: URL(fileURLWithPath: markerPath), options: .atomic)
    logger.fault("\(name) confirmed dead — exiting for a clean relaunch so a fresh ES client can be established (relaunch \(recent.count + 1) in the last 10 min)")
    // EX_TEMPFAIL(75): a transient failure; the supervising system should
    // relaunch us. Flush os_log first.
    exit(75)
}
