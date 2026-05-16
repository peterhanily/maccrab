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
        llmService: LLMService?
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
            eventStore: eventStore
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
            // Source 1a: Native Endpoint Security events (if available)
            if let es = collector {
                Task {
                    while true {
                        for await event in es.events {
                            continuation.yield(event)
                        }
                        mergedStreamLogger.warning("ESCollector stream ended — restarting in 2s")
                        try? await Task.sleep(nanoseconds: 2_000_000_000)
                    }
                }
            }

            // Source 1b: kdebug events (fallback when ES entitlement unavailable)
            if let kdebug = kdebugCollector {
                Task {
                    while true {
                        for await event in kdebug.events {
                            continuation.yield(event)
                        }
                        mergedStreamLogger.warning("KdebugCollector stream ended — restarting in 2s")
                        try? await Task.sleep(nanoseconds: 2_000_000_000)
                    }
                }
            }

            // Source 1c: eslogger proxy events
            if let eslogger = esloggerCollector {
                Task {
                    while true {
                        for await event in eslogger.events {
                            continuation.yield(event)
                        }
                        mergedStreamLogger.warning("EsloggerCollector stream ended — restarting in 2s")
                        try? await Task.sleep(nanoseconds: 2_000_000_000)
                    }
                }
            }

            // Source 2: Unified Log events
            if let ul = ulCollector {
                Task {
                    while true {
                        for await event in ul.events {
                            continuation.yield(event)
                        }
                        mergedStreamLogger.warning("UnifiedLogCollector stream ended — restarting in 2s")
                        try? await Task.sleep(nanoseconds: 2_000_000_000)
                    }
                }
            }

            // Source 3: TCC permission change events
            Task {
                while true {
                    for await event in tccMonitor.events {
                        continuation.yield(event)
                    }
                    mergedStreamLogger.warning("TCCMonitor stream ended — restarting in 2s")
                    try? await Task.sleep(nanoseconds: 2_000_000_000)
                }
            }

            // Source 4: Network connection events
            Task {
                while true {
                    for await event in networkCollector.events {
                        continuation.yield(event)
                    }
                    mergedStreamLogger.warning("NetworkCollector stream ended — restarting in 2s")
                    try? await Task.sleep(nanoseconds: 2_000_000_000)
                }
            }
        }
    }
}
