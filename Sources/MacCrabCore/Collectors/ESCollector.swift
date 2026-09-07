// ESCollector.swift
// MacCrabCore
//
// Wraps Apple's Endpoint Security framework to collect security-relevant
// kernel events and normalise them into MacCrab `Event` objects.
//
// # Event pipeline
//
//   ES framework                                 MacCrab pipeline
//   ────────────                                 ────────────────
//   es_new_client     ──▶  ESCollector.start()
//                          │
//   es_subscribe      ──▶  │  (process exec/fork/exit, file
//                          │   create/write/rename/unlink, signal,
//                          │   kext, mmap, iokit, auth, tcc, …)
//                          │
//   kernel callback   ──▶  │  on ES serial queue:
//                          │    ESHelpers.parse(msg) → Event
//                          │    stream.yield(event)
//                          ▼
//                      AsyncStream<Event>  ──▶  EventLoop → Enricher → RuleEngine
//
// # Queueing model
//
// The ES client callback runs on a private serial queue managed by the
// framework. We copy every field we need out of the `es_message_t` on
// that thread (because the struct is reclaimed the moment the callback
// returns), then yield into a user-space `AsyncStream<Event>` consumed
// on the detection pipeline's own executor. This means no lock around
// collector state; the class opts into `@unchecked Sendable`.
//
// # Required privileges
//
//   - euid 0 (ES framework rejects non-root)
//   - `com.apple.developer.endpoint-security.client` entitlement,
//     signed by an approved provisioning profile bound to the
//     `.systemextension` bundle (AMFI rejects LaunchDaemons since
//     macOS Catalina — see UPGRADE.md)
//   - Full Disk Access to see file events for TCC-protected paths
//
// Without the entitlement, `es_new_client` returns
// `ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED`. `maccrabd`'s fallback chain
// (eslogger → kdebug → FSEvents) handles that case for developer builds.

import Foundation
import EndpointSecurity
import Darwin.POSIX
import os.log

// MARK: - ESCollectorError

/// Errors that can occur when creating or configuring the ES client.
public enum ESCollectorError: Error, CustomStringConvertible {
    /// The calling process is not running as root (euid 0).
    case notRunningAsRoot
    /// The binary does not have the required
    /// `com.apple.developer.endpoint-security.client` entitlement.
    case missingEntitlement
    /// Too many ES clients are already connected system-wide.
    case tooManyClients
    /// An unrecognised error code was returned by `es_new_client`.
    case clientCreationFailed(es_new_client_result_t)
    /// `es_subscribe` returned an error.
    case subscriptionFailed
    /// The client was already stopped or never started.
    case notRunning

    public var description: String {
        switch self {
        case .notRunningAsRoot:
            return "Endpoint Security requires root privileges (euid 0)."
        case .missingEntitlement:
            return "Binary is missing the com.apple.developer.endpoint-security.client entitlement."
        case .tooManyClients:
            return "Too many Endpoint Security clients are already connected."
        case .clientCreationFailed(let code):
            return "es_new_client failed with result code \(code.rawValue)."
        case .subscriptionFailed:
            return "es_subscribe failed — check event types."
        case .notRunning:
            return "ES client is not running."
        }
    }
}

// MARK: - ESCollector

/// Collects macOS Endpoint Security NOTIFY events and emits normalised
/// `Event` values through an `AsyncStream`.
///
/// Usage:
/// ```swift
/// let collector = try ESCollector()
/// for await event in collector.events {
///     // process event
/// }
/// ```
public final class ESCollector: @unchecked Sendable {

    /// Collector-local delivery boundary. Kept public for heartbeat diagnostics
    /// and inventory tests so the reported capacity cannot drift from runtime.
    public static let eventStreamCapacity = 100_000

    // MARK: Properties

    private var continuation: AsyncStream<Event>.Continuation?
    private var traceBindingContinuation: AsyncStream<TraceBindingSignal>.Continuation?
    private let logger = Logger(subsystem: "com.maccrab.core", category: "ESCollector")
    private let deliveryTelemetry = EventCollectorBufferTelemetry(
        capacity: eventStreamCapacity
    )
    /// ES starts exactly once during construction. The condition serialises
    /// teardown callers and lets the async finalizer join the synchronous ES
    /// worker/client drain without claiming cancellation is completion.
    private let lifecycleCondition = NSCondition()
    private var lifecyclePhase: CollectorLifecyclePhase = .initialized

    public var deliveryCounters: EventCollectorBufferSnapshot {
        deliveryTelemetry.snapshot()
    }

    /// v1.21.4 Phase-4 (Mitigation C): the split ES clients. Normally TWO
    /// `ESClientContext`s — a FILE client (write-family + OPEN) and an
    /// EXEC/PROCESS client (everything else) — each on its OWN `es_client_t` /
    /// kernel queue, so a file-write flood can no longer starve exec from a
    /// shared queue (Apple's top-line mitigation). Each context owns its client,
    /// its own `ESSeqTracker` (so `es_kernel_dropped_by_type` is measured
    /// per-queue — the money test needs the EXEC queue's NOTIFY_EXEC drop counter
    /// independent of the FILE queue's), its own `ESMessageWorker`, and the exact
    /// type list it subscribes; the read-path accessors MERGE across contexts. In
    /// the graceful single-client fallback (`splitDegraded == true`) this holds
    /// ONE context subscribing all types. Assigned once in `createClients()`
    /// during `init` and only ever DRAINED (never re-shaped) afterward, so the
    /// heartbeat's concurrent reads are race-free — the same guarantee the old
    /// `let` trackers gave.
    private var contexts: [ESClientContext] = []

    /// v1.21.4 Phase-4 (Mitigation C): true iff the file/exec split could NOT be
    /// established (the second `es_new_client` failed) and the collector fell back
    /// to a single client subscribing ALL types. Surfaced as the heartbeat health
    /// flag `es_client_split_degraded`. Write-once during `init`; read-only after.
    private var splitDegraded = false

    /// v1.21.4 Phase-2 (D3): coverage-canary recognizer. The daemon-health
    /// watchdog (`DaemonTimers`) periodically `posix_spawn`s `/usr/bin/true`
    /// carrying a per-run nonce in argv; this registry lets the callback record
    /// "the probe was seen at the ES callback boundary" for a live nonce. Armed
    /// only for the ~seconds a probe is in flight, so the hot path is a single
    /// locked `isEmpty` check the rest of the time. The spawn NEVER happens from
    /// the callback — only the cheap recognizer note does. See `CoverageCanary`.
    private let canaryRegistry = ESCanaryRegistry()
    public let deliveryHealth = ESDeliveryHealth()

    public func deliveryHealthSnapshot() -> ESDeliveryHealth.Snapshot {
        let latest = contexts.compactMap { $0.tracker.lastCallbackUptimeNanoseconds() }.max()
        return deliveryHealth.snapshot(lastCallbackUptimeNanoseconds: latest)
    }


    // v1.21.4 Phase-4 (Mitigation C): the Phase-3 bounded off-thread worker is
    // now PER-CONTEXT (one per split client), not a single shared worker — a
    // shared worker would re-couple the file and exec channels at the parse
    // stage, defeating the split. Each `ESClientContext` owns its `ESMessageWorker`
    // (built in `makeClientContext`, drained in `teardownContext`). The
    // free-exactly-once + bounded-in-flight guarantees are unchanged per worker.

    /// v1.21.4 Phase-3 (Mitigation B): DEFAULT in-flight cap for each per-client
    /// `ESMessageWorker`. Under a
    /// flood the parse worker can fall behind; rather than let retained messages
    /// pile up without bound (kernel memory held per retained message), the
    /// worker drops the newest arrival past this cap, frees it immediately, and
    /// counts it (`es_copy_backpressure_dropped_total`). 4096 retained messages
    /// is a burst absorber bounded to tens of MB worst-case.
    ///
    /// v1.21.6 (RES-05 / FF-08) — CORRECTION. This comment used to claim the cap
    /// was "large enough that steady state never hits it". That is false on an
    /// ordinary daily driver and has been for the whole shipped life of the
    /// mitigation. Measured on the author's own host at idle-to-normal load:
    /// `es_copy_backpressure_dropped_total` 478,519 against 4,052,571 offered
    /// (11.8%) over 8,075 s uptime, and 2,609,845 against 11,839,098 (22.0%) in a
    /// longer window — with `es_kernel_dropped_total` at 0, i.e. ALL of it is
    /// MacCrab's own userspace backpressure. The drop policy discards the NEWEST
    /// arrival, which is exactly what a burst (and therefore an exploitation
    /// sequence) produces.
    ///
    /// What is and is not done about it here:
    ///   * The lineage reserve (`lineageCriticalRawValues`) already stops a
    ///     MPROTECT burst from evicting EXEC on the same worker.
    ///   * The loss is NOT silent: SensorDegradationEvaluator's `sustainedLoss`
    ///     branch fires the self-defense meta-alert at a >=15% per-tick drop
    ///     fraction, and `es_copy_backpressure_dropped_by_type` attributes it.
    ///   * v1.21.6 makes the cap tunable (`DaemonConfig.esWorkerMaxInFlight`) —
    ///     this constant is now only the DEFAULT.
    ///   * The real fix is to reduce what is OFFERED, not to raise the cap: see
    ///     the PERF-02 demand gate on `memoryProtectionEvents` /
    ///     `introspectionEvents`, which removes ~24-31% of the message stream
    ///     that could not produce a detection in the shipped configuration.
    ///     Sharding the worker per-PID is still open.
    /// `public` because it is the default for the public `workerMaxInFlight`
    /// initializer parameter, and Swift requires a default-argument expression
    /// to be at least as visible as the declaration it defaults.
    public static let maxInFlightMessages = 4096

    /// v1.17.4: subscribe to ES NOTIFY_OPEN (credential-read detection).
    /// Config kill-switch (DaemonConfig.subscribeFileOpenEvents).
    private let subscribeFileOpen: Bool

    /// v1.18: subscribe to the introspection family (get_task_read / trace /
    /// remote_thread_create / cs_invalidated). Kill-switch
    /// (DaemonConfig.subscribeIntrospectionEvents) so an operator can disable
    /// it independently of the OPEN family.
    ///
    /// v1.21.6 (PERF-02): the config kill-switch is now ANDed with live rule
    /// DEMAND at construction (DaemonSetup) — the family is only subscribed when
    /// some ENABLED rule selects one of `introspectionEventActions`.
    private let subscribeIntrospection: Bool

    /// v1.21.6 (PERF-02): subscribe the W+X memory-protection family
    /// (mmap/mprotect). No config kill-switch — it is purely demand-driven,
    /// because no rule in the shipped corpus consumes `mmap_wx`/`mprotect_wx`,
    /// so a static default would only ever be wrong in the expensive direction.
    private let subscribeMemoryProtection: Bool

    /// v1.21.6 (RES-05): the per-client `ESMessageWorker` in-flight cap actually
    /// used, from `DaemonConfig.esWorkerMaxInFlight` (clamped in `init`). Was a
    /// hardcoded constant with no knob while the field host was losing 11.8-22%
    /// of the stream at this stage.
    private let workerMaxInFlight: Int

    /// v1.9 Agent Traces master gate. Seeded from `MACCRAB_AGENT_TRACES=1`
    /// at type-load (the dev / standalone-daemon path) to enable
    /// TRACEPARENT extraction on NOTIFY_EXEC. Default-off so a daemon
    /// binary running on an older host stays bit-identical to the
    /// v1.8.1 wire path until the operator opts in.
    ///
    /// v1.21.4 Phase-6 6A: no longer immutable. DaemonSetup OR's in the
    /// operator's `agent_traces_config.json` master (`agent_traces_enabled`)
    /// via `applyConfigMaster(_:)` at boot — the shipped System Extension
    /// can't be handed an env var, so config is the only reachable switch
    /// there. Written exactly once during boot, BEFORE the ES handler
    /// block starts reading it per-event (createClients runs after the
    /// setter); read-only afterward — hence `nonisolated(unsafe)`.
    nonisolated(unsafe) private static var agentTracesEnabled: Bool =
        Foundation.ProcessInfo.processInfo.environment["MACCRAB_AGENT_TRACES"] == "1"

    /// v1.9 audit Phase-1.8: shared AIToolRegistry instance reused
    /// across every NOTIFY_EXEC. AIToolRegistry's init builds a tuple
    /// of patterns; allocating one per exec at 200-500 events/sec
    /// adds avoidable allocation pressure on the ES callback queue.
    fileprivate static let sharedAIRegistry = AIToolRegistry()

    /// Dynamic AI consumers are an additional exception to the deliberately
    /// narrow static OPEN allowlist. Keep their callback state in one
    /// lock-backed immutable registry: EventLoop publishes complete tracker
    /// snapshots after root/child lifecycle edges; the ES callback only reads.
    ///
    /// This policy intentionally contains *only* the dynamic-AI built-in. It
    /// answers "does an active AI consumer need this otherwise-discarded
    /// OPEN?" and is OR-ed with the established credential/agent-content
    /// paths below. The full rule-derived file policy remains a separate audit
    /// surface and cannot accidentally broaden this hot-path exception.
    static let dynamicAIFileInterestRegistry: FileEventInterestPolicyRegistry = {
        let registry = FileEventInterestPolicyRegistry()
        _ = registry.install(FileEventInterestDescriptorSnapshot(
            singleEventRules: [],
            sequenceRules: [],
            graphRules: [],
            builtinRequirements: [BuiltinFileEventRequirement(
                id: "maccrab.ai-guard.callback-open",
                sources: [.endpointSecurityFile],
                kind: .dynamicAIConsumers
            )]
        ))
        _ = registry.publishDynamicAI(.current(
            validUntilUptimeNanoseconds: UInt64.max,
            demands: []
        ))
        return registry
    }()

    /// Atomically replace callback demand from AIProcessTracker's complete
    /// active-session view. `UInt64.max` is deliberate: EventLoop publishes on
    /// every lifecycle edge, so the snapshot remains current until replaced;
    /// arbitrary wall-clock expiry would turn an idle non-AI host into an
    /// admit-all OPEN firehose. Bounds failure still installs `.unknown` and
    /// therefore fails open.
    @discardableResult
    public static func publishDynamicAIFileEventSessions(
        _ sessions: [DynamicAIFileEventSession]
    ) -> Bool {
        dynamicAIFileInterestRegistry.publishDynamicAI(.currentCanonical(
            validUntilUptimeNanoseconds: UInt64.max,
            sessions: sessions
        ))
    }

    /// Close the short process-start grace on EXIT so rapid PID reuse cannot
    /// inherit even the bounded over-admission window.
    public static func revokeDynamicAIFileEventProcess(_ processID: Int32) {
        dynamicAIFileInterestRegistry.revokeDynamicAIGrace(processID: processID)
    }

    /// v1.21.4 (P6): low-volume operator-visible signal for the agent-trace
    /// self-stamp path. Logs at `.info` ONLY when a TRACEPARENT is actually
    /// found on an exec (rare — never per-exec), so `log stream --predicate
    /// 'category == "agent-traces"'` confirms the traceparent path fires
    /// on-device without FDA/eslogger.
    private static let traceLogger = Logger(subsystem: "com.maccrab.agent", category: "agent-traces")

    /// Public accessor for the master gate (env seed OR'd with the
    /// config master applied at boot). Tests and the dashboard status
    /// panel can read this without touching ProcessInfo themselves.
    public static var isAgentTracesEnabled: Bool { agentTracesEnabled }

    /// v1.21.4 Phase-6 6A: pure `env OR config` combine for the master
    /// gate. Used by `applyConfigMaster` and unit-tested directly so the
    /// truth table is deterministic without mutating global state.
    public static func agentTracesMasterEnabled(env: Bool, config: Bool) -> Bool {
        env || config
    }

    /// v1.21.4 Phase-6 6A: fold the config-file master into the env
    /// seed. Called once by DaemonSetup at boot, BEFORE the ESCollector
    /// is constructed, so the ES handler block and every DaemonSetup
    /// boot-time gate (`isAgentTracesEnabled`) observe the OR'd value.
    /// Monotonic — only ever turns the gate ON (an env-enabled dev run
    /// stays on regardless of config); never OFF. Safe as a one-time
    /// boot write (see the `nonisolated(unsafe)` note on the flag).
    public static func applyConfigMaster(_ configEnabled: Bool) {
        agentTracesEnabled = agentTracesMasterEnabled(env: agentTracesEnabled, config: configEnabled)
    }

    /// The asynchronous stream of normalised events.
    public let events: AsyncStream<Event>

    /// v1.9 side-channel: trace bind/evict signals derived from
    /// NOTIFY_EXEC env scans and NOTIFY_EXIT events. Empty stream when
    /// `agentTracesEnabled` is false. EventLoop owns the consumer.
    public let traceBindings: AsyncStream<TraceBindingSignal>

    // MARK: - Subscribed Event Types

    /// The set of NOTIFY event types we subscribe to.
    private static let subscribedEvents: [es_event_type_t] = [
        ES_EVENT_TYPE_NOTIFY_EXEC,
        ES_EVENT_TYPE_NOTIFY_FORK,
        ES_EVENT_TYPE_NOTIFY_EXIT,
        ES_EVENT_TYPE_NOTIFY_CREATE,
        ES_EVENT_TYPE_NOTIFY_WRITE,
        ES_EVENT_TYPE_NOTIFY_CLOSE,
        ES_EVENT_TYPE_NOTIFY_RENAME,
        ES_EVENT_TYPE_NOTIFY_UNLINK,
        ES_EVENT_TYPE_NOTIFY_SIGNAL,
        ES_EVENT_TYPE_NOTIFY_KEXTLOAD,
        // v1.21.4: BTM launch-item registration. A modern SMAppService.register()
        // login item / launch agent / daemon leaves NO LaunchAgent plist and NO
        // write-time file event, so the ~89 write-time persistence rules never
        // fire (PamStealer / Jamf-Jul-2026 "ghost login item"). This is the only
        // sensor that sees that add — WITH the responsible instigator. Low-volume
        // (adds are rare, like KEXTLOAD), so subscribed UNCONDITIONALLY. Available
        // at the macOS 13.0 deploy floor (ESTypes.h "available beginning in macOS
        // 13.0" block), so no @available guard is needed.
        ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD,
        ES_EVENT_TYPE_NOTIFY_SETOWNER,
        ES_EVENT_TYPE_NOTIFY_SETMODE,
    ]

    /// v1.21.6 (PERF-02) memory-protection family — W+X mmap / mprotect.
    /// MOVED OUT of the unconditional `subscribedEvents` list because it is the
    /// worst cost/yield ratio in the whole subscription. Field-measured: 77/s
    /// MPROTECT + 50/s MMAP (~11.6% of ALL ES messages; 1.03M + 76K over 2.26 h)
    /// yielded exactly ONE stored `mprotect_wx` row and zero alerts — because NO
    /// rule in the corpus selects `event.action` `mprotect_wx` or `mmap_wx` at
    /// all (`grep -rn 'mprotect_wx\|mmap_wx' Rules/` is empty: no single-event,
    /// no sequence, no graph rule). Every one of those messages was retained,
    /// dispatched and discarded for nothing. Now gated on live rule DEMAND
    /// (`optionalFamiliesDemanded`), re-evaluated on SIGHUP.
    private static let memoryProtectionEvents: [es_event_type_t] = [
        ES_EVENT_TYPE_NOTIFY_MMAP,
        ES_EVENT_TYPE_NOTIFY_MPROTECT,
    ]

    /// v1.18 introspection family — observe one process acting on ANOTHER
    /// (memory read / injection / trace) or tampering its own signature.
    /// Grantable under the existing endpoint-security.client entitlement (the
    /// debugger entitlement is only needed to CALL these, not OBSERVE them) and
    /// all available at the macOS 13 deploy floor (GET_TASK_READ 11.3, TRACE
    /// 11.0, REMOTE_THREAD_CREATE 12.3, CS_INVALIDATED 10.15) — no @available
    /// guard. Gated by `subscribeIntrospection` so an operator can disable the
    /// family if it ever degrades a host. PROC_CHECK (firehose) +
    /// GATEKEEPER_USER_OVERRIDE (macOS 15, file-shaped) are deferred.
    private static let introspectionEvents: [es_event_type_t] = [
        ES_EVENT_TYPE_NOTIFY_GET_TASK_READ,
        ES_EVENT_TYPE_NOTIFY_TRACE,
        ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE,
        ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED,
    ]

    // MARK: - Demand gate for the optional families (v1.21.6, PERF-02)

    /// The `event.action` literals the introspection family emits (see the
    /// GET_TASK_READ / TRACE / REMOTE_THREAD_CREATE / CS_INVALIDATED branches in
    /// `normalise`). All four of the rules that select these ship
    /// `status: experimental`, i.e. DISABLED under the default stable profile —
    /// which is why 1.14M GET_TASK_READ messages (12.7% of the stream) produced
    /// zero rows and zero alerts on the field host.
    static let introspectionEventActions: Set<String> = [
        "get_task_read", "trace", "remote_thread_create", "cs_invalidated",
    ]

    /// The `event.action` literals the memory-protection family emits. Currently
    /// consumed by NO rule at all — see `memoryProtectionEvents`.
    static let memoryProtectionEventActions: Set<String> = ["mmap_wx", "mprotect_wx"]

    /// Decide which optional ES families are worth a kernel subscription, from
    /// the `event.action` selectors of the ENABLED ruleset
    /// (`RuleEngine.enabledEventActionSelectors`). Pure, so the truth table is
    /// unit-testable without a live `es_client_t`.
    ///
    /// Deliberately OVER-approximates, twice, because the cost of being wrong is
    /// asymmetric — a spurious subscription only wastes CPU, a missing one is a
    /// SILENT detection outage:
    ///   * `unanalyzable` (a `regex`/`exists` predicate on `event.action`, which
    ///     cannot be evaluated statically) turns BOTH families on.
    ///   * a selector counts for a family when it equals, contains, or is
    ///     contained by one of that family's actions — so `contains` /
    ///     `startswith` / `endswith` predicates (e.g. `event.action|contains:
    ///     task_read`) still demand the subscription.
    /// Empty selector strings are ignored: `"".contains` would otherwise match
    /// every family and defeat the gate entirely.
    /// `public`: DaemonSetup and the SIGHUP handler (both in MacCrabAgentKit)
    /// call this to re-evaluate the PERF-02 demand gate when the rule profile
    /// changes, so it has to cross the module boundary.
    public static func optionalFamiliesDemanded(
        selectors: Set<String>,
        unanalyzable: Bool
    ) -> (introspection: Bool, memoryProtection: Bool) {
        if unanalyzable { return (true, true) }
        func demanded(_ family: Set<String>) -> Bool {
            selectors.contains { selector in
                guard !selector.isEmpty else { return false }
                return family.contains { $0 == selector || $0.contains(selector) || selector.contains($0) }
            }
        }
        return (demanded(introspectionEventActions), demanded(memoryProtectionEventActions))
    }

    // MARK: - Noisy Path Muting

    /// Paths and prefixes that generate excessive noise and should be muted
    /// at the kernel level to reduce overhead.
    private static let mutedPaths: [String] = [
        // System binaries and frameworks
        "/System/",
        "/usr/libexec/xpcproxy",
        // Spotlight indexing
        "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework",
        "/.Spotlight-V100",
        // Time Machine
        "/System/Library/CoreServices/backupd.bundle",
        "/.MobileBackups",
        "/Volumes/com.apple.TimeMachine",
    ]

    /// Literal paths to mute (exact match).
    private static let mutedPathLiterals: [String] = [
        "/usr/libexec/xpcproxy",
        "/usr/sbin/mDNSResponder",
        "/usr/libexec/sandboxd",
        "/System/Library/CoreServices/launchservicesd",
        "/System/Library/PrivateFrameworks/SkyLight.framework/Versions/A/Resources/WindowServer",
    ]

    // MARK: - Observer-effect mute (v1.21.4 Phase-1 Mitigation A)
    //
    // MacCrab's OWN forensic DB copies (LiveDBSnapshot's sqlite-backup copy,
    // the broker's host-owned snapshot dir) and its stores/config writes
    // generate a file-event storm INTO MacCrab-owned directories. `muteSelf`
    // only silences the daemon-as-INITIATOR; the copies are performed by
    // SIBLING processes (MacCrabApp uid 501, maccrabctl, the broker host), so
    // an initiator-path mute (`es_mute_path_literal`/`_prefix`) can't reach
    // them. We mute by TARGET path instead: any write-family event whose
    // destination is under a MacCrab-owned dir is suppressed regardless of who
    // initiates it. Applied via `es_mute_path_events` restricted to the
    // write-family types ONLY (below) — crucially NOT NOTIFY_OPEN, so decoy /
    // honey-prompt reads under `.../MacCrab/decoys/` still emit (the
    // credential-read allowlist above depends on that OPEN emission).
    //
    // ES_MUTE_PATH_TYPE_TARGET_PREFIX is API_AVAILABLE(macos(13.0)) — exactly
    // the deploy floor — and es_mute_path_events is macOS 12.0+, so no
    // @available guard is needed. NEEDS-ON-DEVICE: confirm (a) the enum value
    // is honored at the 13.0 floor and (b) target muting does not perturb the
    // D1 seq_num accounting (mutes should suppress BEFORE sequencing — see the
    // D1 zero-FP caveat).

    /// TARGET-path prefixes whose write-family file events are muted: the
    /// root support dir (root daemon's DB + broker host-owned snapshot dirs +
    /// root-side Cases). Per-user home Cases roots (where the dashboard writes
    /// forensic snapshots) are added dynamically in `muteNoisyPaths()` through
    /// the shared home resolver, mirroring `AgentTracesConfig.findUserHomeConfigPath`.
    private static let mutedTargetPrefixes: [String] = [
        "/Library/Application Support/MacCrab/",
    ]

    /// Write-family ES event types muted on the target prefixes above.
    /// Deliberately excludes NOTIFY_OPEN (decoy reads must still emit). All
    /// five are in ESClient.h's target-muting supported-event list.
    static let forensicCopyMutedEventTypes: [es_event_type_t] = [
        ES_EVENT_TYPE_NOTIFY_CREATE,
        ES_EVENT_TYPE_NOTIFY_WRITE,
        ES_EVENT_TYPE_NOTIFY_CLOSE,
        ES_EVENT_TYPE_NOTIFY_RENAME,
        ES_EVENT_TYPE_NOTIFY_UNLINK,
    ]

    /// Pure builder for the observer-effect TARGET-mute prefixes: the fixed
    /// root support dir plus each supplied user home's MacCrab dir (the
    /// dashboard writes forensic Cases into the console user's home, which the
    /// root sysext doesn't know at compile time). Split out so the path logic
    /// is unit-testable without a live ES client.
    static func forensicCopyMuteTargetPrefixes(userHomes: [String]) -> [String] {
        var prefixes = mutedTargetPrefixes
        for home in userHomes {
            let trimmed = home.hasSuffix("/") ? String(home.dropLast()) : home
            prefixes.append(trimmed + "/Library/Application Support/MacCrab/")
        }
        return prefixes
    }

    /// Resolver-validated real-user homes used to reach per-user forensic Cases
    /// snapshot roots from the root sysext. Keeping mute scope on the shared
    /// home contract prevents a forged/symlink home from suppressing telemetry.
    private static func realUserHomes() -> [String] {
        RealUserHomeResolver.all().map(\.path)
    }

    // MARK: - Log-sink write firehose kernel mute (v1.21.4, post-rc.8 perf)
    //
    // The KERNEL-LEVEL counterpart to the userspace `shouldDropNoisyWrite` (P1).
    // The NOTIFY_WRITE firehose is dominated by append-only LOG SINKS (measured
    // on the field host: ~3200 of ~3800 writes / 2 min were `suricata` appending
    // to /var/log/suricata/*). The userspace drop still pays per-event message
    // RECEIPT + path extraction before it can drop; muting these WRITE/CLOSE
    // events by TARGET prefix at the ES client means the kernel never delivers
    // them at all — strictly cheaper. On-device (rc.8) this class of write is
    // what drives the sysext to ~100 % of a core under a log flood.
    //
    // SAFETY — what muting WRITE/CLOSE here does and does NOT give up:
    //   * Write-family ONLY (WRITE + CLOSE). EXEC / OPEN / CREATE / RENAME /
    //     UNLINK on these paths are NOT muted — so a payload dropped under a log
    //     dir is still seen via CREATE + EXEC, the write→execute cross-process
    //     chain still forms from CREATE + EXEC, and credential OPENs elsewhere are
    //     untouched.
    //   * Only the log DIRECTORIES are muted — never the bare `*.log` suffix
    //     anywhere. Two of the userspace KEEP-cases genuinely live OUTSIDE these
    //     dirs and are therefore fully preserved: credential/wallet `*.log` (a
    //     wallet leveldb lives under `~/Library/Application Support/…`, never a
    //     Logs dir) and agent-content. The bare-suffix + those keep-cases stay in
    //     `shouldDropNoisyWrite`, the precise userspace fallback for `.log` files
    //     elsewhere (`/tmp/x.log`, `~/Desktop/foo.log`).
    //   * HONEST DIVERGENCE from P1 (accepted): `shouldDropNoisyWrite` KEEPS a
    //     code-suffixed write (`.sh`/`.dylib`/`.py`/…) even under a log dir as a
    //     malicious-staging signal; the coarse kernel mute (prefix-only, no suffix
    //     logic) gives up the WRITE event for that narrow case. It is bounded and
    //     proportionate: writing into these system/daemon log dirs needs root or
    //     admin, and the file's CREATE + EXEC (hence the drop→execute chain) still
    //     fire — only the write-event signal for an in-log-dir code stage is lost.
    //     Traded for eliminating the firehose at the kernel (the dominant on-device
    //     CPU cost). The userspace code-keep still applies to `.log`-suffix files
    //     outside these dirs.
    //   * Same TARGET-mute mechanism as the shipped observer-effect mute
    //     (`muteForensicCopyTargets`), so it inherits its D1-seq-accounting
    //     behavior (mutes suppress before sequencing).

    /// Fixed system/daemon log-sink directory prefixes whose WRITE-family target
    /// events are kernel-muted. Per-user `~/Library/Logs/` dirs are appended at
    /// mute time (see `logSinkMuteAllTargetPrefixes`).
    static let logSinkMuteTargetPrefixes: [String] = [
        "/var/log/",
        "/private/var/log/",
        "/Library/Logs/",
    ]

    /// WRITE-family events muted for log sinks: the two events `shouldDropNoisyWrite`
    /// drops (WRITE + modified-CLOSE). CREATE/RENAME/UNLINK stay live so a
    /// drop→execute chain under a log dir still forms from CREATE + EXEC.
    static let logSinkMutedEventTypes: [es_event_type_t] = [
        ES_EVENT_TYPE_NOTIFY_WRITE,
        ES_EVENT_TYPE_NOTIFY_CLOSE,
    ]

    /// Pure builder: the fixed system log dirs plus each supplied user home's
    /// `~/Library/Logs/` (where app-log floods land). Split out so the path logic
    /// is unit-testable without a live ES client — mirrors
    /// `forensicCopyMuteTargetPrefixes`.
    static func logSinkMuteAllTargetPrefixes(userHomes: [String]) -> [String] {
        var prefixes = logSinkMuteTargetPrefixes
        for home in userHomes {
            let trimmed = home.hasSuffix("/") ? String(home.dropLast()) : home
            prefixes.append(trimmed + "/Library/Logs/")
        }
        return prefixes
    }

    // MARK: - Credential-read allowlist (v1.17.4)
    //
    // The ONLY paths for which a NOTIFY_OPEN emits an Event. The OPEN stream
    // is enormous, so this tight allowlist is the load-bearing bound on what
    // reaches the detection pipeline — it mirrors the target paths of the
    // credential-read rules (crypto_wallet_data_access, token_files_accessed,
    // ai_tool_reads_ssh_keys, …) plus the canonical secret locations. Keep it
    // tight; broadening it re-introduces the firehose. Pure + unit-tested
    // (isCredentialReadPath) even though ES delivery itself is live-only.
    static let credentialReadPathSubstrings: [String] = [
        "/.ssh/",
        "/.aws/credentials", "/.aws/config",
        "/.config/gcloud/credentials", "/.config/gcloud/access_tokens",
        "/.config/gcloud/application_default_credentials.json",
        "/.azure/accessTokens", "/.azure/msal_token_cache",
        "/.azure/azureProfile.json",
        "/.kube/config", "/.docker/config.json",
        "/.terraform.d/credentials", "/.config/gh/hosts.yml",
        "/.npmrc", "/.pypirc", "/.netrc", "/.gnupg/",
        // Stable HIGH sequence/single-event read rules. These rules used to
        // select `FileAction: close`, but ESCollector deliberately discards
        // unmodified CLOSE and therefore could only observe credential WRITES.
        // They now select the actual read signal (`open`), so every narrow
        // credential location they name must be admitted here.
        "/.gem/credentials", "/.cargo/credentials", "/.git-credentials",
        "/Library/Application Support/Firefox/Profiles/",
        "/Library/Application Support/Cookies/",
        "/MetaMask/", "/Phantom/", "/Coinbase Wallet/",
        // Exact default honeyfile names that do not otherwise resemble a
        // canonical credential path. Without these, EventEnricher never sees
        // their READ and cannot attach IsHoneyfile for the stable must-fire
        // deception rule. Deliberately filenames, not broad directories.
        "/Library/Application Support/Passwords.backup",
        "/Documents/passwords_backup.csv",
        "/.gcp-service-account.json.bak",
        "/.gitconfig.bak",
        "/Library/Keychains/",
        // v1.18 read-detection: the credential-read rules (safari/notes/password-
        // manager/shadow-hash) target these, so ES must emit NOTIFY_OPEN for them.
        // (Decision: maximum detection coverage — these rules were dead without it;
        // kept in sync by ESCredentialReadAllowlistTests.)
        "/Library/Safari/",                                   // safari_password_accessed, safari_history_accessed
        "/Library/Group Containers/group.com.apple.notes/",   // notes_database_access
        "/1Password/", "/Bitwarden/", ".kdbx",                // password_manager_db (1Password / Bitwarden / KeePass)
        "/var/db/dslocal/",                                   // shadow_hash_access + sensitive_file_read_untrusted (also matches /private/var/db/dslocal/)
        // Deception: any READ of a deployed decoy / honey-prompt is the
        // signal itself (MacCrab's own opens are muted via muteSelf, so a
        // hit here is always a third party). Rescues the critical
        // canary_skill_or_rules_read rule, dead until OPEN emission covered
        // this prefix. (Deployed $HOME honeyfiles at arbitrary paths still
        // need a manifest-sourced allowlist — tracked as a follow-up.)
        "Application Support/MacCrab/decoys/",
        // Native desktop wallets — full mirror of crypto_wallet_data_access.yml
        // selection_native_wallets (kept in sync by ESCredentialReadAllowlistTests).
        "Application Support/Electrum/wallets/",
        "Application Support/Exodus/exodus.wallet/",
        "Application Support/Atomic/Local Storage/",
        "Application Support/Coinomi/",
        "Application Support/Daedalus/",
        "Application Support/monero-project/",
        "Application Support/Trezor Suite/",
        "Application Support/Ledger Live/",
        "Library/Containers/io.trezor.TrezorSuite/",
        "/.ethereum/keystore/",
        // Browser-extension wallet storage (specific extension ids) — full
        // mirror of selection_browser_extension_wallets.
        "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn",  // MetaMask
        "/Local Extension Settings/bfnaelmomeimhlpmgjnjophhpkkoljpa",  // Phantom (Solana)
        "/Local Extension Settings/hnfanknocfeofbddgcijnmhnfnkdnaad",  // Coinbase Wallet
        "/Local Extension Settings/fhbohimaelbohpjbbldcngcnapndodjp",  // Binance Chain Wallet
        "/Local Extension Settings/egjidjbpglichdcondbcbdnbeeppgdph",  // Trust Wallet
        "/Local Extension Settings/lmenefjjbnabbnchedhpaichpfphndbg",  // WalletConnect
        "/Local Extension Settings/efbglgofoippbgcjepnhiblaibcnclgk",  // MetaMask Flask (dev)
    ]

    /// Sensitive filenames whose parent is not safely expressible as one broad
    /// substring. Suffix matching keeps the OPEN admission surface narrow:
    /// `.env` secrets are intentional stable coverage, while Messages/TCC use
    /// their full canonical suffixes. Chrome Login Data additionally requires
    /// its browser-profile parent in `isCredentialReadPath` below.
    static let credentialReadPathSuffixes: [String] = [
        "/.env", "/.env.local", "/.env.production", "/.env.staging",
        "/TCC.db",
        "/Library/Messages/chat.db",
        "/Library/Messages/chat.db-shm",
        "/Library/Messages/chat.db-wal",
        "/.gitconfig",
    ]

    private static let chromeLoginDataSuffixes: [String] = [
        "/Login Data", "/Login Data-journal", "/Login Data For Account",
    ]

    /// True iff `path` is a credential/secret location worth emitting an OPEN
    /// (read) event for. The hot-path early-out for NOTIFY_OPEN.
    static func isCredentialReadPath(_ path: String) -> Bool {
        for substring in credentialReadPathSubstrings where path.contains(substring) {
            return true
        }
        for suffix in credentialReadPathSuffixes where path.hasSuffix(suffix) {
            return true
        }
        if path.contains("/Google/Chrome/") {
            for suffix in chromeLoginDataSuffixes where path.hasSuffix(suffix) {
                return true
            }
        }
        return false
    }

    // MARK: - Agent-content read allowlist (Phase-5 injection-evidence weld)
    //
    // The credential allowlist above emits OPENs for SECRET reads. This second,
    // equally-tight allowlist emits OPENs for reads of AGENT-CONTENT files —
    // skills / hooks / MCP+project config / CI workflows — i.e. the files an AI
    // coding agent *consumes as instructions*. Before this, a poisoned SKILL.md
    // or `.claude/settings.json` that the agent READ produced ZERO events (the
    // 14 FileContent rules fire on WRITES; a pure read never modifies, so
    // NOTIFY_CLOSE was dropped and NOTIFY_OPEN was credential-only). That read is
    // the load-bearing observation the injection-evidence retro-scan pivots on
    // (InjectionEvidenceWeld): the emitted OPEN row records the PATH; the file's
    // content is re-read on demand at trigger time (sidestepping storage
    // truncation), so we only need the path here.
    //
    // These paths mirror FileContentEnricher's agentContentRoots/agentConfigFiles
    // (kept in sync by ESCredentialReadAllowlistTests). They change rarely and
    // are read roughly once per session — far below the credential firehose, so
    // the ES queue bound is preserved. Substring roots + config-file suffixes,
    // both cheap and applied in the NOTIFY_OPEN hot-path guard BEFORE the
    // heap-allocating processFromESProcess build.
    static let agentContentReadPathSubstrings: [String] = [
        "/.claude/skills/", "/.codex/skills/", "/.cursor/skills/",
        "/.claude/scripts/", "/.claude/hooks/", "/.claude/agents/",
        "/.github/workflows/",
    ]
    /// Agent-content CONFIG files matched by suffix (a poisoned MCP / project /
    /// settings config the agent reads). Mirrors FileContentEnricher.agentConfigFiles.
    static let agentConfigReadFileSuffixes: [String] = [
        "/.claude/claude_desktop_config.json", "/.claude.json", "/.cursor/mcp.json",
        "/.continue/config.json", "/.vscode/mcp.json", "/.windsurf/mcp.json",
        "/.claude/settings.json", "/.claude/project.json", "/.claude/local.json",
    ]

    /// True iff `path` is an agent-content file (skill / hook / config / workflow)
    /// whose READ is worth emitting an OPEN event for. The second hot-path
    /// early-out for NOTIFY_OPEN, alongside `isCredentialReadPath`.
    static func isAgentContentReadPath(_ path: String) -> Bool {
        for substring in agentContentReadPathSubstrings where path.contains(substring) {
            return true
        }
        for suffix in agentConfigReadFileSuffixes where path.hasSuffix(suffix) {
            return true
        }
        return false
    }

    /// True iff `path` is an on-disk keychain database the keychain read-rules
    /// target (`/Keychains/…(.keychain-db|.keychain)`). Used to drop the
    /// high-frequency platform-binary (securityd / Security.framework) opens at
    /// emission so the credential allowlist stays a tight firehose bound —
    /// those rules only flag NON-Apple openers anyway. (ES-OPEN-5)
    static func isKeychainPath(_ path: String) -> Bool {
        return path.contains("/Keychains/")
            && (path.hasSuffix(".keychain-db") || path.hasSuffix(".keychain"))
    }

    // MARK: - Write-family hot-path noise guard (v1.21.4 Phase-7)
    //
    // The NOTIFY_WRITE firehose is dominated by benign, high-frequency LOG
    // writers (measured on-device: ~3800 writes / 2 min, ~3200 of them
    // `suricata` appending to /var/log/suricata/*). Unlike NOTIFY_OPEN, the
    // write family had NO hot-path guard, so every such write paid the full
    // heap-allocating processFromESProcess build (lineage/codesig) AND ran the
    // whole 5-tier detection pipeline. This guard mirrors the OPEN credential
    // allowlist: a cheap suffix/substring check on the TARGET path BEFORE
    // processFromESProcess, so provably-irrelevant log-sink writes cost almost
    // nothing and never enter the pipeline.
    //
    // SAFETY — why dropping these loses no detection (verified against the
    // shipped rule corpus + downstream consumers):
    //  * The drop set is ONLY well-known append-only LOG SINKS (`*.log`, and
    //    writes under /var/log, /private/var/log, /Library/Logs). No sequence or
    //    graph rule predicates on any of these as a file-WRITE target, and the one
    //    single-event rule that mentions /var/log (defense_evasion/log_deletion) is
    //    a process_creation rule firing on the `rm`/`truncate` EXEC, not a write.
    //    v1.21.4 review CORRECTION (L1): the earlier blanket "NO single-event rule
    //    predicates on these" was INACCURATE — supply_chain/node_process_writes_to_
    //    system_dirs matches file_event with TargetFilename|startswith ['/Library/',
    //    '/System/'] and no FileAction filter, so it predicates on writes to any
    //    /Library/ path, a superset of /Library/Logs. The residual is bounded and
    //    accepted: (a) a FRESH drop still emits NOTIFY_CREATE (not muted → the rule
    //    still fires on new-file drops); only an OVERWRITE of a pre-existing file
    //    under /Library/Logs loses its event; (b) that rule is status:experimental,
    //    so it is DISABLED under the default `stable` profile and this only manifests
    //    under `rule_profile: all`; (c) writing system /Library/Logs needs admin.
    //    The /var/log firehose win is worth this narrow, documented gap.
    //  * The only file-WRITE signal behavioral scoring consumes is a write to
    //    /LaunchAgents/ or /LaunchDaemons/ (EventLoop) — neither is a log sink.
    //  * StatisticalAnomaly tracks process event-frequency/argc/entropy only (its
    //    file-write-rate field was removed as orphaned) and UEBA is process-only,
    //    so no volume-based detector loses a threat: dropping benign log noise can
    //    only REDUCE false positives, never mask an attack (an attacker's payload
    //    writes land on non-log paths, which are KEPT).
    //  * Deliberately NARROWER than "log/cache/tmp": /Library/Caches, /private/tmp
    //    and /var/folders are EXCLUDED because rules DO predicate on them as
    //    malware drop/staging locations. Only true log sinks are dropped.
    //  * KEEP overrides (err on the side of keeping) below: even a log-sink path
    //    is kept when it is also a credential/wallet file (a wallet leveldb
    //    `*.log`), an agent-content file, or a code drop (script/dylib/…).
    //  * Residual (documented): a payload deliberately named `*.log` (or dropped
    //    under a log dir) has its WRITE event dropped. Its interaction with the
    //    cross-process write→execute chain (CrossProcessCorrelator, whose 2-PID
    //    file chain was un-masked in this same v1.21.4 release) is:
    //      - FRESH drop (create+write+execute): NOTIFY_CREATE is NOT guarded, so
    //        the chain still forms as {create, execute} and STILL FIRES — at
    //        .medium (computeFileSeverity requires a "write"/"download" action
    //        for .high, so losing the write leg degrades HIGH→MEDIUM, but does
    //        not suppress the alert). NOTIFY_EXEC also fires independently, and
    //        single-event exec rules + behavioral scoring see the execution.
    //      - OVERWRITE of a PRE-EXISTING executable `*.log` file (write+execute,
    //        no create): {execute} alone → the cross-process chain does not form.
    //        This narrow case is the only genuine loss; the EXEC is still
    //        independently monitored (exec rules, behavior scoring). Not closed
    //        by adding "create" to the write-equivalent set: that would elevate
    //        legitimate install-then-run (mv/rename a binary into place, then
    //        execute) MEDIUM→HIGH — a worse FP trade than this contrived gap.
    //
    // Pure + unit-tested (ESWriteHotPathGuardTests); ES delivery itself is
    // live-only, exactly like isCredentialReadPath.

    /// Executable/script/dylib/bundle write-target suffixes — a WRITE to code is
    /// detection-relevant (dropper/loader staging) and is KEPT even under a log
    /// root. Suffix match (cheap); Mach-O binaries have no canonical suffix and
    /// are covered by the CREATE/EXEC paths instead (see the residual note).
    static let codeWriteSuffixes: [String] = [
        ".dylib", ".so", ".sh", ".bash", ".zsh", ".command",
        ".py", ".pl", ".rb", ".php", ".js", ".mjs", ".cjs",
        ".jar", ".scpt", ".applescript", ".plist",
    ]

    /// True iff `path` is a code/script/config drop we keep regardless of
    /// location (suffix match plus bundle/framework/kext interiors).
    static func isCodeWritePath(_ path: String) -> Bool {
        for suffix in codeWriteSuffixes where path.hasSuffix(suffix) { return true }
        return path.contains(".app/") || path.contains(".framework/") || path.contains(".kext/")
    }

    /// True iff `path` is a well-known append-only LOG SINK — the ONLY write
    /// targets eligible for the noise drop. Tight by construction: `*.log` files
    /// plus writes under the system/daemon/app log directories (where suricata &
    /// friends append). Everything else returns false ⇒ KEPT. Note `/var/log/`
    /// as a substring also covers `/private/var/log/`.
    static func isLogSinkWritePath(_ path: String) -> Bool {
        if path.hasSuffix(".log") { return true }
        if path.contains("/var/log/") { return true }
        if path.contains("/Library/Logs/") { return true }
        return false
    }

    /// The write-family hot-path drop decision: `true` ⇒ this NOTIFY_WRITE /
    /// modified-CLOSE is provably-irrelevant log noise and may be dropped BEFORE
    /// processFromESProcess. Conservative: only log sinks are eligible, and a
    /// log-sink path is still KEPT if it is a credential/wallet, agent-content,
    /// or code drop. Default is KEEP.
    /// True when a chmod's resulting mode can confer the ability to RUN or to
    /// ESCALATE — the only two properties a SETMODE event can establish that
    /// any detection acts on.
    ///
    /// - execute for any of user/group/other: the `chmod +x` half of the
    ///   download → chmod → execute chain.
    /// - setuid / setgid: privilege gain regardless of execute bits, so they are
    ///   tested independently rather than folded into the execute mask.
    ///
    /// The sticky bit is deliberately excluded: it restricts deletion within a
    /// directory and confers no capability on the caller.
    static func modeGrantsExecutionOrEscalation(_ mode: UInt32) -> Bool {
        let executeAny = UInt32(S_IXUSR | S_IXGRP | S_IXOTH)
        let escalation = UInt32(S_ISUID | S_ISGID)
        return (mode & (executeAny | escalation)) != 0
    }

    static func shouldDropNoisyWrite(path: String) -> Bool {
        guard isLogSinkWritePath(path) else { return false }   // not a log sink ⇒ KEEP
        if isCredentialReadPath(path) { return false }         // wallet leveldb *.log, etc.
        if isAgentContentReadPath(path) { return false }
        if isCodeWritePath(path) { return false }
        return true                                            // provable log noise ⇒ DROP
    }

    // MARK: - Callback-to-worker admission

    /// Decide whether an ES message that the normaliser would discard can be
    /// discarded *before* it consumes one of the bounded worker's in-flight
    /// slots. This is the same set of cheap, detection-preserving predicates
    /// enforced again in `normalise(message:)` as defence in depth.
    ///
    /// This placement matters: filtering only inside the serial worker still
    /// lets the system-wide OPEN and unmodified-CLOSE firehoses fill all 4,096
    /// retained-message slots. Live rc.2 telemetry reproduced exactly that
    /// failure: 23,097 callback-to-worker drops in 65 seconds, of which 22,960
    /// were OPEN/CLOSE, while both downstream merged-stream drop counters were
    /// zero. Those discarded messages never reached any detection engine.
    ///
    /// Pure and internal so tests can pin callback admission to the normaliser's
    /// allowlists without constructing an `es_message_t`.
    static func shouldDropBeforeWorker(
        eventType: UInt32,
        path: String? = nil,
        closeModified: Bool = true,
        isPlatformBinary: Bool = false,
        protection: Int32 = 0,
        mode: UInt32 = 0,
        processID: Int32? = nil,
        dynamicAIRegistry: FileEventInterestPolicyRegistry = dynamicAIFileInterestRegistry
    ) -> Bool {
        switch eventType {
        case ES_EVENT_TYPE_NOTIFY_SETMODE.rawValue:
            // v1.21.7: SETMODE fell through `default: return false`, so EVERY
            // chmod on the host was admitted. Measured on an installed rc.7
            // host: 35% of all stored events — the single largest category,
            // ahead of open (21%) — and overwhelmingly `python3.12` setting
            // 0600/0644 on files it had just created under
            // /private/var/folders/…/T/. That is a build tool tidying its own
            // temp files, retained at ~1,400 events/sec.
            //
            // Keep the chmod that carries security meaning and drop the rest.
            // The detections that rely on SETMODE are the ones where a mode
            // change confers the ability to run or to escalate: `chmod +x` on a
            // dropped payload (download → chmod +x → execute, the standard
            // macOS infostealer chain) and setuid/setgid. A mode change that
            // grants neither cannot enable execution or privilege gain, so no
            // rule in the corpus can act on it.
            //
            // Deliberately mode-based, not path-based: an allowlist of temp
            // directories would drop `chmod +x /tmp/payload`, which is the exact
            // event most worth keeping. Malware writing to a temp directory is
            // the normal case, not the exception.
            return !modeGrantsExecutionOrEscalation(mode)

        case ES_EVENT_TYPE_NOTIFY_OPEN.rawValue:
            guard let path else { return true }
            // Keep the platform-keychain safe drop independent and FIRST: a
            // broad/unknown dynamic snapshot must not re-admit securityd's
            // constant own-keychain noise.
            if isPlatformBinary && isKeychainPath(path) { return true }
            if isCredentialReadPath(path) || isAgentContentReadPath(path) {
                return false
            }
            let facts = FileEventAdmissionFacts.endpointSecurity(
                path: path,
                fileAction: .open,
                eventAction: "open",
                eventType: .change,
                processID: processID,
                isPlatformBinary: isPlatformBinary
            )
            return !dynamicAIRegistry.shouldAdmit(facts)

        case ES_EVENT_TYPE_NOTIFY_CLOSE.rawValue:
            guard closeModified else { return true }
            return path.map(shouldDropNoisyWrite(path:)) ?? false

        case ES_EVENT_TYPE_NOTIFY_WRITE.rawValue:
            return path.map(shouldDropNoisyWrite(path:)) ?? false

        case ES_EVENT_TYPE_NOTIFY_GET_TASK_READ.rawValue,
             ES_EVENT_TYPE_NOTIFY_TRACE.rawValue,
             ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE.rawValue,
             ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED.rawValue:
            return isPlatformBinary

        case ES_EVENT_TYPE_NOTIFY_MMAP.rawValue,
             ES_EVENT_TYPE_NOTIFY_MPROTECT.rawValue:
            return (protection & PROT_WRITE) == 0 || (protection & PROT_EXEC) == 0

        default:
            return false
        }
    }

    /// Bridge a newly-observed AI root/descendant across the split ES clients:
    /// EXEC/FORK can be delivered on the process client concurrently with the
    /// new PID's first OPEN on the file client, before EventLoop has published
    /// the next complete tracker snapshot. Grant only direct AI roots or
    /// children of an already-attributed PID, and expire automatically if the
    /// process event is lost downstream.
    private static func bridgeDynamicAIProcessStart(
        message: UnsafePointer<es_message_t>
    ) {
        let msg = message.pointee
        let now = DispatchTime.now().uptimeNanoseconds
        let graceNanos: UInt64 = 2_000_000_000
        let (deadline, overflow) = now.addingReportingOverflow(graceNanos)
        let validUntil = overflow ? UInt64.max : deadline

        switch msg.event_type {
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            let target = msg.event.exec.target
            let processID = audit_token_to_pid(target.pointee.audit_token)
            let parentID = target.pointee.ppid
            let executable = esFileToPath(target.pointee.executable)
            if dynamicAIFileInterestRegistry.isKnownDynamicAIProcess(
                parentID,
                nowUptimeNanoseconds: now
            ) || sharedAIRegistry.isAITool(executablePath: executable) != nil {
                _ = dynamicAIFileInterestRegistry.grantDynamicAIGrace(
                    processID: processID,
                    validUntilUptimeNanoseconds: validUntil,
                    nowUptimeNanoseconds: now
                )
            }

        case ES_EVENT_TYPE_NOTIFY_FORK:
            let parentID = audit_token_to_pid(msg.process.pointee.audit_token)
            guard dynamicAIFileInterestRegistry.isKnownDynamicAIProcess(
                parentID,
                nowUptimeNanoseconds: now
            ) else { return }
            let childID = audit_token_to_pid(msg.event.fork.child.pointee.audit_token)
            _ = dynamicAIFileInterestRegistry.grantDynamicAIGrace(
                processID: childID,
                validUntilUptimeNanoseconds: validUntil,
                nowUptimeNanoseconds: now
            )

        default:
            break
        }
    }

    /// Extract only the fields required by `shouldDropBeforeWorker` while the
    /// borrowed ES message is valid on the callback boundary. Kept messages are
    /// still normalised on the worker; high-volume rejected messages are never
    /// retained or enqueued.
    private static func shouldDropBeforeWorker(
        message: UnsafePointer<es_message_t>
    ) -> Bool {
        let msg = message.pointee
        let eventType = msg.event_type.rawValue

        // This side effect is confined to process-start events and happens
        // before any file admission read. It never retains the borrowed ES
        // message and only swaps/updates bounded lock-backed callback state.
        bridgeDynamicAIProcessStart(message: message)

        switch msg.event_type {
        case ES_EVENT_TYPE_NOTIFY_OPEN:
            return shouldDropBeforeWorker(
                eventType: eventType,
                path: esFileToPath(msg.event.open.file),
                isPlatformBinary: msg.process.pointee.is_platform_binary,
                processID: audit_token_to_pid(msg.process.pointee.audit_token)
            )

        case ES_EVENT_TYPE_NOTIFY_CLOSE:
            guard msg.event.close.modified else {
                return shouldDropBeforeWorker(
                    eventType: eventType,
                    closeModified: false
                )
            }
            return shouldDropBeforeWorker(
                eventType: eventType,
                path: esFileToPath(msg.event.close.target),
                closeModified: true
            )

        case ES_EVENT_TYPE_NOTIFY_WRITE:
            return shouldDropBeforeWorker(
                eventType: eventType,
                path: esFileToPath(msg.event.write.target)
            )

        case ES_EVENT_TYPE_NOTIFY_GET_TASK_READ,
             ES_EVENT_TYPE_NOTIFY_TRACE,
             ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE,
             ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED:
            return shouldDropBeforeWorker(
                eventType: eventType,
                isPlatformBinary: msg.process.pointee.is_platform_binary
            )

        case ES_EVENT_TYPE_NOTIFY_MMAP:
            return shouldDropBeforeWorker(
                eventType: eventType,
                protection: msg.event.mmap.protection
            )

        case ES_EVENT_TYPE_NOTIFY_MPROTECT:
            return shouldDropBeforeWorker(
                eventType: eventType,
                protection: msg.event.mprotect.protection
            )

        case ES_EVENT_TYPE_NOTIFY_SETMODE:
            return shouldDropBeforeWorker(
                eventType: eventType,
                path: esFileToPath(msg.event.setmode.target),
                mode: UInt32(msg.event.setmode.mode)
            )

        default:
            return false
        }
    }

    /// Enrichment keys describing the TARGET of an actor->target introspection
    /// event (get_task_read / trace / remote_thread_create). Keys are the exact
    /// Sigma field names so RuleEngine.resolveField resolves them via its
    /// enrichment passthrough — no model or engine change. `TargetIsSelf` and
    /// `SameTeam` are the cheap FP gates rules use in place of the
    /// not-yet-implemented |fieldref modifier.
    static func introspectionEnrichments(actor: ProcessInfo, target: ProcessInfo) -> [String: String] {
        let actorTeam = actor.codeSignature?.teamId ?? ""
        let targetTeam = target.codeSignature?.teamId ?? ""
        let sameTeam = !actorTeam.isEmpty && actorTeam == targetTeam
        return [
            "TargetImage": target.executable,
            "TargetProcessName": target.name,
            "TargetSignerType": target.codeSignature?.signerType.rawValue ?? "unknown",
            "TargetPid": String(target.pid),
            "TargetIsSelf": actor.pid == target.pid ? "true" : "false",
            "SameTeam": sameTeam ? "true" : "false",
        ]
    }

    /// v1.21.4: enrichment keys describing a BTM (Background Task Management)
    /// launch-item registration, emitted alongside NOTIFY_BTM_LAUNCH_ITEM_ADD.
    /// Keys are the exact Sigma field names the persistence rules match, resolved
    /// through RuleEngine's enrichment passthrough — no model or engine change.
    /// The instigator's identity (Image / SignerType / team) is already carried
    /// on `event.process`, so this describes only the ITEM and the app it is
    /// attributed to. Pure and synthesizable (raw es_message_t can't be built in
    /// a unit test), mirroring `introspectionEnrichments` as the testable seam.
    static func btmEnrichments(
        itemType: es_btm_item_type_t,
        legacy: Bool,
        managed: Bool,
        executablePath: String,
        itemURL: String,
        appURL: String,
        app: ProcessInfo?
    ) -> [String: String] {
        return [
            "BTMItemType": btmItemTypeName(itemType),
            "BTMLegacy": legacy ? "true" : "false",
            "BTMManaged": managed ? "true" : "false",
            "BTMExecutablePath": executablePath,
            "BTMItemURL": itemURL,
            "BTMAppURL": appURL,
            "BTMAppSignerType": app?.codeSignature?.signerType.rawValue ?? "unknown",
            "BTMAppTeamId": app?.codeSignature?.teamId ?? "",
        ]
    }

    /// Stable lowercase token for the ES BTM item-type enum, used verbatim as the
    /// `BTMItemType` rule value. C enums aren't exhaustive in Swift, so the
    /// `default` covers any future ES item type.
    static func btmItemTypeName(_ itemType: es_btm_item_type_t) -> String {
        switch itemType {
        case ES_BTM_ITEM_TYPE_USER_ITEM:  return "user_item"
        case ES_BTM_ITEM_TYPE_APP:        return "app"
        case ES_BTM_ITEM_TYPE_LOGIN_ITEM: return "login_item"
        case ES_BTM_ITEM_TYPE_AGENT:      return "agent"
        case ES_BTM_ITEM_TYPE_DAEMON:     return "daemon"
        default:                          return "unknown"
        }
    }

    // MARK: - Initialisation

    /// Creates a new ES client, subscribes to events, and begins emitting
    /// `Event` values on the `events` stream.
    ///
    /// - Throws: `ESCollectorError` if the client cannot be created.
    public init(
        subscribeFileOpen: Bool = true,
        subscribeIntrospection: Bool = true,
        subscribeMemoryProtection: Bool = true,
        workerMaxInFlight: Int = ESCollector.maxInFlightMessages
    ) throws {
        // Compile/seed callback demand on the setup thread. The first kernel
        // OPEN must never pay static-initialisation or policy-compilation cost.
        _ = Self.dynamicAIFileInterestRegistry
        self.subscribeFileOpen = subscribeFileOpen
        self.subscribeIntrospection = subscribeIntrospection
        self.subscribeMemoryProtection = subscribeMemoryProtection
        // Clamp the operator knob: below ~256 a single burst evicts the lineage
        // reserve; above 64K the retained-message memory is no longer "tens of MB".
        self.workerMaxInFlight = max(256, min(65_536, workerMaxInFlight))
        // Build the AsyncStream and capture the continuation so the
        // ES callback can yield events into it.
        //
        // v1.18 Stability: bound this stream. It is the HIGHEST-volume
        // collector source and was the only one left on the default
        // `.unbounded` policy — so a bursty execve storm (package install,
        // build, CI) with a momentarily-delayed consumer could grow the
        // buffer without limit (the unbounded-memory failure the bounded
        // traceBindings stream below and the 100K merged stream in
        // DaemonState already guard against). Newest-wins eviction at 100K
        // drops the OLDEST events under extreme flood rather than the host.
        var capturedContinuation: AsyncStream<Event>.Continuation!
        self.events = AsyncStream<Event>(
            bufferingPolicy: .bufferingNewest(Self.eventStreamCapacity)
        ) { continuation in
            capturedContinuation = continuation
        }
        self.continuation = capturedContinuation

        // v1.9 trace bindings stream. We always create the stream — its
        // continuation is captured but only fed when the feature flag
        // is on, so consumers that don't care can iterate without
        // observing any items.
        //
        // v1.9 PR-5 audit Stability-H1: bound the buffer. Default is
        // .unbounded which can grow without limit on bursty execve
        // (package installs, builds, CI runs) if the consumer Task is
        // delayed. Newest-10K policy mirrors the merged event stream
        // in DaemonState (which uses 100K — bind/evict signals are
        // ~10× lower volume than full events, so 10K matches).
        var capturedTraceContinuation: AsyncStream<TraceBindingSignal>.Continuation!
        self.traceBindings = AsyncStream<TraceBindingSignal>(
            bufferingPolicy: .bufferingNewest(10_000)
        ) { continuation in
            capturedTraceContinuation = continuation
        }
        self.traceBindingContinuation = capturedTraceContinuation

        // v1.21.4 Phase-4 (Mitigation C): build the split ES clients. Each
        // `ESClientContext` constructs its OWN bounded off-thread worker
        // (capturing locals, not `self`) inside `makeClientContext`, so the
        // workers exist before their client's callback captures them.
        // `createClients()` also owns the graceful single-client fallback if the
        // second `es_new_client` fails.
        try createClients()
        muteNoisyPaths()
        muteSelf()
        try subscribe()
        lifecyclePhase = .running
        deliveryHealth.started()

        logger.info("ESCollector initialised — \(self.contexts.count) ES client(s), split_degraded=\(self.splitDegraded).")
    }

    deinit {
        stop()
    }

    // MARK: - Client Lifecycle

    // MARK: - v1.21.4 Phase-4 (Mitigation C) — the file/exec client split

    /// The flood-prone FILE family — the write family (CREATE/WRITE/CLOSE/RENAME/
    /// UNLINK) plus the OPEN firehose. This set is the SINGLE source of truth for
    /// the client split: `fileClientTypes`/`execClientTypes` partition the full
    /// subscription list on membership here (predicate P vs !P), so every
    /// subscribed type lands on exactly one client — union == full, intersection
    /// == ∅ — with no drift if a new type is added to `subscribedEvents` (it
    /// defaults to the exec client unless it is also added here). Keyed by
    /// `rawValue` for cheap Set membership.
    static let fileFamilyRawValues: Set<UInt32> = [
        ES_EVENT_TYPE_NOTIFY_CREATE.rawValue,
        ES_EVENT_TYPE_NOTIFY_WRITE.rawValue,
        ES_EVENT_TYPE_NOTIFY_CLOSE.rawValue,
        ES_EVENT_TYPE_NOTIFY_RENAME.rawValue,
        ES_EVENT_TYPE_NOTIFY_UNLINK.rawValue,
        ES_EVENT_TYPE_NOTIFY_OPEN.rawValue,
    ]

    /// v1.21.5 PERF: the subscribed types whose loss is UNRECOVERABLE — process
    /// lineage. Every other type describes an action BY a process we can still
    /// resolve later; drop an EXEC/FORK/EXIT and the parent chain that sequence
    /// rules, campaign detection and TraceGraph are built on has a permanent hole,
    /// and every downstream event attributed through that chain is mis-parented.
    ///
    /// Measured on-device: `es_copy_backpressure_dropped_total` reached 495,830
    /// against 3.66M messages (11.6%) — all of it MacCrab's own userspace
    /// backpressure (`es_kernel_dropped_total` was 0). Because the in-flight cap
    /// was one undifferentiated budget shared per client, a 77/s MPROTECT burst
    /// could evict the 7/s EXEC stream on the same worker. `ESMessageWorker`
    /// reserves the top slice of its budget for these types so that inversion
    /// cannot happen. Keyed by `rawValue` for cheap Set membership on the ES
    /// callback boundary.
    static let lineageCriticalRawValues: Set<UInt32> = [
        ES_EVENT_TYPE_NOTIFY_EXEC.rawValue,
        ES_EVENT_TYPE_NOTIFY_FORK.rawValue,
        ES_EVENT_TYPE_NOTIFY_EXIT.rawValue,
    ]

    /// The full pre-split subscription list — `subscribedEvents` plus the
    /// optional OPEN, introspection and memory-protection families. Used verbatim
    /// for the degraded single client AND as the domain that
    /// `fileClientTypes`/`execClientTypes` partition.
    ///
    /// v1.21.6 (PERF-02): `subscribeMemoryProtection` defaults to `true` so this
    /// still reproduces the pre-gate set byte-for-byte for any caller that does
    /// not opt in to the demand gate.
    static func fullSubscription(
        subscribeFileOpen: Bool,
        subscribeIntrospection: Bool,
        subscribeMemoryProtection: Bool = true
    ) -> [es_event_type_t] {
        var types = subscribedEvents
        if subscribeFileOpen { types.append(ES_EVENT_TYPE_NOTIFY_OPEN) }
        if subscribeMemoryProtection { types.append(contentsOf: memoryProtectionEvents) }
        if subscribeIntrospection { types.append(contentsOf: introspectionEvents) }
        return types
    }

    /// FILE client subscription: the members of the full list that are in the
    /// file family. Disjoint from `execClientTypes`; their union is the full set.
    static func fileClientTypes(
        subscribeFileOpen: Bool,
        subscribeIntrospection: Bool,
        subscribeMemoryProtection: Bool = true
    ) -> [es_event_type_t] {
        fullSubscription(subscribeFileOpen: subscribeFileOpen,
                         subscribeIntrospection: subscribeIntrospection,
                         subscribeMemoryProtection: subscribeMemoryProtection)
            .filter { fileFamilyRawValues.contains($0.rawValue) }
    }

    /// EXEC/PROCESS client subscription: everything in the full list NOT in the
    /// file family — process lineage (EXEC/FORK/EXIT), the (demand-gated)
    /// introspection and memory-protection families, and the low-volume
    /// SIGNAL/KEXTLOAD/BTM/SETOWNER/SETMODE set. Both demand-gated families land
    /// here (neither is in `fileFamilyRawValues`), which is why
    /// `applyOptionalSubscriptions` only has to touch the EXEC-carrying context.
    static func execClientTypes(
        subscribeFileOpen: Bool,
        subscribeIntrospection: Bool,
        subscribeMemoryProtection: Bool = true
    ) -> [es_event_type_t] {
        fullSubscription(subscribeFileOpen: subscribeFileOpen,
                         subscribeIntrospection: subscribeIntrospection,
                         subscribeMemoryProtection: subscribeMemoryProtection)
            .filter { !fileFamilyRawValues.contains($0.rawValue) }
    }

    /// Graceful-degradation decision (pure, so it is unit-testable without a live
    /// `es_client_t`): given the result of creating the SECOND (exec) client, do
    /// we fall back to a single all-types client? Any non-success ⇒ degrade —
    /// we never run with half the events.
    static func shouldDegradeToSingleClient(secondClientResult: es_new_client_result_t) -> Bool {
        secondClientResult != ES_NEW_CLIENT_RESULT_SUCCESS
    }

    /// Merge per-type count maps from every context's tracker into one. The split
    /// clients cover DISJOINT type sets, so this is a union; a shared key (the
    /// degraded single client, or defensively) sums. Pure so the read-path merge
    /// is unit-testable without a live `es_client_t`.
    static func mergeCountMaps(_ maps: [[UInt32: UInt64]]) -> [UInt32: UInt64] {
        var merged: [UInt32: UInt64] = [:]
        for m in maps { for (k, v) in m { merged[k, default: 0] &+= v } }
        return merged
    }

    /// Map an `es_new_client` failure code to a typed error (extracted so both
    /// the first-client and degraded-fallback paths report identically).
    private static func mapClientError(_ result: es_new_client_result_t) -> ESCollectorError {
        switch result {
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:    return .notRunningAsRoot
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:     return .missingEntitlement
        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS: return .tooManyClients
        default:                                        return .clientCreationFailed(result)
        }
    }

    /// Build an `ESClientContext` (fresh tracker + its OWN bounded off-thread
    /// worker) for `types`. The worker closures capture LOCALS (the shared
    /// continuations + this context's own tracker), never `self`, so this is safe
    /// to call before `init` completes — mirroring the old inline worker build.
    /// `canary` is non-nil only for the context that carries EXEC; it is STORED
    /// on the returned context (not captured by the worker) so the D3 recognizer
    /// runs at the ES callback boundary in `openClient`, not downstream.
    private static func makeClientContext(
        label: String,
        types: [es_event_type_t],
        canary: ESCanaryRegistry?,
        continuation: AsyncStream<Event>.Continuation,
        traceContinuation: AsyncStream<TraceBindingSignal>.Continuation,
        deliveryTelemetry: EventCollectorBufferTelemetry,
        logger: Logger,
        maxInFlight: Int,
        reservesLineageSlots: Bool = true
    ) -> ESClientContext {
        let tracker = ESSeqTracker()
        let worker = ESMessageWorker(
            maxInFlight: maxInFlight,
            label: "com.maccrab.es.message-worker.\(label)",
            reservesLineageSlots: reservesLineageSlots,
            process: { handle in
                // Peek at the boxed context WITHOUT consuming the retain (the
                // `free` closure consumes it exactly once). Never frees here.
                let box = Unmanaged<ESPendingMessage>.fromOpaque(handle).takeUnretainedValue()
                ESCollector.processRetained(
                    box,
                    continuation: continuation,
                    traceContinuation: traceContinuation,
                    deliveryTelemetry: deliveryTelemetry,
                    tracker: tracker,
                    logger: logger
                )
            },
            free: { handle in
                // Consume the box's retain (deallocs ESPendingMessage) and release
                // the kernel message. Called EXACTLY ONCE per handle on every
                // worker path (processed / over-bound drop / shutdown drain).
                let box = Unmanaged<ESPendingMessage>.fromOpaque(handle).takeRetainedValue()
                es_release_message(box.message)
            }
        )
        return ESClientContext(label: label, subscribedTypes: types, tracker: tracker, worker: worker, canary: canary)
    }

    /// Wrap `makeClientContext` with this collector's captured continuations.
    private func makeContext(label: String, types: [es_event_type_t], canary: ESCanaryRegistry?, reservesLineageSlots: Bool = true) -> ESClientContext {
        Self.makeClientContext(
            label: label,
            types: types,
            canary: canary,
            continuation: continuation!,
            traceContinuation: traceBindingContinuation!,
            deliveryTelemetry: deliveryTelemetry,
            logger: logger,
            maxInFlight: workerMaxInFlight,
            reservesLineageSlots: reservesLineageSlots
        )
    }

    /// Create an `es_client_t` for `context`, installing a callback that does the
    /// MINIMUM on the callback boundary (D1 seq accounting + retain + hand-off to
    /// this context's OWN worker) and returns immediately. On success stores the
    /// handle on the context. Returns the raw `es_new_client` result so the
    /// caller can decide split-vs-degrade.
    private func openClient(for context: ESClientContext) -> es_new_client_result_t {
        // A fresh es_client_t restarts kernel seq_num/global_seq_num at 0, so
        // clear this context's accountant before its first message or a (re)create
        // would be miscounted as a giant backward gap (D1).
        context.tracker.reset()
        let tracker = context.tracker
        let worker = context.worker
        // v1.21.4 Phase-2 (D3) FIX: the coverage-canary recognizer runs HERE, at
        // the true ES callback boundary, so "seen at callback" means the kernel
        // DELIVERED the probe exec — not that it survived the async hand-off +
        // parse downstream. Non-nil only on the EXEC-carrying context.
        let canary = context.canary

        var newClient: OpaquePointer?   // es_client_t*
        let result = es_new_client(&newClient) { _, message in
            // SAFETY / LIFETIME: both split clients are NOTIFY-ONLY — every
            // subscribed type is ES_EVENT_TYPE_NOTIFY_* (the file family, the
            // process/exec family, OPEN, and the introspection family). There is
            // NO AUTH subscription and NO `es_respond` anywhere in this file, so
            // returning from the callback BEFORE the message is processed is safe
            // — there is no AUTH deadline to satisfy. The kernel owns `message`
            // and it is valid only for THIS callback unless retained;
            // `es_retain_message` extends its lifetime across the hand-off and the
            // worker's `free` closure calls `es_release_message` EXACTLY ONCE.
            //
            // D1 kernel-drop accounting stays on the boundary: seq_num (per-type)
            // and global_seq_num (per-CLIENT — now per split queue) are
            // kernel-assigned BEFORE delivery, so the gap accounting must happen
            // here, once per delivered message, in delivery order. Both fields are
            // present at the 13.0 deploy floor (seq_num v≥2, global_seq_num v≥4).
            let startNanos = DispatchTime.now().uptimeNanoseconds
            let evType = message.pointee.event_type.rawValue
            tracker.record(
                eventType: evType,
                seqNum: message.pointee.seq_num,
                globalSeq: message.pointee.global_seq_num,
                callbackUptimeNanoseconds: startNanos
            )
            // v1.21.4 Phase-2 (D3): coverage-canary recognizer, ON the callback
            // boundary (kernel delivery). Gated on `isArmed` (a single locked
            // `isEmpty`) so the per-exec argv walk only happens during the
            // ~seconds a probe is in flight — near-free otherwise. Reads the
            // live message synchronously within the callback (valid here), so no
            // retain is needed for it. Only the EXEC context has a canary.
            var canaryNonces: [String] = []
            if let canary = canary,
               evType == ES_EVENT_TYPE_NOTIFY_EXEC.rawValue,
               canary.isArmed {
                let args = argsFromExecMessage(message)
                canaryNonces = canary.noteExecIfCanary(commandLine: args.joined(separator: " "))
            }
            // D4 handler-entry timestamp — the worker measures end-to-end latency
            // (arrival → normalise-done, including queue wait) against it. Run
            // the normaliser-equivalent admission guard BEFORE retaining/enqueueing:
            // otherwise messages that can only be discarded still consume the
            // bounded worker and shed unrelated detection input under ordinary load.
            // OPEN/WRITE admission decodes one borrowed path token. Drain that
            // temporary at the callback boundary; the worker's autorelease pool
            // is never entered for messages intentionally rejected here.
            let rejectedBeforeWorker = autoreleasepool {
                ESCollector.shouldDropBeforeWorker(message: message)
            }
            if rejectedBeforeWorker {
                // Preserve the `es_processed_by_type` denominator, but do not
                // flood the callback→worker latency histogram with near-zero
                // samples from messages that intentionally never entered that
                // worker. Otherwise the OPEN/CLOSE majority would mask p99
                // backlog on the smaller detection-relevant retained set.
                tracker.recordFilteredBeforeWorker(eventType: evType)
                return
            }
            es_retain_message(message)
            let box = ESPendingMessage(message: message, startNanos: startNanos, eventType: evType)
            // The sighting above proves KERNEL DELIVERY only. If the worker then
            // refuses this exact message at its in-flight cap, the probe can
            // never reach events.db — and the two-point verdict would blame the
            // store/eviction stage for a loss that happened here, at the ingest
            // hand-off. Record the third point against the message we just lost.
            let accepted = worker.submit(
                UnsafeRawPointer(Unmanaged.passRetained(box).toOpaque()),
                lineageCritical: ESCollector.lineageCriticalRawValues.contains(evType),
                eventType: evType
            )
            if !accepted, let canary = canary { canary.noteDroppedAtHandoff(canaryNonces) }
        }
        if result == ES_NEW_CLIENT_RESULT_SUCCESS {
            context.client = newClient
        }
        return result
    }

    /// Drain a context's worker (frees every retained ES message via
    /// `es_release_message`) THEN delete its client — the strict
    /// release-before-delete ordering. Safe on a context whose client was never
    /// created (drains the empty worker only). Used both by graceful degradation
    /// and by `stop()`. Idempotent (drain is idempotent; delete is guarded).
    private func teardownContext(_ context: ESClientContext) {
        context.worker.shutdownAndDrain()
        if let client = context.client {
            es_delete_client(client)
            context.client = nil
            logger.info("ESCollector: \(context.label) ES client deleted.")
        }
    }

    /// Create the SPLIT ES clients — a FILE client (write-family + OPEN) and an
    /// EXEC/PROCESS client (everything else), each on its OWN `es_client_t` /
    /// kernel queue, so a file-write flood can no longer starve exec from a shared
    /// queue. If the SECOND (exec) client cannot be created (e.g.
    /// `ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS`), GRACEFULLY DEGRADE to a
    /// single client subscribing ALL types (the pre-split topology) with a loud
    /// warning + `splitDegraded = true`, rather than aborting or running with half
    /// the events. Failure of the FIRST client is fatal (same as the pre-split
    /// single-client failure — there is nothing to fall back to).
    private func createClients() throws {
        let fileTypes = Self.fileClientTypes(subscribeFileOpen: subscribeFileOpen,
                                             subscribeIntrospection: subscribeIntrospection,
                                             subscribeMemoryProtection: subscribeMemoryProtection)
        let execTypes = Self.execClientTypes(subscribeFileOpen: subscribeFileOpen,
                                             subscribeIntrospection: subscribeIntrospection,
                                             subscribeMemoryProtection: subscribeMemoryProtection)

        // The exec/process context carries the D3 canary — its EXEC events feed
        // the recognizer. The file context never sees EXEC, so it gets no canary.
        let fileCtx = makeContext(label: "file", types: fileTypes, canary: nil, reservesLineageSlots: false)
        let execCtx = makeContext(label: "exec", types: execTypes, canary: canaryRegistry, reservesLineageSlots: true)

        // FIRST client (file).
        let firstResult = openClient(for: fileCtx)
        guard firstResult == ES_NEW_CLIENT_RESULT_SUCCESS else {
            teardownContext(fileCtx)   // drains the (empty) worker; no client to delete
            teardownContext(execCtx)
            throw Self.mapClientError(firstResult)
        }

        // SECOND client (exec/process).
        let secondResult = openClient(for: execCtx)
        if !Self.shouldDegradeToSingleClient(secondClientResult: secondResult) {
            contexts = [fileCtx, execCtx]
            splitDegraded = false
            logger.info("ESCollector: split ES clients active — file(\(fileTypes.count) types) + exec(\(execTypes.count) types), separate kernel queues.")
            return
        }

        // GRACEFUL DEGRADATION: the second client failed. Tear down the partial
        // split (release the file client + drain both workers) so nothing leaks,
        // then run ONE client subscribing every type. A single kernel queue means
        // a file-write flood can again starve exec — hence the loud warning and
        // the heartbeat flag so the loss of the mitigation is never silent.
        logger.error("ESCollector: SECOND (exec) ES client creation FAILED (rc=\(secondResult.rawValue)) — DEGRADING to a single client subscribing ALL event types. File and exec now share one kernel queue; a file-write flood can starve exec. Heartbeat es_client_split_degraded=true.")
        teardownContext(fileCtx)
        teardownContext(execCtx)

        let allTypes = Self.fullSubscription(subscribeFileOpen: subscribeFileOpen,
                                             subscribeIntrospection: subscribeIntrospection,
                                             subscribeMemoryProtection: subscribeMemoryProtection)
        let unifiedCtx = makeContext(label: "unified", types: allTypes, canary: canaryRegistry, reservesLineageSlots: true)
        let unifiedResult = openClient(for: unifiedCtx)
        guard unifiedResult == ES_NEW_CLIENT_RESULT_SUCCESS else {
            teardownContext(unifiedCtx)
            throw Self.mapClientError(unifiedResult)
        }
        contexts = [unifiedCtx]
        splitDegraded = true
    }

    /// Subscribe each context's client to its OWN type list. In split mode the
    /// file client subscribes the file family and the exec client the rest; in
    /// degraded mode the single unified client subscribes all types.
    private func subscribe() throws {
        for context in contexts {
            guard let client = context.client else {
                throw ESCollectorError.notRunning
            }
            let result = context.subscribedTypes.withUnsafeBufferPointer { buffer -> es_return_t in
                es_subscribe(client, buffer.baseAddress!, UInt32(buffer.count))
            }
            if result != ES_RETURN_SUCCESS {
                logger.error("es_subscribe failed for \(context.label) client with code \(result.rawValue)")
                throw ESCollectorError.subscriptionFailed
            }
        }
    }

    /// v1.21.6 (PERF-02): re-point the two DEMAND-GATED subscription families at
    /// the live ruleset without restarting the engine. Called from the SIGHUP
    /// handler after `reloadRules`, so promoting an introspection rule — or
    /// setting `rule_profile: "all"` — takes effect on reload instead of leaving
    /// an ENABLED rule that can never fire.
    ///
    /// `es_subscribe` is ADDITIVE and `es_unsubscribe` removes, so both calls are
    /// idempotent; no per-family state is tracked here, which keeps the promise
    /// made on `contexts` (write-once, only ever drained) intact and avoids a new
    /// lock on a class the heartbeat reads concurrently. ES client calls are safe
    /// from any thread.
    ///
    /// Applied only to the context carrying NOTIFY_EXEC — the exec client in
    /// split mode, the unified client when degraded — because both gated families
    /// are partitioned there (neither is in `fileFamilyRawValues`).
    ///
    /// KNOWN GAP, stated rather than hidden: the 5 s `user_rules/.reload_tick`
    /// watcher in DaemonSetup reloads rules but cannot reach the collector, so a
    /// dashboard rule-enable needs a `pkill -HUP com.maccrab.agent` before ES
    /// actually delivers those events. The log lines below are how an operator
    /// sees which families are live.
    @discardableResult
    public func applyOptionalSubscriptions(introspection: Bool, memoryProtection: Bool) -> Bool {
        var applied = false
        var failed = false
        var toAdd: [es_event_type_t] = []
        var toRemove: [es_event_type_t] = []
        if introspection { toAdd += Self.introspectionEvents } else { toRemove += Self.introspectionEvents }
        if memoryProtection { toAdd += Self.memoryProtectionEvents } else { toRemove += Self.memoryProtectionEvents }

        for context in contexts {
            guard let client = context.client,
                  context.subscribedTypes.contains(where: { $0.rawValue == ES_EVENT_TYPE_NOTIFY_EXEC.rawValue })
            else { continue }
            applied = true
            if !toAdd.isEmpty {
                let rc = toAdd.withUnsafeBufferPointer { buf -> es_return_t in
                    es_subscribe(client, buf.baseAddress!, UInt32(buf.count))
                }
                if rc != ES_RETURN_SUCCESS {
                    failed = true
                    // LOUD, not fail-closed: the engine keeps running, but the
                    // detections that need this family are dark until restart.
                    logger.error("ESCollector: es_subscribe for demand-gated families FAILED on \(context.label) (rc=\(rc.rawValue)) — rules selecting those event actions cannot fire until the engine restarts")
                }
            }
            if !toRemove.isEmpty {
                let rc = toRemove.withUnsafeBufferPointer { buf -> es_return_t in
                    es_unsubscribe(client, buf.baseAddress!, UInt32(buf.count))
                }
                if rc != ES_RETURN_SUCCESS {
                    failed = true
                    logger.warning("ESCollector: es_unsubscribe for demand-gated families FAILED on \(context.label) (rc=\(rc.rawValue)) — an unconsumed firehose keeps costing CPU")
                }
            }
        }
        if applied && !failed {
            logger.notice("ESCollector demand-gated subscriptions now: introspection=\(introspection), memory_protection=\(memoryProtection)")
        } else {
            logger.error("ESCollector demand-gated subscription update was not fully applied")
        }
        return applied && !failed
    }

    /// Mute noisy paths to reduce kernel-to-userspace traffic. v1.21.4 Phase-4:
    /// with the split, mutes are PER-CLIENT (each kernel queue mutes
    /// independently), so the initiator-path mutes (noisy system binaries emit on
    /// BOTH channels) are applied to EVERY context to preserve the pre-split
    /// noise reduction. The forensic TARGET-mute is write-family only, so it is
    /// applied ONLY to the context that carries the file family (the file client
    /// in split mode, or the unified client in degraded mode).
    private func muteNoisyPaths() {
        for context in contexts {
            guard let client = context.client else { continue }

            for path in Self.mutedPathLiterals {
                let rc = es_mute_path_literal(client, path)
                if rc != ES_RETURN_SUCCESS {
                    logger.warning("Failed to mute path: \(path) on \(context.label)")
                }
            }

            // For prefix-based paths we use es_mute_path_prefix when available.
            // The function was introduced alongside es_mute_path_literal.
            for path in Self.mutedPaths {
                if path.hasSuffix("/") {
                    let rc = es_mute_path_prefix(client, path)
                    if rc != ES_RETURN_SUCCESS {
                        logger.warning("Failed to mute path prefix: \(path) on \(context.label)")
                    }
                } else {
                    let rc = es_mute_path_literal(client, path)
                    if rc != ES_RETURN_SUCCESS {
                        logger.warning("Failed to mute path literal: \(path) on \(context.label)")
                    }
                }
            }

            // v1.21.4 Phase-1 Mitigation A: mute MacCrab's own forensic-copy
            // destinations by TARGET prefix, write-family events only — so only on
            // the context that actually carries the file family. See the
            // "Observer-effect mute" section above for the design + caveats.
            let carriesFileFamily = context.subscribedTypes.contains {
                Self.fileFamilyRawValues.contains($0.rawValue)
            }
            if carriesFileFamily {
                muteForensicCopyTargets(client: client)
                // Kernel-level P1: drop the log-sink WRITE firehose before it
                // is ever delivered (strictly cheaper than the userspace drop).
                muteNoisyLogSinkWrites(client: client)
            }
        }
    }

    /// Suppress the write-family file-event storm generated when ANY process
    /// copies data INTO a MacCrab-owned directory (forensic DB snapshots,
    /// store/config writes) — the observer-effect fix. Uses target-path
    /// muting so it catches sibling-process copies that `muteSelf` (initiator
    /// muting) cannot. NOTIFY_OPEN is intentionally NOT muted so decoy reads
    /// still surface.
    private func muteForensicCopyTargets(client: OpaquePointer) {
        let prefixes = Self.forensicCopyMuteTargetPrefixes(userHomes: Self.realUserHomes())
        Self.forensicCopyMutedEventTypes.withUnsafeBufferPointer { eventsBuf in
            for prefix in prefixes {
                let rc = es_mute_path_events(
                    client,
                    prefix,
                    ES_MUTE_PATH_TYPE_TARGET_PREFIX,
                    eventsBuf.baseAddress!,
                    eventsBuf.count
                )
                if rc != ES_RETURN_SUCCESS {
                    logger.warning("Failed to target-mute forensic-copy prefix: \(prefix) (rc=\(rc.rawValue))")
                } else {
                    logger.info("ESCollector target-muted write-family events under \(prefix)")
                }
            }
        }
    }

    /// Kernel-mute the WRITE/CLOSE log-sink firehose by TARGET prefix — the
    /// kernel-level counterpart to `shouldDropNoisyWrite` (P1). Applied only to
    /// the file-family context (write/close ride there), so the suricata-class
    /// /var/log flood is never delivered to userspace. See the
    /// "Log-sink write firehose kernel mute" section for the safety argument.
    private func muteNoisyLogSinkWrites(client: OpaquePointer) {
        let prefixes = Self.logSinkMuteAllTargetPrefixes(userHomes: Self.realUserHomes())
        Self.logSinkMutedEventTypes.withUnsafeBufferPointer { eventsBuf in
            for prefix in prefixes {
                let rc = es_mute_path_events(
                    client,
                    prefix,
                    ES_MUTE_PATH_TYPE_TARGET_PREFIX,
                    eventsBuf.baseAddress!,
                    eventsBuf.count
                )
                if rc != ES_RETURN_SUCCESS {
                    logger.warning("Failed to kernel-mute log-sink write prefix: \(prefix) (rc=\(rc.rawValue))")
                } else {
                    logger.info("ESCollector kernel-muted WRITE/CLOSE under log sink \(prefix)")
                }
            }
        }
    }

    /// Mute events from our own process to avoid feedback loops.
    /// `argv[0]` is the *invoked* path (relative for sysext bundles —
    /// e.g. `com.maccrab.agent.systemextension`), but ES requires the
    /// absolute resolved executable path for `es_mute_path_literal`.
    /// Use `proc_pidpath` so muteSelf works under the sysext, the dev
    /// daemon, and any future Sparkle-relaunched binary path.
    private func muteSelf() {
        var pathBuf = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        let len = proc_pidpath(getpid(), &pathBuf, UInt32(pathBuf.count))
        guard len > 0 else {
            logger.warning("muteSelf: proc_pidpath returned \(len), errno \(errno) — daemon-self events will reach the pipeline")
            return
        }
        let selfPath = String(cString: pathBuf)
        guard !selfPath.isEmpty else {
            logger.warning("muteSelf: empty path from proc_pidpath")
            return
        }

        // v1.21.4 Phase-4: self-mute on EVERY context. The daemon initiates both
        // file events (store/config writes) and process events (its own
        // exec/fork), and the D3 canary's `env` intermediary relies on the EXEC
        // client's muteSelf, so both split clients need the initiator mute.
        for context in contexts {
            guard let client = context.client else { continue }
            let rc = es_mute_path_literal(client, selfPath)
            if rc != ES_RETURN_SUCCESS {
                logger.warning("Failed to self-mute \(context.label) at path \(selfPath) (rc=\(rc.rawValue))")
            } else {
                logger.info("ESCollector self-muted \(context.label) at \(selfPath)")
            }
        }
    }

    /// Tear down BOTH ES clients (or the single unified client in degraded mode)
    /// and finish the event stream.
    public func stop() {
        lifecycleCondition.lock()
        if lifecyclePhase == .stopped {
            lifecycleCondition.unlock()
            return
        }
        if lifecyclePhase == .stopping {
            while lifecyclePhase == .stopping {
                lifecycleCondition.wait()
            }
            lifecycleCondition.unlock()
            return
        }
        lifecyclePhase = .stopping
        lifecycleCondition.unlock()
        deliveryHealth.stop()

        // v1.21.4 Phase-4 (Mitigation C): symmetric teardown across every
        // context. `teardownContext` drains that context's off-thread worker
        // FIRST — so every retained ES message is released (via
        // `es_release_message`) BEFORE its client goes away, keeping every
        // release strictly ordered before `es_delete_client` — then deletes the
        // client. Each context's worker only ever holds its own client's
        // messages, so per-context teardown is correct regardless of order.
        // `shutdownAndDrain` and the nil-guarded delete make this idempotent; the
        // `contexts` array itself is NOT mutated, so concurrent heartbeat reads of
        // the (now-drained) trackers stay race-free.
        for context in contexts {
            teardownContext(context)
        }
        continuation?.finish()
        continuation = nil
        // v1.9.0 (audit Stab-M6): finish the side-channel continuation
        // too. Pre-fix it was left dangling at SIGTERM teardown — the
        // consumer Task in DaemonSetup blocked on it forever and was
        // only cleaned up by `exit(0)`. Symmetric with the main event
        // stream above.
        traceBindingContinuation?.finish()
        traceBindingContinuation = nil

        lifecycleCondition.lock()
        lifecyclePhase = .stopped
        lifecycleCondition.broadcast()
        lifecycleCondition.unlock()
    }

    /// Run the synchronous ES message/client drain on retained work and bound
    /// only the caller's wait. If a callback normaliser is uncooperative, false
    /// is returned while the retained teardown task continues owning `self` and
    /// the client handles until it really completes.
    @discardableResult
    public func stopAndJoin(deadline: TimeInterval = 1.0) async -> Bool {
        let teardown = Task.detached(priority: .utility) { [self] in
            stop()
        }
        let joined = await CollectorBoundedTaskJoin.waitForAll(
            [teardown],
            deadline: deadline
        )
        if !joined {
            logger.error("ESCollector stop deadline expired while retained messages or clients were still draining.")
        }
        return joined
    }

    // MARK: - v1.21.4 Phase-0 (D1 + D4) — telemetry-drop instrumentation

    // v1.21.4 Phase-4 (Mitigation C): every read-path accessor now MERGES across
    // the split contexts. The two clients cover DISJOINT type sets, so the
    // per-type map merges are unions; the scalar totals sum across queues.

    /// Per-event-type kernel-drop tally since the last client (re)create — the
    /// number of messages the kernel dropped for each type, measured as
    /// per-type `seq_num` gaps at the callback boundary (D1). Keyed by
    /// `es_event_type_t.rawValue`; render with `eventTypeName(_:)`. Merged across
    /// the split queues (disjoint type sets ⇒ a union): the FILE queue owns the
    /// write-family/OPEN drop counters, the EXEC queue owns NOTIFY_EXEC et al.
    public func esKernelDroppedByType() -> [UInt32: UInt64] {
        Self.mergeCountMaps(contexts.map { $0.tracker.droppedByType() })
    }

    /// Total kernel-drop count since the last client (re)create, measured as
    /// `global_seq_num` gaps (D1). NOTE: `global_seq_num` is PER-CLIENT, so with
    /// the file/exec split there is no single client-global number — this SUMS the
    /// per-queue global-drop tallies (the honest "total messages the kernel
    /// dropped across BOTH queues"). Pre-split (or degraded single-client) this is
    /// one client, so the sum degenerates to that single value.
    public func esGlobalDropped() -> UInt64 {
        contexts.reduce(UInt64(0)) { $0 &+ $1.tracker.globalDropped() }
    }

    /// Per-event-type messages accounted after copy admission (D4): retained-worker
    /// completions plus intentional pre-worker policy rejects. Copy-backpressure
    /// refusals are excluded and surfaced separately. Merged across queues.
    public func esProcessedByType() -> [UInt32: UInt64] {
        Self.mergeCountMaps(contexts.map { $0.tracker.processedByType() })
    }

    /// Per-event-type messages intentionally filtered at callback admission,
    /// before retained-worker submission. Merged across the split ES clients.
    public func esIntentionallyFilteredBeforeWorkerByType() -> [UInt32: UInt64] {
        Self.mergeCountMaps(
            contexts.map { $0.tracker.intentionallyFilteredBeforeWorkerByType() }
        )
    }

    /// Per-event-type normalized Events offered to the collector-local stream.
    /// Whether an offer evicted an older buffered event remains accounted by the
    /// collector delivery telemetry and is deliberately not folded into this map.
    public func esNormalizedYieldedByType() -> [UInt32: UInt64] {
        Self.mergeCountMaps(contexts.map { $0.tracker.normalizedYieldedByType() })
    }

    /// p99-estimate of END-TO-END message latency in microseconds (D4) — the
    /// leading indicator that rises before kernel drops appear. NOTE (v1.21.4):
    /// this is NOT the inline ES-callback wall-time. The interval is timed from
    /// `box.startNanos` (captured at the callback boundary) to the worker having
    /// finished `normalise`, so it INCLUDES the time the retained message waited
    /// in the worker's serial GCD queue plus normalise/trace-scan. The inline
    /// callback itself is O(1) (retain + one heap alloc + a non-blocking
    /// `queue.async`) and stays sub-millisecond; a high value here means worker
    /// BACKLOG, not a slow handler. Two independent per-queue histograms can't be
    /// merged into one true p99, so this reports the WORST (max) per-queue p99.
    /// Surfaced under the telemetry key `es_msg_e2e_latency_p99_us`.
    public func esHandlerP99Micros() -> UInt64 {
        contexts.map { $0.tracker.handlerP99Micros() }.max() ?? 0
    }

    /// Count of downstream AsyncStream `yield`s that came back `.dropped` (D4) —
    /// the userspace-backlog proxy. Summed across queues.
    public func esStreamYieldDropped() -> UInt64 {
        contexts.reduce(UInt64(0)) { $0 &+ $1.tracker.yieldDroppedTotal() }
    }

    /// v1.21.4 Phase-3 (Mitigation B): count of retained ES messages dropped at
    /// the copy/hand-off stage because a bounded off-thread worker was already at
    /// its in-flight cap (`maxInFlightMessages`). Surfaced as the heartbeat key
    /// `es_copy_backpressure_dropped_total` (wiring lives in `DaemonTimers`,
    /// alongside the D1/D4 keys). Summed across both per-client workers. This is
    /// honest userspace backpressure — a dropped-here message is COUNTED here,
    /// unlike a silent kernel drop.
    public func esCopyBackpressureDropped() -> UInt64 {
        contexts.reduce(UInt64(0)) { $0 &+ $1.worker.backpressureDropped() }
    }

    /// v1.21.6 (audit DET-05): the copy-stage drops broken out per ES event type,
    /// merged across both split clients — the counterpart to
    /// `esKernelDroppedByType()`. Surfaced as `es_copy_backpressure_dropped_by_type`.
    /// Without it a sustained 22%+ drop rate is a single opaque number, and there
    /// is no way to know whether the budget is being spent on the WRITE/CLOSE/OPEN
    /// firehose or on the exec events every rule tier depends on.
    public func esCopyBackpressureDroppedByType() -> [UInt32: UInt64] {
        Self.mergeCountMaps(contexts.map { $0.worker.backpressureDroppedByEventType() })
    }

    /// v1.21.4 Phase-4 (Mitigation C): true iff the file/exec client split could
    /// NOT be established (the second `es_new_client` failed) and the collector
    /// fell back to a single client subscribing ALL types (the pre-split
    /// topology). Surfaced as the heartbeat health flag `es_client_split_degraded`
    /// so the loss of the cross-channel mitigation is never silent. `false` on the
    /// normal two-client path.
    public func esClientSplitDegraded() -> Bool { splitDegraded }

    // MARK: - v1.21.4 Phase-2 (D3) coverage-canary probe

    /// Arm the recognizer for a live probe `nonce` — the timer task calls this
    /// immediately BEFORE `posix_spawn`ing `/usr/bin/true <nonce>`, so the
    /// callback is watching by the time the exec is delivered.
    public func armCanaryNonce(_ nonce: String) { canaryRegistry.arm(nonce) }

    /// Whether a probe `nonce` was observed at the ES callback boundary. `false`
    /// after the settle delay ⇒ the kernel/ingest stage dropped the probe.
    public func canarySeenAtCallback(_ nonce: String) -> Bool { canaryRegistry.seenAtCallback(nonce) }

    /// Whether a probe `nonce` reached the callback but was then refused at the
    /// callback→worker hand-off (the exec context's `ESMessageWorker` was at its
    /// in-flight cap). `true` means the loss happened in the ingest hand-off,
    /// NOT in the store/eviction path — the distinction the D3 verdict exists to
    /// make, and the one it got wrong for every hand-off drop.
    public func canaryDroppedAtHandoff(_ nonce: String) -> Bool { canaryRegistry.droppedAtHandoff(nonce) }

    /// Retire a probe `nonce` (found or not). Called from the timer's `defer` so
    /// the registry never accumulates stale nonces.
    public func disarmCanaryNonce(_ nonce: String) { canaryRegistry.disarm(nonce) }

    /// Human-readable name for an `es_event_type_t.rawValue`, used to key the
    /// heartbeat drop/processed maps (`NOTIFY_EXEC`, …) instead of a bare
    /// integer. Falls back to `TYPE_<raw>` for any type we don't subscribe to.
    public static func eventTypeName(_ raw: UInt32) -> String {
        switch raw {
        case ES_EVENT_TYPE_NOTIFY_EXEC.rawValue: return "NOTIFY_EXEC"
        case ES_EVENT_TYPE_NOTIFY_FORK.rawValue: return "NOTIFY_FORK"
        case ES_EVENT_TYPE_NOTIFY_EXIT.rawValue: return "NOTIFY_EXIT"
        case ES_EVENT_TYPE_NOTIFY_CREATE.rawValue: return "NOTIFY_CREATE"
        case ES_EVENT_TYPE_NOTIFY_WRITE.rawValue: return "NOTIFY_WRITE"
        case ES_EVENT_TYPE_NOTIFY_CLOSE.rawValue: return "NOTIFY_CLOSE"
        case ES_EVENT_TYPE_NOTIFY_RENAME.rawValue: return "NOTIFY_RENAME"
        case ES_EVENT_TYPE_NOTIFY_UNLINK.rawValue: return "NOTIFY_UNLINK"
        case ES_EVENT_TYPE_NOTIFY_SIGNAL.rawValue: return "NOTIFY_SIGNAL"
        case ES_EVENT_TYPE_NOTIFY_KEXTLOAD.rawValue: return "NOTIFY_KEXTLOAD"
        case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD.rawValue: return "NOTIFY_BTM_LAUNCH_ITEM_ADD"
        case ES_EVENT_TYPE_NOTIFY_MMAP.rawValue: return "NOTIFY_MMAP"
        case ES_EVENT_TYPE_NOTIFY_MPROTECT.rawValue: return "NOTIFY_MPROTECT"
        case ES_EVENT_TYPE_NOTIFY_SETOWNER.rawValue: return "NOTIFY_SETOWNER"
        case ES_EVENT_TYPE_NOTIFY_SETMODE.rawValue: return "NOTIFY_SETMODE"
        case ES_EVENT_TYPE_NOTIFY_OPEN.rawValue: return "NOTIFY_OPEN"
        case ES_EVENT_TYPE_NOTIFY_GET_TASK_READ.rawValue: return "NOTIFY_GET_TASK_READ"
        case ES_EVENT_TYPE_NOTIFY_TRACE.rawValue: return "NOTIFY_TRACE"
        case ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE.rawValue: return "NOTIFY_REMOTE_THREAD_CREATE"
        case ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED.rawValue: return "NOTIFY_CS_INVALIDATED"
        default: return "TYPE_\(raw)"
        }
    }

    // MARK: - v1.21.4 Phase-3 (Mitigation B) — off-thread message processing

    /// The full parse/yield/D4 pipeline that used to run inline on the ES
    /// callback boundary. Now runs on the per-client worker's serial queue against
    /// the RETAINED message (`box.message`), which stays valid until the worker's
    /// `free` closure calls `es_release_message`. Byte-for-byte the same work as
    /// the old inline handler (same single `yield`, same content, same downstream
    /// order), minus the D1 seq accounting AND the D3 coverage-canary recognizer,
    /// which both stay ON the callback boundary (D1 for kernel-drop gap
    /// accounting, D3 so "seen at callback" measures kernel delivery not
    /// downstream processing). Never frees the message — that is the worker's
    /// `free` closure's sole responsibility, called exactly once after this
    /// returns.
    ///
    /// Wrapped in an `autoreleasepool` so the CFString-backed `String`s that
    /// `esStringToSwift`/`normalise` create are reclaimed per message instead of
    /// accumulating on the worker thread — the same defensive discipline the old
    /// inline callback used, moved to where the allocation now happens.
    private static func processRetained(
        _ box: ESPendingMessage,
        continuation: AsyncStream<Event>.Continuation,
        traceContinuation: AsyncStream<TraceBindingSignal>.Continuation,
        deliveryTelemetry: EventCollectorBufferTelemetry,
        tracker: ESSeqTracker,
        logger: Logger
    ) {
        autoreleasepool {
            let message = box.message
            let evType = box.eventType

            // v1.9 Agent Traces side-channel. Computed BEFORE normalise so the
            // env-scan can lift TRACEPARENT off the retained es_message_t before
            // normalise drops the env reference. Cheap no-op when the flag is off.
            var selfTrace: TraceContext? = nil
            if agentTracesEnabled {
                selfTrace = emitTraceSignals(message: message, into: traceContinuation)
            }

            var event = normalise(message: message)
            // v1.21.4 (P6 fix): SELF-STAMP this exec's OWN event with the
            // TRACEPARENT it inherited in its env. The parallel `.bind` signal
            // yielded above only ever helps DESCENDANTS — the exec event of the
            // header-carrying process itself is direct-correlated before the
            // detached bind Task lands, so without this its agent_trace_id
            // stayed null (the P6 bug). `selfTrace` is non-nil only for a
            // NOTIFY_EXEC that actually carried a header; gate on the event
            // type explicitly too. Only write keys not already present so a
            // future upstream stamp is never clobbered.
            if let ctx = selfTrace,
               evType == ES_EVENT_TYPE_NOTIFY_EXEC.rawValue,
               var stamped = event {
                for (k, v) in TraceCorrelator.selfStampEnrichments(context: ctx, pid: stamped.process.pid)
                where stamped.enrichments[k] == nil {
                    stamped.enrichments[k] = v
                }
                event = stamped
            }

            var yielded = false
            var yieldDropped = false
            if let event = event {
                yielded = true
                let result = continuation.yield(event)
                deliveryTelemetry.recordYield(offered: event, result: result)
                if case .dropped = result { yieldDropped = true }
                // v1.21.4 Phase-2 (D3) NOTE: the coverage-canary recognizer no
                // longer runs here. It was moved ONTO the ES callback boundary
                // (see `openClient`) so "seen at callback" measures kernel
                // delivery, not downstream worker processing.
            } else {
                logger.debug("Dropped unhandled ES event type: \(evType)")
            }
            // v1.21.4 Phase-0 D4: end-to-end handler latency (arrival → done,
            // including the queue-wait now that processing is off-thread) plus
            // the yield-outcome backlog gauge. `box.startNanos` was captured at
            // the callback boundary; `&-` is the monotonic DispatchTime delta.
            let elapsedNanos = DispatchTime.now().uptimeNanoseconds &- box.startNanos
            tracker.recordProcessed(
                eventType: evType,
                elapsedNanos: elapsedNanos,
                yielded: yielded,
                yieldDropped: yieldDropped
            )
        }
    }

    // MARK: - v1.9 Agent Traces — side-channel emission

    /// Inspect the live es_message_t for trace-binding-relevant events
    /// (NOTIFY_EXEC env scan, NOTIFY_EXIT pid eviction) and emit
    /// `TraceBindingSignal`s onto the side-channel stream.
    ///
    /// Runs only when `agentTracesEnabled == true`. Still yields the
    /// `.bind`/`.evict` signals for DESCENDANT correlation exactly as before.
    ///
    /// - Returns: the extracted `TraceContext` for a NOTIFY_EXEC that carried
    ///   a TRACEPARENT (so `processRetained` can SELF-STAMP the SAME exec
    ///   event synchronously, avoiding the async-bind race that left the
    ///   process's own event unstamped); nil for EXIT, non-exec, or an exec
    ///   with no inherited trace context.
    private static func emitTraceSignals(
        message: UnsafePointer<es_message_t>,
        into continuation: AsyncStream<TraceBindingSignal>.Continuation
    ) -> TraceContext? {
        let msg = message.pointee
        switch msg.event_type {
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            // Build the identity from the EXEC's *target* process — that's
            // the process that just took over via execve, and whose env
            // we want to inspect. The `msg.process` is the calling
            // process pre-exec; for execve the post-exec image is in
            // `msg.event.exec.target`.
            let target = msg.event.exec.target
            guard let context = traceContextFromExecMessage(message) else {
                return nil
            }
            let executablePath = esFileToPath(target.pointee.executable)
            let identity = ProcessIdentity(from: target, executablePath: executablePath)
            // Best-effort agent-tool tag from the exec'd binary path. The
            // registry stores nil tags fine; the correlator can re-derive
            // at lookup time using the same registry.
            // v1.9 audit Phase-1.8: reuse a single shared registry instance
            // instead of allocating one per NOTIFY_EXEC. The previous
            // `AIToolRegistry()` per call meant ~25 lowercased() string
            // allocations per exec at 200-500 events/sec sustained.
            let aiTool = Self.sharedAIRegistry.isAITool(executablePath: executablePath)
            let signal = TraceBindingSignal(
                kind: .bind(identity: identity, context: context, agentTool: aiTool)
            )
            continuation.yield(signal)
            // v1.21.4 (P6): low-volume confirmation the traceparent path fired.
            // Only reached on an actual TRACEPARENT hit, so this is rare and
            // safe at `.info`. trace_id truncated to its first 8 hex chars.
            let traceIdPrefix = String(context.traceId.prefix(8))
            let lastComponent = (executablePath as NSString).lastPathComponent
            traceLogger.info(
                "agent-traces: self-stamp trace_id=\(traceIdPrefix, privacy: .public) pid=\(identity.pid, privacy: .public) path=\(lastComponent, privacy: .public)"
            )
            return context

        case ES_EVENT_TYPE_NOTIFY_EXIT:
            // The exiting process is `msg.process`. EventLoop's consumer
            // no-ops if no binding exists for this pid.
            let exitingPid = audit_token_to_pid(msg.process.pointee.audit_token)
            continuation.yield(TraceBindingSignal(kind: .evict(pid: exitingPid)))
            return nil

        default:
            return nil
        }
    }

    // MARK: - Event Normalisation

    /// Map a raw `es_message_t` into a MacCrab `Event`, or return `nil`
    /// if the event should be dropped (e.g. unmodified close).
    private static func normalise(message: UnsafePointer<es_message_t>) -> Event? {
        let msg = message.pointee

        // Timestamp from the Mach absolute time in the message header.
        let timestamp = Date(
            timeIntervalSince1970: TimeInterval(msg.time.tv_sec) + TimeInterval(msg.time.tv_nsec) / 1_000_000_000
        )

        // v1.17.4 hot-path guard (ES-OPEN-4): the NOTIFY_OPEN firehose is
        // system-wide and ~all opens are discarded by the credential
        // allowlist. Do the cheap path check (a substring scan + a bool
        // field) BEFORE the heap-allocating processFromESProcess build, so
        // the discarded majority costs almost nothing. Otherwise the ES
        // callback queue backpressures under a heavy open rate and the
        // kernel silently DROPS messages across ALL event types.
        if msg.event_type == ES_EVENT_TYPE_NOTIFY_OPEN {
            let openPath = esFileToPath(msg.event.open.file)
            // Exact callback/normaliser parity. In addition to the static
            // credential and agent-content paths, a fresh owner snapshot may
            // retain ordinary text OPENs for an attributed AI PID. The
            // separate platform-keychain gate remains inside the shared helper
            // and cannot be bypassed by fail-open dynamic state.
            if shouldDropBeforeWorker(
                eventType: ES_EVENT_TYPE_NOTIFY_OPEN.rawValue,
                path: openPath,
                isPlatformBinary: msg.process.pointee.is_platform_binary,
                processID: audit_token_to_pid(msg.process.pointee.audit_token)
            ) {
                return nil
            }
        }

        // v1.18 hot-path guard: introspection events are only interesting from
        // a NON-platform-binary actor. Every benign introspector — lldb,
        // debugserver, ReportCrash, spindump, sysdiagnose, OSAnalyticsHelper,
        // Activity Monitor, securityd — is an Apple platform binary, and the
        // rules filter Apple actors anyway, so dropping the platform-binary
        // majority here (a cheap bool, before the doubled processFromESProcess
        // for actor+target) bounds the volume with zero detection loss — the
        // same firehose discipline as the OPEN allowlist.
        switch msg.event_type {
        case ES_EVENT_TYPE_NOTIFY_GET_TASK_READ, ES_EVENT_TYPE_NOTIFY_TRACE,
             ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE, ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED:
            if msg.process.pointee.is_platform_binary { return nil }
        default:
            break
        }

        // v1.21.5 memory-protection hot-path guard: same discipline as the OPEN,
        // introspection and write-family guards above. Measured on-device,
        // NOTIFY_MPROTECT (77/s) + NOTIFY_MMAP (50/s) are ~11.6% of all ES
        // messages, and the W+X tests in their parse branches below discard
        // essentially all of them — 1.03M MPROTECT + 76K MMAP messages over
        // 2.26 h yielded ONE stored `mprotect_wx` row. Pre-fix every one of those
        // discarded messages still paid for the heap-allocating
        // processFromESProcess build first, because the guard sat BELOW it.
        // Hoisting it here is a pure bitmask test on a value already in the
        // message. The predicate is byte-for-byte the one in the branches below
        // (`isWritable && isExecutable`), so nothing that is emitted today stops
        // being emitted — only the cost of the discarded majority changes.
        switch msg.event_type {
        case ES_EVENT_TYPE_NOTIFY_MMAP:
            let prot = msg.event.mmap.protection
            guard (prot & PROT_WRITE) != 0, (prot & PROT_EXEC) != 0 else { return nil }
        case ES_EVENT_TYPE_NOTIFY_MPROTECT:
            let prot = msg.event.mprotect.protection
            guard (prot & PROT_WRITE) != 0, (prot & PROT_EXEC) != 0 else { return nil }
        default:
            break
        }

        // v1.21.4 Phase-7 write hot-path guard: mirror the OPEN guard for the
        // write family. The NOTIFY_WRITE firehose is dominated by benign log
        // writers (suricata → /var/log/suricata/*, ~84% of measured write
        // volume). Do the cheap TARGET-path check (a suffix/substring scan)
        // BEFORE the heap-allocating processFromESProcess build so provably-
        // irrelevant log-sink noise costs almost nothing and never runs the
        // 5-tier pipeline. See the "Write-family hot-path noise guard" section
        // above for the detection-safety argument (only log sinks drop; any
        // credential / agent-content / code-drop path is kept). For CLOSE we
        // also short-circuit the unmodified case here — it was already dropped
        // downstream, but doing it before processFromESProcess is a free win.
        // #11: decode the write/close TARGET path exactly once. The drop guard
        // reads it here; the kept WRITE/CLOSE branch below reuses it instead of
        // calling esFileToPath(target) a second time on the same es_string_token
        // (byte-identical — same stable pointer, same copy).
        var writeFamilyTargetPath: String?
        switch msg.event_type {
        case ES_EVENT_TYPE_NOTIFY_WRITE:
            let targetPath = esFileToPath(msg.event.write.target)
            if shouldDropNoisyWrite(path: targetPath) { return nil }
            writeFamilyTargetPath = targetPath
        case ES_EVENT_TYPE_NOTIFY_CLOSE:
            guard msg.event.close.modified else { return nil }
            let targetPath = esFileToPath(msg.event.close.target)
            if shouldDropNoisyWrite(path: targetPath) { return nil }
            writeFamilyTargetPath = targetPath
        default:
            break
        }

        // Source process
        let esProcess = msg.process
        let processInfo = processFromESProcess(esProcess)

        switch msg.event_type {

        // -----------------------------------------------------------------
        // MARK: Process Events
        // -----------------------------------------------------------------

        case ES_EVENT_TYPE_NOTIFY_EXEC:
            let execEvent = msg.event.exec
            let args = argsFromExecMessage(message)
            let commandLine = args.joined(separator: " ")

            // The target of exec is in execEvent.target. Build its ProcessInfo
            // ONCE with args + commandLine populated. Previously we built a full
            // ProcessInfo and then reconstructed an entire second one just to
            // attach args/commandLine; processFromESProcess now threads them
            // straight through esProcessInfo, so this is field-for-field
            // identical to the old enrichedTarget (incl. the P6 audit identity)
            // with one allocation instead of two. Exec-only, below flood volume.
            let enrichedTarget = processFromESProcess(
                execEvent.target, args: args, commandLine: commandLine
            )

            return Event(
                timestamp: timestamp,
                eventCategory: .process,
                eventType: .start,
                eventAction: "exec",
                process: enrichedTarget,
                severity: .informational
            )

        case ES_EVENT_TYPE_NOTIFY_FORK:
            let forkEvent = msg.event.fork
            let childInfo = processFromESProcess(forkEvent.child)
            return Event(
                timestamp: timestamp,
                eventCategory: .process,
                eventType: .start,
                eventAction: "fork",
                process: childInfo,
                severity: .informational
            )

        case ES_EVENT_TYPE_NOTIFY_EXIT:
            return Event(
                timestamp: timestamp,
                eventCategory: .process,
                eventType: .end,
                eventAction: "exit",
                process: processInfo,
                severity: .informational
            )

        // -----------------------------------------------------------------
        // MARK: File Events
        // -----------------------------------------------------------------

        case ES_EVENT_TYPE_NOTIFY_CREATE:
            let createEvent = msg.event.create
            // CREATE can be either an existing path or a new-path descriptor.
            // For the destination_type == ES_DESTINATION_TYPE_EXISTING_FILE the
            // file already has a vnode; otherwise we construct from the directory
            // + filename tokens.
            let path: String
            if createEvent.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
                path = esFileToPath(createEvent.destination.existing_file)
            } else {
                let dir = esFileToPath(createEvent.destination.new_path.dir)
                let filename = esStringToSwift(createEvent.destination.new_path.filename)
                path = dir.hasSuffix("/") ? dir + filename : dir + "/" + filename
            }

            let fileInfo = FileInfo(
                path: path,
                action: .create
            )
            return Event(
                timestamp: timestamp,
                eventCategory: .file,
                eventType: .creation,
                eventAction: "create",
                process: processInfo,
                file: fileInfo,
                severity: .informational
            )

        case ES_EVENT_TYPE_NOTIFY_WRITE:
            let writeEvent = msg.event.write
            // #11: reuse the path already decoded by the drop guard above (this
            // branch is only reached for WRITE, where the guard always set it).
            let path = writeFamilyTargetPath ?? esFileToPath(writeEvent.target)
            let fileInfo = FileInfo(
                path: path,
                action: .write
            )
            return Event(
                timestamp: timestamp,
                eventCategory: .file,
                eventType: .change,
                eventAction: "write",
                process: processInfo,
                file: fileInfo,
                severity: .informational
            )

        case ES_EVENT_TYPE_NOTIFY_OPEN:
            // v1.17.4: emit ONLY for credential/secret paths. The firehose
            // bound (isCredentialReadPath + the platform-binary keychain
            // drop) is enforced upstream BEFORE processInfo is built — see
            // the hot-path guard at the top of normalise — so reaching here
            // means the path already passed. The recompute below is the
            // defensive re-check and only runs on the rare matched open.
            // Revives the "credential file READ by untrusted process" rule
            // class, dead until now because no OPEN event was ever emitted.
            let openEvent = msg.event.open
            let openPath = esFileToPath(openEvent.file)
            // Admission was already decided before processInfo allocation via
            // the shared static+dynamic helper above. Do not narrow it back to
            // the legacy static allowlist here: ordinary README/source OPENs
            // retained for FileInjectionScanner and PromptIntentBridge must
            // materialise as events.
            return Event(
                timestamp: timestamp,
                eventCategory: .file,
                eventType: .change,
                eventAction: "open",
                process: processInfo,
                file: FileInfo(path: openPath, action: .open),
                severity: .informational
            )

        case ES_EVENT_TYPE_NOTIFY_CLOSE:
            let closeEvent = msg.event.close
            // Only emit events for files that were actually modified.
            guard closeEvent.modified else { return nil }
            // #11: reuse the path already decoded by the drop guard above (this
            // branch is only reached for a modified CLOSE, where the guard set it).
            let path = writeFamilyTargetPath ?? esFileToPath(closeEvent.target)
            let fileInfo = FileInfo(
                path: path,
                action: .close
            )
            return Event(
                timestamp: timestamp,
                eventCategory: .file,
                eventType: .change,
                eventAction: "close_modified",
                process: processInfo,
                file: fileInfo,
                severity: .informational
            )

        case ES_EVENT_TYPE_NOTIFY_RENAME:
            let renameEvent = msg.event.rename
            let sourcePath = esFileToPath(renameEvent.source)

            // Destination depends on destination_type.
            let destPath: String
            if renameEvent.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
                destPath = esFileToPath(renameEvent.destination.existing_file)
            } else {
                let dir = esFileToPath(renameEvent.destination.new_path.dir)
                let filename = esStringToSwift(renameEvent.destination.new_path.filename)
                destPath = dir.hasSuffix("/") ? dir + filename : dir + "/" + filename
            }

            let fileInfo = FileInfo(
                path: destPath,
                action: .rename,
                sourcePath: sourcePath
            )
            return Event(
                timestamp: timestamp,
                eventCategory: .file,
                eventType: .change,
                eventAction: "rename",
                process: processInfo,
                file: fileInfo,
                severity: .informational
            )

        case ES_EVENT_TYPE_NOTIFY_UNLINK:
            let unlinkEvent = msg.event.unlink
            let path = esFileToPath(unlinkEvent.target)
            let fileInfo = FileInfo(
                path: path,
                action: .delete
            )
            return Event(
                timestamp: timestamp,
                eventCategory: .file,
                eventType: .deletion,
                eventAction: "unlink",
                process: processInfo,
                file: fileInfo,
                severity: .informational
            )

        // -----------------------------------------------------------------
        // MARK: Signal Events
        // -----------------------------------------------------------------

        case ES_EVENT_TYPE_NOTIFY_SIGNAL:
            let signalEvent = msg.event.signal
            let targetInfo = processFromESProcess(signalEvent.target)
            let enrichments: [String: String] = [
                "target.pid": String(targetInfo.pid),
                "target.executable": targetInfo.executable,
                "target.name": targetInfo.name,
            ]
            return Event(
                timestamp: timestamp,
                eventCategory: .process,
                eventType: .info,
                eventAction: "signal(\(signalEvent.sig))",
                process: processInfo,
                enrichments: enrichments,
                severity: .informational
            )

        // -----------------------------------------------------------------
        // MARK: Introspection Events (v1.18) — actor acts on a TARGET process
        // -----------------------------------------------------------------
        // The subject (msg.process) is the ACTOR; the target is the process
        // being read/traced/injected. We carry the target via Sigma-named
        // enrichment keys (TargetImage/TargetSignerType/TargetIsSelf/SameTeam)
        // so RuleEngine resolves them through its enrichment passthrough with
        // no model change, and rules get cheap FP gates (target-self = JIT/own
        // process; same-team = legitimate intra-vendor IPC) without the
        // unimplemented |fieldref modifier. Emitted as .process/.change ->
        // logsource category "process_event".
        //
        // Notes: (a) we read ONLY `.target` (and the empty cs_invalidated),
        // which is version-agnostic — the version>=5 `.type` field is
        // deliberately not accessed, so no es_message version guard is needed.
        // (b) SameTeam is derived from the kernel-attested team_id, so it is an
        // FP-reduction heuristic an attacker cannot spoof without possessing
        // the target team's signing identity — not a hard security boundary.
        // (c) these are ES-native; they are NOT carried by the non-root
        // eslogger/kdebug fallback, so these rules require the ES entitlement.

        case ES_EVENT_TYPE_NOTIFY_GET_TASK_READ:
            // task_read_for_pid: the memory-read port acquisition that gates
            // every cross-process mach_vm_read (credential scraping from a
            // live ssh-agent/securityd/gh process).
            let target = processFromESProcess(msg.event.get_task_read.target)
            return Event(
                timestamp: timestamp, eventCategory: .process, eventType: .change,
                eventAction: "get_task_read", process: processInfo,
                enrichments: introspectionEnrichments(actor: processInfo, target: target),
                severity: .informational)

        case ES_EVENT_TYPE_NOTIFY_TRACE:
            // ptrace(PT_ATTACH) — debugger-style attach to another process.
            let target = processFromESProcess(msg.event.trace.target)
            return Event(
                timestamp: timestamp, eventCategory: .process, eventType: .change,
                eventAction: "trace", process: processInfo,
                enrichments: introspectionEnrichments(actor: processInfo, target: target),
                severity: .informational)

        case ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE:
            // Thread created inside another process's task — code injection.
            // Rarely benign (even debuggers use TRACE, not thread_create).
            let target = processFromESProcess(msg.event.remote_thread_create.target)
            return Event(
                timestamp: timestamp, eventCategory: .process, eventType: .change,
                eventAction: "remote_thread_create", process: processInfo,
                enrichments: introspectionEnrichments(actor: processInfo, target: target),
                severity: .informational)

        case ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED:
            // The process invalidated ITS OWN code signature at runtime
            // (binary tampering, or benign JIT/dynamic codegen). Self-event:
            // no target. TargetIsSelf=true lets rules reason about it.
            return Event(
                timestamp: timestamp, eventCategory: .process, eventType: .change,
                eventAction: "cs_invalidated", process: processInfo,
                enrichments: ["TargetIsSelf": "true"],
                severity: .informational)

        // -----------------------------------------------------------------
        // MARK: Kext Events
        // -----------------------------------------------------------------

        case ES_EVENT_TYPE_NOTIFY_KEXTLOAD:
            let kextEvent = msg.event.kextload
            let kextId = esStringToSwift(kextEvent.identifier)
            return Event(
                timestamp: timestamp,
                eventCategory: .process,
                eventType: .start,
                eventAction: "kextload",
                process: processInfo,
                file: FileInfo(path: kextId, action: .create),
                severity: .medium
            )

        // -----------------------------------------------------------------
        // MARK: BTM / Background Task Management (v1.21.4)
        // -----------------------------------------------------------------
        // A launch item (login item / launch agent / daemon) was made known to
        // Background Task Management — including modern SMAppService.register()
        // registrations that leave NO plist and NO write-time file event.
        //
        // ATTRIBUTION IS THE EXCEPTION HERE: `msg.process` is the OS daemon
        // (backgroundtaskmanagementd), NOT the actor. The event carries a
        // dedicated `instigator` es_process_t (the XPC caller that asked for the
        // add), so that — not the delivering daemon — is the responsible process.
        // Fall back instigator -> app -> msg.process. Both instigator and app are
        // _Nullable, so guard with .map before processFromESProcess (its param is
        // non-optional). `item` is _Nonnull. instigator_token/app_token are msg
        // version >= 8 (macOS 14+) and are deliberately NOT read at the 13.0 floor.
        //
        // Modelled as .file/.creation -> logsource "file_event", gated by the
        // BTM-only enrichment keys so it never cross-matches ordinary file rules.
        case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD:
            let btm = msg.event.btm_launch_item_add.pointee
            let item = btm.item.pointee
            let actor: ProcessInfo = btm.instigator.map { processFromESProcess($0) }
                ?? btm.app.map { processFromESProcess($0) }
                ?? processInfo
            let appInfo = btm.app.map { processFromESProcess($0) }
            let exePath = esStringToSwift(btm.executable_path)
            let itemURL = esStringToSwift(item.item_url)
            // executable_path may be empty or relative to item->app_url for
            // app-scoped records — fall back to the item URL so file.path is set.
            let path = !exePath.isEmpty ? exePath : itemURL
            return Event(
                timestamp: timestamp,
                eventCategory: .file,
                eventType: .creation,
                eventAction: "btm_add",
                process: actor,
                file: FileInfo(path: path, action: .create),
                enrichments: btmEnrichments(
                    itemType: item.item_type,
                    legacy: item.legacy,
                    managed: item.managed,
                    executablePath: exePath,
                    itemURL: itemURL,
                    appURL: esStringToSwift(item.app_url),
                    app: appInfo
                ),
                severity: .medium
            )

        // -----------------------------------------------------------------
        // MARK: Memory Protection Events
        // -----------------------------------------------------------------

        case ES_EVENT_TYPE_NOTIFY_MMAP:
            let mmapEvent = msg.event.mmap
            let filePath = esFileToPath(mmapEvent.source)
            // Only emit for executable mappings (W+X is suspicious)
            let protection = mmapEvent.protection
            let isExecutable = (protection & PROT_EXEC) != 0
            let isWritable = (protection & PROT_WRITE) != 0

            // Only alert on W+X mappings (potential code injection)
            guard isWritable && isExecutable else { return nil }

            let fileInfo = FileInfo(path: filePath, action: .create)
            return Event(
                timestamp: timestamp,
                eventCategory: .process,
                eventType: .change,
                eventAction: "mmap_wx",
                process: processInfo,
                file: fileInfo,
                enrichments: ["mmap.protection": String(protection)],
                severity: .high
            )

        case ES_EVENT_TYPE_NOTIFY_MPROTECT:
            let mprotectEvent = msg.event.mprotect
            let protection = mprotectEvent.protection
            let isExecutable = (protection & PROT_EXEC) != 0
            let isWritable = (protection & PROT_WRITE) != 0

            // Only alert on transitions TO W+X
            guard isWritable && isExecutable else { return nil }

            return Event(
                timestamp: timestamp,
                eventCategory: .process,
                eventType: .change,
                eventAction: "mprotect_wx",
                process: processInfo,
                enrichments: ["mprotect.protection": String(protection)],
                severity: .high
            )

        // -----------------------------------------------------------------
        // MARK: Ownership & Permission Events
        // -----------------------------------------------------------------

        case ES_EVENT_TYPE_NOTIFY_SETOWNER:
            let setownerEvent = msg.event.setowner
            let filePath = esFileToPath(setownerEvent.target)
            let fileInfo = FileInfo(path: filePath, action: .write)
            return Event(
                timestamp: timestamp,
                eventCategory: .file,
                eventType: .change,
                eventAction: "setowner",
                process: processInfo,
                file: fileInfo,
                enrichments: ["file.uid": String(setownerEvent.uid), "file.gid": String(setownerEvent.gid)],
                severity: .informational
            )

        case ES_EVENT_TYPE_NOTIFY_SETMODE:
            let setmodeEvent = msg.event.setmode
            let filePath = esFileToPath(setmodeEvent.target)
            let fileInfo = FileInfo(path: filePath, action: .write)
            return Event(
                timestamp: timestamp,
                eventCategory: .file,
                eventType: .change,
                eventAction: "setmode",
                process: processInfo,
                file: fileInfo,
                enrichments: ["file.mode": String(setmodeEvent.mode, radix: 8)],
                severity: .informational
            )

        default:
            return nil
        }
    }
}

// MARK: - v1.21.4 Phase-2 (D3) coverage canary

/// Shared constants + nonce scheme for the daemon-health coverage canary (D3).
///
/// The watchdog (`DaemonTimers`) periodically spawns a benign, known-signed
/// Apple platform binary carrying a per-run nonce in argv, then verifies the
/// exec reached both the ES callback and `events.db`. Everything the recognizer
/// (`ESCollector`), the spawner (`DaemonTimers`), and the suppression allowlist
/// (`NoiseFilter`) need to agree on lives here so there is exactly one source
/// of truth.
///
/// ## Why an `/usr/bin/env` intermediary (muteSelf interaction)
/// `muteSelf()` mutes the daemon's OWN executable path via `es_mute_path_literal`.
/// A process `posix_spawn`ed directly by the daemon is still running the daemon
/// image at the moment it execs, so its `NOTIFY_EXEC` would be muted and never
/// reach the callback — the canary would falsely report a kernel gap every run.
/// So the watchdog spawns `/usr/bin/env /usr/bin/true <nonce>`: the `env` exec
/// (daemon-initiated) is muted, but the `/usr/bin/true` exec it in turn performs
/// is initiated by `env` (path `/usr/bin/env`, NOT muted), so the OBSERVED probe
/// exec is delivered to the callback with `/usr/bin/true` as its image.
///
/// ## Self-trip safety (why these exact values)
/// - `spawnBinaryPath` (the OBSERVED image) is `/usr/bin/true`: an Apple platform
///   binary that does nothing, matches no `Image|endswith` EDR/RMM rule, and is
///   trust-gated in NoiseFilter's Gate 7 anyway.
/// - `intermediaryBinaryPath` is `/usr/bin/env`: an unmuted Apple platform
///   binary; its own exec is muted (daemon-initiated) so it raises nothing.
/// - `argvMarker` is deliberately **"MCB-…", not "maccrab…"**: `SelfDefense`'s
///   impersonation probe is `pgrep -f "maccrabd|com\.maccrab\.agent"`, so a
///   marker free of those tokens can never be mistaken for a rogue MacCrab
///   instance. It also contains none of the tokens any `CommandLine|contains`
///   rule keys on. `NoiseFilter.isCoverageCanaryProbe` additionally requires
///   the executable to be exactly `/usr/bin/true`, so the marker cannot be used
///   to launder an attacker's own binary through the suppression gate.
public enum CoverageCanary {
    /// The benign, known-signed binary whose exec the probe OBSERVES. Present on
    /// every macOS. Recognizer + suppression key on this image path.
    public static let spawnBinaryPath = "/usr/bin/true"

    /// Unmuted intermediary that performs the observed exec (see muteSelf note).
    public static let intermediaryBinaryPath = "/usr/bin/env"

    /// Fixed, neutral argv marker prefix. The suppression allowlist matches on
    /// this (nonce-agnostic); the recognizer matches on the full nonce below.
    public static let argvMarker = "MCB-COVERAGE-PROBE"

    /// Build a per-run nonce: the fixed marker + a random component. The random
    /// tail makes each probe unforgeable within its short in-flight window, so a
    /// stale or guessed marker can't falsely satisfy the seen-at-callback check.
    public static func makeNonce() -> String {
        "\(argvMarker)-\(UUID().uuidString.replacingOccurrences(of: "-", with: ""))"
    }
}

/// Thread-safe recognizer state for in-flight coverage-canary probes (D3).
///
/// Mirrors `ESSeqTracker`'s locked-primitive style (one `NSLock`, `@unchecked
/// Sendable`) because it is touched from the same synchronous ES callback. The
/// hot path (`noteExecIfCanary`) short-circuits on an empty live set, so in
/// steady state — no probe in flight — it costs one lock + `isEmpty`.
public final class ESCanaryRegistry: @unchecked Sendable {
    private let lock = NSLock()
    /// Nonces the watchdog has spawned and is waiting on.
    private var live: Set<String> = []
    /// Nonces observed at the ES callback boundary this cycle.
    private var seen: Set<String> = []
    /// Nonces that WERE seen at the callback but whose retained message the
    /// per-client `ESMessageWorker` then refused at its in-flight cap. Third
    /// observation point: without it the two-point verdict reads "seen at the
    /// callback but absent from events.db" as a store/eviction gap, so every
    /// probe lost at the callback→worker hand-off is blamed on retention.
    private var droppedAtHandoffNonces: Set<String> = []

    public init() {}

    /// Arm a nonce before its exec is spawned.
    public func arm(_ nonce: String) {
        lock.lock(); defer { lock.unlock() }
        live.insert(nonce)
        seen.remove(nonce)
        droppedAtHandoffNonces.remove(nonce)
    }

    /// Retire a nonce (clears live + seen + hand-off-drop state for it).
    public func disarm(_ nonce: String) {
        lock.lock(); defer { lock.unlock() }
        live.remove(nonce)
        seen.remove(nonce)
        droppedAtHandoffNonces.remove(nonce)
    }

    /// Whether `nonce` was seen at the callback boundary.
    public func seenAtCallback(_ nonce: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return seen.contains(nonce)
    }

    /// Whether the message carrying `nonce` was dropped at the callback→worker
    /// hand-off (the worker was already at `maxInFlightMessages`).
    public func droppedAtHandoff(_ nonce: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return droppedAtHandoffNonces.contains(nonce)
    }

    /// Cheap armed-gate for the ES callback boundary: `true` iff any nonce is
    /// live. Lets the callback skip the (per-exec) argv walk entirely when no
    /// probe is in flight — one locked `isEmpty` the rest of the time.
    public var isArmed: Bool {
        lock.lock(); defer { lock.unlock() }
        return !live.isEmpty
    }

    /// Hot path: called for every EXEC. Latches any LIVE nonce present in the
    /// exec's command line. Near-free when no probe is armed.
    ///
    /// Returns the matched nonces so the callback can tell the registry when
    /// the SAME message is then refused at the worker hand-off. The no-match
    /// path returns the empty-array singleton — no allocation on the hot path.
    @discardableResult
    public func noteExecIfCanary(commandLine: String) -> [String] {
        lock.lock(); defer { lock.unlock() }
        guard !live.isEmpty else { return [] }
        var matched: [String] = []
        for nonce in live where commandLine.contains(nonce) {
            seen.insert(nonce)
            matched.append(nonce)
        }
        return matched
    }

    /// Record that the retained message carrying these probe nonces was freed
    /// at the callback→worker hand-off instead of processed. Called from the ES
    /// callback immediately after a `submit` that returned `false`.
    public func noteDroppedAtHandoff(_ nonces: [String]) {
        guard !nonces.isEmpty else { return }
        lock.lock(); defer { lock.unlock() }
        for nonce in nonces where live.contains(nonce) { droppedAtHandoffNonces.insert(nonce) }
    }
}

// MARK: - ESClientContext (v1.21.4 Phase-4 Mitigation C)

/// Everything one of the split ES clients owns: its kernel handle, its OWN seq
/// accountant (so `es_kernel_dropped_by_type` is measured per-queue), its OWN
/// off-thread worker (a SHARED worker would re-couple the channels at the parse
/// stage, defeating the split), the exact type list it subscribes, and a label
/// for logging. The two contexts feed the ONE downstream continuation, so the
/// split is invisible past this boundary.
///
/// A reference type: `openClient(for:)` mutates `client` after creation and the
/// `contexts` array must observe that mutation. Not `Sendable` on its own — it is
/// only ever set up on the init thread and then read (its thread-safe `tracker` /
/// `worker` are read from the heartbeat) without further re-shaping the array.
private final class ESClientContext {
    let label: String
    let subscribedTypes: [es_event_type_t]
    let tracker: ESSeqTracker
    let worker: ESMessageWorker
    /// v1.21.4 Phase-2 (D3): the coverage-canary recognizer, non-nil ONLY for
    /// the context that carries NOTIFY_EXEC. Held here (not captured by the
    /// worker) so the recognizer runs at the TRUE ES callback boundary —
    /// confirming kernel delivery — rather than downstream on the worker.
    let canary: ESCanaryRegistry?
    /// es_client_t*, set on a successful `es_new_client`; nil'd on teardown.
    var client: OpaquePointer?

    init(label: String, subscribedTypes: [es_event_type_t], tracker: ESSeqTracker, worker: ESMessageWorker, canary: ESCanaryRegistry?) {
        self.label = label
        self.subscribedTypes = subscribedTypes
        self.tracker = tracker
        self.worker = worker
        self.canary = canary
        self.client = nil
    }
}

// MARK: - ESPendingMessage (v1.21.4 Phase-3 Mitigation B)

/// Per-message context carried across the callback → worker hand-off. Holds the
/// RETAINED `es_message_t` pointer (valid until `es_release_message`), the
/// handler-entry timestamp (D4 end-to-end latency), and the event type (D4
/// processed-count + D3 canary gating). Boxed with `Unmanaged.passRetained` at
/// the callback boundary and released by the worker's `free` closure exactly
/// once. Not `Sendable`: it only ever crosses the boundary as an opaque pointer.
private final class ESPendingMessage {
    let message: UnsafePointer<es_message_t>
    let startNanos: UInt64
    let eventType: UInt32

    init(message: UnsafePointer<es_message_t>, startNanos: UInt64, eventType: UInt32) {
        self.message = message
        self.startNanos = startNanos
        self.eventType = eventType
    }
}

// MARK: - ESMessageWorker (v1.21.4 Phase-3 Mitigation B)

/// Bounded off-thread worker that owns retained Endpoint Security messages
/// between the callback boundary and the parse/yield pipeline. The ES callback
/// does the minimum (D1 seq accounting + `es_retain_message`) and hands the
/// retained message here, returning immediately so the per-client kernel queue
/// drains at the retain+enqueue rate, not the parse rate — shrinking the window
/// in which the kernel back-pressures and silently drops messages.
///
/// # Free-exactly-once (the whole risk of this change)
///
/// The worker takes OWNERSHIP of every handle passed to `submit` and guarantees
/// its injected `free` closure runs EXACTLY ONCE per handle, on every path:
///
///   • **accepted** → the serial worker runs `process(handle)` then
///     `free(handle)` inside one dispatched block, and GCD runs each async block
///     exactly once;
///   • **over-bound** → `submit` frees inline (and counts the drop) and never
///     enqueues, so the accepted branch cannot also run for that handle;
///   • **shutting down** → `submit` frees inline and never enqueues.
///
/// The three `submit` branches are mutually exclusive (each returns), and a
/// handle reaches `submit` exactly once (the caller boxes a fresh
/// `Unmanaged.passRetained` per message). Therefore `free` runs on every handle
/// exactly once — no leak (a missed free leaks kernel message memory) and no
/// double-free / use-after-free (either would crash the ES client). `process`
/// never frees (that is `free`'s sole job) and always runs strictly before
/// `free` within the same block, so nothing touches the handle after it is
/// freed.
///
/// # Bounded / backpressure
///
/// `inFlight` (submitted-but-not-yet-completed handles) is capped at
/// `maxInFlight`. Past the cap the NEWEST arrival is dropped (freed + counted in
/// `backpressureDroppedCount`) rather than blocking the callback — blocking the
/// ES callback thread would itself starve the kernel queue, the exact failure
/// this change fixes — or growing memory without bound. Bounding by an in-flight
/// COUNT on a dedicated serial queue is the first mechanism the plan names; it
/// drops-newest because you cannot evict an already-enqueued item from a GCD
/// queue. Drop-newest and drop-oldest bound memory identically, and the drop is
/// COUNTED either way, which is the point (an honest userspace gauge instead of
/// a silent kernel drop).
///
/// # Ordering
///
/// The queue is SERIAL, so messages are normalised and yielded in the same
/// kernel-delivery order as the old inline handler — one at a time, but the
/// callback no longer waits for it. `submit` increments `inFlight` and enqueues
/// under one lock, giving `shutdownAndDrain` a consistent view: every enqueued
/// block is enqueued before a concurrent shutdown observes the flag, or the
/// submit sees the flag and frees inline.
///
/// # Concurrency
///
/// One `NSLock` guards `inFlight`, `shuttingDown`, and `backpressureDroppedCount`
/// — mirroring the sibling `ESSeqTracker` / `ESCanaryRegistry` locked primitives.
public final class ESMessageWorker: @unchecked Sendable {

    /// Opaque per-message handle. In production this is
    /// `Unmanaged.passRetained(ESPendingMessage).toOpaque()`; in tests it is any
    /// distinct non-null pointer. The worker treats it purely as a token whose
    /// only contract is "pass me to `process` then `free`, exactly once each."
    public typealias Handle = UnsafeRawPointer

    private let queue: DispatchQueue
    private let maxInFlight: Int
    private let process: (Handle) -> Void
    private let free: (Handle) -> Void

    /// v1.21.5 PERF: slots held back at the TOP of the in-flight budget for
    /// lineage-critical types (EXEC/FORK/EXIT). Pre-fix the cap was a single
    /// undifferentiated budget, so under backpressure the drop policy was
    /// "newest arrival loses" regardless of value — and on the exec client the
    /// high-rate low-yield types (MPROTECT 77/s, GET_TASK_READ 139/s) vastly
    /// outnumber EXEC (7/s), so the events that anchor process lineage were the
    /// most likely to be lost. Non-critical arrivals are now refused this many
    /// slots early, leaving the tail of the budget for the events nothing
    /// downstream can reconstruct.
    private let lineageReserve: Int

    private let lock = NSLock()
    private var inFlight = 0
    private var shuttingDown = false
    private var backpressureDroppedCount: UInt64 = 0
    /// v1.21.6 (audit DET-05): per-event-type breakdown of the same drops.
    /// Guarded by the same `lock` as the aggregate.
    private var backpressureDroppedByTypeCount: [UInt32: UInt64] = [:]

    /// - Parameters:
    ///   - maxInFlight: in-flight cap (clamped to ≥1).
    ///   - label: dispatch-queue label.
    ///   - reservesLineageSlots: whether a quarter of the budget is held back
    ///     for lineage-critical types (see `lineageReserve`). Only meaningful
    ///     for a client that can carry BOTH lineage-critical and non-critical
    ///     traffic on the same queue; a client whose subscribed types never
    ///     include EXEC/FORK/EXIT (e.g. the FILE client) has nothing to protect
    ///     and should pass `false` so the reserve isn't dead capacity. Defaults
    ///     to `true` so every existing caller keeps today's behavior.
    ///   - process: run the message pipeline; MUST NOT free the handle.
    ///   - free: release the handle; the worker calls it exactly once per handle.
    public init(maxInFlight: Int,
                label: String = "com.maccrab.es.message-worker",
                reservesLineageSlots: Bool = true,
                process: @escaping (Handle) -> Void,
                free: @escaping (Handle) -> Void) {
        let cap = Swift.max(1, maxInFlight)
        self.maxInFlight = cap
        // A quarter of the budget is held for lineage-critical types (see
        // `lineageReserve`). Floored at 1 so even a tiny test cap reserves a slot,
        // and capped below `maxInFlight` so non-critical traffic is never refused
        // outright — it just loses the race for the last slots. Skipped entirely
        // when the client never carries lineage-critical traffic in the first
        // place (`reservesLineageSlots: false`), so that client's full budget is
        // usable instead of sitting reserved for a type it never sees.
        self.lineageReserve = reservesLineageSlots
            ? Swift.max(1, Swift.min(cap - 1, cap / 4))
            : 0
        self.queue = DispatchQueue(label: label, qos: .userInitiated)
        self.process = process
        self.free = free
    }

    /// Take ownership of `handle` and either dispatch it for processing or, if
    /// the worker is at capacity or shutting down, free it inline. On EVERY
    /// return path the handle is freed exactly once (see the type doc). Never
    /// blocks the caller (the ES callback thread).
    ///
    /// Returns whether the handle was ACCEPTED for processing. `false` means it
    /// was freed inline (over-bound drop or shutdown drain) and will never reach
    /// the pipeline — the coverage canary needs this to attribute a lost probe
    /// to the ingest hand-off rather than to the store/eviction stage.
    /// `@discardableResult` so the existing statement-position callers (and the
    /// worker's own tests) are unchanged.
    @discardableResult
    /// `eventType` is the raw ES event type, carried only so a backpressure
    /// drop can be attributed per-type in the heartbeat. Defaults to 0 so the
    /// worker's own unit tests (opaque handles, no ES type) and any non-ES user
    /// of this worker still compile unchanged.
    public func submit(_ handle: Handle, lineageCritical: Bool = true, eventType: UInt32 = 0) -> Bool {
        lock.lock()
        if shuttingDown {
            lock.unlock()
            free(handle)                       // drain path — free once
            return false
        }
        // v1.21.5 PERF: priority-aware admission. Lineage-critical messages may
        // use the whole budget; everything else is refused `lineageReserve` slots
        // early, so a low-yield flood can never consume the last slots and evict
        // EXEC/FORK/EXIT. This can only make non-critical drops MORE likely and
        // critical drops LESS likely — it never admits a message the old policy
        // would have refused. Defaulting to `true` keeps every existing caller
        // (and the worker's unit tests) on the previous full-budget behaviour.
        let admissionCap = lineageCritical ? maxInFlight : maxInFlight - lineageReserve
        if inFlight >= admissionCap {
            backpressureDroppedCount &+= 1
            // v1.21.6 (audit DET-05): the WRITE side of the per-type attribution.
            // The field, `backpressureDroppedByEventType()`, the collector-level
            // `esCopyBackpressureDroppedByType()` merge and the heartbeat key
            // `es_copy_backpressure_dropped_by_type` were all already in place,
            // but nothing ever incremented the map — so the heartbeat published
            // `{}`, which reads identically to "no drops" while the aggregate
            // counter showed millions. Same lock, one dictionary bump, on a path
            // that is already discarding the message. `eventType` defaults to 0
            // so the worker's own unit tests (opaque handles, no ES type) and any
            // non-ES user of this worker still compile.
            backpressureDroppedByTypeCount[eventType, default: 0] &+= 1
            lock.unlock()
            free(handle)                       // over-bound drop — free once + counted
            return false
        }
        inFlight += 1
        // Enqueue UNDER the lock so (inFlight += 1, enqueue) is atomic w.r.t.
        // shutdownAndDrain: any block we enqueue is enqueued before a concurrent
        // shutdown can observe `shuttingDown` and run its drain barrier.
        // `async` never blocks, so holding the lock across it cannot deadlock.
        queue.async {
            self.process(handle)               // pipeline — must not free
            self.free(handle)                  // accepted path — free once
            self.lock.lock()
            self.inFlight -= 1
            self.lock.unlock()
        }
        lock.unlock()
        return true
    }

    /// Stop accepting new work and block until every in-flight handle has been
    /// processed and freed. Idempotent. Called from `ESCollector.stop()` BEFORE
    /// `es_delete_client`, so every `es_release_message` happens strictly before
    /// the client is torn down.
    public func shutdownAndDrain() {
        lock.lock()
        shuttingDown = true
        lock.unlock()
        // Serial queue: this empty sync block runs only after every block
        // enqueued before it (all currently in-flight work) has completed, and
        // each of those frees its handle. Submits after the flag is set free
        // inline and never enqueue, so nothing new can appear behind this barrier.
        queue.sync { }
    }

    /// Count of handles dropped at the copy/hand-off stage because the in-flight
    /// cap was hit — surfaced as `es_copy_backpressure_dropped_total`.
    public func backpressureDropped() -> UInt64 {
        lock.lock(); defer { lock.unlock() }
        return backpressureDroppedCount
    }

    /// v1.21.6 (audit DET-05): the same drops, attributed per ES event type, so
    /// the heartbeat can answer "which detections is the backpressure actually
    /// costing us". Sums to `backpressureDropped()`.
    public func backpressureDroppedByEventType() -> [UInt32: UInt64] {
        lock.lock(); defer { lock.unlock() }
        return backpressureDroppedByTypeCount
    }

    /// Current in-flight count (submitted-but-not-yet-completed). Observability
    /// and test aid; not on any hot path.
    public func inFlightCount() -> Int {
        lock.lock(); defer { lock.unlock() }
        return inFlight
    }
}
