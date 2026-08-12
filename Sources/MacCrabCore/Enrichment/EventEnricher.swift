// EventEnricher.swift
// MacCrabCore
//
// Orchestrates enrichment of raw events from the Endpoint Security collector.
// Attaches process ancestry and code-signing information before events reach
// the detection engine.

import Foundation
import os.log

private struct HeavyFieldResolution<Value: Sendable>: Sendable {
    let value: Value?
    let coverage: HeavyEnrichmentCoverage?

    static func complete(_ value: Value?) -> HeavyFieldResolution<Value> {
        HeavyFieldResolution(value: value, coverage: nil)
    }

    static func degraded(_ state: HeavyEnrichmentCoverage) -> HeavyFieldResolution<Value> {
        HeavyFieldResolution(value: nil, coverage: state)
    }
}

// MARK: - EventEnricher

/// Central enrichment pipeline for MacCrab events.
///
/// Owns the `ProcessLineage` graph and `CodeSigningCache`, using them to
/// augment each incoming event with:
/// - Full process ancestor chain (from the lineage DAG).
/// - Code-signing evaluation results (from the cache/Security framework).
///
/// Cheap graph/cache orchestration is actor-isolated. Blocking cache misses
/// are owned by ``HeavyEnrichmentPlane`` and return later as identity-bound
/// patches, so either ingestion lane can call `enrich(_:)` safely without a
/// slow disk or Security.framework call serialising the other lane.
public actor EventEnricher {

    // MARK: Dependencies

    /// Process parent-child DAG.
    public let lineage: ProcessLineage

    /// Code-signing evaluation cache.
    private let codeSigningCache: CodeSigningCache

    /// Optional SHA-256/CDHash fingerprinter. When provided, exec/fork events
    /// get their `process.hashes` populated. Cache misses run on the bounded
    /// heavy plane; pending/rejected/unavailable coverage is explicit.
    private let processHasher: ProcessHasher?

    /// Optional deception module. When provided, file events whose path
    /// matches a deployed honeyfile get `enrichments["IsHoneyfile"] = "true"`
    /// so the detection rule engine can fire on canary access.
    private let honeyfileManager: HoneyfileManager?

    /// Optional v1.12.0 honey-prompt manager — AI-agent-context bait
    /// (canary CLAUDE.md / SKILL.md / cursorrules under MacCrab's
    /// support dir). Wires the same IsHoneyfile enrichment path used
    /// by HoneyfileManager so the existing `honeyfile_accessed` rule
    /// fires on canary reads.
    private let honeyPromptManager: HoneyPromptManager?

    /// Optional v1.12.0 FileContent enricher. When provided, file
    /// `close` events whose target path is in the
    /// `FileContentEnricher.shouldScan` allowlist get the first
    /// `maxBytes` of text written into
    /// `enrichments["FileContent"]` for `FileContent|contains` selectors.
    /// Reads are descriptor-stable deferred evidence, never inline I/O.
    private let fileContentEnricher: FileContentEnricher?

    /// Opt-in: capture a filtered set of env vars from exec/fork processes
    /// via `sysctl(KERN_PROCARGS2)`. The bounded heavy plane owns that syscall;
    /// the feature remains gated at daemon startup by `MACCRAB_CAPTURE_ENV=1`.
    private let captureEnv: Bool

    /// Telemetry-gap gate. Returns `true` when a kernel drop (ES per-client
    /// queue backpressure) is active for the current window. Nil = no gap
    /// signal wired (tests + non-daemon callers), so the honest-degradation
    /// path never fires and unresolved orphans stay `.unknown`. Wired in
    /// `DaemonSetup` to a `TelemetryGapProbe` over `ESCollector.esGlobalDropped()`.
    private let telemetryGapSignal: (@Sendable () -> Bool)?

    /// Fixed-concurrency owner for every filesystem/Security/sysctl operation
    /// that can block.  `EventEnricher` itself remains the cheap orchestration
    /// actor; cache misses become identity-bound deferred patches instead of
    /// serialising both ingestion lanes.
    private let heavyEnrichmentPlane: HeavyEnrichmentPlane

    /// Logger scoped to the enrichment subsystem.
    private let log = Logger(
        subsystem: "com.maccrab.core",
        category: "EventEnricher"
    )

    /// Counter tracking how many prune cycles have been skipped.
    /// Pruning is triggered every `pruneInterval` enrichments.
    private var enrichmentCount: UInt64 = 0

    /// Number of `enrich(_:)` calls between automatic lineage prune passes.
    private let pruneInterval: UInt64

    // MARK: Initialization

    /// Creates a new enricher.
    ///
    /// - Parameters:
    ///   - lineage: Process lineage graph to use. A new instance is created if
    ///     not provided.
    ///   - codeSigningCache: Code-signing cache to use. A new instance is
    ///     created if not provided.
    ///   - pruneInterval: How often (in number of events) to prune the lineage
    ///     graph. Defaults to 5000.
    public init(
        lineage: ProcessLineage = ProcessLineage(),
        codeSigningCache: CodeSigningCache = CodeSigningCache(),
        processHasher: ProcessHasher? = nil,
        honeyfileManager: HoneyfileManager? = nil,
        honeyPromptManager: HoneyPromptManager? = nil,
        fileContentEnricher: FileContentEnricher? = nil,
        captureEnv: Bool = false,
        pruneInterval: UInt64 = 5000,
        telemetryGapSignal: (@Sendable () -> Bool)? = nil,
        heavyEnrichmentPlane: HeavyEnrichmentPlane = HeavyEnrichmentPlane()
    ) {
        self.lineage = lineage
        self.codeSigningCache = codeSigningCache
        self.processHasher = processHasher
        self.honeyfileManager = honeyfileManager
        self.honeyPromptManager = honeyPromptManager
        self.fileContentEnricher = fileContentEnricher
        self.captureEnv = captureEnv
        self.pruneInterval = pruneInterval
        self.telemetryGapSignal = telemetryGapSignal
        self.heavyEnrichmentPlane = heavyEnrichmentPlane
    }

    // MARK: Enrichment

    /// Enrich a raw event with ancestry and code-signing data.
    ///
    /// Processing steps:
    /// 1. Update the lineage graph based on the event action.
    /// 2. Retrieve the ancestor chain from the lineage.
    /// 3. Evaluate code signing for the process executable.
    /// 4. Return a new `Event` carrying the enriched `ProcessInfo`.
    ///
    /// - Parameter event: The raw event from the collector.
    /// - Returns: A copy of the event with enriched process metadata.
    public func enrich(_ event: Event) async -> Event {
        let proc = event.process

        // --- 1. Update lineage graph ---
        await updateLineage(for: event)

        // --- 2. Retrieve ancestors + direct-parent enrichment in one hop ---
        // Tier-B #10: fold the former separate `ancestors(of:)` and
        // `parentInfo(of:)` awaits into a single actor call. `parentInfo` is
        // consumed later (step 5) when building the enriched event.
        let (ancestors, parentInfo) = await lineage.ancestorsAndParentInfo(of: proc.pid)

        // --- 3. Resolve heavyweight evidence without running misses here ---
        //
        // Collector evidence and validated cache hits stay on this event. A
        // Security/hash/sysctl/file-content miss is offered to the bounded
        // heavy plane and represented honestly as pending/rejected coverage.
        // EventLoop consumes the identity-bound patch later and re-runs the
        // rules that depend on it; no rule input is silently discarded.
        let binding = HeavyEnrichmentBinding(event: event)
        var heavyCoverage: [HeavyEnrichmentComponent: HeavyEnrichmentCoverage] = [:]

        let codeSignatureResolution = await resolveCodeSignature(
            for: event,
            binding: binding
        )
        let codeSignature = codeSignatureResolution.value
        if let state = codeSignatureResolution.coverage {
            heavyCoverage[.codeSignature] = state
        }

        let hashResolution = await resolveHashes(for: event, binding: binding)
        let hashes = hashResolution.value
        if let state = hashResolution.coverage {
            heavyCoverage[.processHashes] = state
        }

        let environmentResolution = await resolveEnvironment(for: event, binding: binding)
        let environment = environmentResolution.value
        if let state = environmentResolution.coverage {
            heavyCoverage[.environment] = state
        }

        let userNameResolution = await resolveUserName(for: event, binding: binding)
        let resolvedUserName = userNameResolution.value ?? proc.userName
        if let state = userNameResolution.coverage {
            heavyCoverage[.userName] = state
        }

        // --- 3.6 Session / launch-source inference ---
        //
        // Pure ancestor-chain analysis: identifies whether the process
        // was launched via SSH, Terminal, Finder, launchd, cron, etc.
        // Feeds IsSSHLaunched / LaunchSource rule selectors. Preserves
        // anything the collector already set.
        let session = proc.session
            ?? SessionEnricher.enrich(pid: proc.pid, ancestors: ancestors.isEmpty ? proc.ancestors : ancestors)
            ?? telemetryGapSession(ancestors: ancestors.isEmpty ? proc.ancestors : ancestors)

        // --- 4. Build enriched ProcessInfo ---
        let enrichedProcess = ProcessInfo(
            pid: proc.pid,
            ppid: proc.ppid,
            rpid: proc.rpid,
            name: proc.name,
            executable: proc.executable,
            commandLine: proc.commandLine,
            args: proc.args,
            workingDirectory: proc.workingDirectory,
            userId: proc.userId,
            userName: resolvedUserName,
            groupId: proc.groupId,
            startTime: proc.startTime,
            exitCode: proc.exitCode,
            codeSignature: codeSignature,
            ancestors: ancestors.isEmpty ? proc.ancestors : ancestors,
            architecture: proc.architecture,
            isPlatformBinary: proc.isPlatformBinary,
            hashes: hashes,
            session: session,
            envVars: environment,
            // v1.21.4 (P6 fix, part 2): preserve the real audit identity through
            // enrichment. This ProcessInfo rebuild otherwise dropped the field
            // (defaulting to nil), which made the agent-trace direct correlation
            // in EventLoop skip on EVERY event — the P6 fix was inert without it.
            auditIdentity: proc.auditIdentity
        )

        // --- 5. Build enriched Event ---
        var enrichedEvent = Event(
            id: event.id,
            timestamp: event.timestamp,
            eventCategory: event.eventCategory,
            eventType: event.eventType,
            eventAction: event.eventAction,
            process: enrichedProcess,
            file: event.file,
            network: event.network,
            tcc: event.tcc,
            enrichments: event.enrichments,
            severity: event.severity,
            ruleMatches: event.ruleMatches
        )

        // Populate parent enrichment fields from lineage (fetched in step 2)
        if let parentInfo {
            if let pcl = parentInfo.commandLine {
                enrichedEvent.enrichments["parent.commandline"] = pcl
            }
            if let pst = parentInfo.signerType {
                enrichedEvent.enrichments["ParentSignerType"] = pst
            }
        }

        // Deception tier: flag any file event whose path matches a deployed
        // honeyfile. Near-zero false positives by design — legitimate software
        // doesn't read canary credential paths.
        if let filePath = event.file?.path,
           let deception = honeyfileManager,
           await deception.isHoneyfile(filePath) {
            enrichedEvent.enrichments["IsHoneyfile"] = "true"
            if let record = await deception.honeyfile(atPath: filePath) {
                enrichedEvent.enrichments["HoneyfileType"] = record.type.rawValue
            }
        }

        // v1.12.0 honey-prompt tier: same enrichment shape, different
        // deception primitive (AI-agent context bait). The existing
        // honeyfile_accessed rule keys off IsHoneyfile so both feed
        // the same detection.
        if let filePath = event.file?.path,
           let promptDeception = honeyPromptManager,
           await promptDeception.isHoneyPrompt(filePath) {
            enrichedEvent.enrichments["IsHoneyfile"] = "true"
            if let record = await promptDeception.honeyPrompt(atPath: filePath) {
                enrichedEvent.enrichments["HoneyfileType"] = record.type.rawValue
            }
        }

        // FileContent evidence is load-bearing rule input.  A miss is now a
        // conserved deferred read of the exact close event rather than a
        // token-bucket nil that permanently loses that write.
        let fileContentResolution = await resolveFileContent(for: event, binding: binding)
        if let evidence = fileContentResolution.value {
            enrichedEvent.enrichments["FileContent"] = evidence.content
        }
        if let state = fileContentResolution.coverage {
            heavyCoverage[.fileContent] = state
        }

        DeferredEventEnrichment.storeCoverage(heavyCoverage, in: &enrichedEvent.enrichments)

        // Mark that enrichment has been applied.
        enrichedEvent.enrichments["enriched"] = "true"

        // --- 6. Periodic prune ---
        enrichmentCount += 1
        if enrichmentCount % pruneInterval == 0 {
            await lineage.prune()
        }

        return enrichedEvent
    }

    // MARK: Graceful attribution (telemetry gap)

    /// Honest-degradation fallback for the session/launch-source resolution.
    ///
    /// Reached ONLY when `SessionEnricher` could not classify the process
    /// (nil result ⇒ empty ancestry). Returns a `.telemetryGap` session IFF a
    /// kernel telemetry gap is active for the current window; otherwise nil so
    /// the event stays a silent NULL / `.unknown`. Both gates are required —
    /// empty ancestry AND an active drop — so a benign orphan (double-fork /
    /// setsid) during a no-drop window is NOT mislabelled. Mirrors
    /// `DeliveryProvenanceWeld.Decision.degradedMissingInput`
    /// (DeliveryProvenanceWeld.swift:156-160): degrade honestly rather than guess.
    private func telemetryGapSession(ancestors: [ProcessAncestor]) -> SessionInfo? {
        guard ancestors.isEmpty, telemetryGapSignal?() == true else { return nil }
        return SessionInfo(launchSource: .telemetryGap)
    }

    // MARK: Heavy evidence resolution

    private func resolveCodeSignature(
        for event: Event,
        binding: HeavyEnrichmentBinding
    ) async -> HeavyFieldResolution<CodeSignatureInfo> {
        let process = event.process
        let collectorSignature = process.codeSignature
        let needsCryptographicVerification = collectorSignature?.signerType == .apple
            && !process.isPlatformBinary

        // Kernel-derived ordinary classifications are complete.  The one
        // spoofable `.apple && !platform` classification must be re-anchored.
        if let collectorSignature, !needsCryptographicVerification {
            return .complete(collectorSignature)
        }

        // A validated CodeSigningCache hit is intentionally same-event.  The
        // cache re-stats the path and rejects a same-path replacement before
        // returning a verdict.
        if let cached = await codeSigningCache.lookup(path: process.executable) {
            if let collectorSignature {
                return .complete(
                    cached.signerType == .apple
                        ? collectorSignature
                        : collectorSignature.withSignerType(cached.signerType)
                )
            }
            return .complete(cached)
        }

        let path = process.executable
        let cache = codeSigningCache
        let offer = await heavyEnrichmentPlane.offer(
            component: .codeSignature,
            binding: binding,
            cacheResult: false
        ) {
            let before = HeavyEnrichmentFileIdentity.capture(path: path)
            let verified = await cache.evaluate(path: path)
            let after = HeavyEnrichmentFileIdentity.capture(path: path)
            guard let stable = after, before == stable else {
                // Never publish a trusted verdict when the path was absent or
                // changed while Security.framework evaluated it.
                return .codeSignature(HeavyCodeSignatureEvidence(
                    value: nil,
                    fileIdentity: nil
                ))
            }
            let final: CodeSignatureInfo
            if let collectorSignature {
                final = verified.signerType == .apple
                    ? collectorSignature
                    : collectorSignature.withSignerType(verified.signerType)
            } else {
                final = verified
            }
            return .codeSignature(HeavyCodeSignatureEvidence(
                value: final,
                fileIdentity: stable
            ))
        }
        switch offer {
        case .cacheHit(.codeSignature(let evidence)):
            guard let value = evidence.value, evidence.fileIdentity != nil else {
                return .degraded(.unavailable)
            }
            return .complete(value)
        case .cacheHit:
            return .degraded(.unavailable)
        case .pending:
            return .degraded(.pending)
        case .rejected:
            return .degraded(.rejected)
        }
    }

    /// Preserves collector hashes immediately; a launch-event miss is hashed
    /// on the heavy plane and bound to one stable executable identity.
    private func resolveHashes(
        for event: Event,
        binding: HeavyEnrichmentBinding
    ) async -> HeavyFieldResolution<ProcessHashes> {
        if let existing = event.process.hashes { return .complete(existing) }
        guard let hasher = processHasher,
              event.eventCategory == .process,
              event.eventAction == "exec" || event.eventAction == "fork" else {
            return .complete(nil)
        }

        let path = event.process.executable
        let pid = event.process.pid
        let offer = await heavyEnrichmentPlane.offer(
            component: .processHashes,
            binding: binding,
            cacheResult: false
        ) {
            let before = HeavyEnrichmentFileIdentity.capture(path: path)
            let computed = await hasher.hash(pid: pid, executablePath: path)
            let after = HeavyEnrichmentFileIdentity.capture(path: path)
            guard computed.hasAny, let stable = after, before == stable else {
                return .processHashes(HeavyProcessHashEvidence(
                    value: nil,
                    fileIdentity: nil
                ))
            }
            return .processHashes(HeavyProcessHashEvidence(
                value: ProcessHashes(
                    sha256: computed.sha256,
                    cdhash: computed.cdhash,
                    md5: nil
                ),
                fileIdentity: stable
            ))
        }
        switch offer {
        case .cacheHit(.processHashes(let evidence)):
            guard let value = evidence.value, evidence.fileIdentity != nil else {
                return .degraded(.unavailable)
            }
            return .complete(value)
        case .cacheHit:
            return .degraded(.unavailable)
        case .pending:
            return .degraded(.pending)
        case .rejected:
            return .degraded(.rejected)
        }
    }

    /// Opt-in sysctl capture runs off the ingestion actor.  PID/start/path are
    /// checked before and after capture so rapid PID reuse cannot attach a new
    /// process's environment to the old exec event.
    private func resolveEnvironment(
        for event: Event,
        binding: HeavyEnrichmentBinding
    ) async -> HeavyFieldResolution<[String: String]> {
        if let existing = event.process.envVars { return .complete(existing) }
        guard captureEnv,
              event.eventCategory == .process,
              event.eventAction == "exec" || event.eventAction == "fork" else {
            return .complete(nil)
        }

        let offer = await heavyEnrichmentPlane.offer(
            component: .environment,
            binding: binding,
            cacheResult: false
        ) {
            guard HeavyEnrichmentLiveProcessIdentity.matches(binding) else {
                return .environment(nil)
            }
            let value = EnvCapture.capture(pid: binding.processID)
            guard HeavyEnrichmentLiveProcessIdentity.matches(binding) else {
                return .environment(nil)
            }
            return .environment(value)
        }
        switch offer {
        case .cacheHit(.environment(let value)):
            return value.map(HeavyFieldResolution.complete) ?? .degraded(.unavailable)
        case .cacheHit:
            return .degraded(.unavailable)
        case .pending:
            return .degraded(.pending)
        case .rejected:
            return .degraded(.rejected)
        }
    }

    /// getpwuid can reach directory services.  Only a lock-protected cache hit
    /// runs inline; the first lookup for a UID is owned by the heavy plane and
    /// all events for that same identity coalesce.
    private func resolveUserName(
        for event: Event,
        binding: HeavyEnrichmentBinding
    ) async -> HeavyFieldResolution<String> {
        if !event.process.userName.isEmpty { return .complete(event.process.userName) }
        if let cached = Self.userNameCache.lookup(event.process.userId) {
            return cached.isEmpty ? .degraded(.unavailable) : .complete(cached)
        }

        let uid = event.process.userId
        let offer = await heavyEnrichmentPlane.offer(
            component: .userName,
            binding: binding
        ) {
            .userName(Self.userNameForUid(uid))
        }
        switch offer {
        case .cacheHit(.userName(let value)):
            guard let value, !value.isEmpty else { return .degraded(.unavailable) }
            return .complete(value)
        case .cacheHit:
            return .degraded(.unavailable)
        case .pending:
            return .degraded(.pending)
        case .rejected:
            return .degraded(.rejected)
        }
    }

    private func resolveFileContent(
        for event: Event,
        binding: HeavyEnrichmentBinding
    ) async -> HeavyFieldResolution<HeavyFileContentEvidence> {
        guard let scanner = fileContentEnricher,
              let path = event.file?.path,
              event.eventCategory == .file,
              event.eventAction.hasPrefix("close"),
              FileContentEnricher.shouldScan(targetPath: path) else {
            return .complete(nil)
        }

        let offer = await heavyEnrichmentPlane.offer(
            component: .fileContent,
            binding: binding,
            maximumResultBytes: max(1, scanner.maxBytes + 512)
        ) {
            let maximumBytes = scanner.maxBytes
            let maximumFileSize = scanner.maxFileSize
            return .fileContent(HeavyFileContentEvidence.read(
                path: path,
                maximumBytes: maximumBytes,
                maximumFileSize: maximumFileSize
            ))
        }
        switch offer {
        case .cacheHit(.fileContent(let evidence)):
            return evidence.map(HeavyFieldResolution.complete) ?? .degraded(.unavailable)
        case .cacheHit:
            return .degraded(.unavailable)
        case .pending:
            return .degraded(.pending)
        case .rejected:
            return .degraded(.rejected)
        }
    }

    // MARK: Lineage Updates

    /// Update the lineage graph based on the event's category and action.
    private func updateLineage(for event: Event) async {
        let proc = event.process

        switch (event.eventCategory, event.eventAction) {
        case (.process, "exec"), (.process, "fork"):
            // New process observed — record in the lineage graph.
            await lineage.recordProcess(
                pid: proc.pid,
                ppid: proc.ppid,
                path: proc.executable,
                name: proc.name,
                startTime: proc.startTime,
                commandLine: proc.commandLine,
                signerType: proc.codeSignature?.signerType.rawValue
            )

        case (.process, "exit"):
            // Process exiting — mark in the lineage for deferred pruning.
            await lineage.recordExit(pid: proc.pid)

        default:
            // Non-process events (file, network, tcc) still contribute to the
            // lineage if the acting process is not yet tracked.
            let alreadyTracked = await lineage.contains(pid: proc.pid)
            if !alreadyTracked {
                await lineage.recordProcess(
                    pid: proc.pid,
                    ppid: proc.ppid,
                    path: proc.executable,
                    name: proc.name,
                    startTime: proc.startTime,
                    commandLine: proc.commandLine,
                    signerType: proc.codeSignature?.signerType.rawValue
                )
            }
        }
    }

    // MARK: Diagnostics

    /// Number of processes currently tracked in the lineage graph.
    public func lineageNodeCount() async -> Int {
        await lineage.nodeCount
    }

    /// Terminal evidence patches for the daemon's bounded deferred
    /// re-evaluation lane.  The caller should batch by event ID before running
    /// detection so one event with multiple components is evaluated once.
    public func drainDeferredEnrichments(
        limit: Int = 128,
        maximumBytes: Int = Int.max
    ) async -> [DeferredEventEnrichment] {
        await heavyEnrichmentPlane.drainDeferredResults(
            limit: limit,
            maximumBytes: maximumBytes
        )
    }

    package func drainOwnedDeferredEnrichments(
        limit: Int = 128,
        maximumBytes: Int = Int.max
    ) async -> [OwnedDeferredEventEnrichment] {
        await heavyEnrichmentPlane.drainOwnedDeferredResults(
            limit: limit,
            maximumBytes: maximumBytes
        )
    }

    public func heavyEnrichmentSnapshot() async -> HeavyEnrichmentPlaneSnapshot {
        await heavyEnrichmentPlane.snapshot()
    }

    /// One-shot shutdown seam.  Admission seals before cancellation and an
    /// uncooperative syscall remains visible as a lingering physical worker.
    @discardableResult
    public func shutdownHeavyEnrichment(
        deadlineSeconds: TimeInterval = 1.0
    ) async -> HeavyEnrichmentPlaneSnapshot {
        await heavyEnrichmentPlane.shutdown(deadlineSeconds: deadlineSeconds)
    }

    // MARK: - User name resolution (Wave 9I)

    /// Per-uid cache of resolved user names. On a single-user macOS
    /// workstation almost every event has the same uid, so a tiny
    /// dictionary collapses the per-event cost to one getpwuid call
    /// total. Protected by a serial queue rather than the actor's
    /// executor because callers from `enrich(_:)` are already on the
    /// actor, but we want the cache to outlive the resolver call
    /// without forcing more actor hops. Using a class with a lock
    /// avoids the actor-isolation issue cleanly.
    private static let userNameCache = UserNameCache()

    fileprivate static func userNameForUid(_ uid: UInt32) -> String {
        Self.userNameCache.name(for: uid)
    }
}

/// Tiny thread-safe uid → name cache backing `EventEnricher`.
/// Defined at file scope so it doesn't inherit `EventEnricher`'s
/// actor isolation — calls into it are cheap, lock-protected reads.
private final class UserNameCache: @unchecked Sendable {
    private var entries: [UInt32: String] = [:]
    private let lock = NSLock()

    func lookup(_ uid: UInt32) -> String? {
        lock.lock()
        defer { lock.unlock() }
        return entries[uid]
    }

    func name(for uid: UInt32) -> String {
        lock.lock()
        defer { lock.unlock() }
        if let cached = entries[uid] {
            return cached
        }

        // Resolve via libc. `getpwuid` may return nil for daemon /
        // service uids that don't have a passwd entry; in that case
        // store "" so we don't re-syscall on the next event. Keep the lock
        // through getpwuid: libc returns process-global static storage, so
        // concurrent misses for different UIDs must not race while copying it.
        let resolved: String
        if let pw = getpwuid(uid_t(uid)) {
            resolved = String(cString: pw.pointee.pw_name)
        } else {
            resolved = ""
        }
        entries[uid] = resolved
        return resolved
    }
}

// MARK: - TelemetryGapProbe

/// Rolling kernel-drop probe backing `EventEnricher`'s telemetry-gap gate.
///
/// Holds the last-observed cumulative kernel-drop count and reports `true`
/// when it has advanced since the previous poll — i.e. the ES per-client queue
/// is actively shedding messages for the current window. `read` pulls the live
/// count (`ESCollector.esGlobalDropped()`) and is nil-safe at the call site, so
/// a non-root / no-collector build simply reports no gap. One `NSLock` guards
/// the rolling baseline (the enrichment actor polls it). `@unchecked Sendable`
/// so `.signal` can be handed to the actor as a plain `@Sendable () -> Bool`
/// even though `read` captures the daemon's collector handle.
public final class TelemetryGapProbe: @unchecked Sendable {
    private let lock = NSLock()
    private var lastDropCount: UInt64 = 0
    private let read: () -> UInt64

    /// - Parameter read: pulls the current cumulative kernel-drop count.
    ///   Called once per poll; must be cheap and non-blocking.
    public init(read: @escaping () -> UInt64) {
        self.read = read
    }

    /// `true` when the drop count has advanced since the previous poll.
    /// Advances the rolling baseline as a side effect so each increase is
    /// reported exactly once.
    public func gapActive() -> Bool {
        let current = read()
        lock.lock()
        defer { lock.unlock() }
        let increased = current > lastDropCount
        lastDropCount = current
        return increased
    }

    /// A `@Sendable` gap signal suitable for `EventEnricher(telemetryGapSignal:)`.
    public var signal: @Sendable () -> Bool {
        { [self] in self.gapActive() }
    }
}
