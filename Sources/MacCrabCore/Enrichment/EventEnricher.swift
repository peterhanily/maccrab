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

    private let userNameCache: UserNameCache

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
        heavyEnrichmentPlane: HeavyEnrichmentPlane = HeavyEnrichmentPlane(),
        userNameResolver: (@Sendable (UInt32) -> String?)? = nil
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
        self.userNameCache = userNameResolver.map { UserNameCache(resolver: $0) }
            ?? Self.sharedUserNameCache
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
        } else if Self.lineageSignerType(proc) == nil, let codeSignature {
            // Children read the parent's signer as ParentSignerType, so a
            // verified verdict replaces the unknown recorded in step 1.
            await lineage.recordVerifiedSignerType(
                pid: proc.pid,
                path: proc.executable,
                signerType: codeSignature.signerType.rawValue
            )
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

    /// Teams whose attested identity buys an exemption somewhere in the
    /// engine: MacCrab's own, Apple's developer tools, Google's and Brave's.
    static let exemptionTeamIds: Set<String> = [
        NoiseFilter.macCrabTeamId, CredentialFence.appleDeveloperToolsTeamId,
        CredentialFence.googleTeamId, CredentialFence.braveTeamId,
    ]

    /// Whether a collector classification must be re-anchored by Security
    /// before it is believed. The kernel reports the team a code directory
    /// names; a `com.apple.*` identifier can claim `.apple` without the
    /// platform flag, and a chain rooted anywhere can claim Developer ID with
    /// any team. Only a claim that would buy trust is re-checked: `.apple`
    /// off a platform binary, and a Developer ID or App Store claim naming an
    /// exemption team. Security classifies a chain not rooted at Apple as
    /// `.adHoc`, and the published signature carries that signer, so the
    /// team then attests nothing downstream. Each such file costs one
    /// Security evaluation while its identity holds: the verdict is cached
    /// against that identity until the file changes or the cache evicts it,
    /// and an evaluation that has not finished leaves nothing cached, so the
    /// next event for the path offers it again.
    static func needsCryptographicVerification(_ signature: CodeSignatureInfo?, isPlatformBinary: Bool) -> Bool {
        guard let signature else { return false }
        if signature.signerType == .apple { return !isPlatformBinary }
        if signature.signerType == .devId || signature.signerType == .appStore,
           let team = signature.teamId, exemptionTeamIds.contains(team) {
            return true
        }
        return false
    }

    /// The signature an event publishes once Security has judged the file
    /// at its process's path. A verdict that grants trust (Apple, App Store,
    /// Developer ID) describes that file, not the process: it is believed
    /// only when the file's code directory hashes include the one the kernel
    /// reports for the image the process runs, and is then taken whole, its
    /// class, team, identifier, flags and notarization all Security's. An
    /// Apple verdict confirms only an Apple claim. A Developer ID or App
    /// Store verdict on an Apple claim is the downgrade Security found and is
    /// published as found: Xcode from the App Store names itself com.apple.*
    /// and is App Store signed. Any other trusted verdict leaves the claim
    /// unverified, carried as the collector carries an ad-hoc signature: no
    /// team, its identifier and the kernel's flags. A producer that reported
    /// no signature keeps none while the running image is unknown, and reads
    /// as ad-hoc when the image is known and is not the file's. A verdict
    /// that grants nothing (ad-hoc, unsigned) needs no binding, and an event
    /// without a process has no image to bind to. A process that Rosetta
    /// translates runs the x86_64 slice, whose hash the native-slice
    /// evaluation lacks, so its trusted claim stays unverified.
    static func publishedSignature(
        claim: CodeSignatureInfo?,
        verdict: CodeSigningCache.Verdict,
        kernelCdhash: String?,
        hasProcess: Bool = true
    ) -> CodeSignatureInfo? {
        let found = verdict.info.withKernelCdhash(kernelCdhash)
        switch found.signerType {
        case .adHoc, .unsigned:
            return found
        case .apple, .appStore, .devId:
            break
        }
        guard hasProcess else { return found }
        let bound = kernelCdhash.map { verdict.cdhashes.contains($0) } ?? false
        let raisesClaim = found.signerType == .apple && claim.map { $0.signerType != .apple } == true
        if bound, !raisesClaim { return found }
        if let claim {
            return CodeSignatureInfo(
                signerType: .adHoc, signingId: claim.signingId, flags: claim.flags, kernelCdhash: kernelCdhash)
        }
        return kernelCdhash.map { CodeSignatureInfo(signerType: .adHoc, kernelCdhash: $0) }
    }

    /// Reads the kernel's code directory hash for a live process, for a
    /// producer whose event carries no signature to take it from.
    private let kernelCdhashReader = CDHashExtractor()

    private func resolveCodeSignature(
        for event: Event,
        binding: HeavyEnrichmentBinding
    ) async -> HeavyFieldResolution<CodeSignatureInfo> {
        let process = event.process
        let claim = process.codeSignature
        let hasProcess = process.pid > 0

        if let claim {
            // A kernel classification that buys nothing is complete as
            // reported. One that would buy trust is believed only after
            // Security has judged the image the process runs.
            let needsVerification = Self.needsCryptographicVerification(
                claim, isPlatformBinary: process.isPlatformBinary)
            // An event without a process, a TCC record about a client
            // binary, carries its collector's own Security verdict on that
            // file; there is no running image to bind it to.
            if !needsVerification || !hasProcess {
                return .complete(claim)
            }
        }

        // The running image's code directory hash: the kernel's, carried by
        // an Endpoint Security claim, or read by pid for a producer that
        // reported no signature. Unknown leaves no trusted verdict to publish.
        let kernelCdhash: String?
        if let claim {
            kernelCdhash = claim.kernelCdhash
        } else if hasProcess {
            kernelCdhash = await kernelCdhashReader.extractCDHash(pid: process.pid)
        } else {
            kernelCdhash = nil
        }

        // A cached verdict is served only while the path still holds the
        // bytes it judged (the cache re-stats it), and believed only for the
        // image this process runs.
        if let cached = codeSigningCache.lookupVerdict(path: process.executable) {
            guard let published = Self.publishedSignature(
                claim: claim, verdict: cached, kernelCdhash: kernelCdhash, hasProcess: hasProcess
            ) else {
                return .degraded(.unavailable)
            }
            return .complete(published)
        }

        let path = process.executable
        let cache = codeSigningCache
        let offer = await heavyEnrichmentPlane.offer(
            component: .codeSignature,
            binding: binding,
            cacheResult: false
        ) {
            let before = HeavyEnrichmentFileIdentity.capture(path: path)
            // Nothing to bind a verdict to, or nothing Security.framework may
            // open: the path is missing, or no longer a regular file.
            guard before != nil,
                  let verdict = await cache.evaluateExecutableVerdict(path: path) else {
                return .codeSignature(HeavyCodeSignatureEvidence(
                    value: nil,
                    fileIdentity: nil
                ))
            }
            let after = HeavyEnrichmentFileIdentity.capture(path: path)
            guard let stable = after, before == stable,
                  let published = Self.publishedSignature(
                    claim: claim, verdict: verdict, kernelCdhash: kernelCdhash, hasProcess: hasProcess
                  ) else {
                // Never publish a trusted verdict when the path was absent or
                // changed while Security.framework evaluated it, or when it
                // binds to no known running image.
                return .codeSignature(HeavyCodeSignatureEvidence(
                    value: nil,
                    fileIdentity: nil
                ))
            }
            return .codeSignature(HeavyCodeSignatureEvidence(
                value: published,
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
            let pid = binding.processID
            let value = await HeavyEnrichmentBlockingWork.run {
                EnvCapture.capture(pid: pid)
            }
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

    /// getpwuid_r can reach directory services. Only a cache hit
    /// runs inline; the first lookup for a UID is owned by the heavy plane and
    /// all events for that same identity coalesce.
    private func resolveUserName(
        for event: Event,
        binding: HeavyEnrichmentBinding
    ) async -> HeavyFieldResolution<String> {
        if !event.process.userName.isEmpty { return .complete(event.process.userName) }
        if let cached = userNameCache.lookup(event.process.userId) {
            return .complete(cached)
        }

        let uid = event.process.userId
        let cache = userNameCache
        let offer = await heavyEnrichmentPlane.offer(
            component: .userName,
            binding: binding
        ) {
            // Publication belongs to the plane's accepted terminal result,
            // not this syscall: cancellation cannot retract an inline cache.
            .userName(await HeavyEnrichmentBlockingWork.run {
                cache.name(for: uid, cacheResult: false)
            })
        }
        switch offer {
        case .cacheHit(.userName(let value)):
            guard let value, !value.isEmpty else { return .degraded(.unavailable) }
            cache.accept(value, for: uid)
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

        let actorUID = event.process.userId
        let offer = await heavyEnrichmentPlane.offer(
            component: .fileContent,
            binding: binding,
            maximumResultBytes: max(1, scanner.maxBytes + 512)
        ) {
            let maximumBytes = scanner.maxBytes
            let maximumFileSize = scanner.maxFileSize
            let evidence = await HeavyEnrichmentBlockingWork.run {
                HeavyFileContentEvidence.read(
                    path: path,
                    maximumBytes: maximumBytes,
                    maximumFileSize: maximumFileSize,
                    hardLinkOwnerUID: actorUID
                )
            }
            // The path may legitimately be replaced or rewritten after the ES
            // close event but before this deferred descriptor read. Reject that
            // stale snapshot inside the worker as an ordinary unavailable
            // result, before it becomes an identity-rejected terminal patch.
            guard let evidence else { return .fileContent(nil) }
            if let expectedSize = binding.eventFileSize,
               UInt64(exactly: evidence.fileIdentity.sizeBytes) != expectedSize {
                return .fileContent(nil)
            }
            return .fileContent(evidence)
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

    /// The signer a child may read as `ParentSignerType`. The collector's
    /// `.apple` for a non-platform binary is a spoofable claim (any binary can
    /// name itself com.apple.*), so it stays unknown until verified.
    static func lineageSignerType(_ process: ProcessInfo) -> String? {
        guard let signature = process.codeSignature else { return nil }
        if signature.signerType == .apple, !process.isPlatformBinary { return nil }
        return signature.signerType.rawValue
    }

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
                signerType: Self.lineageSignerType(proc)
            )

        case (.process, "exit"):
            // Process exiting — mark in the lineage for deferred pruning.
            await lineage.recordExit(pid: proc.pid)

        default:
            // Non-process events (file, network, tcc) still contribute to the
            // lineage if the acting process is not yet tracked. Only Endpoint
            // Security carries the audit token and the kernel's birth time;
            // other sources start the process when they first saw it.
            await lineage.recordProcessIfAbsent(
                pid: proc.pid,
                ppid: proc.ppid,
                path: proc.executable,
                name: proc.name,
                startTime: proc.startTime,
                commandLine: proc.commandLine,
                signerType: Self.lineageSignerType(proc),
                startTimeIsBirth: proc.auditIdentity != nil
            )
        }
    }

    // MARK: Diagnostics

    /// Advisory only; the authoritative deferred drain remains actor-owned.
    package nonisolated var hasDeferredEnrichments: Bool {
        heavyEnrichmentPlane.hasDeferredResults
    }

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
        let patches = await heavyEnrichmentPlane.drainDeferredResults(
            limit: limit,
            maximumBytes: maximumBytes
        )
        for patch in patches { cacheAcceptedUserName(patch) }
        return patches
    }

    package func drainOwnedDeferredEnrichments(
        limit: Int = 128,
        maximumBytes: Int = Int.max
    ) async -> [OwnedDeferredEventEnrichment] {
        let results = await heavyEnrichmentPlane.drainOwnedDeferredResults(
            limit: limit,
            maximumBytes: maximumBytes
        )
        for result in results { cacheAcceptedUserName(result.patch) }
        return results
    }

    private func cacheAcceptedUserName(_ patch: DeferredEventEnrichment) {
        guard patch.component == .userName, patch.outcome == .completed,
              case .userName(let name)? = patch.value, let name else { return }
        userNameCache.accept(name, for: patch.binding.userID)
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
    /// bounded dictionary avoids repeated directory calls for resident UIDs.
    /// Its lock protects only bookkeeping, never the directory lookup.
    private static let sharedUserNameCache = UserNameCache()
}

/// Bounded thread-safe uid → name cache backing `EventEnricher`.
/// Defined at file scope so it doesn't inherit `EventEnricher`'s
/// actor isolation. FIFO eviction changes only memoization: an evicted UID
/// is resolved normally on its next miss. Unavailable results are not cached:
/// a transient directory-service failure must not poison a UID until restart.
/// The existing heavy-enrichment plane remains the owner of blocking misses.
final class UserNameCache: @unchecked Sendable {
    static let maximumEntries = 256

    private var entries: [UInt32: String] = [:]
    private var insertionOrder: [UInt32] = []
    private var nextEvictionIndex = 0
    private let capacity: Int
    private let resolver: @Sendable (UInt32) -> String?
    private var resolving = false
    private let lock = NSLock()

    convenience init() {
        self.init(capacity: Self.maximumEntries, resolver: { Self.resolveSystemName($0) })
    }

    /// Internal explicit-resolver seam; tests never contact directory services.
    /// Smaller capacities exercise the same ring; callers cannot raise its cap.
    init(capacity: Int = UserNameCache.maximumEntries,
         resolver: @escaping @Sendable (UInt32) -> String?) {
        self.capacity = max(1, min(capacity, Self.maximumEntries))
        self.resolver = resolver
        entries.reserveCapacity(self.capacity)
        insertionOrder.reserveCapacity(self.capacity)
    }

    func lookup(_ uid: UInt32) -> String? {
        // Inline event-actor reads must not wait behind directory services.
        // Busy is a cache miss; the existing bounded heavy-enrichment offer
        // owns resolution and exposes pending/rejected coverage as before.
        guard lock.try() else { return nil }
        defer { lock.unlock() }
        return entries[uid]
    }

    func name(for uid: UInt32, cacheResult: Bool = true) -> String? {
        lock.lock()
        if let cached = entries[uid] {
            lock.unlock()
            return cached
        }
        // The heavy plane owns normal coalescing and its physical-worker cap.
        // This nonblocking gate also bounds the shared cache across separate
        // planes: never wait on, or duplicate, an outstanding directory call.
        guard !resolving else { lock.unlock(); return nil }
        resolving = true
        lock.unlock()
        let resolved = resolver(uid)
        lock.lock()
        defer { resolving = false; lock.unlock() }
        // Cancellation is an early exit, not the publication authority. The
        // production worker uses cacheResult:false and only its plane-accepted
        // result may later call accept(), eliminating the deadline/cache race.
        guard !Task.isCancelled, let resolved, !resolved.isEmpty,
              HeavyEnrichmentValue.userName(resolved).retainedByteEstimate
                <= HeavyEnrichmentComponent.userName.defaultMaximumResultBytes else { return nil }
        if cacheResult { insert(resolved, for: uid) }
        return resolved
    }

    /// Seed only from an accepted plane completion or an already accepted
    /// plane cache hit. Empty/error/oversized values are never memoized.
    func accept(_ resolved: String, for uid: UInt32) {
        guard !resolved.isEmpty,
              HeavyEnrichmentValue.userName(resolved).retainedByteEstimate
                <= HeavyEnrichmentComponent.userName.defaultMaximumResultBytes else { return }
        lock.lock()
        defer { lock.unlock() }
        insert(resolved, for: uid)
    }

    private func insert(_ resolved: String, for uid: UInt32) {
        if entries[uid] != nil { entries[uid] = resolved; return }
        if insertionOrder.count == capacity {
            entries.removeValue(forKey: insertionOrder[nextEvictionIndex])
            insertionOrder[nextEvictionIndex] = uid
            nextEvictionIndex = (nextEvictionIndex + 1) % capacity
        } else {
            insertionOrder.append(uid)
        }
        entries[uid] = resolved
    }

    private static func resolveSystemName(_ uid: UInt32) -> String? {
        // Reentrant lookup with exclusively owned storage. Bound ERANGE growth
        // even for malformed directory records; errors remain unavailable and
        // can recover on a later event. No cache lock covers this syscall.
        var size = 1_024
        while size <= 64 * 1_024 {
            var record = passwd()
            var result: UnsafeMutablePointer<passwd>?
            var storage = [CChar](repeating: 0, count: size)
            let (status, name) = storage.withUnsafeMutableBufferPointer { buffer -> (Int32, String?) in
                let status = getpwuid_r(uid_t(uid), &record, buffer.baseAddress!, buffer.count, &result)
                guard status == 0, result != nil, let name = record.pw_name else { return (status, nil) }
                return (status, String(cString: name))
            }
            if status == ERANGE { size *= 2; continue }
            return name
        }
        return nil
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
