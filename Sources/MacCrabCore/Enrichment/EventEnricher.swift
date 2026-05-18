// EventEnricher.swift
// MacCrabCore
//
// Orchestrates enrichment of raw events from the Endpoint Security collector.
// Attaches process ancestry and code-signing information before events reach
// the detection engine.

import Foundation
import os.log

// MARK: - EventEnricher

/// Central enrichment pipeline for MacCrab events.
///
/// Owns the `ProcessLineage` graph and `CodeSigningCache`, using them to
/// augment each incoming event with:
/// - Full process ancestor chain (from the lineage DAG).
/// - Code-signing evaluation results (from the cache/Security framework).
///
/// All access is serialised through the actor, so callers can safely call
/// `enrich(_:)` from any concurrency context.
public actor EventEnricher {

    // MARK: Dependencies

    /// Process parent-child DAG.
    public let lineage: ProcessLineage

    /// Code-signing evaluation cache.
    private let codeSigningCache: CodeSigningCache

    /// Optional SHA-256/CDHash fingerprinter. When provided, exec/fork events
    /// get their `process.hashes` populated. Runs opportunistically — I/O
    /// errors or cache misses silently leave hashes nil so event throughput
    /// is never blocked by hashing latency.
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
    /// `enrichments["FileContent"]` for `FileContent|contains`
    /// rule selectors. Tight allowlist to keep the hot path fast.
    private let fileContentEnricher: FileContentEnricher?

    /// Opt-in: capture a filtered set of env vars from exec/fork processes
    /// via `sysctl(KERN_PROCARGS2)`. Costs a syscall per exec — gated at
    /// daemon startup by `MACCRAB_CAPTURE_ENV=1`.
    private let captureEnv: Bool

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
        pruneInterval: UInt64 = 5000
    ) {
        self.lineage = lineage
        self.codeSigningCache = codeSigningCache
        self.processHasher = processHasher
        self.honeyfileManager = honeyfileManager
        self.honeyPromptManager = honeyPromptManager
        self.fileContentEnricher = fileContentEnricher
        self.captureEnv = captureEnv
        self.pruneInterval = pruneInterval
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

        // --- 2. Retrieve ancestors ---
        let ancestors = await lineage.ancestors(of: proc.pid)

        // --- 3. Evaluate code signing ---
        let codeSignature: CodeSignatureInfo?
        if proc.codeSignature != nil {
            // The collector already provided signing info; keep it.
            codeSignature = proc.codeSignature
        } else {
            codeSignature = await codeSigningCache.evaluate(path: proc.executable)
        }

        // --- 3.5 Compute file + process hashes on exec/fork ---
        //
        // Only hash when a new process is observed; subsequent events
        // inherit the hash via the FileHasher cache if they share an
        // executable path. Avoids re-hashing a long-running process on
        // every file/network event it emits.
        let hashes = await resolveHashes(for: event, existing: proc.hashes)

        // --- 3.6 Session / launch-source inference ---
        //
        // Pure ancestor-chain analysis: identifies whether the process
        // was launched via SSH, Terminal, Finder, launchd, cron, etc.
        // Feeds IsSSHLaunched / LaunchSource rule selectors. Preserves
        // anything the collector already set.
        let session = proc.session
            ?? SessionEnricher.enrich(pid: proc.pid, ancestors: ancestors.isEmpty ? proc.ancestors : ancestors)

        // --- 4. Build enriched ProcessInfo ---
        // v1.12.6 Wave 9I: resolve uid → user_name when the collector
        // left it empty. ESHelpers.processFromESProcess sets userName
        // to "" because the ES framework only exposes audit-token UID;
        // resolution requires getpwuid(). Pre-9I that resolution never
        // happened, so 99.8% of events.db rows had user_id populated
        // but user_name NULL. The dashboard's Wave 9H "User" inspector
        // row showed empty as a result. Cached per-uid to avoid a
        // getpwuid syscall per event on a single-user machine.
        let resolvedUserName = proc.userName.isEmpty
            ? Self.userNameForUid(proc.userId)
            : proc.userName
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
            envVars: resolveEnvVars(for: event, existing: proc.envVars)
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

        // Populate parent enrichment fields from lineage
        if let parentInfo = await lineage.parentInfo(of: proc.pid) {
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

        // v1.12.0 FileContent enrichment: read first 64KB of the
        // target file on close-write events, but only for paths in
        // the FileContentEnricher allowlist (Info.plist, CHANGELOG,
        // README, .gitconfig, LaunchAgents plists, specific IOC
        // filenames). The rule layer uses
        // `FileContent|contains: '...'` selectors against this.
        //
        // v1.12.0 post-audit (M-Perf3, deferred to v1.12.x): this
        // synchronous file read sits on the enricher actor. Under
        // disk pressure (slow USB / network mount / encrypted volume)
        // it can stall enrichment of every other event. The audit
        // recommended detaching into a Task — but detaching is
        // incompatible with the rule pipeline's load-bearing
        // assumption that `enrichments["FileContent"]` is set BEFORE
        // rule eval on the SAME event. The proper fix is a small
        // in-memory FileContent cache keyed by (path, mtime) with a
        // read deadline (~50ms); on deadline-miss the event flows
        // through without FileContent and the cache picks up the
        // miss for the next event hitting the same path. Deferred to
        // v1.12.x — for v1.12.0 the allowlist is tight enough
        // (Info.plist + LaunchAgents + a handful of installer
        // filenames + bounded node_modules/site-packages source
        // files) that the synchronous cost is acceptable.
        if let scanner = fileContentEnricher,
           let filePath = event.file?.path,
           event.eventCategory == .file,
           event.eventAction == "close",
           FileContentEnricher.shouldScan(targetPath: filePath) {
            if let content = await scanner.scan(path: filePath) {
                enrichedEvent.enrichments["FileContent"] = content
            }
        }

        // Mark that enrichment has been applied.
        enrichedEvent.enrichments["enriched"] = "true"

        // --- 6. Periodic prune ---
        enrichmentCount += 1
        if enrichmentCount % pruneInterval == 0 {
            await lineage.prune()
        }

        return enrichedEvent
    }

    // MARK: Hashing

    /// Resolve `ProcessHashes` for an event. Preserves collector-provided
    /// hashes when present; otherwise opportunistically computes them for
    /// exec/fork events when a `ProcessHasher` is configured.
    private func resolveHashes(for event: Event, existing: ProcessHashes?) async -> ProcessHashes? {
        if let existing { return existing }
        guard let hasher = processHasher else { return nil }

        // Only fingerprint on process-launch events — keeps the hot path
        // short and avoids spurious SHA-256 recomputation on file / network
        // events emitted by long-running processes.
        guard event.eventCategory == .process,
              event.eventAction == "exec" || event.eventAction == "fork" else {
            return nil
        }

        let computed = await hasher.hash(
            pid: event.process.pid,
            executablePath: event.process.executable
        )
        guard computed.hasAny else { return nil }
        return ProcessHashes(
            sha256: computed.sha256,
            cdhash: computed.cdhash,
            md5: nil
        )
    }

    // MARK: Environment capture

    /// If captureEnv is enabled and the event is an exec/fork without
    /// pre-existing envVars, read the target process env via sysctl and
    /// filter through EnvCapture's allowlist/deny rules.
    private func resolveEnvVars(for event: Event, existing: [String: String]?) -> [String: String]? {
        if let existing { return existing }
        guard captureEnv else { return nil }
        guard event.eventCategory == .process,
              event.eventAction == "exec" || event.eventAction == "fork" else {
            return nil
        }
        return EnvCapture.capture(pid: event.process.pid)
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

    func name(for uid: UInt32) -> String {
        lock.lock()
        if let cached = entries[uid] {
            lock.unlock()
            return cached
        }
        lock.unlock()

        // Resolve via libc. `getpwuid` may return nil for daemon /
        // service uids that don't have a passwd entry; in that case
        // store "" so we don't re-syscall on the next event.
        let resolved: String
        if let pw = getpwuid(uid_t(uid)) {
            resolved = String(cString: pw.pointee.pw_name)
        } else {
            resolved = ""
        }
        lock.lock()
        entries[uid] = resolved
        lock.unlock()
        return resolved
    }
}
