// EventEnricher.swift
// HawkEyeCore
//
// Orchestrates enrichment of raw events from the Endpoint Security collector.
// Attaches process ancestry and code-signing information before events reach
// the detection engine.

import Foundation
import os.log

// MARK: - EventEnricher

/// Central enrichment pipeline for HawkEye events.
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
    private let lineage: ProcessLineage

    /// Code-signing evaluation cache.
    private let codeSigningCache: CodeSigningCache

    /// Logger scoped to the enrichment subsystem.
    private let log = Logger(
        subsystem: "com.hawkeye.core",
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
        pruneInterval: UInt64 = 5000
    ) {
        self.lineage = lineage
        self.codeSigningCache = codeSigningCache
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
            userName: proc.userName,
            groupId: proc.groupId,
            startTime: proc.startTime,
            exitCode: proc.exitCode,
            codeSignature: codeSignature,
            ancestors: ancestors.isEmpty ? proc.ancestors : ancestors,
            architecture: proc.architecture,
            isPlatformBinary: proc.isPlatformBinary
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

        // Mark that enrichment has been applied.
        enrichedEvent.enrichments["enriched"] = "true"

        // --- 6. Periodic prune ---
        enrichmentCount += 1
        if enrichmentCount % pruneInterval == 0 {
            await lineage.prune()
        }

        return enrichedEvent
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
                startTime: proc.startTime
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
                    startTime: proc.startTime
                )
            }
        }
    }

    // MARK: Diagnostics

    /// Number of processes currently tracked in the lineage graph.
    public func lineageNodeCount() async -> Int {
        await lineage.nodeCount
    }
}
