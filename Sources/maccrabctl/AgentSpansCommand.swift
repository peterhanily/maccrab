// AgentSpansCommand.swift
// maccrabctl
//
// Reader surface for AGENT TRACES (traces.db — OTLP spans exported by Claude
// Code). Deliberately NOT part of the `trace` command family: that one operates
// on TraceGraph (tracegraph.db — causal provenance materialised from kernel
// events). The two systems share the word "trace" and nothing else, and the
// conflation is why `hunt_trace`'s description advertised path search it could
// never perform.
//
// Before this existed, traces.db had NO reader outside the dashboard: no CLI
// subcommand and no MCP tool could see a single span.

import Foundation
import MacCrabCore

extension MacCrabCtl {

    static func agentSpans(search: String?, limit: Int, traceId: String?) async {
        let dir = maccrabDataDir()
        let path = dir + "/traces.db"
        guard FileManager.default.fileExists(atPath: path) else {
            print("No agent-trace store at \(path).")
            print("Agent Traces is opt-in — see docs/AGENT_TRACES.md to enable it.")
            return
        }

        // encryption: nil deliberately — this command renders only structural
        // columns, never `attributes_json`, so it needs no decryption key.
        // Constructing DatabaseEncryption would reach for the Keychain, which can
        // block a non-interactive invocation (it hung the MCP stdio server).
        let store: TraceStore
        do { store = try TraceStore(path: path, encryption: nil) }
        catch {
            FileHandle.standardError.write(Data("Cannot open \(path): \(error)\n".utf8))
            exit(1)
        }

        do {
            let spans: [SpanRecord]
            if let traceId {
                spans = try await store.spansForTrace(traceId)
            } else if let search, !search.isEmpty {
                spans = try await store.searchSpans(matching: search, limit: limit)
            } else {
                // No filter: newest traces, expanded.
                let ids = try await store.recentTraceIds(limit: max(1, limit / 4))
                var acc: [SpanRecord] = []
                for id in ids { acc.append(contentsOf: try await store.spansForTrace(id)) }
                spans = acc
            }

            let total = try await store.count()
            guard !spans.isEmpty else {
                if total == 0 {
                    // The store being empty almost always means the agent side was
                    // never configured — for months the documented recipe omitted
                    // the beta flag, so the receiver bound and ingested nothing.
                    print("No spans ingested yet.")
                    print("")
                    print("Claude Code ships tracing OFF. In the shell you launch it from:")
                    print("  export CLAUDE_CODE_ENABLE_TELEMETRY=1")
                    print("  export CLAUDE_CODE_ENHANCED_TELEMETRY_BETA=1   # required — spans need this")
                    print("  export OTEL_TRACES_EXPORTER=otlp")
                    print("  export OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf")
                    print("  export OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318")
                } else {
                    print("No matching spans. (\(total) span(s) in the store.)")
                }
                return
            }

            print("Agent Traces — \(spans.count) span(s) of \(total) in store")
            print(String(repeating: "═", count: 62))
            var lastTrace = ""
            for s in spans.sorted(by: { $0.startNs < $1.startNs }) {
                if s.traceId != lastTrace {
                    lastTrace = s.traceId
                    print("\ntrace \(String(s.traceId.prefix(16)))…  tool=\(s.agentTool?.rawValue ?? "-")")
                }
                let started = Date(timeIntervalSince1970: Double(s.startNs) / 1_000_000_000)
                let ms = max(0, Int((s.endNs &- s.startNs) / 1_000_000))
                let depth = s.parentSpanId == nil ? "" : "  ↳ "
                print("  \(started.formatted(date: .omitted, time: .standard))  \(depth)\(s.spanName)  (\(ms)ms)")
            }
        } catch {
            FileHandle.standardError.write(Data("Query failed: \(error)\n".utf8))
            exit(1)
        }
    }
}
