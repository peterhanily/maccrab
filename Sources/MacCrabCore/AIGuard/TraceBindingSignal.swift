// TraceBindingSignal.swift
// MacCrabCore
//
// v1.9 Agent Traces (PR-2) — side-channel signal emitted by ESCollector
// alongside the normal event stream when a process's exec env contained a
// valid TRACEPARENT (or when the process exits and any binding should be
// reaped).
//
// Why a side channel instead of stuffing the binding into Event.enrichments:
//   * Bindings are about ProcessIdentity, which is richer than what
//     fits cleanly in a flat string→string dict.
//   * Lookups happen at every later event, not just exec. Putting the
//     binding into the exec event would require every consumer to
//     remember it; an explicit signal makes EventLoop's responsibility
//     unambiguous (it owns the TraceRegistry).
//   * Keeps ESCollector free of any TraceRegistry actor reference —
//     ESCollector emits, EventLoop consumes.

import Foundation

public struct TraceBindingSignal: Sendable {
    public enum Kind: Sendable {
        /// A NOTIFY_EXEC produced a valid TRACEPARENT in env. The
        /// `agentTool` is best-effort from path matching; nil is fine —
        /// EventLoop's correlator can re-derive at lookup time.
        case bind(identity: ProcessIdentity, context: TraceContext, agentTool: AIToolType?)
        /// A NOTIFY_EXIT for a pid that may have a binding.
        /// The consumer no-ops if no entry exists for the pid.
        case evict(pid: pid_t)
    }
    public let kind: Kind
    public let timestamp: Date

    public init(kind: Kind, timestamp: Date = Date()) {
        self.kind = kind
        self.timestamp = timestamp
    }
}
