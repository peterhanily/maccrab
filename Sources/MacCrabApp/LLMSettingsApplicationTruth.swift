// LLMSettingsApplicationTruth.swift
// MacCrabApp
//
// A request-file write is only transport admission. The root engine is the
// authority for whether a configuration was actually applied, and it reports
// that state in a later heartbeat.

import Foundation

struct LLMEngineConfiguration: Equatable, Sendable {
    let enabled: Bool
    let provider: String
    let model: String
}

enum LLMSettingsApplicationTruth {
    /// Returns true only when a fresh engine heartbeat reports the requested
    /// state. When `queuedAt` is non-nil, a heartbeat that predates the request
    /// cannot confirm it even if its values happen to be identical.
    static func heartbeatConfirms(
        requested: LLMEngineConfiguration,
        queuedAt: Date?,
        reported: LLMEngineConfiguration?,
        heartbeatWrittenAt: Date?,
        heartbeatIsStale: Bool
    ) -> Bool {
        guard !heartbeatIsStale,
              let reported,
              let heartbeatWrittenAt else { return false }
        if let queuedAt, heartbeatWrittenAt < queuedAt { return false }
        guard requested.enabled == reported.enabled else { return false }
        // A disabled engine has no active provider/model. Those fields may be
        // omitted by the daemon and are therefore irrelevant to confirmation.
        guard requested.enabled else { return true }
        return requested.provider == reported.provider
            && requested.model == reported.model
    }
}
