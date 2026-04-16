// OutputAdapters.swift
// MacCrabCore
//
// Protocol conformance for the existing alert sinks (WebhookOutput,
// SyslogOutput, NotificationOutput) so the daemon event loop can hold
// them behind the shared `any Output` existential.
//
// Each adapter bridges the sink's native API into the uniform
// `send(alert:event:) / outputStats()` surface defined by Output.
// Existing call sites that invoke sink-specific methods continue to work.

import Foundation

// MARK: - WebhookOutput

extension WebhookOutput: Output {
    public nonisolated var name: String { "webhook" }

    public func send(alert: Alert, event: Event?) async {
        guard let event else {
            // Webhook payloads require the originating event for context;
            // there's nothing meaningful to ship without it.
            return
        }
        await self.send(alert: alert, event: event)
    }

    public func outputStats() async -> OutputStats {
        let raw: (sent: Int, failed: Int) = self.stats()
        return OutputStats(sent: raw.sent, failed: raw.failed)
    }
}

// MARK: - SyslogOutput

extension SyslogOutput: Output {
    public nonisolated var name: String { "syslog" }

    public func send(alert: Alert, event: Event?) async {
        // Syslog formats alerts without the Event block — just the
        // RFC 5424 CEF line, so the event param is intentionally unused.
        _ = event
        await self.send(alert: alert)
    }

    public func outputStats() async -> OutputStats {
        // Syslog's native counter is a single "sent" integer (UDP fire-
        // and-forget has no failure signal). Represent it as sent only.
        OutputStats(sent: self.stats())
    }
}
