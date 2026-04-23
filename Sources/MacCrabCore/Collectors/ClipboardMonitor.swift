// ClipboardMonitor.swift
// MacCrabCore
//
// Monitors the system clipboard for exfiltration patterns.
// Detects clipboard content changes followed by sensitive data placement
// (API keys, tokens, private keys, passwords). Polls NSPasteboard change
// count and flags when credential-like content appears.

import Foundation
import AppKit
import os.log

/// Monitors the system clipboard for exfiltration patterns.
/// Detects: clipboard content changes followed by network activity from the same process.
public actor ClipboardMonitor {
    private let logger = Logger(subsystem: "com.maccrab", category: "clipboard-monitor")

    public struct ClipboardEvent: Sendable {
        public let changeCount: Int
        public let contentTypes: [String]  // UTI types on the pasteboard
        public let timestamp: Date
        public let containsSensitiveData: Bool  // passwords, keys, tokens detected
    }

    public nonisolated let events: AsyncStream<ClipboardEvent>
    private var continuation: AsyncStream<ClipboardEvent>.Continuation?
    private var pollTask: Task<Void, Never>?
    private var lastChangeCount: Int = 0
    private let pollInterval: TimeInterval

    // Patterns that indicate sensitive clipboard content
    private static let sensitivePatterns: [String] = [
        "-----BEGIN", "PRIVATE KEY", "ssh-rsa", "ssh-ed25519",
        "ghp_", "gho_", "github_pat_",  // GitHub tokens
        "sk-", "sk_live_", "pk_live_",  // Stripe/OpenAI keys
        "AKIA",  // AWS access key
        "Bearer ", "token=", "password=",
        "eyJ",  // JWT prefix (base64 of {"...)
    ]

    public init(pollInterval: TimeInterval = 2.0) {
        self.pollInterval = pollInterval
        var capturedContinuation: AsyncStream<ClipboardEvent>.Continuation!
        self.events = AsyncStream(bufferingPolicy: .bufferingNewest(64)) { c in
            capturedContinuation = c
        }
        self.continuation = capturedContinuation
    }

    public func start() {
        guard pollTask == nil else { return }
        // Capture initial state
        lastChangeCount = NSPasteboard.general.changeCount

        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.check()
                // Clipboard polling is aggressive (2s baseline) and purely
                // optional — scale hard on battery/thermal pressure to avoid
                // draining battery for a small detection uplift. Effective
                // interval in low-power mode ≈ 10s.
                let base = self?.pollInterval ?? 2
                let adjusted = PowerGate.adjustedInterval(base: base, aggressiveness: 2.0)
                try? await Task.sleep(nanoseconds: UInt64(adjusted * 1_000_000_000))
            }
        }
    }

    public func stop() {
        pollTask?.cancel()
        pollTask = nil
        continuation?.finish()
    }

    private func check() {
        let currentCount = NSPasteboard.general.changeCount
        guard currentCount != lastChangeCount else { return }
        lastChangeCount = currentCount

        // Get content types
        let types = NSPasteboard.general.types?.map(\.rawValue) ?? []

        // Check for sensitive content (only if string type)
        var isSensitive = false
        if let content = NSPasteboard.general.string(forType: .string) {
            isSensitive = Self.sensitivePatterns.contains { content.contains($0) }
        }

        let event = ClipboardEvent(
            changeCount: currentCount,
            contentTypes: types,
            timestamp: Date(),
            containsSensitiveData: isSensitive
        )
        continuation?.yield(event)

        if isSensitive {
            logger.warning("Sensitive data detected on clipboard (change #\(currentCount))")
        }
    }
}
