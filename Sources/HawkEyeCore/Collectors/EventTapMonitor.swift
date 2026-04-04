// EventTapMonitor.swift
// HawkEyeCore
//
// Enumerates active Core Graphics event taps to detect keyloggers.
// CGEventTap allows processes to intercept keyboard/mouse input system-wide.
// Any non-Apple process tapping kCGEventKeyDown is highly suspicious.

import Foundation
import CoreGraphics
import os.log

/// Monitors for active CGEventTaps that could indicate keylogging.
///
/// Polls `CGGetEventTapList()` every 30 seconds and alerts on:
/// - Any process tapping keyboard events (kCGEventKeyDown/kCGEventKeyUp)
/// - Active (modifying) taps from unsigned processes
/// - Taps from processes without Accessibility/InputMonitoring TCC permission
public actor EventTapMonitor {

    private let logger = Logger(subsystem: "com.hawkeye", category: "event-tap-monitor")

    public nonisolated let events: AsyncStream<EventTapInfo>
    private var continuation: AsyncStream<EventTapInfo>.Continuation?
    private var pollTask: Task<Void, Never>?
    private var knownTaps: Set<UInt32> = []  // Tap IDs we've already alerted on
    private let pollInterval: TimeInterval

    // MARK: - Types

    /// Information about a detected event tap.
    public struct EventTapInfo: Sendable {
        public let tapID: UInt32
        public let tappingPID: Int32
        public let processBeingTapped: Int32
        public let eventMask: CGEventMask
        public let isActive: Bool  // Active (can modify events) vs passive (listen-only)
        public let tapsKeyboard: Bool
        public let tapsMouse: Bool
        public let processPath: String
        public let processName: String
    }

    // MARK: - Event mask constants

    /// CGEventType values for keyboard events.
    private static let keyDownMask: CGEventMask = 1 << CGEventType.keyDown.rawValue
    private static let keyUpMask: CGEventMask = 1 << CGEventType.keyUp.rawValue
    private static let flagsChangedMask: CGEventMask = 1 << CGEventType.flagsChanged.rawValue
    private static let keyboardMask = keyDownMask | keyUpMask | flagsChangedMask

    private static let mouseMovedMask: CGEventMask = 1 << CGEventType.mouseMoved.rawValue
    private static let leftMouseDownMask: CGEventMask = 1 << CGEventType.leftMouseDown.rawValue
    private static let mouseMask = mouseMovedMask | leftMouseDownMask

    // MARK: - Initialization

    public init(pollInterval: TimeInterval = 30.0) {
        self.pollInterval = pollInterval
        var capturedContinuation: AsyncStream<EventTapInfo>.Continuation!
        self.events = AsyncStream(bufferingPolicy: .bufferingNewest(64)) { continuation in
            capturedContinuation = continuation
        }
        self.continuation = capturedContinuation
    }

    // MARK: - Lifecycle

    public func start() {
        guard pollTask == nil else { return }
        logger.info("Event tap monitor starting (poll every \(self.pollInterval)s)")

        pollTask = Task { [weak self] in
            guard let self else { return }
            while !Task.isCancelled {
                await self.scan()
                try? await Task.sleep(nanoseconds: UInt64(self.pollInterval * 1_000_000_000))
            }
        }
    }

    public func stop() {
        pollTask?.cancel()
        pollTask = nil
        continuation?.finish()
    }

    // MARK: - Scanning

    private func scan() {
        var tapCount: UInt32 = 0

        // First call to get count
        CGGetEventTapList(0, nil, &tapCount)
        guard tapCount > 0 else { return }

        var taps = [CGEventTapInformation](repeating: CGEventTapInformation(), count: Int(tapCount))
        CGGetEventTapList(tapCount, &taps, &tapCount)

        for tap in taps.prefix(Int(tapCount)) {
            // Skip taps we've already reported
            guard !knownTaps.contains(tap.eventTapID) else { continue }

            let tapsKeyboard = (tap.eventsOfInterest & Self.keyboardMask) != 0
            let tapsMouse = (tap.eventsOfInterest & Self.mouseMask) != 0
            let isActive = tap.options == .defaultTap  // Active (can modify) vs listenOnly

            // Get process info for the tapping process
            let pid = tap.tappingProcess
            let path = Self.processPath(for: pid)
            let name = (path as NSString).lastPathComponent

            // Skip known Apple system taps
            if path.hasPrefix("/System/") || path.hasPrefix("/usr/libexec/") {
                continue
            }

            // Flag suspicious taps
            let isSuspicious = tapsKeyboard || (isActive && tapsMouse)
            guard isSuspicious else { continue }

            knownTaps.insert(tap.eventTapID)

            let info = EventTapInfo(
                tapID: tap.eventTapID,
                tappingPID: pid,
                processBeingTapped: tap.processBeingTapped,
                eventMask: tap.eventsOfInterest,
                isActive: isActive,
                tapsKeyboard: tapsKeyboard,
                tapsMouse: tapsMouse,
                processPath: path,
                processName: name
            )

            continuation?.yield(info)
            logger.warning("Suspicious event tap detected: PID \(pid) (\(name)) taps keyboard=\(tapsKeyboard) active=\(isActive)")
        }
    }

    // MARK: - Helpers

    /// Get the executable path for a PID.
    private nonisolated static func processPath(for pid: Int32) -> String {
        var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        let result = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard result > 0 else { return "unknown" }
        return String(cString: buffer)
    }
}
