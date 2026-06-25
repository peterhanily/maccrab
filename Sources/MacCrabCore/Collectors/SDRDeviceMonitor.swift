// SDRDeviceMonitor.swift
// MacCrabCore
//
// Detects two physical-access precursors, by enumeration only:
//
// 1. Known software-defined-radio (SDR) hardware (RTL-SDR, HackRF, USRP,
//    BladeRF, etc.) connected via USB — matched against a fixed VID/PID list.
// 2. Suspicious display hotplug patterns (rapid connect/disconnect cycling)
//    that *could* accompany an inline HDMI/DisplayPort tap.
//
// IMPORTANT — what this is NOT: there is NO electromagnetic / RF signal
// analysis here. No spectrum capture, no EDID/timing reconstruction, no Van Eck
// phreaking detection. This monitor flags *equipment that could be misused* and
// *anomalous display behavior* — both of which are precursors that warrant a
// look, not confirmation of an active eavesdropping attack. An SDR is a
// general-purpose radio with many legitimate uses; a display hotplug can be a
// faulty cable, dock, or driver. Treat every alert here as "verify this," not
// "you are being eavesdropped on."
//
// Background reading on the broader threat class (NOT implemented here):
// Deep-TEMPEST (arXiv:2407.09717); NATO SDIP-27 TEMPEST zones.

import Foundation
import os.log
import CoreGraphics

/// Enumerates known SDR USB devices and watches for suspicious display hotplug
/// patterns. Equipment + behavior detection only — performs no electromagnetic
/// signal analysis (see file header).
public actor SDRDeviceMonitor {

    private let logger = Logger(subsystem: "com.maccrab", category: "sdr-device-monitor")

    /// How often to scan for USB SDR devices (default: 60 seconds).
    private let pollInterval: TimeInterval

    /// AsyncStream continuation for emitting discoveries.
    private var continuation: AsyncStream<SDRDeviceEvent>.Continuation?
    private let _events: AsyncStream<SDRDeviceEvent>

    /// Known SDR devices already reported (avoid re-alerting).
    private var reportedDevices: Set<String> = []

    /// Display state tracking for anomaly detection.
    private var knownDisplays: Set<UInt32> = []
    private var displayEventCount: Int = 0
    private var lastDisplayChange: Date = .distantPast

    /// Active task.
    private var scanTask: Task<Void, Never>?

    // MARK: - Types

    public struct SDRDeviceEvent: Sendable {
        public let type: EventType
        public let severity: Severity
        public let title: String
        public let description: String
        public let detail: String
        public let timestamp: Date

        public init(type: EventType, severity: Severity, title: String, description: String, detail: String = "") {
            self.type = type
            self.severity = severity
            self.title = title
            self.description = description
            self.detail = detail
            self.timestamp = Date()
        }
    }

    public enum EventType: String, Sendable {
        case sdrDeviceDetected = "sdr_device"
        case displayAnomaly = "display_anomaly"
        case thunderboltAnomaly = "thunderbolt_anomaly"
        case sdrRisk = "sdr_risk"
    }

    // MARK: - SDR Device Database

    /// Known SDR devices, by USB VID/PID. The `coverage` note describes the
    /// radio's tuning range as a fact about the hardware — NOT a claim that an
    /// attack is occurring. Detection here means "this equipment is present."
    private static let knownSDRDevices: [(vid: Int, pid: Int, name: String, vendor: String, freqRange: String, risk: String)] = [
        // RTL-SDR family (most common, ~$25)
        (0x0bda, 0x2832, "RTL-SDR (RTL2832U)", "Realtek", "24 MHz - 1.766 GHz", "Low-cost wideband receiver; legitimate uses are common."),
        (0x0bda, 0x2838, "RTL-SDR (RTL2838)", "Realtek", "24 MHz - 1.766 GHz", "Low-cost wideband receiver; legitimate uses are common."),
        // HackRF One (~$350)
        (0x1d50, 0x6089, "HackRF One", "Great Scott Gadgets", "1 MHz - 6 GHz", "Wide-range transceiver popular with researchers and hobbyists."),
        // Ettus USRP family (~$1,500+) — the hardware class used in the Deep-TEMPEST paper
        (0x2500, 0x0020, "USRP B210", "Ettus/NI", "70 MHz - 6 GHz", "Research-grade SDR."),
        (0x2500, 0x0021, "USRP B200-mini", "Ettus/NI", "70 MHz - 6 GHz", "Research-grade SDR."),
        (0x2500, 0x0022, "USRP B205-mini", "Ettus/NI", "70 MHz - 6 GHz", "Research-grade SDR."),
        (0x2500, 0x0200, "USRP B200", "Ettus/NI", "70 MHz - 6 GHz", "Research-grade SDR."),
        // Nuand BladeRF (~$480)
        (0x2cf0, 0x5246, "BladeRF", "Nuand", "47 MHz - 6 GHz", "Full-spectrum SDR transceiver."),
        (0x2cf0, 0x5250, "BladeRF 2.0 Micro", "Nuand", "47 MHz - 6 GHz", "Full-spectrum SDR transceiver."),
        // Airspy (~$200)
        (0x1d50, 0x60a1, "Airspy R2/Mini", "Airspy", "24 MHz - 1.8 GHz", "Wideband receiver."),
        // LimeSDR (~$300)
        (0x1d50, 0x6108, "LimeSDR", "Lime Microsystems", "100 kHz - 3.8 GHz", "Full-range SDR transceiver."),
        (0x0403, 0x601f, "LimeSDR Mini", "Lime Microsystems", "10 MHz - 3.5 GHz", "SDR transceiver."),
        // SDRplay (~$120-$260)
        (0x1df7, 0x2500, "SDRplay RSP1", "SDRplay", "1 kHz - 2 GHz", "Wideband receiver."),
        (0x1df7, 0x3000, "SDRplay RSP1A", "SDRplay", "1 kHz - 2 GHz", "Wideband receiver."),
        (0x1df7, 0x3010, "SDRplay RSPduo", "SDRplay", "1 kHz - 2 GHz", "Dual-tuner receiver."),
        // FunCube Dongle
        (0x04d8, 0xfb56, "FunCube Dongle Pro", "FunCube", "64 MHz - 1.7 GHz", "Receiver dongle."),
        (0x04d8, 0xfb31, "FunCube Dongle Pro+", "FunCube", "150 kHz - 1.9 GHz", "Receiver dongle."),
    ]

    // MARK: - Init

    public init(pollInterval: TimeInterval = 60) {
        self.pollInterval = pollInterval
        var capturedContinuation: AsyncStream<SDRDeviceEvent>.Continuation!
        self._events = AsyncStream { c in
            capturedContinuation = c
        }
        self.continuation = capturedContinuation
    }

    // MARK: - Public API

    /// AsyncStream of SDR-device + display-hotplug events.
    public nonisolated var events: AsyncStream<SDRDeviceEvent> {
        _events
    }

    /// Start monitoring.
    public func start() {
        guard scanTask == nil else { return }
        logger.info("SDR device monitor starting (USB SDR scan every \(self.pollInterval)s)")

        // Record initial display state
        knownDisplays = Set(currentDisplayIDs())

        scanTask = Task { [weak self] in
            // Initial scan
            await self?.scanSDRDevices()
            await self?.checkDisplayState()

            while !Task.isCancelled {
                let interval = PowerGate.adjustedInterval(base: self?.pollInterval ?? 60)
                try? await Task.sleep(nanoseconds: UInt64(interval * 1_000_000_000))
                guard !Task.isCancelled else { break }
                await self?.scanSDRDevices()
                await self?.checkDisplayState()
            }
        }
    }

    /// Stop monitoring.
    public func stop() {
        scanTask?.cancel()
        scanTask = nil
        continuation?.finish()
    }

    // MARK: - USB SDR Device Scanning

    private func scanSDRDevices() {
        let devices = getUSBDevices()

        for device in devices {
            for sdr in Self.knownSDRDevices {
                if device.vendorID == sdr.vid && device.productID == sdr.pid {
                    let key = "\(sdr.name):\(device.locationID)"
                    if !reportedDevices.contains(key) {
                        reportedDevices.insert(key)

                        let event = SDRDeviceEvent(
                            type: .sdrDeviceDetected,
                            severity: .high,
                            title: "SDR Device Connected: \(sdr.name)",
                            description: """
                                A software-defined radio (\(sdr.name) by \(sdr.vendor)) has been \
                                connected to this machine (tuning range \(sdr.freqRange)). This is \
                                equipment detection, not confirmation of an attack — SDRs have many \
                                legitimate uses. If you didn't connect it, investigate who has had \
                                physical access. MacCrab does NOT perform any RF/emissions analysis.
                                """,
                            detail: "\(sdr.risk) Location: \(device.locationID)"
                        )
                        continuation?.yield(event)
                        logger.notice("SDR: device connected — \(sdr.name) (\(sdr.vendor))")
                    }
                }
            }
        }
    }

    // MARK: - Display Anomaly Detection

    private func checkDisplayState() {
        let currentIDs = Set(currentDisplayIDs())
        let now = Date()

        // Detect new displays
        let newDisplays = currentIDs.subtracting(knownDisplays)
        let removedDisplays = knownDisplays.subtracting(currentIDs)

        if !newDisplays.isEmpty || !removedDisplays.isEmpty {
            displayEventCount += 1

            // Rapid hotplug cycling is anomalous (could be an inline tap being
            // connected — but also a flaky cable, dock, or driver).
            let timeSinceLastChange = now.timeIntervalSince(lastDisplayChange)
            if timeSinceLastChange < 5.0 && displayEventCount > 2 {
                let event = SDRDeviceEvent(
                    type: .displayAnomaly,
                    severity: .medium,
                    title: "Rapid Display Hotplug Activity",
                    description: """
                        Multiple display connect/disconnect events occurred within \
                        \(String(format: "%.1f", timeSinceLastChange)) seconds. This pattern *can* \
                        accompany an inline HDMI/DisplayPort signal-splitting device, but it is far \
                        more often a faulty cable, a dock waking, or a display driver glitch. Verify \
                        your cabling/dock before treating this as a security event.
                        """,
                    detail: "Events in window: \(displayEventCount). New: \(newDisplays). Removed: \(removedDisplays)"
                )
                continuation?.yield(event)
                logger.notice("SDR: rapid display hotplug detected (\(self.displayEventCount) events)")
            }

            // Unknown display connected
            for displayID in newDisplays {
                let name = displayName(for: displayID)
                logger.info("SDR: display connected — ID \(displayID), name: \(name)")
            }

            lastDisplayChange = now
            knownDisplays = currentIDs
        }

        // Reset event counter after quiet period
        if now.timeIntervalSince(lastDisplayChange) > 30 {
            displayEventCount = 0
        }
    }

    // MARK: - Display Helpers

    private nonisolated func currentDisplayIDs() -> [UInt32] {
        var displayCount: UInt32 = 0
        CGGetActiveDisplayList(0, nil, &displayCount)
        guard displayCount > 0 else { return [] }
        var displays = [CGDirectDisplayID](repeating: 0, count: Int(displayCount))
        CGGetActiveDisplayList(displayCount, &displays, &displayCount)
        return displays.prefix(Int(displayCount)).map { $0 }
    }

    private nonisolated func displayName(for displayID: CGDirectDisplayID) -> String {
        guard let mode = CGDisplayCopyDisplayMode(displayID) else { return "Unknown" }
        return "\(mode.width)x\(mode.height)@\(Int(mode.refreshRate))Hz"
    }

    // MARK: - USB Device Discovery

    private struct USBDevice {
        let vendorID: Int
        let productID: Int
        let name: String
        let locationID: String
    }

    private nonisolated func getUSBDevices() -> [USBDevice] {
        // Use system_profiler for reliable USB enumeration
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/sbin/system_profiler")
        proc.arguments = ["SPUSBDataType", "-json"]
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = FileHandle.nullDevice

        do {
            try proc.run()
            // Drain the pipe BEFORE waiting: SPUSBDataType output can exceed the
            // OS pipe buffer, so waiting first would deadlock (child blocks on
            // write, parent blocks in waitUntilExit, neither drains).
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            proc.waitUntilExit()
            guard proc.terminationStatus == 0 else { return [] }

            guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let usbData = json["SPUSBDataType"] as? [[String: Any]] else {
                return []
            }

            return extractUSBDevices(from: usbData)
        } catch {
            return []
        }
    }

    private nonisolated func extractUSBDevices(from items: [[String: Any]]) -> [USBDevice] {
        var devices: [USBDevice] = []

        for item in items {
            if let vid = item["vendor_id"] as? String,
               let pid = item["product_id"] as? String {
                let vidInt = Int(vid.replacingOccurrences(of: "0x", with: ""), radix: 16) ?? 0
                let pidInt = Int(pid.replacingOccurrences(of: "0x", with: ""), radix: 16) ?? 0
                let name = item["_name"] as? String ?? "Unknown"
                let location = item["location_id"] as? String ?? ""
                devices.append(USBDevice(vendorID: vidInt, productID: pidInt, name: name, locationID: location))
            }

            // Recurse into child items (USB hubs contain nested devices)
            if let children = item["_items"] as? [[String: Any]] {
                devices.append(contentsOf: extractUSBDevices(from: children))
            }
        }

        return devices
    }
}
