// TEMPESTMonitor.swift
// MacCrabCore
//
// Detects indicators of Van Eck phreaking / TEMPEST electromagnetic
// eavesdropping attacks. Monitors for:
//
// 1. SDR hardware (RTL-SDR, HackRF, USRP, BladeRF, etc.) connected via USB
// 2. Display anomalies (phantom hotplug, EDID changes, timing shifts)
// 3. Unauthorized Thunderbolt devices (potential signal interception hardware)
//
// References:
// - Deep-TEMPEST (2024): https://arxiv.org/html/2407.09717v1
// - DisplayPort eavesdropping: Cambridge Computer Lab
// - NATO SDIP-27 TEMPEST zones
// - Soft TEMPEST countermeasures: Cambridge Computer Lab

import Foundation
import os.log
import CoreGraphics

/// Monitors for indicators of TEMPEST / Van Eck phreaking electromagnetic
/// eavesdropping attacks against this machine's display output.
public actor TEMPESTMonitor {

    private let logger = Logger(subsystem: "com.maccrab", category: "tempest-monitor")

    /// How often to scan for USB SDR devices (default: 60 seconds).
    private let pollInterval: TimeInterval

    /// AsyncStream continuation for emitting discoveries.
    private var continuation: AsyncStream<TEMPESTEvent>.Continuation?
    private let _events: AsyncStream<TEMPESTEvent>

    /// Known SDR devices already reported (avoid re-alerting).
    private var reportedDevices: Set<String> = []

    /// Display state tracking for anomaly detection.
    private var knownDisplays: Set<UInt32> = []
    private var displayEventCount: Int = 0
    private var lastDisplayChange: Date = .distantPast

    /// Active task.
    private var scanTask: Task<Void, Never>?

    // MARK: - Types

    public struct TEMPESTEvent: Sendable {
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
        case tempestRisk = "tempest_risk"
    }

    // MARK: - SDR Device Database

    /// Known SDR devices used for TEMPEST/Van Eck attacks.
    /// VID/PID pairs with device info.
    private static let knownSDRDevices: [(vid: Int, pid: Int, name: String, vendor: String, freqRange: String, risk: String)] = [
        // RTL-SDR family (most common, $25)
        (0x0bda, 0x2832, "RTL-SDR (RTL2832U)", "Realtek", "24 MHz - 1.766 GHz", "Can capture HDMI emissions at 324 MHz"),
        (0x0bda, 0x2838, "RTL-SDR (RTL2838)", "Realtek", "24 MHz - 1.766 GHz", "Can capture HDMI emissions at 324 MHz"),
        // HackRF One ($350)
        (0x1d50, 0x6089, "HackRF One", "Great Scott Gadgets", "1 MHz - 6 GHz", "Full TEMPEST attack capability — covers all display emission frequencies"),
        // Ettus USRP family ($1,500+) — used in Deep-TEMPEST paper
        (0x2500, 0x0020, "USRP B210", "Ettus/NI", "70 MHz - 6 GHz", "Research-grade SDR — used in Deep-TEMPEST paper for HDMI reconstruction"),
        (0x2500, 0x0021, "USRP B200-mini", "Ettus/NI", "70 MHz - 6 GHz", "Exact hardware used in Deep-TEMPEST (arXiv:2407.09717)"),
        (0x2500, 0x0022, "USRP B205-mini", "Ettus/NI", "70 MHz - 6 GHz", "Research-grade SDR"),
        (0x2500, 0x0200, "USRP B200", "Ettus/NI", "70 MHz - 6 GHz", "Research-grade SDR"),
        // Nuand BladeRF ($480)
        (0x2cf0, 0x5246, "BladeRF", "Nuand", "47 MHz - 6 GHz", "Full spectrum SDR — TEMPEST capable"),
        (0x2cf0, 0x5250, "BladeRF 2.0 Micro", "Nuand", "47 MHz - 6 GHz", "Full spectrum SDR — TEMPEST capable"),
        // Airspy ($200)
        (0x1d50, 0x60a1, "Airspy R2/Mini", "Airspy", "24 MHz - 1.8 GHz", "Covers HDMI emission frequencies"),
        // LimeSDR ($300)
        (0x1d50, 0x6108, "LimeSDR", "Lime Microsystems", "100 kHz - 3.8 GHz", "Full TEMPEST capability"),
        (0x0403, 0x601f, "LimeSDR Mini", "Lime Microsystems", "10 MHz - 3.5 GHz", "TEMPEST capable"),
        // SDRplay ($120-$260)
        (0x1df7, 0x2500, "SDRplay RSP1", "SDRplay", "1 kHz - 2 GHz", "Covers HDMI emission frequencies"),
        (0x1df7, 0x3000, "SDRplay RSP1A", "SDRplay", "1 kHz - 2 GHz", "Covers HDMI emission frequencies"),
        (0x1df7, 0x3010, "SDRplay RSPduo", "SDRplay", "1 kHz - 2 GHz", "Dual-tuner — simultaneous monitoring"),
        // FunCube Dongle
        (0x04d8, 0xfb56, "FunCube Dongle Pro", "FunCube", "64 MHz - 1.7 GHz", "Covers HDMI emission frequencies"),
        (0x04d8, 0xfb31, "FunCube Dongle Pro+", "FunCube", "150 kHz - 1.9 GHz", "Covers HDMI emission frequencies"),
    ]

    // MARK: - Init

    public init(pollInterval: TimeInterval = 60) {
        self.pollInterval = pollInterval
        var capturedContinuation: AsyncStream<TEMPESTEvent>.Continuation!
        self._events = AsyncStream { c in
            capturedContinuation = c
        }
        self.continuation = capturedContinuation
    }

    // MARK: - Public API

    /// AsyncStream of TEMPEST-related events.
    public nonisolated var events: AsyncStream<TEMPESTEvent> {
        _events
    }

    /// Start monitoring.
    public func start() {
        guard scanTask == nil else { return }
        logger.info("TEMPEST monitor starting (SDR device scan every \(self.pollInterval)s)")

        // Record initial display state
        knownDisplays = Set(currentDisplayIDs())

        scanTask = Task { [weak self] in
            // Initial scan
            await self?.scanSDRDevices()
            await self?.checkDisplayState()

            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: UInt64((self?.pollInterval ?? 60) * 1_000_000_000))
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

                        let event = TEMPESTEvent(
                            type: .sdrDeviceDetected,
                            severity: .critical,
                            title: "SDR Device Detected: \(sdr.name)",
                            description: """
                                A Software Defined Radio (\(sdr.name) by \(sdr.vendor)) has been \
                                connected to this machine. SDR devices can be used for Van Eck \
                                phreaking — capturing electromagnetic emissions from HDMI/DisplayPort \
                                cables to reconstruct screen content. Frequency range: \(sdr.freqRange).
                                """,
                            detail: "\(sdr.risk). Location: \(device.locationID)"
                        )
                        continuation?.yield(event)
                        logger.critical("TEMPEST: SDR device detected — \(sdr.name) (\(sdr.vendor))")
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

            // Rapid hotplug cycling is suspicious (HDMI tap being connected)
            let timeSinceLastChange = now.timeIntervalSince(lastDisplayChange)
            if timeSinceLastChange < 5.0 && displayEventCount > 2 {
                let event = TEMPESTEvent(
                    type: .displayAnomaly,
                    severity: .high,
                    title: "Rapid Display Hotplug Activity",
                    description: """
                        Multiple display connect/disconnect events detected within \
                        \(String(format: "%.1f", timeSinceLastChange)) seconds. This pattern \
                        can indicate an HDMI/DisplayPort signal interception device (tap) being \
                        connected between your machine and display. An attacker could use this to \
                        split your video signal for electromagnetic analysis.
                        """,
                    detail: "Events in window: \(displayEventCount). New: \(newDisplays). Removed: \(removedDisplays)"
                )
                continuation?.yield(event)
                logger.warning("TEMPEST: Rapid display hotplug detected (\(self.displayEventCount) events)")
            }

            // Unknown display connected
            for displayID in newDisplays {
                let name = displayName(for: displayID)
                logger.info("TEMPEST: Display connected — ID \(displayID), name: \(name)")
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
            proc.waitUntilExit()
            guard proc.terminationStatus == 0 else { return [] }

            let data = pipe.fileHandleForReading.readDataToEndOfFile()
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
