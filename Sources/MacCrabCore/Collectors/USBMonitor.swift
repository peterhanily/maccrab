// USBMonitor.swift
// MacCrabCore
//
// Monitors USB device connections and removable media insertions.
// Polls IOKit's USB device registry to detect new USB devices and
// flags suspicious ones (mass storage from unknown vendors, HID devices).

import Foundation
import IOKit
import IOKit.usb
import os.log

/// Monitors USB device connections and removable media insertions.
///
/// Polls `IOServiceGetMatchingServices` to enumerate USB devices and detects:
/// - New USB device connections (non-Apple)
/// - USB mass storage devices (device class 8)
/// - Device disconnections
public actor USBMonitor {

    private let logger = Logger(subsystem: "com.maccrab", category: "usb-monitor")

    // MARK: - Types

    /// Represents a USB device connection or disconnection event.
    public struct USBDeviceEvent: Sendable {
        public let vendorId: Int
        public let productId: Int
        public let vendorName: String
        public let productName: String
        public let serialNumber: String
        public let deviceClass: Int
        public let isConnected: Bool  // true=connected, false=disconnected
        public let isMassStorage: Bool
        public let timestamp: Date
    }

    // MARK: - Properties

    public nonisolated let events: AsyncStream<USBDeviceEvent>
    private var continuation: AsyncStream<USBDeviceEvent>.Continuation?
    private var pollTask: Task<Void, Never>?
    private var knownDevices: Set<String> = []  // "vendorId:productId:serialNumber"
    private let pollInterval: TimeInterval

    /// USB Mass Storage device class code.
    private static let massStorageClass = 8

    /// Apple's USB vendor ID — used to skip internal hubs/controllers.
    private static let appleVendorId = 0x05AC

    // MARK: - Initialization

    public init(pollInterval: TimeInterval = 10) {
        self.pollInterval = pollInterval
        var capturedContinuation: AsyncStream<USBDeviceEvent>.Continuation!
        self.events = AsyncStream(bufferingPolicy: .bufferingNewest(64)) { continuation in
            capturedContinuation = continuation
        }
        self.continuation = capturedContinuation
    }

    // MARK: - Lifecycle

    public func start() {
        guard pollTask == nil else { return }
        logger.info("USB monitor starting (poll every \(self.pollInterval)s)")

        pollTask = Task { [weak self] in
            guard let self else { return }
            while !Task.isCancelled {
                await self.scan()
                let interval = await self.pollInterval
                try? await Task.sleep(nanoseconds: UInt64(interval * 1_000_000_000))
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
        // Build matching dictionary for USB devices
        guard let matchingDict = IOServiceMatching(kIOUSBDeviceClassName) else { return }

        var iterator: io_iterator_t = 0
        let kr = IOServiceGetMatchingServices(kIOMainPortDefault, matchingDict, &iterator)
        guard kr == KERN_SUCCESS else { return }
        defer { IOObjectRelease(iterator) }

        var currentDevices: Set<String> = []

        var service = IOIteratorNext(iterator)
        while service != IO_OBJECT_NULL {
            defer {
                IOObjectRelease(service)
                service = IOIteratorNext(iterator)
            }

            let vendorId = Self.getIntProperty(service, key: "idVendor") ?? 0
            let productId = Self.getIntProperty(service, key: "idProduct") ?? 0
            let vendorName = Self.getStringProperty(service, key: "USB Vendor Name") ?? "Unknown"
            let productName = Self.getStringProperty(service, key: "USB Product Name") ?? "Unknown"
            let serialNumber = Self.getStringProperty(service, key: "USB Serial Number") ?? ""
            let deviceClass = Self.getIntProperty(service, key: "bDeviceClass") ?? 0

            let deviceKey = "\(vendorId):\(productId):\(serialNumber)"
            currentDevices.insert(deviceKey)

            // Skip Apple's internal devices (hubs, controllers)
            if vendorId == Self.appleVendorId { continue }

            // New device?
            if !knownDevices.contains(deviceKey) {
                let isMassStorage = deviceClass == Self.massStorageClass
                let event = USBDeviceEvent(
                    vendorId: vendorId,
                    productId: productId,
                    vendorName: vendorName,
                    productName: productName,
                    serialNumber: serialNumber,
                    deviceClass: deviceClass,
                    isConnected: true,
                    isMassStorage: isMassStorage,
                    timestamp: Date()
                )
                continuation?.yield(event)
                logger.info("USB device connected: \(vendorName) \(productName) (VID:\(vendorId) PID:\(productId))")
            }
        }

        // Detect disconnections
        for deviceKey in knownDevices where !currentDevices.contains(deviceKey) {
            let parts = deviceKey.split(separator: ":")
            let event = USBDeviceEvent(
                vendorId: Int(parts[0]) ?? 0,
                productId: Int(parts[1]) ?? 0,
                vendorName: "Unknown",
                productName: "Disconnected Device",
                serialNumber: parts.count > 2 ? String(parts[2]) : "",
                deviceClass: 0,
                isConnected: false,
                isMassStorage: false,
                timestamp: Date()
            )
            continuation?.yield(event)
        }

        knownDevices = currentDevices
    }

    // MARK: - IOKit Helpers

    private nonisolated static func getStringProperty(_ service: io_service_t, key: String) -> String? {
        guard let cfValue = IORegistryEntryCreateCFProperty(
            service, key as CFString, kCFAllocatorDefault, 0
        ) else { return nil }
        return cfValue.takeRetainedValue() as? String
    }

    private nonisolated static func getIntProperty(_ service: io_service_t, key: String) -> Int? {
        guard let cfValue = IORegistryEntryCreateCFProperty(
            service, key as CFString, kCFAllocatorDefault, 0
        ) else { return nil }
        return (cfValue.takeRetainedValue() as? NSNumber)?.intValue
    }
}
