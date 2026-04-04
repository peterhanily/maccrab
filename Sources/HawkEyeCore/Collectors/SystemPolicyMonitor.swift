// SystemPolicyMonitor.swift
// HawkEyeCore
//
// Periodic scanner for macOS security policy state and persistence mechanisms.
// Consolidates: SIP status, AMFI boot-args, authorization plugins,
// DirectoryService plugins, Spotlight importers, CryptoTokenKit extensions,
// XProtect version, quarantine xattr scanning, BTM persistence inventory.

import Foundation
import os.log

/// Periodically scans macOS system policy and persistence state.
///
/// Emits alerts for: SIP disabled, unauthorized auth plugins, unsigned
/// persistence items, quarantine stripping, outdated XProtect, rogue plugins.
public actor SystemPolicyMonitor {

    private let logger = Logger(subsystem: "com.hawkeye", category: "system-policy")

    public nonisolated let events: AsyncStream<SystemPolicyEvent>
    private var continuation: AsyncStream<SystemPolicyEvent>.Continuation?
    private var pollTask: Task<Void, Never>?
    private let pollInterval: TimeInterval

    /// Baseline state for diffing.
    private var knownPlugins: Set<String> = []
    private var knownBTMItems: Set<String> = []
    private var lastSIPStatus: String?
    private var lastXProtectVersion: String?

    // MARK: - Types

    public struct SystemPolicyEvent: Sendable {
        public let type: PolicyEventType
        public let description: String
        public let path: String?
        public let severity: Severity
        public let mitreTactic: String
        public let mitreTechnique: String
    }

    public enum PolicyEventType: String, Sendable {
        case sipDisabled = "sip_disabled"
        case amfiBypass = "amfi_bypass"
        case authPluginFound = "auth_plugin_found"
        case directoryServicePlugin = "directory_service_plugin"
        case spotlightImporter = "spotlight_importer"
        case cryptoTokenExtension = "crypto_token_extension"
        case xprotectOutdated = "xprotect_outdated"
        case quarantineStripped = "quarantine_stripped"
        case btmNewItem = "btm_new_persistence"
        case gatekeeperOverride = "gatekeeper_override"
        case rogueXPCService = "rogue_xpc_service"
        case rogueMDMProfile = "rogue_mdm_profile"
        case unexpectedSnapshot = "unexpected_apfs_snapshot"
    }

    // MARK: - Initialization

    public init(pollInterval: TimeInterval = 300) { // Every 5 minutes
        self.pollInterval = pollInterval
        var capturedContinuation: AsyncStream<SystemPolicyEvent>.Continuation!
        self.events = AsyncStream(bufferingPolicy: .bufferingNewest(64)) { continuation in
            capturedContinuation = continuation
        }
        self.continuation = capturedContinuation
    }

    // MARK: - Lifecycle

    public func start() {
        guard pollTask == nil else { return }
        logger.info("System policy monitor starting")

        // Initial baseline
        knownPlugins = scanPluginPaths()

        pollTask = Task { [weak self] in
            guard let self else { return }
            // Immediate first scan
            await self.fullScan()
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: UInt64(self.pollInterval * 1_000_000_000))
                guard !Task.isCancelled else { break }
                await self.fullScan()
            }
        }
    }

    public func stop() {
        pollTask?.cancel()
        pollTask = nil
        continuation?.finish()
    }

    // MARK: - Full Scan

    private func fullScan() {
        checkSIPStatus()
        checkAMFIBootArgs()
        checkAuthPlugins()
        checkPluginDirectories()
        checkXProtectVersion()
        scanDownloadsForMissingQuarantine()
        checkXPCServices()
        checkMDMProfiles()
        checkAPFSSnapshots()
    }

    // MARK: - SIP Status

    private func checkSIPStatus() {
        let status = runCommand("/usr/bin/csrutil", args: ["status"])
        let isDisabled = status.contains("disabled") || status.contains("Custom Configuration")

        if isDisabled && lastSIPStatus != "disabled" {
            lastSIPStatus = "disabled"
            emit(SystemPolicyEvent(
                type: .sipDisabled,
                description: "System Integrity Protection is DISABLED. All system protections are weakened. Status: \(status.trimmingCharacters(in: .whitespacesAndNewlines))",
                path: nil,
                severity: .critical,
                mitreTactic: "attack.defense_evasion",
                mitreTechnique: "attack.t1562.001"
            ))
        } else if !isDisabled {
            lastSIPStatus = "enabled"
        }
    }

    // MARK: - AMFI Boot Args

    private func checkAMFIBootArgs() {
        let bootArgs = runCommand("/usr/sbin/nvram", args: ["boot-args"]).lowercased()
        let dangerous = [
            ("amfi_get_out_of_my_way", "AMFI code signing enforcement disabled"),
            ("cs_enforcement_disable", "Code signing enforcement disabled"),
            ("PE_i_can_has_debugger", "Kernel debugging enabled"),
        ]

        for (flag, desc) in dangerous {
            if bootArgs.contains(flag) {
                emit(SystemPolicyEvent(
                    type: .amfiBypass,
                    description: "\(desc) via boot-args: \(flag)",
                    path: nil,
                    severity: .critical,
                    mitreTactic: "attack.defense_evasion",
                    mitreTechnique: "attack.t1562.001"
                ))
            }
        }
    }

    // MARK: - Authorization Plugins

    private func checkAuthPlugins() {
        let pluginDir = "/Library/Security/SecurityAgentPlugins"
        guard let items = try? FileManager.default.contentsOfDirectory(atPath: pluginDir) else { return }

        for item in items where item.hasSuffix(".bundle") {
            let fullPath = pluginDir + "/" + item
            if !knownPlugins.contains(fullPath) {
                knownPlugins.insert(fullPath)

                // Check code signature
                let sigInfo = runCommand("/usr/bin/codesign", args: ["-dvv", fullPath])
                let isApple = sigInfo.contains("Apple") && sigInfo.contains("Authority=Software Signing")

                if !isApple {
                    emit(SystemPolicyEvent(
                        type: .authPluginFound,
                        description: "Non-Apple authorization plugin found: \(item). This plugin runs during login with root privileges and can intercept credentials.",
                        path: fullPath,
                        severity: .critical,
                        mitreTactic: "attack.credential_access",
                        mitreTechnique: "attack.t1556.003"
                    ))
                }
            }
        }
    }

    // MARK: - Plugin Directories

    private func checkPluginDirectories() {
        let directories: [(String, PolicyEventType, String, String)] = [
            ("/Library/DirectoryServices/PlugIns", .directoryServicePlugin, "attack.persistence", "attack.t1556"),
            ("/Library/Spotlight", .spotlightImporter, "attack.persistence", "attack.t1547"),
            (NSHomeDirectory() + "/Library/Spotlight", .spotlightImporter, "attack.persistence", "attack.t1547"),
        ]

        for (dir, type, tactic, technique) in directories {
            guard let items = try? FileManager.default.contentsOfDirectory(atPath: dir) else { continue }

            for item in items where item.hasSuffix(".bundle") || item.hasSuffix(".dsplug") || item.hasSuffix(".mdimporter") {
                let fullPath = dir + "/" + item
                if !knownPlugins.contains(fullPath) {
                    knownPlugins.insert(fullPath)

                    let sigInfo = runCommand("/usr/bin/codesign", args: ["-dv", fullPath])
                    let isUnsigned = sigInfo.contains("not signed") || sigInfo.contains("invalid")

                    if isUnsigned {
                        emit(SystemPolicyEvent(
                            type: type,
                            description: "Unsigned \(type.rawValue) found: \(item) at \(dir)",
                            path: fullPath,
                            severity: .high,
                            mitreTactic: tactic,
                            mitreTechnique: technique
                        ))
                    }
                }
            }
        }

        // CryptoTokenKit extensions
        let ctkOutput = runCommand("/usr/bin/pluginkit", args: ["-m", "-p", "com.apple.ctk-tokens"])
        let ctkLines = ctkOutput.split(separator: "\n")
        for line in ctkLines {
            let lineStr = String(line)
            if !lineStr.contains("com.apple.") && !knownPlugins.contains(lineStr) {
                knownPlugins.insert(lineStr)
                emit(SystemPolicyEvent(
                    type: .cryptoTokenExtension,
                    description: "Non-Apple CryptoTokenKit extension: \(lineStr)",
                    path: nil,
                    severity: .high,
                    mitreTactic: "attack.credential_access",
                    mitreTechnique: "attack.t1556"
                ))
            }
        }
    }

    // MARK: - XProtect Version

    private func checkXProtectVersion() {
        let versionPlist = "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/version.plist"
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: versionPlist)),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let version = plist["CFBundleShortVersionString"] as? String else { return }

        if lastXProtectVersion == nil {
            lastXProtectVersion = version
            return
        }

        // Check modification date of XProtect bundle
        if let attrs = try? FileManager.default.attributesOfItem(atPath: versionPlist),
           let modDate = attrs[.modificationDate] as? Date {
            let daysSinceUpdate = Date().timeIntervalSince(modDate) / 86400
            if daysSinceUpdate > 30 {
                emit(SystemPolicyEvent(
                    type: .xprotectOutdated,
                    description: "XProtect signatures are \(Int(daysSinceUpdate)) days old (version \(version)). Apple malware definitions may be outdated.",
                    path: versionPlist,
                    severity: .medium,
                    mitreTactic: "attack.defense_evasion",
                    mitreTechnique: "attack.t1562.001"
                ))
            }
        }
    }

    // MARK: - Quarantine xattr Scanning

    private func scanDownloadsForMissingQuarantine() {
        let downloadsDir = NSHomeDirectory() + "/Downloads"
        guard let items = try? FileManager.default.contentsOfDirectory(atPath: downloadsDir) else { return }

        for item in items {
            let fullPath = downloadsDir + "/" + item
            var isDir: ObjCBool = false
            FileManager.default.fileExists(atPath: fullPath, isDirectory: &isDir)

            // Check executables and app bundles
            let isExecutable = FileManager.default.isExecutableFile(atPath: fullPath)
            let isApp = item.hasSuffix(".app")
            let isDMG = item.hasSuffix(".dmg") || item.hasSuffix(".iso")

            guard isExecutable || isApp || isDMG else { continue }

            // Check for quarantine xattr
            let xattrOutput = runCommand("/usr/bin/xattr", args: ["-l", fullPath])
            if !xattrOutput.contains("com.apple.quarantine") {
                // File in Downloads without quarantine — possible stripping
                emit(SystemPolicyEvent(
                    type: .quarantineStripped,
                    description: "Executable in Downloads missing quarantine xattr: \(item). May have had Gatekeeper protection removed.",
                    path: fullPath,
                    severity: .high,
                    mitreTactic: "attack.defense_evasion",
                    mitreTechnique: "attack.t1553.001"
                ))
            }
        }
    }

    // MARK: - XPC Service Enumeration

    private var knownXPCServices: Set<String> = []

    private func checkXPCServices() {
        let output = runCommand("/bin/launchctl", args: ["list"])
        let lines = output.split(separator: "\n")

        for line in lines.dropFirst() { // Skip header
            let parts = line.split(separator: "\t", maxSplits: 2)
            guard parts.count >= 3 else { continue }
            let label = String(parts[2])

            // Skip known Apple services
            if label.hasPrefix("com.apple.") || label.hasPrefix("Apple") { continue }
            if label.hasPrefix("[") { continue } // System services

            if !knownXPCServices.contains(label) {
                knownXPCServices.insert(label)

                // Check if this is a new, possibly rogue service
                // Only alert on services that look suspicious
                if label.count < 5 || label.contains("..") || !label.contains(".") {
                    emit(SystemPolicyEvent(
                        type: .rogueXPCService,
                        description: "Suspicious XPC service registered: \(label). Non-standard naming suggests potential persistence mechanism.",
                        path: nil,
                        severity: .medium,
                        mitreTactic: "attack.persistence",
                        mitreTechnique: "attack.t1543"
                    ))
                }
            }
        }
    }

    // MARK: - MDM Profile Detection

    private func checkMDMProfiles() {
        let output = runCommand("/usr/bin/profiles", args: ["list", "-output", "stdout-xml"])
        if output.isEmpty { return }

        // Look for configuration profiles
        let profileDir = "/var/db/ConfigurationProfiles"
        guard let items = try? FileManager.default.contentsOfDirectory(atPath: profileDir) else { return }

        for item in items where item.hasSuffix(".mobileconfig") || item.hasSuffix(".plist") {
            let fullPath = profileDir + "/" + item

            // Read profile to check if it modifies security settings
            if let data = try? String(contentsOfFile: fullPath, encoding: .utf8) {
                let suspicious = [
                    "allowSigned", "DisableGatekeeper", "allowAllApps",
                    "PayloadRemovalDisallowed", "com.apple.ManagedClient",
                ]
                for keyword in suspicious where data.contains(keyword) {
                    emit(SystemPolicyEvent(
                        type: .rogueMDMProfile,
                        description: "MDM profile modifies security policy (\(keyword)): \(item)",
                        path: fullPath,
                        severity: .high,
                        mitreTactic: "attack.defense_evasion",
                        mitreTechnique: "attack.t1562.001"
                    ))
                    break
                }
            }
        }
    }

    // MARK: - APFS Snapshot Monitoring

    private var knownSnapshots: Set<String> = []

    private func checkAPFSSnapshots() {
        let output = runCommand("/usr/bin/tmutil", args: ["listlocalsnapshots", "/"])
        let lines = output.split(separator: "\n").map(String.init)

        for line in lines {
            let snapshot = line.trimmingCharacters(in: .whitespaces)
            guard !snapshot.isEmpty, !snapshot.hasPrefix("Snapshots for") else { continue }

            if !knownSnapshots.contains(snapshot) {
                let wasEmpty = knownSnapshots.isEmpty
                knownSnapshots.insert(snapshot)

                // Only alert on new snapshots after initial baseline
                if !wasEmpty {
                    emit(SystemPolicyEvent(
                        type: .unexpectedSnapshot,
                        description: "New APFS snapshot created: \(snapshot). Unexpected snapshots may be used to hide data or stage attacks.",
                        path: nil,
                        severity: .low,
                        mitreTactic: "attack.defense_evasion",
                        mitreTechnique: "attack.t1564"
                    ))
                }
            }
        }
    }

    // MARK: - Helpers

    private func emit(_ event: SystemPolicyEvent) {
        continuation?.yield(event)
    }

    private func scanPluginPaths() -> Set<String> {
        var paths: Set<String> = []
        let dirs = [
            "/Library/Security/SecurityAgentPlugins",
            "/Library/DirectoryServices/PlugIns",
            "/Library/Spotlight",
            NSHomeDirectory() + "/Library/Spotlight",
        ]
        for dir in dirs {
            if let items = try? FileManager.default.contentsOfDirectory(atPath: dir) {
                for item in items {
                    paths.insert(dir + "/" + item)
                }
            }
        }
        return paths
    }

    private nonisolated func runCommand(_ path: String, args: [String], timeout: TimeInterval = 10) -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = args
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
            // Timeout: kill process if it hangs
            let deadline = DispatchTime.now() + timeout
            DispatchQueue.global().asyncAfter(deadline: deadline) {
                if process.isRunning { process.terminate() }
            }
            process.waitUntilExit()
            return String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        } catch {
            return ""
        }
    }
}
