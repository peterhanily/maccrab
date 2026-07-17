// SystemPolicyMonitor.swift
// MacCrabCore
//
// Periodic scanner for macOS security policy state and persistence mechanisms.
// Consolidates: SIP status, AMFI boot-args, authorization plugins,
// DirectoryService plugins, Spotlight importers, CryptoTokenKit extensions,
// XProtect version, quarantine xattr scanning, BTM persistence inventory.

import Foundation
import Darwin
import Security
import os.log

/// Periodically scans macOS system policy and persistence state.
///
/// Emits alerts for: SIP disabled, unauthorized auth plugins, unsigned
/// persistence items, quarantine stripping, outdated XProtect, rogue plugins.
public actor SystemPolicyMonitor {

    private let logger = Logger(subsystem: "com.maccrab", category: "system-policy")

    public nonisolated let events: AsyncStream<SystemPolicyEvent>
    private var continuation: AsyncStream<SystemPolicyEvent>.Continuation?
    private var pollTask: Task<Void, Never>?
    private let pollInterval: TimeInterval

    /// Baseline state for diffing.
    private var knownPlugins: Set<String> = []
    private var knownBTMItems: Set<String> = []
    private var knownMDMProfiles: Set<String> = []
    private var mdmProfilesBaselined = false
    private var lastSIPStatus: String?
    private var lastXProtectVersion: String?
    /// XProtect-outdated dedup: the version string we last emitted an
    /// `xprotectOutdated` alert for, and when. XProtect being outdated is a
    /// PERSISTENT condition — without this the 5-min poll re-alerted every
    /// cycle (~25 identical "signatures are N days old" alerts/day of pure
    /// noise). We alert once per outdated version and only re-arm when the
    /// version changes OR the 24h cooldown lapses.
    private var xprotectAlertedVersion: String?
    private var xprotectLastAlertAt: Date?
    private static let xprotectAlertCooldown: TimeInterval = 24 * 3600
    /// AMFI boot-arg flags we have already emitted for. Boot-args are a
    /// persistent, reboot-scoped condition (they can't change without a
    /// reboot, which restarts this process and clears the set), so a plain
    /// per-flag dedup within the process lifetime is sufficient. Without it,
    /// every poll re-fired the same critical AMFI alert.
    private var amfiAlertedFlags: Set<String> = []
    /// MDM profiles we have already emitted a `rogueMDMProfile` content-
    /// inspection alert for. A profile that modifies security policy stays
    /// installed — without this the content-inspection loop re-alerted on the
    /// same profile every poll.
    private var mdmRogueContentAlerted: Set<String> = []
    /// Paths we have already emitted a "quarantine stripped" event for.
    /// Without this, every full scan re-alerts on the same Downloads items,
    /// which previously accounted for the bulk of SystemPolicyMonitor noise.
    private var quarantineAlerted: Set<String> = []

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
        case mdmProfileInstalled = "mdm_profile_installed"
        case mdmProfileRemoved = "mdm_profile_removed"
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
                // v1.6.21: gate poll interval through PowerGate so the 5-min
                // SIP/XProtect/plugin scan throttles on battery / thermal
                // pressure. Pre-fix the interval was static — every 5 min
                // the daemon shelled out to csrutil/xprotect even in low-
                // power mode.
                let adjusted = PowerGate.adjustedInterval(base: self.pollInterval)
                try? await Task.sleep(nanoseconds: UInt64(adjusted * 1_000_000_000))
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
        // Match keys are lowercase to compare against the lowercased boot-args.
        // (v1.21.4 review: `PE_i_can_has_debugger` was an UPPERCASE literal that
        // could never match the lowercased read — a pre-existing dead flag,
        // corrected here while diff-tracking is added.)
        let dangerous = [
            ("amfi_get_out_of_my_way", "AMFI code signing enforcement disabled"),
            ("cs_enforcement_disable", "Code signing enforcement disabled"),
            ("pe_i_can_has_debugger", "Kernel debugging enabled"),
        ]

        // v1.21.4 review fix (L5): nvram boot-args is RUNTIME-mutable, not merely
        // reboot-scoped — a flag can be cleared (`nvram -d boot-args`) and re-added
        // within one uptime. Diff-track like the MDM-profile check: alert on a
        // newly-present flag, and DROP a flag from the alerted set once it's absent
        // so a clear-then-re-add re-alerts. Without the drop, re-introduction of a
        // critical AMFI/CS bypass stayed silent for the rest of the process life.
        var present: Set<String> = []
        for (flag, desc) in dangerous where bootArgs.contains(flag) {
            present.insert(flag)
            guard !amfiAlertedFlags.contains(flag) else { continue }
            amfiAlertedFlags.insert(flag)
            emit(SystemPolicyEvent(
                type: .amfiBypass,
                description: "\(desc) via boot-args: \(flag)",
                path: nil,
                severity: .critical,
                mitreTactic: "attack.defense_evasion",
                mitreTechnique: "attack.t1562.001"
            ))
        }
        // Re-arm flags that are no longer present so their return re-alerts.
        amfiAlertedFlags.formIntersection(present)
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

        // CryptoTokenKit extensions. v1.4.5 tightening: most non-Apple
        // CTK extensions on a real Mac are YubiKey, 1Password, OneSpan,
        // PIV smartcard tokens, and other legitimate auth hardware.
        // HIGH severity for all of them made every user see a "credential
        // access attempt" alert on normal YubiKey insert. Skip known
        // signed auth providers entirely; lower the rest to
        // informational (the sysext still records the enumeration, the
        // operator just doesn't get a red alert in the dashboard).
        let ctkOutput = runCommand("/usr/bin/pluginkit", args: ["-m", "-p", "com.apple.ctk-tokens"])
        let ctkLines = ctkOutput.split(separator: "\n")
        for line in ctkLines {
            let lineStr = String(line)
            // pluginkit can emit status/error lines to the match column on
            // machines with smartcard daemons in transitional states ("match:
            // Connection invalid", "match: Operation not permitted"). These
            // aren't plugin bundle IDs and shouldn't surface as CTK alerts.
            // Real plugin entries are reverse-DNS bundle IDs that contain a
            // dot and no whitespace in the matching segment.
            if lineStr.contains("Connection invalid") ||
               lineStr.contains("Operation not permitted") ||
               lineStr.contains("No such") ||
               lineStr.lowercased().contains("error") {
                continue
            }
            guard !lineStr.contains("com.apple."),
                  !Self.trustedCTKProviders.contains(where: { lineStr.contains($0) }),
                  !knownPlugins.contains(lineStr) else {
                continue
            }
            knownPlugins.insert(lineStr)
            emit(SystemPolicyEvent(
                type: .cryptoTokenExtension,
                description: "Non-Apple CryptoTokenKit extension: \(lineStr)",
                path: nil,
                severity: .informational,
                mitreTactic: "attack.credential_access",
                mitreTechnique: "attack.t1556"
            ))
        }
    }

    /// Known-legitimate CTK providers. Installing one of these is not a
    /// credential-access attack — it's a user plugging in a YubiKey or
    /// installing 1Password. Substring match against the plugin bundle
    /// ID from `pluginkit -m`.
    private static let trustedCTKProviders: [String] = [
        "com.yubico.",                  // YubiKey
        "com.agilebits.",               // 1Password 7 / 8
        "com.1password.",               // 1Password browser integration
        "com.onespan.",                 // OneSpan / VASCO
        "com.thalesgroup.",             // Thales / SafeNet
        "com.entrust.",                 // Entrust smartcards
        "com.gemalto.",                 // Gemalto PIV
        "net.opensc-project.",          // OpenSC
        "com.cryptosmart.",
        "at.mtrust.",                   // mTrust
    ]

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
                // Dedup: XProtect being outdated is a persistent condition, so
                // emitting once per poll (every 5 min) produced ~25 identical
                // alerts/day. Alert once per outdated version; re-arm only when
                // the version string changes OR the 24h cooldown lapses.
                let now = Date()
                guard Self.shouldEmitXProtectOutdated(
                    version: version,
                    alertedVersion: xprotectAlertedVersion,
                    lastAlertAt: xprotectLastAlertAt,
                    now: now
                ) else { return }
                xprotectAlertedVersion = version
                xprotectLastAlertAt = now
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

    /// Pure per-poll dedup decision for the persistent XProtect-outdated
    /// condition. Returns true when an alert SHOULD be emitted for `version`
    /// given the last-alerted version/time. Extracted (and `static`) so the
    /// dedup is unit-testable without shelling out to the real XProtect bundle.
    /// Re-arms when the version changes OR the 24h cooldown lapses. (R1)
    static func shouldEmitXProtectOutdated(
        version: String,
        alertedVersion: String?,
        lastAlertAt: Date?,
        now: Date
    ) -> Bool {
        let alreadyAlerted = alertedVersion == version
            && (lastAlertAt.map { now.timeIntervalSince($0) < xprotectAlertCooldown } ?? false)
        return !alreadyAlerted
    }

    /// Probe for the `com.apple.quarantine` extended attribute on a
    /// path without shelling out. `getxattr(path, name, nil, 0, 0, 0)`
    /// returns ≥0 if the attribute exists (the size in bytes), -1 if
    /// it doesn't or the path is unreadable. We only care about
    /// presence, not the value.
    private func hasQuarantineXattr(path: String) -> Bool {
        path.withCString { pathPtr in
            "com.apple.quarantine".withCString { namePtr in
                getxattr(pathPtr, namePtr, nil, 0, 0, 0) >= 0
            }
        }
    }

    // MARK: - Quarantine xattr Scanning

    private func scanDownloadsForMissingQuarantine() {
        let downloadsDir = NSHomeDirectory() + "/Downloads"
        guard let items = try? FileManager.default.contentsOfDirectory(atPath: downloadsDir) else { return }

        for item in items {
            let fullPath = downloadsDir + "/" + item

            // Skip items we have already alerted on. The poll cycle re-runs
            // every 5 minutes; without this guard a single unquarantined file
            // generates one alert per poll indefinitely.
            if quarantineAlerted.contains(fullPath) { continue }

            var isDir: ObjCBool = false
            FileManager.default.fileExists(atPath: fullPath, isDirectory: &isDir)

            // Check executables and app bundles only. Disk images (.dmg/.iso)
            // are containers, not executables — macOS cannot codesign them
            // directly, and Gatekeeper re-evaluates the contained app bundle
            // when the image is mounted and its app is launched. A stripped
            // quarantine xattr on a downloaded DMG is therefore not a
            // meaningful bypass indicator on its own.
            let isExecutable = FileManager.default.isExecutableFile(atPath: fullPath)
            let isApp = item.hasSuffix(".app")

            guard isExecutable || isApp else { continue }

            // Check for quarantine xattr via getxattr(2). Pre-fix this
            // shelled out to `/usr/bin/xattr -l <path>` per file (~50
            // items in Downloads × every 5 min = ~14,400 forks/day for
            // a single syscall's worth of work). Now zero forks.
            if hasQuarantineXattr(path: fullPath) { continue }

            // A validly-signed app with an Apple-rooted anchor is a
            // non-issue: Gatekeeper still evaluates signed code regardless
            // of the quarantine xattr, and legitimate apps often ship
            // without quarantine once installed. Only flag when the target
            // is unsigned/ad-hoc or outright fails signature validation.
            if isSignedWithAppleAnchor(path: fullPath) {
                quarantineAlerted.insert(fullPath)
                continue
            }

            quarantineAlerted.insert(fullPath)
            emit(SystemPolicyEvent(
                type: .quarantineStripped,
                description: "Unsigned executable in Downloads missing quarantine xattr: \(item). May have had Gatekeeper protection removed.",
                path: fullPath,
                severity: .high,
                mitreTactic: "attack.defense_evasion",
                mitreTechnique: "attack.t1553.001"
            ))
        }
    }

    /// True when the file at `path` has a valid signature rooted in Apple
    /// (first-party, Mac App Store, or Developer ID). These files do not
    /// represent a meaningful "stripped quarantine" risk.
    private func isSignedWithAppleAnchor(path: String) -> Bool {
        let url = URL(fileURLWithPath: path) as CFURL
        var staticCodeRef: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url, [], &staticCodeRef) == errSecSuccess,
              let staticCode = staticCodeRef else { return false }

        let flags = SecCSFlags(rawValue: kSecCSCheckAllArchitectures)
        guard SecStaticCodeCheckValidity(staticCode, flags, nil) == errSecSuccess else { return false }

        var reqRef: SecRequirement?
        guard SecRequirementCreateWithString(
            "anchor apple generic" as CFString, [], &reqRef
        ) == errSecSuccess, let requirement = reqRef else { return false }

        return SecStaticCodeCheckValidity(staticCode, flags, requirement) == errSecSuccess
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
        // Enumerate current profiles from the profiles CLI (triggers MDM refresh)
        _ = runCommand("/usr/bin/profiles", args: ["list", "-output", "stdout-xml"])

        // Scan the configuration profiles directory
        let profileDir = "/var/db/ConfigurationProfiles"
        let currentProfiles: Set<String>
        if let items = try? FileManager.default.contentsOfDirectory(atPath: profileDir) {
            currentProfiles = Set(items.filter { $0.hasSuffix(".mobileconfig") || $0.hasSuffix(".plist") })
        } else {
            currentProfiles = []
        }

        // --- Drift detection: detect installations and removals ---
        if mdmProfilesBaselined {
            // Detect newly installed profiles
            let addedProfiles = currentProfiles.subtracting(knownMDMProfiles)
            for profile in addedProfiles {
                let fullPath = profileDir + "/" + profile
                emit(SystemPolicyEvent(
                    type: .mdmProfileInstalled,
                    description: "MDM configuration profile installed: \(profile). New profiles may modify security policy, install certificates, or change device configuration.",
                    path: fullPath,
                    severity: .high,
                    mitreTactic: "attack.defense_evasion",
                    mitreTechnique: "attack.t1562.001"
                ))
            }

            // Detect removed profiles
            let removedProfiles = knownMDMProfiles.subtracting(currentProfiles)
            for profile in removedProfiles {
                let fullPath = profileDir + "/" + profile
                emit(SystemPolicyEvent(
                    type: .mdmProfileRemoved,
                    description: "MDM configuration profile removed: \(profile). Profile removal may indicate evasion of enterprise security controls.",
                    path: fullPath,
                    severity: .critical,
                    mitreTactic: "attack.defense_evasion",
                    mitreTechnique: "attack.t1562.001"
                ))
            }
        } else {
            mdmProfilesBaselined = true
        }

        // Update baseline
        knownMDMProfiles = currentProfiles

        // --- Content inspection: check for security-modifying profiles ---
        for item in currentProfiles {
            let fullPath = profileDir + "/" + item

            // Read profile to check if it modifies security settings
            if let data = try? String(contentsOfFile: fullPath, encoding: .utf8) {
                let suspicious = [
                    "allowSigned", "DisableGatekeeper", "allowAllApps",
                    "PayloadRemovalDisallowed", "com.apple.ManagedClient",
                    "com.apple.security.firewall", "forceAutoFillUpdate",
                    "allowRoot", "com.apple.TCC",
                ]
                for keyword in suspicious where data.contains(keyword) {
                    // Dedup: an installed policy-modifying profile is a
                    // persistent condition; without this the content-inspection
                    // loop re-alerted on the same profile every poll. Alert once
                    // per profile path (installation drift is handled separately
                    // above by the added/removed diff).
                    guard !mdmRogueContentAlerted.contains(fullPath) else { break }
                    mdmRogueContentAlerted.insert(fullPath)
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
            // Drain the pipe BEFORE waiting so large command output can't
            // deadlock (child blocks on write, parent blocks in waitUntilExit).
            let output = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            process.waitUntilExit()
            return output
        } catch {
            return ""
        }
    }
}
