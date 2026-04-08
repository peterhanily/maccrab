// EDRMonitor.swift
// MacCrabCore
//
// Proactive monitor for EDR, RMM, insider threat, and remote access tools
// running on this machine. Periodically scans the process list and
// LaunchDaemons/LaunchAgents for known tool signatures.
//
// This is a visibility feature — it answers "what can remotely control my Mac?"

import Foundation
import os.log

/// Monitors for EDR, remote management, insider threat, and remote access
/// tools running on or installed on this machine.
public actor EDRMonitor {

    private let logger = Logger(subsystem: "com.maccrab", category: "edr-monitor")

    /// How often to scan for EDR/RMM tools (default: 120 seconds).
    private let pollInterval: TimeInterval

    /// AsyncStream continuation for emitting discoveries.
    private var continuation: AsyncStream<EDRDiscovery>.Continuation?

    /// The event stream — created once at init, shared via nonisolated property.
    private let _events: AsyncStream<EDRDiscovery>

    /// Known tools already reported (avoid re-alerting per session).
    private var reportedTools: Set<String> = []

    /// Active task.
    private var scanTask: Task<Void, Never>?

    // MARK: - Types

    public struct EDRDiscovery: Sendable {
        public let toolName: String
        public let vendor: String
        public let category: ToolCategory
        public let capabilities: [String]
        public let processName: String?
        public let processPath: String?
        public let pid: Int32?
        public let installedPath: String?
        public let timestamp: Date

        public init(
            toolName: String, vendor: String, category: ToolCategory,
            capabilities: [String], processName: String? = nil,
            processPath: String? = nil, pid: Int32? = nil,
            installedPath: String? = nil
        ) {
            self.toolName = toolName
            self.vendor = vendor
            self.category = category
            self.capabilities = capabilities
            self.processName = processName
            self.processPath = processPath
            self.pid = pid
            self.installedPath = installedPath
            self.timestamp = Date()
        }
    }

    public enum ToolCategory: String, Sendable {
        case edr = "EDR"
        case insiderThreat = "Insider Threat / UAM"
        case mdm = "MDM"
        case remoteAccess = "Remote Access"
        case rmm = "RMM"
    }

    // MARK: - Tool Database

    /// Each known tool with its process signatures, vendor, capabilities, and paths.
    private static let knownTools: [KnownTool] = [
        // === EDR ===
        KnownTool(
            name: "CrowdStrike Falcon", vendor: "CrowdStrike", category: .edr,
            processNames: ["falcond", "falcon-sensor", "CSFalconService", "falconctl"],
            pathFragments: ["CrowdStrike", "com.crowdstrike"],
            capabilities: ["Remote shell (RTR)", "File collection", "Process kill", "Memory dump", "Script execution", "Network containment"]
        ),
        KnownTool(
            name: "SentinelOne", vendor: "SentinelOne", category: .edr,
            processNames: ["sentineld", "SentinelAgent", "sentinelctl", "SentinelMonitor"],
            pathFragments: ["sentinel", "SentinelOne", "com.sentinelone"],
            capabilities: ["Remote shell", "File fetch", "Process kill", "Network isolation", "Rollback"]
        ),
        KnownTool(
            name: "Carbon Black", vendor: "Broadcom/VMware", category: .edr,
            processNames: ["cbagentd", "CbDefense", "cbdaemon", "CbOsxSensorService"],
            pathFragments: ["CarbonBlack", "com.carbonblack", "CbDefense"],
            capabilities: ["Live Response shell", "File collection", "Memory dump", "Process kill", "Network isolation"]
        ),
        KnownTool(
            name: "Microsoft Defender for Endpoint", vendor: "Microsoft", category: .edr,
            processNames: ["wdavdaemon", "mdatp", "MicrosoftDefender", "MicrosoftDefenderATP"],
            pathFragments: ["Microsoft Defender", "com.microsoft.wdav"],
            capabilities: ["Live Response", "Investigation package collection", "File quarantine", "Network indicators"]
        ),
        KnownTool(
            name: "Tanium", vendor: "Tanium", category: .edr,
            processNames: ["TaniumClient", "taniumd", "TaniumEndpointIndex"],
            pathFragments: ["Tanium", "com.tanium"],
            capabilities: ["Remote shell", "File collection", "Direct connect", "Patch deployment", "Software distribution"]
        ),
        KnownTool(
            name: "Velociraptor", vendor: "Rapid7", category: .edr,
            processNames: ["velociraptor"],
            pathFragments: ["velociraptor"],
            capabilities: ["Remote artifact collection", "Shell access", "File download", "YARA scanning"]
        ),
        KnownTool(
            name: "Osquery / Fleet", vendor: "Various", category: .edr,
            processNames: ["osqueryd", "orbit", "osqueryctl"],
            pathFragments: ["osquery", "fleetdm"],
            capabilities: ["SQL-based remote querying", "File integrity monitoring", "Process monitoring"]
        ),
        KnownTool(
            name: "Sophos", vendor: "Sophos", category: .edr,
            processNames: ["SophosScanD", "SophosAntiVirus", "SophosServiceManager", "SophosCleanD"],
            pathFragments: ["Sophos", "com.sophos"],
            capabilities: ["Remote scan", "File quarantine", "Web filtering", "Tamper protection"]
        ),
        KnownTool(
            name: "ESET Endpoint Security", vendor: "ESET", category: .edr,
            processNames: ["esets_daemon", "esets_proxy", "ESET"],
            pathFragments: ["ESET", "com.eset"],
            capabilities: ["Remote scan", "File quarantine", "Web filtering", "Device control"]
        ),
        KnownTool(
            name: "Palo Alto Cortex XDR", vendor: "Palo Alto", category: .edr,
            processNames: ["traps_agent", "cortex_xdr"],
            pathFragments: ["Cortex XDR", "Traps", "com.paloaltonetworks"],
            capabilities: ["Live Terminal", "File retrieval", "Script execution", "Network isolation"]
        ),

        // === INSIDER THREAT / UAM ===
        KnownTool(
            name: "Proofpoint/ObserveIT", vendor: "Proofpoint", category: .insiderThreat,
            processNames: ["OIAgent", "observeitd", "proofpoint_agent", "ProofpointAgent"],
            pathFragments: ["ObserveIT", "Proofpoint", "com.proofpoint"],
            capabilities: ["Screen recording", "Keystroke logging", "File monitoring", "Email monitoring", "USB monitoring", "Clipboard capture"]
        ),
        KnownTool(
            name: "ForcePoint Insider Threat", vendor: "ForcePoint", category: .insiderThreat,
            processNames: ["fpagent", "FPDLPAgent", "InnerViewAgent", "FPInsiderThreat"],
            pathFragments: ["Forcepoint", "ForcePoint", "InnerView"],
            capabilities: ["Screen capture", "Keystroke logging", "File monitoring", "DLP", "Behavioral analytics", "Video recording"]
        ),
        KnownTool(
            name: "Teramind", vendor: "Teramind", category: .insiderThreat,
            processNames: ["teramind_agent", "tmicro", "TeramindAgent"],
            pathFragments: ["Teramind", "teramind"],
            capabilities: ["Screen recording", "Keystroke logging", "Behavioral analysis", "OCR", "DLP", "Productivity tracking"]
        ),
        KnownTool(
            name: "ActivTrak", vendor: "ActivTrak", category: .insiderThreat,
            processNames: ["activtrak", "ActivTrakAgent"],
            pathFragments: ["ActivTrak", "activtrak"],
            capabilities: ["Screen capture", "App usage tracking", "Website monitoring", "Productivity analytics"]
        ),
        KnownTool(
            name: "Veriato (Cerebral)", vendor: "Veriato", category: .insiderThreat,
            processNames: ["VeriatoAgent", "Veriato360"],
            pathFragments: ["Veriato", "veriato"],
            capabilities: ["Screen recording", "Keystroke logging", "Email monitoring", "IM monitoring", "File tracking"]
        ),
        KnownTool(
            name: "Hubstaff", vendor: "Hubstaff", category: .insiderThreat,
            processNames: ["Hubstaff", "HubstaffAgent"],
            pathFragments: ["Hubstaff"],
            capabilities: ["Screenshot capture", "Activity tracking", "App/URL monitoring", "GPS tracking"]
        ),
        KnownTool(
            name: "Securonix UEBA", vendor: "Securonix", category: .insiderThreat,
            processNames: ["securonix_agent", "SnyprAgent"],
            pathFragments: ["Securonix", "securonix"],
            capabilities: ["Behavioral analytics", "Anomaly detection", "Risk scoring", "Data exfiltration detection"]
        ),

        // === MDM ===
        KnownTool(
            name: "Jamf Pro", vendor: "Jamf", category: .mdm,
            processNames: ["jamf", "JamfDaemon", "JamfAgent", "JamfManagementService"],
            pathFragments: ["Jamf", "com.jamf", "com.jamfsoftware"],
            capabilities: ["Remote commands", "Script execution", "App install/remove", "Configuration profiles", "Inventory", "Remote lock/wipe"]
        ),
        KnownTool(
            name: "Kandji", vendor: "Kandji", category: .mdm,
            processNames: ["kandji-daemon", "KandjiAgent"],
            pathFragments: ["kandji", "io.kandji"],
            capabilities: ["MDM commands", "Script execution", "App deployment", "Auto-remediation", "Device compliance"]
        ),
        KnownTool(
            name: "Mosyle", vendor: "Mosyle", category: .mdm,
            processNames: ["MosyleAgent", "MosyleFuse"],
            pathFragments: ["Mosyle", "com.mosyle"],
            capabilities: ["MDM commands", "Script execution", "App deployment", "Remote lock/wipe"]
        ),
        KnownTool(
            name: "Hexnode", vendor: "Mitsogo", category: .mdm,
            processNames: ["HexnodeAgent", "HexnodeMDM"],
            pathFragments: ["Hexnode", "com.hexnode"],
            capabilities: ["MDM commands", "Remote lock/wipe", "Kiosk mode", "Geofencing", "App management"]
        ),
        KnownTool(
            name: "Absolute (Computrace)", vendor: "Absolute", category: .mdm,
            processNames: ["rpcnet", "absolute-agent"],
            pathFragments: ["Absolute", "com.absolute"],
            capabilities: ["Persistence (firmware-level)", "Remote lock/wipe", "Geolocation", "Data delete", "Device freeze"]
        ),
        KnownTool(
            name: "Addigy", vendor: "Addigy", category: .mdm,
            processNames: ["addigy-agent", "AddigyAgent"],
            pathFragments: ["Addigy", "com.addigy"],
            capabilities: ["MDM commands", "Live terminal", "Script execution", "Software deployment"]
        ),

        // === REMOTE ACCESS ===
        KnownTool(
            name: "TeamViewer", vendor: "TeamViewer", category: .remoteAccess,
            processNames: ["TeamViewer", "teamviewerd", "TeamViewer_Service"],
            pathFragments: ["TeamViewer", "com.teamviewer"],
            capabilities: ["Remote desktop", "File transfer", "Remote printing", "VPN", "Wake-on-LAN"]
        ),
        KnownTool(
            name: "AnyDesk", vendor: "AnyDesk", category: .remoteAccess,
            processNames: ["AnyDesk", "anydesk"],
            pathFragments: ["AnyDesk", "com.anydesk"],
            capabilities: ["Remote desktop", "File transfer", "Unattended access", "Session recording"]
        ),
        KnownTool(
            name: "ConnectWise ScreenConnect", vendor: "ConnectWise", category: .remoteAccess,
            processNames: ["ScreenConnect", "ConnectWiseControl"],
            pathFragments: ["ScreenConnect", "ConnectWise"],
            capabilities: ["Remote desktop", "File transfer", "Command line", "Unattended access", "Backstage mode"]
        ),
        KnownTool(
            name: "Splashtop", vendor: "Splashtop", category: .remoteAccess,
            processNames: ["SplashtopStreamer", "Splashtop"],
            pathFragments: ["Splashtop", "com.splashtop"],
            capabilities: ["Remote desktop", "File transfer", "Remote sound", "Unattended access"]
        ),
        KnownTool(
            name: "BeyondTrust/Bomgar", vendor: "BeyondTrust", category: .remoteAccess,
            processNames: ["bomgar-scc", "BeyondTrustJumpClient"],
            pathFragments: ["Bomgar", "BeyondTrust"],
            capabilities: ["Remote desktop", "Privileged access", "Session recording", "Command shell"]
        ),
    ]

    private struct KnownTool {
        let name: String
        let vendor: String
        let category: ToolCategory
        let processNames: [String]
        let pathFragments: [String]
        let capabilities: [String]
    }

    // MARK: - Init

    public init(pollInterval: TimeInterval = 120) {
        self.pollInterval = pollInterval
        var capturedContinuation: AsyncStream<EDRDiscovery>.Continuation!
        self._events = AsyncStream { c in
            capturedContinuation = c
        }
        self.continuation = capturedContinuation
    }

    // MARK: - Public API

    /// AsyncStream of EDR/RMM tool discoveries.
    public nonisolated var events: AsyncStream<EDRDiscovery> {
        _events
    }

    /// Start periodic scanning.
    public func start() {
        guard scanTask == nil else { return }
        logger.info("EDR monitor starting (scan every \(self.pollInterval)s)")

        scanTask = Task { [weak self] in
            // Initial scan immediately
            await self?.scan()

            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: UInt64((self?.pollInterval ?? 120) * 1_000_000_000))
                guard !Task.isCancelled else { break }
                await self?.scan()
            }
        }
    }

    /// Stop scanning.
    public func stop() {
        scanTask?.cancel()
        scanTask = nil
        continuation?.finish()
    }

    /// Get a snapshot of all currently detected tools.
    public func detectedTools() -> [EDRDiscovery] {
        // Scan running processes synchronously
        var results: [EDRDiscovery] = []
        let runningProcesses = getRunningProcesses()

        for tool in Self.knownTools {
            if let match = matchTool(tool, against: runningProcesses) {
                results.append(match)
            }
        }

        // Also check installed LaunchDaemons/LaunchAgents
        let installedTools = scanInstalledTools()
        results.append(contentsOf: installedTools)

        return results
    }

    // MARK: - Scanning

    private func scan() {
        let runningProcesses = getRunningProcesses()

        for tool in Self.knownTools {
            if let discovery = matchTool(tool, against: runningProcesses) {
                let key = "\(tool.name):\(discovery.processName ?? "installed")"
                if !reportedTools.contains(key) {
                    reportedTools.insert(key)
                    continuation?.yield(discovery)
                    logger.info("EDR tool detected: \(tool.name) (\(tool.vendor)) — \(tool.category.rawValue)")
                }
            }
        }

        // Check LaunchDaemons/LaunchAgents for installed (not necessarily running) tools
        for discovery in scanInstalledTools() {
            let key = "\(discovery.toolName):installed:\(discovery.installedPath ?? "")"
            if !reportedTools.contains(key) {
                reportedTools.insert(key)
                continuation?.yield(discovery)
                logger.info("EDR tool installed: \(discovery.toolName) (\(discovery.vendor)) at \(discovery.installedPath ?? "unknown")")
            }
        }
    }

    private func matchTool(_ tool: KnownTool, against processes: [(name: String, path: String, pid: Int32)]) -> EDRDiscovery? {
        for proc in processes {
            for toolProcess in tool.processNames {
                if proc.name == toolProcess || proc.path.hasSuffix("/\(toolProcess)") {
                    return EDRDiscovery(
                        toolName: tool.name, vendor: tool.vendor,
                        category: tool.category, capabilities: tool.capabilities,
                        processName: proc.name, processPath: proc.path,
                        pid: proc.pid
                    )
                }
            }
            // Check path fragments for tools that don't have exact process name matches
            for fragment in tool.pathFragments {
                if proc.path.contains(fragment) && !tool.processNames.contains(proc.name) {
                    return EDRDiscovery(
                        toolName: tool.name, vendor: tool.vendor,
                        category: tool.category, capabilities: tool.capabilities,
                        processName: proc.name, processPath: proc.path,
                        pid: proc.pid
                    )
                }
            }
        }
        return nil
    }

    /// Scan LaunchDaemons and LaunchAgents for known tool plists.
    private func scanInstalledTools() -> [EDRDiscovery] {
        var results: [EDRDiscovery] = []
        let plistDirs = [
            "/Library/LaunchDaemons",
            "/Library/LaunchAgents",
            NSHomeDirectory() + "/Library/LaunchAgents",
        ]
        let fm = FileManager.default

        for dir in plistDirs {
            guard let files = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for file in files where file.hasSuffix(".plist") {
                let fileLower = file.lowercased()
                for tool in Self.knownTools {
                    for fragment in tool.pathFragments {
                        if fileLower.contains(fragment.lowercased()) {
                            let fullPath = dir + "/" + file
                            // Only report if not already found as a running process
                            if !reportedTools.contains("\(tool.name):") {
                                results.append(EDRDiscovery(
                                    toolName: tool.name, vendor: tool.vendor,
                                    category: tool.category, capabilities: tool.capabilities,
                                    installedPath: fullPath
                                ))
                            }
                            break
                        }
                    }
                }
            }
        }
        return results
    }

    /// Get all running processes using sysctl.
    private nonisolated func getRunningProcesses() -> [(name: String, path: String, pid: Int32)] {
        var results: [(String, String, Int32)] = []
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL]
        var size: Int = 0

        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 0 else { return [] }

        let count = size / MemoryLayout<kinfo_proc>.stride
        var procs = [kinfo_proc](repeating: kinfo_proc(), count: count)
        guard sysctl(&mib, 3, &procs, &size, nil, 0) == 0 else { return [] }

        let actualCount = size / MemoryLayout<kinfo_proc>.stride
        for i in 0..<actualCount {
            let pid = procs[i].kp_proc.p_pid
            let name = withUnsafePointer(to: procs[i].kp_proc.p_comm) { ptr in
                String(cString: UnsafeRawPointer(ptr).assumingMemoryBound(to: CChar.self))
            }

            // Get full path via proc_pidpath
            var pathBuffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
            let pathLen = proc_pidpath(pid, &pathBuffer, UInt32(MAXPATHLEN))
            let path = pathLen > 0 ? String(cString: pathBuffer) : ""

            results.append((name, path, pid))
        }
        return results
    }
}
