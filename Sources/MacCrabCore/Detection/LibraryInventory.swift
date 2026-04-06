// LibraryInventory.swift
// MacCrabCore
//
// Scans process memory regions to enumerate loaded libraries via
// PROC_PIDREGIONPATHINFO. Detects injected dylibs that bypass
// DYLD_INSERT_LIBRARIES detection by checking library paths against
// known system locations and flagging suspicious loads.

import Foundation
import Darwin
import os.log

/// Scans process memory regions to enumerate loaded libraries.
/// Detects injected dylibs that bypass DYLD_INSERT_LIBRARIES detection.
public actor LibraryInventory {
    private let logger = Logger(subsystem: "com.maccrab.detection", category: "library-inventory")

    /// Known legitimate library paths that are expected in most processes.
    private static let systemLibPrefixes: [String] = [
        "/System/Library/",
        "/usr/lib/",
        "/Library/Apple/",
        "/usr/local/lib/libSystem",
    ]

    /// Suspicious library locations.
    private static let suspiciousPathPatterns: [String] = [
        "/tmp/",
        "/private/tmp/",
        "/Users/Shared/",
        "/Downloads/",
        "/var/tmp/",
    ]

    public struct InjectedLibrary: Sendable {
        public let pid: Int32
        public let processName: String
        public let processPath: String
        public let libraryPath: String
        public let reason: String
        public let severity: Severity
    }

    public init() {}

    /// Scan a specific process for injected libraries.
    public func scanProcess(pid: Int32) -> [InjectedLibrary] {
        let libraries = getLoadedLibraries(pid: pid)
        guard !libraries.isEmpty else { return [] }

        let processPath = getProcessPath(pid: pid)
        let processName = (processPath as NSString).lastPathComponent

        // Skip system processes
        if processPath.hasPrefix("/System/") || processPath.hasPrefix("/usr/libexec/") {
            return []
        }

        var injected: [InjectedLibrary] = []

        for lib in libraries {
            // Skip known system libraries
            if Self.systemLibPrefixes.contains(where: { lib.hasPrefix($0) }) { continue }
            // Skip the process's own executable
            if lib == processPath { continue }
            // Skip frameworks in /Library/Frameworks (legitimate)
            if lib.hasPrefix("/Library/Frameworks/") { continue }
            // Skip app bundles the process belongs to
            if let appDir = processPath.range(of: ".app/") {
                let appBundle = String(processPath[processPath.startIndex..<appDir.upperBound])
                if lib.hasPrefix(appBundle) { continue }
            }

            // Check for suspicious paths
            var flaggedSuspicious = false
            for pattern in Self.suspiciousPathPatterns {
                if lib.contains(pattern) {
                    injected.append(InjectedLibrary(
                        pid: pid, processName: processName, processPath: processPath,
                        libraryPath: lib,
                        reason: "Library loaded from suspicious location: \(pattern)",
                        severity: .critical
                    ))
                    flaggedSuspicious = true
                    break
                }
            }

            if flaggedSuspicious { continue }

            // Check for unsigned dylibs (path not in standard locations)
            if lib.hasSuffix(".dylib") &&
                !lib.hasPrefix("/usr/") &&
                !lib.hasPrefix("/System/") &&
                !lib.hasPrefix("/Library/") {
                injected.append(InjectedLibrary(
                    pid: pid, processName: processName, processPath: processPath,
                    libraryPath: lib,
                    reason: "Non-system dylib loaded from unexpected location",
                    severity: .high
                ))
            }
        }

        return injected
    }

    /// Scan all running processes for injected libraries.
    public func scanAllProcesses() -> [InjectedLibrary] {
        let count = proc_listallpids(nil, 0)
        guard count > 0 else { return [] }
        var pids = [Int32](repeating: 0, count: Int(count) + 50)
        let actual = proc_listallpids(&pids, Int32(pids.count * MemoryLayout<Int32>.size))
        guard actual > 0 else { return [] }

        var results: [InjectedLibrary] = []
        for pid in pids.prefix(Int(actual)) where pid > 0 {
            results.append(contentsOf: scanProcess(pid: pid))
        }
        return results
    }

    // MARK: - Private Helpers

    /// Get all loaded libraries for a process via PROC_PIDREGIONPATHINFO.
    private nonisolated func getLoadedLibraries(pid: Int32) -> [String] {
        var libraries: Set<String> = []
        var address: UInt64 = 0

        // Iterate memory regions — safety limit to prevent runaway loops
        for _ in 0..<10_000 {
            var regionInfo = proc_regionwithpathinfo()
            let size = proc_pidinfo(
                pid, PROC_PIDREGIONPATHINFO, address,
                &regionInfo, Int32(MemoryLayout<proc_regionwithpathinfo>.size)
            )
            guard size > 0 else { break }

            // Extract the path from vnode info
            let path = withUnsafePointer(to: regionInfo.prp_vip.vip_path) { ptr in
                ptr.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) { cstr in
                    String(cString: cstr)
                }
            }

            if !path.isEmpty {
                libraries.insert(path)
            }

            // Move to next region
            let nextAddr = regionInfo.prp_prinfo.pri_address + regionInfo.prp_prinfo.pri_size
            if nextAddr <= address { break }  // No progress
            address = nextAddr
        }

        return Array(libraries)
    }

    private nonisolated func getProcessPath(pid: Int32) -> String {
        var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        let result = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard result > 0 else { return "" }
        return String(cString: buffer)
    }
}
