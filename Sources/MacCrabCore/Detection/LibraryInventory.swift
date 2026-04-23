// LibraryInventory.swift
// MacCrabCore
//
// Scans process memory regions to enumerate loaded libraries via
// PROC_PIDREGIONPATHINFO. Detects injected dylibs that bypass
// DYLD_INSERT_LIBRARIES detection by checking library paths against
// known system locations and flagging suspicious loads.

import Foundation
import Darwin
import Security
import os.log

/// Scans process memory regions to enumerate loaded libraries.
/// Detects injected dylibs that bypass DYLD_INSERT_LIBRARIES detection.
public actor LibraryInventory {
    private let logger = Logger(subsystem: "com.maccrab.detection", category: "library-inventory")

    /// Library paths expected in most processes. Covers the macOS system
    /// libraries AND the common third-party package-manager roots (Homebrew,
    /// MacPorts) so that legitimately installed tools like postgres don't
    /// generate false-positive "injected library" alerts for every Kerberos /
    /// ICU / OpenSSL dylib they link against.
    private static let systemLibPrefixes: [String] = [
        "/System/",
        "/usr/lib/",
        "/usr/libexec/",
        "/Library/Apple/",
        "/usr/local/lib/libSystem",
        // Homebrew (Apple Silicon default prefix).
        "/opt/homebrew/",
        // Homebrew (Intel default prefix) + legacy /usr/local installs.
        "/usr/local/Cellar/",
        "/usr/local/opt/",
        "/usr/local/Homebrew/",
        "/usr/local/lib/",
        // MacPorts.
        "/opt/local/",
        // Nix.
        "/nix/store/",
    ]

    /// Suspicious library locations. These are world-writable or user-writable
    /// directories that should never be the source of a loaded dylib on a
    /// healthy system.
    private static let suspiciousPathPatterns: [String] = [
        "/tmp/",
        "/private/tmp/",
        "/Users/Shared/",
        "/Downloads/",
        "/var/tmp/",
    ]

    /// Processes whose loaded-library inventory should be skipped entirely.
    /// These are legitimately loading unsigned dylibs as part of their normal
    /// job description (debuggers loading user-compiled symbols, interpreter
    /// JIT loaders, etc.). Flagging them generates noise with zero signal.
    ///
    /// Field dogfooding showed this collector producing 19 alerts/day on a
    /// quiet machine, 100% of them on `lldb-rpc-server` loading a user's
    /// `.debug.dylib` — a completely normal Xcode workflow.
    private static let processAllowlist: [String] = [
        // Xcode: LLDB RPC server loads the user's compiled .debug.dylib
        // symbols for every active debug session.
        "lldb-rpc-server",
        "lldb",
        "debugserver",
        // Instruments probes load user-compiled dylibs for profiling.
        "Instruments",
        "RemoteTestRunner",
        // App extensions, XPC helpers, and test runners routinely load
        // dylibs from their containing app bundle — but sometimes those
        // paths resolve outside the bundle via symlink, and the bundle
        // walker in `scanProcess` can't follow every case.
        "xctest",
        "XCTRunner",
    ]

    /// Library path suffixes / substrings that indicate build-system or
    /// debug-symbol output rather than a genuine runtime dependency. These
    /// never represent an injection attack — they're the output of `xcodebuild`,
    /// `swift build`, `cargo`, etc.
    private static let buildArtifactPatterns: [String] = [
        ".debug.dylib",      // Xcode debug symbol libraries
        "/DerivedData/",     // Xcode per-project build output
        "/Build/Products/",  // Xcode build products
        "/.build/debug/",    // SwiftPM debug output
        "/.build/release/",  // SwiftPM release output
        "/target/debug/",    // Cargo debug output
        "/target/release/",  // Cargo release output
    ]

    /// Already-alerted (pid, library) pairs within this daemon lifetime.
    /// The forensic scan repeats every 5 minutes and the AlertDeduplicator
    /// only gates repeats on identical `ruleId+processPath` — but a single
    /// process legitimately loads the same user-compiled dylib across many
    /// scans, so ruleId+processPath alone can let the same alert through
    /// the dedup on the emission side too. Tracking (pid, library) here
    /// guarantees at-most-one alert per running process per library per
    /// lifetime, regardless of dedup window.
    private var alertedPairs: Set<String> = []
    private let alertedPairsLimit = 5000

    /// Signature cache: many processes load the same few dozen dylibs, so we
    /// cache the "is this library signed by a trusted authority" verdict per
    /// path to avoid re-running `SecStaticCodeCheckValidity` on every scan.
    private var signatureCache: [String: Bool] = [:]
    private let signatureCacheLimit = 4096

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

        // Skip system processes — these legitimately load dylibs in unusual
        // places as part of macOS internal plumbing.
        if processPath.hasPrefix("/System/") || processPath.hasPrefix("/usr/libexec/") {
            return []
        }

        // Skip allowlisted processes (Xcode debugger, XCTest runners, etc.).
        // These legitimately load user-compiled, unsigned dylibs — flagging
        // them produces pure noise with zero attack signal.
        if Self.processAllowlist.contains(processName) {
            return []
        }

        // Skip processes whose executable lives under /Applications/Xcode.app/.
        // Xcode-embedded binaries (xctest, xcrun, swift-testing, etc.) load
        // user build artifacts from DerivedData as part of normal operation.
        if processPath.hasPrefix("/Applications/Xcode.app/") {
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
            // Skip libraries from the same app bundle (including nested .app helpers).
            // Use the outermost .app/ to catch frameworks within the bundle.
            if let appDir = processPath.range(of: ".app/") {
                let appBundle = String(processPath[processPath.startIndex..<appDir.upperBound])
                if lib.hasPrefix(appBundle) { continue }
            }
            // Also check if the library and process share a common .app parent
            // (e.g., Chrome Helper loading dylibs from Google Chrome.app/Frameworks/)
            if let libAppDir = lib.range(of: ".app/"),
               let procAppDir = processPath.range(of: ".app/") {
                let libApp = String(lib[lib.startIndex..<libAppDir.upperBound])
                let procApp = String(processPath[processPath.startIndex..<procAppDir.upperBound])
                if libApp == procApp { continue }
                // Same parent directory (e.g., both under /Applications/)
                if (libApp as NSString).deletingLastPathComponent ==
                   (procApp as NSString).deletingLastPathComponent { continue }
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

            // Skip build-system output (debug symbols, DerivedData, cargo
            // target/, SwiftPM .build/). These are routinely unsigned but
            // are produced by the user's compiler, not an attacker.
            if Self.buildArtifactPatterns.contains(where: { lib.contains($0) }) {
                continue
            }

            // Any dylib outside the system/package-manager prefixes is only
            // flagged if it lacks a trusted (Apple or Developer ID) signature.
            // Legitimately signed third-party libraries in unusual locations
            // (e.g. a Developer ID-signed app shipping a dylib under
            // /Applications/MyApp.app/../PlugIns/) produce far more noise
            // than signal, so we require the loader to be both off-prefix
            // AND unsigned/ad-hoc before emitting an alert.
            if lib.hasSuffix(".dylib") &&
                !lib.hasPrefix("/usr/") &&
                !lib.hasPrefix("/System/") &&
                !lib.hasPrefix("/Library/") {
                if !isTrustedSigned(path: lib) {
                    // Pair-dedup: don't re-emit the same (pid, library) alert
                    // across forensic scan cycles. Complements the process-
                    // level AlertDeduplicator which keys only on ruleId +
                    // processPath and would let a per-scan reload of the
                    // same dylib through.
                    let pairKey = "\(pid):\(lib)"
                    if alertedPairs.contains(pairKey) { continue }
                    if alertedPairs.count >= alertedPairsLimit {
                        // Drop oldest half. O(n); cheap because we cap at 5k.
                        alertedPairs.removeAll(keepingCapacity: true)
                    }
                    alertedPairs.insert(pairKey)
                    injected.append(InjectedLibrary(
                        pid: pid, processName: processName, processPath: processPath,
                        libraryPath: lib,
                        reason: "Unsigned dylib loaded from unexpected location",
                        severity: .high
                    ))
                }
            }
        }

        return injected
    }

    /// Returns `true` when the library at `path` is validly signed by Apple,
    /// the Mac App Store, or a Developer ID certificate. Results are cached
    /// per-path to avoid repeated Security framework calls for the same dylib.
    private func isTrustedSigned(path: String) -> Bool {
        if let cached = signatureCache[path] { return cached }

        let url = URL(fileURLWithPath: path) as CFURL
        var staticCodeRef: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url, [], &staticCodeRef) == errSecSuccess,
              let staticCode = staticCodeRef else {
            storeSignatureResult(path: path, trusted: false)
            return false
        }

        let validityFlags = SecCSFlags(rawValue: kSecCSCheckAllArchitectures)
        guard SecStaticCodeCheckValidity(staticCode, validityFlags, nil) == errSecSuccess else {
            storeSignatureResult(path: path, trusted: false)
            return false
        }

        // "anchor apple generic" is satisfied by Apple first-party, Mac App
        // Store, and Developer ID signatures — exactly the set of authorities
        // we trust for loaded libraries.
        var requirementRef: SecRequirement?
        guard SecRequirementCreateWithString(
            "anchor apple generic" as CFString, [], &requirementRef
        ) == errSecSuccess, let requirement = requirementRef else {
            storeSignatureResult(path: path, trusted: false)
            return false
        }

        let trusted = SecStaticCodeCheckValidity(
            staticCode, validityFlags, requirement
        ) == errSecSuccess
        storeSignatureResult(path: path, trusted: trusted)
        return trusted
    }

    private func storeSignatureResult(path: String, trusted: Bool) {
        if signatureCache.count >= signatureCacheLimit {
            signatureCache.removeAll(keepingCapacity: true)
        }
        signatureCache[path] = trusted
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
