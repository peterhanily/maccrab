// RootkitDetector.swift
// MacCrabCore
//
// Detects hidden processes by cross-referencing two independent process
// enumeration APIs: proc_listallpids() and sysctl(KERN_PROC_ALL).
// A process visible to one but not the other indicates userland rootkit
// activity (e.g. hooking one syscall path but not the other).

import Foundation
import Darwin
import os.log

/// Detects hidden processes by cross-referencing proc_listallpids() with
/// sysctl(KERN_PROC_ALL). A process visible to one but not the other
/// indicates userland rootkit activity.
public actor RootkitDetector {
    private let logger = Logger(subsystem: "com.maccrab.detection", category: "rootkit-detector")

    public struct HiddenProcess: Sendable {
        public let pid: Int32
        public let source: String  // "proc_only" or "sysctl_only"
        public let timestamp: Date
    }

    public nonisolated let events: AsyncStream<HiddenProcess>
    private let continuation: AsyncStream<HiddenProcess>.Continuation
    private var pollTask: Task<Void, Never>?
    private let pollInterval: TimeInterval

    public init(pollInterval: TimeInterval = 60) {
        self.pollInterval = pollInterval
        var cap: AsyncStream<HiddenProcess>.Continuation!
        self.events = AsyncStream(bufferingPolicy: .bufferingNewest(32)) { cap = $0 }
        self.continuation = cap
    }

    public func start() {
        guard pollTask == nil else { return }
        let interval = pollInterval
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.scan()
                try? await Task.sleep(nanoseconds: UInt64(interval * 1_000_000_000))
            }
        }
    }

    public func stop() {
        pollTask?.cancel()
        pollTask = nil
        continuation.finish()
    }

    private func scan() async {
        // Method 1: proc_listallpids
        let procPids = getPidsViaProcList()

        // Method 2: sysctl KERN_PROC_ALL
        let sysctlPids = getPidsViaSysctl()

        // Find discrepancies
        let procOnly = procPids.subtracting(sysctlPids)
        let sysctlOnly = sysctlPids.subtracting(procPids)

        let myPid = getpid()
        let suspects = procOnly.union(sysctlOnly).filter { $0 != 0 && $0 != myPid }
        guard !suspects.isEmpty else { return }

        // The two APIs are not snapshotted atomically — we call them
        // back-to-back, so any process that exits or starts in the gap
        // between the two calls appears in one set but not the other.
        // That race was producing the bulk of `hidden-process` alerts on
        // a busy workstation (a short-lived `grep`, `git`, IDE subprocess,
        // etc.). Re-query both APIs after a short delay and only alert on
        // PIDs where the discrepancy persists. A true userland rootkit
        // hides the process for its entire lifetime; a race does not.
        try? await Task.sleep(nanoseconds: 300_000_000) // 300ms
        let verifyProc = getPidsViaProcList()
        let verifySysctl = getPidsViaSysctl()

        for pid in procOnly where suspects.contains(pid) {
            guard verifyProc.contains(pid), !verifySysctl.contains(pid) else { continue }
            let event = HiddenProcess(pid: pid, source: "proc_only", timestamp: Date())
            continuation.yield(event)
            logger.critical("Hidden process detected: PID \(pid) visible to proc_listallpids but not sysctl (verified)")
        }

        for pid in sysctlOnly where suspects.contains(pid) {
            guard verifySysctl.contains(pid), !verifyProc.contains(pid) else { continue }
            let event = HiddenProcess(pid: pid, source: "sysctl_only", timestamp: Date())
            continuation.yield(event)
            logger.critical("Hidden process detected: PID \(pid) visible to sysctl but not proc_listallpids (verified)")
        }
    }

    // MARK: - Process Enumeration

    private nonisolated func getPidsViaProcList() -> Set<Int32> {
        let count = proc_listallpids(nil, 0)
        guard count > 0 else { return [] }
        var pids = [Int32](repeating: 0, count: Int(count) + 100)
        let actual = proc_listallpids(&pids, Int32(pids.count * MemoryLayout<Int32>.size))
        guard actual > 0 else { return [] }
        return Set(pids.prefix(Int(actual)).filter { $0 > 0 })
    }

    private nonisolated func getPidsViaSysctl() -> Set<Int32> {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL]
        var size: Int = 0
        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 0 else { return [] }

        let count = size / MemoryLayout<kinfo_proc>.size
        var procs = [kinfo_proc](repeating: kinfo_proc(), count: count + 10)
        var actualSize = procs.count * MemoryLayout<kinfo_proc>.size
        guard sysctl(&mib, 3, &procs, &actualSize, nil, 0) == 0 else { return [] }

        let actualCount = actualSize / MemoryLayout<kinfo_proc>.size
        return Set(procs.prefix(actualCount).map { $0.kp_proc.p_pid }.filter { $0 > 0 })
    }
}
