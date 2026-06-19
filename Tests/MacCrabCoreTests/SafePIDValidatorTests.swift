// SafePIDValidatorTests.swift
// MacCrabCoreTests

import Testing
import Foundation
import Darwin
@testable import MacCrabCore

@Suite("SafePIDValidator")
struct SafePIDValidatorTests {

    @Test("Rejects PID 1 (launchd)")
    func rejectsLaunchd() {
        #expect(SafePIDValidator.isSafeToKill(pid: 1) == false)
        let reason = SafePIDValidator.reasonToReject(pid: 1)
        #expect(reason != nil)
        #expect(reason?.contains("reserved") == true)
    }

    @Test("Rejects PID 0 (kernel)")
    func rejectsKernel() {
        #expect(SafePIDValidator.isSafeToKill(pid: 0) == false)
        #expect(SafePIDValidator.reasonToReject(pid: 0)?.contains("reserved") == true)
    }

    @Test("Rejects negative PID")
    func rejectsNegativePID() {
        #expect(SafePIDValidator.isSafeToKill(pid: -1) == false)
        #expect(SafePIDValidator.isSafeToKill(pid: -100) == false)
    }

    @Test("Rejects MacCrab's own PID")
    func rejectsSelf() {
        let myPid = getpid()
        #expect(SafePIDValidator.isSafeToKill(pid: myPid) == false)
        let reason = SafePIDValidator.reasonToReject(pid: myPid)
        #expect(reason?.contains("MacCrab itself") == true)
    }

    @Test("Critical name list covers kernel, login chain, auth, and self")
    func criticalListCoversEssentials() {
        let critical = SafePIDValidator.criticalProcessNames
        // Kernel + init
        #expect(critical.contains("kernel_task"))
        #expect(critical.contains("launchd"))
        // Login chain
        #expect(critical.contains("WindowServer"))
        #expect(critical.contains("loginwindow"))
        // Auth & keychain
        #expect(critical.contains("securityd"))
        #expect(critical.contains("opendirectoryd"))
        #expect(critical.contains("trustd"))
        // Network/config
        #expect(critical.contains("configd"))
        #expect(critical.contains("mDNSResponder"))
        // MacCrab self-targets
        #expect(critical.contains("maccrabd"))
        #expect(critical.contains("com.maccrab.agent"))
        #expect(critical.contains("MacCrab"))
        #expect(critical.contains("maccrabctl"))
    }

    @Test("Protected path prefixes cover Apple system locations")
    func protectedPathsCovered() {
        let prefixes = SafePIDValidator.protectedPathPrefixes
        #expect(prefixes.contains("/System/"))
        #expect(prefixes.contains("/usr/libexec/"))
        #expect(prefixes.contains("/sbin/"))
        #expect(prefixes.contains("/usr/sbin/"))
    }

    @Test("Rejects unresolvable PID (process gone or permission denied)")
    func rejectsUnresolvablePID() {
        // PID 999999 is virtually guaranteed to not exist on a normal system.
        // proc_pidpath returns 0 → validator rejects defensively.
        let reason = SafePIDValidator.reasonToReject(pid: 999_999)
        #expect(reason != nil)
        #expect(reason?.contains("cannot be resolved") == true)
    }

    @Test("Rejects PID 1 by reason structure (no path lookup needed)")
    func rejectsPID1WithoutPathLookup() {
        // PID 1 should be rejected at the pid <= 1 check before any
        // proc_pidpath call. Verify the reason mentions the reserved-PID
        // condition, not the path-resolution failure.
        let reason = SafePIDValidator.reasonToReject(pid: 1)
        #expect(reason?.contains("reserved") == true)
        #expect(reason?.contains("cannot be resolved") == false)
    }

    @Test("Accepts a transient child process running from /bin/")
    func acceptsTransientChildFromBin() async throws {
        // Spawn a sleep process from /bin/ — not in protected paths,
        // basename "sleep" not in critical list, so should be safe to kill.
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/bin/sleep")
        proc.arguments = ["30"]
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = FileHandle.nullDevice
        try proc.run()
        defer {
            if proc.isRunning { proc.terminate() }
        }
        let pid = proc.processIdentifier
        // Synchronize on the child actually being resolvable before asserting.
        // Under CI CPU saturation a fixed sleep can fire before the kernel has
        // the child's path (proc_pidpath returns 0) — poll with a bounded
        // budget (~2s) instead. `/bin/sleep 30` outlives this window comfortably.
        for _ in 0..<40 {
            if proc.isRunning,
               SafePIDValidator.reasonToReject(pid: pid)?.contains("cannot be resolved") != true {
                break
            }
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        // The child must still be alive for this assertion to be meaningful.
        try #require(proc.isRunning, "spawned /bin/sleep exited before validation")

        #expect(SafePIDValidator.isSafeToKill(pid: pid) == true)
        #expect(SafePIDValidator.reasonToReject(pid: pid) == nil)
    }
}
