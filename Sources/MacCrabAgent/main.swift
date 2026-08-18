// main.swift — MacCrab Endpoint Security system extension.
//
// This process is launched by sysextd after the user approves the
// extension in System Settings > General > Login Items & Extensions.
// Unlike the standalone maccrabd LaunchDaemon (which AMFI rejects as
// of macOS Catalina — see research notes in CHANGELOG 1.3.0), the
// sysext launch context is the only one where
// com.apple.developer.endpoint-security.client is honoured.
//
// Lifecycle:
//   1. sysextd spawns this binary
//   2. We run the shared daemon bootstrap (DaemonSetup → EventLoop)
//   3. Phase 3 will add NSXPCListener here so MacCrabApp + maccrabctl
//      can reach the sysext without shared SQLite files
//   4. sysextd signals teardown on uninstall; event stream ends; exit

import Foundation
import os.log
import MacCrabAgentKit

// Shared bootstrap lives in the MacCrabAgentKit library target so the
// standalone `maccrabd` and this system extension compile identical
// logic from one copy; only the outermost entry point differs.
//
// v1.7.6: DaemonBootstrap.runForever writes a startup marker
// `<supportDir>/sysext_started.json` as its very first action — so
// even if storage init fails, the dashboard can distinguish "launched
// but crashed in init" (banner: "Detection database failed — click
// Recover") from "never launched" (banner: "Reactivate Extension").
//
// v1.7.7: collector hot-loops (Eslogger, UnifiedLog) now wrap each
// per-event JSON parse in autoreleasepool to drain Foundation
// autoreleased objects (NSDictionary/NSError/_NSJSONReader/NSConcreteData)
// that previously accumulated in long-running async Tasks — fixed a
// 1+ GB/hour heap growth observed in the field on v1.7.6.
// v1.21.6-rc.32: this was a bare `try await`. Any error escaping the bootstrap
// propagated out of async main as `swift_errorInMain`, which traps — so a root
// Endpoint Security extension answered a recoverable storage condition by
// dying, and sysextd relaunched it into a crash loop (five SIGTRAP reports on
// one installed rc.31 host in a single morning). The exception carried no
// reason, so the surviving evidence was an opaque `EXC_BREAKPOINT`.
//
// Failing is still correct — the startup marker written by `runForever` is what
// tells the dashboard "launched but failed in init". Failing *legibly* is the
// fix: log the classified reason, then exit non-zero so sysextd's own relaunch
// provides the retry instead of a trap.
do {
    try await DaemonBootstrap.runForever(printBanner: false)
} catch {
    Logger(subsystem: "com.maccrab.agent", category: "lifecycle").critical(
        "Daemon bootstrap failed, exiting for sysextd relaunch: \(String(describing: error), privacy: .public)"
    )
    exit(1)
}
