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
await DaemonBootstrap.runForever(printBanner: false)
