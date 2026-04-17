// main.swift — MacCrab Endpoint Security system extension.
//
// Phase 1 scaffold: the extension bundle compiles and registers itself
// with sysextd but does not yet take over from Sources/maccrabd/main.swift.
// Phase 2 ports the DaemonSetup/EventLoop/MonitorTasks bootstrap into
// this target; Phase 3 wires XPC.
//
// The Mach-O at MacCrab.app/Contents/Library/SystemExtensions/
// com.maccrab.agent.systemextension/Contents/MacOS/com.maccrab.agent is
// launched by sysextd (not launchd) after the user approves the
// extension in System Settings. That launch context is what makes
// com.apple.developer.endpoint-security.client legal — see the research
// notes in CHANGELOG 1.3.0.

import Foundation
import os.log

// The standard pattern for a system extension is to create the ES
// client, then run the main dispatch loop forever. sysextd owns the
// process lifecycle — we don't fork, we don't detach, we don't write a
// pidfile.

let logger = Logger(subsystem: "com.maccrab.agent", category: "bootstrap")

logger.notice("MacCrab Endpoint Security extension starting")
print("[MacCrabAgent] Phase 1 scaffold — awaiting Phase 2 DaemonSetup port")

// TODO(Phase 2): import MacCrabCore, create DaemonState, run EventLoop
// TODO(Phase 3): register NSXPCListener on com.maccrab.agent Mach service

// sysextd expects us to stay alive. Block indefinitely.
RunLoop.main.run()
