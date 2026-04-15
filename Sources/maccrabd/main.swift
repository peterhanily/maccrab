import Foundation
import Darwin
import MacCrabCore
import os.log

// Disable stdout buffering so output appears immediately in log files
setbuf(stdout, nil)

// Handle --background / --bg flag: spawn daemon in background, open dashboard
let args = CommandLine.arguments
if args.contains("--background") || args.contains("--bg") || args.contains("-b") {
    // Re-spawn ourselves without --background flag as a background process
    let binaryPath = ProcessInfo.processInfo.arguments[0]
    var resolvedPath = binaryPath
    // Resolve to full path if needed
    if !binaryPath.hasPrefix("/") {
        var buf = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        if proc_pidpath(getpid(), &buf, UInt32(buf.count)) > 0 {
            resolvedPath = String(cString: buf)
        }
    }

    // Spawn daemon in background
    var pid: pid_t = 0
    let cPath = strdup(resolvedPath)!
    let cArgs: [UnsafeMutablePointer<CChar>?] = [cPath, nil]
    var fileActions: posix_spawn_file_actions_t?
    posix_spawn_file_actions_init(&fileActions)
    let supportDir = geteuid() == 0
        ? "/Library/Application Support/MacCrab"
        : (FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first?.appendingPathComponent("MacCrab").path ?? "/tmp")
    let logPath = supportDir + "/maccrabd.log"
    let errPath = supportDir + "/maccrabd.err"
    posix_spawn_file_actions_addopen(&fileActions, STDOUT_FILENO, logPath, O_WRONLY | O_CREAT | O_APPEND, 0o644)
    posix_spawn_file_actions_addopen(&fileActions, STDERR_FILENO, errPath, O_WRONLY | O_CREAT | O_APPEND, 0o644)

    let result = cArgs.withUnsafeBufferPointer { buf in
        posix_spawn(&pid, resolvedPath, &fileActions, nil,
                    UnsafeMutablePointer(mutating: buf.baseAddress!), environ)
    }
    posix_spawn_file_actions_destroy(&fileActions)
    free(cPath)

    if result == 0 {
        print("MacCrab daemon started (PID \(pid))")
        // Open dashboard
        let appPaths = [
            "/Applications/MacCrab.app",
            NSHomeDirectory() + "/Applications/MacCrab.app",
        ]
        for path in appPaths {
            if FileManager.default.fileExists(atPath: path) {
                let task = Process()
                task.executableURL = URL(fileURLWithPath: "/usr/bin/open")
                task.arguments = [path]
                try? task.run()
                break
            }
        }
    } else {
        fputs("Error: failed to start daemon (errno \(result))\n", stderr)
    }
    exit(result == 0 ? 0 : 1)
}

logger.info("MacCrab daemon starting...")

// 1. Initialize all components
let state = await DaemonSetup.initialize()

// 2. Print startup banner
await StartupBanner.print(state: state)

// 3. Install signal handlers (SIGHUP, SIGTERM, SIGINT)
let signalHandles = SignalHandlers.install(state: state)

// 4. Start background monitor tasks
MonitorTasks.start(state: state)

// 5. Start periodic timers
var eventCount: UInt64 = 0
var alertCount: UInt64 = 0
let startTime = Date()
let timerHandles = DaemonTimers.start(
    state: state,
    eventCount: { eventCount },
    alertCount: { alertCount },
    startTime: startTime
)

// 6. Merge event sources and run the main event processing loop
let eventStream = state.mergedEventStream()
await EventLoop.run(
    state: state,
    eventStream: eventStream,
    eventCount: &eventCount,
    alertCount: &alertCount
)

// Keep handles alive (prevents ARC from deallocating dispatch sources)
_ = signalHandles
_ = timerHandles
