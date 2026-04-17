import Foundation
import Darwin
import MacCrabCore
import MacCrabAgentKit
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

    // Clean environment: only pass PATH and HOME (don't leak API keys etc.)
    let path = ProcessInfo.processInfo.environment["PATH"] ?? "/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin"
    let home = ProcessInfo.processInfo.environment["HOME"] ?? "/var/root"
    let envPath = strdup("PATH=\(path)")!
    let envHome = strdup("HOME=\(home)")!
    let cEnv: [UnsafeMutablePointer<CChar>?] = [envPath, envHome, nil]

    let result = cArgs.withUnsafeBufferPointer { argBuf in
        cEnv.withUnsafeBufferPointer { envBuf in
            posix_spawn(&pid, resolvedPath, &fileActions, nil,
                        UnsafeMutablePointer(mutating: argBuf.baseAddress!),
                        UnsafeMutablePointer(mutating: envBuf.baseAddress!))
        }
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

// LaunchDaemon / manual-invocation entry point. The actual daemon
// bootstrap (component wiring, timers, event loop) lives in
// DaemonBootstrap so the MacCrabAgent system extension target can
// share identical behaviour without maintaining a parallel copy.
await DaemonBootstrap.runForever(printBanner: true)
