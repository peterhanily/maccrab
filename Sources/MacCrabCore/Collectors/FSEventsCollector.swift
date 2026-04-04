// FSEventsCollector.swift
// MacCrabCore
//
// Fallback file system monitor using FSEvents framework.
// Works WITHOUT root — provides file event coverage when ES is unavailable.
// Watches persistence directories for file creation/modification/deletion.

import Foundation
import os.log

/// File system change monitor using FSEvents (no root required).
///
/// Monitors critical persistence and configuration directories for changes.
/// Intended as a fallback when Endpoint Security is not available (non-root).
/// Provides file-level granularity via kFSEventStreamCreateFlagFileEvents.
public actor FSEventsCollector {

    private let logger = Logger(subsystem: "com.maccrab", category: "fsevents")

    public nonisolated let events: AsyncStream<Event>
    private var continuation: AsyncStream<Event>.Continuation?
    private var stream: FSEventStreamRef?
    private var isRunning = false

    /// Directories to watch for security-relevant file changes.
    private static let watchedPaths: [String] = [
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
        NSHomeDirectory() + "/Library/LaunchAgents",
        "/Library/Security/SecurityAgentPlugins",
        "/Library/DirectoryServices/PlugIns",
        "/Library/Spotlight",
        NSHomeDirectory() + "/Library/Spotlight",
        "/etc/periodic",
        "/private/var/at/tabs",
        "/Library/StartupItems",
        NSHomeDirectory() + "/Library/Application Support",
    ]

    // MARK: - Initialization

    public init() {
        var capturedContinuation: AsyncStream<Event>.Continuation!
        self.events = AsyncStream<Event>(bufferingPolicy: .bufferingNewest(256)) { continuation in
            capturedContinuation = continuation
        }
        self.continuation = capturedContinuation
    }

    // MARK: - Lifecycle

    public func start() {
        guard !isRunning else { return }
        isRunning = true

        let paths = Self.watchedPaths.filter { FileManager.default.fileExists(atPath: $0) }
        guard !paths.isEmpty else {
            logger.warning("FSEvents: no watched paths exist")
            return
        }

        let continuation = self.continuation!
        let logger = self.logger

        // FSEventStream must be created and scheduled on a specific thread
        DispatchQueue.global(qos: .utility).async {
            let pathsCF = paths as CFArray

            var context = FSEventStreamContext()

            // Store continuation pointer for the callback
            let info = Unmanaged.passRetained(FSEventsCallbackInfo(
                continuation: continuation,
                logger: logger
            )).toOpaque()
            context.info = info

            guard let stream = FSEventStreamCreate(
                nil,
                Self.fsEventsCallback,
                &context,
                pathsCF,
                FSEventStreamEventId(kFSEventStreamEventIdSinceNow),
                1.0,  // 1-second latency
                UInt32(
                    kFSEventStreamCreateFlagFileEvents |
                    kFSEventStreamCreateFlagUseCFTypes |
                    kFSEventStreamCreateFlagNoDefer
                )
            ) else {
                logger.error("FSEvents: failed to create event stream")
                return
            }

            FSEventStreamScheduleWithRunLoop(stream, CFRunLoopGetCurrent(), CFRunLoopMode.defaultMode.rawValue)
            FSEventStreamStart(stream)

            logger.info("FSEvents collector active — watching \(paths.count) directories")

            // Run the run loop to receive events
            CFRunLoopRun()
        }
    }

    public func stop() {
        isRunning = false
        if let stream = stream {
            FSEventStreamStop(stream)
            FSEventStreamInvalidate(stream)
            FSEventStreamRelease(stream)
            self.stream = nil
        }
        continuation?.finish()
    }

    // MARK: - Callback

    private static let fsEventsCallback: FSEventStreamCallback = {
        (streamRef, clientCallbackInfo, numEvents, eventPaths, eventFlags, eventIds) in

        guard let info = clientCallbackInfo else { return }
        let callbackInfo = Unmanaged<FSEventsCallbackInfo>.fromOpaque(info).takeUnretainedValue()

        guard let paths = unsafeBitCast(eventPaths, to: NSArray.self) as? [String] else { return }
        let flags = UnsafeBufferPointer(start: eventFlags, count: numEvents)

        for i in 0..<numEvents {
            let path = paths[i]
            let flag = flags[i]

            // Determine action from flags
            let action: String
            let fileAction: FileAction
            if flag & UInt32(kFSEventStreamEventFlagItemCreated) != 0 {
                action = "create"
                fileAction = .create
            } else if flag & UInt32(kFSEventStreamEventFlagItemRemoved) != 0 {
                action = "delete"
                fileAction = .delete
            } else if flag & UInt32(kFSEventStreamEventFlagItemModified) != 0 {
                action = "write"
                fileAction = .write
            } else if flag & UInt32(kFSEventStreamEventFlagItemRenamed) != 0 {
                action = "rename"
                fileAction = .rename
            } else {
                continue // Skip non-interesting flags
            }

            // Skip directories themselves (we want file events)
            if flag & UInt32(kFSEventStreamEventFlagItemIsDir) != 0 { continue }

            // Build minimal process info (FSEvents doesn't provide process attribution)
            let process = ProcessInfo(
                pid: 0, ppid: 0, rpid: 0,
                name: "unknown", executable: "",
                commandLine: "", args: [],
                workingDirectory: "/",
                userId: UInt32(getuid()), userName: NSUserName(),
                groupId: UInt32(getgid()),
                startTime: Date(),
                ancestors: [],
                isPlatformBinary: false
            )

            let file = FileInfo(path: path, action: fileAction)

            let event = Event(
                eventCategory: .file,
                eventType: fileAction == .delete ? .deletion : .creation,
                eventAction: action,
                process: process,
                file: file,
                enrichments: ["source": "fsevents"]
            )

            callbackInfo.continuation.yield(event)
        }
    }
}

// MARK: - Callback Context

private class FSEventsCallbackInfo {
    let continuation: AsyncStream<Event>.Continuation
    let logger: Logger

    init(continuation: AsyncStream<Event>.Continuation, logger: Logger) {
        self.continuation = continuation
        self.logger = logger
    }
}
