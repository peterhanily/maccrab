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
    private var workerTask: Task<Void, Never>?
    private var workerControl: FSEventsWorkerControl?
    private var lifecyclePhase: CollectorLifecyclePhase = .initialized
    private var lifecycleGeneration: UInt64 = 0

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
        guard lifecyclePhase == .initialized else {
            logger.warning("FSEvents start rejected after its one-shot lifecycle advanced")
            return
        }
        lifecyclePhase = .running
        lifecycleGeneration &+= 1
        let generation = lifecycleGeneration

        let paths = Self.watchedPaths.filter { FileManager.default.fileExists(atPath: $0) }
        guard !paths.isEmpty else {
            logger.warning("FSEvents: no watched paths exist")
            lifecyclePhase = .stopped
            continuation?.finish()
            continuation = nil
            return
        }

        let continuation = self.continuation!
        let logger = self.logger
        let control = FSEventsWorkerControl()
        workerControl = control

        // The worker owns creation AND teardown of every Core Foundation
        // resource. `stop()` only seals its thread-safe control token. This
        // removes the old adopt-after-create race where stop could run while
        // `self.stream` was still nil and the later actor hop resurrected a
        // leaked stream/run loop/context.
        workerTask = Task.detached(priority: .utility) { [weak self] in
            guard !control.shouldStop else {
                await self?.workerExited(generation: generation)
                return
            }
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
                Unmanaged<FSEventsCallbackInfo>.fromOpaque(info).release()
                await self?.workerExited(generation: generation)
                return
            }

            guard let runLoop = CFRunLoopGetCurrent() else {
                logger.error("FSEvents: CFRunLoopGetCurrent returned nil")
                FSEventStreamRelease(stream)
                Unmanaged<FSEventsCallbackInfo>.fromOpaque(info).release()
                await self?.workerExited(generation: generation)
                return
            }
            FSEventStreamScheduleWithRunLoop(stream, runLoop, CFRunLoopMode.defaultMode.rawValue)
            let admitted = control.install(runLoop: runLoop)
            var started = false
            if admitted, !Task.isCancelled, !control.shouldStop {
                started = FSEventStreamStart(stream)
            }
            if started {
                logger.info("FSEvents collector active — watching \(paths.count) directories")
                // Use bounded run-loop slices as a second line of defence. Even
                // if stop wins immediately before the first run call, the worker
                // observes the sealed token within 250 ms rather than blocking
                // forever on a lost CFRunLoopStop edge.
                while !Task.isCancelled, !control.shouldStop {
                    _ = CFRunLoopRunInMode(
                        CFRunLoopMode.defaultMode,
                        0.25,
                        false
                    )
                }
                FSEventStreamStop(stream)
            } else if admitted, !control.shouldStop {
                logger.error("FSEvents: failed to start event stream")
            }
            FSEventStreamInvalidate(stream)
            FSEventStreamRelease(stream)
            Unmanaged<FSEventsCallbackInfo>.fromOpaque(info).release()
            control.clear(runLoop: runLoop)
            await self?.workerExited(generation: generation)
        }
    }

    public func stop() {
        _ = beginStop()
    }

    /// Seal stream creation before waking the run loop, then join the worker
    /// that owns stream invalidation, release, and callback-context release.
    @discardableResult
    public func stopAndJoin(deadline: TimeInterval = 1.0) async -> Bool {
        let task = beginStop()
        let joined = await CollectorBoundedTaskJoin.waitForAll(
            task.map { [$0] } ?? [],
            deadline: deadline
        )
        if joined {
            workerTask = nil
            workerControl = nil
            lifecyclePhase = .stopped
            logger.info("FSEvents collector stopped cleanly")
        } else {
            logger.error("FSEvents stop deadline expired with stream worker active")
        }
        return joined
    }

    private func beginStop() -> Task<Void, Never>? {
        if lifecyclePhase == .stopped { return nil }
        lifecyclePhase = .stopping
        workerControl?.requestStop()
        let task = workerTask
        task?.cancel()
        continuation?.finish()
        continuation = nil
        return task
    }

    private func workerExited(generation: UInt64) {
        guard generation == lifecycleGeneration else { return }
        workerTask = nil
        workerControl = nil
        if lifecyclePhase == .running {
            lifecyclePhase = .stopped
            continuation?.finish()
            continuation = nil
        }
    }

    deinit {
        workerControl?.requestStop()
        workerTask?.cancel()
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

/// Crosses the actor/CFRunLoop boundary without transferring ownership of the
/// stream itself. The worker remains the sole releaser; shutdown can only seal
/// admission and wake/stop the currently-published run loop.
final class FSEventsWorkerControl: @unchecked Sendable {
    private let lock = NSLock()
    private var stopped = false
    private var runLoop: CFRunLoop?

    var shouldStop: Bool {
        lock.lock()
        defer { lock.unlock() }
        return stopped
    }

    func install(runLoop: CFRunLoop) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !stopped else { return false }
        self.runLoop = runLoop
        return true
    }

    func requestStop() {
        lock.lock()
        stopped = true
        let published = runLoop
        lock.unlock()
        if let published {
            CFRunLoopStop(published)
            CFRunLoopWakeUp(published)
        }
    }

    func clear(runLoop completed: CFRunLoop) {
        lock.lock()
        if let current = runLoop, current === completed {
            runLoop = nil
        }
        lock.unlock()
    }
}

private class FSEventsCallbackInfo {
    let continuation: AsyncStream<Event>.Continuation
    let logger: Logger

    init(continuation: AsyncStream<Event>.Continuation, logger: Logger) {
        self.continuation = continuation
        self.logger = logger
    }
}
