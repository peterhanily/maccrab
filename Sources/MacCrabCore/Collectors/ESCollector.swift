// ESCollector.swift
// MacCrabCore
//
// Wraps Apple's Endpoint Security framework to collect security-relevant
// kernel events and normalise them into MacCrab `Event` objects.
//
// # Event pipeline
//
//   ES framework                                 MacCrab pipeline
//   ────────────                                 ────────────────
//   es_new_client     ──▶  ESCollector.start()
//                          │
//   es_subscribe      ──▶  │  (process exec/fork/exit, file
//                          │   create/write/rename/unlink, signal,
//                          │   kext, mmap, iokit, auth, tcc, …)
//                          │
//   kernel callback   ──▶  │  on ES serial queue:
//                          │    ESHelpers.parse(msg) → Event
//                          │    stream.yield(event)
//                          ▼
//                      AsyncStream<Event>  ──▶  EventLoop → Enricher → RuleEngine
//
// # Queueing model
//
// The ES client callback runs on a private serial queue managed by the
// framework. We copy every field we need out of the `es_message_t` on
// that thread (because the struct is reclaimed the moment the callback
// returns), then yield into a user-space `AsyncStream<Event>` consumed
// on the detection pipeline's own executor. This means no lock around
// collector state; the class opts into `@unchecked Sendable`.
//
// # Required privileges
//
//   - euid 0 (ES framework rejects non-root)
//   - `com.apple.developer.endpoint-security.client` entitlement,
//     signed by an approved provisioning profile bound to the
//     `.systemextension` bundle (AMFI rejects LaunchDaemons since
//     macOS Catalina — see UPGRADE.md)
//   - Full Disk Access to see file events for TCC-protected paths
//
// Without the entitlement, `es_new_client` returns
// `ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED`. `maccrabd`'s fallback chain
// (eslogger → kdebug → FSEvents) handles that case for developer builds.

import Foundation
import EndpointSecurity
import Darwin.POSIX
import os.log

// MARK: - ESCollectorError

/// Errors that can occur when creating or configuring the ES client.
public enum ESCollectorError: Error, CustomStringConvertible {
    /// The calling process is not running as root (euid 0).
    case notRunningAsRoot
    /// The binary does not have the required
    /// `com.apple.developer.endpoint-security.client` entitlement.
    case missingEntitlement
    /// Too many ES clients are already connected system-wide.
    case tooManyClients
    /// An unrecognised error code was returned by `es_new_client`.
    case clientCreationFailed(es_new_client_result_t)
    /// `es_subscribe` returned an error.
    case subscriptionFailed
    /// The client was already stopped or never started.
    case notRunning

    public var description: String {
        switch self {
        case .notRunningAsRoot:
            return "Endpoint Security requires root privileges (euid 0)."
        case .missingEntitlement:
            return "Binary is missing the com.apple.developer.endpoint-security.client entitlement."
        case .tooManyClients:
            return "Too many Endpoint Security clients are already connected."
        case .clientCreationFailed(let code):
            return "es_new_client failed with result code \(code.rawValue)."
        case .subscriptionFailed:
            return "es_subscribe failed — check event types."
        case .notRunning:
            return "ES client is not running."
        }
    }
}

// MARK: - ESCollector

/// Collects macOS Endpoint Security NOTIFY events and emits normalised
/// `Event` values through an `AsyncStream`.
///
/// Usage:
/// ```swift
/// let collector = try ESCollector()
/// for await event in collector.events {
///     // process event
/// }
/// ```
public final class ESCollector: @unchecked Sendable {

    // MARK: Properties

    private var client: OpaquePointer?          // es_client_t*
    private var continuation: AsyncStream<Event>.Continuation?
    private var traceBindingContinuation: AsyncStream<TraceBindingSignal>.Continuation?
    private let logger = Logger(subsystem: "com.maccrab.core", category: "ESCollector")

    /// v1.9 Agent Traces feature flag, read once at type-load. Set
    /// `MACCRAB_AGENT_TRACES=1` in the daemon's environment to enable
    /// TRACEPARENT extraction on NOTIFY_EXEC. Default-off so a v1.9
    /// daemon binary running on an older host stays bit-identical to
    /// the v1.8.1 wire path until the operator opts in.
    private static let agentTracesEnabled: Bool =
        Foundation.ProcessInfo.processInfo.environment["MACCRAB_AGENT_TRACES"] == "1"

    /// v1.9 audit Phase-1.8: shared AIToolRegistry instance reused
    /// across every NOTIFY_EXEC. AIToolRegistry's init builds a tuple
    /// of patterns; allocating one per exec at 200-500 events/sec
    /// adds avoidable allocation pressure on the ES callback queue.
    fileprivate static let sharedAIRegistry = AIToolRegistry()

    /// Public accessor for the feature flag. Tests and the dashboard
    /// status panel can read this without touching ProcessInfo themselves.
    public static var isAgentTracesEnabled: Bool { agentTracesEnabled }

    /// The asynchronous stream of normalised events.
    public let events: AsyncStream<Event>

    /// v1.9 side-channel: trace bind/evict signals derived from
    /// NOTIFY_EXEC env scans and NOTIFY_EXIT events. Empty stream when
    /// `agentTracesEnabled` is false. EventLoop owns the consumer.
    public let traceBindings: AsyncStream<TraceBindingSignal>

    // MARK: - Subscribed Event Types

    /// The set of NOTIFY event types we subscribe to.
    private static let subscribedEvents: [es_event_type_t] = [
        ES_EVENT_TYPE_NOTIFY_EXEC,
        ES_EVENT_TYPE_NOTIFY_FORK,
        ES_EVENT_TYPE_NOTIFY_EXIT,
        ES_EVENT_TYPE_NOTIFY_CREATE,
        ES_EVENT_TYPE_NOTIFY_WRITE,
        ES_EVENT_TYPE_NOTIFY_CLOSE,
        ES_EVENT_TYPE_NOTIFY_RENAME,
        ES_EVENT_TYPE_NOTIFY_UNLINK,
        ES_EVENT_TYPE_NOTIFY_SIGNAL,
        ES_EVENT_TYPE_NOTIFY_KEXTLOAD,
        ES_EVENT_TYPE_NOTIFY_MMAP,
        ES_EVENT_TYPE_NOTIFY_MPROTECT,
        ES_EVENT_TYPE_NOTIFY_SETOWNER,
        ES_EVENT_TYPE_NOTIFY_SETMODE,
    ]

    // MARK: - Noisy Path Muting

    /// Paths and prefixes that generate excessive noise and should be muted
    /// at the kernel level to reduce overhead.
    private static let mutedPaths: [String] = [
        // System binaries and frameworks
        "/System/",
        "/usr/libexec/xpcproxy",
        // Spotlight indexing
        "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework",
        "/.Spotlight-V100",
        // Time Machine
        "/System/Library/CoreServices/backupd.bundle",
        "/.MobileBackups",
        "/Volumes/com.apple.TimeMachine",
    ]

    /// Literal paths to mute (exact match).
    private static let mutedPathLiterals: [String] = [
        "/usr/libexec/xpcproxy",
        "/usr/sbin/mDNSResponder",
        "/usr/libexec/sandboxd",
        "/System/Library/CoreServices/launchservicesd",
        "/System/Library/PrivateFrameworks/SkyLight.framework/Versions/A/Resources/WindowServer",
    ]

    // MARK: - Initialisation

    /// Creates a new ES client, subscribes to events, and begins emitting
    /// `Event` values on the `events` stream.
    ///
    /// - Throws: `ESCollectorError` if the client cannot be created.
    public init() throws {
        // Build the AsyncStream and capture the continuation so the
        // ES callback can yield events into it.
        var capturedContinuation: AsyncStream<Event>.Continuation!
        self.events = AsyncStream<Event> { continuation in
            capturedContinuation = continuation
        }
        self.continuation = capturedContinuation

        // v1.9 trace bindings stream. We always create the stream — its
        // continuation is captured but only fed when the feature flag
        // is on, so consumers that don't care can iterate without
        // observing any items.
        //
        // v1.9 PR-5 audit Stability-H1: bound the buffer. Default is
        // .unbounded which can grow without limit on bursty execve
        // (package installs, builds, CI runs) if the consumer Task is
        // delayed. Newest-10K policy mirrors the merged event stream
        // in DaemonState (which uses 100K — bind/evict signals are
        // ~10× lower volume than full events, so 10K matches).
        var capturedTraceContinuation: AsyncStream<TraceBindingSignal>.Continuation!
        self.traceBindings = AsyncStream<TraceBindingSignal>(
            bufferingPolicy: .bufferingNewest(10_000)
        ) { continuation in
            capturedTraceContinuation = continuation
        }
        self.traceBindingContinuation = capturedTraceContinuation

        try createClient()
        muteNoisyPaths()
        muteSelf()
        try subscribe()

        logger.info("ESCollector initialised — subscribed to \(Self.subscribedEvents.count) event types.")
    }

    deinit {
        stop()
    }

    // MARK: - Client Lifecycle

    /// Create the `es_client_t`, mapping result codes to typed errors.
    private func createClient() throws {
        // We need a local to pass into the closure so that `self` is not
        // captured before initialisation completes.
        let continuation = self.continuation!
        let traceContinuation = self.traceBindingContinuation!
        let logger = self.logger

        var newClient: OpaquePointer?   // es_client_t*

        let result = es_new_client(&newClient) { _, message in
            // SAFETY: message memory is owned by the kernel and valid only during
            // this callback. normalise() is synchronous and copies all needed data
            // (via esStringToSwift) before the callback returns.
            //
            // v1.7.9 defensive autoreleasepool: this callback fires per ES event
            // on a kernel-managed dispatch queue. Pass 9 doesn't flag it (no
            // `while let`/`for await` shape) but the same Foundation autorelease
            // accumulation that bit Eslogger/UnifiedLog could happen here too —
            // esStringToSwift creates Strings (CFString-backed under the hood)
            // and any future enrichment that touches Foundation APIs would
            // accumulate. Wrap defensively so the discipline holds.
            autoreleasepool {
                // v1.9 Agent Traces side-channel. Computed BEFORE normalise so
                // the env-scan can lift TRACEPARENT off the live es_message_t
                // before normalise drops the env reference. Cheap no-op when
                // the feature flag is off.
                if Self.agentTracesEnabled {
                    Self.emitTraceSignals(message: message, into: traceContinuation)
                }

                let event = Self.normalise(message: message)
                if let event = event {
                    continuation.yield(event)
                } else {
                    logger.debug("Dropped unhandled ES event type: \(message.pointee.event_type.rawValue)")
                }
            }
        }

        switch result {
        case ES_NEW_CLIENT_RESULT_SUCCESS:
            self.client = newClient
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
            throw ESCollectorError.notRunningAsRoot
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
            throw ESCollectorError.missingEntitlement
        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
            throw ESCollectorError.tooManyClients
        default:
            throw ESCollectorError.clientCreationFailed(result)
        }
    }

    /// Subscribe to the configured NOTIFY event types.
    private func subscribe() throws {
        guard let client = self.client else {
            throw ESCollectorError.notRunning
        }
        let events = Self.subscribedEvents
        let result = events.withUnsafeBufferPointer { buffer -> es_return_t in
            es_subscribe(client, buffer.baseAddress!, UInt32(buffer.count))
        }
        if result != ES_RETURN_SUCCESS {
            logger.error("es_subscribe failed with code \(result.rawValue)")
            throw ESCollectorError.subscriptionFailed
        }
    }

    /// Mute noisy paths to reduce kernel-to-userspace traffic.
    private func muteNoisyPaths() {
        guard let client = self.client else { return }

        for path in Self.mutedPathLiterals {
            let rc = es_mute_path_literal(client, path)
            if rc != ES_RETURN_SUCCESS {
                logger.warning("Failed to mute path: \(path)")
            }
        }

        // For prefix-based paths we use es_mute_path_prefix when available.
        // The function was introduced alongside es_mute_path_literal.
        for path in Self.mutedPaths {
            if path.hasSuffix("/") {
                let rc = es_mute_path_prefix(client, path)
                if rc != ES_RETURN_SUCCESS {
                    logger.warning("Failed to mute path prefix: \(path)")
                }
            } else {
                let rc = es_mute_path_literal(client, path)
                if rc != ES_RETURN_SUCCESS {
                    logger.warning("Failed to mute path literal: \(path)")
                }
            }
        }
    }

    /// Mute events from our own process to avoid feedback loops.
    private func muteSelf() {
        guard let client = self.client else { return }

        let selfPath = Foundation.ProcessInfo.processInfo.arguments.first ?? CommandLine.arguments.first ?? ""
        guard !selfPath.isEmpty else { return }

        let rc = es_mute_path_literal(client, selfPath)
        if rc != ES_RETURN_SUCCESS {
            logger.warning("Failed to self-mute at path: \(selfPath)")
        }
    }

    /// Tear down the ES client and finish the event stream.
    public func stop() {
        if let client = self.client {
            es_delete_client(client)
            self.client = nil
            logger.info("ESCollector stopped — client deleted.")
        }
        continuation?.finish()
        continuation = nil
        // v1.9.0 (audit Stab-M6): finish the side-channel continuation
        // too. Pre-fix it was left dangling at SIGTERM teardown — the
        // consumer Task in DaemonSetup blocked on it forever and was
        // only cleaned up by `exit(0)`. Symmetric with the main event
        // stream above.
        traceBindingContinuation?.finish()
        traceBindingContinuation = nil
    }

    // MARK: - v1.9 Agent Traces — side-channel emission

    /// Inspect the live es_message_t for trace-binding-relevant events
    /// (NOTIFY_EXEC env scan, NOTIFY_EXIT pid eviction) and emit
    /// `TraceBindingSignal`s onto the side-channel stream.
    ///
    /// Runs only when `agentTracesEnabled == true`. Pure side-effect; the
    /// caller still runs `normalise(...)` immediately after to produce
    /// the normal Event for the detection pipeline.
    private static func emitTraceSignals(
        message: UnsafePointer<es_message_t>,
        into continuation: AsyncStream<TraceBindingSignal>.Continuation
    ) {
        let msg = message.pointee
        switch msg.event_type {
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            // Build the identity from the EXEC's *target* process — that's
            // the process that just took over via execve, and whose env
            // we want to inspect. The `msg.process` is the calling
            // process pre-exec; for execve the post-exec image is in
            // `msg.event.exec.target`.
            let target = msg.event.exec.target
            guard let context = traceContextFromExecMessage(message) else {
                return
            }
            let executablePath = esFileToPath(target.pointee.executable)
            let identity = ProcessIdentity(from: target, executablePath: executablePath)
            // Best-effort agent-tool tag from the exec'd binary path. The
            // registry stores nil tags fine; the correlator can re-derive
            // at lookup time using the same registry.
            // v1.9 audit Phase-1.8: reuse a single shared registry instance
            // instead of allocating one per NOTIFY_EXEC. The previous
            // `AIToolRegistry()` per call meant ~25 lowercased() string
            // allocations per exec at 200-500 events/sec sustained.
            let aiTool = Self.sharedAIRegistry.isAITool(executablePath: executablePath)
            let signal = TraceBindingSignal(
                kind: .bind(identity: identity, context: context, agentTool: aiTool)
            )
            continuation.yield(signal)

        case ES_EVENT_TYPE_NOTIFY_EXIT:
            // The exiting process is `msg.process`. EventLoop's consumer
            // no-ops if no binding exists for this pid.
            let exitingPid = audit_token_to_pid(msg.process.pointee.audit_token)
            continuation.yield(TraceBindingSignal(kind: .evict(pid: exitingPid)))

        default:
            break
        }
    }

    // MARK: - Event Normalisation

    /// Map a raw `es_message_t` into a MacCrab `Event`, or return `nil`
    /// if the event should be dropped (e.g. unmodified close).
    private static func normalise(message: UnsafePointer<es_message_t>) -> Event? {
        let msg = message.pointee

        // Timestamp from the Mach absolute time in the message header.
        let timestamp = Date(
            timeIntervalSince1970: TimeInterval(msg.time.tv_sec) + TimeInterval(msg.time.tv_nsec) / 1_000_000_000
        )

        // Source process
        let esProcess = msg.process
        let processInfo = processFromESProcess(esProcess)

        switch msg.event_type {

        // -----------------------------------------------------------------
        // MARK: Process Events
        // -----------------------------------------------------------------

        case ES_EVENT_TYPE_NOTIFY_EXEC:
            let execEvent = msg.event.exec
            let args = argsFromExecMessage(message)
            let commandLine = args.joined(separator: " ")

            // The target of exec is in execEvent.target — use it if available.
            let targetInfo = processFromESProcess(execEvent.target)

            // Reconstruct ProcessInfo with args and commandLine populated.
            let enrichedTarget = ProcessInfo(
                pid: targetInfo.pid,
                ppid: targetInfo.ppid,
                rpid: targetInfo.rpid,
                name: targetInfo.name,
                executable: targetInfo.executable,
                commandLine: commandLine,
                args: args,
                workingDirectory: targetInfo.workingDirectory,
                userId: targetInfo.userId,
                userName: targetInfo.userName,
                groupId: targetInfo.groupId,
                startTime: targetInfo.startTime,
                codeSignature: targetInfo.codeSignature,
                ancestors: targetInfo.ancestors,
                architecture: targetInfo.architecture,
                isPlatformBinary: targetInfo.isPlatformBinary
            )

            return Event(
                timestamp: timestamp,
                eventCategory: .process,
                eventType: .start,
                eventAction: "exec",
                process: enrichedTarget,
                severity: .informational
            )

        case ES_EVENT_TYPE_NOTIFY_FORK:
            let forkEvent = msg.event.fork
            let childInfo = processFromESProcess(forkEvent.child)
            return Event(
                timestamp: timestamp,
                eventCategory: .process,
                eventType: .start,
                eventAction: "fork",
                process: childInfo,
                severity: .informational
            )

        case ES_EVENT_TYPE_NOTIFY_EXIT:
            return Event(
                timestamp: timestamp,
                eventCategory: .process,
                eventType: .end,
                eventAction: "exit",
                process: processInfo,
                severity: .informational
            )

        // -----------------------------------------------------------------
        // MARK: File Events
        // -----------------------------------------------------------------

        case ES_EVENT_TYPE_NOTIFY_CREATE:
            let createEvent = msg.event.create
            // CREATE can be either an existing path or a new-path descriptor.
            // For the destination_type == ES_DESTINATION_TYPE_EXISTING_FILE the
            // file already has a vnode; otherwise we construct from the directory
            // + filename tokens.
            let path: String
            if createEvent.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
                path = esFileToPath(createEvent.destination.existing_file)
            } else {
                let dir = esFileToPath(createEvent.destination.new_path.dir)
                let filename = esStringToSwift(createEvent.destination.new_path.filename)
                path = dir.hasSuffix("/") ? dir + filename : dir + "/" + filename
            }

            let fileInfo = FileInfo(
                path: path,
                action: .create
            )
            return Event(
                timestamp: timestamp,
                eventCategory: .file,
                eventType: .creation,
                eventAction: "create",
                process: processInfo,
                file: fileInfo,
                severity: .informational
            )

        case ES_EVENT_TYPE_NOTIFY_WRITE:
            let writeEvent = msg.event.write
            let path = esFileToPath(writeEvent.target)
            let fileInfo = FileInfo(
                path: path,
                action: .write
            )
            return Event(
                timestamp: timestamp,
                eventCategory: .file,
                eventType: .change,
                eventAction: "write",
                process: processInfo,
                file: fileInfo,
                severity: .informational
            )

        case ES_EVENT_TYPE_NOTIFY_CLOSE:
            let closeEvent = msg.event.close
            // Only emit events for files that were actually modified.
            guard closeEvent.modified else { return nil }
            let path = esFileToPath(closeEvent.target)
            let fileInfo = FileInfo(
                path: path,
                action: .close
            )
            return Event(
                timestamp: timestamp,
                eventCategory: .file,
                eventType: .change,
                eventAction: "close_modified",
                process: processInfo,
                file: fileInfo,
                severity: .informational
            )

        case ES_EVENT_TYPE_NOTIFY_RENAME:
            let renameEvent = msg.event.rename
            let sourcePath = esFileToPath(renameEvent.source)

            // Destination depends on destination_type.
            let destPath: String
            if renameEvent.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
                destPath = esFileToPath(renameEvent.destination.existing_file)
            } else {
                let dir = esFileToPath(renameEvent.destination.new_path.dir)
                let filename = esStringToSwift(renameEvent.destination.new_path.filename)
                destPath = dir.hasSuffix("/") ? dir + filename : dir + "/" + filename
            }

            let fileInfo = FileInfo(
                path: destPath,
                action: .rename,
                sourcePath: sourcePath
            )
            return Event(
                timestamp: timestamp,
                eventCategory: .file,
                eventType: .change,
                eventAction: "rename",
                process: processInfo,
                file: fileInfo,
                severity: .informational
            )

        case ES_EVENT_TYPE_NOTIFY_UNLINK:
            let unlinkEvent = msg.event.unlink
            let path = esFileToPath(unlinkEvent.target)
            let fileInfo = FileInfo(
                path: path,
                action: .delete
            )
            return Event(
                timestamp: timestamp,
                eventCategory: .file,
                eventType: .deletion,
                eventAction: "unlink",
                process: processInfo,
                file: fileInfo,
                severity: .informational
            )

        // -----------------------------------------------------------------
        // MARK: Signal Events
        // -----------------------------------------------------------------

        case ES_EVENT_TYPE_NOTIFY_SIGNAL:
            let signalEvent = msg.event.signal
            let targetInfo = processFromESProcess(signalEvent.target)
            let enrichments: [String: String] = [
                "target.pid": String(targetInfo.pid),
                "target.executable": targetInfo.executable,
                "target.name": targetInfo.name,
            ]
            return Event(
                timestamp: timestamp,
                eventCategory: .process,
                eventType: .info,
                eventAction: "signal(\(signalEvent.sig))",
                process: processInfo,
                enrichments: enrichments,
                severity: .informational
            )

        // -----------------------------------------------------------------
        // MARK: Kext Events
        // -----------------------------------------------------------------

        case ES_EVENT_TYPE_NOTIFY_KEXTLOAD:
            let kextEvent = msg.event.kextload
            let kextId = esStringToSwift(kextEvent.identifier)
            return Event(
                timestamp: timestamp,
                eventCategory: .process,
                eventType: .start,
                eventAction: "kextload",
                process: processInfo,
                file: FileInfo(path: kextId, action: .create),
                severity: .medium
            )

        // -----------------------------------------------------------------
        // MARK: Memory Protection Events
        // -----------------------------------------------------------------

        case ES_EVENT_TYPE_NOTIFY_MMAP:
            let mmapEvent = msg.event.mmap
            let filePath = esFileToPath(mmapEvent.source)
            // Only emit for executable mappings (W+X is suspicious)
            let protection = mmapEvent.protection
            let isExecutable = (protection & PROT_EXEC) != 0
            let isWritable = (protection & PROT_WRITE) != 0

            // Only alert on W+X mappings (potential code injection)
            guard isWritable && isExecutable else { return nil }

            let fileInfo = FileInfo(path: filePath, action: .create)
            return Event(
                timestamp: timestamp,
                eventCategory: .process,
                eventType: .change,
                eventAction: "mmap_wx",
                process: processInfo,
                file: fileInfo,
                enrichments: ["mmap.protection": String(protection)],
                severity: .high
            )

        case ES_EVENT_TYPE_NOTIFY_MPROTECT:
            let mprotectEvent = msg.event.mprotect
            let protection = mprotectEvent.protection
            let isExecutable = (protection & PROT_EXEC) != 0
            let isWritable = (protection & PROT_WRITE) != 0

            // Only alert on transitions TO W+X
            guard isWritable && isExecutable else { return nil }

            return Event(
                timestamp: timestamp,
                eventCategory: .process,
                eventType: .change,
                eventAction: "mprotect_wx",
                process: processInfo,
                enrichments: ["mprotect.protection": String(protection)],
                severity: .high
            )

        // -----------------------------------------------------------------
        // MARK: Ownership & Permission Events
        // -----------------------------------------------------------------

        case ES_EVENT_TYPE_NOTIFY_SETOWNER:
            let setownerEvent = msg.event.setowner
            let filePath = esFileToPath(setownerEvent.target)
            let fileInfo = FileInfo(path: filePath, action: .write)
            return Event(
                timestamp: timestamp,
                eventCategory: .file,
                eventType: .change,
                eventAction: "setowner",
                process: processInfo,
                file: fileInfo,
                enrichments: ["file.uid": String(setownerEvent.uid), "file.gid": String(setownerEvent.gid)],
                severity: .informational
            )

        case ES_EVENT_TYPE_NOTIFY_SETMODE:
            let setmodeEvent = msg.event.setmode
            let filePath = esFileToPath(setmodeEvent.target)
            let fileInfo = FileInfo(path: filePath, action: .write)
            return Event(
                timestamp: timestamp,
                eventCategory: .file,
                eventType: .change,
                eventAction: "setmode",
                process: processInfo,
                file: fileInfo,
                enrichments: ["file.mode": String(setmodeEvent.mode, radix: 8)],
                severity: .informational
            )

        default:
            return nil
        }
    }
}
