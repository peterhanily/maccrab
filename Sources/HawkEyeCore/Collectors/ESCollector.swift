// ESCollector.swift
// HawkEyeCore
//
// Wraps Apple's Endpoint Security framework to collect security-relevant
// kernel events and normalise them into HawkEye `Event` objects.
//
// The ES client callback runs on a private serial queue managed by the
// framework, so the class opts into `@unchecked Sendable` rather than
// adding a lock around every field.

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
    private let logger = Logger(subsystem: "com.hawkeye.core", category: "ESCollector")

    /// The asynchronous stream of normalised events.
    public let events: AsyncStream<Event>

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
        let logger = self.logger

        var newClient: OpaquePointer?   // es_client_t*

        let result = es_new_client(&newClient) { _, message in
            guard let message = message else { return }
            let event = Self.normalise(message: message)
            if let event = event {
                continuation.yield(event)
            } else {
                logger.debug("Dropped unhandled ES event type: \(message.pointee.event_type.rawValue)")
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
        guard result == ES_RETURN_SUCCESS else {
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

        let selfPath = ProcessInfo.processInfo.arguments.first ?? CommandLine.arguments.first ?? ""
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
    }

    // MARK: - Event Normalisation

    /// Map a raw `es_message_t` into a HawkEye `Event`, or return `nil`
    /// if the event should be dropped (e.g. unmodified close).
    private static func normalise(message: UnsafePointer<es_message_t>) -> Event? {
        let msg = message.pointee

        // Timestamp from the Mach absolute time in the message header.
        let timestamp = Date(
            timeIntervalSince1970: TimeInterval(msg.time.tv_sec) + TimeInterval(msg.time.tv_nsec) / 1_000_000_000
        )

        // Source process
        guard let esProcess = msg.process else { return nil }
        var processInfo = processFromESProcess(esProcess)

        switch msg.event_type {

        // -----------------------------------------------------------------
        // MARK: Process Events
        // -----------------------------------------------------------------

        case ES_EVENT_TYPE_NOTIFY_EXEC:
            let execEvent = msg.event.exec
            let args = argsFromExecMessage(message)
            processInfo.args = args

            // The target of exec is in execEvent.target — use it if available.
            var targetInfo = processInfo
            if let target = execEvent.target {
                targetInfo = processFromESProcess(target)
                targetInfo.args = args
            }

            return Event(
                timestamp: timestamp,
                eventCategory: .process,
                eventType: .start,
                eventAction: "exec",
                process: targetInfo,
                parent: processInfo,
                file: nil,
                network: nil,
                severity: .informational
            )

        case ES_EVENT_TYPE_NOTIFY_FORK:
            let forkEvent = msg.event.fork
            var childInfo: ProcessInfo?
            if let child = forkEvent.child {
                childInfo = processFromESProcess(child)
            }
            return Event(
                timestamp: timestamp,
                eventCategory: .process,
                eventType: .start,
                eventAction: "fork",
                process: childInfo ?? processInfo,
                parent: processInfo,
                file: nil,
                network: nil,
                severity: .informational
            )

        case ES_EVENT_TYPE_NOTIFY_EXIT:
            return Event(
                timestamp: timestamp,
                eventCategory: .process,
                eventType: .end,
                eventAction: "exit",
                process: processInfo,
                parent: nil,
                file: nil,
                network: nil,
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
                if let existingFile = createEvent.destination.existing_file {
                    path = esFileToPath(existingFile)
                } else {
                    path = ""
                }
            } else {
                let dir = esFileToPath(createEvent.destination.new_path.dir)
                let filename = esStringToSwift(createEvent.destination.new_path.filename)
                path = dir.hasSuffix("/") ? dir + filename : dir + "/" + filename
            }

            let fileInfo = FileInfo(
                path: path,
                name: (path as NSString).lastPathComponent,
                action: .create
            )
            return Event(
                timestamp: timestamp,
                eventCategory: .file,
                eventType: .creation,
                eventAction: "create",
                process: processInfo,
                parent: nil,
                file: fileInfo,
                network: nil,
                severity: .informational
            )

        case ES_EVENT_TYPE_NOTIFY_WRITE:
            let writeEvent = msg.event.write
            guard let target = writeEvent.target else { return nil }
            let path = esFileToPath(target)
            let fileInfo = FileInfo(
                path: path,
                name: (path as NSString).lastPathComponent,
                action: .write
            )
            return Event(
                timestamp: timestamp,
                eventCategory: .file,
                eventType: .change,
                eventAction: "write",
                process: processInfo,
                parent: nil,
                file: fileInfo,
                network: nil,
                severity: .informational
            )

        case ES_EVENT_TYPE_NOTIFY_CLOSE:
            let closeEvent = msg.event.close
            // Only emit events for files that were actually modified.
            guard closeEvent.modified else { return nil }
            guard let target = closeEvent.target else { return nil }
            let path = esFileToPath(target)
            let fileInfo = FileInfo(
                path: path,
                name: (path as NSString).lastPathComponent,
                action: .close
            )
            return Event(
                timestamp: timestamp,
                eventCategory: .file,
                eventType: .change,
                eventAction: "close_modified",
                process: processInfo,
                parent: nil,
                file: fileInfo,
                network: nil,
                severity: .informational
            )

        case ES_EVENT_TYPE_NOTIFY_RENAME:
            let renameEvent = msg.event.rename
            guard let source = renameEvent.source else { return nil }
            let sourcePath = esFileToPath(source)

            // Destination depends on destination_type.
            let destPath: String
            if renameEvent.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
                if let existingFile = renameEvent.destination.existing_file {
                    destPath = esFileToPath(existingFile)
                } else {
                    destPath = ""
                }
            } else {
                let dir = esFileToPath(renameEvent.destination.new_path.dir)
                let filename = esStringToSwift(renameEvent.destination.new_path.filename)
                destPath = dir.hasSuffix("/") ? dir + filename : dir + "/" + filename
            }

            let fileInfo = FileInfo(
                path: destPath,
                name: (destPath as NSString).lastPathComponent,
                action: .rename,
                sourcePath: sourcePath
            )
            return Event(
                timestamp: timestamp,
                eventCategory: .file,
                eventType: .change,
                eventAction: "rename",
                process: processInfo,
                parent: nil,
                file: fileInfo,
                network: nil,
                severity: .informational
            )

        case ES_EVENT_TYPE_NOTIFY_UNLINK:
            let unlinkEvent = msg.event.unlink
            guard let target = unlinkEvent.target else { return nil }
            let path = esFileToPath(target)
            let fileInfo = FileInfo(
                path: path,
                name: (path as NSString).lastPathComponent,
                action: .delete
            )
            return Event(
                timestamp: timestamp,
                eventCategory: .file,
                eventType: .deletion,
                eventAction: "unlink",
                process: processInfo,
                parent: nil,
                file: fileInfo,
                network: nil,
                severity: .informational
            )

        // -----------------------------------------------------------------
        // MARK: Signal Events
        // -----------------------------------------------------------------

        case ES_EVENT_TYPE_NOTIFY_SIGNAL:
            let signalEvent = msg.event.signal
            var targetInfo: ProcessInfo?
            if let target = signalEvent.target {
                targetInfo = processFromESProcess(target)
            }
            return Event(
                timestamp: timestamp,
                eventCategory: .process,
                eventType: .info,
                eventAction: "signal(\(signalEvent.sig))",
                process: processInfo,
                parent: nil,
                file: nil,
                network: nil,
                severity: .informational,
                targetProcess: targetInfo
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
                parent: nil,
                file: FileInfo(path: kextId, name: kextId, action: .create),
                network: nil,
                severity: .medium
            )

        default:
            return nil
        }
    }
}
