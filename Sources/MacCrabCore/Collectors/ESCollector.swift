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
    /// v1.17.4: subscribe to ES NOTIFY_OPEN (credential-read detection).
    /// Config kill-switch (DaemonConfig.subscribeFileOpenEvents).
    private let subscribeFileOpen: Bool

    /// v1.18: subscribe to the introspection family (get_task_read / trace /
    /// remote_thread_create / cs_invalidated). Kill-switch
    /// (DaemonConfig.subscribeIntrospectionEvents) so an operator can disable
    /// it independently of the OPEN family.
    private let subscribeIntrospection: Bool

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

    /// v1.18 introspection family — observe one process acting on ANOTHER
    /// (memory read / injection / trace) or tampering its own signature.
    /// Grantable under the existing endpoint-security.client entitlement (the
    /// debugger entitlement is only needed to CALL these, not OBSERVE them) and
    /// all available at the macOS 13 deploy floor (GET_TASK_READ 11.3, TRACE
    /// 11.0, REMOTE_THREAD_CREATE 12.3, CS_INVALIDATED 10.15) — no @available
    /// guard. Gated by `subscribeIntrospection` so an operator can disable the
    /// family if it ever degrades a host. PROC_CHECK (firehose) +
    /// GATEKEEPER_USER_OVERRIDE (macOS 15, file-shaped) are deferred.
    private static let introspectionEvents: [es_event_type_t] = [
        ES_EVENT_TYPE_NOTIFY_GET_TASK_READ,
        ES_EVENT_TYPE_NOTIFY_TRACE,
        ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE,
        ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED,
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

    // MARK: - Credential-read allowlist (v1.17.4)
    //
    // The ONLY paths for which a NOTIFY_OPEN emits an Event. The OPEN stream
    // is enormous, so this tight allowlist is the load-bearing bound on what
    // reaches the detection pipeline — it mirrors the target paths of the
    // credential-read rules (crypto_wallet_data_access, token_files_accessed,
    // ai_tool_reads_ssh_keys, …) plus the canonical secret locations. Keep it
    // tight; broadening it re-introduces the firehose. Pure + unit-tested
    // (isCredentialReadPath) even though ES delivery itself is live-only.
    static let credentialReadPathSubstrings: [String] = [
        "/.ssh/",
        "/.aws/credentials", "/.aws/config",
        "/.config/gcloud/credentials", "/.config/gcloud/access_tokens",
        "/.azure/accessTokens", "/.azure/msal_token_cache",
        "/.kube/config", "/.docker/config.json",
        "/.terraform.d/credentials", "/.config/gh/hosts.yml",
        "/.npmrc", "/.pypirc", "/.netrc", "/.gnupg/",
        "/Library/Keychains/",
        // Deception: any READ of a deployed decoy / honey-prompt is the
        // signal itself (MacCrab's own opens are muted via muteSelf, so a
        // hit here is always a third party). Rescues the critical
        // canary_skill_or_rules_read rule, dead until OPEN emission covered
        // this prefix. (Deployed $HOME honeyfiles at arbitrary paths still
        // need a manifest-sourced allowlist — tracked as a follow-up.)
        "Application Support/MacCrab/decoys/",
        // Native desktop wallets — full mirror of crypto_wallet_data_access.yml
        // selection_native_wallets (kept in sync by ESCredentialReadAllowlistTests).
        "Application Support/Electrum/wallets/",
        "Application Support/Exodus/exodus.wallet/",
        "Application Support/Atomic/Local Storage/",
        "Application Support/Coinomi/",
        "Application Support/Daedalus/",
        "Application Support/monero-project/",
        "Application Support/Trezor Suite/",
        "Application Support/Ledger Live/",
        "Library/Containers/io.trezor.TrezorSuite/",
        "/.ethereum/keystore/",
        // Browser-extension wallet storage (specific extension ids) — full
        // mirror of selection_browser_extension_wallets.
        "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn",  // MetaMask
        "/Local Extension Settings/bfnaelmomeimhlpmgjnjophhpkkoljpa",  // Phantom (Solana)
        "/Local Extension Settings/hnfanknocfeofbddgcijnmhnfnkdnaad",  // Coinbase Wallet
        "/Local Extension Settings/fhbohimaelbohpjbbldcngcnapndodjp",  // Binance Chain Wallet
        "/Local Extension Settings/egjidjbpglichdcondbcbdnbeeppgdph",  // Trust Wallet
        "/Local Extension Settings/lmenefjjbnabbnchedhpaichpfphndbg",  // WalletConnect
        "/Local Extension Settings/efbglgofoippbgcjepnhiblaibcnclgk",  // MetaMask Flask (dev)
    ]

    /// True iff `path` is a credential/secret location worth emitting an OPEN
    /// (read) event for. The hot-path early-out for NOTIFY_OPEN.
    static func isCredentialReadPath(_ path: String) -> Bool {
        for substring in credentialReadPathSubstrings where path.contains(substring) {
            return true
        }
        return false
    }

    /// True iff `path` is an on-disk keychain database the keychain read-rules
    /// target (`/Keychains/…(.keychain-db|.keychain)`). Used to drop the
    /// high-frequency platform-binary (securityd / Security.framework) opens at
    /// emission so the credential allowlist stays a tight firehose bound —
    /// those rules only flag NON-Apple openers anyway. (ES-OPEN-5)
    static func isKeychainPath(_ path: String) -> Bool {
        return path.contains("/Keychains/")
            && (path.hasSuffix(".keychain-db") || path.hasSuffix(".keychain"))
    }

    /// Enrichment keys describing the TARGET of an actor->target introspection
    /// event (get_task_read / trace / remote_thread_create). Keys are the exact
    /// Sigma field names so RuleEngine.resolveField resolves them via its
    /// enrichment passthrough — no model or engine change. `TargetIsSelf` and
    /// `SameTeam` are the cheap FP gates rules use in place of the
    /// not-yet-implemented |fieldref modifier.
    static func introspectionEnrichments(actor: ProcessInfo, target: ProcessInfo) -> [String: String] {
        let actorTeam = actor.codeSignature?.teamId ?? ""
        let targetTeam = target.codeSignature?.teamId ?? ""
        let sameTeam = !actorTeam.isEmpty && actorTeam == targetTeam
        return [
            "TargetImage": target.executable,
            "TargetProcessName": target.name,
            "TargetSignerType": target.codeSignature?.signerType.rawValue ?? "unknown",
            "TargetPid": String(target.pid),
            "TargetIsSelf": actor.pid == target.pid ? "true" : "false",
            "SameTeam": sameTeam ? "true" : "false",
        ]
    }

    // MARK: - Initialisation

    /// Creates a new ES client, subscribes to events, and begins emitting
    /// `Event` values on the `events` stream.
    ///
    /// - Throws: `ESCollectorError` if the client cannot be created.
    public init(subscribeFileOpen: Bool = true, subscribeIntrospection: Bool = true) throws {
        self.subscribeFileOpen = subscribeFileOpen
        self.subscribeIntrospection = subscribeIntrospection
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
        var events = Self.subscribedEvents
        // v1.17.4: NOTIFY_OPEN is enormous system-wide, so emission is bounded
        // to a tight credential-dir allowlist in the handler (isCredentialReadPath).
        // Gated so an operator can disable it if the firehose ever degrades a host.
        if subscribeFileOpen { events.append(ES_EVENT_TYPE_NOTIFY_OPEN) }
        if subscribeIntrospection { events.append(contentsOf: Self.introspectionEvents) }
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
    /// `argv[0]` is the *invoked* path (relative for sysext bundles —
    /// e.g. `com.maccrab.agent.systemextension`), but ES requires the
    /// absolute resolved executable path for `es_mute_path_literal`.
    /// Use `proc_pidpath` so muteSelf works under the sysext, the dev
    /// daemon, and any future Sparkle-relaunched binary path.
    private func muteSelf() {
        guard let client = self.client else { return }

        var pathBuf = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        let len = proc_pidpath(getpid(), &pathBuf, UInt32(pathBuf.count))
        guard len > 0 else {
            logger.warning("muteSelf: proc_pidpath returned \(len), errno \(errno) — daemon-self events will reach the pipeline")
            return
        }
        let selfPath = String(cString: pathBuf)
        guard !selfPath.isEmpty else {
            logger.warning("muteSelf: empty path from proc_pidpath")
            return
        }

        let rc = es_mute_path_literal(client, selfPath)
        if rc != ES_RETURN_SUCCESS {
            logger.warning("Failed to self-mute at path \(selfPath) (rc=\(rc.rawValue))")
        } else {
            logger.info("ESCollector self-muted at \(selfPath)")
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

        // v1.17.4 hot-path guard (ES-OPEN-4): the NOTIFY_OPEN firehose is
        // system-wide and ~all opens are discarded by the credential
        // allowlist. Do the cheap path check (a substring scan + a bool
        // field) BEFORE the heap-allocating processFromESProcess build, so
        // the discarded majority costs almost nothing. Otherwise the ES
        // callback queue backpressures under a heavy open rate and the
        // kernel silently DROPS messages across ALL event types.
        if msg.event_type == ES_EVENT_TYPE_NOTIFY_OPEN {
            let openPath = esFileToPath(msg.event.open.file)
            guard isCredentialReadPath(openPath) else { return nil }
            // ES-OPEN-5: keychain DBs are opened constantly by securityd /
            // the Security framework (platform binaries) for every keychain
            // query; the keychain read-rules only care about non-Apple
            // openers, so drop the platform-binary case here.
            if isKeychainPath(openPath) && msg.process.pointee.is_platform_binary {
                return nil
            }
        }

        // v1.18 hot-path guard: introspection events are only interesting from
        // a NON-platform-binary actor. Every benign introspector — lldb,
        // debugserver, ReportCrash, spindump, sysdiagnose, OSAnalyticsHelper,
        // Activity Monitor, securityd — is an Apple platform binary, and the
        // rules filter Apple actors anyway, so dropping the platform-binary
        // majority here (a cheap bool, before the doubled processFromESProcess
        // for actor+target) bounds the volume with zero detection loss — the
        // same firehose discipline as the OPEN allowlist.
        switch msg.event_type {
        case ES_EVENT_TYPE_NOTIFY_GET_TASK_READ, ES_EVENT_TYPE_NOTIFY_TRACE,
             ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE, ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED:
            if msg.process.pointee.is_platform_binary { return nil }
        default:
            break
        }

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

        case ES_EVENT_TYPE_NOTIFY_OPEN:
            // v1.17.4: emit ONLY for credential/secret paths. The firehose
            // bound (isCredentialReadPath + the platform-binary keychain
            // drop) is enforced upstream BEFORE processInfo is built — see
            // the hot-path guard at the top of normalise — so reaching here
            // means the path already passed. The recompute below is the
            // defensive re-check and only runs on the rare matched open.
            // Revives the "credential file READ by untrusted process" rule
            // class, dead until now because no OPEN event was ever emitted.
            let openEvent = msg.event.open
            let openPath = esFileToPath(openEvent.file)
            guard Self.isCredentialReadPath(openPath) else { return nil }
            return Event(
                timestamp: timestamp,
                eventCategory: .file,
                eventType: .change,
                eventAction: "open",
                process: processInfo,
                file: FileInfo(path: openPath, action: .open),
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
        // MARK: Introspection Events (v1.18) — actor acts on a TARGET process
        // -----------------------------------------------------------------
        // The subject (msg.process) is the ACTOR; the target is the process
        // being read/traced/injected. We carry the target via Sigma-named
        // enrichment keys (TargetImage/TargetSignerType/TargetIsSelf/SameTeam)
        // so RuleEngine resolves them through its enrichment passthrough with
        // no model change, and rules get cheap FP gates (target-self = JIT/own
        // process; same-team = legitimate intra-vendor IPC) without the
        // unimplemented |fieldref modifier. Emitted as .process/.change ->
        // logsource category "process_event".
        //
        // Notes: (a) we read ONLY `.target` (and the empty cs_invalidated),
        // which is version-agnostic — the version>=5 `.type` field is
        // deliberately not accessed, so no es_message version guard is needed.
        // (b) SameTeam is derived from the kernel-attested team_id, so it is an
        // FP-reduction heuristic an attacker cannot spoof without possessing
        // the target team's signing identity — not a hard security boundary.
        // (c) these are ES-native; they are NOT carried by the non-root
        // eslogger/kdebug fallback, so these rules require the ES entitlement.

        case ES_EVENT_TYPE_NOTIFY_GET_TASK_READ:
            // task_read_for_pid: the memory-read port acquisition that gates
            // every cross-process mach_vm_read (credential scraping from a
            // live ssh-agent/securityd/gh process).
            let target = processFromESProcess(msg.event.get_task_read.target)
            return Event(
                timestamp: timestamp, eventCategory: .process, eventType: .change,
                eventAction: "get_task_read", process: processInfo,
                enrichments: introspectionEnrichments(actor: processInfo, target: target),
                severity: .informational)

        case ES_EVENT_TYPE_NOTIFY_TRACE:
            // ptrace(PT_ATTACH) — debugger-style attach to another process.
            let target = processFromESProcess(msg.event.trace.target)
            return Event(
                timestamp: timestamp, eventCategory: .process, eventType: .change,
                eventAction: "trace", process: processInfo,
                enrichments: introspectionEnrichments(actor: processInfo, target: target),
                severity: .informational)

        case ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE:
            // Thread created inside another process's task — code injection.
            // Rarely benign (even debuggers use TRACE, not thread_create).
            let target = processFromESProcess(msg.event.remote_thread_create.target)
            return Event(
                timestamp: timestamp, eventCategory: .process, eventType: .change,
                eventAction: "remote_thread_create", process: processInfo,
                enrichments: introspectionEnrichments(actor: processInfo, target: target),
                severity: .informational)

        case ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED:
            // The process invalidated ITS OWN code signature at runtime
            // (binary tampering, or benign JIT/dynamic codegen). Self-event:
            // no target. TargetIsSelf=true lets rules reason about it.
            return Event(
                timestamp: timestamp, eventCategory: .process, eventType: .change,
                eventAction: "cs_invalidated", process: processInfo,
                enrichments: ["TargetIsSelf": "true"],
                severity: .informational)

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
