// OTLPReceiver.swift
// MacCrabCore
//
// v1.9 — OTLP/HTTP receiver (wired; config-gated).
//
// Listens on 127.0.0.1:<port> (default 4318 — the OTel ecosystem's
// canonical OTLP/HTTP port). Accepts POST /v1/traces with a protobuf body,
// decodes it, and writes ingested spans into traces.db (attributes are
// sanitized + AES-GCM-encrypted at rest with the shared DB key).
//
// Started from DaemonSetup.buildState (boot) and DaemonSetup
// .applyAgentTracesConfig (SIGHUP reload) when the agent-traces config
// asks for it. Not a stub — the class is live on any daemon whose config
// has enabled + receiverEnabled set.
//
// Hard invariants from Plan v3:
//   * Loopback only. NWListener bound to 127.0.0.1 explicitly via
//     `requiredLocalEndpoint` (AI-15 — `requiredInterfaceType` alone left the
//     socket on the WILDCARD address: `netstat` showed `tcp46 *.4318 LISTEN`).
//     Connection handlers still refuse any non-loopback peer, as defence in
//     depth.
//     CONSEQUENCE, and the one operational trap that bind introduces: it is
//     IPv4-only, so an exporter configured with `http://localhost:4318` can
//     resolve to ::1 and get connection-refused where the wildcard bind used to
//     accept it. Every snippet we ship already says 127.0.0.1 explicitly
//     (AgentSpansCommand.swift, the `agentTraces.*` strings in all 14 locales,
//     docs/AGENT_TRACES.md) — keep it that way; do not "helpfully" rewrite any
//     of them to `localhost`.
//   * Bind failure surfaces loudly — we do NOT silently fall back to a
//     different port (that would make the user-facing setup snippet lie).
//   * Default-off: the daemon starts the receiver only when the master
//     (env MACCRAB_AGENT_TRACES=1 OR agent_traces_config.json
//     `agent_traces_enabled`) AND `receiverEnabled` are both on. The
//     dashboard's "Receive agent traces" toggle writes both; a dev run
//     can use env vars instead.

import Foundation
import Network
import os.log

public enum OTLPReceiverError: Error, LocalizedError, Equatable {
    case bindFailed(String)
    case alreadyRunning
    case notRunning
    case invalidPort(Int)

    public var errorDescription: String? {
        switch self {
        case let .bindFailed(m): return "OTLPReceiver: bind failed: \(m)"
        case .alreadyRunning:    return "OTLPReceiver: already running"
        case .notRunning:        return "OTLPReceiver: not running"
        case let .invalidPort(p): return "OTLPReceiver: invalid port \(p)"
        }
    }
}

/// Lightweight summary of receiver activity. Surfaced via `metricsSnapshot()`
/// for the dashboard's diagnostics panel and the `maccrabctl status` line.
public struct OTLPReceiverMetrics: Sendable, Codable, Equatable {
    public var requestsAccepted: UInt64
    public var requestsRejectedNonLoopback: UInt64
    public var requestsBadRequest: UInt64
    public var bodyDecodeErrors: UInt64
    public var resourceSpansSeen: UInt64
    public var bytesReceived: UInt64
    // PR-3b additions:
    public var spansPersisted: UInt64
    public var spanInsertErrors: UInt64
    public var attributesKeyRedacted: UInt64
    public var attributesValueRedacted: UInt64
    /// v1.9 audit Phase-1.4: connection-deadline expiries. Indicator of
    /// slow-loris or genuinely broken peers.
    public var connectionDeadlineExceeded: UInt64

    public init() {
        self.requestsAccepted = 0
        self.requestsRejectedNonLoopback = 0
        self.requestsBadRequest = 0
        self.bodyDecodeErrors = 0
        self.resourceSpansSeen = 0
        self.bytesReceived = 0
        self.spansPersisted = 0
        self.spanInsertErrors = 0
        self.attributesKeyRedacted = 0
        self.attributesValueRedacted = 0
        self.connectionDeadlineExceeded = 0
    }
}

/// Result of one fully buffered OTLP request. Public solely to make the exact
/// pre-decode/pre-persist behavior adversarially testable without binding a
/// real port in CI.
public struct OTLPReceiverIngestResult: Sendable, Equatable {
    public let status: Int
    public let body: String

    public init(status: Int, body: String) {
        self.status = status
        self.body = body
    }
}

/// Thread-safe bridge from Network.framework's callback-driven listener state
/// to `OTLPReceiver.start()`'s async readiness contract. Construction success
/// is not bind success: `NWListener.start(queue:)` returns before the socket is
/// ready, and address-in-use/permission failures arrive later through
/// `stateUpdateHandler`. The first terminal startup state wins exactly once.
///
/// Internal so the callback/timeout races can be tested deterministically
/// without requiring a real listener in a sandboxed test process.
final class OTLPListenerStartupGate: @unchecked Sendable {
    enum Outcome: Sendable, Equatable {
        case ready
        case failed(String)
        case cancelled
        case timedOut
    }

    private let lock = NSLock()
    private var outcome: Outcome?
    private var continuation: CheckedContinuation<Outcome, Never>?
    private var timeoutWorkItem: DispatchWorkItem?

    func wait(
        timeoutSeconds: Double,
        start: () -> Void
    ) async -> Outcome {
        await withCheckedContinuation { continuation in
            let timeout = DispatchWorkItem { [weak self] in
                self?.resolve(.timedOut)
            }

            lock.lock()
            if let outcome {
                lock.unlock()
                continuation.resume(returning: outcome)
                return
            }
            self.continuation = continuation
            timeoutWorkItem = timeout
            lock.unlock()

            DispatchQueue.global(qos: .utility).asyncAfter(
                deadline: .now() + timeoutSeconds,
                execute: timeout
            )
            start()
        }
    }

    func observe(_ state: NWListener.State) {
        switch state {
        case .ready:
            resolve(.ready)
        case .failed(let error):
            resolve(.failed(error.localizedDescription))
        case .cancelled:
            resolve(.cancelled)
        default:
            break
        }
    }

    private func resolve(_ newOutcome: Outcome) {
        let continuation: CheckedContinuation<Outcome, Never>?
        let timeout: DispatchWorkItem?

        lock.lock()
        guard outcome == nil else {
            lock.unlock()
            return
        }
        outcome = newOutcome
        continuation = self.continuation
        self.continuation = nil
        timeout = timeoutWorkItem
        timeoutWorkItem = nil
        lock.unlock()

        timeout?.cancel()
        continuation?.resume(returning: newOutcome)
    }
}

public actor OTLPReceiver {

    // MARK: - Configuration

    public static let defaultPort: UInt16 = 4318
    /// Hard upper bound on a single request body. Picked to comfortably
    /// fit a typical agent batch (~1 MB observed) plus headroom; protects
    /// against denial-of-service via a single huge body.
    public static let maxBodyBytes: Int = 8 * 1024 * 1024
    /// Wall-clock deadline applied per connection. Starts when the
    /// connection is accepted; if the full request hasn't been read by
    /// the deadline, the connection is cancelled. Mitigates slow-loris
    /// (peer holding a half-sent head forever) on a feature whose only
    /// peers are local processes — but a malicious local peer could
    /// still pin many FDs without this. v1.9 PR-5 audit Sec-M2.
    public static let connectionDeadlineSeconds: Double = 10.0
    /// Hard cap on simultaneously-open connections. v1.9.0 (audit
    /// Sec-M2): without this, a local agent could hold thousands of
    /// half-open sockets — each pinning a file descriptor under the
    /// 10 s slow-loris deadline. 64 covers any plausible legitimate
    /// burst (Claude Code spans rarely exceed ~10 simultaneous) with
    /// headroom; excess connections close immediately with 503.
    public static let maxConcurrentConnections: Int = 64
    /// `NWListener.start(queue:)` is asynchronous. Refuse to advertise the
    /// receiver as running unless Network.framework reaches `.ready` within a
    /// bounded interval.
    public static let startupTimeoutSeconds: Double = 5.0

    // MARK: - State

    private var listener: NWListener?
    /// Listener whose asynchronous bind has started but has not reached
    /// `.ready`. Kept separate so `isRunning` cannot lie during startup and so
    /// `stop()` can cancel a concurrent start while the actor is re-entrant.
    private var startingListener: NWListener?
    private let port: UInt16
    private var metrics = OTLPReceiverMetrics()
    private let logger = Logger(subsystem: "com.maccrab.network", category: "otlp-receiver")
    /// Open-connection counter. Incremented on accept, decremented on
    /// every connection-end path (HTTP response sent, error, cancel,
    /// deadline). Compared against `maxConcurrentConnections` at accept.
    private var activeConnections: Int = 0

    /// Optional `TraceStore`. When nil (PR-3a behaviour) the receiver
    /// decodes-and-drops; when set (PR-3b) it decodes → sanitises →
    /// extracts → inserts. Nil-default keeps the type cheap to construct
    /// in tests and on hosts that haven't opted in to span persistence.
    private let traceStore: TraceStore?
    /// Called by the receiver actor immediately after it takes ownership of a
    /// listener that reached `.ready`. Keeping ready and terminal publication
    /// on this actor prevents an immediate post-ready failure from racing a
    /// caller that would otherwise persist `running: true` after the failure.
    private let onReady: (@Sendable () -> Void)?
    /// Called only when a listener that previously reached `.ready` later
    /// fails or is unexpectedly cancelled. Startup failures are returned
    /// directly from `start()` instead.
    /// AgentKit uses this to replace its persisted `running: true` snapshot;
    /// without it the dashboard can advertise a dead receiver indefinitely.
    private let onTerminalFailure: (@Sendable (String) -> Void)?

    /// v1.21.5 (audit S-04): rolling-window ingest budget. The receiver has NO
    /// caller authentication — the only admission control is "peer endpoint is
    /// loopback" (handleNewConnection) plus a connection cap — so ANY local uid
    /// that can reach 127.0.0.1:<port> can POST spans into the ROOT-owned
    /// traces.db. Without a budget an unprivileged process can push 8 MB bodies
    /// until the traces retention size cap evicts GENUINE forensic traces: an
    /// evidence-destruction primitive aimed at the engine's own audit trail.
    /// Legitimate agent tooling emits a few KB/s (observed batches ~1 MB), so
    /// 32 MB per 60 s is orders of magnitude of headroom and only ever bites a
    /// flood. This BOUNDS THE RATE — it mitigates the missing authentication, it
    /// does not replace it; the real fix is a bearer token in a 0600 root-owned
    /// file, or a unix socket in a root-owned dir authenticated with
    /// LOCAL_PEERCRED, both of which need coordinated client-config changes.
    public static let ingestWindowSeconds: Double = 60.0
    public static let ingestWindowByteBudget: Int = 32 * 1024 * 1024
    private var ingestWindowStart: Date = Date()
    private var ingestWindowBytes: Int = 0

    /// Charge `bytes` against the current window. False means the budget is
    /// spent and the caller must drop the body BEFORE the store insert. Reuses
    /// `requestsBadRequest` as the counter, exactly as the connection cap does,
    /// so no new `OTLPReceiverMetrics` field is introduced — that struct has an
    /// explicit memberwise init and synthesized Codable, and adding a key would
    /// break decoding of a metrics blob written by an older build.
    private func admitIngest(bytes: Int) -> Bool {
        let now = Date()
        if now.timeIntervalSince(ingestWindowStart) >= Self.ingestWindowSeconds {
            ingestWindowStart = now
            ingestWindowBytes = 0
        }
        guard ingestWindowBytes + bytes <= Self.ingestWindowByteBudget else {
            metrics.requestsBadRequest &+= 1
            logger.warning("OTLPReceiver: ingest budget exceeded — dropping \(bytes, privacy: .public) byte body")
            return false
        }
        ingestWindowBytes += bytes
        return true
    }

    public init(
        port: UInt16 = defaultPort,
        traceStore: TraceStore? = nil,
        onReady: (@Sendable () -> Void)? = nil,
        onTerminalFailure: (@Sendable (String) -> Void)? = nil
    ) {
        self.port = port
        self.traceStore = traceStore
        self.onReady = onReady
        self.onTerminalFailure = onTerminalFailure
    }

    public var isRunning: Bool { listener != nil }

    public func metricsSnapshot() -> OTLPReceiverMetrics { metrics }

    public func currentPort() -> UInt16 { port }

    /// v1.9.0 (audit Sec-M2): live count for tests and debug-overlay
    /// panels. Counts strictly the connections currently held; not a
    /// monotonic accept counter (use `metrics.requestsAccepted` for
    /// that).
    public func activeConnectionCount() -> Int { activeConnections }

    // MARK: - Lifecycle

    /// Bind and start the listener. Returns only after Network.framework emits
    /// `.ready`; asynchronous bind failure/cancellation/timeout throws instead
    /// of letting DaemonSetup persist a false `running: true` status.
    public func start() async throws {
        guard listener == nil, startingListener == nil else {
            throw OTLPReceiverError.alreadyRunning
        }
        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            throw OTLPReceiverError.invalidPort(Int(port))
        }
        let params = NWParameters.tcp
        // AI-15: `requiredInterfaceType = .loopback` constrains which INTERFACE
        // the listener may use — it does NOT choose the local ADDRESS, so the
        // socket still bound to the wildcard. `netstat -an -p tcp` showed
        // `tcp46  *.4318  LISTEN` (compare ollama's `127.0.0.1.11434`), which
        // contradicts this file's own header invariant ("NWListener bound to
        // 127.0.0.1 explicitly") and means the port is visible to LAN scanning
        // and completes a TCP handshake from a remote peer BEFORE the
        // peer-endpoint check below cancels it. `requiredLocalEndpoint` is what
        // actually pins the bind address. The peer check in
        // handleNewConnection stays as defence in depth, unchanged.
        params.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: nwPort)
        params.requiredInterfaceType = .loopback

        let listener: NWListener
        do {
            // MUST be `NWListener(using:)`, NOT `NWListener(using:on:)`.
            // `requiredLocalEndpoint` already carries the port, and passing `on:`
            // as well specifies it twice — Network.framework rejects the pair
            // with EINVAL ("Invalid argument") at construction. The first cut of
            // the AI-15 fix did exactly that, so the receiver threw on every
            // start and the whole Agent Traces module bound nothing on the
            // shipping engine while still advertising itself [STABLE]. The bind
            // failure was recorded only in agent_traces_status.json, which
            // nothing but one dashboard tile reads — so it looked healthy
            // everywhere an operator would actually look.
            listener = try NWListener(using: params)
        } catch {
            throw OTLPReceiverError.bindFailed("\(error)")
        }
        listener.newConnectionHandler = { [weak self] conn in
            // Verify peer is loopback before doing any work.
            guard let self else { conn.cancel(); return }
            Task { await self.handleNewConnection(conn) }
        }
        let startupGate = OTLPListenerStartupGate()
        listener.stateUpdateHandler = { [weak self, weak listener] state in
            startupGate.observe(state)
            guard let self, let listener else { return }
            Task { await self.handleListenerState(state, source: listener) }
        }
        startingListener = listener
        let outcome = await startupGate.wait(
            timeoutSeconds: Self.startupTimeoutSeconds
        ) {
            listener.start(queue: .global(qos: .utility))
        }

        switch outcome {
        case .ready:
            // `stop()` can run while this actor is suspended in `wait`.
            // Never resurrect a listener that was cancelled during startup.
            guard startingListener === listener else {
                listener.cancel()
                throw OTLPReceiverError.bindFailed("listener cancelled before readiness")
            }
            startingListener = nil
            self.listener = listener
            onReady?()
        case .failed(let message):
            if startingListener === listener { startingListener = nil }
            listener.cancel()
            throw OTLPReceiverError.bindFailed(message)
        case .cancelled:
            if startingListener === listener { startingListener = nil }
            throw OTLPReceiverError.bindFailed("listener cancelled before readiness")
        case .timedOut:
            if startingListener === listener { startingListener = nil }
            listener.cancel()
            throw OTLPReceiverError.bindFailed(
                "listener did not reach ready within \(Self.startupTimeoutSeconds) seconds"
            )
        }
        logger.notice("OTLPReceiver started on 127.0.0.1:\(self.port, privacy: .public)")
    }

    public func stop() {
        startingListener?.cancel()
        startingListener = nil
        listener?.cancel()
        listener = nil
        logger.notice("OTLPReceiver stopped")
    }

    private func handleListenerState(_ state: NWListener.State, source: NWListener) {
        switch state {
        case .failed(let err):
            logger.error("OTLPReceiver listener failed: \(err.localizedDescription, privacy: .public)")
            // A cancelled old listener can deliver its terminal callback after
            // a replacement has reached `.ready`. Clear only the listener that
            // emitted this state; never erase the replacement's ownership.
            let failedAfterReadiness = listener === source
            if failedAfterReadiness { listener = nil }
            if startingListener === source { startingListener = nil }
            if failedAfterReadiness {
                onTerminalFailure?(err.localizedDescription)
            }
        case .cancelled:
            let cancelledAfterReadiness = listener === source
            if cancelledAfterReadiness { listener = nil }
            if startingListener === source { startingListener = nil }
            if cancelledAfterReadiness {
                onTerminalFailure?("listener cancelled after readiness")
            }
        default:
            break
        }
    }

    // MARK: - Connection handling

    private func handleNewConnection(_ conn: NWConnection) {
        // Non-loopback rejection. Network framework does sometimes deliver
        // a remote endpoint string we have to inspect to be sure.
        if !Self.isLoopback(conn.endpoint) {
            metrics.requestsRejectedNonLoopback &+= 1
            conn.cancel()
            return
        }
        // v1.9.0 (audit Sec-M2): connection-count cap. A local agent
        // could otherwise keep 1000+ half-open sockets pinned under
        // the slow-loris deadline. Connections past the cap get a
        // 503 response and immediate close; metric `requestsBadRequest`
        // doubles as the "too-many-connections" counter.
        if activeConnections >= Self.maxConcurrentConnections {
            metrics.requestsBadRequest &+= 1
            logger.warning("OTLPReceiver: connection cap reached (\(Self.maxConcurrentConnections, privacy: .public)) — refusing")
            // No state handler / no increment — `respond` cancels and
            // `releaseConnection` is never tapped.
            conn.start(queue: .global(qos: .utility))
            Self.respond(conn, status: 503, body: "too many concurrent connections")
            return
        }
        activeConnections += 1
        // v1.9.0 (audit Sec-M2): single release point. Attach a state
        // update handler that decrements the counter exactly once on
        // terminal cancel/fail. Covers every exit path below — receive
        // errors, validation rejects, deadline timer, post-respond
        // cancel — without scattering manual decrements through 16
        // callsites. Set BEFORE start so the handler is in place even
        // if the connection transitions immediately.
        conn.stateUpdateHandler = { [weak self] state in
            switch state {
            case .cancelled, .failed:
                Task { await self?.releaseConnection() }
            default:
                break
            }
        }
        conn.start(queue: .global(qos: .utility))
        // v1.9 audit (Phase-1.1): a class-wrapped buffer keeps the
        // accumulator mutable across closure-captures so chunk appends
        // are amortized O(1) instead of the prior recursive
        // `var combined = accumulated; append; recurse` pattern that
        // copy-on-wrote the full prefix per chunk (O(N²)).
        // Buffer also carries the per-connection slow-loris deadline
        // (Phase-1.4) — a oneshot timer cancels the connection if the
        // full request hasn't been read by then.
        let buffer = ConnectionBuffer()
        buffer.startDeadline(on: conn, after: Self.connectionDeadlineSeconds, receiver: self)
        Self.receiveRequestHead(on: conn, buffer: buffer, receiver: self)
    }

    /// Decrement the active-connection counter on terminal exit. Used
    /// by every code path that closes a connection — receive errors,
    /// validation rejects, deadline timer, and the post-respond
    /// completion handler in `respond(...)`.
    fileprivate func releaseConnection() {
        if activeConnections > 0 {
            activeConnections -= 1
        }
    }

    /// Reference-typed scratch buffer for one connection. Captured by
    /// reference into NWConnection callbacks so mutations are in-place.
    /// Marked `@unchecked Sendable` because NWConnection serialises its
    /// own `receive` callbacks for a given connection — there's no
    /// concurrent mutation of `data` on the main path. The deadline
    /// timer fires on a separate queue but only ever flips `timedOut`
    /// from false to true and cancels the connection; receive
    /// callbacks observe `timedOut` and bail without touching `data`.
    fileprivate final class ConnectionBuffer: @unchecked Sendable {
        var data = Data()
        private var deadlineTimer: DispatchSourceTimer?
        var timedOut: Bool = false

        /// v1.9.0 (audit Stab-M3): defensive deinit. Apple's
        /// DispatchSourceTimer requires `cancel()` before deallocating
        /// a non-suspended timer, otherwise the process aborts. Every
        /// observable exit path already calls `cancelDeadline()`, but
        /// a future code change that misses one would crash on dealloc.
        /// `cancel()` is idempotent — safe to call after a prior cancel.
        deinit {
            deadlineTimer?.cancel()
        }

        func startDeadline(on conn: NWConnection, after seconds: Double, receiver: OTLPReceiver) {
            let timer = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
            timer.schedule(deadline: .now() + seconds)
            timer.setEventHandler { [weak self, weak conn, weak receiver] in
                guard let self else { return }
                self.timedOut = true
                Task { await receiver?.bumpDeadlineExceeded() }
                conn?.cancel()
            }
            timer.resume()
            self.deadlineTimer = timer
        }

        /// Cancel the timer when we hand the body off to handleBody —
        /// the work after that is decode/persist, not network-bound.
        func cancelDeadline() {
            deadlineTimer?.cancel()
            deadlineTimer = nil
        }
    }

    /// Public accessor used by tests to assert the loopback-check
    /// implementation matches the documented contract.
    public static func isLoopback(_ endpoint: NWEndpoint) -> Bool {
        switch endpoint {
        case let .hostPort(host, _):
            switch host {
            case .ipv4(let v4):
                return v4.isLoopback
            case .ipv6(let v6):
                return v6.isLoopback
            case .name(let name, _):
                return name == "localhost"
            @unknown default:
                return false
            }
        default:
            return false
        }
    }

    /// Recursively read until we have a full request head (terminated by
    /// `\r\n\r\n`) plus the declared Content-Length body, then dispatch.
    /// Stays off-actor so the NWConnection callbacks don't block on
    /// every chunk. Hops to `receiver` only when it needs to mutate metrics.
    /// v1.9 audit (Phase-1.1): buffer is a class so chunk appends are
    /// in-place — was recursive value-copy before, O(N²).
    nonisolated private static func receiveRequestHead(
        on conn: NWConnection,
        buffer: ConnectionBuffer,
        receiver: OTLPReceiver
    ) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { data, _, isComplete, error in
            if buffer.timedOut { return }
            if let error {
                Task { await receiver.completeWithLog("recv head failed: \(error)") }
                buffer.cancelDeadline()
                conn.cancel()
                return
            }
            guard let chunk = data, !chunk.isEmpty else {
                if isComplete {
                    buffer.cancelDeadline()
                    conn.cancel()
                }
                return
            }
            buffer.data.append(chunk)
            if buffer.data.count > 256 * 1024 {
                Task { await receiver.bumpBadRequest("request head too large") }
                buffer.cancelDeadline()
                Self.respond(conn, status: 413, body: "head too large")
                return
            }
            if let headEnd = Self.findHeadEnd(in: buffer.data) {
                let head = buffer.data.subdata(in: 0..<headEnd)
                // Reset buffer to whatever bytes already follow the
                // CRLF CRLF — those are the start of the body.
                let bodyPrefix = buffer.data.subdata(in: (headEnd + 4)..<buffer.data.count)
                buffer.data = bodyPrefix
                Self.processRequest(conn: conn, head: head, buffer: buffer, receiver: receiver)
            } else {
                Self.receiveRequestHead(on: conn, buffer: buffer, receiver: receiver)
            }
        }
    }

    nonisolated private static func findHeadEnd(in data: Data) -> Int? {
        guard data.count >= 4 else { return nil }
        for i in 0..<(data.count - 3) {
            if data[i] == 0x0D, data[i+1] == 0x0A, data[i+2] == 0x0D, data[i+3] == 0x0A {
                return i
            }
        }
        return nil
    }

    nonisolated private static func processRequest(
        conn: NWConnection,
        head: Data,
        buffer: ConnectionBuffer,
        receiver: OTLPReceiver
    ) {
        guard let headStr = String(data: head, encoding: .utf8) else {
            Task { await receiver.bumpBadRequest("non-utf8 head") }
            buffer.cancelDeadline()
            Self.respond(conn, status: 400, body: "bad request")
            return
        }
        let lines = headStr.split(separator: "\r\n", omittingEmptySubsequences: false).map(String.init)
        guard let requestLine = lines.first else {
            Task { await receiver.bumpBadRequest("empty head") }
            buffer.cancelDeadline()
            Self.respond(conn, status: 400, body: "bad request")
            return
        }
        let parts = requestLine.split(separator: " ", maxSplits: 2).map(String.init)
        guard parts.count == 3 else {
            Task { await receiver.bumpBadRequest("bad request line") }
            buffer.cancelDeadline()
            Self.respond(conn, status: 400, body: "bad request")
            return
        }
        let method = parts[0]
        let path = parts[1]
        guard method == "POST", path == "/v1/traces" else {
            buffer.cancelDeadline()
            Self.respond(conn, status: 404, body: "not found")
            return
        }

        var contentLength = 0
        var contentType = ""
        for line in lines.dropFirst() {
            if line.isEmpty { continue }
            if let colon = line.firstIndex(of: ":") {
                let name = String(line[..<colon]).lowercased()
                let value = line[line.index(after: colon)...]
                    .trimmingCharacters(in: .whitespaces)
                switch name {
                case "content-length":
                    contentLength = Int(value) ?? 0
                case "content-type":
                    contentType = value.lowercased()
                default:
                    break
                }
            }
        }

        if contentLength <= 0 {
            Task { await receiver.bumpBadRequest("no content-length") }
            buffer.cancelDeadline()
            Self.respond(conn, status: 411, body: "length required")
            return
        }
        if contentLength > Self.maxBodyBytes {
            Task { await receiver.bumpBadRequest("content-length too large") }
            buffer.cancelDeadline()
            Self.respond(conn, status: 413, body: "payload too large")
            return
        }
        if !contentType.contains("application/x-protobuf")
            && !contentType.contains("application/protobuf") {
            Task { await receiver.bumpBadRequest("unsupported content-type") }
            buffer.cancelDeadline()
            Self.respond(conn, status: 415, body: "unsupported media type")
            return
        }

        Self.accumulateBody(
            conn: conn,
            buffer: buffer,
            remaining: contentLength - buffer.data.count,
            receiver: receiver
        )
    }

    /// v1.9 audit (Phase-1.1, Phase-1.5): in-place chunk append into the
    /// class-wrapped buffer (avoid O(N²) value copies); strict body-cap
    /// enforcement against `maxBodyBytes` even if the peer's
    /// Content-Length header lied.
    nonisolated private static func accumulateBody(
        conn: NWConnection,
        buffer: ConnectionBuffer,
        remaining: Int,
        receiver: OTLPReceiver
    ) {
        if remaining <= 0 {
            // Body fully received — hand off to decode. Cancel the
            // slow-loris deadline so the decode/persist phase doesn't
            // race the timer.
            buffer.cancelDeadline()
            Self.handleBody(conn: conn, body: buffer.data, receiver: receiver)
            return
        }
        conn.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { data, _, _, error in
            if buffer.timedOut { return }
            if let error {
                Task { await receiver.completeWithLog("recv body failed: \(error)") }
                buffer.cancelDeadline()
                conn.cancel()
                return
            }
            guard let chunk = data, !chunk.isEmpty else {
                buffer.cancelDeadline()
                conn.cancel()
                return
            }
            buffer.data.append(chunk)
            // v1.9 audit Phase-1.5: even if Content-Length lied, hard
            // cap the accumulator. Otherwise a peer claiming a small
            // length could keep streaming bytes that grow `data` past
            // 8 MiB.
            if buffer.data.count > Self.maxBodyBytes {
                Task { await receiver.bumpBadRequest("body exceeded maxBodyBytes during recv") }
                buffer.cancelDeadline()
                Self.respond(conn, status: 413, body: "payload too large")
                return
            }
            Self.accumulateBody(
                conn: conn,
                buffer: buffer,
                remaining: remaining - chunk.count,
                receiver: receiver
            )
        }
    }

    nonisolated private static func handleBody(
        conn: NWConnection,
        body: Data,
        receiver: OTLPReceiver
    ) {
        Task {
            let result = await receiver.processBody(body)
            Self.respond(conn, status: result.status, body: result.body)
        }
    }

    /// Full buffered-body pipeline shared by the live socket and deterministic
    /// tests. Storage admission runs once before protobuf decode and again with
    /// the exact decoded records before persistence; TraceStore repeats the
    /// latter centrally inside `insertSpans`.
    public func ingestBodyForTesting(_ body: Data) async -> OTLPReceiverIngestResult {
        await processBody(body)
    }

    private func processBody(_ body: Data) async -> OTLPReceiverIngestResult {
        recordBody(body)
        // v1.21.5 (audit S-04): bound unauthenticated local traffic by rate.
        guard admitIngest(bytes: body.count) else {
            return OTLPReceiverIngestResult(status: 429, body: "ingest budget exceeded")
        }

        // Ask the actor-owned store BEFORE allocating the decoded protobuf
        // graph. A pressure-blocked store rejects even malformed input as 507,
        // proving decode cannot become a pressure-side CPU/memory bypass.
        if let traceStore {
            do {
                try await traceStore.preflightStorageAdmission(
                    estimatedGrowthBytes: Int64(body.count)
                )
            } catch let pressure as TraceStoreStorageAdmissionError {
                recordSpanInsertError(pressure.localizedDescription)
                return OTLPReceiverIngestResult(status: 507, body: "storage pressure")
            } catch {
                recordSpanInsertError("storage preflight: \(error)")
                return OTLPReceiverIngestResult(status: 500, body: "storage unavailable")
            }
        }

        let decoded: (OTLPTracesSummary, OTLPSpanExtractionResult)
        do {
            // v1.9 audit Phase-1.3: promptly release decoder/sanitizer
            // temporaries for bursty requests.
            decoded = try autoreleasepool {
                let groups = try OTLPNestedDecoder.decodeRequest(body)
                return (
                    OTLPTracesSummary(
                        resourceSpansCount: groups.count,
                        bytesParsed: body.count
                    ),
                    OTLPSpanExtractor.extract(from: groups)
                )
            }
        } catch {
            bumpDecodeError("\(error)")
            return OTLPReceiverIngestResult(status: 400, body: "bad protobuf")
        }

        let (summary, extraction) = decoded
        recordAccept(summary)
        recordSanitisation(
            keyRedacted: extraction.totalAttributesKeyRedacted,
            valueRedacted: extraction.totalAttributesValueRedacted
        )
        guard let traceStore else {
            return OTLPReceiverIngestResult(status: 200, body: "")
        }

        let valid = extraction.spans.filter {
            $0.traceId.count == 32 && $0.spanId.count == 16
        }
        do {
            // Receiver-level exact decoded-batch gate, then the store repeats
            // it immediately before BEGIN so no alternate writer can bypass it.
            try await traceStore.preflightInsertSpans(valid)
            let result = try await traceStore.insertSpans(valid)
            for _ in 0..<result.succeeded { recordSpanPersisted() }
            for _ in 0..<result.failed {
                recordSpanInsertError("batch insert: row failed")
            }
            return OTLPReceiverIngestResult(status: 200, body: "")
        } catch let pressure as TraceStoreStorageAdmissionError {
            for _ in 0..<max(1, valid.count) {
                recordSpanInsertError(pressure.localizedDescription)
            }
            return OTLPReceiverIngestResult(status: 507, body: "storage pressure")
        } catch {
            for _ in 0..<max(1, valid.count) {
                recordSpanInsertError("\(error)")
            }
            return OTLPReceiverIngestResult(status: 500, body: "storage unavailable")
        }
    }

    // MARK: - Metric helpers (actor-isolated counters)

    private func recordBody(_ body: Data) {
        metrics.bytesReceived &+= UInt64(body.count)
    }

    private func recordAccept(_ summary: OTLPTracesSummary) {
        metrics.requestsAccepted &+= 1
        metrics.resourceSpansSeen &+= UInt64(summary.resourceSpansCount)
    }

    private func bumpBadRequest(_ reason: String) {
        metrics.requestsBadRequest &+= 1
        logger.debug("400: \(reason, privacy: .public)")
    }

    private func bumpDecodeError(_ reason: String) {
        metrics.bodyDecodeErrors &+= 1
        logger.debug("decode error: \(reason, privacy: .public)")
    }

    private func recordSanitisation(keyRedacted: Int, valueRedacted: Int) {
        metrics.attributesKeyRedacted &+= UInt64(keyRedacted)
        metrics.attributesValueRedacted &+= UInt64(valueRedacted)
    }

    private func recordSpanPersisted() {
        metrics.spansPersisted &+= 1
    }

    private func recordSpanInsertError(_ reason: String) {
        metrics.spanInsertErrors &+= 1
        logger.debug("span insert error: \(reason, privacy: .public)")
    }

    /// v1.9 audit Phase-1.4: connection-deadline expired (slow-loris).
    fileprivate func bumpDeadlineExceeded() {
        metrics.connectionDeadlineExceeded &+= 1
        logger.debug("connection deadline exceeded")
    }

    /// Accessor for the optional store. Read-only — the receiver never
    /// rebinds the store at runtime; PR-4's "Receive agent traces"
    /// toggle starts/stops the receiver wholesale.
    private func storeRef() -> TraceStore? { traceStore }

    private func completeWithLog(_ msg: String) {
        logger.debug("\(msg, privacy: .public)")
    }

    // MARK: - HTTP response

    nonisolated private static func respond(_ conn: NWConnection, status: Int, body: String) {
        let reason: String
        switch status {
        case 200: reason = "OK"
        case 400: reason = "Bad Request"
        case 404: reason = "Not Found"
        case 411: reason = "Length Required"
        case 413: reason = "Payload Too Large"
        case 415: reason = "Unsupported Media Type"
        case 429: reason = "Too Many Requests"
        case 500: reason = "Internal Server Error"
        case 503: reason = "Service Unavailable"
        case 507: reason = "Insufficient Storage"
        default:  reason = "Error"
        }
        let bodyBytes = Array(body.utf8)
        let headers = """
        HTTP/1.1 \(status) \(reason)\r
        Content-Length: \(bodyBytes.count)\r
        Content-Type: text/plain; charset=utf-8\r
        Connection: close\r
        \r

        """
        var out = Data(headers.utf8)
        out.append(Data(bodyBytes))
        conn.send(content: out, completion: .contentProcessed { _ in
            conn.cancel()
        })
    }
}

// MARK: - v1.9.0 audit Sec-M2: connection-count bookkeeping at exit
// Each terminal path in the receive pipeline taps `releaseConnection()`
// via a Task hop, mirroring the metric mutators. Counter never goes
// below zero (releaseConnection clamps).
