// ESIngressAdmissionTests.swift
// MacCrabCoreTests
//
// v1.22.7 ES ingress throughput. Unit coverage for the admission decisions
// and the routing split:
//
//   • the callback-boundary DROP policy is FIELD-ONLY (no path decode) — every
//     path-dependent drop runs on the retained-message worker;
//   • the one path the callback classifies is a NOTIFY_OPEN's, as raw bytes
//     (`ESPathMarkerSet`), so a credential / honeyfile / agent-content OPEN
//     can claim the worker reserve and keep the priority lane;
//   • NOTIFY_SIGNAL is dropped at the callback unless it is a fatal signal aimed
//     at MacCrab itself or at a security tool (no rule, sequence, graph rule,
//     built-in heuristic or AI Guard consumer reads signal events);
//   • repeated WRITE/OPEN by the same (pid, pidversion) on the same path inside
//     a window ANCHORED at the yielded callback are coalesced on the worker —
//     the first always passes, a terminal event on the path ends every
//     reader's OPEN window, and credential / honeyfile / persistence /
//     agent-config paths are exempt;
//   • only a dynamic-AI-admitted `open` rides the file lane.
//
// Every case that a consumer needs is written as a must-pass assertion.

import Darwin
import EndpointSecurity
import Foundation
import Testing
@testable import MacCrabCore

@Suite("ES ingress admission (v1.22.7)")
struct ESIngressAdmissionTests {

    // MARK: Callback boundary is field-only

    @Test("path-dependent types are never dropped at the callback: they always reach the worker")
    func pathDependentTypesReachTheWorker() {
        for type in [
            ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_WRITE, ES_EVENT_TYPE_NOTIFY_CREATE,
            ES_EVENT_TYPE_NOTIFY_RENAME, ES_EVENT_TYPE_NOTIFY_UNLINK, ES_EVENT_TYPE_NOTIFY_EXEC,
            ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXIT, ES_EVENT_TYPE_NOTIFY_KEXTLOAD,
            ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD, ES_EVENT_TYPE_NOTIFY_SETOWNER,
        ] {
            #expect(!ESCollector.shouldDropAtCallback(eventType: type.rawValue),
                    "\(ESCollector.eventTypeName(type.rawValue)) must be retained for the worker")
        }
        #expect(!ESCollector.shouldDropAtCallback(
            eventType: ES_EVENT_TYPE_NOTIFY_CLOSE.rawValue, closeModified: true))
    }

    @Test("the cheap field gates stay on the callback: unmodified CLOSE, permissions-only chmod, non-W+X, platform introspection")
    func cheapFieldGatesStayOnTheCallback() {
        #expect(ESCollector.shouldDropAtCallback(
            eventType: ES_EVENT_TYPE_NOTIFY_CLOSE.rawValue, closeModified: false))
        #expect(ESCollector.shouldDropAtCallback(
            eventType: ES_EVENT_TYPE_NOTIFY_SETMODE.rawValue, mode: 0o644))
        #expect(!ESCollector.shouldDropAtCallback(
            eventType: ES_EVENT_TYPE_NOTIFY_SETMODE.rawValue, mode: 0o755))
        #expect(ESCollector.shouldDropAtCallback(
            eventType: ES_EVENT_TYPE_NOTIFY_MPROTECT.rawValue, protection: Int32(PROT_READ | PROT_EXEC)))
        #expect(!ESCollector.shouldDropAtCallback(
            eventType: ES_EVENT_TYPE_NOTIFY_MMAP.rawValue, protection: Int32(PROT_READ | PROT_WRITE | PROT_EXEC)))
        #expect(ESCollector.shouldDropAtCallback(
            eventType: ES_EVENT_TYPE_NOTIFY_GET_TASK_READ.rawValue, isPlatformBinary: true))
        #expect(!ESCollector.shouldDropAtCallback(
            eventType: ES_EVENT_TYPE_NOTIFY_TRACE.rawValue, isPlatformBinary: false))
    }

    // MARK: Protected OPEN classification (byte-level, callback)

    /// The corpora `ESCredentialReadAllowlistTests` pins, plus the edge shapes
    /// a byte matcher can get wrong: empty, shorter than every marker, a
    /// multibyte UTF-8 component next to a marker, a marker at offset 0, a
    /// suffix marker that only appears mid-path, and the gated Chrome case.
    private static let protectedCorpus: [String] = [
        "/Users/x/.ssh/id_ed25519", "/Users/x/.aws/credentials", "/Users/x/.kube/config",
        "/Users/x/.npmrc", "/Users/x/.netrc", "/Users/x/.gnupg/secring.gpg",
        "/Users/x/Library/Keychains/login.keychain-db",
        "/Users/x/Library/Application Support/Electrum/wallets/default_wallet",
        "/Users/x/Library/Application Support/Google/Chrome/Profile 1/Login Data",
        "/Users/x/Library/Application Support/Firefox/Profiles/abc/logins.json",
        "/Users/x/Library/Application Support/MacCrab/decoys/passwords.txt",
        "/Users/x/Documents/passwords_backup.csv", "/Users/x/.gcp-service-account.json.bak",
        "/Users/x/Library/Safari/History.db", "/private/var/db/dslocal/nodes/Default/users/x.plist",
        "/Users/x/project/.env", "/Users/x/project/.env.production", "/Users/x/.gitconfig",
        "/Users/x/Library/Messages/chat.db-wal", "/Library/Application Support/com.apple.TCC/TCC.db",
        "/Users/x/.claude/settings.json", "/Users/x/.claude/skills/reviewer/SKILL.md",
        "/Users/x/project/.github/workflows/ci.yml", "/Users/x/.cursor/mcp.json",
        "/Users/x/Library/Application Support/Google/Chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/000003.log",
        "/Users/émilie/.ssh/id_rsa", "/Users/x/ドキュメント/.aws/credentials",
        "/.ssh/id_rsa", ".kdbx",
        "/Users/x/project/README.md", "/Users/x/project/src/module.ts", "/usr/lib/libSystem.B.dylib",
        "/private/var/folders/hf/T/cache.bin", "/Users/x/project/node_modules/.cache/esbuild/x.json",
        "/Users/x/project/.git/objects/ab/cd", "/Users/x/Library/Caches/com.apple.dt.Xcode/x",
        "/Users/x/project/.envrc", "/Users/x/project/.env.example.bak",
        "/Users/x/Library/Application Support/Code/User/settings.json",
        "/Users/x/Library/Application Support/Google/Chrome/Default/Login Data.bak",
        "/Users/x/Documents/Login Data", "/Users/x/project/TCC.db.txt",
        "", "/", "/a", "/.", "/.s",
        "/Users/x/project/src/\u{FFFD}/a.ts",
    ]

    @Test("the byte-level protected-OPEN matcher agrees with isCredentialReadPath || isAgentContentReadPath on every corpus path")
    func protectedOpenMatcherParity() {
        for path in Self.protectedCorpus {
            let reference = ESCollector.isCredentialReadPath(path) || ESCollector.isAgentContentReadPath(path)
            #expect(ESCollector.isProtectedOpenPath(path) == reference,
                    "parity broke for \(path.debugDescription): bytes=\(ESCollector.isProtectedOpenPath(path)) reference=\(reference)")
        }
        // The allowlists themselves, verbatim, with a home prefix.
        for marker in ESCollector.credentialReadPathSubstrings + ESCollector.agentContentReadPathSubstrings {
            let path = "/Users/x" + (marker.hasPrefix("/") ? "" : "/") + marker + "tail"
            #expect(ESCollector.isProtectedOpenPath(path), "substring marker \(marker) must match")
        }
        for marker in ESCollector.credentialReadPathSuffixes + ESCollector.agentConfigReadFileSuffixes {
            #expect(ESCollector.isProtectedOpenPath("/Users/x/project" + marker), "suffix marker \(marker) must match")
            #expect(ESCollector.isProtectedOpenPath("/Users/x/project" + marker) ==
                    (ESCollector.isCredentialReadPath("/Users/x/project" + marker)
                     || ESCollector.isAgentContentReadPath("/Users/x/project" + marker)))
        }
    }

    @Test("the matcher reads a borrowed es_string_token_t in place")
    func protectedOpenMatcherOnToken() {
        for (path, expected) in [
            ("/Users/x/.ssh/id_ed25519", true),
            ("/Users/x/project/src/module.ts", false),
            ("/Users/x/.claude/settings.json", true),
        ] {
            var bytes = Array(path.utf8)
            let matched = bytes.withUnsafeMutableBufferPointer { buffer -> Bool in
                buffer.baseAddress!.withMemoryRebound(to: CChar.self, capacity: buffer.count) { base in
                    ESCollector.protectedOpenPathMarkers.matches(
                        es_string_token_t(length: buffer.count, data: base)
                    )
                }
            }
            #expect(matched == expected, "\(path)")
        }
        #expect(!ESCollector.protectedOpenPathMarkers.matches(es_string_token_t(length: 0, data: nil)))
    }

    @Test("a protected OPEN uses the worker reserve; an ordinary OPEN and SIGNAL never do")
    func workerReserveEligibility() {
        let open = ES_EVENT_TYPE_NOTIFY_OPEN.rawValue
        #expect(ESCollector.usesWorkerReserve(eventType: open, protectedOpen: true))
        #expect(!ESCollector.usesWorkerReserve(eventType: open, protectedOpen: false))
        #expect(!ESCollector.usesWorkerReserve(eventType: ES_EVENT_TYPE_NOTIFY_SIGNAL.rawValue, protectedOpen: true),
                "the flag is OPEN-only; it cannot promote another type")
        for type in [
            ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXIT,
            ES_EVENT_TYPE_NOTIFY_CREATE, ES_EVENT_TYPE_NOTIFY_WRITE, ES_EVENT_TYPE_NOTIFY_CLOSE,
            ES_EVENT_TYPE_NOTIFY_RENAME, ES_EVENT_TYPE_NOTIFY_UNLINK,
        ] {
            #expect(ESCollector.reserveEligibleRawValues.contains(type.rawValue))
            #expect(ESCollector.usesWorkerReserve(eventType: type.rawValue, protectedOpen: false))
        }
        for type in [
            ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_SIGNAL, ES_EVENT_TYPE_NOTIFY_MPROTECT,
            ES_EVENT_TYPE_NOTIFY_MMAP, ES_EVENT_TYPE_NOTIFY_GET_TASK_READ,
        ] {
            #expect(!ESCollector.reserveEligibleRawValues.contains(type.rawValue))
        }
    }

    @Test("the worker-stage OPEN policy honours the callback verdict and keeps the keychain gate first")
    func workerOpenPolicyUsesTheCallbackVerdict() {
        let open = ES_EVENT_TYPE_NOTIFY_OPEN.rawValue
        // Protected verdict → admitted without consulting the registry.
        #expect(!ESCollector.shouldDropBeforeWorker(eventType: open, path: "/Users/x/.ssh/id_ed25519", protectedPath: true))
        // The platform-binary keychain gate is absolute, verdict or not.
        #expect(ESCollector.shouldDropBeforeWorker(
            eventType: open, path: "/Users/x/Library/Keychains/login.keychain-db",
            isPlatformBinary: true, protectedPath: true))
        // No verdict carried → the String allowlists decide, as before.
        #expect(!ESCollector.shouldDropBeforeWorker(eventType: open, path: "/Users/x/.ssh/id_ed25519"))
        #expect(ESCollector.shouldDropBeforeWorker(eventType: open, path: "/usr/lib/libSystem.B.dylib"))
    }

    // MARK: NOTIFY_SIGNAL

    @Test("non-fatal signals are dropped even when aimed at MacCrab; the executable is never decoded for them")
    func nonFatalSignalsDropWithoutDecodingTheTarget() {
        var decodes = 0
        for sig: Int32 in [0, SIGCHLD, SIGUSR1, SIGUSR2, SIGCONT, SIGWINCH, SIGPIPE, SIGALRM] {
            let keep = ESCollector.shouldKeepSignal(
                sig: sig, targetPID: 77, ownPID: 77,
                targetExecutable: { decodes += 1; return "/usr/local/bin/com.maccrab.agent" }()
            )
            #expect(!keep, "signal \(sig) carries no detection input")
        }
        #expect(decodes == 0, "the path decode must stay off the callback for the signal flood")
    }

    @Test("fatal signals aimed at MacCrab itself or a security tool are kept")
    func fatalSignalsAtSecurityToolsAreKept() {
        for sig: Int32 in [SIGKILL, SIGTERM, SIGSTOP, SIGINT, SIGHUP, SIGQUIT, SIGABRT, SIGSEGV] {
            #expect(ESCollector.shouldKeepSignal(
                sig: sig, targetPID: 500, ownPID: 500, targetExecutable: "/anything"),
                    "fatal signal \(sig) at our own pid must be kept")
        }
        for executable in [
            "/Applications/MacCrab.app/Contents/Library/SystemExtensions/com.maccrab.agent.systemextension/Contents/MacOS/com.maccrab.agent",
            "/usr/local/bin/maccrabd",
            "/Applications/MacCrab.app/Contents/MacOS/MacCrab",
            "/Library/CS/falcond",
            "/Library/Sentinel/sentinel-agent.bundle/Contents/MacOS/sentineld",
            "/Library/Application Support/Microsoft/Defender/wdavdaemon",
            "/usr/local/bin/osqueryd",
            "/Library/Application Support/ESET/esets_daemon",
            "/Library/Application Support/PaloAltoNetworks/Traps/bin/traps_agent",
            "/Applications/LuLu.app/Contents/MacOS/LuLu",
            "/Applications/Santa.app/Contents/MacOS/santad",
        ] {
            #expect(ESCollector.shouldKeepSignal(
                sig: SIGKILL, targetPID: 900, ownPID: 1, targetExecutable: executable),
                    "SIGKILL at \(executable) is the self-defense observation")
        }
    }

    @Test("the signal keep-list is derived from EDRMonitor's .edr roster and the kill_persist sequence's tools")
    func securityToolRosterCannotDrift() {
        #expect(!EDRMonitor.edrProcessNames.isEmpty)
        for name in EDRMonitor.edrProcessNames {
            #expect(ESCollector.securityToolProcessNames.contains(name), "EDRMonitor .edr process \(name) missing from the keep-list")
        }
        for name in ["esets_daemon", "esets_proxy", "ESET", "traps_agent", "cortex_xdr"] {
            #expect(EDRMonitor.edrProcessNames.contains(name))
        }
        // Rules/sequences/defense_evasion_kill_persist.yml names these tools.
        for name in ["LuLu", "BlockBlock", "OverSight", "Santa", "santad",
                     "com.maccrab.agent", "maccrabd", "MacCrab", "maccrabctl", "maccrab-mcp"] {
            #expect(ESCollector.securityToolProcessNames.contains(name))
        }
    }

    @Test("fatal signals at ordinary processes are the build-storm flood and are dropped")
    func fatalSignalsAtOrdinaryProcessesDrop() {
        for executable in ["/usr/local/bin/node", "/bin/sh", "/usr/bin/git", "/Applications/Xcode.app/Contents/MacOS/Xcode"] {
            #expect(!ESCollector.shouldKeepSignal(
                sig: SIGTERM, targetPID: 901, ownPID: 1, targetExecutable: executable))
            #expect(!ESCollector.shouldKeepSignal(
                sig: SIGKILL, targetPID: 901, ownPID: 1, targetExecutable: executable))
        }
    }

    @Test("the callback applies the signal policy: the drop is counted as intentional filtering, never a loss")
    func callbackSignalPolicyIsIntentionalFiltering() {
        #expect(ESCollector.shouldDropAtCallback(
            eventType: ES_EVENT_TYPE_NOTIFY_SIGNAL.rawValue,
            signal: 0, signalTargetPID: 12, signalTargetExecutable: "/usr/local/bin/node"))
        #expect(!ESCollector.shouldDropAtCallback(
            eventType: ES_EVENT_TYPE_NOTIFY_SIGNAL.rawValue,
            signal: SIGKILL, signalTargetPID: ESCollector.ownProcessID, signalTargetExecutable: "/x"))
    }

    // MARK: Repeat coalescing

    private let bundle = "/Users/x/project/dist/bundle.js"

    @Test("the first WRITE always passes; repeats inside the window coalesce; the window closes on CLOSE and the count rides it")
    func firstWritePassesRepeatsCoalesceUntilClose() {
        let c = ESRepeatCoalescer(windowNanos: 2_000_000_000)
        #expect(!c.shouldCoalesce(path: bundle, pid: 43, pidversion: 7, kind: .write, nowNanos: 1_000))
        #expect(c.shouldCoalesce(path: bundle, pid: 43, pidversion: 7, kind: .write, nowNanos: 2_000))
        #expect(c.shouldCoalesce(path: bundle, pid: 43, pidversion: 7, kind: .write, nowNanos: 1_500_000_000))
        #expect(c.terminate(path: bundle, pid: 43, pidversion: 7) == 2, "the modified CLOSE carries the coalesced write count")
        // After the terminal event the next write is a new interaction.
        #expect(!c.shouldCoalesce(path: bundle, pid: 43, pidversion: 7, kind: .write, nowNanos: 1_600_000_000))
        #expect(c.terminate(path: bundle, pid: 43, pidversion: 7) == 0)
        #expect(c.count == 0)
    }

    @Test("the window is anchored at the yielded callback: a continuous writer is observed once per window, not once ever")
    func windowIsAnchoredNotSliding() {
        let c = ESRepeatCoalescer(windowNanos: 2_000_000_000)
        var yieldedAt: [UInt64] = []
        for second: UInt64 in 0...10 {
            if !c.shouldCoalesce(path: bundle, pid: 43, pidversion: 7, kind: .write,
                                 nowNanos: second * 1_000_000_000) {
                yieldedAt.append(second)
            }
        }
        #expect(yieldedAt == [0, 3, 6, 9], "one yield per window for a writer touching the file every second")
        #expect(c.terminate(path: bundle, pid: 43, pidversion: 7) == 7)
        // The sliding form: a repeat 1 ns before the window end must not
        // extend it past first + window.
        let open = ESRepeatCoalescer(windowNanos: 1_000)
        #expect(!open.shouldCoalesce(path: bundle, pid: 43, pidversion: 7, kind: .open, nowNanos: 10))
        #expect(open.shouldCoalesce(path: bundle, pid: 43, pidversion: 7, kind: .open, nowNanos: 1_009))
        #expect(open.shouldCoalesce(path: bundle, pid: 43, pidversion: 7, kind: .open, nowNanos: 1_010))
        #expect(!open.shouldCoalesce(path: bundle, pid: 43, pidversion: 7, kind: .open, nowNanos: 1_011),
                "first + window + 1 passes even though the previous repeat was 1 ns earlier")
    }

    @Test("a modified CLOSE by another process ends every reader's OPEN window on the path (read-after-third-party-write is observed)")
    func terminalByAnotherProcessEndsReaderWindows() {
        let c = ESRepeatCoalescer(windowNanos: 2_000_000_000)
        let doc = "/Users/x/project/docs/setup.md"
        // Agent (pid 43) reads; an unattributed writer (pid 99) rewrites it.
        #expect(!c.shouldCoalesce(path: doc, pid: 43, pidversion: 7, kind: .open, nowNanos: 0))
        #expect(c.terminate(path: doc, pid: 99, pidversion: 1) == 0, "the writer coalesced nothing")
        #expect(!c.shouldCoalesce(path: doc, pid: 43, pidversion: 7, kind: .open, nowNanos: 1_000_000_000),
                "the re-read inside the window must reach FileInjectionScanner: the file changed")
        // The writer's own WRITE window and count are untouched by a reader's terminal.
        #expect(!c.shouldCoalesce(path: doc, pid: 99, pidversion: 1, kind: .write, nowNanos: 1_100_000_000))
        #expect(c.shouldCoalesce(path: doc, pid: 99, pidversion: 1, kind: .write, nowNanos: 1_200_000_000))
        c.terminate(path: doc, pid: 43, pidversion: 7)   // pretend an UNLINK-shaped terminal by the reader
        #expect(c.shouldCoalesce(path: doc, pid: 99, pidversion: 1, kind: .write, nowNanos: 1_300_000_000),
                "another process's terminal leaves the writer's own WRITE window alone")
        #expect(c.terminate(path: doc, pid: 99, pidversion: 1) == 2)
        #expect(c.count == 0)
    }

    @Test("WRITE and OPEN windows are independent, and so are different pids, pidversions and paths")
    func windowsAreIndependentPerKindAndKey() {
        let c = ESRepeatCoalescer(windowNanos: 1_000_000)
        let a = "/Users/x/project/src/a.ts"
        #expect(!c.shouldCoalesce(path: a, pid: 43, pidversion: 7, kind: .write, nowNanos: 1))
        #expect(!c.shouldCoalesce(path: a, pid: 43, pidversion: 7, kind: .open, nowNanos: 2), "an OPEN is not a repeat of a WRITE")
        #expect(!c.shouldCoalesce(path: a, pid: 44, pidversion: 7, kind: .write, nowNanos: 3))
        #expect(!c.shouldCoalesce(path: a, pid: 43, pidversion: 8, kind: .write, nowNanos: 4),
                "a recycled pid with a new pidversion is a different process")
        #expect(!c.shouldCoalesce(path: "/Users/x/project/src/b.ts", pid: 43, pidversion: 7, kind: .write, nowNanos: 5))
        #expect(c.shouldCoalesce(path: a, pid: 43, pidversion: 7, kind: .write, nowNanos: 6))
        #expect(c.count == 4)
    }

    @Test("the entry table is bounded: a build touching more files than the capacity cannot grow it")
    func entryTableIsBounded() {
        let c = ESRepeatCoalescer(windowNanos: UInt64.max / 2, capacity: 64)
        for i in 0..<10_000 {
            _ = c.shouldCoalesce(path: "/Users/x/project/out/\(i).o", pid: 43, pidversion: 7, kind: .write, nowNanos: UInt64(i + 1))
            #expect(c.count <= 64)
        }
        // Many processes on one path count individually against the bound.
        let shared = ESRepeatCoalescer(windowNanos: UInt64.max / 2, capacity: 16)
        for pid in 0..<100 {
            _ = shared.shouldCoalesce(path: "/shared", pid: Int32(pid), pidversion: 1, kind: .open, nowNanos: UInt64(pid + 1))
            #expect(shared.count <= 16)
        }
        // Expired entries are swept before anything live is evicted.
        let short = ESRepeatCoalescer(windowNanos: 10, capacity: 4)
        for i in 0..<4 { _ = short.shouldCoalesce(path: "/f\(i)", pid: 1, pidversion: 1, kind: .write, nowNanos: 1) }
        _ = short.shouldCoalesce(path: "/fresh", pid: 1, pidversion: 1, kind: .write, nowNanos: 100)
        #expect(short.count == 1)
    }

    @Test("credential, honeyfile, persistence and agent-config paths are never coalesced")
    func consumerCriticalPathsAreExempt() {
        for path in [
            "/Users/x/.ssh/id_ed25519",
            "/Users/x/.aws/credentials",
            "/Users/x/Library/Application Support/MacCrab/decoys/passwords.txt",
            "/Users/x/Documents/passwords_backup.csv",
            "/Users/x/Library/LaunchAgents/com.evil.plist",
            "/Library/LaunchDaemons/com.evil.plist",
            "/Users/x/.zshrc", "/Users/x/.bash_profile",
            "/Users/x/.claude/settings.json",
            "/Users/x/.claude/skills/reviewer/SKILL.md",
            "/Users/x/project/.github/workflows/ci.yml",
            "/Library/StartupItems/Evil/Evil",
            "/Users/x/Library/LoginItems/x",
            // CredentialFence-only defaults the OPEN allowlist does not spell out.
            "/Users/x/project/.env.development", "/Users/x/.config/gh/config.yml",
            "/Users/x/snap/gcloud/credentials.db", "/Users/x/.azure/anything",
            "/Users/x/Library/Application Support/BraveSoftware/Default/Login Data",
            "/Users/x/Library/Application Support/Firefox/Profiles/a/logins.json",
        ] {
            #expect(ESCollector.isRepeatCoalescingExempt(path: path), "\(path) must keep every callback")
        }
        for path in [
            "/Users/x/project/dist/bundle.js",
            "/Users/x/project/node_modules/.cache/esbuild/x.json",
            "/private/var/folders/hf/T/artifact.o",
            "/Users/x/project/README.md",
        ] {
            #expect(!ESCollector.isRepeatCoalescingExempt(path: path), "\(path) is build churn")
        }
    }

    @Test("only WRITE and OPEN are coalescable kinds")
    func coalescableKinds() {
        #expect(ESCollector.repeatCoalescingKind(for: ES_EVENT_TYPE_NOTIFY_WRITE.rawValue) == .write)
        #expect(ESCollector.repeatCoalescingKind(for: ES_EVENT_TYPE_NOTIFY_OPEN.rawValue) == .open)
        for type in [
            ES_EVENT_TYPE_NOTIFY_CREATE, ES_EVENT_TYPE_NOTIFY_CLOSE, ES_EVENT_TYPE_NOTIFY_RENAME,
            ES_EVENT_TYPE_NOTIFY_UNLINK, ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_SETMODE,
        ] {
            #expect(ESCollector.repeatCoalescingKind(for: type.rawValue) == nil)
        }
    }

    // MARK: Lane routing

    private func open(_ path: String, enrichments: [String: String] = [:]) -> Event {
        Event(
            timestamp: Date(timeIntervalSince1970: 1_700_000_000),
            eventCategory: .file, eventType: .change, eventAction: "open",
            process: MacCrabCore.ProcessInfo(
                pid: 43, ppid: 42, rpid: 42, name: "node", executable: "/usr/local/bin/node",
                commandLine: "node", args: ["node"], workingDirectory: "/Users/x/project",
                userId: 501, userName: "x", groupId: 20,
                startTime: Date(timeIntervalSince1970: 1_700_000_000), isPlatformBinary: false),
            file: FileInfo(path: path, action: .open),
            enrichments: enrichments
        )
    }

    @Test("a credential or agent-content open keeps the priority lane; only a dynamic-AI-stamped open rides file")
    func openLaneSplitsByAdmissionClass() {
        #expect(!EventPipelineLane.routesToFile(.file, action: "open"))
        #expect(!EventPipelineLane.routesToFile(.file, action: "btm_add"))
        #expect(EventPipelineLane.finalLane(for: open("/Users/x/.ssh/id_ed25519")) == .priority)
        #expect(EventPipelineLane.finalLane(for: open("/Users/x/.claude/settings.json")) == .priority)
        let stamp = [EventPipelineLane.openAdmissionEnrichmentKey: EventPipelineLane.dynamicAIOpenAdmission]
        #expect(EventPipelineLane.finalLane(for: open("/Users/x/project/README.md", enrichments: stamp)) == .file)
        #expect(EventPipelineLane.finalLane(for: open("/Users/x/project/README.md")) == .priority,
                "an unstamped open (a non-ES producer) keeps the pre-v1.22.7 lane")
        for category in EventCategory.allCases where category != .file {
            #expect(!EventPipelineLane.routesToFile(category, action: "open"))
        }
    }

    // MARK: Tracker ledger

    @Test("worker-side policy rejects and coalesced repeats are counted per type and survive reset semantics")
    func trackerLedgerForWorkerStage() {
        let t = ESSeqTracker()
        t.recordFilteredOnWorker(eventType: ES_EVENT_TYPE_NOTIFY_OPEN.rawValue)
        t.recordFilteredOnWorker(eventType: ES_EVENT_TYPE_NOTIFY_OPEN.rawValue)
        t.recordCoalescedOnWorker(eventType: ES_EVENT_TYPE_NOTIFY_WRITE.rawValue)
        #expect(t.intentionallyFilteredOnWorkerByType()[ES_EVENT_TYPE_NOTIFY_OPEN.rawValue] == 2)
        #expect(t.coalescedOnWorkerByType()[ES_EVENT_TYPE_NOTIFY_WRITE.rawValue] == 1)
        #expect(t.processedByType()[ES_EVENT_TYPE_NOTIFY_OPEN.rawValue] == 2,
                "a worker-side policy reject still belongs in the processed denominator")
        #expect(t.processedByType()[ES_EVENT_TYPE_NOTIFY_WRITE.rawValue] == 1)
        t.reset()
        #expect(t.intentionallyFilteredOnWorkerByType().isEmpty)
        #expect(t.coalescedOnWorkerByType().isEmpty)
    }
}
