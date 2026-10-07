// ESIngressAdmissionTests.swift
// MacCrabCoreTests
//
// v1.22.7 ES ingress throughput. Unit coverage for the three new admission
// decisions and the one routing change:
//
//   • the callback-boundary policy is FIELD-ONLY (no path decode) — every
//     path-dependent decision now runs on the retained-message worker;
//   • NOTIFY_SIGNAL is dropped at the callback unless it is a fatal signal aimed
//     at MacCrab itself or at a security tool (no rule, sequence, graph rule,
//     built-in heuristic or AI Guard consumer reads signal events);
//   • repeated WRITE/OPEN by the same (pid, pidversion) on the same path inside
//     the window are coalesced on the worker — the first always passes, and
//     credential / honeyfile / persistence / agent-config paths are exempt;
//   • `open` rides the file lane so an OPEN flood cannot evict exec/fork/exit.
//
// Every case that a consumer needs is written as a must-pass assertion.

import Darwin
import EndpointSecurity
import Testing
@testable import MacCrabCore

@Suite("ES ingress admission (v1.22.7)")
struct ESIngressAdmissionTests {

    // MARK: Callback boundary is field-only

    @Test("path-dependent types are never decided at the callback: they always reach the worker")
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
        ] {
            #expect(ESCollector.shouldKeepSignal(
                sig: SIGKILL, targetPID: 900, ownPID: 1, targetExecutable: executable),
                    "SIGKILL at \(executable) is the self-defense observation")
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

    // MARK: Worker reserve

    @Test("the worker reserve protects lineage AND the write family, never OPEN or SIGNAL")
    func reserveEligibilityIsLineageAndWriteFamily() {
        for type in [
            ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXIT,
            ES_EVENT_TYPE_NOTIFY_CREATE, ES_EVENT_TYPE_NOTIFY_WRITE, ES_EVENT_TYPE_NOTIFY_CLOSE,
            ES_EVENT_TYPE_NOTIFY_RENAME, ES_EVENT_TYPE_NOTIFY_UNLINK,
        ] {
            #expect(ESCollector.reserveEligibleRawValues.contains(type.rawValue))
        }
        for type in [
            ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_SIGNAL, ES_EVENT_TYPE_NOTIFY_MPROTECT,
            ES_EVENT_TYPE_NOTIFY_MMAP, ES_EVENT_TYPE_NOTIFY_GET_TASK_READ,
        ] {
            #expect(!ESCollector.reserveEligibleRawValues.contains(type.rawValue))
        }
    }

    // MARK: Repeat coalescing

    private func key(_ path: String, pid: Int32 = 43, pidversion: UInt32 = 7) -> ESRepeatCoalescer.Key {
        ESRepeatCoalescer.Key(pid: pid, pidversion: pidversion, path: path)
    }

    @Test("the first WRITE always passes; repeats inside the window coalesce; the window closes on CLOSE")
    func firstWritePassesRepeatsCoalesceUntilClose() {
        let coalescer = ESRepeatCoalescer(windowNanos: 2_000_000_000)
        let k = key("/Users/x/project/dist/bundle.js")
        #expect(!coalescer.shouldCoalesce(k, kind: .write, nowNanos: 1_000))
        #expect(coalescer.shouldCoalesce(k, kind: .write, nowNanos: 2_000))
        #expect(coalescer.shouldCoalesce(k, kind: .write, nowNanos: 1_500_000_000))
        #expect(coalescer.terminate(k) == 2, "the modified CLOSE carries the coalesced write count")
        // After the terminal event the next write is a new interaction.
        #expect(!coalescer.shouldCoalesce(k, kind: .write, nowNanos: 1_600_000_000))
        #expect(coalescer.terminate(k) == 0)
    }

    @Test("a repeat after the window is a new observation and passes")
    func repeatAfterWindowPasses() {
        let coalescer = ESRepeatCoalescer(windowNanos: 1_000)
        let k = key("/Users/x/project/src/a.ts")
        #expect(!coalescer.shouldCoalesce(k, kind: .open, nowNanos: 10))
        #expect(coalescer.shouldCoalesce(k, kind: .open, nowNanos: 1_000))
        #expect(!coalescer.shouldCoalesce(k, kind: .open, nowNanos: 2_001))
    }

    @Test("WRITE and OPEN windows are independent, and so are different pids, pidversions and paths")
    func windowsAreIndependentPerKindAndKey() {
        let coalescer = ESRepeatCoalescer(windowNanos: 1_000_000)
        let k = key("/Users/x/project/src/a.ts")
        #expect(!coalescer.shouldCoalesce(k, kind: .write, nowNanos: 1))
        #expect(!coalescer.shouldCoalesce(k, kind: .open, nowNanos: 2), "an OPEN is not a repeat of a WRITE")
        #expect(!coalescer.shouldCoalesce(key("/Users/x/project/src/a.ts", pid: 44), kind: .write, nowNanos: 3))
        #expect(!coalescer.shouldCoalesce(key("/Users/x/project/src/a.ts", pidversion: 8), kind: .write, nowNanos: 4),
                "a recycled pid with a new pidversion is a different process")
        #expect(!coalescer.shouldCoalesce(key("/Users/x/project/src/b.ts"), kind: .write, nowNanos: 5))
        #expect(coalescer.shouldCoalesce(k, kind: .write, nowNanos: 6))
    }

    @Test("the key table is bounded: a build touching more files than the capacity cannot grow it")
    func keyTableIsBounded() {
        let coalescer = ESRepeatCoalescer(windowNanos: UInt64.max / 2, capacity: 64)
        for i in 0..<10_000 {
            _ = coalescer.shouldCoalesce(key("/Users/x/project/out/\(i).o"), kind: .write, nowNanos: UInt64(i + 1))
            #expect(coalescer.count <= 64)
        }
        // Expired keys are swept before anything live is evicted.
        let short = ESRepeatCoalescer(windowNanos: 10, capacity: 4)
        for i in 0..<4 { _ = short.shouldCoalesce(key("/f\(i)"), kind: .write, nowNanos: 1) }
        _ = short.shouldCoalesce(key("/fresh"), kind: .write, nowNanos: 100)
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
            "/Users/x/.zshrc",
            "/Users/x/.claude/settings.json",
            "/Users/x/.claude/skills/reviewer/SKILL.md",
            "/Users/x/project/.github/workflows/ci.yml",
            "/Library/StartupItems/Evil/Evil",
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

    @Test("open rides the file lane; btm_add and every non-file category keep the priority lane")
    func openRidesTheFileLane() {
        #expect(EventPipelineLane.routesToFile(.file, action: "open"))
        #expect(!EventPipelineLane.routesToFile(.file, action: "btm_add"))
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
