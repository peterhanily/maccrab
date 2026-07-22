import Foundation
import HarnessCore

// assessment-framework (P0): trigger/orchestrate CLI. Lives in the NON-SHIPPING
// harness sub-package. For P0 every subcommand is a stub EXCEPT `run`, which is
// wired far enough to emit a well-formed empty AssessmentReport so the Codable
// wire schema is exercised end-to-end. Real orchestration lands in P1+.

// Exit codes: 0 = ok, 2 = usage error.
let EXIT_OK: Int32 = 0
let EXIT_USAGE: Int32 = 2

/// Runs the async offline-replay lane from the synchronous CLI entry point.
func blockingReplay(corpus: TechniqueCorpus) -> Result<DetectionScore, Error> {
    let sem = DispatchSemaphore(value: 0)
    var out: Result<DetectionScore, Error>!
    Task {
        do { out = .success(try await OfflineReplayLane().run(corpus: corpus)) }
        catch { out = .failure(error) }
        sem.signal()
    }
    sem.wait()
    return out
}

func fmtOpt(_ d: Double?) -> String { d.map { String(format: "%.3f", $0) } ?? "—" }

let arguments = Array(CommandLine.arguments.dropFirst())

func printUsage() {
    print("""
    maccrab-assess — MacCrab agent-driven assessment harness (non-shipping)

    USAGE:
      maccrab-assess run [--lane <lane>]... [--feature <id>]... [--profile user|root] [--out DIR]
      maccrab-assess report [--run DIR] [--format json|md]
      maccrab-assess diff <baseline.json> [--against run.json]
      maccrab-assess verify <assessment.json>
      maccrab-assess --help

    LANES:
      offline_replay, seeded_store, live_trigger

    P0 STATUS:
      `run` emits a well-formed empty assessment.json. All other subcommands are
      stubs that land in P1+.
    """)
}

/// Best-effort read of a single-line git value; returns nil on any failure so the
/// caller can fall back to "unknown". Runs from the repo the harness lives in.
func gitValue(_ args: [String]) -> String? {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
    process.arguments = ["git"] + args
    process.currentDirectoryURL = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
    let pipe = Pipe()
    process.standardOutput = pipe
    process.standardError = Pipe()
    do {
        try process.run()
        process.waitUntilExit()
    } catch {
        return nil
    }
    guard process.terminationStatus == 0 else { return nil }
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    let value = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
    return value.isEmpty ? nil : value
}

/// Pulls the next value for a repeatable/scalar flag out of the argument list.
func values(for flag: String, in args: [String]) -> [String] {
    var out: [String] = []
    var index = 0
    while index < args.count {
        if args[index] == flag, index + 1 < args.count {
            out.append(args[index + 1])
            index += 2
        } else {
            index += 1
        }
    }
    return out
}

func runSubcommand(_ args: [String]) -> Int32 {
    let laneStrings = values(for: "--lane", in: args)
    var lanes: [Lane] = []
    for raw in laneStrings {
        guard let lane = Lane(rawValue: raw) else {
            FileHandle.standardError.write(Data("error: unknown lane '\(raw)'\n".utf8))
            return EXIT_USAGE
        }
        lanes.append(lane)
    }

    let profile = values(for: "--profile", in: args).last
        ?? (geteuid() == 0 ? "root" : "user")
    let outDir = values(for: "--out", in: args).last ?? "./assessment-run"

    let hostProfile = HostProfile(
        privilegeLane: profile,
        esEntitled: false, // best-effort; real entitlement probe lands in P1+
        os: ProcessInfo.processInfo.operatingSystemVersionString
    )

    // P1: run the offline-replay lane when requested (via --lane offline_replay
    // or --technique). Today one technique (T1059.004 reverse shell) is wired;
    // the corpus registry grows in later phases.
    let techniques = values(for: "--technique", in: args)
    var verdicts: [VerdictRecord] = []
    if lanes.contains(.offlineReplay) || !techniques.isEmpty {
        let corpus = Corpora.reverseShell
        switch blockingReplay(corpus: corpus) {
        case .success(let score):
            let result = PrecisionOracle().decide(
                observed: score, expected: .init(technique: corpus.technique), thresholds: .default)
            verdicts.append(VerdictRecord(
                featureId: corpus.targetRuleName,
                lane: .offlineReplay,
                triggerRef: TriggerRef(source: "offline-corpus", testGuid: corpus.technique, cmdSha256: nil),
                expectedRuleId: corpus.targetRuleId,
                expectedMinSeverity: "critical",
                observedFired: (score.tp ?? 0) > 0,
                observedAlertId: nil,
                verdict: result.verdict,
                oracle: "PrecisionOracle@v1",
                measured: score,
                requiresRoot: false,
                evidenceRef: nil,
                timestamp: ""
            ))
            print("""
            \(corpus.technique) \(corpus.targetRuleName): \(result.verdict.rawValue.uppercased()) \
            (precision \(fmtOpt(score.precision)), held-out recall \(fmtOpt(score.heldOutRecall)), \
            obfuscation \(fmtOpt(score.obfuscationCoverage)); tp=\(score.tp ?? 0) fp=\(score.fp ?? 0) fn=\(score.fn ?? 0))
            """)
        case .failure(let err):
            FileHandle.standardError.write(Data("error: offline lane failed: \(err)\n".utf8))
            return EXIT_USAGE
        }
    }

    // P5: the live-trigger lane, gated hard by the disposable-host guard. On any
    // normal machine this refuses (safe by design); it runs only on a sacrificial
    // ES-entitled runner.
    if lanes.contains(.liveTrigger) {
        switch LiveTriggerLane().run(manifest: LiveTriggerLane.starterManifest) {
        case .refused(let reason):
            print("live_trigger: REFUSED — \(reason)")
        case .ran(let liveVerdicts):
            verdicts.append(contentsOf: liveVerdicts)
            print("live_trigger: ran \(liveVerdicts.count) trigger(s) on a disposable host")
        }
    }

    func tally(_ v: Verdict) -> Int { verdicts.filter { $0.verdict == v }.count }
    let report = AssessmentReport(
        schemaVersion: currentAssessmentSchemaVersion,
        maccrabVersion: gitValue(["describe", "--tags", "--always"]) ?? "unknown",
        commit: gitValue(["rev-parse", "--short", "HEAD"]) ?? "unknown",
        hostProfile: hostProfile,
        lanesRun: lanes.isEmpty && !verdicts.isEmpty ? [.offlineReplay] : lanes,
        featureVerdicts: verdicts,
        summary: Summary(pass: tally(.pass), fail: tally(.fail),
                         skip: tally(.skip), inconclusive: tally(.inconclusive)),
        regressions: [],
        evidenceBundleRef: nil,
        signature: nil
    )

    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]

    do {
        let data = try encoder.encode(report)
        try FileManager.default.createDirectory(
            atPath: outDir, withIntermediateDirectories: true
        )
        let outPath = (outDir as NSString).appendingPathComponent("assessment.json")
        try data.write(to: URL(fileURLWithPath: outPath))
        let label = verdicts.isEmpty ? "empty assessment report" : "assessment report (\(verdicts.count) verdict(s))"
        print("wrote \(label) → \(outPath)")
        return EXIT_OK
    } catch {
        FileHandle.standardError.write(Data("error: \(error)\n".utf8))
        return EXIT_USAGE
    }
}

func stub(_ name: String) -> Int32 {
    print("\(name): not yet implemented — lands in P1+")
    return EXIT_OK
}

/// P4: `diff <baseline.json> [--against <run.json>]` — regression gate.
/// Exit 0 = no regression; 1 = regression(s) found; 2 = usage/IO error.
func diffSubcommand(_ args: [String]) -> Int32 {
    let positionals = args.filter { !$0.hasPrefix("--") }
    guard let baselinePath = positionals.first else {
        FileHandle.standardError.write(Data("error: diff needs <baseline.json>\n".utf8))
        return EXIT_USAGE
    }
    let againstPath = values(for: "--against", in: args).last ?? positionals.dropFirst().first
    guard let againstPath else {
        FileHandle.standardError.write(Data("error: diff needs --against <run.json> (or a second path)\n".utf8))
        return EXIT_USAGE
    }
    let decoder = JSONDecoder()
    do {
        let baseline = try decoder.decode(AssessmentReport.self,
            from: Data(contentsOf: URL(fileURLWithPath: baselinePath)))
        let current = try decoder.decode(AssessmentReport.self,
            from: Data(contentsOf: URL(fileURLWithPath: againstPath)))
        let result = RegressionOracle().diff(baseline: baseline, current: current)
        if result.regressed {
            print("REGRESSION — \(result.regressions.count) axis/axes regressed vs baseline:")
            for r in result.regressions {
                print("  \(r.ruleId) · \(r.axis): \(fmtOpt(r.was)) → \(fmtOpt(r.now))")
            }
            return 1
        }
        print("no regression vs baseline (\(current.featureVerdicts.count) feature(s) compared)")
        return EXIT_OK
    } catch {
        FileHandle.standardError.write(Data("error: \(error)\n".utf8))
        return EXIT_USAGE
    }
}

// Dispatch.
guard let subcommand = arguments.first else {
    printUsage()
    exit(EXIT_USAGE)
}

let rest = Array(arguments.dropFirst())

switch subcommand {
case "--help", "-h", "help":
    printUsage()
    exit(EXIT_OK)
case "run":
    exit(runSubcommand(rest))
case "report":
    exit(stub("report"))
case "diff":
    exit(diffSubcommand(rest))
case "verify":
    exit(stub("verify"))
default:
    FileHandle.standardError.write(Data("error: unknown subcommand '\(subcommand)'\n".utf8))
    printUsage()
    exit(EXIT_USAGE)
}
