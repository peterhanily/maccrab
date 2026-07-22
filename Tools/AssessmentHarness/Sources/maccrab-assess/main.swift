import Foundation
import HarnessCore

// assessment-framework (P0): trigger/orchestrate CLI. Lives in the NON-SHIPPING
// harness sub-package. For P0 every subcommand is a stub EXCEPT `run`, which is
// wired far enough to emit a well-formed empty AssessmentReport so the Codable
// wire schema is exercised end-to-end. Real orchestration lands in P1+.

// Exit codes: 0 = ok, 2 = usage error.
let EXIT_OK: Int32 = 0
let EXIT_USAGE: Int32 = 2

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

    let report = AssessmentReport(
        schemaVersion: currentAssessmentSchemaVersion,
        maccrabVersion: gitValue(["describe", "--tags", "--always"]) ?? "unknown",
        commit: gitValue(["rev-parse", "--short", "HEAD"]) ?? "unknown",
        hostProfile: hostProfile,
        lanesRun: lanes,
        featureVerdicts: [],
        summary: Summary(pass: 0, fail: 0, skip: 0, inconclusive: 0),
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
        print("wrote empty assessment report → \(outPath)")
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
    exit(stub("diff"))
case "verify":
    exit(stub("verify"))
default:
    FileHandle.standardError.write(Data("error: unknown subcommand '\(subcommand)'\n".utf8))
    printUsage()
    exit(EXIT_USAGE)
}
