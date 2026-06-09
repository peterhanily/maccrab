// `maccrabctl mcfp corpus collect / diff` + `maccrabctl mcfp
// imposter` — MCFP R2 prep tooling per plan §6.4.
//
// Used to populate docs/mcfp-research/corpus-{hostname}.jsonl and
// produce the cross-Mac diff + imposter divergence reports the
// R2 ship-decision depends on.

import Foundation
import MacCrabForensics

func dispatchMCFP(args: [String]) async {
    guard let sub = args.first else {
        printMCFPUsage()
        exit(0)
    }
    let rest = Array(args.dropFirst())
    switch sub {
    case "corpus":
        await dispatchCorpus(args: rest)
    case "imposter":
        await runImposter(args: rest)
    case "separation":
        await runSeparation(args: rest)
    case "help", "-h", "--help":
        printMCFPUsage()
    default:
        print("Unknown mcfp subcommand: \(sub)")
        printMCFPUsage()
        exit(1)
    }
}

private func printMCFPUsage() {
    print("""
    Usage: maccrabctl mcfp <subcommand>

    Subcommands:
      corpus collect --target <dir> --output <jsonl>
          Walk <dir>, fingerprint every Mach-O via MCFPStatic,
          write one JSONL row per binary. Used by plan §6.4 R2.

      corpus diff <corpus-a.jsonl> <corpus-b.jsonl>
          Compare two corpus files. Reports per-component
          stability + R2 verdict.

      imposter --target <binary-path>
          Run the R2 imposter experiment: copy + strip-sign +
          re-fingerprint. Expects cs + ent divergence.

      separation <corpus.jsonl>
          Different-family separation measurement (plan §6.4 R2).
          Computes %% of cross-family pairs with diverging cs or
          ent components + Wilson 95%% CI. Verdict PASS when CI
          lower-bound ≥ 80%%.
    """)
}

private func dispatchCorpus(args: [String]) async {
    guard let sub = args.first else {
        printMCFPUsage()
        exit(0)
    }
    let rest = Array(args.dropFirst())
    switch sub {
    case "collect":
        await runCorpusCollect(args: rest)
    case "diff":
        await runCorpusDiff(args: rest)
    default:
        print("Unknown corpus subcommand: \(sub)")
        printMCFPUsage()
        exit(1)
    }
}

private func runCorpusCollect(args: [String]) async {
    var target: String? = nil
    var output: String? = nil
    var i = 0
    while i < args.count {
        switch args[i] {
        case "--target" where i + 1 < args.count:
            target = args[i+1]; i += 2
        case "--output" where i + 1 < args.count:
            output = args[i+1]; i += 2
        default:
            i += 1
        }
    }
    guard let target = target, let output = output else {
        print("Usage: maccrabctl mcfp corpus collect --target <dir> --output <jsonl>")
        exit(1)
    }
    print("Collecting MCFP corpus from \(target) → \(output)")
    do {
        let stats = try await CorpusCollector.collect(target: target, outputPath: output) { path in
            // Minimal progress — print every 50th binary for
            // long runs.
            // (Caller's terminal doesn't need to see every line.)
        }
        print("Collected: \(stats.collected) binaries fingerprinted, \(stats.skipped) skipped (non-Mach-O or unreadable).")
        print("Wrote: \(output)")
    } catch {
        print("Corpus collect failed: \(error)")
        exit(1)
    }
}

private func runCorpusDiff(args: [String]) async {
    guard args.count >= 2 else {
        print("Usage: maccrabctl mcfp corpus diff <corpus-a.jsonl> <corpus-b.jsonl>")
        exit(1)
    }
    let a = args[0]
    let b = args[1]
    do {
        let corpusA = try CorpusCollector.load(corpusPath: a)
        let corpusB = try CorpusCollector.load(corpusPath: b)
        let report = CorpusDiff.diff(corpusA: corpusA, corpusB: corpusB)
        print("MCFP R2 Cross-Mac Stability Report")
        print("===================================")
        print("Corpus A: \(a) (\(corpusA.count) binaries)")
        print("Corpus B: \(b) (\(corpusB.count) binaries)")
        print("Matched (present in both): \(report.matchedBinaryCount)")
        print("Only in A: \(report.onlyInA)")
        print("Only in B: \(report.onlyInB)")
        print("")
        print("Per-component same-binary stability:")
        print(String(format: "  arch  %6.2f%%", report.archStabilityPercent))
        print(String(format: "  lc    %6.2f%%", report.lcStabilityPercent))
        print(String(format: "  cs    %6.2f%%", report.csStabilityPercent))
        print(String(format: "  ent   %6.2f%%", report.entStabilityPercent))
        print(String(format: "  sha256(file) %6.2f%%", report.fileSha256StabilityPercent))
        print("")
        print("R2 ship verdict (plan §6.4 — ≥3 components at ≥95%): \(report.r2StabilityVerdict.rawValue.uppercased())")
        let cis = report.stabilityConfidenceIntervals()
        if !cis.isEmpty {
            print("")
            print("Wilson 95% CI per component (lower bound is the conservative ship gate):")
            for ci in cis {
                print("  \(ci.component.padding(toLength: 4, withPad: " ", startingAt: 0))  point " + String(
                    format: "%6.2f%%   95%% CI [%5.2f%%, %5.2f%%]",
                    ci.pointEstimatePct, ci.ci95LowerPct, ci.ci95UpperPct
                ))
            }
        }
        if !report.divergenceSamples.isEmpty {
            print("")
            print("Divergence samples (first \(report.divergenceSamples.count)):")
            for s in report.divergenceSamples.prefix(10) {
                let cols = [
                    s.archDiverged ? "arch" : "",
                    s.lcDiverged ? "lc" : "",
                    s.csDiverged ? "cs" : "",
                    s.entDiverged ? "ent" : "",
                ].filter { !$0.isEmpty }.joined(separator: ",")
                print("  \(s.path)  [\(cols)]")
            }
        }
    } catch {
        print("Corpus diff failed: \(error)")
        exit(1)
    }
}

private func runSeparation(args: [String]) async {
    guard let corpusPath = args.first else {
        print("Usage: maccrabctl mcfp separation <corpus.jsonl>")
        exit(1)
    }
    do {
        let entries = try CorpusCollector.load(corpusPath: corpusPath)
        let report = MCFPStatistics.differentFamilySeparation(entries: entries) { entry in
            MCFPStatistics.defaultFamilyToken(forPath: entry.path)
        }
        print("MCFP R2 Different-Family Separation")
        print("====================================")
        print("Corpus:               \(corpusPath) (\(entries.count) binaries)")
        print("Distinct families:    \(report.familyCount)")
        print("Pairs compared:       \(report.pairsCompared)")
        print(String(format: "Pairs cs∨ent differ:  %d  (%6.2f%%)", report.csOrEntDifferentCount, report.csOrEntSeparationPercent))
        print(String(format: "Pairs fully differ:   %d  (%6.2f%%)", report.fullyDifferentCount, report.fullSeparationPercent))
        print(String(format: "95%% CI:              [%6.2f%%, %6.2f%%]", report.ci95Lower, report.ci95Upper))
        print("")
        print("R2 separation verdict (CI lower-bound ≥ 80%): \(report.verdict.rawValue.uppercased())")
    } catch {
        print("Separation run failed: \(error)")
        exit(1)
    }
}

private func runImposter(args: [String]) async {
    var target: String? = nil
    var i = 0
    while i < args.count {
        switch args[i] {
        case "--target" where i + 1 < args.count:
            target = args[i+1]; i += 2
        default:
            i += 1
        }
    }
    guard let target = target else {
        print("Usage: maccrabctl mcfp imposter --target <binary-path>")
        exit(1)
    }
    do {
        let report = try await ImposterHarness.run(target: target)
        print("MCFP R2 Imposter Experiment")
        print("===========================")
        print("Target:   \(report.targetPath)")
        print("Imposter: \(report.imposterPath)")
        print("")
        print("Original:  \(report.originalCanonical)")
        print("Imposter:  \(report.imposterCanonical)")
        print("")
        print("Divergence:")
        print("  arch \(report.archDiverged ? "✓" : "—")")
        print("  lc   \(report.lcDiverged ? "✓" : "—")")
        print("  cs   \(report.csDiverged ? "✓" : "—")")
        print("  ent  \(report.entDiverged ? "✓" : "—")")
        print("")
        print("R2 imposter verdict (expect cs + ent both diverged): \(report.r2ImposterVerdict.rawValue.uppercased())")
    } catch {
        print("Imposter run failed: \(error)")
        exit(1)
    }
}
