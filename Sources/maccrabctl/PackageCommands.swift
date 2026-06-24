// `maccrabctl package` subcommands — operator-facing CLI parity for the
// v1.12.0 Package Intelligence + Intent Classification analyzers that were
// previously MCP-only (check_typosquat_score, scan_package_content,
// analyze_package_metadata, verify_package_attestation,
// classify_package_intent).
//
// Each subcommand constructs the SAME public MacCrabCore analyzer the MCP
// handler in Sources/maccrab-mcp/main.swift uses and prints the same fields.
// No detection logic is reimplemented here.

import Foundation
import MacCrabCore

enum PackageCommandError: Error, CustomStringConvertible {
    case usage(String)
    case underlying(String)

    var description: String {
        switch self {
        case .usage(let msg): return msg
        case .underlying(let msg): return msg
        }
    }
}

/// Dispatch `maccrabctl package <subcommand> ...`. Called from
/// MacCrabCtl.main when args[1] == "package".
func dispatchPackage(args: [String]) async {
    guard let sub = args.first else {
        printPackageUsage()
        exit(0)
    }
    let rest = Array(args.dropFirst())

    do {
        switch sub {
        case "typosquat":
            try await packageTyposquat(args: rest)
        case "content":
            try await packageContent(args: rest)
        case "metadata":
            try await packageMetadata(args: rest)
        case "attestation":
            try await packageAttestation(args: rest)
        case "intent":
            try await packageIntent(args: rest)
        case "help", "-h", "--help":
            printPackageUsage()
        default:
            print("Unknown package subcommand: \(sub)")
            printPackageUsage()
            exit(1)
        }
    } catch let PackageCommandError.usage(msg) {
        print(msg)
        exit(1)
    } catch {
        print("Error: \(error)")
        exit(1)
    }
}

func printPackageUsage() {
    print("""
    Usage: maccrabctl package <subcommand>

    Supply-chain package intelligence (parity with the MCP package tools).

    Subcommands:
      typosquat <name> --registry npm|pypi
                                          Score a package name against the
                                          bundled popular-name corpus
                                          (Damerau-Levenshtein + confusable fold).
      content <path> --ecosystem npm|pypi|homebrew
                                          Walk an installed package directory and
                                          compute a content-anomaly score.
      metadata <name> --registry npm|pypi
                                          Fetch + score one registry metadata doc
                                          (one HTTP GET per package per 24h).
      attestation <name> --version <ver> --registry npm|pypi [--prior-builder <id>]
                                          Verify cryptographic provenance
                                          (npm Sigstore / PyPI PEP 740).
      intent <package_name> --registry npm|pypi|brew [--version <ver>]
             [--installer <p> ...] [--cred-read <path> ...] [--egress <host> ...]
             [--file-written <path> ...] [--spawned <p> ...]
             [--obfuscated] [--bundled-runtime] [--language-mismatch] [--ai-triggered]
                                          Classify package install intent. Uses a
                                          configured LLM backend when available,
                                          else the deterministic heuristic.
    """)
}

// MARK: - typosquat

private func packageTyposquat(args: [String]) async throws {
    var name: String? = nil
    var registryRaw: String? = nil
    var i = 0
    while i < args.count {
        switch args[i] {
        case "--registry" where i + 1 < args.count:
            registryRaw = args[i+1]; i += 2
        default:
            if !args[i].hasPrefix("--") && name == nil { name = args[i] }
            i += 1
        }
    }
    guard let name = name, let registryRaw = registryRaw,
          let registry = TyposquatDatabase.Registry(rawValue: registryRaw) else {
        throw PackageCommandError.usage("Usage: maccrabctl package typosquat <name> --registry npm|pypi")
    }
    let db = TyposquatDatabase()
    let result = await db.score(candidate: name, registry: registry)
    print("Typosquat scan: \(name) (\(registry.rawValue))")
    print("Score: \(result.score)/100")
    if let similar = result.similarTo, let distance = result.distance {
        print("Closest popular: '\(similar)' (Damerau-Levenshtein \(distance))")
    } else {
        print("No nearby popular name in the bundled package-name corpus")
    }
    print("Homoglyph: \(result.isHomoglyph ? "YES" : "no")")
    for reason in result.reasons { print("- \(reason)") }
}

// MARK: - content

private func packageContent(args: [String]) async throws {
    var path: String? = nil
    var ecosystemRaw: String? = nil
    var i = 0
    while i < args.count {
        switch args[i] {
        case "--ecosystem" where i + 1 < args.count:
            ecosystemRaw = args[i+1]; i += 2
        default:
            if !args[i].hasPrefix("--") && path == nil { path = args[i] }
            i += 1
        }
    }
    guard let path = path, let ecosystemRaw = ecosystemRaw,
          let ecosystem = PackageContentAnalyzer.Ecosystem(rawValue: ecosystemRaw) else {
        throw PackageCommandError.usage("Usage: maccrabctl package content <path> --ecosystem npm|pypi|homebrew")
    }
    let analyzer = PackageContentAnalyzer()
    let result = await analyzer.analyze(packagePath: URL(fileURLWithPath: path), ecosystem: ecosystem)
    print("Content scan: \(path)")
    print("Score: \(result.score)/100")
    print("Total bytes: \(result.totalBytes)")
    print("File count: \(result.fileCount)")
    if !result.singleLineLargeFiles.isEmpty {
        print("Single-line large files: \(result.singleLineLargeFiles.joined(separator: ", "))")
    }
    if !result.nativeBinaryFiles.isEmpty {
        print("Native binaries: \(result.nativeBinaryFiles.joined(separator: ", "))")
    }
    if !result.obfuscatorMatches.isEmpty {
        print("Obfuscator markers: \(result.obfuscatorMatches.joined(separator: "; "))")
    }
    if !result.bundledRuntimeFiles.isEmpty {
        print("Bundled runtime drops: \(result.bundledRuntimeFiles.joined(separator: ", "))")
    }
    for reason in result.reasons { print("- \(reason)") }
}

// MARK: - metadata

private func packageMetadata(args: [String]) async throws {
    var name: String? = nil
    var registryRaw: String? = nil
    var i = 0
    while i < args.count {
        switch args[i] {
        case "--registry" where i + 1 < args.count:
            registryRaw = args[i+1]; i += 2
        default:
            if !args[i].hasPrefix("--") && name == nil { name = args[i] }
            i += 1
        }
    }
    guard let name = name, let registryRaw = registryRaw,
          let registry = PackageMetadataAnalyzer.Registry(rawValue: registryRaw) else {
        throw PackageCommandError.usage("Usage: maccrabctl package metadata <name> --registry npm|pypi")
    }
    let analyzer = PackageMetadataAnalyzer()
    guard let result = await analyzer.analyze(packageName: name, registry: registry) else {
        throw PackageCommandError.underlying("Failed to fetch metadata for \(name) on \(registry.rawValue)")
    }
    print("Metadata scan: \(name) (\(registry.rawValue))")
    print("Score: \(result.score)/100")
    print("Description length: \(result.descriptionLength)")
    print("Homepage: \(result.homepage ?? "(missing)") [\(result.homepageHostClass.rawValue)]")
    print("Repo: \(result.repositoryURL ?? "(missing)")")
    print("First version: \(result.firstVersion ?? "?")  Latest: \(result.latestVersion ?? "?")")
    print("Maintainer emails: \(result.maintainerEmails.joined(separator: ", "))")
    for reason in result.reasons { print("- \(reason)") }
}

// MARK: - attestation

private func packageAttestation(args: [String]) async throws {
    var name: String? = nil
    var version: String? = nil
    var registryRaw: String? = nil
    var priorBuilder: String? = nil
    var i = 0
    while i < args.count {
        switch args[i] {
        case "--version" where i + 1 < args.count:
            version = args[i+1]; i += 2
        case "--registry" where i + 1 < args.count:
            registryRaw = args[i+1]; i += 2
        case "--prior-builder" where i + 1 < args.count:
            priorBuilder = args[i+1]; i += 2
        default:
            if !args[i].hasPrefix("--") && name == nil { name = args[i] }
            i += 1
        }
    }
    guard let name = name, let version = version, let registryRaw = registryRaw,
          let registry = AttestationEnricher.Registry(rawValue: registryRaw) else {
        throw PackageCommandError.usage("Usage: maccrabctl package attestation <name> --version <ver> --registry npm|pypi [--prior-builder <id>]")
    }
    let enricher = AttestationEnricher()
    let result = await enricher.verify(packageName: name, version: version, registry: registry, priorBuilder: priorBuilder)
    print("Attestation: \(name)@\(version) (\(registry.rawValue))")
    print("Status: \(result.status.rawValue)")
    if let builder = result.builder { print("Builder: \(builder)") }
    if let repo = result.sourceRepo { print("Source repo: \(repo)") }
    if let prior = result.priorBuilder { print("Compared against prior builder: \(prior)") }
    for warning in result.warnings { print("WARNING: \(warning)") }
}

// MARK: - intent

private func packageIntent(args: [String]) async throws {
    var packageName: String? = nil
    var registry: String? = nil
    var version: String? = nil
    var installerLineage: [String] = []
    var credentialsRead: [String] = []
    var networkEgress: [String] = []
    var filesWritten: [String] = []
    var processesSpawned: [String] = []
    var hasObfuscated = false
    var hasBundledRuntime = false
    var hasLanguageMismatch = false
    var aiTriggered = false

    var i = 0
    while i < args.count {
        switch args[i] {
        case "--registry" where i + 1 < args.count:
            registry = args[i+1]; i += 2
        case "--version" where i + 1 < args.count:
            version = args[i+1]; i += 2
        case "--installer" where i + 1 < args.count:
            installerLineage.append(args[i+1]); i += 2
        case "--cred-read" where i + 1 < args.count:
            credentialsRead.append(args[i+1]); i += 2
        case "--egress" where i + 1 < args.count:
            networkEgress.append(args[i+1]); i += 2
        case "--file-written" where i + 1 < args.count:
            filesWritten.append(args[i+1]); i += 2
        case "--spawned" where i + 1 < args.count:
            processesSpawned.append(args[i+1]); i += 2
        case "--obfuscated":
            hasObfuscated = true; i += 1
        case "--bundled-runtime":
            hasBundledRuntime = true; i += 1
        case "--language-mismatch":
            hasLanguageMismatch = true; i += 1
        case "--ai-triggered":
            aiTriggered = true; i += 1
        default:
            if !args[i].hasPrefix("--") && packageName == nil { packageName = args[i] }
            i += 1
        }
    }

    guard let packageName = packageName, let registry = registry else {
        throw PackageCommandError.usage("Usage: maccrabctl package intent <package_name> --registry npm|pypi|brew [--version <ver>] [--installer <p> ...] [--cred-read <path> ...] [--egress <host> ...] [--file-written <path> ...] [--spawned <p> ...] [--obfuscated] [--bundled-runtime] [--language-mismatch] [--ai-triggered]")
    }

    let brief = IntentClassifier.BehaviorBrief(
        packageName: packageName,
        packageRegistry: registry,
        packageVersion: version,
        installerLineage: installerLineage,
        credentialsRead: credentialsRead,
        networkEgress: networkEgress,
        filesWritten: filesWritten,
        processesSpawned: processesSpawned,
        hasObfuscatedContent: hasObfuscated,
        hasBundledRuntime: hasBundledRuntime,
        hasLanguageMismatch: hasLanguageMismatch,
        aiAgentTriggered: aiTriggered
    )
    // Use a configured LLM backend when one is available (same resolution
    // path the CLI uses elsewhere); IntentClassifier falls back to its
    // deterministic heuristic when this is nil.
    let classifier = IntentClassifier(llmService: MacCrabCtl.createCLILLMService())
    let result = await classifier.classify(brief)
    print("Intent classification: \(packageName)")
    print("Label: \(result.label.rawValue)")
    print("Confidence: \(String(format: "%.2f", result.confidence))")
    print("Provider: \(result.provider)")
    print("Abstained: \(result.abstained)")
    for reason in result.reasons { print("- \(reason)") }
}
