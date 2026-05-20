// ImposterHarness — plan §6.4 R2 imposter test.
//
// "Unsigned binary at the same path as a known-good system
// process (in sandbox) produces divergence in cs + ent
// components."
//
// We can't actually place an unsigned binary at /usr/bin/X (SIP
// rejects). What we CAN do: copy the known-good binary into a
// sandbox dir, strip its signature, fingerprint both, compare.
// The path-context part of the imposter narrative isn't exercised
// here (would need a real OS-level path-substitution attack);
// the cs + ent component divergence is what the experiment
// actually measures.

import Foundation

public struct ImposterReport: Sendable, Codable {
    public let targetPath: String
    public let imposterPath: String

    public let originalCanonical: String
    public let imposterCanonical: String

    public let archDiverged: Bool
    public let lcDiverged: Bool
    public let csDiverged: Bool
    public let entDiverged: Bool

    /// Plan §6.4 R2 imposter expectation: divergence in cs + ent.
    public let r2ImposterVerdict: Verdict

    public enum Verdict: String, Sendable, Codable {
        case pass            // cs + ent both diverged as expected
        case partial         // only one of cs/ent diverged
        case fail            // neither diverged (imposter looks identical)
    }
}

public enum ImposterHarness {

    public enum HarnessError: Error, CustomStringConvertible {
        case targetMissing(path: String)
        case copyFailed(message: String)
        case stripFailed(message: String)
        case fingerprintFailed(message: String)

        public var description: String {
            switch self {
            case .targetMissing(let p): return "Imposter: target missing at \(p)"
            case .copyFailed(let m): return "Imposter: copy failed: \(m)"
            case .stripFailed(let m): return "Imposter: codesign --remove-signature failed: \(m)"
            case .fingerprintFailed(let m): return "Imposter: fingerprint failed: \(m)"
            }
        }
    }

    /// Run the imposter experiment for a given target binary.
    /// Returns the structured report.
    public static func run(target: String) async throws -> ImposterReport {
        guard FileManager.default.fileExists(atPath: target) else {
            throw HarnessError.targetMissing(path: target)
        }

        // Sandbox dir for the imposter copy.
        let sandboxDir = NSTemporaryDirectory() + "maccrab-imposter-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: sandboxDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: sandboxDir) }

        let imposterPath = sandboxDir + "/" + (URL(fileURLWithPath: target).lastPathComponent)

        // Copy target → imposter.
        do {
            try FileManager.default.copyItem(atPath: target, toPath: imposterPath)
        } catch {
            throw HarnessError.copyFailed(message: error.localizedDescription)
        }
        try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: imposterPath)

        // Strip signature: `codesign --remove-signature <path>`.
        let stripProc = Process()
        stripProc.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        stripProc.arguments = ["--remove-signature", imposterPath]
        let stripErr = Pipe()
        stripProc.standardError = stripErr
        stripProc.standardOutput = Pipe()
        do { try stripProc.run() } catch {
            throw HarnessError.stripFailed(message: error.localizedDescription)
        }
        stripProc.waitUntilExit()
        // codesign may fail on platform binaries (SIP) — that's
        // fine, the strip can be partial. We continue regardless
        // and let the fingerprint divergence speak.

        // Fingerprint both.
        let original: MCFPStaticResult
        let imposter: MCFPStaticResult
        do {
            original = try await MCFPStatic.fingerprint(path: target)
            imposter = try await MCFPStatic.fingerprint(path: imposterPath)
        } catch {
            throw HarnessError.fingerprintFailed(message: "\(error)")
        }

        let archDiverged = original.archToken != imposter.archToken
        let lcDiverged = original.lc != imposter.lc
        let csDiverged = original.cs != imposter.cs
        let entDiverged = original.ent != imposter.ent

        let verdict: ImposterReport.Verdict
        if csDiverged && entDiverged { verdict = .pass }
        else if csDiverged || entDiverged { verdict = .partial }
        else { verdict = .fail }

        return ImposterReport(
            targetPath: target,
            imposterPath: imposterPath,
            originalCanonical: original.canonical,
            imposterCanonical: imposter.canonical,
            archDiverged: archDiverged,
            lcDiverged: lcDiverged,
            csDiverged: csDiverged,
            entDiverged: entDiverged,
            r2ImposterVerdict: verdict
        )
    }
}
