// `maccrabctl fingerprint <pid-or-path>` — compute the MCFP static
// fingerprint for a binary at a path, or for the executable behind
// a live PID.
//
// Plan reference: §6.4 R1 — "Static components for any Mach-O.
// CLI: `maccrabctl fingerprint <pid-or-path>`."

import Foundation
import MacCrabForensics

func dispatchFingerprint(args: [String]) async {
    guard let target = args.first else {
        printFingerprintUsage()
        exit(0)
    }
    let asJSON = args.contains("--json")

    let path: String
    if let pid = Int32(target) {
        // Resolve PID to executable path.
        guard let p = resolveExecutablePath(forPID: pid) else {
            print("Could not resolve executable for PID \(pid).")
            exit(1)
        }
        path = p
    } else {
        path = target
    }

    do {
        let result = try await MCFPStatic.fingerprint(path: path)
        if asJSON {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let data = (try? encoder.encode(result)) ?? Data()
            print(String(data: data, encoding: .utf8) ?? "{}")
        } else {
            print(result.canonical)
        }
    } catch {
        print("fingerprint failed: \(error)")
        exit(1)
    }
}

func printFingerprintUsage() {
    print("""
    Usage: maccrabctl fingerprint <pid-or-path> [--json]

    Compute the MCFP v1 static fingerprint for a Mach-O binary.
    Either supply a PID (resolved to its executable path via
    proc_pidpath) or a direct filesystem path.

    Output forms:
      Default:    mcfp1/static/<arch>/<lc>/<cs>/<ent>
      --json:     full per-component JSON record

    See docs/mcfp.md for the v1 specification.
    """)
}

private func resolveExecutablePath(forPID pid: Int32) -> String? {
    var buf = [CChar](repeating: 0, count: 4096)
    let rc = proc_pidpath(pid, &buf, UInt32(buf.count))
    if rc <= 0 { return nil }
    return String(cString: buf)
}
