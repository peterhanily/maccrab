// MCFPStatic — computes the static-only MCFP fingerprint
// (`mcfp1/static/<arch>/<lc>/<cs>/<ent>`) for a Mach-O binary at
// a path.
//
// Reference: docs/mcfp.md v1 spec; docs/mcfp-research/R0.md
// (selects option (d) — static-only — for v1.14).

import Foundation
import CryptoKit
import MacCrabCore

public struct MCFPStaticResult: Sendable, Codable {
    public let scheme: String                  // "mcfp1"
    public let archToken: String
    public let lc: String                       // 12-hex prefix
    public let cs: String                       // 12-hex prefix
    public let ent: String                      // 12-hex prefix

    public var canonical: String {
        "\(scheme)/static/\(archToken)/\(lc)/\(cs)/\(ent)"
    }
}

public enum MCFPStaticError: Error, CustomStringConvertible {
    case fileNotFound(path: String)
    case notReadable(path: String)
    case unexpectedFormat(path: String, message: String)

    public var description: String {
        switch self {
        case .fileNotFound(let p): return "MCFPStatic: file not found at \(p)"
        case .notReadable(let p): return "MCFPStatic: file not readable at \(p)"
        case .unexpectedFormat(let p, let m): return "MCFPStatic: unexpected format at \(p): \(m)"
        }
    }
}

public enum MCFPStatic {

    /// Compute the static fingerprint for the Mach-O at `path`.
    ///
    /// Implementation strategy: subprocess-based (otool, codesign,
    /// lipo). Adequate for v1.14 reference — the CLI invocation
    /// cost is dwarfed by the Mach-O parse itself, and we get
    /// Apple-supported behavior for free. A future iteration can
    /// drop down to raw Mach-O parsing if performance becomes a
    /// bottleneck (corpus jobs across thousands of binaries).
    public static func fingerprint(path: String) async throws -> MCFPStaticResult {
        guard FileManager.default.fileExists(atPath: path) else {
            throw MCFPStaticError.fileNotFound(path: path)
        }
        guard FileManager.default.isReadableFile(atPath: path) else {
            throw MCFPStaticError.notReadable(path: path)
        }

        async let arch = archToken(for: path)
        async let lc = lcHash(for: path)
        async let cs = csHash(for: path)
        async let ent = entHash(for: path)

        return MCFPStaticResult(
            scheme: "mcfp1",
            archToken: await arch,
            lc: await lc,
            cs: await cs,
            ent: await ent
        )
    }

    // MARK: - Components

    /// Read the Mach-O magic number directly. Avoids the cost of
    /// spawning `lipo -info` for the common case.
    static func archToken(for path: String) async -> String {
        guard let fh = FileHandle(forReadingAtPath: path) else {
            return "unknown"
        }
        defer { try? fh.close() }
        guard let header = try? fh.read(upToCount: 12), header.count >= 8 else {
            return "unknown"
        }
        // First 4 bytes: Mach-O magic.
        //   0xfeedface  → 32-bit single-arch (little-endian)
        //   0xcefaedfe  → 32-bit single-arch (big-endian on the wire; little-endian
        //                  observed; the BE form was Apple's PowerPC era)
        //   0xfeedfacf  → 64-bit single-arch
        //   0xcffaedfe  → 64-bit single-arch (reversed byte order)
        //   0xcafebabe  → fat (universal) header big-endian
        //   0xbebafeca  → fat (universal) header reversed
        let magic = header.withUnsafeBytes { $0.load(as: UInt32.self) }
        switch magic {
        case 0xcafebabe, 0xbebafeca:
            return "universal"
        case 0xfeedfacf, 0xcffaedfe:
            // 64-bit single-arch. Read cputype + cpusubtype to
            // distinguish arm64 vs arm64e vs x86_64.
            let cpuType = header.withUnsafeBytes { $0.load(fromByteOffset: 4, as: UInt32.self) }
            let cpuSubtype = header.withUnsafeBytes { $0.load(fromByteOffset: 8, as: UInt32.self) }
            // CPU_TYPE_ARM64 = 0x100000C, CPU_TYPE_X86_64 = 0x1000007.
            // CPU_SUBTYPE_ARM64E carries the 2 in the low bits.
            switch cpuType {
            case 0x0100000C:
                let CPU_SUBTYPE_ARM64E: UInt32 = 2
                if (cpuSubtype & 0xff) == CPU_SUBTYPE_ARM64E {
                    return "arm64e"
                }
                return "arm64"
            case 0x01000007:
                return "x86_64"
            default:
                return "unknown"
            }
        case 0xfeedface, 0xcefaedfe:
            return "i386"
        default:
            return "unknown"
        }
    }

    /// SHA-256 (12-hex prefix) of LC_LOAD_DYLIB names joined by \n
    /// in load-command order.
    static func lcHash(for path: String) async -> String {
        let names = await runSubprocess("/usr/bin/otool", args: ["-L", path])
        // otool -L output:
        //   /path/to/binary:
        //   	/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1.0.0)
        //   	/System/Library/Frameworks/.../Foo.framework/Versions/A/Foo (compatibility ...)
        // We extract each dylib path (the first field on each
        // tab-indented line).
        var dylibs: [String] = []
        for line in names.split(separator: "\n", omittingEmptySubsequences: true) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            // Skip the header (first line, ends with `:`).
            if trimmed.hasSuffix(":") { continue }
            // The first whitespace-delimited token is the path.
            if let firstSpace = trimmed.firstIndex(where: { $0 == " " || $0 == "\t" }) {
                dylibs.append(String(trimmed[..<firstSpace]))
            } else {
                dylibs.append(trimmed)
            }
        }
        let canonical = dylibs.joined(separator: "\n")
        return hex12(of: canonical)
    }

    /// SHA-256 (12-hex prefix) of `<team_id>|<flags>|<sealed_hash_alg>|<requirement>`.
    static func csHash(for path: String) async -> String {
        // CodeSigningCache provides team_id + flags + (implicitly) the
        // signing requirement. Sealed hash alg is sha256 on modern
        // macOS; we annotate as "sha256" until a future codesign-
        // resolve enricher emits the actual value.
        let cache = CodeSigningCache()
        let info = await cache.evaluate(path: path)
        let teamID = info.teamId ?? ""
        let flags = String(info.flags)
        let sealedHashAlg = "sha256"  // de-facto default; refine later
        // Designated requirement string — query via codesign -d -r-.
        let requirement = await runSubprocess(
            "/usr/bin/codesign",
            args: ["-d", "-r-", path]
        )
        // The interesting line of `codesign -d -r-` output is
        // `designated => ...`. Extract everything after "=> " on
        // that line.
        var designated = ""
        for line in requirement.split(separator: "\n", omittingEmptySubsequences: true) {
            let t = line.trimmingCharacters(in: .whitespaces)
            if t.hasPrefix("designated => ") {
                designated = String(t.dropFirst("designated => ".count))
                break
            }
        }
        let canonical = "\(teamID)|\(flags)|\(sealedHashAlg)|\(designated)"
        return hex12(of: canonical)
    }

    /// SHA-256 (12-hex prefix) of sorted entitlement keys joined
    /// by \n. Values are not part of the hash — see docs/mcfp.md
    /// for the rationale.
    static func entHash(for path: String) async -> String {
        let xml = await runSubprocess(
            "/usr/bin/codesign",
            args: ["-d", "--entitlements", ":-", path]
        )
        // Parse the embedded entitlement plist. codesign emits
        // either pure XML plist or a Magic + Length prefix
        // followed by the plist; the v1.13a stripping is
        // permissive — find the first `<?xml` marker and parse
        // from there.
        guard let xmlStart = xml.range(of: "<?xml") else {
            // No entitlements present at all.
            return hex12(of: "")
        }
        let plistText = String(xml[xmlStart.lowerBound...])
        guard let data = plistText.data(using: .utf8),
              let plist = try? PropertyListSerialization.propertyList(
                from: data, options: [], format: nil
              ),
              let dict = plist as? [String: Any] else {
            return hex12(of: "")
        }
        let sortedKeys = dict.keys.sorted()
        let canonical = sortedKeys.joined(separator: "\n")
        return hex12(of: canonical)
    }

    // MARK: - Helpers

    /// Take the first 12 hex characters of SHA-256(value as UTF-8).
    static func hex12(of value: String) -> String {
        let digest = SHA256.hash(data: Data(value.utf8))
        let hex = digest.map { String(format: "%02x", $0) }.joined()
        return String(hex.prefix(12))
    }

    /// Run a subprocess synchronously and return its stdout as a
    /// UTF-8 string. stderr is discarded (codesign / otool routinely
    /// chatter on stderr; we don't need it for fingerprint inputs).
    /// Returns empty string on launch failure — fingerprint
    /// computation still produces a result, just an "empty input"
    /// fingerprint, which is consistent across runs.
    private static func runSubprocess(_ exe: String, args: [String]) async -> String {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: exe)
        proc.arguments = args
        let out = Pipe()
        let err = Pipe()
        proc.standardOutput = out
        proc.standardError = err
        do {
            try proc.run()
        } catch {
            return ""
        }
        proc.waitUntilExit()
        let data = out.fileHandleForReading.readDataToEndOfFile()
        return String(data: data, encoding: .utf8) ?? ""
    }
}
