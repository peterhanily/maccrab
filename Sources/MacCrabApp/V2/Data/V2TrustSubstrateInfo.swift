// V2TrustSubstrateInfo.swift
// Read-only view of the daemon's trust-substrate state for the
// dashboard. The daemon's `TrustSubstrate` actor owns the keys; the
// dashboard process just reads the public key file + state json on
// disk to surface fingerprint / mode / activation timestamp.
//
// File layout under <dataDir>/keys/:
//   trace-signing.pub         — public key DER bytes
//   trust-substrate.json      — { "mode": "secure_enclave" | "filesystem_degraded", ... }

import Foundation
import CryptoKit

public struct V2TrustSubstrateInfo: Sendable, Equatable {
    public let mode: String
    public let derBytes: Data
    public let activatedAt: Date

    public var pemString: String {
        let b64 = derBytes.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        return "-----BEGIN PUBLIC KEY-----\n\(b64)\n-----END PUBLIC KEY-----\n"
    }

    public var fingerprintFull: String {
        SHA256.hash(data: derBytes).map { String(format: "%02x", $0) }.joined()
    }

    public var fingerprintShort: String {
        let f = fingerprintFull
        guard f.count > 16 else { return f }
        return String(f.prefix(8)) + "…" + String(f.suffix(8))
    }

    public var modeLabel: String {
        switch mode {
        case "secure_enclave":      return "Secure Enclave"
        case "filesystem_degraded": return "Filesystem (degraded)"
        default:                    return mode.capitalized
        }
    }

    public var modeChipKind: V2ChipKind {
        mode == "secure_enclave" ? .healthy : .warning
    }

    public var derSizeLabel: String { "\(derBytes.count) B (DER)" }

    public var activatedLabel: String {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return f.string(from: activatedAt)
    }

    /// Three honest outcomes for the dashboard's Trust-substrate card.
    ///
    /// Pre-fix `read()` collapsed the last two into a single `nil`, so on a
    /// RELEASE install the card sat permanently on "Not generated" — the
    /// sysext runs as root and creates `keys/` as `0o700 root-owned`, so the
    /// uid-501 menubar app can't traverse the directory to reach the (0o644)
    /// public key, even though the key exists. That read as "no key" when the
    /// truth is "key present, root-protected". `.managedByEngine` distinguishes
    /// that expected hardening from a genuinely-absent key.
    public enum Status: Sendable, Equatable {
        /// Public key was read successfully — full detail available.
        case available(V2TrustSubstrateInfo)
        /// The `keys/` dir exists but this (non-root) process can't traverse it
        /// — the key is owned + protected by the engine (release install).
        case managedByEngine
        /// No key material found — no `keys/` dir, or an empty one we can read.
        case notGenerated

        public var info: V2TrustSubstrateInfo? {
            if case .available(let i) = self { return i }
            return nil
        }
    }

    /// Pure classifier (unit-testable): given the public-key bytes we managed to
    /// read (nil/empty when unreadable) and whether the `keys/` dir exists but
    /// isn't traversable by this process, decide which status to show.
    static func classify(der: Data?, mode: String, activatedAt: Date,
                         keysDirExistsButUnreadable: Bool) -> Status {
        if let der, !der.isEmpty {
            return .available(V2TrustSubstrateInfo(mode: mode, derBytes: der, activatedAt: activatedAt))
        }
        return keysDirExistsButUnreadable ? .managedByEngine : .notGenerated
    }

    public static func status(dataDir: String) -> Status {
        let keysDir = dataDir + "/keys"
        let pubPath = keysDir + "/trace-signing.pub"
        let statePath = keysDir + "/trust-substrate.json"
        let fm = FileManager.default

        let der = try? Data(contentsOf: URL(fileURLWithPath: pubPath))
        let activatedAt = (try? fm.attributesOfItem(atPath: pubPath))?[.modificationDate] as? Date ?? Date()
        var mode = "secure_enclave"
        if let stateData = try? Data(contentsOf: URL(fileURLWithPath: statePath)),
           let json = try? JSONSerialization.jsonObject(with: stateData) as? [String: Any],
           let m = json["mode"] as? String {
            mode = m
        }

        // Couldn't read the key? Tell "root-protected, not readable here" apart
        // from "genuinely not generated". `stat`ing the dir only needs traverse
        // on its PARENTS (0o755), so it succeeds even for a 0o700 root-owned
        // `keys/`; directory-execute permission for THIS process is the traverse
        // gate, and that's what fails on release.
        var isDir: ObjCBool = false
        let dirExists = fm.fileExists(atPath: keysDir, isDirectory: &isDir) && isDir.boolValue
        let traversable = fm.isExecutableFile(atPath: keysDir)

        return classify(der: der, mode: mode, activatedAt: activatedAt,
                        keysDirExistsButUnreadable: dirExists && !traversable)
    }

    /// Back-compat convenience — the readable-key detail, or nil.
    public static func read(dataDir: String) -> V2TrustSubstrateInfo? {
        status(dataDir: dataDir).info
    }
}
