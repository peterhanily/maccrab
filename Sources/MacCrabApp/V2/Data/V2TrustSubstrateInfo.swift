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

    public static func read(dataDir: String) -> V2TrustSubstrateInfo? {
        let pubPath = dataDir + "/keys/trace-signing.pub"
        let statePath = dataDir + "/keys/trust-substrate.json"
        guard let der = try? Data(contentsOf: URL(fileURLWithPath: pubPath)),
              !der.isEmpty
        else { return nil }
        let activatedAt = (try? FileManager.default.attributesOfItem(atPath: pubPath))?[.modificationDate] as? Date
            ?? Date()
        var mode = "secure_enclave"
        if let stateData = try? Data(contentsOf: URL(fileURLWithPath: statePath)),
           let json = try? JSONSerialization.jsonObject(with: stateData) as? [String: Any],
           let m = json["mode"] as? String {
            mode = m
        }
        return V2TrustSubstrateInfo(mode: mode, derBytes: der, activatedAt: activatedAt)
    }
}
