// RuleChannelFetch.swift
// maccrabctl
//
// The client half of the RULE-UPDATE CHANNEL: fetch a signed detection-rule
// manifest, verify it, and stage it into <data>/compiled_rules/pushed/ so the
// engine loads it (detection-only, additive — see RuleEngine.loadPushedRules).
//
// This decouples rule distribution from the notarized app / Sparkle cycle:
// rules are DATA, so only signature verification is needed (no notarization).
// It mirrors the plugin-catalog trust chain but is deliberately SIMPLER + safer:
//   - The rules are INLINE in the signed manifest (no separate tarball → no
//     untar / TOCTOU / partial-extract attack surface; the one Ed25519 signature
//     covers the entire payload).
//   - A SEPARATE `rules.pub` key (not the app/plugin key) bounds blast radius —
//     a leaked rules key can only push detection-only, additive rules.
// Fail-closed at every step; a bad manifest leaves the prior pushed corpus intact.

import Foundation
import CryptoKit
import MacCrabCore
import MacCrabForensics

enum RuleChannelError: Error, CustomStringConvertible {
    case noRulesPublicKey
    case rulesPublicKeyInvalid(reason: String)
    case httpFetchFailed(url: URL, status: Int)
    case signatureVerifyFailed(url: URL)
    case manifestParseFailed(reason: String)
    case manifestSerialMissing
    case rollback(stored: Int, incoming: Int)
    case versionFloor(reason: String)
    case ruleValidationFailed(ruleIndex: Int, reason: String)

    var description: String {
        switch self {
        case .noRulesPublicKey:
            return "No rule-channel public key configured. Set MACCRAB_RAVE_RULES_PUB_PATH or rebuild with a bundled rules.pub."
        case .rulesPublicKeyInvalid(let r): return "Rule-channel public key invalid: \(r)"
        case .httpFetchFailed(let url, let s): return "HTTP fetch failed: \(url.absoluteString) → HTTP \(s)"
        case .signatureVerifyFailed(let url): return "Ed25519 signature verification failed for \(url.absoluteString)"
        case .manifestParseFailed(let r): return "Rules manifest parse failed: \(r)"
        case .manifestSerialMissing:
            return "Refusing: the signature-verified rules manifest has no serial (anti-rollback requires one)."
        case .rollback(let stored, let incoming):
            return "Rules manifest rollback rejected — signed serial \(incoming) is older than the last-accepted \(stored). Keeping the prior pushed rules (stale/replay)."
        case .versionFloor(let r): return r
        case .ruleValidationFailed(let i, let r):
            return "Rules manifest rejected: rule #\(i) did not validate (\(r)). The whole manifest is refused (no partial corpus)."
        }
    }
}

struct RuleChannelManifest {
    let serial: Int
    let corpusVersion: String
    let minMaccrabVersion: String?
    /// Each element is the raw JSON bytes of one CompiledRule, already validated
    /// to decode, plus its id (for the on-disk filename).
    let rules: [(id: String, json: Data)]
}

struct RuleChannelFetcher {
    let rulesBase: URL
    let rulesPublicKey: Curve25519.Signing.PublicKey
    let trustState: RaveTrustStateStore

    init(rulesBase: String, trustState: RaveTrustStateStore? = nil) throws {
        var trimmed = rulesBase
        if !trimmed.hasSuffix("/") { trimmed += "/" }
        guard let url = URL(string: trimmed) else {
            throw RuleChannelError.manifestParseFailed(reason: "bad rules base URL: \(rulesBase)")
        }
        self.rulesBase = url
        self.rulesPublicKey = try Self.loadRulesPublicKey()
        self.trustState = trustState ?? RaveTrustStateStore.default(supportDir: maccrabUserWritableDataDir())
    }

    // MARK: - Key

    private static func loadRulesPublicKey() throws -> Curve25519.Signing.PublicKey {
        #if DEBUG
        if let path = ProcessInfo.processInfo.environment["MACCRAB_RAVE_RULES_PUB_PATH"], !path.isEmpty {
            return try loadFromFile(path: path)
        }
        #endif
        let candidates = [
            "/Applications/MacCrab.app/Contents/Resources/rave-keys/rules.pub",
            FileManager.default.currentDirectoryPath + "/Sources/MacCrabApp/Resources/rave-keys/rules.pub",
        ]
        for path in candidates where FileManager.default.fileExists(atPath: path) {
            return try loadFromFile(path: path)
        }
        throw RuleChannelError.noRulesPublicKey
    }

    private static func loadFromFile(path: String) throws -> Curve25519.Signing.PublicKey {
        let data: Data
        do { data = try Data(contentsOf: URL(fileURLWithPath: path)) }
        catch { throw RuleChannelError.rulesPublicKeyInvalid(reason: "cannot read \(path): \(error)") }
        guard data.count == 32 else {
            throw RuleChannelError.rulesPublicKeyInvalid(reason: "expected 32 bytes, got \(data.count) at \(path)")
        }
        do { return try Curve25519.Signing.PublicKey(rawRepresentation: data) }
        catch { throw RuleChannelError.rulesPublicKeyInvalid(reason: "Curve25519 rejected key: \(error)") }
    }

    // MARK: - Fetch + verify

    private func fetch(url: URL) async throws -> Data {
        // Always pull fresh: the manifest is re-published frequently and the
        // anti-rollback serial only works if we actually SEE the newest one.
        // URLSession.shared's default cache will otherwise serve a stale
        // manifest for the same URL, silently masking a just-published update.
        var req = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData)
        req.setValue("no-cache", forHTTPHeaderField: "Cache-Control")
        let (data, response) = try await URLSession.shared.data(for: req)
        guard let http = response as? HTTPURLResponse else {
            throw RuleChannelError.httpFetchFailed(url: url, status: -1)
        }
        guard (200..<300).contains(http.statusCode) else {
            throw RuleChannelError.httpFetchFailed(url: url, status: http.statusCode)
        }
        return data
    }

    /// Fetch `rules-manifest.json` + `.sig`, Ed25519-verify, and parse. Each rule
    /// is decode-validated as a CompiledRule here; a single bad rule rejects the
    /// whole manifest (fail-closed — no partial corpus).
    func fetchVerifiedManifest() async throws -> RuleChannelManifest {
        let manifestURL = rulesBase.appendingPathComponent("rules-manifest.json")
        let sigURL = rulesBase.appendingPathComponent("rules-manifest.json.sig")
        let manifestData = try await fetch(url: manifestURL)
        let sig = try await fetch(url: sigURL)
        guard rulesPublicKey.isValidSignature(sig, for: manifestData) else {
            throw RuleChannelError.signatureVerifyFailed(url: manifestURL)
        }
        guard let obj = try? JSONSerialization.jsonObject(with: manifestData) as? [String: Any] else {
            throw RuleChannelError.manifestParseFailed(reason: "not a JSON object")
        }
        guard let serial = (obj["serial"] as? NSNumber)?.intValue else {
            throw RuleChannelError.manifestSerialMissing
        }
        let corpus = (obj["corpus_version"] as? String) ?? "?"
        let floor = obj["min_maccrab_version"] as? String
        guard let rawRules = obj["rules"] as? [[String: Any]] else {
            throw RuleChannelError.manifestParseFailed(reason: "missing 'rules' array")
        }
        let decoder = JSONDecoder()
        var rules: [(id: String, json: Data)] = []
        for (i, raw) in rawRules.enumerated() {
            guard let json = try? JSONSerialization.data(withJSONObject: raw) else {
                throw RuleChannelError.ruleValidationFailed(ruleIndex: i, reason: "re-encode failed")
            }
            let rule: CompiledRule
            do { rule = try decoder.decode(CompiledRule.self, from: json) }
            catch { throw RuleChannelError.ruleValidationFailed(ruleIndex: i, reason: "not a valid CompiledRule: \(error)") }
            // Defense in depth: refuse a rule id containing a path separator so it
            // can never escape the pushed/ directory when written to disk.
            guard !rule.id.contains("/"), !rule.id.contains("\\"), rule.id != "..", !rule.id.isEmpty else {
                throw RuleChannelError.ruleValidationFailed(ruleIndex: i, reason: "unsafe rule id '\(rule.id)'")
            }
            rules.append((id: rule.id, json: json))
        }
        return RuleChannelManifest(serial: serial, corpusVersion: corpus, minMaccrabVersion: floor, rules: rules)
    }

    // MARK: - Update

    /// Result of a (read-only) update check.
    struct UpdateStatus { let installedSerial: Int?; let availableSerial: Int; let corpusVersion: String; let updateAvailable: Bool; let ruleCount: Int }

    /// Read-only: fetch + verify the manifest and compare its serial to the
    /// recorded high-water mark. Never writes.
    func check() async throws -> UpdateStatus {
        let m = try await fetchVerifiedManifest()
        let installed = trustState.load().rulesManifestSerial
        return UpdateStatus(installedSerial: installed, availableSerial: m.serial, corpusVersion: m.corpusVersion,
                            updateAvailable: installed == nil || m.serial > installed!, ruleCount: m.rules.count)
    }

    /// Fetch → verify → anti-rollback → version-floor → validate → atomic-swap the
    /// verified rules into `pushedDir`, then advance the serial high-water mark.
    /// Returns the number of rules installed. Fail-closed: any failure leaves the
    /// prior pushed corpus intact.
    @discardableResult
    func update(into pushedDir: URL) async throws -> Int {
        let m = try await fetchVerifiedManifest()

        // Anti-rollback: refuse a manifest older than the last accepted serial.
        switch trustState.evaluateRulesManifest(incoming: m.serial) {
        case .rollback(let stored, let incoming): throw RuleChannelError.rollback(stored: stored, incoming: incoming)
        case .firstSeen, .accepted: break
        }

        // Version floor: don't install rules that need a newer engine.
        if let floor = m.minMaccrabVersion, !floor.isEmpty {
            do {
                try RaveVersionFloor.enforce(pluginID: "rules-manifest", floor: floor, running: MacCrabVersion.current)
            } catch let e as RaveVersionFloorError {
                throw RuleChannelError.versionFloor(reason: e.description)
            }
        }

        // Atomic swap: write the validated set into a sibling temp dir, then
        // replace pushedDir. A failed write never disturbs the prior corpus.
        let fm = FileManager.default
        let parent = pushedDir.deletingLastPathComponent()
        try fm.createDirectory(at: parent, withIntermediateDirectories: true)
        let tmp = parent.appendingPathComponent("pushed.tmp.\(UUID().uuidString)")
        try fm.createDirectory(at: tmp, withIntermediateDirectories: true)
        do {
            for rule in m.rules {
                try rule.json.write(to: tmp.appendingPathComponent("\(rule.id).json"))
            }
        } catch {
            try? fm.removeItem(at: tmp)
            throw error
        }
        if fm.fileExists(atPath: pushedDir.path) { try fm.removeItem(at: pushedDir) }
        try fm.moveItem(at: tmp, to: pushedDir)
        try? fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: pushedDir.path)

        // Advance the high-water mark only after the swap succeeds.
        try trustState.recordRulesManifest(serial: m.serial)
        return m.rules.count
    }
}
