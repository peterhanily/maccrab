// RuleChannelFetch.swift
// maccrabctl
//
// The dormant client half of the RULE-UPDATE CHANNEL: fetch a signed
// detection-rule manifest, verify it, and stage it into
// <data>/compiled_rules/pushed/. Production is fail-closed in this release:
// RuleChannelPolicy disables fetches and the engine does not load staged rules.
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
import Darwin
import MacCrabCore
import MacCrabForensics

enum RuleChannelError: Error, CustomStringConvertible {
    case channelDisabled
    case noRulesPublicKey
    case rulesPublicKeyInvalid(reason: String)
    case httpFetchFailed(url: URL, status: Int)
    case signatureVerifyFailed(url: URL)
    case signatureSizeInvalid(expectedBytes: Int, actualBytes: Int)
    case manifestTooLarge(maximumBytes: Int, actualBytes: Int)
    case ruleCountExceeded(maximum: Int, actual: Int)
    case manifestParseFailed(reason: String)
    case manifestSerialMissing
    case rollback(stored: Int, incoming: Int)
    case versionFloor(reason: String)
    case ruleValidationFailed(ruleIndex: Int, reason: String)
    case atomicRollbackFailed(reason: String)

    var description: String {
        switch self {
        case .channelDisabled:
            return """
                The signed rule-update channel is disabled in this release. Its public \
                trust anchor has no verified custody or key-ceremony record, and the \
                default distribution endpoint is not active. MacCrab refuses before \
                key lookup or any network request (fail-closed).

                Existing files under compiled_rules/pushed are preserved but ignored. \
                Detection-rule updates require a future app release after the owner \
                establishes offline key custody and explicitly enables the channel.
                """
        case .noRulesPublicKey:
            return """
                This build enabled the signed rule-update channel, but its packaged \
                public trust anchor (rules.pub) is missing. The build is internally \
                inconsistent or corrupt.

                The update is refused because no manifest can be authenticated without \
                that anchor (fail-closed). Do not substitute an unverified key; install \
                an owner-approved release with a documented channel key rotation.
                """
        case .rulesPublicKeyInvalid(let r): return "Rule-channel public key invalid: \(r)"
        case .httpFetchFailed(let url, let s): return "HTTP fetch failed: \(url.absoluteString) → HTTP \(s)"
        case .signatureVerifyFailed(let url): return "Ed25519 signature verification failed for \(url.absoluteString)"
        case .signatureSizeInvalid(let expected, let actual):
            return "Rules-manifest signature must be exactly \(expected) bytes; got \(actual)."
        case .manifestTooLarge(let maximum, let actual):
            return "Rules manifest is \(actual) bytes; the signed-channel limit is \(maximum) bytes. Refusing before parse or staging."
        case .ruleCountExceeded(let maximum, let actual):
            return "Rules manifest contains \(actual) rules; the signed-channel limit is \(maximum). Refusing the whole manifest."
        case .manifestParseFailed(let r): return "Rules manifest parse failed: \(r)"
        case .manifestSerialMissing:
            return "Refusing: the signature-verified rules manifest has no serial (anti-rollback requires one)."
        case .rollback(let stored, let incoming):
            return "Rules manifest rollback rejected — signed serial \(incoming) is older than the last-accepted \(stored). Keeping the prior pushed rules (stale/replay)."
        case .versionFloor(let r): return r
        case .ruleValidationFailed(let i, let r):
            return "Rules manifest rejected: rule #\(i) did not validate (\(r)). The whole manifest is refused (no partial corpus)."
        case .atomicRollbackFailed(let reason):
            return "Rules install could not restore the prior file/state pair after a failed trust-state commit: \(reason)"
        }
    }
}

/// Hard resource ceilings for the signed rule-update channel. The sender-side
/// builder carries the same values and pre-release-audit.sh asserts they do not
/// drift. Tests inject smaller ceilings to exercise both boundaries cheaply.
struct RuleChannelLimits: Sendable, Equatable {
    let maximumManifestBytes: Int
    let maximumRuleCount: Int

    static let production = RuleChannelLimits(
        maximumManifestBytes: 8_388_608, // 8 MiB; current full corpus is ~1 MiB.
        maximumRuleCount: 2_048          // >4x the current single-event corpus.
    )

    static let signatureBytes = 64
}

/// Accumulates an HTTP response without ever retaining byte `maximumBytes + 1`.
/// RuleChannelFetcher drives this from URLSession.AsyncBytes so a chunked peer
/// cannot make URLSession buffer an unbounded body before the policy runs.
struct RuleChannelBodyAccumulator: Sendable {
    let maximumBytes: Int
    private(set) var data: Data

    init(maximumBytes: Int) {
        self.maximumBytes = maximumBytes
        self.data = Data()
        self.data.reserveCapacity(min(maximumBytes, 64 * 1024))
    }

    mutating func append(_ byte: UInt8) -> Bool {
        guard data.count < maximumBytes else { return false }
        data.append(byte)
        return true
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

enum RuleChannelUpdateResult: Sendable, Equatable {
    case installed(serial: Int, ruleCount: Int)
    /// A verified manifest at the already-accepted serial is idempotent: do not
    /// let different bytes that reused a serial replace the installed corpus.
    case unchanged(serial: Int)
}

enum RuleChannelSerialDisposition: Sendable, Equatable {
    case firstSeen
    case newer
    case unchanged
    case rollback(stored: Int, incoming: Int)
}

struct RuleChannelFetcher {
    let rulesBase: URL
    let rulesPublicKey: Curve25519.Signing.PublicKey
    let trustState: RaveTrustStateStore

    init(rulesBase: String, trustState: RaveTrustStateStore? = nil) throws {
        // This must be the first operation: disabled release builds do not parse
        // operator input, inspect a key path, or create a network-capable fetcher.
        guard RuleChannelPolicy.productionEnabled else {
            throw RuleChannelError.channelDisabled
        }
        var trimmed = rulesBase
        if !trimmed.hasSuffix("/") { trimmed += "/" }
        guard let url = URL(string: trimmed) else {
            throw RuleChannelError.manifestParseFailed(reason: "bad rules base URL: \(rulesBase)")
        }
        self.rulesBase = url
        self.rulesPublicKey = try Self.loadRulesPublicKey()
        self.trustState = trustState ?? RaveTrustStateStore.default(supportDir: maccrabUserWritableDataDir())
    }

    /// Dependency-injected construction for direct, side-effect-free verifier
    /// and staging-policy tests. Production callers use the String initializer,
    /// which resolves only the packaged key (plus DEBUG-only test overrides).
    init(
        rulesBase: URL,
        rulesPublicKey: Curve25519.Signing.PublicKey,
        trustState: RaveTrustStateStore
    ) {
        self.rulesBase = rulesBase
        self.rulesPublicKey = rulesPublicKey
        self.trustState = trustState
    }

    // MARK: - Key

    private static func loadRulesPublicKey() throws -> Curve25519.Signing.PublicKey {
        #if DEBUG
        if let path = ProcessInfo.processInfo.environment["MACCRAB_RAVE_RULES_PUB_PATH"], !path.isEmpty {
            return try loadFromFile(path: path)
        }
        #endif
        // The cwd-relative candidate is DEBUG-only, same as the env override
        // above: in a release build it makes anyone who can write a directory the
        // operator later runs `maccrabctl rules update` from (a cloned repo,
        // ~/Downloads, an agent workspace) the signing authority for the entire
        // detection-rule channel.
        // Probe the SPM RESOURCE BUNDLE first — that is where `swift build`
        // actually places Sources/MacCrabApp/Resources/**, and it is where the
        // sibling catalog.pub lands in shipped builds. If a future approved
        // release enables this channel, its rotated rules.pub belongs in that
        // resource bundle too. The rave-keys/ path below is a legacy probe.
        // Mirrors PluginCatalogFetch.loadCatalogPublicKey's ordering.
        var candidates = [
            "/Applications/MacCrab.app/Contents/Resources/MacCrab_MacCrabApp.bundle/rules.pub",
            "/Applications/MacCrab.app/Contents/Resources/rave-keys/rules.pub",
        ]
        #if DEBUG
        candidates.append(
            FileManager.default.currentDirectoryPath + "/Sources/MacCrabApp/Resources/rave-keys/rules.pub")
        #endif
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

    private func fetch(
        url: URL,
        maximumBytes: Int,
        oversizedError: (Int) -> RuleChannelError
    ) async throws -> Data {
        // Defense in depth at the network boundary: even an internal caller that
        // bypasses the production String initializer cannot issue a request while
        // the shared release policy is disabled.
        guard RuleChannelPolicy.productionEnabled else {
            throw RuleChannelError.channelDisabled
        }
        // Route through SecureURLSession.shared (TLS 1.2 floor, ephemeral no-disk
        // cache, SSRF-redirect re-validation) — the hardened session every other
        // outbound caller uses. This is the highest-trust channel (it delivers
        // detection rules), so it must not fall back to raw URLSession.shared.
        // We ALSO keep the explicit no-cache request policy: the manifest is
        // re-published frequently and the anti-rollback serial only works if we
        // actually SEE the newest one; a stale cached copy would silently mask a
        // just-published update.
        var req = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData)
        req.setValue("no-cache", forHTTPHeaderField: "Cache-Control")
        // Stream with a hard cap DURING accumulation. A post-data(for:) count
        // check is not a memory bound: a chunked hostile response can make
        // URLSession allocate gigabytes before that check gets control.
        let (bytes, response) = try await SecureURLSession.shared.bytes(for: req)
        guard let http = response as? HTTPURLResponse else {
            throw RuleChannelError.httpFetchFailed(url: url, status: -1)
        }
        guard (200..<300).contains(http.statusCode) else {
            throw RuleChannelError.httpFetchFailed(url: url, status: http.statusCode)
        }
        let declared = http.expectedContentLength
        if declared > Int64(maximumBytes) {
            let reported = declared > Int64(Int.max) ? Int.max : Int(declared)
            throw oversizedError(reported)
        }
        var body = RuleChannelBodyAccumulator(maximumBytes: maximumBytes)
        for try await byte in bytes {
            guard body.append(byte) else {
                throw oversizedError(maximumBytes + 1)
            }
        }
        return body.data
    }

    /// Fetch `rules-manifest.json` + `.sig`, Ed25519-verify, and parse. Each rule
    /// is decode-validated as a CompiledRule here; a single bad rule rejects the
    /// whole manifest (fail-closed — no partial corpus).
    func fetchVerifiedManifest() async throws -> RuleChannelManifest {
        guard RuleChannelPolicy.productionEnabled else {
            throw RuleChannelError.channelDisabled
        }
        let manifestURL = rulesBase.appendingPathComponent("rules-manifest.json")
        let sigURL = rulesBase.appendingPathComponent("rules-manifest.json.sig")
        let maximumManifestBytes = RuleChannelLimits.production.maximumManifestBytes
        let manifestData = try await fetch(
            url: manifestURL,
            maximumBytes: maximumManifestBytes,
            oversizedError: {
                .manifestTooLarge(maximumBytes: maximumManifestBytes, actualBytes: $0)
            }
        )
        let sig = try await fetch(
            url: sigURL,
            maximumBytes: RuleChannelLimits.signatureBytes,
            oversizedError: {
                .signatureSizeInvalid(
                    expectedBytes: RuleChannelLimits.signatureBytes,
                    actualBytes: $0
                )
            }
        )
        return try Self.verifyAndParseManifest(
            manifestData: manifestData,
            signature: sig,
            publicKey: rulesPublicKey,
            manifestURL: manifestURL
        )
    }

    /// Pure verifier/parser used by the network path and imported directly by
    /// MacCrabCLITests. Resource ceilings are enforced before signature work or
    /// JSON allocation, and the decoded array count is checked before per-rule
    /// re-encoding/decoding.
    static func verifyAndParseManifest(
        manifestData: Data,
        signature: Data,
        publicKey: Curve25519.Signing.PublicKey,
        manifestURL: URL,
        limits: RuleChannelLimits = .production
    ) throws -> RuleChannelManifest {
        guard manifestData.count <= limits.maximumManifestBytes else {
            throw RuleChannelError.manifestTooLarge(
                maximumBytes: limits.maximumManifestBytes,
                actualBytes: manifestData.count
            )
        }
        guard signature.count == RuleChannelLimits.signatureBytes else {
            throw RuleChannelError.signatureSizeInvalid(
                expectedBytes: RuleChannelLimits.signatureBytes,
                actualBytes: signature.count
            )
        }
        guard publicKey.isValidSignature(signature, for: manifestData) else {
            throw RuleChannelError.signatureVerifyFailed(url: manifestURL)
        }
        guard let obj = try? JSONSerialization.jsonObject(with: manifestData) as? [String: Any] else {
            throw RuleChannelError.manifestParseFailed(reason: "not a JSON object")
        }
        guard let serialNumber = obj["serial"] as? NSNumber else {
            throw RuleChannelError.manifestSerialMissing
        }
        // JSONSerialization bridges booleans through NSNumber and `.intValue`
        // truncates floating point. Neither is an actual JSON integer. Reject
        // them, negatives and values outside Int before the anti-rollback gate.
        let numberType = String(cString: serialNumber.objCType)
        let integerNumberTypes: Set<String> = ["s", "i", "l", "q", "S", "I", "L", "Q"]
        guard integerNumberTypes.contains(numberType),
              serialNumber.int64Value >= 0,
              UInt64(serialNumber.int64Value) <= UInt64(Int.max) else {
            throw RuleChannelError.manifestParseFailed(
                reason: "serial must be a nonnegative JSON integer representable by Int"
            )
        }
        let serial = Int(serialNumber.int64Value)
        let corpus = (obj["corpus_version"] as? String) ?? "?"
        let floor = obj["min_maccrab_version"] as? String
        guard let rawRules = obj["rules"] as? [[String: Any]] else {
            throw RuleChannelError.manifestParseFailed(reason: "missing 'rules' array")
        }
        guard rawRules.count <= limits.maximumRuleCount else {
            throw RuleChannelError.ruleCountExceeded(
                maximum: limits.maximumRuleCount,
                actual: rawRules.count
            )
        }
        let decoder = JSONDecoder()
        var rules: [(id: String, json: Data)] = []
        var seenRuleIDs: Set<String> = []
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
            guard seenRuleIDs.insert(rule.id).inserted else {
                throw RuleChannelError.ruleValidationFailed(
                    ruleIndex: i,
                    reason: "duplicate rule id '\(rule.id)'"
                )
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
                            updateAvailable: installed.map { m.serial > $0 } ?? true, ruleCount: m.rules.count)
    }

    /// Fetch → verify → anti-rollback → version-floor → validate → atomic-swap the
    /// verified rules into `pushedDir`, then advance the serial high-water mark.
    /// An equal serial is a successful no-op: signed bytes that reuse an accepted
    /// serial can never replace the installed corpus. Fail-closed: any failure
    /// leaves the prior pushed corpus intact.
    @discardableResult
    func update(into pushedDir: URL) async throws -> RuleChannelUpdateResult {
        let m = try await fetchVerifiedManifest()
        return try applyVerifiedManifest(m, into: pushedDir)
    }

    static func serialDisposition(stored: Int?, incoming: Int) -> RuleChannelSerialDisposition {
        guard let stored else { return .firstSeen }
        if incoming < stored { return .rollback(stored: stored, incoming: incoming) }
        if incoming == stored { return .unchanged }
        return .newer
    }

    /// Apply an already signature-verified and decoded manifest. Split from the
    /// network fetch so tests can prove equal-serial bytes never touch the staged
    /// corpus or high-water mark.
    func applyVerifiedManifest(
        _ m: RuleChannelManifest,
        into pushedDir: URL,
        replacingDirectoryWith replaceDirectory: (
            _ staged: URL,
            _ destination: URL,
            _ destinationExists: Bool
        ) throws -> Void = RuleChannelFetcher.replaceDirectoryAtomically
    ) throws -> RuleChannelUpdateResult {
        let stored = trustState.load().rulesManifestSerial
        switch Self.serialDisposition(stored: stored, incoming: m.serial) {
        case .rollback(let stored, let incoming):
            throw RuleChannelError.rollback(stored: stored, incoming: incoming)
        case .unchanged:
            return .unchanged(serial: m.serial)
        case .firstSeen, .newer:
            break
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
        let destinationExists = fm.fileExists(atPath: pushedDir.path)
        do {
            // For an existing destination the default implementation uses
            // macOS RENAME_SWAP: either both directory names exchange atomically
            // or neither changes. `tmp` then names the prior accepted corpus.
            try replaceDirectory(tmp, pushedDir, destinationExists)
        } catch {
            try? fm.removeItem(at: tmp)
            throw error
        }
        try? fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: pushedDir.path)

        // Advance the high-water mark only after the swap succeeds. Keep the
        // prior directory at `tmp` until the state write commits; if persistence
        // fails, swap it back so files and serial remain a consistent pair.
        do {
            try trustState.recordRulesManifest(serial: m.serial)
        } catch let commitError {
            if destinationExists {
                do {
                    try Self.replaceDirectoryAtomically(
                        staged: tmp,
                        destination: pushedDir,
                        destinationExists: true
                    )
                } catch let rollbackError {
                    // A failed swap-back leaves the prior corpus at `tmp`.
                    // Preserve it for operator recovery; deleting it here would
                    // turn a state-write failure into data loss.
                    throw RuleChannelError.atomicRollbackFailed(
                        reason: "trust state: \(commitError); restore: \(rollbackError); prior corpus preserved at \(tmp.path)"
                    )
                }
            } else {
                do {
                    try fm.removeItem(at: pushedDir)
                } catch let rollbackError {
                    throw RuleChannelError.atomicRollbackFailed(
                        reason: "trust state: \(commitError); removing first install: \(rollbackError)"
                    )
                }
            }
            // After a successful swap-back, `tmp` contains the rejected new
            // corpus. For a rolled-back first install it no longer exists.
            try? fm.removeItem(at: tmp)
            throw commitError
        }
        // On RENAME_SWAP `tmp` now contains the old corpus. Once trust state is
        // durable it is no longer needed. For a first install `tmp` was renamed
        // away and this is a no-op.
        try? fm.removeItem(at: tmp)
        return .installed(serial: m.serial, ruleCount: m.rules.count)
    }

    /// Atomically install a staged directory. Existing destinations are swapped
    /// with the staged directory in one filesystem operation; a syscall failure
    /// leaves both names and all bytes untouched. Both paths are siblings, so the
    /// no-destination rename is atomic as well.
    static func replaceDirectoryAtomically(
        staged: URL,
        destination: URL,
        destinationExists: Bool
    ) throws {
        let result: Int32 = staged.path.withCString { stagedPath in
            destination.path.withCString { destinationPath in
                if destinationExists {
                    return Darwin.renamex_np(
                        stagedPath,
                        destinationPath,
                        UInt32(RENAME_SWAP)
                    )
                }
                return Darwin.rename(stagedPath, destinationPath)
            }
        }
        guard result == 0 else {
            let code = errno
            throw NSError(
                domain: NSPOSIXErrorDomain,
                code: Int(code),
                userInfo: [NSLocalizedDescriptionKey: "atomic rules-directory replacement failed: \(String(cString: strerror(code)))"]
            )
        }
    }
}
