// DeliveryProvenanceWeld.swift
// MacCrabCore
//
// Phase-5 P0(2) — the Delivery-Provenance Weld.
//
// A pure ENRICHMENT that runs ONLY after one of a small set of already-precise
// HIGH credential-access / exfil rules fires (browser cookie DB read by a
// non-browser, direct keychain DB read, crypto-wallet read by an untrusted
// process, or the credential-read -> network-upload sequence). For the firing
// process's on-disk executable it welds together two forensic layers that no
// commodity EDR joins:
//
//   1. the file's `com.apple.quarantine` xattr GUID  ->  LSQuarantineEvent
//      (delivering agent + download time t0 + origin URL), via the EXISTING
//      QuarantineEnricher; and
//   2. for Chromium-delivered files (whose LSQuarantine origin_url is empty)
//      the referrer / redirect origin from Chromium's own History.downloads —
//      the same rows the `chrome_downloads_recent` collector parses, read here
//      through a Core-side mirror because MacCrabForensics is deliberately not
//      linked by the daemon/sysext (same layering split as
//      QuarantinePlugin <-> QuarantineEnricher).
//
// The result is attached as ALERT CONTEXT (appended to the alert's
// `description`, the same channel AlertSink's recalibration note uses):
//     "delivered by <app> from <origin> at <t0>, run <dwell> later".
//
// It MUST add ~ZERO new alerts of its own: it never emits an Alert, never
// changes severity, and never auto-executes any response action. When the
// FP-gate conjunction holds it merely marks the attached narrative as a
// SUSPICIOUS delivery; otherwise the narrative is neutral provenance context.
//
// Read-only throughout: the quarantine DB and Chromium History are opened
// READONLY (History via a backup-API snapshot, WAL-safe while the browser
// runs) and never mutated.

import Foundation
import CSQLCipher

// MARK: - Resolved provenance

/// The download provenance resolved for one executable: who delivered it,
/// when, and (best-effort) from what origin.
public struct DeliveryProvenance: Sendable, Equatable {
    /// Delivering agent — the LSQuarantineAgentBundleIdentifier, e.g.
    /// `"com.google.Chrome"`, `"com.apple.Safari"`, `"curl"`.
    public let deliveringAgent: String
    /// Download time t0 (LSQuarantineTimeStamp).
    public let downloadedAt: Date
    /// The downloaded file's URL (LSQuarantineDataURLString), if known.
    public let fileURL: String?
    /// Referring page / origin host (registrable domain resolvable from this),
    /// or nil when it could not be resolved (a required FP-gate input — its
    /// absence degrades the weld to narrative-only, no flag).
    public let originHost: String?
    /// Which layer resolved the origin: `"quarantine"` or `"chromium"`.
    public let originSource: String?

    public init(
        deliveringAgent: String,
        downloadedAt: Date,
        fileURL: String?,
        originHost: String?,
        originSource: String?
    ) {
        self.deliveringAgent = deliveringAgent
        self.downloadedAt = downloadedAt
        self.fileURL = fileURL
        self.originHost = originHost
        self.originSource = originSource
    }
}

/// Injectable provenance resolver so the weld's gate/narrative logic can be
/// unit-tested without live quarantine / Chromium databases. Production uses
/// `QuarantineProvenanceSource`.
public protocol DeliveryProvenanceSource: Sendable {
    func provenance(forExecutable path: String) async -> DeliveryProvenance?
    func provenance(forExecutable path: String, userID: UInt32) async -> DeliveryProvenance?
}

public extension DeliveryProvenanceSource {
    /// Compatibility path for synthetic/test sources that carry no per-user
    /// state. Production QuarantineProvenanceSource overrides this requirement.
    func provenance(forExecutable path: String, userID: UInt32) async -> DeliveryProvenance? {
        await provenance(forExecutable: path)
    }
}

// MARK: - Weld result

/// The context the weld produces for one alert. Never a new alert — this is
/// appended to the triggering alert's description.
public struct WeldResult: Sendable, Equatable {
    /// Human-readable delivery narrative ("delivered by X from Y at t0, run
    /// <dwell> later").
    public let narrative: String
    /// True when the FP-gate conjunction held — the delivery looks suspicious.
    /// False = neutral provenance context (attached, not escalated).
    public let flagged: Bool
    /// The FP-gate conjuncts that held (empty when not flagged / degraded).
    public let reasons: [String]

    public init(narrative: String, flagged: Bool, reasons: [String]) {
        self.narrative = narrative
        self.flagged = flagged
        self.reasons = reasons
    }

    /// Combine this context onto an existing alert description, matching the
    /// AlertSink recalibration-note style ("<base> — <clause>").
    public func appended(to base: String?) -> String {
        let label = flagged ? "Suspicious delivery" : "Delivery provenance"
        let clause = "\(label): \(narrative)"
        if let base, !base.isEmpty { return "\(base) — \(clause)" }
        return clause
    }
}

// MARK: - FP-gate (pure)

/// The pure false-positive gate for the delivery weld. Kept free of I/O and
/// actor state so the conjunction is directly unit-testable.
public enum DeliveryProvenanceGate {

    /// Inputs to the conjunction. `originRegistrableDomain == nil` means the
    /// origin could not be resolved — a REQUIRED input is missing, so the weld
    /// degrades safely (narrative only, no flag) rather than guessing.
    public struct Inputs: Sendable {
        public let originRegistrableDomain: String?
        public let signerType: SignerType?
        public let isAdhoc: Bool
        public let signingId: String?
        public let executablePath: String
        /// process.startTime - t0, in seconds. Negative = ran before the
        /// recorded download (anomalous / mismatched artifact).
        public let dwellSeconds: Double
        public let originFirstSeenThisSession: Bool
        /// Delivered as a Messages/Mail attachment. FDA-gated to a shell, so the
        /// daemon leaves this false — the "novel origin" branch carries G2.
        public let deliveredViaMessagesOrMail: Bool

        public init(
            originRegistrableDomain: String?,
            signerType: SignerType?,
            isAdhoc: Bool,
            signingId: String?,
            executablePath: String,
            dwellSeconds: Double,
            originFirstSeenThisSession: Bool,
            deliveredViaMessagesOrMail: Bool
        ) {
            self.originRegistrableDomain = originRegistrableDomain
            self.signerType = signerType
            self.isAdhoc = isAdhoc
            self.signingId = signingId
            self.executablePath = executablePath
            self.dwellSeconds = dwellSeconds
            self.originFirstSeenThisSession = originFirstSeenThisSession
            self.deliveredViaMessagesOrMail = deliveredViaMessagesOrMail
        }
    }

    public struct Decision: Sendable, Equatable {
        public let flagged: Bool
        /// True when a required input was missing and the weld degraded to
        /// narrative-only rather than guessing.
        public let degradedMissingInput: Bool
        public let reasons: [String]
    }

    /// Dwell ceiling: "tight" = the binary ran within a day of being delivered
    /// (consistent with a fresh malvertising / DMG delivery run in the same
    /// session). A binary run long after download is not a tight-dwell match.
    public static let dwellCeilingSeconds: Double = 24 * 60 * 60
    /// Clock-skew leeway for a slightly-negative dwell.
    public static let dwellLeewaySeconds: Double = 5 * 60

    /// Evaluate the conjunction. Flag an origin ONLY when ALL hold:
    ///   G1  origin registrable-domain != the binary's signer/team domain,
    ///       OR the binary is ad-hoc / unsigned; AND
    ///   G2  origin first-seen this session (or a Messages/Mail attachment); AND
    ///   G3  run-in-place from ~/Downloads, /tmp, /var temp, or a mounted DMG
    ///       (NOT /Applications and other trusted install roots); AND
    ///   G4  tight dwell (ran within the dwell window of t0).
    /// Any missing required input -> degrade (no flag).
    public static func evaluate(_ i: Inputs) -> Decision {
        // Required input: an origin domain. Without it G1/G2 cannot be decided.
        guard let origin = i.originRegistrableDomain, !origin.isEmpty else {
            return Decision(flagged: false, degradedMissingInput: true,
                            reasons: [])
        }

        // G1 — domain != signer/team OR untrusted binary.
        let untrusted = i.signerType == nil
            || i.signerType == .unsigned
            || i.signerType == .adHoc
            || i.isAdhoc
        let g1: Bool
        let g1Reason: String
        if untrusted {
            g1 = true
            g1Reason = "binary is unsigned/ad-hoc"
        } else {
            // Signed binary: establish the signer's vendor token(s) from the
            // signing identifier (reverse-DNS bundle id). If we cannot, the
            // "team domain" input is missing for a trusted binary -> degrade,
            // never flag a trust-anchored binary on a guess.
            let vendorTokens = signerVendorTokens(signingId: i.signingId)
            if vendorTokens.isEmpty {
                return Decision(flagged: false, degradedMissingInput: true, reasons: [])
            }
            let originLabel = primaryLabel(ofRegistrableDomain: origin)
            let mismatch = !vendorTokens.contains(originLabel)
            g1 = mismatch
            g1Reason = "origin domain \(origin) != signer \(vendorTokens.joined(separator: "/"))"
            if !mismatch {
                // Vendor self-delivery (Slack from slack.com, 1Password from
                // 1password.com, …) — suppress.
                return Decision(flagged: false, degradedMissingInput: false, reasons: [])
            }
        }
        guard g1 else {
            return Decision(flagged: false, degradedMissingInput: false, reasons: [])
        }

        // G2 — novel origin this session (or Messages/Mail attachment).
        let g2 = i.originFirstSeenThisSession || i.deliveredViaMessagesOrMail
        guard g2 else {
            return Decision(flagged: false, degradedMissingInput: false, reasons: [])
        }

        // G3 — run-in-place from an untrusted location, not /Applications.
        guard isRunInPlace(i.executablePath) else {
            return Decision(flagged: false, degradedMissingInput: false, reasons: [])
        }

        // G4 — tight dwell.
        guard i.dwellSeconds >= -dwellLeewaySeconds,
              i.dwellSeconds <= dwellCeilingSeconds else {
            return Decision(flagged: false, degradedMissingInput: false, reasons: [])
        }

        let reasons = [
            g1Reason,
            i.deliveredViaMessagesOrMail ? "delivered as a Messages/Mail attachment" : "origin first-seen this session",
            "run in place from \(runInPlaceLabel(i.executablePath))",
            "ran within \(DeliveryProvenanceWeld.humanDwell(i.dwellSeconds)) of download",
        ]
        return Decision(flagged: true, degradedMissingInput: false, reasons: reasons)
    }

    // MARK: Helpers (pure)

    /// The registrable domain (eTLD+1 approximation: the last two labels) of a
    /// host. `"www.evil.example.com"` -> `"example.com"`. Best-effort — the
    /// weld is enrichment, not authority; a two-label public suffix (co.uk) is
    /// out of scope.
    public static func registrableDomain(ofHost host: String) -> String? {
        let h = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        guard !h.isEmpty else { return nil }
        let labels = h.split(separator: ".")
        guard labels.count >= 2 else { return labels.isEmpty ? nil : h }
        return labels.suffix(2).joined(separator: ".")
    }

    /// The primary label of a registrable domain: `"evil-cdn.com"` ->
    /// `"evil-cdn"`.
    static func primaryLabel(ofRegistrableDomain domain: String) -> String {
        String(domain.split(separator: ".").first ?? Substring(domain))
    }

    /// Vendor tokens derived from a reverse-DNS signing identifier, used to
    /// compare a signer to an origin domain. `"com.google.Chrome"` ->
    /// `["google", "chrome"]`. Drops the generic leading TLD-ish label
    /// (com/org/io/net/app/co) so `com.slack.Slack` -> `["slack"]`.
    static func signerVendorTokens(signingId: String?) -> Set<String> {
        guard let id = signingId?.lowercased(), !id.isEmpty else { return [] }
        let generic: Set<String> = ["com", "org", "io", "net", "app", "co", "dev", "me", "us"]
        let labels = id.split(separator: ".").map(String.init).filter { !$0.isEmpty }
        guard labels.count >= 2 else { return [] }
        var tokens = Set(labels)
        // Remove the leading generic label(s) so the middle vendor label wins.
        if let first = labels.first, generic.contains(first) {
            tokens.remove(first)
        }
        tokens.subtract(generic)
        return tokens
    }

    /// True when the executable is running IN PLACE from a delivery location
    /// (Downloads, temp, or a mounted DMG) rather than a trusted install root
    /// like /Applications. Validated-real-home aware for user Downloads dirs.
    public static func isRunInPlace(_ path: String) -> Bool {
        if let home = RealUserHomeResolver.home(containingPath: path),
           path.hasPrefix(home.appending("Downloads") + "/") { return true }
        if path.hasPrefix("/tmp/") || path.hasPrefix("/private/tmp/") { return true }
        if path.hasPrefix("/var/folders/") || path.hasPrefix("/private/var/folders/") { return true }
        if path.hasPrefix("/Volumes/") { return true }  // mounted DMG / removable
        return false
    }

    static func runInPlaceLabel(_ path: String) -> String {
        if let home = RealUserHomeResolver.home(containingPath: path),
           path.hasPrefix(home.appending("Downloads") + "/") { return "~/Downloads" }
        if path.hasPrefix("/Volumes/") { return "a mounted volume/DMG" }
        if path.contains("/var/folders/") { return "a temp directory" }
        if path.hasPrefix("/tmp/") || path.hasPrefix("/private/tmp/") { return "/tmp" }
        return "a delivery location"
    }
}

// MARK: - The weld

/// Runs the delivery-provenance weld on firing cred/exfil alerts. Actor because
/// it holds the session-scoped novel-origin set (the G2 "first-seen this
/// session" input).
public actor DeliveryProvenanceWeld {

    /// The exact rule IDs the weld fires on. Attaching provenance to anything
    /// else would break the "enrichment on an already-precise trigger" contract
    /// and risk new noise, so the set is intentionally closed.
    public static let triggerRuleIds: Set<String> = [
        "d1a2b3c4-0031-4000-a000-000000000031", // Browser Cookie DB Accessed by Non-Browser
        "d1a2b3c4-0034-4000-a000-000000000034", // login.keychain / System.keychain opened by non-Apple
        "a1b2c3d4-0003-4000-a003-000000000003", // Cryptocurrency Wallet Data Accessed by Untrusted
        "e1f2a3b4-0009-4000-b000-000000000009", // Credential File Access Followed by Network Upload (sequence)
    ]

    private let source: any DeliveryProvenanceSource
    /// Origin registrable-domains already welded this session -> a domain not in
    /// here is "first-seen this session" (the G2 input).
    private var seenOrigins: Set<String> = []
    private let maxSeenOrigins = 4096

    public init(source: any DeliveryProvenanceSource) {
        self.source = source
    }

    /// Returns `true` iff `ruleId` is one the weld enriches.
    public nonisolated func isTrigger(ruleId: String) -> Bool {
        Self.triggerRuleIds.contains(ruleId)
    }

    /// Weld delivery provenance onto a firing alert. Returns nil (no change)
    /// when the alert's rule is not a trigger, or when the executable carries no
    /// resolvable download provenance (Preview-made / never-downloaded files
    /// have no quarantine GUID). Never emits an alert; never mutates severity.
    public func weld(alert: Alert, event: Event) async -> WeldResult? {
        guard Self.triggerRuleIds.contains(alert.ruleId) else { return nil }
        guard let prov = await source.provenance(
            forExecutable: event.process.executable,
            userID: event.process.userId
        ) else {
            return nil
        }

        let dwell = event.process.startTime.timeIntervalSince(prov.downloadedAt)
        let originDomain = prov.originHost.flatMap { DeliveryProvenanceGate.registrableDomain(ofHost: $0) }

        // G2 input: first time we see this origin domain this session.
        let firstSeen: Bool
        if let d = originDomain {
            firstSeen = !seenOrigins.contains(d)
            if firstSeen {
                if seenOrigins.count >= maxSeenOrigins { seenOrigins.removeAll() }
                seenOrigins.insert(d)
            }
        } else {
            firstSeen = false
        }

        let sig = event.process.codeSignature
        let inputs = DeliveryProvenanceGate.Inputs(
            originRegistrableDomain: originDomain,
            signerType: sig?.signerType,
            isAdhoc: sig?.isAdhocSigned ?? false,
            signingId: sig?.signingId,
            executablePath: event.process.executable,
            dwellSeconds: dwell,
            originFirstSeenThisSession: firstSeen,
            // FDA-gated to a shell in the daemon; left false (the "novel origin"
            // branch of G2 carries the gate). See onDeviceGaps.
            deliveredViaMessagesOrMail: false
        )
        let decision = DeliveryProvenanceGate.evaluate(inputs)

        let narrative = Self.narrative(agent: prov.deliveringAgent,
                                       origin: prov.originHost,
                                       t0: prov.downloadedAt,
                                       dwell: dwell)
        return WeldResult(narrative: narrative,
                          flagged: decision.flagged,
                          reasons: decision.reasons)
    }

    // MARK: Narrative

    /// "delivered by <app> from <origin> at <t0>, run <dwell> later".
    static func narrative(agent: String, origin: String?, t0: Date, dwell: Double) -> String {
        let app = prettyAgent(agent)
        let originClause = (origin.map { " from \($0)" }) ?? ""
        let iso = ISO8601DateFormatter().string(from: t0)
        let dwellClause = dwell >= 0
            ? "run \(humanDwell(dwell)) later"
            : "process start predates the recorded download (\(humanDwell(-dwell)) before)"
        return "delivered by \(app)\(originClause) at \(iso), \(dwellClause)"
    }

    /// Human-friendly delivering-agent name for common bundle identifiers,
    /// else the raw agent string.
    static func prettyAgent(_ agent: String) -> String {
        let map: [String: String] = [
            "com.google.chrome": "Google Chrome",
            "com.apple.safari": "Safari",
            "org.mozilla.firefox": "Firefox",
            "com.microsoft.edgemac": "Microsoft Edge",
            "com.brave.browser": "Brave",
            "company.thebrowser.browser": "Arc",
            "com.operasoftware.opera": "Opera",
            "com.vivaldi.vivaldi": "Vivaldi",
        ]
        return map[agent.lowercased()] ?? agent
    }

    /// Compact dwell formatting: "45s", "12m 3s", "3h 5m", "1d 4h".
    static func humanDwell(_ seconds: Double) -> String {
        let s = Int(seconds.rounded())
        if s < 60 { return "\(s)s" }
        if s < 3600 { return "\(s / 60)m \(s % 60)s" }
        if s < 86400 { return "\(s / 3600)h \((s % 3600) / 60)m" }
        return "\(s / 86400)d \((s % 86400) / 3600)h"
    }
}

// MARK: - Production provenance source

/// Production `DeliveryProvenanceSource`: joins the executable's quarantine GUID
/// (delivering agent + t0 + origin_url) to a Chromium History referrer when the
/// quarantine origin is empty (Chrome-dominated boxes).
public struct QuarantineProvenanceSource: DeliveryProvenanceSource {

    private let quarantine: QuarantineEnricher
    private let chromium: ChromiumDownloadOriginReader

    public init(quarantine: QuarantineEnricher,
                chromium: ChromiumDownloadOriginReader = ChromiumDownloadOriginReader()) {
        self.quarantine = quarantine
        self.chromium = chromium
    }

    public func provenance(forExecutable path: String) async -> DeliveryProvenance? {
        // Legacy callers have no uid, so the existing no-follow target must be
        // owned inside one validated home. Paths on volumes or in global app
        // directories cannot be associated and deliberately lose provenance.
        guard let home = RealUserHomeResolver.provenanceHome(forPath: path) else {
            return nil
        }
        return await provenance(forExecutable: path, home: home)
    }

    public func provenance(forExecutable path: String, userID: UInt32) async -> DeliveryProvenance? {
        guard let home = RealUserHomeResolver.provenanceHome(
            forPath: path,
            userID: userID
        ) else { return nil }
        return await provenance(forExecutable: path, home: home)
    }

    private func provenance(forExecutable path: String, home: RealUserHome) async -> DeliveryProvenance? {
        // Deterministic join: the file's com.apple.quarantine xattr GUID keys
        // its LSQuarantineEvent row. No GUID (Preview-made / never downloaded)
        // -> no provenance -> no weld.
        guard let guid = QuarantineEnricher.quarantineGUID(forPath: path),
              let q = await quarantine.lookupByGUID(
                  guid,
                  userID: home.userID,
                  executablePath: path
              ) else {
            return nil
        }

        var originHost = Self.host(q.originURL)
        var originSource: String? = originHost == nil ? nil : "quarantine"

        // Chromium keeps its referrer in its own History, not LSQuarantine.
        if originHost == nil, Self.isChromiumAgent(q.downloadAgent) {
            if let chrome = chromium.origin(forDownloadPath: path, userHome: home) {
                originHost = Self.host(chrome.referrer)
                    ?? Self.host(chrome.originURL)
                    ?? Self.host(chrome.tabURL)
                if originHost != nil { originSource = "chromium" }
            }
        }

        return DeliveryProvenance(
            deliveringAgent: q.downloadAgent,
            downloadedAt: q.downloadTimestamp,
            fileURL: q.downloadURL.isEmpty ? nil : q.downloadURL,
            originHost: originHost,
            originSource: originSource
        )
    }

    static func host(_ urlString: String?) -> String? {
        guard let s = urlString, !s.isEmpty, let h = URL(string: s)?.host, !h.isEmpty else { return nil }
        return h
    }

    static func fileName(fromURL urlString: String) -> String? {
        guard !urlString.isEmpty else { return nil }
        let last = URL(string: urlString)?.lastPathComponent
        guard let last, !last.isEmpty, last != "/" else { return nil }
        return last
    }

    static func isChromiumAgent(_ agent: String) -> Bool {
        let a = agent.lowercased()
        return a.contains("chrome") || a.contains("chromium") || a.contains("brave")
            || a.contains("edgemac") || a.contains("thebrowser") || a.contains("arc")
            || a.contains("vivaldi") || a.contains("opera")
    }
}

// MARK: - Core-side Chromium History origin reader

/// Reads the referrer / redirect origin for a downloaded file from Chromium's
/// per-profile `History.downloads` table — the same rows the
/// `chrome_downloads_recent` collector emits. Lives in Core (not MacCrabForensics,
/// which the daemon does not link) so the weld can resolve Chromium origins at
/// alert-fire time. STRICTLY read-only: each `History` is copied via the sqlite
/// backup API (WAL-safe while the browser runs) and read from the frozen snapshot.
public struct ChromiumDownloadOriginReader: Sendable {

    /// History is attacker-influenced and may be arbitrarily large. This
    /// enrichment runs inside the long-lived detection process, so a browser DB
    /// copy must obey the same boot-volume floor as other bounded stores.
    static let maxSnapshotBytes: Int64 = 512 * 1_048_576
    static let freeSpaceFloorBytes: Int64 = 1_024 * 1_048_576
    static let snapshotReserveBytes: Int64 = 16 * 1_048_576

    public struct Origin: Sendable, Equatable {
        public let referrer: String
        public let originURL: String  // first hop of the redirect chain
        public let tabURL: String
    }

    struct BrowserBase { let relPath: String }
    /// Same set the ChromiumLitePlugin enumerates.
    static let browserBases: [BrowserBase] = [
        BrowserBase(relPath: "Google/Chrome"),
        BrowserBase(relPath: "Google/Chrome Beta"),
        BrowserBase(relPath: "Google/Chrome Canary"),
        BrowserBase(relPath: "Chromium"),
        BrowserBase(relPath: "BraveSoftware/Brave-Browser"),
        BrowserBase(relPath: "Microsoft Edge"),
        BrowserBase(relPath: "Arc/User Data"),
        BrowserBase(relPath: "Vivaldi"),
        BrowserBase(relPath: "com.operasoftware.Opera"),
    ]

    public init() {}

    /// Find the most recent Chromium download whose on-disk target ends with
    /// `fileName` and return its referrer / origin. Returns nil when no
    /// Chromium History has a matching row.
    public func origin(forDownloadFileName fileName: String) -> Origin? {
        guard !fileName.isEmpty,
              let home = RealUserHomeResolver.uniqueHome() else { return nil }
        return origin(forDownloadFileName: fileName, userHome: home)
    }

    private func origin(forDownloadFileName fileName: String, userHome: RealUserHome) -> Origin? {
        let appSupport = userHome.appending("Library/Application Support") + "/"
        for base in Self.browserBases {
            let baseDir = appSupport + base.relPath
            for historyPath in Self.discoverHistories(baseDir: baseDir, ownerUID: userHome.userID) {
                if let o = Self.readOrigin(historyPath: historyPath, fileName: fileName) {
                    return o
                }
            }
        }
        return nil
    }

    /// Production exact join. A basename-only match can select a different
    /// user's/profile's `payload` download; bind discovery to one validated
    /// home and require the exact Chromium target_path. Conflicting profile
    /// results fail closed rather than taking directory-enumeration order.
    public func origin(forDownloadPath path: String, userHome: RealUserHome) -> Origin? {
        guard RealUserHomeResolver.provenanceHome(
                  forPath: path,
                  userID: userHome.userID
              ) == userHome else { return nil }
        let appSupport = userHome.appending("Library/Application Support") + "/"
        var matches: [Origin] = []
        for base in Self.browserBases {
            let baseDir = appSupport + base.relPath
            for historyPath in Self.discoverHistories(baseDir: baseDir, ownerUID: userHome.userID) {
                if let origin = Self.readOrigin(historyPath: historyPath, targetPath: path),
                   !matches.contains(origin) {
                    matches.append(origin)
                    guard matches.count == 1 else { return nil }
                }
            }
        }
        return matches.first
    }

    /// Directly read a single `History` SQLite file (legacy fixture API;
    /// production uses the event-bound exact target-path method above).
    public func origin(historyPath: String, fileName: String) -> Origin? {
        Self.readOrigin(historyPath: historyPath, fileName: fileName)
    }

    // MARK: profile discovery (base itself + immediate subdirs with a History)

    static func discoverHistories(baseDir: String, ownerUID: UInt32? = nil) -> [String] {
        guard let snapshot = BoundedDirectoryLister.list(
            at: baseDir,
            maximumEntries: 512,
            expectedOwnerUID: ownerUID
        ) else { return [] }
        // A bounded partial set is useful provenance enrichment and is never
        // advertised as a complete browser inventory.
        var result: [String] = []
        let baseHistory = baseDir + "/History"
        if snapshot.entries.contains(where: { entry in
            entry.name == "History"
                && entry.kind == .regularFile
                && (ownerUID.map { entry.ownerUID == $0 } ?? true)
        }), isReadableRegularFile(baseHistory, ownerUID: ownerUID) {
            result.append(baseHistory)
        }
        for entry in snapshot.entries where
            entry.kind == .directory
                && (ownerUID.map { entry.ownerUID == $0 } ?? true) {
            let hist = baseDir + "/" + entry.name + "/History"
            if isReadableRegularFile(hist, ownerUID: ownerUID) { result.append(hist) }
        }
        return result
    }

    static func isReadableRegularFile(_ path: String, ownerUID: UInt32? = nil) -> Bool {
        var info = stat()
        guard lstat(path, &info) == 0,
              (UInt32(info.st_mode) & UInt32(S_IFMT)) == UInt32(S_IFREG),
              info.st_nlink == 1,
              ownerUID.map({ info.st_uid == $0 }) ?? true else {
            return false
        }
        return access(path, R_OK) == 0
    }

    // MARK: read

    static func readOrigin(historyPath: String, fileName: String) -> Origin? {
        readOrigin(historyPath: historyPath, predicate: "%\(fileName)", exact: false)
    }

    static func readOrigin(historyPath: String, targetPath: String) -> Origin? {
        readOrigin(historyPath: historyPath, predicate: targetPath, exact: true)
    }

    private static func readOrigin(
        historyPath: String,
        predicate: String,
        exact: Bool
    ) -> Origin? {
        guard let snapshot = snapshot(sourcePath: historyPath) else { return nil }
        defer { try? FileManager.default.removeItem(atPath: snapshot) }

        var db: OpaquePointer?
        guard SQLiteOpenPathPolicy.open(
            snapshot,
            database: &db,
            flags: SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX
        ) == SQLITE_OK,
              let h = db else {
            if let h = db { sqlite3_close(h) }
            return nil
        }
        defer { sqlite3_close(h) }

        // Production passes an exact target path. The suffix form remains only
        // for the backwards-compatible single-fixture test API above.
        let sql = """
            SELECT d.id, COALESCE(d.referrer, ''), COALESCE(d.tab_url, '')
            FROM downloads d
            WHERE d.target_path \(exact ? "=" : "LIKE") ?
            ORDER BY d.start_time DESC
            LIMIT 1
            """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(h, sql, -1, &stmt, nil) == SQLITE_OK else { return nil }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, predicate, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self))
        guard sqlite3_step(stmt) == SQLITE_ROW else { return nil }

        let downloadID = sqlite3_column_int64(stmt, 0)
        let referrer = sqlite3_column_text(stmt, 1).map { String(cString: $0) } ?? ""
        let tabURL = sqlite3_column_text(stmt, 2).map { String(cString: $0) } ?? ""

        // First hop of the redirect chain = the origin URL.
        var originURL = ""
        let chainSQL = "SELECT COALESCE(url, '') FROM downloads_url_chains WHERE id = ? ORDER BY chain_index ASC LIMIT 1"
        var chainStmt: OpaquePointer?
        if sqlite3_prepare_v2(h, chainSQL, -1, &chainStmt, nil) == SQLITE_OK {
            sqlite3_bind_int64(chainStmt, 1, downloadID)
            if sqlite3_step(chainStmt) == SQLITE_ROW {
                originURL = sqlite3_column_text(chainStmt, 0).map { String(cString: $0) } ?? ""
            }
        }
        if chainStmt != nil { sqlite3_finalize(chainStmt) }

        return Origin(referrer: referrer, originURL: originURL, tabURL: tabURL)
    }

    /// Copy `sourcePath` to a fresh temp file via the sqlite backup API
    /// (WAL-safe while the browser holds the live DB). Returns the snapshot
    /// path, or nil on failure. Caller removes it.
    static func snapshot(
        sourcePath: String,
        maxBytes: Int64 = maxSnapshotBytes,
        freeFloorBytes: Int64 = freeSpaceFloorBytes,
        reserveBytes: Int64 = snapshotReserveBytes
    ) -> String? {
        guard maxBytes > 0 else { return nil }
        var sourceInfo = stat()
        guard lstat(sourcePath, &sourceInfo) == 0,
              (UInt32(sourceInfo.st_mode) & UInt32(S_IFMT)) == UInt32(S_IFREG),
              sourceInfo.st_nlink == 1 else {
            return nil
        }
        let dest = NSTemporaryDirectory() + "maccrab-chromium-\(UUID().uuidString).db"
        defer {
            // Success transfers the main path to the caller; sidecars are never
            // useful to the read-only parser and must not leak on any path.
            for suffix in ["-wal", "-shm", "-journal"] {
                try? FileManager.default.removeItem(atPath: dest + suffix)
            }
        }
        var src: OpaquePointer?
        guard SQLiteOpenPathPolicy.open(
            sourcePath,
            database: &src,
            flags: SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX
        ) == SQLITE_OK,
              let s = src else {
            if let s = src { sqlite3_close(s) }
            return nil
        }
        defer { sqlite3_close(s) }

        guard let pageSize = pragmaInt64(s, name: "page_size"), pageSize > 0,
              let pageCount = pragmaInt64(s, name: "page_count"), pageCount >= 0 else {
            return nil
        }
        let (logicalBytes, overflow) = pageSize.multipliedReportingOverflow(by: pageCount)
        guard !overflow, logicalBytes <= maxBytes,
              hasFreeSpace(
                  at: NSTemporaryDirectory(),
                  floor: max(0, freeFloorBytes),
                  copy: logicalBytes,
                  reserve: max(0, reserveBytes)
              ) else {
            return nil
        }

        var dst: OpaquePointer?
        guard SQLiteOpenPathPolicy.open(
            dest,
            database: &dst,
            flags: SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE
                | SQLITE_OPEN_EXCLUSIVE | SQLITE_OPEN_FULLMUTEX
        ) == SQLITE_OK,
              let d = dst else {
            if let d = dst { sqlite3_close(d) }
            return nil
        }
        var success = false
        defer {
            sqlite3_close(d)
            if !success { try? FileManager.default.removeItem(atPath: dest) }
        }
        let maximumPages = max(Int64(1), maxBytes / pageSize)
        guard sqlite3_exec(d, "PRAGMA page_size = \(pageSize)", nil, nil, nil) == SQLITE_OK,
              sqlite3_exec(d, "PRAGMA max_page_count = \(maximumPages)", nil, nil, nil) == SQLITE_OK,
              sqlite3_exec(d, "PRAGMA journal_mode = OFF", nil, nil, nil) == SQLITE_OK else {
            return nil
        }
        guard let backup = sqlite3_backup_init(d, "main", s, "main") else {
            return nil
        }
        var finished = false
        defer { if !finished { sqlite3_backup_finish(backup) } }
        var busyRetries = 0
        while true {
            let rc = sqlite3_backup_step(backup, 256)
            if rc == SQLITE_DONE { break }
            if rc == SQLITE_BUSY || rc == SQLITE_LOCKED {
                guard busyRetries < 50 else { return nil }
                busyRetries += 1
                usleep(10_000)
                continue
            }
            guard rc == SQLITE_OK else { return nil }
            busyRetries = 0
            var destInfo = stat()
            guard lstat(dest, &destInfo) == 0,
                  (UInt32(destInfo.st_mode) & UInt32(S_IFMT)) == UInt32(S_IFREG),
                  destInfo.st_nlink == 1,
                  destInfo.st_size >= 0,
                  Int64(destInfo.st_size) <= maxBytes,
                  hasFreeSpace(
                      at: NSTemporaryDirectory(),
                      floor: max(0, freeFloorBytes),
                      copy: 0,
                      reserve: max(0, reserveBytes)
                  ) else {
                return nil
            }
        }
        let finishRC = sqlite3_backup_finish(backup)
        finished = true
        guard finishRC == SQLITE_OK else { return nil }
        var finalInfo = stat()
        guard lstat(dest, &finalInfo) == 0,
              (UInt32(finalInfo.st_mode) & UInt32(S_IFMT)) == UInt32(S_IFREG),
              finalInfo.st_nlink == 1,
              finalInfo.st_size >= 0,
              Int64(finalInfo.st_size) <= maxBytes,
              chmod(dest, 0o600) == 0 else { return nil }
        success = true
        return dest
    }

    private static func pragmaInt64(_ db: OpaquePointer, name: String) -> Int64? {
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(db, "PRAGMA \(name)", -1, &statement, nil) == SQLITE_OK,
              let statement else { return nil }
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW else { return nil }
        return sqlite3_column_int64(statement, 0)
    }

    private static func hasFreeSpace(
        at path: String,
        floor: Int64,
        copy: Int64,
        reserve: Int64
    ) -> Bool {
        let (floorAndCopy, overflow1) = floor.addingReportingOverflow(copy)
        let (required, overflow2) = floorAndCopy.addingReportingOverflow(reserve)
        guard !overflow1, !overflow2 else { return false }
        var info = statfs()
        guard statfs(path, &info) == 0 else { return false }
        let free = UInt64(info.f_bavail).multipliedReportingOverflow(
            by: UInt64(info.f_bsize)
        )
        guard !free.overflow else { return false }
        return Int64(clamping: free.partialValue) >= required
    }
}
