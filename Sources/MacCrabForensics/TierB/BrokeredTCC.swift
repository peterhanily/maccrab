// BrokeredTCC — partitions a sandboxed third-party plugin's manifest-declared
// reads into (non-TCC → the broker opens them directly) and (TCC-protected → the
// host SNAPSHOTS the live store into a host-owned, plugin-UNWRITABLE dir and the
// broker REDIRECTS the real path to the snapshot). The untrusted child therefore
// never opens a TCC-protected store and never inherits host FDA/TCC — it only
// ever gets an fd to a frozen copy. (Plan §3.1 / Invariant 2 / binding decision:
// full brokered personal-comms from v0.)
//
// SECURITY: snapshots land in a host-owned 0o700 dir with 0o600 files (the broker
// review showed plugin-WRITABLE roots enable hardlink/symlink bypass — snapshot
// roots are deliberately not plugin-writable). A TCC source that cannot be
// snapshotted in this build (a directory — recursive snapshot not built yet — or
// a missing/oversized/unreadable file) is FAIL-CLOSED: it is neither a direct
// root nor a redirect, so the broker denies it.
//
// STATUS: built + unit-tested; the runner does not call this yet (it wires into
// the deferred SandboxedTierBRunner fd-3 attach). The snapshot of the LIVE store
// requires the host's FDA/TCC at call time — which it has, and the child never
// does.

import Foundation

/// Classifies a path as TCC-protected (must be brokered via a snapshot, never
/// opened live by the untrusted child).
public enum TCCProtectedPaths {

    /// Home-relative prefixes of TCC-protected locations. Expanded as the corpus
    /// surfaces more on device; over-inclusion is safe (it only forces brokering).
    static let homeRelativePrefixes: [String] = [
        "Library/Messages",                              // chat.db — personal-comms
        "Library/Mail",
        "Library/Safari",
        "Library/Application Support/com.apple.TCC",      // TCC.db
        "Library/Application Support/AddressBook",
        "Library/Application Support/CallHistoryDB",
        "Library/Application Support/CallHistoryTransactions",
        "Library/Calendars",                             // Calendar.app store — Calendars TCC
        "Library/Reminders",                             // Reminders store — Reminders TCC
        "Library/Application Support/Knowledge",          // knowledgeC.db — usage graph
        "Library/Application Support/com.apple.sharedfilelist",
        "Library/Accounts",                              // Accounts4.sqlite — identities
        "Library/Biome",                                 // event streams (messaging/intent)
        "Library/DuetExpertCenter",                      // Siri/proactive (knowledgeC-class)
        "Library/CoreFollowUp",
        "Library/IntelligencePlatform",
        "Library/com.apple.aiml.instrumentation",
        "Library/Sharing",
        "Library/Suggestions",
        "Library/Trial",
        "Library/CloudStorage",
        "Library/Autosave Information",
        "Library/Containers",                             // sandboxed-app data (many TCC)
        "Library/Group Containers",
        "Library/Daemon Containers",                      // per-daemon sandboxed stores
        "Library/Cookies",
        "Library/HomeKit",
        "Library/IdentityServices",
        "Library/Metadata/CoreSpotlight",
        "Pictures/Photos Library.photoslibrary",
        // Credential + secret stores that live OUTSIDE ~/Library (home dotfiles).
        // These are NOT under the ~/Library deny-by-default subtree, so without an
        // explicit prefix the FDA-holding broker would serve them LIVE as a direct
        // read root and the consent sheet would miss them entirely. They must be
        // brokered (snapshotted, or denied if a directory/unreadable) and consent-
        // gated exactly like chat.db / Mail / TCC.db. (`.config` is broad but
        // over-classification is safe — it only forces brokering.)
        ".ssh",                                          // SSH private keys / known_hosts
        ".aws",                                          // AWS access keys + config
        ".config",                                       // gcloud + many CLI credential stores
        ".netrc",                                        // machine login tokens
        ".docker",                                       // ~/.docker/config.json registry auth
        ".gnupg",                                        // GPG keyrings
        ".kube",                                         // kubeconfig (cluster credentials)
        ".azure",                                        // Azure CLI credentials
    ]

    /// Absolute (non-home) TCC-protected prefixes.
    static let absolutePrefixes: [String] = [
        "/Library/Application Support/com.apple.TCC",
    ]

    /// The ONLY ~/Library subtrees the FDA broker may serve LIVE (deny-by-default,
    /// below). Kept deliberately small: adding a prefix here means the broker opens
    /// the real file with the host's Full Disk Access, so it must be a location
    /// Apple does NOT gate behind TCC/FDA-sensitive consent. `Library/Preferences`
    /// is not TCC-gated and is routinely read; everything else under ~/Library
    /// (Calendars, Reminders, and any store Apple adds later) is snapshotted or
    /// denied rather than served live.
    static let homeLibrarySafePrefixes: [String] = [
        "Library/Preferences",
    ]

    /// True iff `path` must be BROKERED (snapshotted, or denied) rather than opened
    /// LIVE by the FDA-holding broker for `home`.
    ///
    /// Two rules, both fail-safe:
    ///   1. an explicit TCC-protected location (the prefix lists above), and
    ///   2. DENY-BY-DEFAULT across the whole ~/Library subtree: anything under
    ///      ~/Library that is not on `homeLibrarySafePrefixes` is protected. A new
    ///      or unenumerated TCC store (Calendars, Reminders, a future one) is thus
    ///      never leaked live merely because it wasn't named — the broker holds
    ///      host FDA, so an ~/Library read it isn't sure is safe is snapshotted or
    ///      denied. (System `/Library` and non-Library paths are unaffected.)
    ///
    /// Matching is CASE-FOLDED: the default macOS boot volume is APFS
    /// case-insensitive, so `/Users/x/library/Messages` resolves to the real
    /// `Library` at open time. A case-sensitive classifier would file that as a
    /// direct (live) read and leak the store; folding closes that bypass.
    /// Over-classification is safe (it only forces brokering).
    public static func isProtected(_ path: String, home: String) -> Bool {
        let p = path.lowercased()
        let h = (home.hasSuffix("/") ? String(home.dropLast()) : home).lowercased()
        for rel in homeRelativePrefixes {
            let pre = (h + "/" + rel).lowercased()
            if p == pre || p.hasPrefix(pre + "/") { return true }
        }
        for abs in absolutePrefixes {
            let a = abs.lowercased()
            if p == a || p.hasPrefix(a + "/") { return true }
        }
        // Deny-by-default under ~/Library: protected unless on a known-safe prefix.
        let lib = h + "/library"
        if p == lib || p.hasPrefix(lib + "/") {
            return !isHomeLibrarySafe(p, foldedHome: h)
        }
        return false
    }

    /// True iff a case-folded `p` (home already folded to `foldedHome`) is at or
    /// under a known-safe ~/Library prefix — the broker may serve it LIVE.
    private static func isHomeLibrarySafe(_ p: String, foldedHome h: String) -> Bool {
        for safe in homeLibrarySafePrefixes {
            let s = (h + "/" + safe).lowercased()
            if p == s || p.hasPrefix(s + "/") { return true }
        }
        return false
    }

    /// True iff `path` is a LIVE-served ~/Library read (under ~/Library and on the
    /// known-safe allowlist). Such a read is more sensitive than generic file
    /// "content" — the broker opens it with the host's Full Disk Access — so the
    /// consent summary elevates it above plain content.
    public static func isLiveServedHomeLibrary(_ path: String, home: String) -> Bool {
        let p = path.lowercased()
        let h = (home.hasSuffix("/") ? String(home.dropLast()) : home).lowercased()
        let lib = h + "/library"
        guard p == lib || p.hasPrefix(lib + "/") else { return false }
        return isHomeLibrarySafe(p, foldedHome: h)
    }
}

/// The broker-policy inputs derived for one sandboxed invocation.
public struct BrokeredReadPlan: Sendable {
    /// Non-TCC manifest reads — the broker opens these directly.
    public let directReadRoots: [String]
    /// TCC reads remapped to their snapshots (real path → snapshot file).
    public let redirects: [TierBFileBroker.Redirect]
    /// (live source, snapshot path) — for the audit log + the consent sheet.
    public let snapshotted: [(source: String, snapshot: String)]
    /// TCC reads that could NOT be brokered in this build (directory sources, or
    /// missing/unreadable files) — fail-closed (neither granted nor redirected).
    public let denied: [String]
    /// The home dir TCC classification was resolved against. Handed to the broker
    /// Policy as the SERVED-PATH TCC guard: a direct read root may be an ANCESTOR
    /// of a TCC store (a plugin declaring `~/Library` would otherwise let the
    /// FDA-holding broker open `~/Library/Messages/chat.db` LIVE). The guard
    /// fail-closes any served TCC path that isn't an explicit snapshot redirect.
    public let tccGuardHome: String

    /// Build the broker Policy for this plan + the plugin's own scratch dir.
    ///
    /// WIRING CONTRACT: `snapshotDir` (where the redirects point) MUST be
    /// host-owned and OUTSIDE the plugin-writable `scratchDir` — the whole scheme
    /// rests on snapshots being plugin-unwritable (a same-uid plugin could
    /// otherwise replace a 0o600 snapshot). As defense in depth this DROPS any
    /// redirect whose snapshot resolved under `scratchDir` (fail-closed: that
    /// source becomes unreadable rather than reading a plugin-tamperable copy).
    ///
    /// The Policy also carries `tccGuardHome` so the broker re-checks every DIRECT
    /// (non-redirect) grant on the SERVED path: a broad ancestor read root can
    /// never coax the broker into opening a live TCC-protected store — those are
    /// reachable only via the explicit snapshot redirects built here.
    public func brokerPolicy(scratchDir: String) -> TierBFileBroker.Policy {
        let scratch = scratchDir.hasSuffix("/") ? String(scratchDir.dropLast()) : scratchDir
        let safeRedirects = redirects.filter { !($0.to == scratch || $0.to.hasPrefix(scratch + "/")) }
        return TierBFileBroker.Policy(
            allowedReadRoots: directReadRoots + [scratchDir],
            redirects: safeRedirects,
            tccGuardHome: tccGuardHome
        )
    }
}

public enum BrokeredTCC {

    /// Prepare the brokered-read plan: snapshot every manifest-declared TCC FILE
    /// source into `snapshotDir` (host-owned, plugin-unwritable) and redirect the
    /// real path → snapshot. Non-TCC reads pass through as direct roots. Best-
    /// effort per source: a source that can't be snapshotted is denied, not fatal.
    public static func prepare(
        manifestReadPaths: [String],
        snapshotDir: URL,
        home: String,
        fileManager: FileManager = .default
    ) -> BrokeredReadPlan {
        var direct: [String] = []
        var redirects: [TierBFileBroker.Redirect] = []
        var snapshotted: [(String, String)] = []
        var denied: [String] = []

        for path in manifestReadPaths {
            guard TCCProtectedPaths.isProtected(path, home: home) else {
                direct.append(path)
                continue
            }
            // A TCC source must be an existing REGULAR FILE to snapshot in this
            // build. A directory (recursive snapshot not built yet) or a
            // missing/symlinked source is fail-closed.
            var isDir: ObjCBool = false
            guard fileManager.fileExists(atPath: path, isDirectory: &isDir), !isDir.boolValue else {
                denied.append(path)
                continue
            }
            do {
                let result: LiveDBSnapshotResult = looksLikeSQLite(path)
                    ? try LiveDBSnapshot.snapshot(sourcePath: path, destDir: snapshotDir)
                    : try LiveDBSnapshot.snapshotFile(sourcePath: path, destDir: snapshotDir)
                redirects.append(.init(prefix: path, to: result.path.path))
                snapshotted.append((path, result.path.path))
            } catch {
                denied.append(path)   // snapshot failed → stays denied (fail-closed)
            }
        }
        return BrokeredReadPlan(
            directReadRoots: direct, redirects: redirects,
            snapshotted: snapshotted, denied: denied,
            tccGuardHome: home
        )
    }

    /// Sniff the SQLite magic header so we backup-API a real DB (consistent even
    /// while tccd/Messages writes it) and plain-copy everything else. Falls back
    /// to the `.db` extension if the file can't be peeked.
    static func looksLikeSQLite(_ path: String) -> Bool {
        guard let fh = FileHandle(forReadingAtPath: path) else { return path.hasSuffix(".db") }
        defer { try? fh.close() }
        let magic = (try? fh.read(upToCount: 16)) ?? Data()
        return magic.starts(with: Array("SQLite format 3".utf8))
            || path.hasSuffix(".db") || path.hasSuffix(".sqlite") || path.hasSuffix(".sqlite3")
    }
}
