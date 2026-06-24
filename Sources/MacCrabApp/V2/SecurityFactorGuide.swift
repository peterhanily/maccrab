// SecurityFactorGuide.swift
//
// Per-security-factor explainer: what the factor means, why it matters, how to
// address a fail/warn, and a link to the authoritative Apple documentation.
// Surfaced when an operator clicks a row in the security-score breakdown so a
// "macOS Firewall: 0/6" line becomes actionable instead of just a red badge.

import Foundation

/// Actionable guidance for one security-score factor.
struct SecurityFactorGuide {
    /// What the control is, in one or two plain sentences.
    let what: String
    /// Why it matters to this Mac's security posture.
    let why: String
    /// Concrete steps to turn it on / fix a fail or warn (nil for informational
    /// factors that aren't an OS setting, e.g. "Active Alerts").
    let howToFix: String?
    /// Authoritative documentation (Apple support / security guide). nil for
    /// MacCrab-internal factors.
    let docTitle: String?
    let docURL: URL?

    init(what: String, why: String, howToFix: String? = nil, docTitle: String? = nil, doc: String? = nil) {
        self.what = what
        self.why = why
        self.howToFix = howToFix
        self.docTitle = docTitle
        self.docURL = doc.flatMap(URL.init(string:))
    }

    /// Look up the guide for a SecurityScorer factor by its name. Matching is
    /// case-insensitive + prefix-tolerant so minor scorer wording changes don't
    /// silently drop the explainer; falls back to a generic guide that still
    /// shows the factor's own one-line detail.
    static func forFactor(name: String, detail: String) -> SecurityFactorGuide {
        let key = name.lowercased()
        for (needle, guide) in table where key.contains(needle) {
            return guide
        }
        return SecurityFactorGuide(
            what: detail,
            why: "This factor contributes to MacCrab's overall security-posture score for this Mac.",
            howToFix: "Open System Settings and review the related security control; see Apple's macOS Security guide for details.",
            docTitle: "Apple Platform Security",
            doc: "https://support.apple.com/guide/security/welcome/web"
        )
    }

    /// Ordered (specific → general) so `contains` matches the right entry.
    private static let table: [(String, SecurityFactorGuide)] = [
        ("system integrity", SecurityFactorGuide(
            what: "System Integrity Protection (SIP, \u{201C}rootless\u{201D}) restricts even the root user from modifying protected system files, processes, and the kernel.",
            why: "With SIP off, malware running as root can tamper with the OS, disable security tools, and hide persistently. It is one of the strongest baseline macOS protections.",
            howToFix: "SIP can only be changed from Recovery: reboot holding the power button \u{2192} Options \u{2192} Utilities \u{2192} Terminal \u{2192} run \u{201C}csrutil enable\u{201D} \u{2192} reboot. Leave it ON unless a specific, trusted tool requires otherwise.",
            docTitle: "About System Integrity Protection",
            doc: "https://support.apple.com/en-us/102149")),
        ("filevault", SecurityFactorGuide(
            what: "FileVault encrypts the entire startup disk with XTS-AES-128, so the data is unreadable without the account password or recovery key.",
            why: "Without FileVault, anyone who removes the drive or boots from external media can read every file \u{2014} a lost or stolen Mac means a full data breach.",
            howToFix: "System Settings \u{2192} Privacy & Security \u{2192} FileVault \u{2192} Turn On. Store the recovery key somewhere safe (not on the Mac).",
            docTitle: "Encrypt your Mac with FileVault",
            doc: "https://support.apple.com/guide/mac-help/protect-data-on-your-mac-with-filevault-mh11785/mac")),
        ("firewall", SecurityFactorGuide(
            what: "The built-in application firewall controls which apps and services can accept incoming network connections.",
            why: "With the firewall off, any listening service on this Mac is reachable from the local network \u{2014} a larger attack surface for lateral movement.",
            howToFix: "System Settings \u{2192} Network \u{2192} Firewall \u{2192} turn it on. Consider enabling \u{201C}Block all incoming connections\u{201D} or stealth mode for higher assurance.",
            docTitle: "Block connections with a firewall",
            doc: "https://support.apple.com/guide/mac-help/block-connections-to-your-mac-with-a-firewall-mh34041/mac")),
        ("gatekeeper", SecurityFactorGuide(
            what: "Gatekeeper verifies that apps are signed by a known developer and notarized by Apple before they run, blocking unsigned or tampered software.",
            why: "Disabling Gatekeeper (\u{201C}allow apps from anywhere\u{201D}) removes a major barrier against trojaned downloads and unsigned malware.",
            howToFix: "Restore it from Terminal with \u{201C}sudo spctl --master-enable\u{201D}, then in System Settings \u{2192} Privacy & Security keep \u{201C}Allow applications from\u{201D} set to App Store / identified developers.",
            docTitle: "Safely open apps on your Mac",
            doc: "https://support.apple.com/en-us/102445")),
        ("automatic update", SecurityFactorGuide(
            what: "Automatic updates install macOS security fixes and the latest XProtect / malware-definition data without manual intervention.",
            why: "Unpatched Macs are exposed to known, weaponized vulnerabilities; rapid security responses also ship this way.",
            howToFix: "System Settings \u{2192} General \u{2192} Software Update \u{2192} Automatic Updates \u{2192} enable \u{201C}Install Security Responses and system files\u{201D} (and ideally all options).",
            docTitle: "Keep your Mac up to date",
            doc: "https://support.apple.com/guide/mac-help/keep-your-mac-up-to-date-mchlpx1065/mac")),
        ("screen lock", SecurityFactorGuide(
            what: "Requiring a password immediately after sleep / screen saver prevents walk-up access to an unlocked session.",
            why: "An unlocked Mac left unattended is a trivial physical compromise \u{2014} full access to files, keychain, and any logged-in services.",
            howToFix: "System Settings \u{2192} Lock Screen \u{2192} \u{201C}Require password after screen saver begins or display is turned off\u{201D} \u{2192} Immediately (or a short delay).",
            docTitle: "Require a password after waking",
            doc: "https://support.apple.com/guide/mac-help/require-a-password-after-waking-mh11851/mac")),
        ("remote login", SecurityFactorGuide(
            what: "Remote Login enables inbound SSH access to this Mac.",
            why: "SSH is a powerful remote-control surface. If it's on without your intent \u{2014} or open to the network with weak auth \u{2014} it's a direct foothold for an attacker.",
            howToFix: "If you don't need it: System Settings \u{2192} General \u{2192} Sharing \u{2192} turn off Remote Login. If you do, restrict it to specific users and use key-based auth.",
            docTitle: "Allow remote login to your Mac",
            doc: "https://support.apple.com/guide/mac-help/allow-a-remote-computer-to-access-your-mac-mchlp1066/mac")),
        ("ssh key", SecurityFactorGuide(
            what: "Checks whether private SSH keys in ~/.ssh are protected by a passphrase.",
            why: "An unencrypted private key (e.g. id_ed25519 with no passphrase) is a ready-to-use credential: anyone who reads the file \u{2014} or any malware running as you \u{2014} can authenticate to every server and service that key unlocks.",
            howToFix: "Add a passphrase to an existing key with `ssh-keygen -p -f ~/.ssh/id_ed25519`, and let the login keychain (ssh-agent) hold it so you aren\u{2019}t prompted each time. Delete keys you no longer use.",
            docTitle: nil, doc: nil)),
        ("unsigned process", SecurityFactorGuide(
            what: "Counts currently-running processes that are unsigned or ad-hoc-signed (no verifiable developer identity).",
            why: "Unsigned binaries can't be attributed to a known publisher and are a common malware trait \u{2014} though developer toolchains and homebrew binaries are also frequently unsigned, so treat this as a lead, not a verdict.",
            howToFix: "Open the Events / Investigation view to see which processes are unsigned and from where. Quarantine or remove anything you don't recognize; signed, expected dev tools are normal.",
            docTitle: "App security in macOS",
            doc: "https://support.apple.com/guide/security/app-security-overview-sec35dd877d0/web")),
        ("active alert", SecurityFactorGuide(
            what: "Reflects the volume of recent CRITICAL/HIGH detections from MacCrab's own engine over the last 24 hours.",
            why: "A high count means MacCrab is seeing serious activity worth triaging \u{2014} or noisy false positives worth tuning. Either way it lowers your posture until reviewed.",
            howToFix: "Open the Alerts workspace to triage: confirm and respond to real detections, and suppress / tune any false positives so the score reflects genuine risk.",
            docTitle: nil, doc: nil)),
    ]
}
