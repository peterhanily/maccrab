// SafeQuarantinePathValidatorTests.swift
// MacCrabCoreTests

import Testing
import Foundation
@testable import MacCrabCore

@Suite("SafeQuarantinePathValidator")
struct SafeQuarantinePathValidatorTests {

    // MARK: - Protected system prefixes

    @Test("Rejects /System/Library binaries")
    func rejectsSystem() {
        #expect(SafeQuarantinePathValidator.isSafeToQuarantine(path: "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder") == false)
        #expect(SafeQuarantinePathValidator.isSafeToQuarantine(path: "/System/Applications/Mail.app") == false)
        #expect(SafeQuarantinePathValidator.isSafeToQuarantine(path: "/System/Library/Frameworks/Foundation.framework") == false)
    }

    @Test("Rejects /Library/Apple, frameworks, and helper tools")
    func rejectsLibraryAppleAndFrameworks() {
        #expect(SafeQuarantinePathValidator.isSafeToQuarantine(path: "/Library/Apple/usr/bin/something") == false)
        #expect(SafeQuarantinePathValidator.isSafeToQuarantine(path: "/Library/Frameworks/Python.framework") == false)
        #expect(SafeQuarantinePathValidator.isSafeToQuarantine(path: "/Library/PrivilegedHelperTools/com.example.helper") == false)
        #expect(SafeQuarantinePathValidator.isSafeToQuarantine(path: "/Library/SystemExtensions/somesysext.systemextension") == false)
    }

    @Test("Rejects launch agents and daemons")
    func rejectsLaunchPaths() {
        #expect(SafeQuarantinePathValidator.isSafeToQuarantine(path: "/Library/LaunchDaemons/com.foo.bar.plist") == false)
        #expect(SafeQuarantinePathValidator.isSafeToQuarantine(path: "/Library/LaunchAgents/com.foo.bar.plist") == false)
    }

    @Test("Rejects /usr/bin, /usr/sbin, /usr/libexec, /usr/lib, /sbin, /bin")
    func rejectsUsrAndSbin() {
        #expect(SafeQuarantinePathValidator.isSafeToQuarantine(path: "/usr/bin/python3") == false)
        #expect(SafeQuarantinePathValidator.isSafeToQuarantine(path: "/usr/sbin/sshd") == false)
        #expect(SafeQuarantinePathValidator.isSafeToQuarantine(path: "/usr/libexec/security_authtrampoline") == false)
        #expect(SafeQuarantinePathValidator.isSafeToQuarantine(path: "/usr/lib/dyld") == false)
        #expect(SafeQuarantinePathValidator.isSafeToQuarantine(path: "/sbin/launchd") == false)
        #expect(SafeQuarantinePathValidator.isSafeToQuarantine(path: "/bin/bash") == false)
    }

    @Test("Rejects /private/var/db and /etc")
    func rejectsSystemDbsAndEtc() {
        #expect(SafeQuarantinePathValidator.isSafeToQuarantine(path: "/private/var/db/sudo/lectured/user") == false)
        #expect(SafeQuarantinePathValidator.isSafeToQuarantine(path: "/private/etc/hosts") == false)
        #expect(SafeQuarantinePathValidator.isSafeToQuarantine(path: "/etc/sudoers") == false)
    }

    @Test("Rejects MacCrab's own support directory (sysext)")
    func rejectsMacCrabSelf() {
        #expect(SafeQuarantinePathValidator.isSafeToQuarantine(path: "/Library/Application Support/MacCrab/events.db") == false)
        #expect(SafeQuarantinePathValidator.isSafeToQuarantine(path: "/Library/Application Support/MacCrab/baseline.json") == false)
        #expect(SafeQuarantinePathValidator.isSafeToQuarantine(path: "/Library/Application Support/MacCrab/compiled_rules/foo.json") == false)
    }

    // MARK: - Per-user protected suffixes

    @Test("Rejects per-user Mail data")
    func rejectsUserMail() {
        #expect(SafeQuarantinePathValidator.isSafeToQuarantine(path: "/Users/alice/Library/Mail/V10/MailData/Envelope Index") == false)
        #expect(SafeQuarantinePathValidator.isSafeToQuarantine(path: "/Users/bob/Library/Containers/com.apple.mail/Data/foo") == false)
    }

    @Test("Rejects per-user Calendar / Contacts / iCloud")
    func rejectsUserCalContactsICloud() {
        #expect(SafeQuarantinePathValidator.isSafeToQuarantine(path: "/Users/alice/Library/Calendars/Calendar Cache.db") == false)
        #expect(SafeQuarantinePathValidator.isSafeToQuarantine(path: "/Users/alice/Library/Application Support/AddressBook/Sources/foo.abcdp") == false)
        #expect(SafeQuarantinePathValidator.isSafeToQuarantine(path: "/Users/alice/Library/Mobile Documents/com~apple~CloudDocs/file.pdf") == false)
    }

    @Test("Rejects per-user Keychain")
    func rejectsUserKeychain() {
        #expect(SafeQuarantinePathValidator.isSafeToQuarantine(path: "/Users/alice/Library/Keychains/login.keychain-db") == false)
    }

    @Test("Rejects per-user Photos library")
    func rejectsUserPhotos() {
        #expect(SafeQuarantinePathValidator.isSafeToQuarantine(path: "/Users/alice/Pictures/Photos Library.photoslibrary/database/Photos.sqlite") == false)
    }

    @Test("Rejects per-user MacCrab support dir")
    func rejectsUserMacCrabSupport() {
        #expect(SafeQuarantinePathValidator.isSafeToQuarantine(path: "/Users/alice/Library/Application Support/MacCrab/events.db") == false)
    }

    // MARK: - Edge cases

    @Test("Rejects empty / non-absolute paths")
    func rejectsRelativeAndEmpty() {
        #expect(SafeQuarantinePathValidator.isSafeToQuarantine(path: "") == false)
        #expect(SafeQuarantinePathValidator.isSafeToQuarantine(path: "   ") == false)
        #expect(SafeQuarantinePathValidator.isSafeToQuarantine(path: "relative/path") == false)
        #expect(SafeQuarantinePathValidator.isSafeToQuarantine(path: "../escape") == false)
    }

    // MARK: - Accepted: legitimate quarantine targets

    @Test("Accepts /tmp/ and /var/tmp/ binaries")
    func acceptsTmp() {
        #expect(SafeQuarantinePathValidator.isSafeToQuarantine(path: "/tmp/evilware"))
        #expect(SafeQuarantinePathValidator.isSafeToQuarantine(path: "/private/tmp/dropper.sh"))
        #expect(SafeQuarantinePathValidator.isSafeToQuarantine(path: "/var/tmp/xyz"))
    }

    @Test("Accepts user Downloads and Desktop")
    func acceptsUserDownloadsAndDesktop() {
        #expect(SafeQuarantinePathValidator.isSafeToQuarantine(path: "/Users/alice/Downloads/maybe-malware.dmg"))
        #expect(SafeQuarantinePathValidator.isSafeToQuarantine(path: "/Users/alice/Desktop/sketchy.pkg"))
        #expect(SafeQuarantinePathValidator.isSafeToQuarantine(path: "/Users/alice/Documents/Random.bin"))
    }

    @Test("Accepts third-party /Applications")
    func acceptsThirdPartyApplications() {
        // Non-Apple apps in /Applications/ are quarantine-able by design —
        // the directory is mutable, signed by Developer ID, and most
        // user-installed malware lands here.
        #expect(SafeQuarantinePathValidator.isSafeToQuarantine(path: "/Applications/Sketchy App.app/Contents/MacOS/Sketchy"))
    }

    @Test("Accepts /Users/Shared")
    func acceptsUsersShared() {
        #expect(SafeQuarantinePathValidator.isSafeToQuarantine(path: "/Users/Shared/dropper"))
    }

    // MARK: - reasonToReject contract

    @Test("reasonToReject returns nil for safe paths and a string for unsafe")
    func reasonToRejectContract() {
        #expect(SafeQuarantinePathValidator.reasonToReject(path: "/tmp/evil") == nil)
        let r = SafeQuarantinePathValidator.reasonToReject(path: "/System/Library/X")
        #expect(r != nil)
        #expect(r?.contains("/System/") == true)
    }
}
