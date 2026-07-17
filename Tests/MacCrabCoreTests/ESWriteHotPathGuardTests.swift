// ESWriteHotPathGuardTests.swift
// v1.21.4 Phase-7 — the write-family hot-path noise guard.
//
// The NOTIFY_WRITE firehose is dominated by benign, high-frequency LOG writers
// (measured on-device: ~3800 writes / 2 min, ~3200 of them `suricata` appending
// to /var/log/suricata/*). Unlike NOTIFY_OPEN, the write family had no hot-path
// guard, so every such write paid the full processFromESProcess build AND the
// 5-tier detection pipeline. `shouldDropNoisyWrite` early-drops provably-
// irrelevant log-sink writes BEFORE processFromESProcess.
//
// ES delivery itself is live-only (no unit test possible), but this predicate —
// the part that decides what we drop — is pure and MUST be tested. It is
// SAFETY-CRITICAL: a false drop loses detection, so these tests pin down both
// what is dropped (only log sinks) and — the load-bearing half — everything that
// must always be KEPT.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("ESCollector write hot-path noise guard (v1.21.4 Phase-7)")
struct ESWriteHotPathGuardTests {

    // MARK: - Dropped: provable log-sink noise

    @Test("Log-sink writes are dropped (the suricata / system-log firehose)")
    func logSinkWritesDropped() {
        let dropped = [
            // suricata's actual output dir — the dominant on-device offender.
            "/var/log/suricata/eve.json",
            "/var/log/suricata/fast.log",
            "/var/log/suricata/stats.log",
            "/private/var/log/suricata/eve.json",
            // System / daemon logs.
            "/var/log/system.log",
            "/private/var/log/install.log",
            "/var/log/wtmp",                       // extension-less binary log DB
            // macOS app logs.
            "/Users/x/Library/Logs/Foo/foo.log",
            "/Library/Logs/DiagnosticReports/x.diag",
            // Any *.log anywhere (append-only text logs).
            "/Users/x/Library/Application Support/Bar/bar.log",
            "/tmp/build.log",
        ]
        for p in dropped {
            #expect(ESCollector.shouldDropNoisyWrite(path: p), "expected DROP (log noise): \(p)")
        }
    }

    @Test("The task's canonical example — a daemon writing /private/var/log/x.log — is dropped")
    func canonicalNoiseExampleDropped() {
        #expect(ESCollector.shouldDropNoisyWrite(path: "/private/var/log/x.log"))
    }

    // MARK: - Kept: detection-relevant writes (the load-bearing safety half)

    @Test("Persistence writes are KEPT and still reach detection")
    func persistenceWritesKept() {
        let kept = [
            "/Users/x/Library/LaunchAgents/com.evil.plist",
            "/Library/LaunchDaemons/com.evil.plist",
            "/Users/x/Library/LaunchAgents/agent",   // extension-less under LaunchAgents
            "/etc/cron.d/evil",
            "/private/etc/sudoers",
            "/Users/x/.zshrc",
        ]
        for p in kept {
            #expect(!ESCollector.shouldDropNoisyWrite(path: p), "expected KEEP (persistence): \(p)")
        }
    }

    @Test("Executable / script / dylib drops are KEPT — even under a log root")
    func executableDropsKept() {
        let kept = [
            "/tmp/evil",                       // extension-less payload in world-writable tmp
            "/private/tmp/stage2",
            "/Users/x/Library/Application Support/evil.dylib",
            "/Users/x/Downloads/installer.sh",
            "/tmp/loader.py",
            // Code under a log root — the noise root does NOT swallow a code drop.
            "/var/log/evil.sh",
            "/private/var/log/backdoor.dylib",
            "/Library/Logs/payload.py",
        ]
        for p in kept {
            #expect(!ESCollector.shouldDropNoisyWrite(path: p), "expected KEEP (code drop): \(p)")
        }
    }

    @Test("Credential / wallet writes are KEPT — including a wallet leveldb *.log")
    func credentialWritesKept() {
        let kept = [
            "/Users/x/.ssh/authorized_keys",
            "/Users/x/.aws/credentials",
            "/Users/x/.aws/credentials.bak",       // honeyfile under a credential dir
            "/Users/x/Library/Keychains/login.keychain-db",
            // Wallet leveldb rotation file: ends in .log (a log sink by suffix) but
            // lives under a wallet dir — the credential override must KEEP it.
            "/Users/x/Library/Application Support/Google/Chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/000003.log",
        ]
        for p in kept {
            #expect(!ESCollector.shouldDropNoisyWrite(path: p), "expected KEEP (credential): \(p)")
        }
    }

    @Test("Agent-content writes (skills / hooks / config / workflows) are KEPT")
    func agentContentWritesKept() {
        let kept = [
            "/Users/x/.claude/skills/evil/SKILL.md",
            "/Users/x/.claude/hooks/pre.sh",
            "/Users/x/.claude/settings.json",
            "/Users/x/project/.github/workflows/ci.yml",
        ]
        for p in kept {
            #expect(!ESCollector.shouldDropNoisyWrite(path: p), "expected KEEP (agent-content): \(p)")
        }
    }

    // MARK: - Conservatism: cache / tmp / var-folders are NOT in the drop set

    @Test("Cache / tmp / var-folders writes are KEPT — rules predicate on them as drop sites")
    func stagingRootsNotDropped() {
        // Deliberately NARROWER than "log/cache/tmp": these roots host malware
        // drop/staging that rules DO target, so a write there is never treated as
        // provable noise. (Regression guard for the conservative choice.)
        let kept = [
            "/Library/Caches/com.apple.act.mond",   // fake-Apple binary drop rule
            "/Library/Caches/node",
            "/Users/x/Library/Caches/com.google.Keystone/foo",
            "/private/tmp/bun",
            "/var/folders/ab/T/payload",
            "/private/var/folders/xy/AppTranslocation/x",
        ]
        for p in kept {
            #expect(!ESCollector.shouldDropNoisyWrite(path: p), "expected KEEP (staging root): \(p)")
        }
    }

    @Test("Ordinary document / source writes are KEPT (default is keep)")
    func ordinaryWritesKept() {
        let kept = [
            "/Users/x/Documents/notes.txt",
            "/Users/x/project/Sources/main.swift",
            "/Users/x/Library/Application Support/App/db.sqlite-wal",
        ]
        for p in kept {
            #expect(!ESCollector.shouldDropNoisyWrite(path: p), "expected KEEP (ordinary): \(p)")
        }
    }

    // MARK: - Component predicates

    @Test("isLogSinkWritePath matches only log sinks")
    func logSinkClassification() {
        #expect(ESCollector.isLogSinkWritePath("/var/log/system.log"))
        #expect(ESCollector.isLogSinkWritePath("/private/var/log/x"))
        #expect(ESCollector.isLogSinkWritePath("/Users/x/Library/Logs/a/b"))
        #expect(ESCollector.isLogSinkWritePath("/tmp/foo.log"))
        #expect(!ESCollector.isLogSinkWritePath("/Library/Caches/foo"))
        #expect(!ESCollector.isLogSinkWritePath("/Users/x/.ssh/id_rsa"))
        #expect(!ESCollector.isLogSinkWritePath("/Users/x/Documents/log.txt"))  // "log" but not a sink
    }

    @Test("isCodeWritePath matches code / script / bundle interiors")
    func codeWriteClassification() {
        #expect(ESCollector.isCodeWritePath("/x/evil.dylib"))
        #expect(ESCollector.isCodeWritePath("/x/run.sh"))
        #expect(ESCollector.isCodeWritePath("/x/hook.py"))
        #expect(ESCollector.isCodeWritePath("/Applications/Evil.app/Contents/MacOS/Evil"))
        #expect(ESCollector.isCodeWritePath("/x/com.evil.plist"))
        #expect(!ESCollector.isCodeWritePath("/x/notes.txt"))
        #expect(!ESCollector.isCodeWritePath("/x/data.json"))
    }
}
