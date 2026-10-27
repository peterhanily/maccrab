import Foundation
import Testing
@testable import MacCrabCore

/// The stored command line must never carry a credential that the stored
/// argv redacts, and both must cover the common password-argument shapes.
@Suite("Command-line redaction matches argv redaction")
struct CommandLineRedactionParityTests {
    private func stored(_ argv: [String]) throws -> MacCrabCore.ProcessInfo {
        let process = MacCrabCore.ProcessInfo(
            pid: 7, ppid: 1, rpid: 1, name: (argv[0] as NSString).lastPathComponent,
            executable: argv[0], commandLine: argv.joined(separator: " "), args: argv,
            workingDirectory: "/", userId: 501, userName: "u", groupId: 20, startTime: Date())
        let event = Event(timestamp: Date(), eventCategory: .process, eventType: .start,
                          eventAction: "exec", process: process)
        return try EventPrivacySanitizer.sanitize(event).event.process
    }

    @Test("a separated password value is redacted in the command line as in argv")
    func separatedValues() throws {
        for (argv, secret) in [
            (["/usr/local/bin/sshpass", "-p", "S3cret", "ssh", "host"], "S3cret"),
            (["/usr/local/bin/sshpass", "-p", "letmein", "ssh", "host"], "letmein"),
            (["/usr/bin/tool", "--key", "abcdef123456"], "abcdef123456"),
            (["/usr/bin/tool", "--passwd", "hunter2"], "hunter2"),
            (["/usr/bin/tool", "--private-key", "MIIEvQIBADAN"], "MIIEvQIBADAN"),
            (["/usr/bin/tool", "--private_key=MIIEvQIBADAN"], "MIIEvQIBADAN"),
            (["/usr/bin/curl", "-u", "alice:wonderland", "https://x.invalid"], "wonderland"),
            (["/usr/bin/curl", "--user=alice:wonderland", "https://x.invalid"], "wonderland"),
            (["/usr/bin/curl", "-ualice:wonderland", "https://x.invalid"], "wonderland"),
            (["/usr/bin/openssl", "enc", "-aes-256-cbc", "-pass", "pass:wonderland"], "wonderland"),
        ] {
            let process = try stored(argv)
            #expect(!process.commandLine.contains(secret), "\(process.commandLine)")
            #expect(!process.args.contains { $0.contains(secret) }, "\(process.args)")
        }
    }

    @Test("paths after a standalone -p and numeric uid:gid pairs stay visible")
    func structuralValuesStayVisible() throws {
        let mkdir = try stored(["/bin/mkdir", "-p", "/Users/u/project/build"])
        #expect(mkdir.commandLine == "/bin/mkdir -p /Users/u/project/build")
        #expect(mkdir.args.last == "/Users/u/project/build")
        let docker = try stored(["/usr/local/bin/docker", "run", "-u", "501:20", "image"])
        #expect(docker.commandLine.contains("501:20"))
        let sudo = try stored(["/usr/bin/sudo", "-u", "alice", "id"])
        #expect(sudo.commandLine == "/usr/bin/sudo -u alice id")
    }

    @Test("-p and -P values stay visible for programs where they are not secrets")
    func portAndPidValuesStayVisible() throws {
        for argv in [
            ["/usr/bin/ssh", "-p", "2222", "host"],
            ["/usr/bin/ssh", "-i", "/Users/u/.ssh/key", "-p", "2222", "-o", "Port=22", "host"],
            ["/usr/bin/nc", "-l", "-p", "4444"],
            ["/usr/sbin/lsof", "-p", "123"],
            ["/bin/ps", "-p", "1"],
            ["/usr/local/bin/docker", "run", "-p", "8080:80", "image"],
            ["/usr/local/bin/docker", "run", "--name", "web", "-dp", "8080:80", "-p", "443:443", "image"],
            ["/usr/bin/scp", "-P", "2222", "f", "h:"],
            ["/bin/mkdir", "-p", "build/x"],
            ["/bin/cp", "-p", "a", "b"],
            ["/usr/bin/find", "/", "-perm", "-4000", "-print"],
            ["/usr/bin/git", "log", "-p"],
            ["/usr/bin/swiftc", "-parse-as-library", "main.swift"],
            ["/usr/bin/clang", "-pthread", "main.c"],
            ["/usr/local/bin/mysql", "-h", "db", "-P", "3306"],
        ] {
            let process = try stored(argv)
            #expect(process.commandLine == argv.joined(separator: " "), "\(process.commandLine)")
            #expect(process.args == argv)
        }
        // The command line's string backstop still hides a compact value
        // with a digit (it cannot tell `patch -p1` from `mysql -p1x`); argv
        // keeps it.
        #expect(try stored(["/usr/bin/patch", "-p1"]).args == ["/usr/bin/patch", "-p1"])
    }

    @Test("an unknown program, a launcher, or another program's argv redacts -p and -P values")
    func unknownProgramsFailClosed() throws {
        for (argv, secret) in [
            (["/usr/local/bin/tool", "-p", "Hunter22"], "Hunter22"),
            (["/usr/local/bin/tool", "-PHunter22"], "Hunter22"),
            (["/usr/bin/xargs", "-P", "Hunter22", "echo"], "Hunter22"),
            (["/usr/bin/sudo", "lsof", "-p", "Hunter22"], "Hunter22"),
            (["/usr/bin/python3", "tool.py", "-p", "Hunter22"], "Hunter22"),
            (["/usr/bin/ssh", "h", "--", "tool", "-p", "Hunter22"], "Hunter22"),
            (["/usr/bin/ssh", "-p", "22", "host", "tool", "-p", "Hunter22"], "Hunter22"),
            (["/usr/local/bin/docker", "run", "-p", "80:80", "image", "tool", "-p", "Hunter22"], "Hunter22"),
            (["/usr/bin/find", ".", "-exec", "tool", "-p", "Hunter22", ";"], "Hunter22"),
            (["/usr/bin/cargo", "run", "-p", "pkg", "--", "-p", "Hunter22"], "Hunter22"),
            (["/usr/bin/swift", "run", "tool", "-p", "Hunter22"], "Hunter22"),
            (["/opt/homebrew/bin/mosh", "-p", "60001", "host", "tool", "-p", "Hunter22"], "Hunter22"),
            (["/opt/homebrew/bin/gdb", "--args", "prog", "-p", "Hunter22"], "Hunter22"),
        ] {
            let process = try stored(argv)
            #expect(!process.commandLine.contains(secret), "\(process.commandLine)")
            #expect(!process.args.contains { $0.contains(secret) }, "\(process.args)")
        }
        // The flag itself and the arguments before it stay for hunting.
        let ssh = try stored(["/usr/bin/ssh", "-p", "22", "host", "tool", "-p", "Hunter22"])
        #expect(ssh.args == ["/usr/bin/ssh", "-p", "22", "host", "tool", "-p", "[REDACTED]"])
    }

    @Test("passwords of programs that take one through -p, -P or -N are redacted")
    func passwordProgramForms() throws {
        for (argv, secret) in [
            (["/usr/bin/security", "unlock-keychain", "-p", "Tr0ub4dor&3", "/Users/u/Library/Keychains/login.keychain-db"], "Tr0ub4dor"),
            (["/usr/bin/security", "import", "id.p12", "-k", "ci.keychain", "-P", "Tr0ub4dor&3"], "Tr0ub4dor"),
            (["/usr/local/bin/docker", "login", "-u", "ci", "-p", "Tr0ub4dor&3", "registry.invalid"], "Tr0ub4dor"),
            (["/opt/homebrew/bin/podman", "login", "-p", "Tr0ub4dor&3", "registry.invalid"], "Tr0ub4dor"),
            (["/usr/bin/xcrun", "altool", "-u", "dev@example.invalid", "-p", "Tr0ub4dor&3"], "Tr0ub4dor"),
            (["/usr/bin/zip", "-P", "-x7Kq9!", "out.zip", "f"], "x7Kq9"),
            (["/usr/bin/zip", "-erP", "Tr0ub4dor&3", "out.zip", "f"], "Tr0ub4dor"),
            (["/usr/local/bin/sshpass", "-p", "-Secret1", "ssh", "host"], "Secret1"),
            (["/usr/local/bin/gradle", "-Psigning.password=Tr0ub4dor&3"], "Tr0ub4dor"),
            (["/usr/local/bin/mysql_upgrade", "-pTr0ub4dor&3"], "Tr0ub4dor"),
            (["/usr/local/bin/sqlcmd", "-S", "db", "-U", "sa", "-P", "Tr0ub4dor&3"], "Tr0ub4dor"),
        ] {
            let process = try stored(argv)
            #expect(!process.commandLine.contains(secret), "\(process.commandLine)")
            #expect(!process.args.contains { $0.contains(secret) }, "\(process.args)")
        }
        let keygen = try stored(["/usr/bin/ssh-keygen", "-p", "-f", "k", "-P", "Old-pass1", "-N", "New-pass2"])
        #expect(keygen.args == ["/usr/bin/ssh-keygen", "-p", "-f", "k", "-P", "[REDACTED]", "-N", "[REDACTED]"])
        // mysql's -P is the port; its -p is the password.
        let mysql = try stored(["/usr/local/bin/mysql", "-P", "3306", "-u", "u", "-pTr0ub4dor&3"])
        #expect(mysql.args == ["/usr/local/bin/mysql", "-P", "3306", "-u", "u", "-p[REDACTED]"])
    }

    @Test("password -p forms are redacted after a password program, through wrappers too")
    func passwordPForms() throws {
        for (argv, secret) in [
            (["/usr/local/bin/mysql", "-uroot", "-pS3cret", "db"], "S3cret"),
            (["/usr/bin/sudo", "mysql", "-pS3cret"], "S3cret"),
            (["/usr/local/bin/kubectl", "exec", "pod", "--", "mysql", "-pS3cret"], "S3cret"),
            (["/usr/local/bin/mongosh", "-u", "admin", "-p", "S3cret"], "S3cret"),
            (["/usr/bin/zip", "-P", "S3cret", "out.zip", "f"], "S3cret"),
            (["/opt/homebrew/bin/7z", "a", "-pS3cret", "out.7z", "f"], "S3cret"),
            (["/usr/local/bin/sshpass", "-p", "/S3cret", "ssh", "host"], "/S3cret"),
            (["/usr/bin/curl", "-u", "admin:123456", "https://x.invalid"], "123456"),
            (["/usr/bin/curl", "-p", "-u", "alice:wonderland", "https://x.invalid"], "wonderland"),
        ] {
            let process = try stored(argv)
            #expect(!process.commandLine.contains(secret), "\(process.commandLine)")
            #expect(!process.args.contains { $0.contains(secret) }, "\(process.args)")
        }
        // `mysql -p` prompts for the password; the next option is not its value.
        let prompt = try stored(["/usr/local/bin/mysql", "-p", "-u", "root"])
        #expect(prompt.args == ["/usr/local/bin/mysql", "-p", "-u", "root"])
        #expect(CommandSanitizer.sanitize("curl -u admin:123456 https://x.invalid").contains("admin:[REDACTED]"))
        #expect(CommandSanitizer.sanitize("docker run -u 501:20 image").contains("501:20"))
    }

    @Test("bare strings without argv still cover password programs, -u pairs and pass:")
    func bareStrings() {
        for (line, secret) in [
            ("sshpass -p letmein ssh host", "letmein"),
            ("sshpass -pletmein ssh host", "letmein"),
            ("security unlock-keychain -p letmein ~/Library/Keychains/login.keychain-db", "letmein"),
            ("security import id.p12 -P letmein", "letmein"),
            ("zip -P letmein out.zip f", "letmein"),
            ("ssh-keygen -p -f k -P oldpass -N letmein", "letmein"),
            ("ssh-keygen -p -f k -P letmein -N newpass", "letmein"),
            ("docker login -u ci -p letmein registry.invalid", "letmein"),
            ("xcrun altool -u dev -p letmein", "letmein"),
            ("curl -u alice:wonderland https://x.invalid", "wonderland"),
            ("openssl rsa -passin pass:wonderland -in key.pem", "wonderland"),
            ("tool --passwd=hunter2", "hunter2"),
            ("tool --key abcdef123456", "abcdef123456"),
        ] {
            #expect(!CommandSanitizer.sanitize(line).contains(secret), "\(line)")
        }
        // A shell separator ends the program's arguments; gzip is not zip.
        #expect(CommandSanitizer.sanitize("security list-keychains; ls -p /tmp") == "security list-keychains; ls -p /tmp")
        #expect(CommandSanitizer.sanitize("gzip -P 4 f") == "gzip -P 4 f")
        // A shell -c string is redacted as one argument.
        let shell = CommandSanitizer.sanitize(arguments: ["/bin/sh", "-c", "security unlock-keychain -p letmein"])
        #expect(!shell.joined(separator: " ").contains("letmein"), "\(shell)")
        #expect(CommandSanitizer.sanitize(commandLine: "a b", arguments: ["a", "c"]) == "a b")
        #expect(CommandSanitizer.sanitize(
            commandLine: "/usr/local/bin/sshpass -p letmein ssh",
            arguments: ["/usr/local/bin/sshpass", "-p", "letmein", "ssh"]
        ) == "/usr/local/bin/sshpass -p [REDACTED] ssh")
    }

    @Test("a password letter bundled after other flags, or attached, is redacted")
    func bundledPasswordLetters() throws {
        for (argv, secret) in [
            (["/usr/bin/ssh-keygen", "-t", "ed25519", "-qN", "NewPass1", "-f", "k"], "NewPass1"),
            (["/usr/bin/ssh-keygen", "-NNewPass1", "-f", "k"], "NewPass1"),
            (["/usr/bin/zip", "-r9P", "Secret77", "out.zip", "dir"], "Secret77"),
            // A pending value never swallows a flag the walk handles.
            (["/usr/bin/zip", "-P", "-P", "Secret77", "out.zip"], "Secret77"),
            (["/usr/local/bin/tool", "-p", "--password", "Secret77"], "Secret77"),
            (["/usr/local/bin/tool", "-p", "-p", "Secret77"], "Secret77"),
        ] {
            let process = try stored(argv)
            #expect(!process.commandLine.contains(secret), "\(process.commandLine)")
            #expect(!process.args.contains { $0.contains(secret) }, "\(process.args)")
        }
        #expect(try stored(["/usr/bin/ssh-keygen", "-NNewPass1"]).args.last == "-N[REDACTED]")
        // 7z and rar switches never bundle: `-ssp`, `-ep` and `-oOutput` are not passwords.
        for argv in [
            ["/opt/homebrew/bin/7z", "a", "-ssp", "-spf", "out.7z", "f"],
            ["/opt/homebrew/bin/7z", "x", "in.7z", "-oOutput"],
            ["/opt/homebrew/bin/rar", "a", "-ep", "out.rar", "f"],
        ] {
            #expect(try stored(argv).args == argv)
        }
        for line in [
            "ssh-keygen -t ed25519 -qN NewPass1 -f k",
            "ssh-keygen -NNewPass1 -f k",
            "zip -r9P NewPass1 out.zip dir",
            "sh -c 'security unlock-keychain -p NewPass1'",
            "bash -lc \"ssh-keygen -qN NewPass1 -f k\"",
        ] {
            #expect(!CommandSanitizer.sanitize(line).contains("NewPass1"), "\(line)")
        }
    }

    @Test("a password program's name inside another word does not redact")
    func programNamesInsideOtherWords() throws {
        for line in [
            "docker run --security-opt seccomp=unconfined -p 8080:80 nginx",
            "docker run --name login-svc -p 8080:80 img",
            "ssh -i ~/.ssh/security-key -p 2222 host",
            "find /x/security -print",
            "rsync src.zip -P dst",
        ] {
            #expect(CommandSanitizer.sanitize(line) == line, "\(line)")
            #expect(CommandSanitizer.sanitize(arguments: ["/bin/sh", "-c", line]) == ["/bin/sh", "-c", line])
            #expect(try stored(line.split(separator: " ").map(String.init)).commandLine == line)
        }
    }

    @Test("the latest password program decides whether -p may take a dash value")
    func optionalValueFollowsLatestProgram() throws {
        let prompt = try stored(["/usr/local/bin/mysql", "-p", "-h", "db", "app"])
        #expect(prompt.args == ["/usr/local/bin/mysql", "-p", "-h", "db", "app"])
        let nested = try stored(["/usr/local/bin/docker", "exec", "mysql", "sshpass", "-p", "-Secret1", "ssh", "h"])
        #expect(!nested.args.contains { $0.contains("Secret1") }, "\(nested.args)")
        #expect(!nested.commandLine.contains("Secret1"), "\(nested.commandLine)")
        #expect(!CommandSanitizer.sanitize("docker exec mysql sshpass -p -Secret1 ssh h").contains("Secret1"))
    }

    @Test("a password program glued to an assignment or shell punctuation is found")
    func gluedProgramNames() throws {
        for argv in [
            ["/usr/bin/rsync", "-av", "--rsh=sshpass -p Hunter22 ssh -l u", "src/", "h:dst/"],
            ["/usr/bin/ssh", "-o", "ProxyCommand=sshpass -p Hunter22 ssh -W %h:%p jump", "target"],
            ["/usr/bin/ssh", "-oProxyCommand=sshpass -p Hunter22 ssh -W %h:%p jump", "target"],
            ["/usr/bin/git", "-c", "core.sshCommand=sshpass -p Hunter22 ssh", "pull"],
            ["/usr/bin/env", "GIT_SSH_COMMAND=sshpass -p Hunter22 ssh", "git", "pull"],
            ["/bin/sh", "-c", "(sshpass -p Hunter22 ssh h uptime) &"],
            ["/bin/sh", "-c", "out=$(sshpass -p Hunter22 ssh h cat f)"],
            ["/bin/sh", "-c", "out=`sshpass -p Hunter22 ssh h cat f`"],
            ["/usr/bin/ssh", "-o", "RemoteCommand=sshpass -p Hunter22 ssh inner", "jump"],
            ["/usr/bin/ssh", "-oLocalCommand=sshpass -p Hunter22 ssh inner", "jump"],
            ["/usr/bin/env", "SVN_SSH=sshpass -p Hunter22 ssh", "svn", "up"],
            ["/opt/homebrew/bin/hg", "--config", "ui.ssh=sshpass -p Hunter22 ssh", "pull"],
            ["/usr/local/bin/docker", "run", "--entrypoint=sshpass", "img", "-p", "Hunter22", "ssh", "h"],
            ["/opt/homebrew/bin/sshuttle", "--ssh-cmd=sshpass -p Hunter22 ssh", "-r", "u@h", "0/0"],
        ] {
            let process = try stored(argv)
            #expect(!process.commandLine.contains("Hunter22"), "\(process.commandLine)")
            #expect(!process.args.contains { $0.contains("Hunter22") }, "\(process.args)")
            let line = argv.joined(separator: " ")
            #expect(!CommandSanitizer.sanitize(line).contains("Hunter22"), "\(line)")
        }
        // A letters-only compact password has no digit for the bare `-pVALUE`
        // pattern to key on: only the program behind `--health-cmd=` marks it.
        let health = ["/usr/local/bin/docker", "run", "--health-cmd=mysqladmin ping -uroot -pHunterpw", "mysql:8"]
        let healthProcess = try stored(health)
        #expect(!healthProcess.commandLine.contains("Hunterpw"), "\(healthProcess.commandLine)")
        #expect(!healthProcess.args.contains { $0.contains("Hunterpw") }, "\(healthProcess.args)")
        #expect(!CommandSanitizer.sanitize(health.joined(separator: " ")).contains("Hunterpw"))
        // A command substitution starts its own command: its program is not the
        // value of the outer `-p`, and its dash-leading password is redacted.
        let substituted = "mysql -p $(sshpass -p -Secret1 ssh h cat pw) db"
        #expect(!CommandSanitizer.sanitize(substituted).contains("Secret1"))
        #expect(!CommandSanitizer.sanitize(arguments: ["/bin/sh", "-c", substituted])
            .joined(separator: " ").contains("Secret1"))
    }

    @Test("a value cut by &, ; or | in a bare string is redacted to the end of its run")
    func separatorsInsideValues() throws {
        for (line, redacted) in [
            ("/usr/local/bin/sshpass -p Tr0ub4dor&3 ssh host", "/usr/local/bin/sshpass -p [REDACTED] ssh host"),
            ("sshpass -p pa|ss;w0rd ssh h", "sshpass -p [REDACTED] ssh h"),
            ("docker login -u ci -p Tr0ub4dor&3 registry", "docker login -u ci -p [REDACTED] registry"),
            ("zip -PHunt&er22 out.zip f", "zip -P[REDACTED] out.zip f"),
        ] {
            #expect(CommandSanitizer.sanitize(line) == redacted, "\(line)")
        }
        // A parent's command line reaches storage only as a string.
        let child = MacCrabCore.ProcessInfo(
            pid: 8, ppid: 7, rpid: 1, name: "ssh", executable: "/usr/bin/ssh",
            commandLine: "/usr/bin/ssh host", args: ["/usr/bin/ssh", "host"],
            workingDirectory: "/", userId: 501, userName: "u", groupId: 20, startTime: Date())
        let event = Event(timestamp: Date(), eventCategory: .process, eventType: .start,
                          eventAction: "exec", process: child,
                          enrichments: ["parent.commandline": "/usr/local/bin/sshpass -p Tr0ub4dor&3 ssh host"])
        let parent = try EventPrivacySanitizer.sanitize(event).event.enrichments["parent.commandline"]
        #expect(parent == "/usr/local/bin/sshpass -p [REDACTED] ssh host")
    }

    @Test("a value whose first byte is a shell separator is redacted; shell syntax is not")
    func valuesStartingWithSeparators() throws {
        // Argv joined by spaces puts any byte first (`sshpass -p '(Secret1'`).
        for (line, redacted) in [
            ("sshpass -p (Secret1 ssh host", "sshpass -p [REDACTED] ssh host"),
            ("sshpass -p `Secret1 ssh host", "sshpass -p [REDACTED] ssh host"),
            ("zip -P(Secret1 out.zip f", "zip -P[REDACTED] out.zip f"),
            ("sshpass -p &Secret1 ssh host", "sshpass -p [REDACTED] ssh host"),
            ("sshpass -p ;Secret1 ssh host", "sshpass -p [REDACTED] ssh host"),
        ] {
            #expect(CommandSanitizer.sanitize(line) == redacted, "\(line)")
            let child = MacCrabCore.ProcessInfo(
                pid: 8, ppid: 7, rpid: 1, name: "ssh", executable: "/usr/bin/ssh",
                commandLine: "/usr/bin/ssh host", args: ["/usr/bin/ssh", "host"],
                workingDirectory: "/", userId: 501, userName: "u", groupId: 20, startTime: Date())
            let event = Event(timestamp: Date(), eventCategory: .process, eventType: .start,
                              eventAction: "exec", process: child,
                              enrichments: ["parent.commandline": line])
            let parent = try EventPrivacySanitizer.sanitize(event).event.enrichments["parent.commandline"]
            #expect(parent == redacted, "\(line)")
        }
        // A separator followed by a space is shell syntax: prose quoting a
        // command, and a prompting `-p` ended by `;`.
        for line in ["Run `sshpass -p` to see the prompt", "mysql -p; echo done", "sshpass -p ; echo"] {
            #expect(CommandSanitizer.sanitize(line) == line, "\(line)")
        }
    }

    @Test("a separator glued to a pending -u or -p is shell syntax; a pending -u takes only a user:password run")
    func separatorsAfterPendingFlags() throws {
        // `-u` is a pair flag for every program, and the next command's text
        // (a launchd label, a pipeline) is hunting data, not a password.
        for line in [
            "launchctl kickstart -k gui/$(id -u)/com.x",
            "uid=$(id -u);launchctl asuser $uid /bin/ls",
            "launchctl print gui/`id -u`/com.x",
            "sort -u|head -5",
            "set -u;curl x",
            "set -u\ncurl x",
            // After a space, a pending -u still needs a user:password run,
            // and a newline always ends the command.
            "sort -u |head -5",
            "id -u ;ls",
            "sshpass -p \necho next",
        ] {
            #expect(CommandSanitizer.sanitize(line) == line, "\(line)")
            let argv = ["/bin/sh", "-c", line]
            #expect(try stored(argv).args == argv, "\(line)")
        }
        // A pair that starts with a separator byte is still a pair.
        let curl = CommandSanitizer.sanitize("curl -U (alice:secret https://x")
        #expect(!curl.contains("secret"), "\(curl)")
        #expect(curl.contains("(alice:"), "\(curl)")
    }

    @Test("a value glued to its password flag by a separator is redacted, in a parent's command line too")
    func gluedSeparatorValues() throws {
        // Argv joined by spaces: `sshpass '-p;Secret'` reaches a child's
        // parent.commandline as `-p;Secret`, which only the string walk sees.
        for (line, redacted) in [
            ("/usr/local/bin/sshpass -p;Secret ssh host", "/usr/local/bin/sshpass -p[REDACTED] ssh host"),
            ("zip -P&Secret1 out.zip f", "zip -P[REDACTED] out.zip f"),
            ("security import id.p12 -P|Pass1", "security import id.p12 -P[REDACTED]"),
            ("ssh-keygen -N;New1 -f k", "ssh-keygen -N[REDACTED] -f k"),
            // The accepted cost: a boolean -p loses its pipeline.
            ("security find-certificate -c X -p|openssl x509", "security find-certificate -c X -p[REDACTED] x509"),
        ] {
            #expect(CommandSanitizer.sanitize(line) == redacted, "\(line)")
            let child = MacCrabCore.ProcessInfo(
                pid: 8, ppid: 7, rpid: 1, name: "ssh", executable: "/usr/bin/ssh",
                commandLine: "/usr/bin/ssh host", args: ["/usr/bin/ssh", "host"],
                workingDirectory: "/", userId: 501, userName: "u", groupId: 20, startTime: Date())
            let event = Event(timestamp: Date(), eventCategory: .process, eventType: .start,
                              eventAction: "exec", process: child, enrichments: ["parent.commandline": line])
            let parent = try EventPrivacySanitizer.sanitize(event).event.enrichments["parent.commandline"]
            #expect(parent == redacted, "\(line)")
        }
        let argv = try stored(["/usr/local/bin/sshpass", "-p;Secret", "ssh", "host"])
        #expect(!argv.args.contains { $0.contains("Secret") }, "\(argv.args)")
        #expect(!argv.commandLine.contains("Secret"), "\(argv.commandLine)")
    }

    @Test("a flag behind escaped quotes reaches the walk at the top level too")
    func escapedQuotedFlagAtTopLevel() throws {
        let line = #"ssh host "zip \"-P\" Secret77 out.zip f""#
        let bare = CommandSanitizer.sanitize(line)
        #expect(!bare.contains("Secret77"), "\(bare)")
        let process = try stored(["/bin/bash", "-c", line])
        #expect(!process.args[2].contains("Secret77"), "\(process.args[2])")
        #expect(!process.commandLine.contains("Secret77"), "\(process.commandLine)")
    }

    @Test("an escaped space or quote in a nested double-quoted script stays inside its word")
    func escapesInNestedScripts() {
        #expect(CommandSanitizer.sanitize(#"sh -c "sshpass -p pass\ word ssh h""#)
            == #"sh -c "sshpass -p [REDACTED] ssh h""#)
        #expect(CommandSanitizer.sanitize(#"bash -lc "ssh-keygen -qN new\ pass -f k""#)
            == #"bash -lc "ssh-keygen -qN [REDACTED] -f k""#)
        let quotedFlag = CommandSanitizer.sanitize(#"sh -c "zip \"-P\" Secret77 out.zip f""#)
        #expect(!quotedFlag.contains("Secret77"), "\(quotedFlag)")
    }

    @Test("an assignment in argv is not a program; ports stay visible")
    func argvAssignmentsAreNotPrograms() throws {
        for argv in [
            ["/usr/local/bin/docker", "run", "--name=mysql", "-p", "3306:3306", "mysql:8"],
            ["/usr/local/bin/docker", "run", "-e", "MYSQL_DATABASE=mysql", "-p", "3306:3306", "mysql:8"],
        ] {
            let process = try stored(argv)
            #expect(process.args == argv)
            // The stored command line is rebuilt from argv and walked as a
            // string, where only an assignment carrying a command names one.
            #expect(process.commandLine == argv.joined(separator: " "), "\(process.commandLine)")
            #expect(CommandSanitizer.sanitize(commandLine: argv.joined(separator: " "), arguments: argv)
                == argv.joined(separator: " "))
        }
    }

    @Test("a dash-leading password shaped like a bundle is the pending value")
    func bundleShapedPasswords() throws {
        #expect(try stored(["/usr/local/bin/sshpass", "-p", "-Secretp", "ssh", "host"]).args
            == ["/usr/local/bin/sshpass", "-p", "[REDACTED]", "ssh", "host"])
        #expect(try stored(["/usr/bin/zip", "-P", "-Secret7P", "out.zip", "f"]).args
            == ["/usr/bin/zip", "-P", "[REDACTED]", "out.zip", "f"])
        #expect(try stored(["/usr/bin/ssh-keygen", "-p", "-f", "k", "-P", "-OldPassN", "-N", "NewPass1"]).args
            == ["/usr/bin/ssh-keygen", "-p", "-f", "k", "-P", "[REDACTED]", "-N", "[REDACTED]"])
        for (line, secret) in [
            ("sshpass -p -Secretp ssh host", "Secretp"),
            ("zip -P -Secret7P out.zip f", "Secret7P"),
            ("ssh-keygen -p -f k -P -OldPassN -N NewPass1", "OldPassN"),
        ] {
            #expect(!CommandSanitizer.sanitize(line).contains(secret), "\(line)")
        }
    }

    @Test("nested double-quoted scripts and quoted flags are read with their escapes resolved")
    func nestedQuoting() throws {
        let nested = CommandSanitizer.sanitize(#"sh -c 'bash -lc "security unlock-keychain -p \"hunter two\" k"'"#)
        #expect(nested == #"sh -c 'bash -lc "security unlock-keychain -p [REDACTED] k"'"#)
        let json = CommandSanitizer.sanitize(#"{"cmd":"sh -c \"sshpass -p Secret77 ssh h\""}"#)
        #expect(!json.contains("Secret77"), "\(json)")
        let quotedFlag = try stored(["/bin/sh", "-c", "zip '-P' Secret77 out.zip f"])
        #expect(!quotedFlag.args.contains { $0.contains("Secret77") }, "\(quotedFlag.args)")
    }

    @Test("URL passwords longer than 256 bytes are redacted")
    func longURLPasswords() throws {
        for length in [300, 4_000] {
            let token = String(repeating: "t", count: length)
            let url = "https://oauth2:\(token)@git.example.invalid/repo.git"
            #expect(CommandSanitizer.sanitize("git clone " + url)
                == "git clone https://oauth2:[REDACTED]@git.example.invalid/repo.git", "\(length) bytes")
            let process = try stored(["/usr/bin/git", "clone", url])
            #expect(!process.args.contains { $0.contains(token) }, "\(length) bytes in argv")
            #expect(!process.commandLine.contains(token), "\(length) bytes in the command line")
        }
    }

    @Test("a URL password containing a slash is redacted")
    func urlPasswordsWithSlash() {
        #expect(CommandSanitizer.sanitize("git clone https://u:p/q@host/r.git")
            == "git clone https://u:[REDACTED]@host/r.git")
        let database = CommandSanitizer.sanitize("python app.py --db postgresql://admin:Ab/cd+ef@db/app")
        #expect(!database.contains("Ab/cd+ef"), "\(database)")
    }

    @Test("bare-string redaction takes linear time on adversarial input")
    func linearTime() {
        // Each took seconds or more before: nested lazy spans after a program
        // word, a lazy span per sshpass, a greedy password span per `://`, and
        // a backtracking separator after --password. The memo skips inputs
        // over 4 KiB, so each runs in full.
        let inputs = [
            String(repeating: "docker login ", count: 640),
            String(repeating: "sshpass ", count: 4_096),
            String(repeating: "://a:b", count: 10_923),
            "--password" + String(repeating: " ", count: 16_384) + "!",
        ]
        let clock = ContinuousClock()
        for input in inputs {
            var fastest = Duration.seconds(3_600)
            for _ in 0..<3 {
                fastest = min(fastest, clock.measure { _ = CommandSanitizer.sanitize(input) })
            }
            #expect(fastest < .milliseconds(250), "\(input.prefix(16))…: \(fastest)")
        }
        let argv = ["/usr/bin/true", String(repeating: "docker login ", count: 640)]
        var fastest = Duration.seconds(3_600)
        for _ in 0..<3 {
            fastest = min(fastest, clock.measure { _ = CommandSanitizer.sanitize(arguments: argv) })
        }
        #expect(fastest < .milliseconds(250), "argv: \(fastest)")
    }
}
