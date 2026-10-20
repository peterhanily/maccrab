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

    @Test("-p and -P values stay visible unless the program takes a password there")
    func portAndPidValuesStayVisible() throws {
        for argv in [
            ["/usr/bin/ssh", "-p", "2222", "host"],
            ["/usr/bin/nc", "-l", "-p", "4444"],
            ["/usr/sbin/lsof", "-p", "123"],
            ["/usr/local/bin/docker", "run", "-p", "8080:80", "image"],
            ["/usr/bin/scp", "-P", "2222", "f", "h:"],
            ["/usr/bin/xargs", "-P", "4", "echo"],
            ["/bin/mkdir", "-p", "build/x"],
            ["/usr/bin/find", "/", "-perm", "-4000", "-print"],
            ["/usr/local/bin/mysql", "-h", "db", "-P", "3306"],
        ] {
            let process = try stored(argv)
            #expect(process.commandLine == argv.joined(separator: " "), "\(process.commandLine)")
            #expect(process.args == argv)
        }
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

    @Test("bare strings without argv still cover sshpass, -u pairs and pass:")
    func bareStrings() {
        for (line, secret) in [
            ("sshpass -p letmein ssh host", "letmein"),
            ("sshpass -pletmein ssh host", "letmein"),
            ("curl -u alice:wonderland https://x.invalid", "wonderland"),
            ("openssl rsa -passin pass:wonderland -in key.pem", "wonderland"),
            ("tool --passwd=hunter2", "hunter2"),
            ("tool --key abcdef123456", "abcdef123456"),
        ] {
            #expect(!CommandSanitizer.sanitize(line).contains(secret), "\(line)")
        }
        #expect(CommandSanitizer.sanitize(commandLine: "a b", arguments: ["a", "c"]) == "a b")
        #expect(CommandSanitizer.sanitize(
            commandLine: "/usr/local/bin/sshpass -p letmein ssh",
            arguments: ["/usr/local/bin/sshpass", "-p", "letmein", "ssh"]
        ) == "/usr/local/bin/sshpass -p [REDACTED] ssh")
    }
}
