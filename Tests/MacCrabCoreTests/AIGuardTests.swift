// AIGuardTests.swift
// Tests for AI coding tool monitoring (AIGuard module).

import Testing
import Foundation
@testable import MacCrabCore

// MARK: - AI Tool Registry Tests

@Suite("AI Guard: Tool Registry")
struct AIToolRegistryTests {

    @Test("Detects Claude Code by path")
    func detectClaude() {
        let registry = AIToolRegistry()
        #expect(registry.isAITool(executablePath: "/Users/user/.local/bin/claude") == .claudeCode)
        #expect(registry.isAITool(executablePath: "/Users/user/.local/share/claude/versions/2.1.90") == .claudeCode)
    }

    @Test("Detects Codex by path")
    func detectCodex() {
        let registry = AIToolRegistry()
        #expect(registry.isAITool(executablePath: "/Applications/Codex.app/Contents/Resources/codex") == .codex)
    }

    @Test("Detects OpenClaw by path")
    func detectOpenClaw() {
        let registry = AIToolRegistry()
        #expect(registry.isAITool(executablePath: "/Users/user/.nvm/versions/node/v24/bin/openclaw") == .openClaw)
        #expect(registry.isAITool(executablePath: "/usr/local/bin/openclaw-gateway") == .openClaw)
    }

    @Test("Detects Cursor by path")
    func detectCursor() {
        let registry = AIToolRegistry()
        #expect(registry.isAITool(executablePath: "/Applications/Cursor.app/Contents/MacOS/Cursor") == .cursor)
    }

    @Test("Detects Continue.dev via config dir + name (Wave 7A.5)")
    func detectContinue() {
        let registry = AIToolRegistry()
        // App / binary-style paths
        #expect(registry.isAITool(executablePath: "/Users/user/.continue/continue-binary") == .continuedev)
        // Explicit MCP config path (SANDWORM_MODE compromise target)
        #expect(registry.isAITool(executablePath: "/Users/user/.continue/config.json") == .continuedev)
        // Process-name lookup
        #expect(registry.isAIToolByName("continue") == .continuedev)
    }

    @Test("Detects Windsurf via Codeium support dir + MCP config (Wave 7A.5)")
    func detectWindsurf() {
        let registry = AIToolRegistry()
        // The Codeium-branded support dir is the SANDWORM_MODE target
        #expect(registry.isAITool(
            executablePath: "/Users/user/Library/Application Support/Codeium/Windsurf/extensions"
        ) == .windsurf)
        // The dotfile-style MCP config path
        #expect(registry.isAITool(executablePath: "/Users/user/.windsurf/mcp.json") == .windsurf)
        // The .app path is preserved from the pre-existing pattern
        #expect(registry.isAITool(executablePath: "/Applications/Windsurf.app/Contents/MacOS/Windsurf") == .windsurf)
        #expect(registry.isAIToolByName("windsurf") == .windsurf)
    }

    @Test("Detects Kiro IDE via app + ~/.kiro + ~/Library/Application Support/Kiro (Wave 7A.5)")
    func detectKiro() {
        let registry = AIToolRegistry()
        // Amazon Kiro .app bundle
        #expect(registry.isAITool(executablePath: "/Applications/Kiro.app/Contents/MacOS/Kiro") == .kiro)
        // node-ipc compromise target dirs
        #expect(registry.isAITool(
            executablePath: "/Users/user/Library/Application Support/Kiro/settings"
        ) == .kiro)
        #expect(registry.isAITool(executablePath: "/Users/user/.kiro/cache") == .kiro)
        #expect(registry.isAIToolByName("kiro") == .kiro)
    }

    @Test("Does NOT flag regular binaries as AI tools")
    func noFalsePositives() {
        let registry = AIToolRegistry()
        #expect(registry.isAITool(executablePath: "/usr/bin/git") == nil)
        #expect(registry.isAITool(executablePath: "/bin/bash") == nil)
        #expect(registry.isAITool(executablePath: "/Applications/Safari.app/Contents/MacOS/Safari") == nil)
        #expect(registry.isAITool(executablePath: "/usr/bin/python3") == nil)
    }

    @Test("Detects AI child via ancestry")
    func detectChildByAncestry() {
        let registry = AIToolRegistry()
        let ancestors = [
            ProcessAncestor(pid: 100, executable: "/Users/user/.local/bin/claude", name: "claude"),
            ProcessAncestor(pid: 1, executable: "/sbin/launchd", name: "launchd"),
        ]
        let (isChild, toolType) = registry.isAIChildProcess(ancestors: ancestors)
        #expect(isChild)
        #expect(toolType == .claudeCode)
    }

    @Test("Non-AI ancestry returns false")
    func noAIAncestry() {
        let registry = AIToolRegistry()
        let ancestors = [
            ProcessAncestor(pid: 50, executable: "/Applications/Terminal.app/Contents/MacOS/Terminal", name: "Terminal"),
            ProcessAncestor(pid: 1, executable: "/sbin/launchd", name: "launchd"),
        ]
        let (isChild, _) = registry.isAIChildProcess(ancestors: ancestors)
        #expect(!isChild)
    }
}

// MARK: - Credential Fence Tests

@Suite("AI Guard: Credential Fence")
struct CredentialFenceTests {

    @Test("Detects SSH key access")
    func sshKeyAccess() {
        let fence = CredentialFence()
        #expect(fence.checkAccess(filePath: "/Users/user/.ssh/id_rsa") == .sshKey)
        #expect(fence.checkAccess(filePath: "/Users/user/.ssh/id_ed25519") == .sshKey)
    }

    @Test("Detects AWS credential access")
    func awsAccess() {
        let fence = CredentialFence()
        #expect(fence.checkAccess(filePath: "/Users/user/.aws/credentials") == .awsCredential)
    }

    @Test("Detects .env file access")
    func envFileAccess() {
        let fence = CredentialFence()
        #expect(fence.checkAccess(filePath: "/Users/user/project/.env") == .envFile)
        #expect(fence.checkAccess(filePath: "/Users/user/project/.env.production") == .envFile)
    }

    @Test("Detects npm/docker token access")
    func tokenAccess() {
        let fence = CredentialFence()
        #expect(fence.checkAccess(filePath: "/Users/user/.npmrc") == .npmToken)
        #expect(fence.checkAccess(filePath: "/Users/user/.docker/config.json") == .dockerAuth)
    }

    @Test("Does NOT flag normal source files")
    func noFalsePositives() {
        let fence = CredentialFence()
        #expect(fence.checkAccess(filePath: "/Users/user/project/src/main.swift") == nil)
        #expect(fence.checkAccess(filePath: "/Users/user/project/README.md") == nil)
        #expect(fence.checkAccess(filePath: "/Users/user/project/package.json") == nil)
    }

    @Test("Detailed check returns description")
    func detailedCheck() {
        let fence = CredentialFence()
        let result = fence.checkAccessDetailed(filePath: "/Users/user/.ssh/id_rsa", aiToolName: "Claude Code")
        #expect(result != nil)
        #expect(result?.type == .sshKey)
        #expect(result?.description.contains("Claude Code") == true)
        #expect(result?.description.contains("SSH") == true)
    }
}

// MARK: - Project Boundary Tests

@Suite("AI Guard: Project Boundary")
struct ProjectBoundaryTests {

    @Test("Allows writes within project directory")
    func withinBoundary() async {
        let boundary = ProjectBoundary()
        await boundary.registerBoundary(aiPid: 100, projectDir: "/Users/user/Projects/myapp")

        let violation = await boundary.checkWrite(
            filePath: "/Users/user/Projects/myapp/src/main.swift",
            aiSessionPid: 100,
            aiToolName: "Claude Code"
        )
        #expect(violation == nil, "Write within project should be allowed")
    }

    @Test("Flags writes outside project directory")
    func outsideBoundary() async {
        let boundary = ProjectBoundary()
        await boundary.registerBoundary(aiPid: 100, projectDir: "/Users/user/Projects/myapp")

        let violation = await boundary.checkWrite(
            filePath: "/Users/user/Library/LaunchAgents/evil.plist",
            aiSessionPid: 100,
            aiToolName: "Claude Code"
        )
        #expect(violation != nil, "Write outside project should be flagged")
        #expect(violation?.description.contains("OUTSIDE") == true)
    }

    @Test("Allows writes to exception directories (/tmp)")
    func tmpException() async {
        let boundary = ProjectBoundary()
        await boundary.registerBoundary(aiPid: 100, projectDir: "/Users/user/Projects/myapp")

        let violation = await boundary.checkWrite(
            filePath: "/tmp/build-output-12345",
            aiSessionPid: 100,
            aiToolName: "Claude Code"
        )
        #expect(violation == nil, "/tmp should be an exception")
    }

    @Test("Allows writes to npm cache")
    func npmCacheException() async {
        let boundary = ProjectBoundary()
        await boundary.registerBoundary(aiPid: 100, projectDir: "/Users/user/Projects/myapp")

        let violation = await boundary.checkWrite(
            filePath: "/Users/user/.npm/_cacache/content-v2/sha512/abc",
            aiSessionPid: 100,
            aiToolName: "Claude Code"
        )
        #expect(violation == nil, "npm cache should be an exception")
    }

    @Test("No violation when no boundary registered")
    func noBoundary() async {
        let boundary = ProjectBoundary()
        let violation = await boundary.checkWrite(
            filePath: "/anywhere/anything",
            aiSessionPid: 999,
            aiToolName: "Claude Code"
        )
        #expect(violation == nil, "No boundary registered = no violation")
    }

    @Test("registerBoundary rejects filesystem root")
    func rejectsFilesystemRoot() async {
        let boundary = ProjectBoundary()
        let accepted = await boundary.registerBoundary(aiPid: 100, projectDir: "/")
        #expect(accepted == false, "A boundary at / would flag every write as outside")

        // And no violation should be emitted for subsequent writes — the
        // boundary was never recorded, so checkWrite returns nil for the
        // "no boundary registered" branch.
        let violation = await boundary.checkWrite(
            filePath: "/Users/u/anywhere",
            aiSessionPid: 100,
            aiToolName: "Claude Code"
        )
        #expect(violation == nil, "Rejected boundary must not produce violations")
    }

    @Test("registerBoundary rejects empty projectDir")
    func rejectsEmpty() async {
        let boundary = ProjectBoundary()
        #expect(await boundary.registerBoundary(aiPid: 100, projectDir: "") == false)
        #expect(await boundary.registerBoundary(aiPid: 101, projectDir: "   ") == false)
        #expect(await boundary.registerBoundary(aiPid: 102, projectDir: "\t\n") == false)
    }

    @Test("registerBoundary accepts a normal project path")
    func acceptsValidPath() async {
        let boundary = ProjectBoundary()
        let accepted = await boundary.registerBoundary(
            aiPid: 100,
            projectDir: "/Users/user/Projects/myapp"
        )
        #expect(accepted == true, "A normal user project path must be accepted")
    }

    @Test("Writes to /dev/null are not flagged as boundary violations")
    func devNullAllowed() async {
        let boundary = ProjectBoundary()
        await boundary.registerBoundary(aiPid: 100, projectDir: "/Users/user/Projects/myapp")

        for path in ["/dev/null", "/dev/urandom", "/dev/random", "/dev/zero"] {
            let violation = await boundary.checkWrite(
                filePath: path,
                aiSessionPid: 100,
                aiToolName: "Claude Code"
            )
            #expect(violation == nil, "\(path) is a legitimate device sink, not a boundary violation")
        }
    }
}

// MARK: - Behavioral Scoring AI Indicators

@Suite("AI Guard: Behavioral Scoring Indicators")
struct AIBehaviorScoringTests {

    @Test("All AI indicators are registered with positive weights")
    func aiIndicatorWeights() {
        let aiIndicators = [
            "ai_tool_detected", "ai_tool_spawns_shell", "ai_tool_runs_sudo",
            "ai_tool_credential_access", "ai_tool_boundary_violation",
            "ai_tool_installs_unknown_pkg", "ai_tool_persistence_write",
            "ai_tool_downloads_and_exec",
            "prompt_injection_low", "prompt_injection_medium",
            "prompt_injection_high", "prompt_injection_critical",
            "prompt_injection_compound",
        ]
        for name in aiIndicators {
            let weight = BehaviorScoring.weights[name]
            #expect(weight != nil && weight! > 0, "AI indicator '\(name)' should have positive weight")
        }
    }

    @Test("Credential access has high weight")
    func credentialWeight() {
        let weight = BehaviorScoring.weights["ai_tool_credential_access"] ?? 0
        #expect(weight >= 8.0, "Credential access should have weight >= 8.0")
    }

    @Test("Prompt injection compound has highest AI weight")
    func injectionCompoundWeight() {
        let weight = BehaviorScoring.weights["prompt_injection_compound"] ?? 0
        #expect(weight >= 10.0, "Compound injection should have weight >= 10.0")
    }
}// MARK: - Behavioral Scoring Eviction

@Suite("AI Guard: Behavioral Scoring Eviction")
struct BehaviorScoringEvictionTests {

    // A high-score process must survive eviction even when the tracking table
    // overflows with transient zero/low-score processes. Regression guard for
    // the FIFO->lowest-decayed-score eviction change (detection-03): the old
    // FIFO logic would evict the early-inserted attacker first.
    @Test("High-score process survives eviction; low-score transient is dropped")
    func highScoreSurvivesEviction() async {
        let cap = 8
        // Long half-life so scores don't decay to zero during the test, keeping
        // the assertion about retained signal deterministic.
        let scorer = BehaviorScoring(
            alertThreshold: 100.0,      // high so transient inserts never alert
            criticalThreshold: 200.0,
            decayHalfLife: 100_000,
            maxTrackedProcesses: cap
        )

        // Insert one heavily-scored "attacker" process FIRST (oldest insertion).
        let attackerPid: Int32 = 1
        let attackerPath = "/tmp/attacker"
        let heavy = BehaviorScoring.Indicator(name: "sigma_rule_match_critical", weight: 50.0)
        await scorer.addIndicator(heavy, forProcess: attackerPid, path: attackerPath)
        #expect(await scorer.score(forPid: attackerPid, path: attackerPath) > 0)

        // Flood the table with many distinct transient processes, each carrying
        // a single tiny indicator. This forces eviction well past the cap.
        let light = BehaviorScoring.Indicator(name: "sigma_rule_match_low", weight: 0.5)
        for i in 0..<(cap * 4) {
            let pid = Int32(1000 + i)
            await scorer.addIndicator(light, forProcess: pid, path: "/tmp/transient_\(i)")
        }

        // The high-score attacker must still be tracked (lowest-score eviction),
        // whereas the earliest transient (pid 1000) must have been evicted.
        #expect(await scorer.score(forPid: attackerPid, path: attackerPath) > 40.0,
                "High-score attacker must survive eviction churn (decay-tolerant)")
        #expect(await scorer.score(forPid: 1000, path: "/tmp/transient_0") == 0,
                "An early low-score transient should have been evicted")
    }
}
