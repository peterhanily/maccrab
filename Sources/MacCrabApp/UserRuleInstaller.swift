// UserRuleInstaller.swift
// MacCrabApp
//
// Shared "compile one Sigma YAML rule and install it as a user override" path.
// Used by the in-dashboard YAML editor (RuleYAMLEditorSheet) and the rule
// creation wizard (RuleWizard) so the two can never drift on how a rule is
// installed.
//
// Flow:
//   1. ensure /Library/Application Support/MacCrab/user_rules exists and is
//      writable (prompt for admin ONCE to create it 0775 root:admin),
//   2. write <id>.yml there,
//   3. run the bundled compile_rules.py (with vendored PyYAML on PYTHONPATH)
//      in a tmp dir to produce <id>.json,
//   4. atomically rename the JSON into user_rules/,
//   5. touch .reload_tick so the daemon's mtime watcher reloads the rule.
//
// user_rules/ survives Sparkle updates — RuleBundleInstaller never touches it.

import Foundation

enum UserRuleInstaller {
    static let userRulesDir = "/Library/Application Support/MacCrab/user_rules"
    static let reloadTickPath = userRulesDir + "/.reload_tick"

    enum Result {
        case success
        case failure(String)
    }

    /// Install (or overwrite) a single user rule. `ruleId` is the rule's
    /// canonical id (lowercased UUID) and the basename for <id>.{yml,json};
    /// it MUST match the `id:` field inside `yaml` so the engine keys the
    /// override on the same id.
    static func install(ruleId: String, yaml: String) async -> Result {
        // Compile locally in tmp (no privileged write), then route the install
        // through the daemon's privileged inbox: the ROOT daemon writes it into
        // the secure root-owned user_rules dir. The engine's secure-dir gate
        // refuses a user/group-writable rules dir, so the app can't write there
        // itself — the old osascript-created 0775 dir was exactly why
        // dashboard-saved rules showed as active but never fired. No admin
        // prompt now; the daemon applies the rule on its ~5 s inbox poll.
        let (json, compileError) = await compileViaBundledPython(ruleId: ruleId, yaml: yaml)
        guard let json else { return .failure(compileError ?? "Rule compile failed") }
        return dropInboxRequest(verb: "install-rule",
                                payload: ["ruleId": ruleId, "yaml": yaml, "json": json])
    }

    static let inboxDir = "/Library/Application Support/MacCrab/inbox"

    /// Drop a JSON request into the daemon's privileged inbox (mode 1777 sticky —
    /// a non-root user can write, the root daemon validates the owner uid +
    /// sanitizes the rule id). The daemon, not the app, does the privileged write
    /// into user_rules. Returns .success once queued (applied on the ~5 s poll).
    static func dropInboxRequest(verb: String, payload: [String: Any]) -> Result {
        guard let data = try? JSONSerialization.data(withJSONObject: payload) else {
            return .failure("Couldn't serialize the \(verb) request")
        }
        let reqPath = inboxDir + "/\(verb)-\(UUID().uuidString).json"
        guard FileManager.default.createFile(atPath: reqPath, contents: data) else {
            return .failure("Couldn't reach MacCrab's inbox at \(inboxDir). Is MacCrab's protection running?")
        }
        return .success
    }

    /// Run the bundled `compile_rules.py` on JUST the rule being saved, using a
    /// fresh tmp dir as both input AND output so the compiler's
    /// `_snapshot_previous_output` step (which tries to create
    /// `<output_dir>.archive/`) doesn't trip over /Library's root-only write
    /// permissions. The produced JSON is then renamed back into user_rules/.
    static func compileViaBundledPython(ruleId: String, yaml: String) async -> (json: String?, error: String?) {
        guard let compilerPath = Bundle.main.path(forResource: "compile_rules", ofType: "py", inDirectory: "Compiler") else {
            return (nil, "Bundled compiler not found in MacCrab.app/Contents/Resources/Compiler/")
        }
        let pythonPath = (compilerPath as NSString).deletingLastPathComponent
        let tmpRoot = NSTemporaryDirectory() + "maccrab-compile-\(UUID().uuidString)"
        defer { try? FileManager.default.removeItem(atPath: tmpRoot) }
        do {
            try FileManager.default.createDirectory(atPath: tmpRoot, withIntermediateDirectories: true)
        } catch {
            return (nil, "Couldn't create tmp dir: \(error.localizedDescription)")
        }
        // Stage the supplied YAML in the tmp dir (no read from the now
        // root-owned user_rules — the daemon owns that).
        let ymlStaged = tmpRoot + "/\(ruleId).yml"
        do {
            try yaml.data(using: .utf8)?.write(to: URL(fileURLWithPath: ymlStaged))
        } catch {
            return (nil, "Couldn't stage YAML for compile: \(error.localizedDescription)")
        }
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        task.arguments = [compilerPath, "--input-dir", tmpRoot, "--output-dir", tmpRoot]
        var env = ProcessInfo.processInfo.environment
        env["PYTHONPATH"] = pythonPath
        task.environment = env
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        task.standardOutput = stdoutPipe
        task.standardError = stderrPipe
        // Drain pipes in real time so a >64 KB PyYAML traceback can't deadlock
        // the child on a full pipe buffer while the parent waits.
        var outBytes = Data()
        var errBytes = Data()
        let drainLock = NSLock()
        stdoutPipe.fileHandleForReading.readabilityHandler = { handle in
            let chunk = handle.availableData
            guard !chunk.isEmpty else { handle.readabilityHandler = nil; return }
            drainLock.lock(); outBytes.append(chunk); drainLock.unlock()
        }
        stderrPipe.fileHandleForReading.readabilityHandler = { handle in
            let chunk = handle.availableData
            guard !chunk.isEmpty else { handle.readabilityHandler = nil; return }
            drainLock.lock(); errBytes.append(chunk); drainLock.unlock()
        }
        do {
            try task.run()
        } catch {
            return (nil, "Couldn't run python3: \(error.localizedDescription)")
        }
        // 10 s timeout (compiling one rule is <100 ms; 100× margin).
        let deadline = DispatchTime.now() + .seconds(10)
        let timeoutItem = DispatchWorkItem {
            if task.isRunning {
                task.terminate()
                DispatchQueue.global().asyncAfter(deadline: .now() + 1) {
                    if task.isRunning { kill(task.processIdentifier, SIGKILL) }
                }
            }
        }
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: deadline, execute: timeoutItem)
        task.waitUntilExit()
        timeoutItem.cancel()
        stdoutPipe.fileHandleForReading.readabilityHandler = nil
        stderrPipe.fileHandleForReading.readabilityHandler = nil
        if let finalOut = try? stdoutPipe.fileHandleForReading.readToEnd() {
            drainLock.lock(); outBytes.append(finalOut); drainLock.unlock()
        }
        if let finalErr = try? stderrPipe.fileHandleForReading.readToEnd() {
            drainLock.lock(); errBytes.append(finalErr); drainLock.unlock()
        }
        if task.terminationStatus != 0 {
            let stderr = String(data: errBytes, encoding: .utf8) ?? ""
            let stdout = String(data: outBytes, encoding: .utf8) ?? ""
            let detail = (stderr + "\n" + stdout)
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .components(separatedBy: "\n")
                .filter { !$0.isEmpty }
                .suffix(8)
                .joined(separator: "\n")
            return (nil, detail.isEmpty ? "compile_rules.py exited \(task.terminationStatus)" : detail)
        }
        let jsonStaged = tmpRoot + "/\(ruleId).json"
        guard FileManager.default.fileExists(atPath: jsonStaged) else {
            return (nil, "Compiler ran cleanly but produced no JSON — rule may be malformed or product != macos")
        }
        guard let jsonText = try? String(contentsOf: URL(fileURLWithPath: jsonStaged), encoding: .utf8) else {
            return (nil, "Couldn't read the compiled JSON")
        }
        // Return the JSON text; the caller routes it through the privileged inbox
        // so the root daemon writes it into the secure user_rules dir.
        return (jsonText, nil)
    }
    // (Rule installs/overrides now route through the privileged inbox; the ROOT
    // daemon writes the rule + touches .reload_tick. The app no longer writes
    // user_rules or the tick directly — see install()/dropInboxRequest.)
}
