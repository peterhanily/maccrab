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
        guard ensureOverrideDirWritable() else {
            return .failure("Admin password is required the first time MacCrab saves a rule.")
        }
        let ymlPath = userRulesDir + "/\(ruleId).yml"
        guard (try? yaml.data(using: .utf8)?.write(to: URL(fileURLWithPath: ymlPath))) != nil else {
            return .failure("Couldn't write YAML to \(ymlPath)")
        }
        let compiled = await compileViaBundledPython(ruleId: ruleId)
        switch compiled {
        case .success:
            touchReloadTick()
            return .success
        case .failure(let message):
            // Keep the YAML on disk so work isn't lost, but the daemon won't
            // load it until the YAML compiles cleanly.
            return .failure(message)
        }
    }

    /// If the override dir doesn't exist or isn't writable, prompt for admin
    /// once and chmod it 0775 root:admin so this user (admin group) can write
    /// without elevation on subsequent saves.
    static func ensureOverrideDirWritable() -> Bool {
        let fm = FileManager.default
        let dir = userRulesDir
        if fm.isWritableFile(atPath: dir) { return true }
        let shell = "mkdir -p '\(dir)' && chown root:admin '\(dir)' && chmod 0775 '\(dir)'"
        let escaped = shell.replacingOccurrences(of: "\"", with: "\\\"")
        let script = "do shell script \"\(escaped)\" with administrator privileges with prompt \"MacCrab needs to create the user-rules directory once so you can save rules without entering your password every time.\""
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        task.arguments = ["-e", script]
        task.standardOutput = FileHandle.nullDevice
        task.standardError = FileHandle.nullDevice
        do {
            try task.run()
            task.waitUntilExit()
            return task.terminationStatus == 0 && fm.isWritableFile(atPath: dir)
        } catch {
            return false
        }
    }

    /// Run the bundled `compile_rules.py` on JUST the rule being saved, using a
    /// fresh tmp dir as both input AND output so the compiler's
    /// `_snapshot_previous_output` step (which tries to create
    /// `<output_dir>.archive/`) doesn't trip over /Library's root-only write
    /// permissions. The produced JSON is then renamed back into user_rules/.
    static func compileViaBundledPython(ruleId: String) async -> Result {
        guard let compilerPath = Bundle.main.path(forResource: "compile_rules", ofType: "py", inDirectory: "Compiler") else {
            return .failure("Bundled compiler not found in MacCrab.app/Contents/Resources/Compiler/")
        }
        let pythonPath = (compilerPath as NSString).deletingLastPathComponent
        let tmpRoot = NSTemporaryDirectory() + "maccrab-compile-\(UUID().uuidString)"
        defer { try? FileManager.default.removeItem(atPath: tmpRoot) }
        do {
            try FileManager.default.createDirectory(atPath: tmpRoot, withIntermediateDirectories: true)
        } catch {
            return .failure("Couldn't create tmp dir: \(error.localizedDescription)")
        }
        let ymlSrc = userRulesDir + "/\(ruleId).yml"
        let ymlStaged = tmpRoot + "/\(ruleId).yml"
        do {
            try FileManager.default.copyItem(atPath: ymlSrc, toPath: ymlStaged)
        } catch {
            return .failure("Couldn't stage YAML for compile: \(error.localizedDescription)")
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
            return .failure("Couldn't run python3: \(error.localizedDescription)")
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
            return .failure(detail.isEmpty ? "compile_rules.py exited \(task.terminationStatus)" : detail)
        }
        let jsonStaged = tmpRoot + "/\(ruleId).json"
        let jsonDst = userRulesDir + "/\(ruleId).json"
        guard FileManager.default.fileExists(atPath: jsonStaged) else {
            return .failure("Compiler ran cleanly but produced no JSON — rule may be malformed or product != macos")
        }
        // POSIX rename is atomic when both paths share a filesystem (/tmp and
        // /Library are both on /).
        let renamed = jsonStaged.withCString { src in
            jsonDst.withCString { dst in rename(src, dst) == 0 }
        }
        guard renamed else {
            return .failure("Atomic rename failed: \(String(cString: strerror(errno)))")
        }
        return .success
    }

    static func touchReloadTick() {
        let data = "\(Date().timeIntervalSince1970)\n".data(using: .utf8) ?? Data()
        try? data.write(to: URL(fileURLWithPath: reloadTickPath))
    }
}
