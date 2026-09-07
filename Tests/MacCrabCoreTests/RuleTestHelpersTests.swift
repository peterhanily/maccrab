import Foundation
import Testing

@Suite("Rule fixture compilation reliability")
struct RuleTestHelpersTests {
    private func makeProject(compiler: String) throws -> URL {
        let project = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-fixture-helper-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: project.appendingPathComponent("Compiler"), withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(
            at: project.appendingPathComponent("Rules"), withIntermediateDirectories: true
        )
        try compiler.write(
            to: project.appendingPathComponent("Compiler/compile_rules.py"),
            atomically: true, encoding: .utf8
        )
        return project
    }

    @Test("Source contents are recompiled even when modification times stay old")
    func oldSourceTimestampDoesNotReuseOutput() throws {
        let project = try makeProject(compiler: """
        import json, pathlib, sys
        src = pathlib.Path(sys.argv[sys.argv.index('--input-dir') + 1])
        dst = pathlib.Path(sys.argv[sys.argv.index('--output-dir') + 1])
        (dst / 'rule.json').write_text(json.dumps({'value': (src / 'value.txt').read_text()}))
        """)
        defer { try? FileManager.default.removeItem(at: project) }
        let source = project.appendingPathComponent("Rules/value.txt")
        let oldDate = Date(timeIntervalSince1970: 1)
        try "first source".write(to: source, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.modificationDate: oldDate], ofItemAtPath: source.path)
        let first = try compileRuleFixture(
            projectDirectory: project, outputDirectory: project.appendingPathComponent("first-run")
        )
        try "second source".write(to: source, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.modificationDate: oldDate], ofItemAtPath: source.path)
        let second = try compileRuleFixture(
            projectDirectory: project, outputDirectory: project.appendingPathComponent("second-run")
        )
        let firstData = try Data(contentsOf: first.appendingPathComponent("rule.json"))
        let secondData = try Data(contentsOf: second.appendingPathComponent("rule.json"))
        #expect(firstData != secondData)
        #expect(String(decoding: secondData, as: UTF8.self).contains("second source"))
    }

    @Test("A failed compiler propagates its diagnostic and removes partial output")
    func failedCompilerDoesNotPublishPartialFixture() throws {
        let project = try makeProject(compiler: """
        import pathlib, sys
        dst = pathlib.Path(sys.argv[sys.argv.index('--output-dir') + 1])
        (dst / 'partial.json').write_text('{}')
        print('fixture compiler diagnostic', file=sys.stderr)
        sys.exit(7)
        """)
        defer { try? FileManager.default.removeItem(at: project) }
        let output = project.appendingPathComponent("output")
        do {
            _ = try compileRuleFixture(projectDirectory: project, outputDirectory: output)
            Issue.record("Expected the compiler exit status to reject partial output")
        } catch let error as RuleFixtureCompilationError {
            #expect(error.description.contains("status 7"))
            #expect(error.description.contains("fixture compiler diagnostic"))
        }
        #expect(!FileManager.default.fileExists(atPath: output.path))
    }

    @Test("Existing output is refused and preserved")
    func existingOutputIsNotReusedOrRemoved() throws {
        let project = try makeProject(compiler: "")
        defer { try? FileManager.default.removeItem(at: project) }
        let output = project.appendingPathComponent("output")
        try FileManager.default.createDirectory(at: output, withIntermediateDirectories: false)
        let original = output.appendingPathComponent("rule.json")
        try "existing fixture".write(to: original, atomically: true, encoding: .utf8)
        #expect(throws: RuleFixtureCompilationError.self) {
            try compileRuleFixture(projectDirectory: project, outputDirectory: output)
        }
        #expect(try String(contentsOf: original, encoding: .utf8) == "existing fixture")
    }

    @Test("Missing compiler executable fails without waiting on an unstarted process")
    func launchFailureIsReported() throws {
        let project = try makeProject(compiler: "")
        defer { try? FileManager.default.removeItem(at: project) }
        let output = project.appendingPathComponent("output")
        do {
            _ = try compileRuleFixture(
                projectDirectory: project,
                outputDirectory: output,
                pythonExecutableURL: project.appendingPathComponent("missing-python")
            )
            Issue.record("Expected a launch failure")
        } catch let error as RuleFixtureCompilationError {
            #expect(error.description.contains("Could not launch rule compiler"))
        }
        #expect(!FileManager.default.fileExists(atPath: output.path))
    }

    @Test("A successful process with no rule JSON is not a usable fixture")
    func emptyOutputFails() throws {
        let project = try makeProject(compiler: "print('no rules generated')")
        defer { try? FileManager.default.removeItem(at: project) }
        let output = project.appendingPathComponent("output")
        #expect(throws: RuleFixtureCompilationError.self) {
            try compileRuleFixture(projectDirectory: project, outputDirectory: output)
        }
        #expect(!FileManager.default.fileExists(atPath: output.path))
    }

    @Test("Compiler completion has a deadline and timed-out output is removed")
    func timeoutFailsAndCleansUp() throws {
        let project = try makeProject(compiler: "import time; time.sleep(60)")
        defer { try? FileManager.default.removeItem(at: project) }
        let output = project.appendingPathComponent("output")
        do {
            _ = try compileRuleFixture(projectDirectory: project, outputDirectory: output, timeout: 0.1)
            Issue.record("Expected compiler deadline to expire")
        } catch let error as RuleFixtureCompilationError {
            #expect(error.description.contains("exceeded"))
        }
        #expect(!FileManager.default.fileExists(atPath: output.path))
    }
}
