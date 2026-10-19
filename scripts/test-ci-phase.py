#!/usr/bin/python3
"""Ordinary process lifecycle tests for bounded CI phase execution."""
import json
import errno
import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest import mock

RUNNER = Path(__file__).with_name("run-ci-phase.py")
SPEC = importlib.util.spec_from_file_location("ci_phase_runner", RUNNER)
CI_PHASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CI_PHASE)
SELECT_SPEC = importlib.util.spec_from_file_location("select_regressions", RUNNER.with_name("select-regression-tests.py"))
SELECTOR = importlib.util.module_from_spec(SELECT_SPEC)
SELECT_SPEC.loader.exec_module(SELECTOR)


class PhaseTests(unittest.TestCase):
    def setUp(self):
        self.previous_cwd = Path.cwd()
        self.cwd_fixture = tempfile.TemporaryDirectory()
        os.chdir(self.cwd_fixture.name)

    def tearDown(self):
        os.chdir(self.previous_cwd)
        self.cwd_fixture.cleanup()

    def test_reference_selection_catches_omitted_wiring_and_changed_tests(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Sources").mkdir()
            (root / "Tests").mkdir()
            (root / "scripts").mkdir()
            (root / "Sources/Worker.swift").write_text("struct AdmissionWorker {}")
            (root / "Tests/Wiring.swift").write_text('source("Sources/Worker.swift")')
            (root / "Tests/Behavior.swift").write_text("let worker = AdmissionWorker()")
            (root / "Tests/Changed.swift").write_text("a changed test without source references")
            (root / "Tests/Unrelated.swift").write_text("nothing related")
            manifest = SELECTOR.discover(root, ["Sources/Worker.swift", "Tests/Changed.swift"])
            self.assertEqual([row["path"] for row in manifest["candidates"]],
                             ["Tests/Behavior.swift", "Tests/Changed.swift", "Tests/Wiring.swift"])
            self.assertTrue(all(row["execution"] == "unreviewed" for row in manifest["candidates"]))

    def test_selector_ignores_ambient_git_redirection_and_pins_base(self):
        with tempfile.TemporaryDirectory() as directory:
            _, source, _ = self.bound_fixture(directory, "")
            source.write_text("changed source")
            expected = subprocess.check_output(
                ["/usr/bin/git", "-C", str(source.parent), "rev-parse", "HEAD"], text=True
            ).strip()
            environment = dict(os.environ, GIT_DIR="/nonexistent-fixture-git-dir",
                               GIT_WORK_TREE="/nonexistent-fixture-work-tree",
                               GIT_INDEX_FILE="/nonexistent-fixture-index")
            result = subprocess.run([sys.executable, str(RUNNER.with_name("select-regression-tests.py")),
                "--source-root", str(source.parent), "--base", "HEAD"],
                env=environment, text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads(result.stdout)
            self.assertEqual(manifest["base"], expected)
            self.assertEqual(manifest["head"], expected)
            self.assertEqual(manifest["changed_files"], ["example.swift"])

    def test_selector_preserves_overlapping_path_basename_and_type_reasons(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Sources/First").mkdir(parents=True)
            (root / "Sources/Second").mkdir(parents=True)
            (root / "Tests").mkdir()
            first = "Sources/First/AdmissionWorker.swift"
            second = "Sources/Second/AdmissionWorker.swift"
            for name in (first, second):
                (root / name).write_text("struct AdmissionWorker {}")
            (root / "Tests/Wiring.swift").write_text('source("' + first + '")')
            (root / "Tests/Unrelated.swift").write_text("PrefixAdmissionWorker AdmissionWorkerSuffix")
            manifest = SELECTOR.discover(root, [first, second])
            self.assertEqual([row["path"] for row in manifest["candidates"]], ["Tests/Wiring.swift"])
            reasons = manifest["candidates"][0]["reasons"]
            self.assertEqual(reasons, [
                {"changed": first, "kind": "reference", "matches": ["AdmissionWorker", "AdmissionWorker.swift", first]},
                {"changed": second, "kind": "reference", "matches": ["AdmissionWorker", "AdmissionWorker.swift"]},
            ])

    def test_selector_does_not_treat_base_as_git_options(self):
        with tempfile.TemporaryDirectory() as directory:
            _, source, _ = self.bound_fixture(directory, "")
            result = subprocess.run([sys.executable, str(RUNNER.with_name("select-regression-tests.py")),
                "--source-root", str(source.parent), "--base=--help"],
                text=True, capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")

    def phase_args(self, directory, code, timeout=0.5):
        root = Path(directory)
        return SimpleNamespace(label="ordinary fixture", log=str(root / "phase.log"),
                               result=str(root / "phase.json"), timeout_seconds=timeout,
                               grace_seconds=0.2, command=[sys.executable, "-c", code])

    def run_phase(self, directory, code, timeout="5"):
        root = Path(directory)
        return [sys.executable, "-I", str(RUNNER), "--label", "ordinary fixture",
                "--log", str(root / "phase.log"), "--result", str(root / "phase.json"),
                "--timeout-seconds", timeout, "--grace-seconds", "0.2", "--",
                sys.executable, "-c", code]

    def test_success_retains_output_and_measured_result(self):
        with tempfile.TemporaryDirectory() as directory:
            run = subprocess.run(self.run_phase(directory, "print('complete')"), timeout=10)
            record = json.loads((Path(directory) / "phase.json").read_text())
            self.assertEqual(run.returncode, 0)
            self.assertEqual(record["status"], "PASSED")
            self.assertEqual(record["exit_code"], 0)
            self.assertGreater(record["elapsed_seconds"], 0)
            self.assertEqual((Path(directory) / "phase.log").read_text(), "complete\n")
            self.assertEqual(record["argv"], [sys.executable, "-c", "print('complete')"])
            self.assertEqual(record["cwd"], str(Path.cwd().resolve()))
            self.assertTrue(record["inputs_unchanged"])
            self.assertEqual(len(record["command_executable"]["sha256"]), 64)
            self.assertEqual(len(record["log_identity"]["sha256"]), 64)

    def bound_fixture(self, directory, code):
        root = Path(directory)
        repo = root / "source"
        repo.mkdir()
        subprocess.run(["/usr/bin/git", "init", "-q", str(repo)], check=True)
        source = repo / "example.swift"
        source.write_text("original source\n")
        subprocess.run(["/usr/bin/git", "-C", str(repo), "add", "."], check=True)
        subprocess.run(["/usr/bin/git", "-C", str(repo), "-c", "user.name=Fixture",
                        "-c", "user.email=fixture@example.invalid", "-c", "core.hooksPath=/dev/null",
                        "commit", "-qm", "fixture"], check=True)
        executable = root / "test-binary"
        executable.write_bytes(b"synthetic binary")
        args = self.phase_args(directory, code, timeout=5)
        args.source_root = str(repo)
        args.artifact = [str(executable)]
        return args, source, executable

    def test_source_binary_and_inventory_are_bound_and_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            args, source, executable = self.bound_fixture(directory, "print('Test run with 2 tests in 1 suite passed')")
            inventory = Path(directory) / "inventory.json"
            inventory.write_text(json.dumps({"selected": ["First/a", "Second/b"]}))
            args.test_inventory = str(inventory)
            args.expected_test_count = 2
            self.assertEqual(CI_PHASE.run_phase(args), 0)
            result = json.loads(Path(args.result).read_text())
            identity = result["inputs_before"]
            self.assertTrue(identity["source"]["clean"])
            self.assertEqual(len(identity["source"]["commit"]), 40)
            self.assertEqual(len(identity["source"]["tree"]), 40)
            self.assertEqual(len(identity["source"]["worktree_sha256"]), 64)
            self.assertEqual(identity, result["inputs_after"])
            self.assertEqual(identity["test_inventory"]["document"]["selected"], ["First/a", "Second/b"])
            self.assertEqual(result["test_results"]["reported_tests"], 2)

    def linked_fixture(self, directory):
        build, source, executable = self.bound_fixture(directory, "print('built fixture')")
        build.artifact = []
        build.output_artifact = [str(executable)]
        self.assertEqual(CI_PHASE.run_phase(build), 0)
        test = self.phase_args(directory, "print('Test run with 2 tests in 1 suite passed')", timeout=5)
        test.log = str(Path(directory) / "test.log")
        test.result = str(Path(directory) / "test.json")
        test.source_root = str(source.parent)
        test.artifact = [str(executable)]
        test.build_receipt = build.result
        return test, source, executable

    def assert_link_refused_before_execution(self, args):
        args.command = [sys.executable, "-c", "raise AssertionError('must not run')"]
        self.assertEqual(CI_PHASE.run_phase(args), 65)
        result = json.loads(Path(args.result).read_text())
        self.assertEqual(result["status"], "INVALID_INPUT")
        self.assertFalse(Path(args.log).exists())

    def test_build_receipt_links_exact_output_to_test_input(self):
        with tempfile.TemporaryDirectory() as directory:
            args, _, _ = self.linked_fixture(directory)
            command = [sys.executable, "-I", str(RUNNER), "--label", args.label,
                       "--log", args.log, "--result", args.result,
                       "--source-root", args.source_root, "--artifact", args.artifact[0],
                       "--build-receipt", args.build_receipt, "--", *args.command]
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            record = json.loads(Path(args.result).read_text())
            self.assertEqual(record["status"], "PASSED")
            self.assertTrue(record["inputs_unchanged"])
            prior = record["inputs_before"]["build_receipt"]
            self.assertEqual(prior["sha256"], CI_PHASE.file_identity(args.build_receipt)["sha256"])
            self.assertEqual(prior["document"]["output_artifacts"], record["inputs_before"]["artifacts"])

    def test_build_link_refuses_between_phase_artifact_or_source_changes(self):
        for changed in ("binary", "path", "historical-path-redirected", "source", "missing-artifact", "no-artifacts"):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as directory:
                args, source, executable = self.linked_fixture(directory)
                if changed == "binary":
                    executable.write_bytes(b"different executable")
                elif changed in ("path", "historical-path-redirected"):
                    other = Path(directory) / "different-path-same-bytes"
                    other.write_bytes(executable.read_bytes())
                    args.artifact = [str(other)]
                    if changed == "historical-path-redirected":
                        executable.unlink()
                        executable.symlink_to(other)
                elif changed == "source":
                    source.write_text("changed between build and test")
                elif changed == "missing-artifact":
                    executable.unlink()
                else:
                    args.artifact = []
                self.assert_link_refused_before_execution(args)

    def test_build_link_captures_canonical_parent_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            args, _, executable = self.linked_fixture(directory)
            alias = Path(directory) / "parent-alias"
            alias.symlink_to(executable.parent, target_is_directory=True)
            args.artifact = [str(alias / executable.name)]
            self.assertEqual(CI_PHASE.run_phase(args), 0)
            result = json.loads(Path(args.result).read_text())
            self.assertEqual(result["inputs_before"]["artifacts"][0]["path"], str(executable.resolve()))

    def test_build_link_refuses_invalid_or_incomplete_receipts(self):
        def alter(document, case):
            if case == "schema":
                document["schema_version"] = 3
            elif case == "schema-type":
                document["schema_version"] = True
            elif case == "failed":
                document["status"] = "FAILED"
            elif case == "exit":
                document["exit_code"] = 1
            elif case == "changed-inputs":
                document["inputs_unchanged"] = False
            elif case == "incomplete":
                del document["completed_at"]
            elif case == "invalidated":
                document["identity_error"] = "prior invalidation"
            elif case == "unequal-sources":
                document["inputs_after"]["source"]["worktree_sha256"] = "f" * 64
            elif case == "wrong-source":
                for field in ("inputs_before", "inputs_after"):
                    document[field]["source"]["worktree_sha256"] = "f" * 64
            elif case == "no-source":
                for field in ("inputs_before", "inputs_after"):
                    document[field].pop("source")
            elif case == "unbound-source":
                for field in ("inputs_before", "inputs_after"):
                    document[field]["source"] = {"unbound": True}
            elif case == "no-output":
                document["output_artifacts"] = []
            elif case == "bytes":
                document["output_artifacts"][0]["bytes"] += 1
            elif case == "malformed-artifact":
                document["output_artifacts"][0]["bytes"] = "123"
            elif case == "duplicate-artifact":
                document["output_artifacts"] *= 2

        cases = ("schema", "schema-type", "failed", "exit", "changed-inputs", "incomplete", "invalidated",
                 "unequal-sources", "wrong-source", "no-source", "unbound-source", "no-output", "bytes",
                 "malformed-artifact", "duplicate-artifact")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                args, _, _ = self.linked_fixture(directory)
                path = Path(args.build_receipt)
                document = json.loads(path.read_text())
                alter(document, case)
                path.write_text(json.dumps(document))
                self.assert_link_refused_before_execution(args)

    def test_build_link_refuses_malformed_missing_or_redirected_receipt(self):
        for case in ("missing", "empty-path", "malformed-json", "non-object", "duplicate-field", "symlink"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                args, _, _ = self.linked_fixture(directory)
                path = Path(args.build_receipt)
                if case == "missing":
                    path.unlink()
                elif case == "empty-path":
                    args.build_receipt = ""
                elif case == "malformed-json":
                    path.write_text("{")
                elif case == "non-object":
                    path.write_text("[]")
                elif case == "duplicate-field":
                    path.write_text('{"status":"FAILED",' + path.read_text()[1:])
                else:
                    link = Path(directory) / "redirected-build.json"
                    link.symlink_to(path)
                    args.build_receipt = str(link)
                self.assert_link_refused_before_execution(args)

    def test_build_receipt_drift_during_test_invalidates_success(self):
        with tempfile.TemporaryDirectory() as directory:
            args, _, _ = self.linked_fixture(directory)
            # Keep a valid receipt with identical source/artifact identities;
            # only its independent file binding catches this replacement.
            args.command = [sys.executable, "-c", "import json; from pathlib import Path; p=Path(" +
                            repr(args.build_receipt) + "); d=json.loads(p.read_text()); "
                            "d['phase']='changed during test'; p.write_text(json.dumps(d))"]
            self.assertEqual(CI_PHASE.run_phase(args), 65)
            result = json.loads(Path(args.result).read_text())
            self.assertEqual(result["status"], "INVALIDATED")
            self.assertFalse(result["inputs_unchanged"])
            self.assertIn("inputs changed", result["identity_error"])

    def test_source_and_executable_changes_invalidate_a_passing_command(self):
        for changed in ("source", "binary", "untracked"):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as directory:
                args, source, executable = self.bound_fixture(directory, "")
                target = {"source": source, "binary": executable, "untracked": source.parent / "new.swift"}[changed]
                args.command = [sys.executable, "-c",
                                "from pathlib import Path; Path(" + repr(str(target)) + ").write_text('changed')"]
                self.assertEqual(CI_PHASE.run_phase(args), 65)
                result = json.loads(Path(args.result).read_text())
                self.assertEqual(result["status"], "INVALIDATED")
                self.assertEqual(result["command_exit_code"], 0)
                self.assertFalse(result["inputs_unchanged"])

    def test_dirty_source_is_explicit_and_bound_by_content(self):
        with tempfile.TemporaryDirectory() as directory:
            args, source, _ = self.bound_fixture(directory, "print('done')")
            source.write_text("uncommitted source")
            (source.parent / "new.swift").write_text("untracked input")
            self.assertEqual(CI_PHASE.run_phase(args), 0)
            result = json.loads(Path(args.result).read_text())
            self.assertFalse(result["inputs_before"]["source"]["clean"])
            self.assertEqual(result["inputs_before"]["source"]["file_count"], 2)

    def test_missing_artifact_stops_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            args, _, _ = self.bound_fixture(directory, "raise AssertionError('must not run')")
            args.artifact = [str(Path(directory) / "missing")]
            self.assertEqual(CI_PHASE.run_phase(args), 65)
            result = json.loads(Path(args.result).read_text())
            self.assertEqual(result["status"], "INVALID_INPUT")
            self.assertFalse(Path(args.log).exists())

    def test_symlink_and_fifo_artifacts_are_refused_without_blocking(self):
        for kind in ("symlink", "fifo"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                args, _, binary = self.bound_fixture(directory, "raise AssertionError('must not run')")
                target = Path(directory) / "not-a-regular-input"
                if kind == "symlink":
                    target.symlink_to(binary)
                else:
                    os.mkfifo(target)
                args.artifact = [str(target)]
                self.assertEqual(CI_PHASE.run_phase(args), 65)
                self.assertFalse(Path(args.log).exists())

    def test_command_executable_is_rechecked_without_explicit_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            args, _, binary = self.bound_fixture(directory, "")
            binary.write_text("#!/bin/sh\nprintf '#!/bin/sh\\nexit 0\\n' > \"$0\"\n")
            binary.chmod(0o700)
            args.command = [str(binary)]
            args.artifact = []
            self.assertEqual(CI_PHASE.run_phase(args), 65)
            record = json.loads(Path(args.result).read_text())
            self.assertEqual(record["status"], "INVALIDATED")
            self.assertNotEqual(record["inputs_before"]["command_executable"]["sha256"],
                                record["inputs_after"]["command_executable"]["sha256"])

    def test_count_mismatch_cannot_be_a_passing_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            args, _, _ = self.bound_fixture(directory, "print('Test run with 0 tests in 1 suite passed')")
            args.expected_test_count = 2
            self.assertEqual(CI_PHASE.run_phase(args), 65)
            result = json.loads(Path(args.result).read_text())
            self.assertEqual(result["status"], "INVALIDATED")
            self.assertIn("test count", result["identity_error"])

    def test_zero_matching_tests_cannot_pass_without_an_expected_count(self):
        with tempfile.TemporaryDirectory() as directory:
            args, _, _ = self.bound_fixture(directory, "print('Test run with 0 tests in 0 suites passed')")
            self.assertEqual(CI_PHASE.run_phase(args), 65)
            record = json.loads(Path(args.result).read_text())
            self.assertEqual(record["status"], "INVALIDATED")
            self.assertIn("no tests", record["identity_error"])

    def test_selected_run_requires_a_test_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            args, _, _ = self.bound_fixture(directory, "print('nothing ran')")
            inventory = Path(directory) / "selection.json"
            inventory.write_text('{"selected": ["Suite/test"]}')
            args.test_inventory = str(inventory)
            self.assertEqual(CI_PHASE.run_phase(args), 65)
            self.assertIn("no recognized test summary", json.loads(Path(args.result).read_text())["identity_error"])

    def test_framework_failure_cannot_be_hidden_by_successful_wrapper(self):
        for summary in ("Test run with 2 tests in 1 suite failed", "Ran 2 tests in 0.1s\n\nFAILED (failures=1)"):
            with self.subTest(summary=summary), tempfile.TemporaryDirectory() as directory:
                args, _, _ = self.bound_fixture(directory, "print(" + repr(summary) + ")")
                args.expected_test_count = 2
                self.assertEqual(CI_PHASE.run_phase(args), 65)
                result = json.loads(Path(args.result).read_text())
                self.assertEqual(result["status"], "INVALIDATED")
                self.assertEqual(result["command_exit_code"], 0)
                self.assertIn("framework reported failure", result["identity_error"])

    def test_evidence_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            args, _, _ = self.bound_fixture(directory, "print('done')")
            self.assertEqual(CI_PHASE.run_phase(args), 0)
            original = Path(args.result).read_bytes()
            with self.assertRaisesRegex(ValueError, "overwrite"):
                CI_PHASE.run_phase(args)
            self.assertEqual(Path(args.result).read_bytes(), original)

    def test_failed_phase_preserves_exit_code_and_stderr(self):
        with tempfile.TemporaryDirectory() as directory:
            run = subprocess.run(self.run_phase(directory,
                "import sys; print('ordinary error', file=sys.stderr); sys.exit(7)"), timeout=10)
            record = json.loads((Path(directory) / "phase.json").read_text())
            self.assertEqual(run.returncode, 7)
            self.assertEqual(record["status"], "FAILED")
            self.assertIn("ordinary error", (Path(directory) / "phase.log").read_text())

    def test_deadline_terminates_group_after_parent_exits(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "unexpected-completion"
            child = ("import signal,time,pathlib; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                     "time.sleep(2); pathlib.Path(" + repr(str(marker)) + ").touch()")
            code = ("import subprocess,sys,time; subprocess.Popen([sys.executable,'-c'," +
                    repr(child) + "]); print('started',flush=True); time.sleep(10)")
            run = subprocess.run(self.run_phase(directory, code, "0.5"), timeout=10)
            record = json.loads((Path(directory) / "phase.json").read_text())
            self.assertEqual(run.returncode, 124)
            self.assertEqual(record["status"], "TIMED_OUT")
            self.assertLess(record["elapsed_seconds"], 2)
            time.sleep(2)
            self.assertFalse(marker.exists())

    def test_successful_parent_exit_does_not_leave_descendants_or_publish_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "unexpected-completion"
            # Parent waits for a positive handshake, so this exercises a known
            # live TERM-ignoring descendant, not a scheduling-dependent guess.
            child = ("import signal,time,pathlib; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                     "print('ready',flush=True); time.sleep(2); pathlib.Path(" + repr(str(marker)) + ").touch()")
            code = ("import subprocess,sys; p=subprocess.Popen([sys.executable,'-c'," +
                    repr(child) + "],stdout=subprocess.PIPE); assert p.stdout.readline()==b'ready\\n'")
            run = subprocess.run(self.run_phase(directory, code), timeout=10)
            record = json.loads((Path(directory) / "phase.json").read_text())
            self.assertEqual(run.returncode, 70)
            self.assertEqual(record["status"], "DESCENDANTS_REMAIN")
            self.assertEqual(record["command_exit_code"], 0)
            self.assertTrue(record["descendants_after_exit"])
            self.assertNotIn("cleanup_error", record)
            time.sleep(2)
            self.assertFalse(marker.exists())

    def test_interruption_is_retained_and_not_a_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            process = subprocess.Popen(self.run_phase(directory,
                "import time; print('ready',flush=True); time.sleep(10)"))
            try:
                log = Path(directory) / "phase.log"
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if log.exists() and "ready" in log.read_text():
                        break
                    time.sleep(0.02)
                else:
                    self.fail("fixture did not start")
                os.kill(process.pid, signal.SIGTERM)
                self.assertEqual(process.wait(timeout=5), 143)
                record = json.loads((Path(directory) / "phase.json").read_text())
                self.assertEqual(record["status"], "INTERRUPTED")
                self.assertEqual(record["signal"], signal.SIGTERM)
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait()

    def test_denied_existence_probe_still_kills_term_ignoring_descendant(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "unexpected-completion"
            child = ("import signal,time,pathlib; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                     "time.sleep(2); pathlib.Path(" + repr(str(marker)) + ").touch()")
            code = ("import subprocess,sys,time; subprocess.Popen([sys.executable,'-c'," +
                    repr(child) + "]); time.sleep(10)")
            real_killpg = os.killpg
            signals = []

            def denied_probe(pid, sig):
                signals.append(sig)
                if sig == 0:
                    raise PermissionError(errno.EPERM, "fixture probe denied")
                return real_killpg(pid, sig)

            with mock.patch.object(CI_PHASE.os, "killpg", side_effect=denied_probe):
                code = CI_PHASE.run_phase(self.phase_args(directory, code))
            record = json.loads((Path(directory) / "phase.json").read_text())
            self.assertEqual(code, 124)
            self.assertEqual(record["status"], "TIMED_OUT")
            self.assertNotIn("cleanup_error", record)
            self.assertIn(0, signals)
            self.assertIn(signal.SIGKILL, signals)
            self.assertLess(record["elapsed_seconds"], 2)
            time.sleep(2)
            self.assertFalse(marker.exists())

    def test_actual_termination_denial_is_retained_as_cleanup_failure(self):
        cases = [(sig, interrupted) for sig in (signal.SIGTERM, signal.SIGKILL)
                 for interrupted in (False, True)]
        for denied_signal, interrupted in cases:
            with self.subTest(signal=denied_signal, interrupted=interrupted), \
                    tempfile.TemporaryDirectory() as directory:
                real_killpg = os.killpg
                real_popen = subprocess.Popen
                processes = []

                def track_process(*args, **kwargs):
                    process = real_popen(*args, **kwargs)
                    # Identity now invokes git too. Those subprocesses are
                    # not the phase, have no owned session, and must be reaped
                    # normally by subprocess.run rather than this fixture.
                    if not kwargs.get("start_new_session"):
                        return process
                    processes.append(process)
                    if interrupted:
                        # Deliver the installed handler deterministically after
                        # the live fixture has installed its TERM disposition.
                        log = Path(directory) / "phase.log"
                        deadline = time.monotonic() + 5
                        while time.monotonic() < deadline:
                            if "ready" in log.read_text():
                                break
                            time.sleep(0.02)
                        else:
                            self.fail("fixture did not start")
                        signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
                    return process

                def denied_termination(pid, sig):
                    if sig == denied_signal:
                        raise PermissionError(errno.EPERM, "fixture termination denied")
                    return real_killpg(pid, sig)

                code = ("import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                        "print('ready',flush=True); time.sleep(10)")
                try:
                    with mock.patch.object(CI_PHASE.subprocess, "Popen", side_effect=track_process), \
                            mock.patch.object(CI_PHASE.os, "killpg", side_effect=denied_termination):
                        result = CI_PHASE.run_phase(self.phase_args(directory, code))
                    record = json.loads((Path(directory) / "phase.json").read_text())
                    self.assertEqual(result, 143 if interrupted else 124)
                    self.assertEqual(record["status"], "INTERRUPTED" if interrupted else "TIMED_OUT")
                    if interrupted:
                        self.assertEqual(record["signal"], signal.SIGTERM)
                    self.assertEqual(record["cleanup_error"]["type"], "PermissionError")
                    self.assertEqual(record["cleanup_error"]["errno"], errno.EPERM)
                    log = (Path(directory) / "phase.log").read_text()
                    self.assertIn("cleanup failed", log)
                    self.assertNotIn("process group terminated", log)
                finally:
                    for process in processes:
                        try:
                            real_killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        process.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
