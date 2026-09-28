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


class PhaseTests(unittest.TestCase):
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
