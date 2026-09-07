#!/usr/bin/python3
"""Ordinary process lifecycle tests for bounded CI phase execution."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

RUNNER = Path(__file__).with_name("run-ci-phase.py")


class PhaseTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
