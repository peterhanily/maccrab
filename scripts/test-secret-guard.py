#!/usr/bin/env python3
"""Local-only controls for the unpublished-history privacy guard."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().with_name("check-secrets.sh")

class SecretGuardTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="maccrab-secret-guard-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.env = {"HOME": os.environ["HOME"], "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                    "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"}
        (self.root / "scripts").mkdir()
        shutil.copy2(SCRIPT, self.root / "scripts/check-secrets.sh")
        self.git("init", "-q")
        self.git("config", "user.name", "Privacy guard fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "core.hooksPath", "/dev/null")
        self.commit("Initial fixture")
        self.base = self.git("rev-parse", "HEAD").strip()

    def git(self, *args):
        return subprocess.check_output(["/usr/bin/git", *args], cwd=self.root,
                                       env=self.env, stderr=subprocess.DEVNULL).decode()

    def commit(self, message):
        self.git("add", "-A")
        self.git("commit", "-qm", message)

    def check(self, *args):
        return subprocess.run(["/bin/bash", "scripts/check-secrets.sh", *(args or (self.base,))],
                              cwd=self.root, env=self.env, capture_output=True, text=True, timeout=30)

    def test_safe_diff_and_documented_canary(self):
        (self.root / "fixture.txt").write_text("ghp_" + "A" * 36 + " # secret-scan:allow explicit fake fixture\n")
        self.commit("Documented fixture")
        self.assertEqual(self.check().returncode, 0)

    def test_added_then_removed_credential_is_not_hidden(self):
        token = "ghp_" + "B" * 36
        path = self.root / "fixture.txt"
        path.write_text(token + "\n")
        self.commit("Add fake token")
        path.write_text("Removed\n")
        self.commit("Remove fake token")
        result = self.check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("fixture.txt", result.stderr)
        self.assertNotIn(token, result.stdout + result.stderr)

    def test_fine_grained_token_is_detected_without_output(self):
        token = "github_pat_" + "C" * 50
        (self.root / "fixture.txt").write_text(token + "\n")
        self.commit("Fake fine-grained token")
        result = self.check()
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(token, result.stdout + result.stderr)

    def test_private_baseline_removal_does_not_clean_history(self):
        path = self.root / "docs/RELEASE_RESOURCE_BASELINE.json"
        path.parent.mkdir()
        path.write_text('{"host":{"machine_id_sha256":"synthetic-not-a-host"}}\n')
        self.commit("Add synthetic private baseline")
        path.write_text('{"status":"awaiting-reference-measurement","measurements":null}\n')
        self.commit("Replace baseline")
        result = self.check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("private host telemetry", result.stderr)
        self.assertNotIn("synthetic-not-a-host", result.stdout + result.stderr)
        self.assertEqual(self.check("--tree").returncode, 0)

    def test_public_summary_has_no_private_fields(self):
        path = self.root / "docs/RELEASE_RESOURCE_BASELINE.json"
        path.parent.mkdir()
        path.write_text('{"status":"accepted","measurements":{"write_rate":1},"limits":{"write_rate":2}}\n')
        self.commit("Public aggregate summary")
        self.assertEqual(self.check().returncode, 0)

    def test_tree_mode_checks_uncommitted_private_policy(self):
        path = self.root / "docs/RELEASE_RESOURCE_BASELINE.json"
        path.parent.mkdir()
        path.write_text('{"status":"awaiting-reference-measurement"}\n')
        self.commit("Safe policy")
        path.write_text('{"host":{"machine_id_sha256":"synthetic-not-a-host"}}\n')
        self.assertEqual(self.check("--tree").returncode, 1)

    def test_missing_base_fails_closed(self):
        self.assertEqual(self.check("missing-reference-fixture").returncode, 2)

    def test_invalid_utf8_history_is_scanned_without_echoing_raw_content(self):
        self.env.update(LC_ALL="en_US.UTF-8", LANG="en_US.UTF-8")
        marker = b"PRIVATE_HISTORY_FIXTURE_DO_NOT_ECHO"
        path = self.root / "invalid-text.txt"
        path.write_bytes(b"\xff\xfe" + marker + b"\n")
        self.commit("Add non-UTF-8 text fixture")
        for with_token in (False, True):
            with self.subTest(with_token=with_token):
                token = ("ghp_" + "E" * 36).encode()
                if with_token:
                    path.write_bytes(b"\xff\xfe" + marker + b" " + token + b"\n")
                    self.commit("Add fake token beside non-UTF-8 bytes")
                result = subprocess.run(["/bin/bash", "scripts/check-secrets.sh", self.base],
                                        cwd=self.root, env=self.env, capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 1 if with_token else 0)
                output = result.stdout + result.stderr
                self.assertNotIn(marker, output)
                self.assertNotIn(token, output)
                self.assertNotIn(b"\xff", output)
                self.assertNotIn(b"\xfe", output)

    def test_historical_fixture_allowance_is_exact_line_and_path_only(self):
        approved = "Tests/MacCrabCoreTests/AlertTriggerRepresentationTests.swift"
        lines = (
            b'        let secret = "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ123456"',  # secret-scan:allow exact historical alphabet fixture
            b'        let secret = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890"',  # secret-scan:allow exact historical alphabet fixture
        )
        for original in lines:
            changed_token = original.replace(b"abcdefghijklmnopqrstuvwxyz", b"zbcdefghijklmnopqrstuvwxyz")
            self.assertNotEqual(changed_token, original)
            for name, relative, content, expected_status in (
                ("exact", approved, original, 0),
                ("changed token", approved, changed_token, 1),
                ("changed line", approved, b" " + original, 1),
                ("changed path", "other-fixture.swift", original, 1),
            ):
                with self.subTest(case=name):
                    self.base = self.git("rev-parse", "HEAD").strip()
                    path = self.root / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(content + b"\n")
                    self.commit("Exact historical fixture control")
                    result = self.check()
                    self.assertEqual(result.returncode, expected_status)
                    self.assertNotIn(content.decode(), result.stdout + result.stderr)

    def install_git_fault(self, predicate):
        fake = self.root / "fake-tools"
        fake.mkdir(exist_ok=True)
        wrapper = fake / "git"
        wrapper.write_text("#!/bin/bash\nif " + predicate + "; then exit 7; fi\nexec /usr/bin/git \"$@\"\n")
        wrapper.chmod(0o755)
        self.env["PATH"] = str(fake) + ":/usr/bin:/bin:/usr/sbin:/sbin"
        # Fault injection is confined to this disposable scanner copy. No real
        # repository or production Git executable is altered.
        source = SCRIPT.read_text().replace('"/usr/bin/git"', repr(str(wrapper)))
        (self.root / "scripts/check-secrets.sh").write_text(source)

    def test_git_failures_never_return_clean(self):
        policy = self.root / "docs/RELEASE_RESOURCE_BASELINE.json"
        policy.parent.mkdir()
        policy.write_text('{"status":"accepted"}\n')
        self.commit("Safe policy")
        for label, predicate, args in (
            ("tree inventory", '[[ "$1" == ls-files && "$2" == -z ]]', ("--tree",)),
            ("ignored inventory", '[[ "$1" == ls-files && "$2" == --cached ]]', ()),
            ("diff history", '[[ "$1" == log ]]', ()),
            ("policy history", '[[ "$1" == rev-list ]]', ()),
            ("policy blob", '[[ "$1" == cat-file ]]', ()),
        ):
            with self.subTest(label=label):
                self.install_git_fault(predicate)
                result = self.check(*args)
                self.assertEqual(result.returncode, 2)
                self.assertNotIn("check-secrets: clean", result.stdout)

    def test_grep_read_error_is_not_a_no_match(self):
        fake = self.root / "fake-tools"
        fake.mkdir()
        wrapper = fake / "grep"
        wrapper.write_text("#!/bin/bash\nexit 2\n")
        wrapper.chmod(0o755)
        self.env["PATH"] = str(fake) + ":/usr/bin:/bin:/usr/sbin:/sbin"
        self.assertEqual(self.check().returncode, 2)

    def test_history_command_errors_do_not_echo_private_stderr(self):
        marker = "PRIVATE_HISTORY_ERROR_DO_NOT_ECHO"
        for stage in ("git", "awk"):
            with self.subTest(stage=stage):
                if stage == "git":
                    self.install_git_fault('[[ "$1" == log ]]')
                    wrapper = self.root / "fake-tools/git"
                    source = wrapper.read_text().replace("then exit 7;", 'then printf "' + marker + '\\n" >&2; exit 7;')
                    wrapper.write_text(source)
                else:
                    wrapper = self.root / "fake-tools/awk"
                    wrapper.write_text('#!/bin/bash\nprintf "' + marker + '\\n" >&2\nexit 2\n')
                    wrapper.chmod(0o755)
                    source = SCRIPT.read_text().replace("| /usr/bin/awk ", "| " + str(wrapper) + " ")
                    (self.root / "scripts/check-secrets.sh").write_text(source)
                    self.env["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"
                result = self.check()
                self.assertEqual(result.returncode, 2)
                self.assertIn("cannot read the complete unpublished history", result.stderr)
                self.assertNotIn(marker, result.stdout + result.stderr)

    def test_tree_read_failure_is_not_silently_skipped(self):
        path = self.root / "tracked.txt"
        path.write_text("ordinary text\n")
        self.commit("Track ordinary input")
        path.unlink()
        result = self.check("--tree")
        self.assertEqual(result.returncode, 2)
        self.assertIn("complete tracked text inventory", result.stderr)

    def test_merged_side_branch_private_policy_is_not_hidden(self):
        path = self.root / "docs/RELEASE_RESOURCE_BASELINE.json"
        path.parent.mkdir()
        safe = '{"status":"accepted","measurements":{"rate":1}}\n'
        path.write_text(safe)
        self.commit("Safe policy")
        self.base = self.git("rev-parse", "HEAD").strip()
        main = self.git("branch", "--show-current").strip()
        self.git("checkout", "-qb", "side")
        path.write_text('{"host":{"machine_id_sha256":"synthetic-private-host"}}\n')
        self.commit("Add synthetic private host")
        path.write_text(safe)
        self.commit("Remove synthetic private host")
        self.git("checkout", "-q", main)
        (self.root / "main.txt").write_text("ordinary change\n")
        self.commit("Main progress")
        self.git("merge", "--no-ff", "-qm", "Merge cleaned side", "side")
        result = self.check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("private host telemetry", result.stderr)
        self.assertNotIn("synthetic-private-host", result.stdout + result.stderr)

    def test_ambiguous_or_nonfinite_policy_json_is_rejected(self):
        path = self.root / "docs/RELEASE_RESOURCE_BASELINE.json"
        path.parent.mkdir()
        for content in (
            '{"measurements":{"host":"synthetic-private-host"},"measurements":{"rate":1}}',
            '{"measurements":{"rate":NaN}}',
            '{"measurements":{"rate":1e400}}',
        ):
            with self.subTest(content_kind="invalid JSON semantics"):
                path.write_text(content + "\n")
                self.commit("Ambiguous or nonfinite fixture")
                result = self.check()
                self.assertEqual(result.returncode, 1)
                self.assertIn("invalid public reference policy", result.stderr)
                self.assertNotIn("synthetic-private-host", result.stdout + result.stderr)

    def test_tree_symlink_target_is_literal_and_never_followed(self):
        with tempfile.TemporaryDirectory(prefix="maccrab-external-fixture-") as directory:
            target = Path(directory) / "external.txt"
            token = "ghp_" + "D" * 36
            target.write_text(token + "\n")
            link = self.root / "fixture-link"
            link.symlink_to(target)
            self.commit("Track harmless external link literal")
            self.assertEqual(self.check("--tree").returncode, 0)
            link.unlink()
            link.symlink_to(token)
            result = self.check("--tree")
            self.assertEqual(result.returncode, 1)
            self.assertNotIn(token, result.stdout + result.stderr)

if __name__ == "__main__":
    unittest.main()
