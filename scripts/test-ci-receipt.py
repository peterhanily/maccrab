#!/usr/bin/python3
"""Fixture tests for clean-CI receipts and the pre-push hook's reuse decision.

Every fixture is a disposable real-Git repository carrying copies of the real
hook and receipt helper, a logging stand-in for ci-local.sh, and a canned
toolchain checker. Nothing here builds, pushes, or touches the live repository.
"""
import datetime
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SCRIPTS = Path(__file__).resolve().parent
HELPER = SCRIPTS / "ci-receipt.py"
HOOK = SCRIPTS.parent / ".githooks" / "pre-push"
SPEC = importlib.util.spec_from_file_location("ci_receipt", HELPER)
RECEIPT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RECEIPT)

ZERO = "0" * 40
NOW = datetime.datetime(2026, 9, 28, 12, 0, 0, tzinfo=datetime.timezone.utc)
IDENTITY = {"schema_version": 1, "swift_banner": "Apple Swift version fixture",
            "xcode_version": "26.4.1", "xcode_build": "17E202"}
TOOLCHAIN_STUB = """import json, os, sys
if os.environ.get("FIXTURE_TOOLCHAIN_FAIL") == "1":
    sys.exit(1)
print(json.dumps({"result": "PASSED", "schema_version": 1,
                  "swift_banner": os.environ.get("FIXTURE_SWIFT", "Apple Swift version fixture"),
                  "xcode_version": "26.4.1", "xcode_build": "17E202"}, sort_keys=True))
"""
CI_STUB = '#!/bin/bash\nprintf "ci-local:%s\\n" "$*" >> "$FIXTURE_CI_LOG"\n'
# What release.sh exports for its tag push; the hook must not need real values
# to notice that no created or moved tag line came with them.
MANIFEST = {
    "MACCRAB_RELEASE_EXPECTED_DMG": ".build/MacCrab-v9.9.9.dmg",
    "MACCRAB_RELEASE_EXPECTED_SHA256": "a" * 64,
    "MACCRAB_RELEASE_EXPECTED_COMMIT": "b" * 40,
    "MACCRAB_RELEASE_EXPECTED_TAG_OBJECT": "c" * 40,
    "MACCRAB_RELEASE_EXPECTED_HOOK_BLOB": "d" * 40,
    "MACCRAB_RELEASE_SOURCE_COMMIT": "b" * 40,
    "MACCRAB_RELEASE_SOURCE_TREE": "e" * 40,
    "MACCRAB_RELEASE_METADATA_TREE": "e" * 40,
}


def same_identity(_repo):
    return dict(IDENTITY)


class Fixture:
    def __init__(self, root: Path):
        self.root = root
        self.repo = root / "repo"
        self.home = root / "home"
        self.ci_log = root / "ci.log"
        self.home.mkdir()
        (self.repo / ".githooks").mkdir(parents=True)
        (self.repo / "scripts").mkdir()
        shutil.copy2(HOOK, self.repo / ".githooks" / "pre-push")
        shutil.copy2(HELPER, self.repo / "scripts" / "ci-receipt.py")
        (self.repo / "scripts" / "ci-local.sh").write_text(CI_STUB)
        (self.repo / "scripts" / "ci-local.sh").chmod(0o755)
        (self.repo / "scripts" / "check-swift-toolchain.py").write_text(TOOLCHAIN_STUB)
        (self.repo / "source.txt").write_text("fixture\n")
        self.git("init", "-q")
        for key, value in (("user.name", "MacCrab receipt fixture"),
                           ("user.email", "receipt@invalid.example"),
                           ("commit.gpgSign", "false"), ("core.hooksPath", ".no-hooks")):
            self.git("config", key, value)
        self.git("add", ".")
        self.git("commit", "-q", "-m", "fixture root")

    def env(self, **extra):
        # A real tag push runs this suite with the release manifest exported;
        # these fixtures must not inherit it or the operator's Git settings.
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(("GIT_", "MACCRAB_RELEASE_"))}
        env.update(HOME=str(self.home), GIT_CONFIG_NOSYSTEM="1",
                   FIXTURE_CI_LOG=str(self.ci_log), **extra)
        return env

    def git(self, *args) -> str:
        return subprocess.run(["/usr/bin/git", *args], cwd=self.repo, env=self.env(),
                              check=True, capture_output=True, text=True).stdout.strip()

    def head(self):
        return self.git("rev-parse", "HEAD")

    def tree(self, commit="HEAD"):
        return self.git("rev-parse", commit + "^{tree}")

    def directory(self) -> Path:
        return self.repo / ".git" / RECEIPT.RECEIPT_DIR_NAME

    def receipt(self, commit="HEAD") -> Path:
        return self.directory() / f"{self.tree(commit)}.json"

    def record(self, now=NOW, identity=None) -> Path:
        state = RECEIPT.checkout_state(self.repo)
        return RECEIPT.write_receipt(self.repo, state, identity or dict(IDENTITY), now)

    def helper(self, *args, stdin="", **env):
        return subprocess.run([sys.executable, "-I", str(self.repo / "scripts" / "ci-receipt.py"),
                               *args], cwd=self.repo, env=self.env(**env), input=stdin,
                              capture_output=True, text=True, timeout=60)

    def hook(self, lines, **env):
        return subprocess.run(["/bin/bash", str(self.repo / ".githooks" / "pre-push"),
                               "origin", "fixture"], cwd=self.repo, env=self.env(**env),
                              input="".join(line + "\n" for line in lines),
                              capture_output=True, text=True, timeout=60)

    def ci_runs(self):
        return self.ci_log.read_text().splitlines() if self.ci_log.exists() else []


class FixtureCase(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        # Keep the operator's global Git configuration out of in-process calls.
        home = Path(temporary.name) / "home"
        patcher = mock.patch.dict(os.environ, {"HOME": str(home), "GIT_CONFIG_NOSYSTEM": "1"})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.fx = Fixture(Path(temporary.name))

    def reuse(self, lines, now=NOW + datetime.timedelta(minutes=5), probe=same_identity):
        return RECEIPT.reusable_receipts(self.fx.repo, "".join(l + "\n" for l in lines),
                                         now, toolchain_probe=probe)

    def branch(self, commit=None, ref="refs/heads/main"):
        return f"{ref} {commit or self.fx.head()} {ref} {ZERO}"

    def assertRefused(self, fragment, lines, **kwargs):
        with self.assertRaises(RECEIPT.Refused) as caught:
            self.reuse(lines, **kwargs)
        self.assertIn(fragment, str(caught.exception))

    def rewrite(self, mutate):
        path = self.fx.receipt()
        record = json.loads(path.read_text())
        mutate(record)
        path.write_text(json.dumps(record))
        path.chmod(0o600)


class RecordingTests(FixtureCase):
    def test_passing_clean_run_records_a_private_bound_receipt(self):
        log = self.fx.root / "toolchain.log"
        log.write_text(json.dumps({"result": "PASSED", **IDENTITY}) + "\n")
        start = self.fx.helper("snapshot")
        self.assertEqual(start.returncode, 0, start.stderr)
        written = self.fx.helper("write", "--start", start.stdout.strip(),
                                 "--toolchain-log", str(log))
        self.assertEqual(written.returncode, 0, written.stderr)
        self.assertIn(f"commit {self.fx.head()}", written.stdout)
        self.assertEqual(stat.S_IMODE(os.lstat(self.fx.directory()).st_mode), 0o700)
        receipt = self.fx.receipt()
        self.assertEqual(stat.S_IMODE(os.lstat(receipt).st_mode), 0o600)
        record = json.loads(receipt.read_text())
        self.assertEqual(record["commit"], self.fx.head())
        self.assertEqual(record["tree"], self.fx.tree())
        self.assertEqual((record["result"], record["mode"]), ("PASSED", "clean"))
        self.assertEqual(record["toolchain"], IDENTITY)
        for key, path in RECEIPT.GATE_BLOBS.items():
            self.assertEqual(record[key], self.fx.git("hash-object", "--no-filters", path))
        self.assertEqual(self.fx.git("status", "--porcelain", "--untracked-files=all"), "")

    def test_modified_untracked_or_staged_inputs_never_record(self):
        mutations = {
            "modified": lambda: (self.fx.repo / "source.txt").write_text("edited\n"),
            "untracked": lambda: (self.fx.repo / "new.swift").write_text("x\n"),
            "staged": lambda: ((self.fx.repo / "source.txt").write_text("staged\n"),
                               self.fx.git("add", "source.txt")),
        }
        for name, mutate in mutations.items():
            with self.subTest(name):
                self.fx.git("reset", "-q", "--hard")
                self.fx.git("clean", "-qfd")
                mutate()
                result = self.fx.helper("snapshot")
                self.assertEqual(result.returncode, 1)
                self.assertIn("No clean-CI receipt will be recorded", result.stderr)

    def test_hidden_index_edits_never_record(self):
        for flag in ("--assume-unchanged", "--skip-worktree"):
            with self.subTest(flag):
                self.fx.git("update-index", flag, "source.txt")
                (self.fx.repo / "source.txt").write_text("hidden edit\n")
                self.assertEqual(self.fx.git("status", "--porcelain"), "")
                with self.assertRaisesRegex(RECEIPT.Refused, "assume-unchanged/skip-worktree"):
                    RECEIPT.checkout_state(self.fx.repo)
                self.fx.git("update-index", flag.replace("--", "--no-"), "source.txt")
                self.fx.git("checkout", "-q", "--", "source.txt")

    def test_checkout_that_moved_during_the_run_is_not_recorded(self):
        start = RECEIPT.checkout_state(self.fx.repo)
        (self.fx.repo / "source.txt").write_text("committed mid-run\n")
        self.fx.git("commit", "-q", "-am", "mid-run")
        with self.assertRaisesRegex(RECEIPT.Refused, "changed while CI ran"):
            RECEIPT.write_receipt(self.fx.repo, start, dict(IDENTITY), NOW)
        self.assertFalse(self.fx.directory().exists())

    def test_unproven_toolchain_log_is_not_recorded(self):
        start = self.fx.helper("snapshot").stdout.strip()
        logs = {
            "failed": json.dumps({"result": "FAILED", **IDENTITY}),
            "partial": json.dumps({"result": "PASSED", "schema_version": 1}),
            "garbage": "ERROR: qualification toolchain: mismatch\n",
            "duplicate": '{"result": "PASSED", "result": "PASSED"}',
        }
        for name, text in logs.items():
            with self.subTest(name):
                log = self.fx.root / f"{name}.log"
                log.write_text(text)
                result = self.fx.helper("write", "--start", start, "--toolchain-log", str(log))
                self.assertEqual(result.returncode, 1)
                self.assertFalse(self.fx.receipt().exists())

    def test_preexisting_shared_receipt_directory_is_not_trusted(self):
        self.fx.directory().mkdir(mode=0o755)
        self.fx.directory().chmod(0o755)
        with self.assertRaisesRegex(RECEIPT.Refused, "mode 0755"):
            self.fx.record()
        self.assertFalse(self.fx.receipt().exists())


class ReuseDecisionTests(FixtureCase):
    def test_matching_receipt_is_reused(self):
        path = self.fx.record()
        reused = self.reuse([self.branch()])
        self.assertEqual([(ref, commit, receipt) for ref, commit, _tree, receipt, _ in reused],
                         [("refs/heads/main", self.fx.head(), path)])

    def test_tag_refs_and_deletion_only_pushes_never_reuse(self):
        self.fx.record()
        head = self.fx.head()
        self.assertRefused("tag", [f"refs/tags/v9.9.9 {head} refs/tags/v9.9.9 {ZERO}"])
        self.assertRefused("tag", [self.branch(), f"(delete) {ZERO} refs/tags/v9.9.9 {head}"])
        self.assertRefused("tag", [f"refs/tags/v9.9.9 {head} refs/heads/main {ZERO}"])
        self.assertRefused("no new commit", [f"(delete) {ZERO} refs/heads/old {head}"])
        self.assertRefused("no new commit", [])
        # A branch deletion riding along with a verified update is not a reason
        # to rerun, but the verified update still needs its receipt.
        self.assertEqual(len(self.reuse([self.branch(), f"(delete) {ZERO} refs/heads/old {head}"])), 1)

    def test_every_pushed_commit_needs_its_own_receipt(self):
        self.fx.record()
        verified = self.fx.head()
        (self.fx.repo / "source.txt").write_text("unverified\n")
        self.fx.git("commit", "-q", "-am", "unverified")
        self.assertRefused("no receipt", [self.branch(verified), self.branch(ref="refs/heads/dev")])

    def test_same_tree_under_a_different_commit_is_not_reused(self):
        self.fx.record()
        self.fx.git("commit", "-q", "--allow-empty", "-m", "message the secret scan never saw")
        self.assertRefused("recorded for commit", [self.branch()])

    def test_changed_gate_is_not_reused(self):
        for path in RECEIPT.GATE_BLOBS.values():
            with self.subTest(path):
                self.fx.record()
                gate = self.fx.repo / path
                original = gate.read_bytes()
                gate.write_bytes(original + b"\n# changed after the receipt\n")
                try:
                    self.assertRefused(f"{path} has changed", [self.branch()])
                finally:
                    gate.write_bytes(original)

    def test_changed_or_unprovable_toolchain_is_not_reused(self):
        self.fx.record()
        other = dict(IDENTITY, xcode_build="17E999")
        self.assertRefused("toolchain has changed", [self.branch()], probe=lambda _repo: other)

        def failing(_repo):
            raise RECEIPT.Refused("installed toolchain does not pass")
        self.assertRefused("does not pass", [self.branch()], probe=failing)

    def test_receipt_older_than_six_hours_or_from_the_future_is_not_reused(self):
        self.fx.record()
        self.assertEqual(len(self.reuse([self.branch()],
                                        now=NOW + datetime.timedelta(hours=5, minutes=59))), 1)
        self.assertRefused("older than 6 hours", [self.branch()],
                           now=NOW + datetime.timedelta(hours=6, seconds=1))
        self.assertRefused("in the future", [self.branch()],
                           now=NOW - datetime.timedelta(minutes=1))

    def test_tampered_receipt_contents_are_not_reused(self):
        tampering = {
            "failed result": lambda r: r.update(result="FAILED"),
            "warm mode": lambda r: r.update(mode="warm"),
            "string schema": lambda r: r.update(schema_version="1"),
            "extra field": lambda r: r.update(bypass=True),
            "missing field": lambda r: r.pop("pre_push_blob"),
            "other tree": lambda r: r.update(tree="f" * 40),
            "bad time": lambda r: r.update(completed_at="yesterday"),
        }
        for name, mutate in tampering.items():
            with self.subTest(name):
                self.fx.record()
                self.rewrite(mutate)
                with self.assertRaises(RECEIPT.Refused):
                    self.reuse([self.branch()])
        self.fx.record()
        self.fx.receipt().write_text('{"result": "PASSED", "result": "PASSED"}')
        self.assertRefused("duplicate", [self.branch()])
        self.fx.receipt().write_text("{not json")
        self.assertRefused("malformed JSON", [self.branch()])
        self.fx.receipt().write_text(" " * (RECEIPT.MAX_RECEIPT_BYTES + 1))
        self.assertRefused("implausibly large", [self.branch()])

    def test_unsafe_receipt_files_are_not_reused(self):
        path = self.fx.record()
        path.chmod(0o644)
        self.assertRefused("mode 0644", [self.branch()])
        path.chmod(0o600)

        self.fx.directory().chmod(0o755)
        self.assertRefused("mode 0755", [self.branch()])
        self.fx.directory().chmod(0o700)

        link = self.fx.root / "hard-link.json"
        os.link(path, link)
        self.assertRefused("hard links", [self.branch()])
        link.unlink()

        with mock.patch.object(RECEIPT.os, "getuid", return_value=os.getuid() + 1):
            self.assertRefused("not owned by the current user", [self.branch()])

        elsewhere = self.fx.root / "elsewhere.json"
        path.rename(elsewhere)
        path.symlink_to(elsewhere)
        self.assertRefused("cannot be opened safely", [self.branch()])
        path.unlink()

        os.mkfifo(path, 0o600)
        self.assertRefused("wrong file type", [self.branch()])
        path.unlink()

        elsewhere.rename(path)
        moved = self.fx.root / "moved-receipts"
        self.fx.directory().rename(moved)
        self.fx.directory().symlink_to(moved)
        self.assertRefused("wrong file type", [self.branch()])


class HookTests(FixtureCase):
    def record_through_cli(self):
        log = self.fx.root / "toolchain.log"
        log.write_text(json.dumps({"result": "PASSED", **IDENTITY}) + "\n")
        start = self.fx.helper("snapshot").stdout.strip()
        written = self.fx.helper("write", "--start", start, "--toolchain-log", str(log))
        self.assertEqual(written.returncode, 0, written.stderr)

    def test_branch_push_with_valid_receipt_skips_ci_and_names_the_receipt(self):
        self.record_through_cli()
        result = self.fx.hook([self.branch()])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.fx.ci_runs(), [])
        printed = [line.split(":", 1)[1].strip() for line in result.stdout.splitlines()
                   if line.startswith("  receipt:")]
        self.assertEqual([Path(path).resolve() for path in printed], [self.fx.receipt().resolve()])
        self.assertIn(f"commit:    {self.fx.head()}", result.stdout)
        self.assertIn("Skipping local CI", result.stdout)

    def test_branch_push_without_a_valid_receipt_runs_warm_ci(self):
        result = self.fx.hook([self.branch()])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.fx.ci_runs(), ["ci-local:"])
        self.assertIn("Local CI receipt not reused", result.stderr)

        self.record_through_cli()
        result = self.fx.hook([self.branch()], FIXTURE_SWIFT="Apple Swift version other")
        self.assertIn("toolchain has changed", result.stderr)
        self.assertEqual(self.fx.ci_runs(), ["ci-local:", "ci-local:"])

    def test_push_with_any_tag_ref_runs_clean_ci_despite_a_receipt(self):
        self.record_through_cli()
        head = self.fx.head()
        result = self.fx.hook([self.branch(), f"(delete) {ZERO} refs/tags/v9.9.9 {head}"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.fx.ci_runs(), ["ci-local:--clean"])

    def test_deletion_only_push_runs_ci_as_before(self):
        self.record_through_cli()
        result = self.fx.hook([f"(delete) {ZERO} refs/heads/old {self.fx.head()}"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.fx.ci_runs(), ["ci-local:"])

    def test_broken_helper_runs_ci(self):
        self.record_through_cli()
        (self.fx.repo / "scripts" / "ci-receipt.py").write_text("raise RuntimeError('broken')\n")
        result = self.fx.hook([self.branch()])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.fx.ci_runs(), ["ci-local:"])

    def test_push_with_no_ref_to_update_skips_ci(self):
        result = self.fx.hook([])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("nothing to gate", result.stdout)
        self.assertEqual(self.fx.ci_runs(), [])

    def test_release_manifest_without_a_created_tag_fails_before_ci(self):
        pushes = {
            "no ref at all": [],
            "branch only": [self.branch()],
            "tag deletion": [f"(delete) {ZERO} refs/tags/v9.9.9 {self.fx.head()}"],
        }
        for variable, value in MANIFEST.items():
            for name, lines in pushes.items():
                with self.subTest(variable=variable, push=name):
                    result = self.fx.hook(lines, **{variable: value})
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn("no created/moved version tag was pushed", result.stderr)
                    self.assertEqual(self.fx.ci_runs(), [])


class RealPushTests(FixtureCase):
    """git itself drives the hook while pushing to a disposable local bare remote."""

    def setUp(self):
        super().setUp()
        self.remote = self.fx.root / "remote.git"
        self.run_git(self.fx.root, "init", "-q", "--bare", str(self.remote))
        self.fx.git("remote", "add", "origin", str(self.remote))
        self.fx.git("push", "-q", "origin", "HEAD:refs/heads/main")
        # Another clone moves main on. Fetching it makes this checkout's own
        # commit a known non-fast-forward, which git leaves out of the hook's
        # stdin; a remote commit missing locally ("fetch first") is still sent.
        other = self.fx.root / "other"
        self.run_git(self.fx.root, "clone", "-q", "-b", "main", str(self.remote), str(other))
        (other / "source.txt").write_text("moved on elsewhere\n")
        self.run_git(other, "commit", "-q", "-am", "elsewhere")
        self.run_git(other, "push", "-q", "origin", "HEAD:refs/heads/main")
        (self.fx.repo / "source.txt").write_text("diverged here\n")
        self.fx.git("commit", "-q", "-am", "diverged")
        self.fx.git("fetch", "-q", "origin")

    def run_git(self, cwd, *args):
        return subprocess.run(["/usr/bin/git", "-c", "user.name=MacCrab receipt fixture",
                               "-c", "user.email=receipt@invalid.example",
                               "-c", "commit.gpgSign=false", "-c", "core.hooksPath=.no-hooks",
                               *args], cwd=cwd, env=self.fx.env(), check=True,
                              capture_output=True, text=True)

    def push(self, *args, **env):
        result = subprocess.run(["/usr/bin/git", "-c", "core.hooksPath=.githooks", "push", *args],
                                cwd=self.fx.repo, env=self.fx.env(**env),
                                capture_output=True, text=True, timeout=60)
        return result, result.stdout + result.stderr

    def replaced_tag_with_stale_lease(self, **env):
        """A --respin-shaped tag push whose lease no longer matches the remote."""
        self.fx.git("tag", "-a", "v9.9.9", "-m", "published elsewhere", "origin/main")
        self.fx.git("push", "-q", "origin", "refs/tags/v9.9.9")
        self.fx.git("tag", "-d", "v9.9.9")
        self.fx.git("tag", "-a", "v9.9.9", "-m", "replacement")
        return self.push("--force-with-lease=refs/tags/v9.9.9:", "origin", "refs/tags/v9.9.9", **env)

    def test_non_fast_forward_branch_push_leaves_the_rejection_to_git(self):
        result, output = self.push("origin", "HEAD:refs/heads/main")
        self.assertNotEqual(result.returncode, 0, output)
        self.assertIn("(non-fast-forward)", output)
        self.assertIn("nothing to gate", output)
        self.assertEqual(self.fx.ci_runs(), [])

    def test_up_to_date_push_skips_ci(self):
        result, output = self.push("origin", "refs/remotes/origin/main:refs/heads/main")
        self.assertEqual(result.returncode, 0, output)
        self.assertIn("Everything up-to-date", output)
        self.assertEqual(self.fx.ci_runs(), [])

    def test_stale_lease_tag_push_leaves_the_rejection_to_git(self):
        result, output = self.replaced_tag_with_stale_lease()
        self.assertNotEqual(result.returncode, 0, output)
        self.assertIn("(stale info)", output)
        self.assertIn("nothing to gate", output)
        self.assertEqual(self.fx.ci_runs(), [])

    def test_stale_lease_release_tag_push_fails_fast_without_ci(self):
        result, output = self.replaced_tag_with_stale_lease(**MANIFEST)
        self.assertNotEqual(result.returncode, 0, output)
        self.assertIn("no created/moved version tag was pushed", output)
        self.assertEqual(self.fx.ci_runs(), [])
        self.assertNotEqual(self.fx.git("ls-remote", "origin", "refs/tags/v9.9.9").split()[0],
                            self.fx.git("rev-parse", "refs/tags/v9.9.9"))


if __name__ == "__main__":
    unittest.main()
