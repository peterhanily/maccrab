#!/usr/bin/python3
"""Record, and later reuse, a passing clean local-CI run for one exact commit.

A release used to run the full suite three times: release.sh's clean CI, the
tag push's clean CI, and the branch push's warm CI. The branch push sends the
very commit the tag push has just verified from scratch, so that third run
(~30 minutes during v1.22.2) proved nothing new. A passing `ci-local.sh --clean`
over an unmodified checkout records a receipt here, and the pre-push hook may
skip CI for a tag-free push only when every pushed commit has a receipt that
still matches the gate that would run now.

This caches a verdict; it must never become a way around one. Every mismatch,
unreadable file, unexpected field or failed probe answers "run CI".

  ci-receipt.py snapshot                 print the checkout identity, or refuse
  ci-receipt.py write --start JSON --toolchain-log PATH
  ci-receipt.py check < pre-push-stdin   exit 0 only when CI may be skipped
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


GIT = "/usr/bin/git"
PYTHON = "/usr/bin/python3"
RECEIPT_DIR_NAME = "maccrab-ci-receipts"
SCHEMA_VERSION = 1
MAX_AGE = datetime.timedelta(hours=6)
MAX_RECEIPT_BYTES = 64 * 1024
TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
# A receipt vouches only for the gate that produced it. If the hook, the CI
# script, or this decision logic has changed since, the verdict is not reusable.
GATE_BLOBS = {
    "ci_local_blob": "scripts/ci-local.sh",
    "pre_push_blob": ".githooks/pre-push",
    "receipt_helper_blob": "scripts/ci-receipt.py",
}
REQUIRED_TOOLCHAIN_FIELDS = ("swift_banner", "xcode_version", "xcode_build")
RECEIPT_KEYS = {"schema_version", "result", "mode", "commit", "tree", "toolchain",
                "completed_at", *GATE_BLOBS}
OBJECT_ID = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


class Refused(Exception):
    """The receipt cannot be recorded or reused; the caller runs full CI."""


def git(repo, *args) -> str:
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith("GIT_")}
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    result = subprocess.run([GIT, *args], cwd=repo, env=environment,
                            capture_output=True, text=True, errors="replace",
                            timeout=120)
    if result.returncode != 0:
        raise Refused(f"git {args[0]} failed: {result.stderr.strip() or result.returncode}")
    return result.stdout


def object_id(value, what: str) -> str:
    if not isinstance(value, str) or not OBJECT_ID.fullmatch(value):
        raise Refused(f"{what} is not a Git object ID")
    return value


def strict_json(text: str):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise Refused(f"duplicate JSON key {key!r}")
            result[key] = value
        return result
    try:
        return json.loads(text, object_pairs_hook=unique)
    except ValueError as error:
        raise Refused(f"malformed JSON: {error}") from None


def gate_blobs(repo) -> dict:
    blobs = {}
    for key, path in GATE_BLOBS.items():
        full = Path(repo, path)
        if full.is_symlink() or not full.is_file():
            raise Refused(f"{path} is missing, redirected, or not a regular file")
        blobs[key] = object_id(git(repo, "hash-object", "--no-filters", "--", path).strip(), path)
    return blobs


def checkout_state(repo) -> dict:
    """HEAD's commit and tree plus the gate blobs, only if the checkout IS HEAD.

    A clean run over uncommitted or untracked inputs tested something other
    than HEAD's tree, so it must not vouch for HEAD. `git status` alone hides
    assume-unchanged/skip-worktree edits; mirror the release gate's checks.
    """
    hidden = [line for line in git(repo, "ls-files", "-v").splitlines()
              if line[:1] == "S" or "a" <= line[:1] <= "z"]
    if hidden:
        raise Refused("the index hides worktree changes (assume-unchanged/skip-worktree)")
    try:
        git(repo, "update-index", "--really-refresh")
        git(repo, "diff-files", "--quiet", "--")
        git(repo, "diff-index", "--cached", "--quiet", "HEAD", "--")
    except Refused:
        raise Refused("the worktree or index differs from HEAD") from None
    if git(repo, "status", "--porcelain", "--untracked-files=all"):
        raise Refused("the checkout has uncommitted or untracked files")
    commit = object_id(git(repo, "rev-parse", "--verify", "HEAD^{commit}").strip(), "HEAD")
    tree = object_id(git(repo, "rev-parse", "--verify", commit + "^{tree}").strip(), "HEAD tree")
    return {"commit": commit, "tree": tree, **gate_blobs(repo)}


def toolchain_identity(text: str) -> dict:
    """The identity check-swift-toolchain.py prints after a passing check."""
    record = strict_json(text)
    if not isinstance(record, dict) or record.get("result") != "PASSED":
        raise Refused("toolchain identity is not a passing check-swift-toolchain.py record")
    identity = {key: value for key, value in record.items() if key != "result"}
    for key in REQUIRED_TOOLCHAIN_FIELDS:
        if not isinstance(identity.get(key), str) or not identity[key]:
            raise Refused(f"toolchain identity lacks {key}")
    return identity


def current_toolchain(repo) -> dict:
    checker = Path(repo, "scripts/check-swift-toolchain.py")
    result = subprocess.run([PYTHON, "-I", str(checker)], cwd=repo, capture_output=True,
                            text=True, errors="replace", timeout=120)
    if result.returncode != 0:
        raise Refused("the installed Swift toolchain does not pass check-swift-toolchain.py")
    return toolchain_identity(result.stdout)


def receipt_directory(repo) -> Path:
    common = git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir").strip()
    if not common:
        raise Refused("cannot locate the Git common directory")
    return Path(common, RECEIPT_DIR_NAME)


def require_private(info, is_kind, mode: int, what) -> None:
    if not is_kind(info.st_mode):
        raise Refused(f"{what} is a symlink or the wrong file type")
    if info.st_uid != os.getuid():
        raise Refused(f"{what} is not owned by the current user")
    if stat.S_IMODE(info.st_mode) != mode:
        raise Refused(f"{what} has mode {stat.S_IMODE(info.st_mode):04o}, expected {mode:04o}")


def private_directory(directory: Path, create: bool) -> None:
    if create:
        try:
            os.mkdir(directory, 0o700)
        except FileExistsError:
            pass
        else:
            os.chmod(directory, 0o700)
    try:
        info = os.lstat(directory)
    except FileNotFoundError:
        raise Refused("no clean-CI receipt has been recorded in this repository") from None
    require_private(info, stat.S_ISDIR, 0o700, directory)


def write_receipt(repo, start: dict, toolchain: dict, now: datetime.datetime) -> Path:
    end = checkout_state(repo)
    if end != start:
        raise Refused("the checkout changed while CI ran")
    directory = receipt_directory(repo)
    private_directory(directory, create=True)
    record = {"schema_version": SCHEMA_VERSION, "result": "PASSED", "mode": "clean",
              **end, "toolchain": toolchain, "completed_at": now.strftime(TIME_FORMAT)}
    data = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode()
    final = directory / f"{end['tree']}.json"
    temporary = directory / f".{end['tree']}.{os.getpid()}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                         | os.O_CLOEXEC, 0o600)
    try:
        try:
            os.fchmod(descriptor, 0o600)
            view = memoryview(data)
            while view:
                view = view[os.write(descriptor, view):]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, final)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
    return final


def read_receipt(path: Path) -> dict:
    try:
        # NOFOLLOW refuses a symlinked receipt; NONBLOCK keeps a FIFO from
        # hanging the push before fstat rejects it.
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        raise Refused(f"no receipt at {path}") from None
    except OSError as error:
        raise Refused(f"receipt {path} cannot be opened safely: {error.strerror}") from None
    try:
        info = os.fstat(descriptor)
        require_private(info, stat.S_ISREG, 0o600, path)
        if info.st_nlink != 1:
            raise Refused(f"receipt {path} has additional hard links")
        if info.st_size > MAX_RECEIPT_BYTES:
            raise Refused(f"receipt {path} is implausibly large")
        data = os.read(descriptor, MAX_RECEIPT_BYTES + 1)
    finally:
        os.close(descriptor)
    try:
        return strict_json(data.decode("utf-8"))
    except UnicodeDecodeError:
        raise Refused(f"receipt {path} is not UTF-8") from None


def validate_receipt(record, *, commit: str, tree: str, blobs: dict, toolchain: dict,
                     now: datetime.datetime) -> datetime.datetime:
    if not isinstance(record, dict) or set(record) != RECEIPT_KEYS:
        raise Refused("receipt fields are incomplete or unknown")
    if type(record["schema_version"]) is not int or record["schema_version"] != SCHEMA_VERSION:
        raise Refused("unsupported receipt schema")
    if record["result"] != "PASSED" or record["mode"] != "clean":
        raise Refused("receipt does not record a passing clean run")
    if record["tree"] != tree:
        raise Refused(f"receipt names tree {record['tree']!r}, not {tree}")
    # Same tree is not enough: ci-local's secret scan covers commit messages
    # and every unpublished commit, which only the commit ID pins down.
    if record["commit"] != commit:
        raise Refused(f"receipt was recorded for commit {record['commit']!r}, not {commit}")
    for key, path in GATE_BLOBS.items():
        if record[key] != blobs[key]:
            raise Refused(f"{path} has changed since the receipt was recorded")
    if record["toolchain"] != toolchain:
        raise Refused("the Swift toolchain has changed since the receipt was recorded")
    try:
        completed = datetime.datetime.strptime(record["completed_at"], TIME_FORMAT).replace(
            tzinfo=datetime.timezone.utc)
    except (TypeError, ValueError):
        raise Refused("receipt completion time is malformed") from None
    age = now - completed
    if age < datetime.timedelta(0):
        raise Refused("receipt completion time is in the future")
    if age > MAX_AGE:
        raise Refused(f"receipt is older than {MAX_AGE.total_seconds() / 3600:g} hours")
    return completed


def pushed_commits(text: str) -> list:
    """(remote ref, new commit) for every non-deletion line of pre-push stdin."""
    pushed = []
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) != 4:
            raise Refused("unrecognised pre-push input")
        local_ref, local_sha, remote_ref, _remote_sha = fields
        if local_ref.startswith("refs/tags/") or remote_ref.startswith("refs/tags/"):
            raise Refused("the push contains a tag ref; tags always run clean CI")
        object_id(local_sha, "pushed object")
        if set(local_sha) == {"0"}:
            continue
        pushed.append((remote_ref, local_sha))
    if not pushed:
        raise Refused("the push carries no new commit")
    return pushed


def reusable_receipts(repo, push_text: str, now: datetime.datetime,
                      toolchain_probe=current_toolchain) -> list:
    pushed = pushed_commits(push_text)
    directory = receipt_directory(repo)
    private_directory(directory, create=False)
    blobs = gate_blobs(repo)
    toolchain = toolchain_probe(repo)
    reused = []
    for remote_ref, commit in pushed:
        if git(repo, "cat-file", "-t", commit).strip() != "commit":
            raise Refused(f"{remote_ref} does not point at a commit")
        tree = object_id(git(repo, "rev-parse", "--verify", commit + "^{tree}").strip(),
                         f"{remote_ref} tree")
        path = directory / f"{tree}.json"
        record = read_receipt(path)
        completed = validate_receipt(record, commit=commit, tree=tree, blobs=blobs,
                                     toolchain=toolchain, now=now)
        reused.append((remote_ref, commit, tree, path, completed))
    return reused


def main(argv) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("snapshot")
    write = commands.add_parser("write")
    write.add_argument("--start", required=True)
    write.add_argument("--toolchain-log", required=True)
    commands.add_parser("check")
    args = parser.parse_args(argv)
    repo = Path(__file__).resolve().parent.parent
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    prefix = {"snapshot": "No clean-CI receipt will be recorded",
              "write": "Clean-CI receipt not recorded",
              "check": "Local CI receipt not reused"}[args.command]
    try:
        if args.command == "snapshot":
            print(json.dumps(checkout_state(repo), sort_keys=True))
        elif args.command == "write":
            start = strict_json(args.start)
            toolchain = toolchain_identity(Path(args.toolchain_log).read_text(encoding="utf-8"))
            write_receipt(repo, start, toolchain, now)
            print(f"Clean-CI receipt recorded for commit {start['commit']} (tree {start['tree']}).")
        else:
            reused = reusable_receipts(repo, sys.stdin.read(), now)
            for remote_ref, commit, tree, path, completed in reused:
                minutes = int((now - completed).total_seconds() // 60)
                print(f"Reusing clean-CI receipt for {remote_ref}:")
                print(f"  receipt:   {path}")
                print(f"  commit:    {commit}")
                print(f"  tree:      {tree}")
                print(f"  completed: {completed.strftime(TIME_FORMAT)} ({minutes} min ago)")
            print("Skipping local CI: every pushed commit passed a clean run under this "
                  "hook, ci-local.sh and toolchain.")
    except Exception as error:  # Any failure means "run CI", never "skip it".
        reason = str(error) if isinstance(error, Refused) else f"{type(error).__name__}: {error}"
        print(f"{prefix}: {reason}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
