#!/usr/bin/python3
"""Run one CI phase with a deadline and retained log/result, including on failure."""

import argparse
import datetime
import hashlib
import json
import math
import os
import signal
import shutil
import stat
import subprocess
import sys
import time
import re
import tempfile
from pathlib import Path


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def positive_seconds(value):
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        raise argparse.ArgumentTypeError("deadline must be finite and positive")
    return result


def unique_json_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def file_identity(path, *, read_json=False):
    """Hash a regular input at its canonical parent; never follow its leaf."""
    path = Path(path).absolute()
    path = path.parent.resolve(strict=True) / path.name
    digest = hashlib.sha256()
    content = bytearray() if read_json else None
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"not a regular file: {path}")
        if read_json and info.st_size > 8 * 1024 * 1024:
            raise ValueError(f"JSON identity input exceeds 8 MiB: {path}")
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            if content is not None:
                content.extend(chunk)
                if len(content) > 8 * 1024 * 1024:
                    raise ValueError(f"JSON identity input exceeds 8 MiB: {path}")
        after = os.fstat(stream.fileno())
    fields = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    if fields(info) != fields(after) or fields(after) != fields(path.lstat()):
        raise ValueError(f"input changed during hashing: {path}")
    result = {"path": str(path), "sha256": digest.hexdigest(), "bytes": after.st_size}
    if content is not None:
        result["document"] = json.loads(content, object_pairs_hook=unique_json_fields)
    return result


def source_identity(directory):
    """Bind dirty runs as dirty, never attribute their bytes to HEAD's tree.

    Hash tracked and nonignored untracked inputs, including executable mode,
    deleted paths and symlink text. Ignored build products are bound separately.
    This is diagnostic evidence, NOT a substitute for ci-receipt.py clean CI.
    """
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"

    def git(*arguments):
        return subprocess.run(["/usr/bin/git", "-C", str(directory), *arguments],
                              env=environment, check=True, capture_output=True,
                              timeout=30).stdout

    root = Path(os.fsdecode(git("rev-parse", "--show-toplevel")).strip())
    commit = git("rev-parse", "HEAD").decode().strip()
    tree = git("rev-parse", "HEAD^{tree}").decode().strip()
    status = git("status", "--porcelain=v1", "-z", "--untracked-files=all")
    index = git("ls-files", "--stage", "-z")
    hidden = [line for line in git("ls-files", "-v").splitlines()
              if line[:1] == b"S" or line[:1].islower()]
    names = sorted(set(git("ls-files", "--cached", "--others", "--exclude-standard", "-z").split(b"\0")) - {b""})
    digest = hashlib.sha256()
    for name in names:
        path = root / os.fsdecode(name)
        if path.is_symlink():
            value = {"symlink": os.readlink(path)}
        elif not path.exists():
            value = {"missing": True}
        else:
            value = file_identity(path)
            value.pop("path")
            value["mode"] = stat.S_IMODE(path.stat().st_mode)
        digest.update(name + b"\0" + json.dumps(value, sort_keys=True).encode() + b"\0")
    return {"root": str(root), "commit": commit, "tree": tree,
            "clean": not status and not hidden,
            "status_sha256": hashlib.sha256(status).hexdigest(),
            "index_sha256": hashlib.sha256(index).hexdigest(),
            "worktree_sha256": digest.hexdigest(), "file_count": len(names),
            "hidden_index_entries": len(hidden)}


def validate_build_receipt(receipt, current):
    """Link this test input to a completed build, not merely two stable files."""
    def require(condition, message):
        if not condition:
            raise ValueError("build receipt: " + message)

    require(isinstance(receipt, dict), "expected an object")
    require(type(receipt.get("schema_version")) is int and receipt["schema_version"] == 2,
            "unsupported schema")
    require(receipt.get("status") == "PASSED" and type(receipt.get("exit_code")) is int
            and receipt["exit_code"] == 0 and receipt.get("inputs_unchanged") is True,
            "build did not complete successfully with unchanged inputs")
    require(isinstance(receipt.get("completed_at"), str) and bool(receipt["completed_at"])
            and not any(key in receipt for key in ("identity_error", "cleanup_error", "descendants_after_exit")),
            "build is incomplete or has invalidation evidence")
    before, after = receipt.get("inputs_before"), receipt.get("inputs_after")
    require(isinstance(before, dict) and isinstance(after, dict) and before == after,
            "build input identities are missing or differ")
    source = current["source"]
    source_keys = {"root", "commit", "tree", "clean", "status_sha256", "index_sha256",
                   "worktree_sha256", "file_count", "hidden_index_entries"}
    require(isinstance(source, dict) and set(source) == source_keys, "source identity is not fully bound")
    require(isinstance(source["root"], str) and Path(source["root"]).is_absolute()
            and type(source["clean"]) is bool
            and type(source["file_count"]) is int and source["file_count"] > 0
            and type(source["hidden_index_entries"]) is int and source["hidden_index_entries"] >= 0,
            "source identity is malformed")
    for key in ("commit", "tree", "status_sha256", "index_sha256", "worktree_sha256"):
        pattern = r"(?:[0-9a-f]{40}|[0-9a-f]{64})" if key in ("commit", "tree") else r"[0-9a-f]{64}"
        require(isinstance(source[key], str) and re.fullmatch(pattern, source[key]) is not None,
                "source identity is malformed")
    require(before.get("source") == source and after.get("source") == source,
            "source identity differs from the build")

    def artifact_set(items):
        require(isinstance(items, list) and bool(items), "missing output or input artifacts")
        result = {}
        for item in items:
            require(isinstance(item, dict) and set(item) == {"path", "sha256", "bytes"},
                    "artifact identity is malformed")
            require(isinstance(item["path"], str) and Path(item["path"]).is_absolute()
                    and isinstance(item["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is not None
                    and type(item["bytes"]) is int and item["bytes"] > 0,
                    "artifact identity is malformed")
            # file_identity captured the canonical parent when the build ran.
            # Do not re-resolve historical paths: a later symlink must not
            # relabel output A as input B after the build receipt was written.
            path = item["path"]
            require(path == os.path.normpath(path), "artifact path is not canonical")
            require(path not in result, "duplicate artifact path")
            result[path] = (item["sha256"], item["bytes"])
        return result

    require(artifact_set(receipt.get("output_artifacts")) == artifact_set(current["artifacts"]),
            "test artifacts differ from the successful build outputs")


def input_identity(args):
    result = {}
    executable = shutil.which(args.command[0])
    result["command_executable"] = file_identity(Path(executable).resolve()) if executable else None
    try:
        result["source"] = source_identity(getattr(args, "source_root", None) or Path.cwd())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        # Non-repository lifecycle fixtures are allowed, but explicitly unbound.
        # A requested source root is mandatory and fails closed.
        if getattr(args, "source_root", None):
            raise ValueError("cannot bind source identity") from error
        result["source"] = {"unbound": True, "reason": type(error).__name__}
    result["artifacts"] = [file_identity(path) for path in getattr(args, "artifact", [])]
    for key in ("test_inventory", "toolchain_report"):
        path = getattr(args, key, None)
        if path:
            result[key] = file_identity(path, read_json=True)
    if getattr(args, "build_receipt", None) is not None:
        result["build_receipt"] = file_identity(args.build_receipt, read_json=True)
        validate_build_receipt(result["build_receipt"]["document"], result)
    return result


def test_result_summary(path):
    # Retain the complete log and its digest. The bounded tail is only used to
    # extract framework-reported counts; it is not a claim about test coverage.
    with Path(path).open("rb") as stream:
        stream.seek(max(0, stream.seek(0, 2) - 1024 * 1024))
        tail = stream.read().decode("utf-8", errors="replace")
    swift = re.findall(r"Test run with (\d+) tests? in (\d+) suites? (passed|failed)", tail)
    if swift:
        count, suites, outcome = swift[-1]
        return {"framework": "Swift Testing", "reported_tests": int(count),
                "reported_suites": int(suites), "outcome": outcome}
    python = re.findall(r"Ran (\d+) tests? in [^\n]+\n\s*\n?(OK|FAILED)", tail)
    if python:
        count, outcome = python[-1]
        return {"framework": "unittest", "reported_tests": int(count), "outcome": outcome}
    return None


def run_phase(args):
    started = time.monotonic()
    record = {
        "schema_version": 2,
        "phase": args.label,
        "started_at": utc_now(),
        "timeout_seconds": args.timeout_seconds,
        "grace_seconds": args.grace_seconds,
        "log": str(Path(args.log).resolve()),
        "status": "RUNNING",
        "argv": list(args.command),
        "cwd": str(Path.cwd().resolve()),
        "runner": {"python": sys.version, "executable": sys.executable},
        "qualification_scope": "individual phase; not a clean-CI or release receipt",
    }
    result_path = Path(args.result)
    # Never overwrite old evidence. Commands must not contain secrets: argv is
    # retained exactly; use the caller's secure credential mechanism instead.
    for path in (result_path, Path(args.log)):
        if path.exists() or path.is_symlink():
            raise ValueError(f"refusing to overwrite phase evidence: {path}")
    # Reserve atomically so concurrent invocations cannot replace one another.
    descriptor = os.open(result_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump(record, output)

    def save():
        with tempfile.NamedTemporaryFile(mode="w", dir=result_path.parent,
                                         prefix=result_path.name + ".", delete=False) as output:
            json.dump(record, output, indent=2, sort_keys=True)
            output.write("\n")
            temporary = Path(output.name)
        temporary.replace(result_path)

    save()  # A killed runner leaves an explicit RUNNING record, never a pass.
    try:
        record["inputs_before"] = input_identity(args)
        record["command_executable"] = record["inputs_before"]["command_executable"]
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        record.update(status="INVALID_INPUT", exit_code=65, identity_error=str(error),
                      completed_at=utc_now())
        save()
        return 65
    save()
    process = None
    interrupted = None

    def interrupt(signum, _frame):
        nonlocal interrupted
        interrupted = signum

    previous = {sig: signal.signal(sig, interrupt)
                for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}

    def stop_group():
        # The phase owns a new session. Terminate descendants even if the
        # immediate process exits first (e.g. a shell waiting for a compiler).
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        until = time.monotonic() + args.grace_seconds
        while time.monotonic() < until:
            process.poll()
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                return
            except PermissionError:
                # A denied existence probe does not prove the group is gone.
                # Keep the grace period and still attempt actual termination.
                pass
            time.sleep(min(0.1, max(0, until - time.monotonic())))
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()

    try:
        with open(args.log, "xb") as output:
            os.chmod(args.log, 0o600)
            try:
                process = subprocess.Popen(args.command, stdout=output,
                                           stderr=subprocess.STDOUT,
                                           start_new_session=True)
            except OSError as error:
                output.write(("Unable to start phase: " + str(error) + "\n").encode())
                record.update(status="FAILED", exit_code=127)
            else:
                deadline = time.monotonic() + args.timeout_seconds
                while process.poll() is None and interrupted is None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    try:
                        process.wait(timeout=min(0.2, remaining))
                    except subprocess.TimeoutExpired:
                        pass
                if interrupted is not None:
                    record.update(status="INTERRUPTED", exit_code=128 + interrupted,
                                  signal=interrupted)
                elif process.poll() is None:
                    record.update(status="TIMED_OUT", exit_code=124)
                else:
                    code = process.returncode
                    record.update(status="PASSED" if code == 0 else "FAILED",
                                  exit_code=code if code >= 0 else 128 - code)
                    # The direct child exiting does not prove its phase is
                    # complete: a shell/test runner may leave workers behind.
                    # Do not hash a still-written log or publish a pass while
                    # descendants in our owned process group remain active.
                    try:
                        os.killpg(process.pid, 0)
                        descendants_remain = True
                    except ProcessLookupError:
                        descendants_remain = False
                    except PermissionError:
                        descendants_remain = True  # absence is not proven
                    if descendants_remain:
                        record["descendants_after_exit"] = True
                        if code == 0:
                            record.update(status="DESCENDANTS_REMAIN", exit_code=70,
                                          command_exit_code=0)
                        output.write(b"\nCI phase exited before its process group completed; refusing a passing receipt.\n")
                if record["status"] in ("INTERRUPTED", "TIMED_OUT") or record.get("descendants_after_exit"):
                    try:
                        stop_group()
                    except Exception as error:
                        # Retain the original non-success outcome even when
                        # cleanup fails; never describe termination as verified.
                        record["cleanup_error"] = {
                            "type": type(error).__name__,
                            "message": str(error),
                        }
                        if isinstance(error, OSError):
                            record["cleanup_error"]["errno"] = error.errno
                        output.write(("\nCI phase process-group cleanup failed: " +
                                      str(error) + "\n").encode())
                    else:
                        if record["status"] == "TIMED_OUT":
                            output.write(b"\nCI phase exceeded its deadline; process group terminated.\n")
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        try:
            record["inputs_after"] = input_identity(args)
            record["inputs_unchanged"] = record["inputs_before"] == record["inputs_after"]
            record["log_identity"] = file_identity(args.log)
            record["test_results"] = test_result_summary(args.log)
            record["output_artifacts"] = [
                file_identity(path) for path in getattr(args, "output_artifact", [])
                if record.get("status") == "PASSED" or Path(path).exists()
            ]
            expected = getattr(args, "expected_test_count", None)
            if expected is not None and (
                not record["test_results"] or record["test_results"]["reported_tests"] != expected
            ):
                raise ValueError("executed test count does not match the expected count")
            if record["test_results"] and record["test_results"]["outcome"].lower() == "failed":
                raise ValueError("test framework reported failure")
            if record["test_results"] and record["test_results"]["reported_tests"] == 0:
                raise ValueError("test count is zero; no tests were executed")
            if getattr(args, "test_inventory", None) and not record["test_results"]:
                raise ValueError("selected test run has no recognized test summary")
            if not record["inputs_unchanged"]:
                raise ValueError("source, executable or evidence inputs changed during the phase")
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            record["identity_error"] = str(error)
            if record.get("status") == "PASSED":
                record.update(status="INVALIDATED", command_exit_code=0, exit_code=65)
        record.update(completed_at=utc_now(),
                      elapsed_seconds=round(time.monotonic() - started, 6))
        save()
    return record["exit_code"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label", required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--result", required=True)
    parser.add_argument("--timeout-seconds", type=positive_seconds, default=1800)
    parser.add_argument("--grace-seconds", type=positive_seconds, default=15)
    parser.add_argument("--source-root", help="mandatory repository identity (including dirty bytes)")
    parser.add_argument("--artifact", action="append", default=[], help="required unchanged input executable/file")
    parser.add_argument("--output-artifact", action="append", default=[], help="required build output to hash after success")
    parser.add_argument("--build-receipt", help="require test inputs to match a successful schema-2 build receipt")
    parser.add_argument("--test-inventory", help="JSON selection/discovery inventory to retain and hash")
    parser.add_argument("--toolchain-report", help="JSON compiler/toolchain identity to retain and hash")
    parser.add_argument("--expected-test-count", type=int, help="require this framework-reported test count")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    if not args.command:
        parser.error("a phase command is required")
    return run_phase(args)


if __name__ == "__main__":
    sys.exit(main())
