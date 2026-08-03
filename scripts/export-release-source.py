#!/usr/bin/python3
"""Export one Git commit as an exact, tracked-only release source tree.

Unlike ``git archive``, this deliberately does not consult export attributes,
working-tree filters, the index, or ignored files.  Every output byte comes
directly from a blob named by the requested commit's tree.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
from typing import Optional


GIT = "/usr/bin/git"
ALLOWED_MODES = {"100644": 0o644, "100755": 0o755}


def git(repo: Path, *args: str, input_bytes: Optional[bytes] = None) -> bytes:
    git_environment = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": os.environ.get("HOME", "/var/empty"),
        "LC_ALL": "C",
        "LANG": "C",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
    }
    result = subprocess.run(
        [GIT, "-C", os.fspath(repo), *args],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=git_environment,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError(f"git {' '.join(args)} failed: {detail}")
    return result.stdout


def safe_parts(raw_path: bytes) -> tuple[str, ...]:
    try:
        text = raw_path.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise RuntimeError("release source contains a non-UTF-8 path") from error
    pure = PurePosixPath(text)
    if not text or pure.is_absolute() or any(part in ("", ".", "..") for part in pure.parts):
        raise RuntimeError(f"unsafe path in release tree: {text!r}")
    if "\n" in text or "\r" in text:
        raise RuntimeError(f"release source contains a newline path: {text!r}")
    return pure.parts


def ensure_private_empty_directory(destination: Path) -> None:
    info = destination.lstat()
    if not stat.S_ISDIR(info.st_mode) or destination.is_symlink():
        raise RuntimeError("destination must be a real directory")
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise RuntimeError("destination must be owned by this user with mode 0700")
    if any(destination.iterdir()):
        raise RuntimeError("destination must be empty")


def export(repo: Path, commit: str, destination: Path) -> int:
    ensure_private_empty_directory(destination)
    commit_oid = git(repo, "rev-parse", "--verify", f"{commit}^{{commit}}").decode().strip()
    if commit_oid != commit:
        raise RuntimeError("release source must be a full canonical commit object ID")

    records = git(repo, "ls-tree", "-rz", "--full-tree", "-r", commit).split(b"\0")
    count = 0
    for record in records:
        if not record:
            continue
        metadata, separator, raw_path = record.partition(b"\t")
        if not separator:
            raise RuntimeError("malformed git ls-tree record")
        fields = metadata.decode("ascii", "strict").split()
        if len(fields) != 3:
            raise RuntimeError("malformed git ls-tree metadata")
        mode, object_type, oid = fields
        if object_type != "blob" or mode not in ALLOWED_MODES:
            path_label = raw_path.decode("utf-8", "replace")
            raise RuntimeError(
                f"unsupported release-tree entry {mode} {object_type}: {path_label}"
            )
        parts = safe_parts(raw_path)
        output = destination.joinpath(*parts)
        output.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        if output.exists() or output.is_symlink():
            raise RuntimeError(f"duplicate or redirected export path: {'/'.join(parts)}")
        payload = git(repo, "cat-file", "blob", oid)
        descriptor = os.open(
            output,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            ALLOWED_MODES[mode],
        )
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(descriptor)
        os.chmod(output, ALLOWED_MODES[mode], follow_symlinks=False)
        count += 1
    return count


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--destination", required=True, type=Path)
    args = parser.parse_args()
    try:
        count = export(args.repo.resolve(), args.commit, args.destination.resolve())
    except (OSError, RuntimeError) as error:
        print(f"ERROR: tracked-only release export failed: {error}", file=sys.stderr)
        return 1
    print(f"exported_files={count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
