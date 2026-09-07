#!/usr/bin/python3
"""Read a release env file as data without executing shell syntax."""

from __future__ import annotations

import argparse
import os
import re
import shlex
import stat
import sys


MAX_BYTES = 64 * 1024

RELEASE_KEYS = {
    "DEVELOPER_ID",
    "APPLE_ID",
    "APPLE_TEAM_ID",
    "NOTARIZE_PASSWORD",
    "NOTARIZE_KEYCHAIN_PROFILE",
    "SITE_REPO_TOKEN",
    "TAP_REPO_TOKEN",
    "GH_TOKEN",
}
SIGNING_KEYS = {
    "DEVELOPER_ID",
    "APPLE_ID",
    "APPLE_TEAM_ID",
    "NOTARIZE_PASSWORD",
    "NOTARIZE_KEYCHAIN_PROFILE",
}
PUBLISHER_KEYS = {
    "SITE_REPO_TOKEN",
    "TAP_REPO_TOKEN",
    "GH_TOKEN",
}
STAGE_KEYS = {
    "VERSION",
    "BUILD_NUMBER",
    "SU_EDKEY",
    "SU_FEEDURL",
    "CHANNEL",
    "SU_AUTOCHECK",
}


def fail(message: str) -> "None":
    raise ValueError(message)


def read_secure(path: str) -> bytes:
    try:
        before = os.lstat(path)
    except OSError as exc:
        fail(f"cannot lstat {path}: {exc}")
    if stat.S_ISLNK(before.st_mode):
        fail("env file must not be a symlink")

    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        fail(f"cannot open env file safely: {exc}")
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            fail("env file must be a regular file")
        if opened.st_uid != os.getuid():
            fail(f"env file owner uid {opened.st_uid} != release uid {os.getuid()}")
        if opened.st_nlink != 1:
            fail("env file must have exactly one hard link")
        if stat.S_IMODE(opened.st_mode) & 0o077:
            fail("env file must not grant group/other permissions (chmod 600)")
        if opened.st_size > MAX_BYTES:
            fail(f"env file exceeds {MAX_BYTES} bytes")
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            fail("env file changed between lstat and open")

        chunks: list[bytes] = []
        remaining = MAX_BYTES + 1
        while remaining:
            chunk = os.read(fd, min(8192, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > MAX_BYTES:
            fail(f"env file exceeds {MAX_BYTES} bytes")

        after = os.fstat(fd)
        stable = (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_uid,
            opened.st_nlink,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ) == (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if not stable or len(data) != after.st_size:
            fail("env file changed while it was read")
        return data
    finally:
        os.close(fd)


def validate_value(profile: str, key: str, value: str) -> None:
    if not value or len(value) > 4096:
        fail(f"{key} must contain 1...4096 characters")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        fail(f"{key} contains a control character")

    if profile == "stage":
        semver = r"[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[0-9]+)?"
        if key == "VERSION" and not re.fullmatch(semver, value):
            fail("VERSION is not an allowed MacCrab version")
        if key == "BUILD_NUMBER" and not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+\.[1-9][0-9]*", value):
            fail("BUILD_NUMBER must be a numeric base version and positive revision")
        if key == "SU_EDKEY" and not re.fullmatch(r"[A-Za-z0-9+/]{43}=", value):
            fail("SU_EDKEY is not a 32-byte base64 public key")
        if key == "SU_FEEDURL" and not re.fullmatch(r"https://[A-Za-z0-9.-]+(?::[0-9]+)?/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*", value):
            fail("SU_FEEDURL is not a fixed HTTPS URL")
        if key == "CHANNEL" and value not in {"release", "dev"}:
            fail("CHANNEL must be release or dev")
        if key == "SU_AUTOCHECK" and value not in {"true", "false"}:
            fail("SU_AUTOCHECK must be true or false")
    else:
        if key == "APPLE_TEAM_ID" and not re.fullmatch(r"[A-Z0-9]{10}", value):
            fail("APPLE_TEAM_ID must be a 10-character team id")
        if key == "APPLE_ID" and not re.fullmatch(r"[^\s@]+@[^\s@]+", value):
            fail("APPLE_ID must be an email address")
        if key == "NOTARIZE_KEYCHAIN_PROFILE" and not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", value):
            fail("NOTARIZE_KEYCHAIN_PROFILE has an unsafe shape")
        if key in {"SITE_REPO_TOKEN", "TAP_REPO_TOKEN", "GH_TOKEN", "NOTARIZE_PASSWORD"} and re.search(r"\s", value):
            fail(f"{key} must not contain whitespace")


def parse(data: bytes, profile: str) -> list[tuple[str, str]]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        fail(f"env file is not UTF-8: {exc}")
    if "\x00" in text:
        fail("env file contains NUL")

    # signing/publisher are projections of the same on-disk release file.  The
    # parser still validates every key in that file, but returns only the
    # requested least-privilege subset so callers never need to import all
    # credentials just to run one phase.
    allowed = STAGE_KEYS if profile == "stage" else RELEASE_KEYS
    selected = {
        "signing": SIGNING_KEYS,
        "publisher": PUBLISHER_KEYS,
    }.get(profile, allowed)
    parsed: list[tuple[str, str]] = []
    seen: set[str] = set()
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "$" in line or "`" in line:
            fail(f"line {number}: shell expansion syntax is forbidden")
        lexer = shlex.shlex(line, posix=True)
        lexer.whitespace_split = True
        lexer.commenters = ""
        try:
            tokens = list(lexer)
        except ValueError as exc:
            fail(f"line {number}: malformed quoting: {exc}")
        if tokens[:1] == ["export"]:
            tokens = tokens[1:]
        if len(tokens) != 1 or "=" not in tokens[0]:
            fail(f"line {number}: expected [export] KEY=VALUE only")
        key, value = tokens[0].split("=", 1)
        if key not in allowed:
            fail(f"line {number}: key {key!r} is not allowed for {profile} data")
        if key in seen:
            fail(f"line {number}: duplicate key {key}")
        validate_value(profile, key, value)
        if key in selected:
            parsed.append((key, value))
        seen.add(key)
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--profile",
        choices=("release", "signing", "publisher", "stage"),
        required=True,
    )
    parser.add_argument("path")
    args = parser.parse_args()
    try:
        values = parse(read_secure(args.path), args.profile)
    except (OSError, ValueError) as exc:
        print(f"ERROR: release env rejected: {exc}", file=sys.stderr)
        return 1
    output = sys.stdout.buffer
    for key, value in values:
        output.write(key.encode("ascii") + b"\0" + value.encode("utf-8") + b"\0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
