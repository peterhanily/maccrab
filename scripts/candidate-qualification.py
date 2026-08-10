#!/usr/bin/env python3
"""Create and verify MacCrab release-candidate qualification evidence.

The public release path calls ``verify-release`` with full artifact checks.
Digest-only inspection exists so the deterministic fixture suite can run on a
non-macOS host; release.sh never selects it.

The evidence files are deliberately data, not executable shell fragments.
They bind an installed-host run to one source commit/tree and one immutable DMG
digest, and make every threshold in docs/RUNTIME_QUALITY_CONTRACT.md a
machine-checked release condition.
"""

from __future__ import annotations

import argparse
import copy
import ctypes
import datetime as dt
import hashlib
import json
import math
import os
import pathlib
import platform
import plistlib
import pwd
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, Iterable, List, Mapping, NoReturn, Sequence, Tuple


CANDIDATE_SCHEMA = "com.maccrab.release-candidate.v1"
RUNTIME_SCHEMA = "com.maccrab.installed-host-qualification.v1"
CONTAINMENT_SCHEMA = "com.maccrab.containment-qualification.v2"
QUALIFICATION_DIR = ".qualification-evidence"

MIB = 1024 * 1024
GIB = 1024 * MIB
MIN_EPOCH_SECONDS = 900.0
MAX_SAMPLE_GAP_SECONDS = 35.0
MAX_ENGINE_WRITE_BYTES_PER_SECOND = 1 * MIB
MAX_WINDOW_WRITE_BYTES_PER_SECOND = 4 * MIB
MAX_ENGINE_AVERAGE_CORES = 0.50
MAX_GUI_P95_PERCENT = 10.0
MAX_ENGINE_RSS_BYTES = 450 * MIB
MAX_ENGINE_RSS_GROWTH_BYTES = 64 * MIB
MIN_TRACE_WRITABLE_DUTY = 0.99
BURST_START_OFFSET_SECONDS = 300
BURST_END_OFFSET_SECONDS = 390
# The failed reference-host capture reached 1,274 events/s while the earlier
# quiet capture reached only 98 events/s.  Qualification therefore has to
# exercise at least the observed failure-state rate; a conserving idle engine
# is not a load test.
MIN_BURST_COMBINED_OFFERED_PER_SECOND = 1_274.0
MIN_TRACE_STORE_INGEST_DELTA = 1
FOCUSED_RUNTIME_TEST_FILTER = (
    "SequenceCheckpointTests|Phase3SequenceReloadTests|"
    "BundledRuleSynchronizerTests"
)
CONTAINMENT_FIXTURE_PRODUCTS = (
    "maccrab-tierb-corpus-probe",
    "maccrab-tierb-corpus-probe-swift",
)
CONTAINMENT_BUILD_SCRATCH_NAME = "swiftpm-build"
CONTAINMENT_LOOPBACK_HOST = "127.0.0.1"
CONTAINMENT_LOOPBACK_PORT = 49373
CONTAINMENT_UNSANDBOXED_LEAKS = {
    "c-probe": (
        "leak.file_escape", "leak.network", "leak.fork", "leak.metadata",
        "leak.mach",
    ),
    "swift-probe": (
        "leak.file_escape", "leak.network", "leak.fork", "leak.metadata",
    ),
}
CONTAINMENT_CANDIDATE_BINARIES = {
    "maccrabctl": (
        "MacCrab.app/Contents/Resources/bin/maccrabctl",
        "com.maccrab.maccrabctl",
    ),
    "trampoline": (
        "MacCrab.app/Contents/Resources/bin/maccrab-tierb-sandbox-host",
        "maccrab-tierb-sandbox-host",
    ),
    "example": (
        "MacCrab.app/Contents/Resources/bin/maccrab-tierb-example",
        "maccrab-tierb-example",
    ),
}
CONTAINMENT_RUNS = (
    ("example", "org.maccrab.qualification.example", "example.heartbeat"),
    ("c-probe", "org.maccrab.qualification.c-probe", "broker.read.ok"),
    ("swift-probe", "org.maccrab.qualification.swift-probe", "broker.read.ok"),
)
RUNTIME_WORKLOAD_EXECUTORS = (
    "scripts/runtime-qualification-workload.sh",
    "scripts/test-otlp-curl.sh",
)
RUNTIME_RECORDER_SCHEMA = "com.maccrab.installed-host-recorder.v1"
RUNTIME_OBSERVATION_SCHEMA = "com.maccrab.installed-host-observation.v1"
DEFAULT_HEARTBEAT_PATH = pathlib.Path(
    "/Library/Application Support/MacCrab/heartbeat_rich.json"
)
DEFAULT_DATA_DIR = pathlib.Path("/Library/Application Support/MacCrab")
HEARTBEAT_MAX_AGE_SECONDS = 75.0

LLM_FEATURES = (
    "unspecified",
    "intent_classification",
    "alert_investigation",
    "campaign_investigation",
    "active_defense",
    "threat_hunt",
    "rule_generation",
    "alert_cluster_rationale",
    "security_posture",
    "sdr_context",
    "edr_context",
    "incident_report",
)
LLM_ALERT_REJECTION_REASONS = (
    "backend_response_unavailable",
    "response_size_limit",
    "response_envelope",
    "schema_decode",
    "trusted_alert_identifier",
    "response_alert_identifier",
    "confidence_range",
    "summary_safety",
    "evidence_cardinality",
    "evidence_shape",
    "evidence_grounding",
    "mitre_cardinality",
    "mitre_reasoning_safety",
    "mitre_grounding",
    "action_cardinality",
    "action_prose_safety",
    "d3fend_reference",
    "action_preview_safety",
    "action_confirmation",
    "confidence_penalty_safety",
)

# This inventory is part of the v1 evidence schema. A producer cannot omit a
# failing lane/store and still claim completeness. Adding a new shipping
# boundary or SQLite family requires a deliberate schema/gate update.
REQUIRED_CONSERVATION_BOUNDARIES = frozenset(
    {
        "priority-ingress",
        "file-ingress",
        "priority-event-persistence",
        "file-event-persistence",
        "sequence-checkpoint",
        "sequence-journal",
        "trace-graph-mutation",
        "trace-store-ingest",
    }
)
REQUIRED_SQLITE_FAMILIES = frozenset(
    {
        "events.db",
        "alerts.db",
        "campaigns.db",
        "tracegraph.db",
        "traces.db",
        "attribution_overrides.db",
    }
)

# Fallbacks match DaemonConfig.Storage defaults. The active events, alerts,
# TraceGraph and traces caps are replaced by heartbeat values when present;
# config-file overrides are applied before each sample.
DEFAULT_SQLITE_CAP_BYTES = {
    "events.db": 320 * MIB,
    "alerts.db": 200 * MIB,
    "campaigns.db": 50 * MIB,
    "tracegraph.db": 250 * MIB,
    "traces.db": 100 * MIB,
    "attribution_overrides.db": 32 * MIB,
}
DEFAULT_SQLITE_FREE_SPACE_FLOOR_BYTES = 1024 * MIB
EXPECTED_DEVELOPER_ID = "Developer ID Application: Peter Hanily (79S425CW99)"
EXPECTED_TEAM_ID = "79S425CW99"
EXPECTED_APP_IDENTIFIER = "com.maccrab.app"
EXPECTED_AGENT_IDENTIFIER = "com.maccrab.agent"
AGENT_PAYLOAD_PATH = (
    "MacCrab.app/Contents/Library/SystemExtensions/"
    "com.maccrab.agent.systemextension/Contents/MacOS/com.maccrab.agent"
)

HEX_OBJECT_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
HEX_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[0-9]+)?$")
BUILD_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[0-9]+)?\.[0-9]+$")
UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)


class QualificationError(Exception):
    """A candidate or evidence file failed a blocking qualification rule."""


def fail(message: str) -> NoReturn:
    raise QualificationError(message)


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def absolute_path(value: str) -> pathlib.Path:
    """Make a path absolute without dereferencing its final symlink."""
    return pathlib.Path(os.path.abspath(value))


def write_json_exclusive(path: pathlib.Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".tmp.{os.getpid()}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(str(temporary), flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_json_bytes(value))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(str(temporary), str(path))
        os.chmod(str(path), 0o600)
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def read_json_file(path: pathlib.Path, label: str) -> Dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        fail(f"{label} is missing, non-regular, or redirected: {path}")
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"{label} is not valid JSON: {path}: {exc}")
    if not isinstance(value, dict):
        fail(f"{label} root must be an object")
    return value


def object_value(value: Any, path: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{path} must be an object")
    return value


def list_value(value: Any, path: str, *, nonempty: bool = False) -> List[Any]:
    if not isinstance(value, list):
        fail(f"{path} must be an array")
    if nonempty and not value:
        fail(f"{path} must not be empty")
    return value


def string_value(value: Any, path: str, *, nonempty: bool = True) -> str:
    if not isinstance(value, str) or (nonempty and not value.strip()):
        fail(f"{path} must be a{' non-empty' if nonempty else ''} string")
    return value


def bool_value(value: Any, path: str) -> bool:
    if type(value) is not bool:
        fail(f"{path} must be a boolean")
    return value


def number_value(value: Any, path: str, *, minimum: float | None = None) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        fail(f"{path} must be a finite number")
    result = float(value)
    if minimum is not None and result < minimum:
        fail(f"{path} must be >= {minimum}")
    return result


def int_value(value: Any, path: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        fail(f"{path} must be an integer >= {minimum}")
    return value


def require_true(value: Any, path: str) -> None:
    if not bool_value(value, path):
        fail(f"{path} must be true")


def require_zero(value: Any, path: str) -> None:
    if number_value(value, path, minimum=0) != 0:
        fail(f"{path} must be zero")


def require_sha(value: Any, path: str) -> str:
    text = string_value(value, path)
    if not HEX_SHA256_RE.fullmatch(text):
        fail(f"{path} must be a lowercase SHA-256")
    return text


def require_object_id(value: Any, path: str) -> str:
    text = string_value(value, path)
    if not HEX_OBJECT_RE.fullmatch(text):
        fail(f"{path} must be a 40- or 64-character lowercase Git object ID")
    return text


def parse_time(value: Any, path: str) -> dt.datetime:
    text = string_value(value, path)
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        fail(f"{path} must be an ISO-8601 timestamp with timezone")
    if parsed.tzinfo is None:
        fail(f"{path} must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def percentile_nearest_rank(values: Sequence[float], percentile: float) -> float:
    if not values:
        fail("cannot calculate a percentile from an empty sample set")
    ordered = sorted(values)
    rank = max(1, math.ceil(percentile * len(ordered)))
    return ordered[rank - 1]


def run_checked(command: Sequence[str], label: str) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, check=True, capture_output=True, text=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = ""
        if isinstance(exc, subprocess.CalledProcessError):
            detail = (exc.stderr or exc.stdout or "").strip()
        fail(f"{label} failed{': ' + detail if detail else ''}")


def assert_exact_clean_source(
    root: pathlib.Path, *, source_commit: str, source_tree: str, label: str
) -> None:
    """Fail unless *root* is still the clean checkout bound to the candidate.

    Recorders call this immediately before and after running their measured
    workload.  The second check is important: build/test/workload subprocesses
    must not be able to leave the recorder reporting evidence from source bytes
    other than the candidate tree.
    """
    git = fixed_tool("/usr/bin/git")
    def git_command(*arguments: str) -> List[str]:
        # record-runtime is root-owned, but the checkout is deliberately owned
        # by the invoking desktop user. Run Git as that user so Git's
        # safe.directory protection remains effective instead of weakening it.
        return original_user_command([git, "-C", str(root), *arguments])

    toplevel = pathlib.Path(
        run_checked(
            git_command("rev-parse", "--show-toplevel"),
            f"{label} source-root probe",
        ).stdout.strip()
    ).resolve()
    if toplevel != root.resolve():
        fail(f"{label} source root is not the Git worktree root")
    head = run_checked(
        git_command("rev-parse", "HEAD"),
        f"{label} source HEAD probe",
    ).stdout.strip()
    tree = run_checked(
        git_command("rev-parse", "HEAD^{tree}"),
        f"{label} source tree probe",
    ).stdout.strip()
    if head != source_commit or tree != source_tree:
        fail(f"{label} source checkout does not match the exact candidate")
    hidden = run_checked(
        git_command("ls-files", "-v"),
        f"{label} hidden-index-state probe",
    ).stdout.splitlines()
    if any(line and (line[0] == "S" or line[0].islower()) for line in hidden):
        fail(f"{label} source checkout has assume-unchanged/skip-worktree entries")
    dirty = run_checked(
        git_command("status", "--porcelain=v1", "--untracked-files=all"),
        f"{label} source cleanliness probe",
    ).stdout.strip()
    if dirty:
        fail(f"{label} requires the clean exact candidate source checkout")


def codesign_identity(path: pathlib.Path, *, label: str) -> Dict[str, Any]:
    codesign = fixed_tool("/usr/bin/codesign")
    details = run_checked([codesign, "-dv", "--verbose=4", str(path)], label)
    signing_text = (details.stdout or "") + "\n" + (details.stderr or "")
    authorities = re.findall(r"^Authority=(.+)$", signing_text, flags=re.MULTILINE)
    team_match = re.search(r"^TeamIdentifier=(\S+)$", signing_text, flags=re.MULTILINE)
    identifier_match = re.search(r"^Identifier=(\S+)$", signing_text, flags=re.MULTILINE)
    cdhash_match = re.search(r"^CDHash=([0-9a-fA-F]+)$", signing_text, flags=re.MULTILINE)
    if not authorities or not team_match or not identifier_match:
        fail(f"{label} lacks Authority, TeamIdentifier, or Identifier")
    return {
        "developer_id": authorities[0],
        "authority_chain": authorities,
        "team_id": team_match.group(1),
        "signing_identifier": identifier_match.group(1),
        "cdhash": cdhash_match.group(1).lower() if cdhash_match else "",
    }


def require_maccrab_signing_identity(
    identity: Mapping[str, Any], *, expected_identifier: str, path: str
) -> None:
    if identity.get("developer_id") != EXPECTED_DEVELOPER_ID:
        fail(f"{path}.developer_id is not the documented MacCrab release identity")
    if identity.get("team_id") != EXPECTED_TEAM_ID:
        fail(f"{path}.team_id is not {EXPECTED_TEAM_ID}")
    if identity.get("signing_identifier") != expected_identifier:
        fail(f"{path}.signing_identifier must be {expected_identifier}")


def fixed_tool(path: str) -> str:
    if not pathlib.Path(path).is_file():
        fail(f"required macOS artifact-inspection tool is unavailable: {path}")
    return path


def inventory_mounted_payload(mountpoint: pathlib.Path) -> Tuple[List[Dict[str, Any]], str]:
    entries: List[Dict[str, Any]] = []
    for path in sorted(mountpoint.rglob("*"), key=lambda item: item.relative_to(mountpoint).as_posix()):
        relative = path.relative_to(mountpoint).as_posix()
        stat_result = path.lstat()
        if path.is_symlink():
            entries.append({
                "path": relative,
                "kind": "symlink",
                "target": os.readlink(str(path)),
                "mode": stat_result.st_mode & 0o7777,
            })
        elif path.is_file():
            entries.append({
                "path": relative,
                "kind": "file",
                "size_bytes": stat_result.st_size,
                "sha256": sha256_file(path),
                "mode": stat_result.st_mode & 0o7777,
            })
        elif path.is_dir():
            entries.append({
                "path": relative,
                "kind": "directory",
                "mode": stat_result.st_mode & 0o7777,
            })
        else:
            fail(f"mounted payload contains unsupported filesystem object: {relative}")
    return entries, sha256_bytes(canonical_json_bytes(entries))


def inspect_artifact_full(dmg: pathlib.Path) -> Dict[str, Any]:
    codesign = fixed_tool("/usr/bin/codesign")
    xcrun = fixed_tool("/usr/bin/xcrun")
    spctl = fixed_tool("/usr/sbin/spctl")
    hdiutil = fixed_tool("/usr/bin/hdiutil")

    run_checked([codesign, "--verify", "--deep", "--strict", str(dmg)], "DMG codesign verification")
    dmg_identity = codesign_identity(dmg, label="DMG signing identity inspection")
    if dmg_identity.get("developer_id") != EXPECTED_DEVELOPER_ID \
            or dmg_identity.get("team_id") != EXPECTED_TEAM_ID:
        fail("DMG is not signed by the documented MacCrab Developer ID identity")

    run_checked([xcrun, "stapler", "validate", str(dmg)], "DMG stapling validation")
    run_checked(
        [spctl, "-a", "-t", "open", "--context", "context:primary-signature", "-v", str(dmg)],
        "DMG Gatekeeper assessment",
    )

    mount_parent = pathlib.Path(tempfile.mkdtemp(prefix="maccrab-candidate-mount.", dir="/private/tmp"))
    mountpoint = mount_parent / "payload"
    mountpoint.mkdir(mode=0o700)
    attached = False
    try:
        run_checked(
            [hdiutil, "attach", "-readonly", "-nobrowse", "-mountpoint", str(mountpoint), str(dmg)],
            "read-only DMG mount",
        )
        attached = True
        required_directories = [
            "MacCrab.app",
            "MacCrab.app/Contents/Library/SystemExtensions/com.maccrab.agent.systemextension",
        ]
        required_files = [
            "MacCrab.app/Contents/MacOS/MacCrab",
            AGENT_PAYLOAD_PATH,
            "MacCrab.app/Contents/Resources/bin/maccrabctl",
            "MacCrab.app/Contents/Resources/bin/maccrab-mcp",
            "MacCrab.app/Contents/Resources/release-input-attestation.txt",
            "install.sh",
        ]
        for relative in required_directories:
            required_path = mountpoint / relative
            if required_path.is_symlink() or not required_path.is_dir():
                fail(f"mounted DMG required directory is missing or redirected: {relative}")
        for relative in required_files:
            required_path = mountpoint / relative
            if required_path.is_symlink() or not required_path.is_file():
                fail(f"mounted DMG required file is missing or redirected: {relative}")

        app_path = mountpoint / "MacCrab.app"
        run_checked([codesign, "--verify", "--deep", "--strict", str(app_path)], "mounted app codesign verification")
        app_identity = codesign_identity(app_path, label="mounted app signing identity inspection")
        require_maccrab_signing_identity(
            app_identity, expected_identifier=EXPECTED_APP_IDENTIFIER,
            path="mounted app signing identity",
        )
        if app_identity["developer_id"] != dmg_identity["developer_id"] \
                or app_identity["team_id"] != dmg_identity["team_id"]:
            fail("mounted app and enclosing DMG do not share the same Developer ID identity")

        agent_path = mountpoint / AGENT_PAYLOAD_PATH
        run_checked([codesign, "--verify", "--strict", str(agent_path)], "mounted system-extension executable codesign verification")
        agent_identity = codesign_identity(
            agent_path, label="mounted system-extension signing identity inspection"
        )
        require_maccrab_signing_identity(
            agent_identity, expected_identifier=EXPECTED_AGENT_IDENTIFIER,
            path="mounted system-extension signing identity",
        )
        agent_plist_path = agent_path.parent.parent / "Info.plist"
        try:
            with agent_plist_path.open("rb") as handle:
                agent_plist = plistlib.load(handle)
        except (OSError, plistlib.InvalidFileException) as exc:
            fail(f"mounted system-extension Info.plist is unreadable: {exc}")
        agent_short_version = string_value(
            agent_plist.get("CFBundleShortVersionString"),
            "mounted system-extension CFBundleShortVersionString",
        )
        agent_build_version = string_value(
            agent_plist.get("CFBundleVersion"),
            "mounted system-extension CFBundleVersion",
        )

        entries, inventory_sha = inventory_mounted_payload(mountpoint)
        attestation_path = mountpoint / "MacCrab.app/Contents/Resources/release-input-attestation.txt"
        attestation_sha = sha256_file(attestation_path)
        attestation_lines = attestation_path.read_text(encoding="utf-8").splitlines()
        attestation = {}
        for line in attestation_lines:
            if "=" in line:
                key, value = line.split("=", 1)
                attestation[key] = value
        return {
            "inspection_level": "full",
            "codesign_verified": True,
            "developer_id": dmg_identity["developer_id"],
            "authority_chain": dmg_identity["authority_chain"],
            "team_id": dmg_identity["team_id"],
            "signing_identifier": dmg_identity["signing_identifier"],
            "app_developer_id": app_identity["developer_id"],
            "app_team_id": app_identity["team_id"],
            "app_signing_identifier": app_identity["signing_identifier"],
            "system_extension": {
                "developer_id": agent_identity["developer_id"],
                "team_id": agent_identity["team_id"],
                "signing_identifier": agent_identity["signing_identifier"],
                "cdhash": agent_identity["cdhash"],
                "executable_sha256": sha256_file(agent_path),
                "bundle_version": agent_short_version,
                "build_version": agent_build_version,
            },
            "notarization_status": "accepted",
            "stapled": True,
            "gatekeeper_accepted": True,
            "release_input_attestation_sha256": attestation_sha,
            "release_input_attestation": attestation,
            "xcode_toolchain": attestation.get("xcode_toolchain", "unknown"),
            "swift_toolchain": attestation.get("swift_toolchain", "unknown"),
            "payload_inventory": {
                "format": "maccrab-path-sha256-v1",
                "entry_count": len(entries),
                "sha256": inventory_sha,
                "entries": entries,
            },
        }
    finally:
        if attached:
            subprocess.run([hdiutil, "detach", str(mountpoint)], capture_output=True, text=True)
        shutil.rmtree(mount_parent, ignore_errors=True)


def inspect_artifact(dmg: pathlib.Path, level: str) -> Dict[str, Any]:
    if dmg.is_symlink() or not dmg.is_file() or dmg.stat().st_size <= 0:
        fail(f"candidate DMG is missing, empty, non-regular, or redirected: {dmg}")
    if level == "full":
        return inspect_artifact_full(dmg)
    if level != "digest":
        fail(f"unsupported artifact inspection level: {level}")
    return {
        "inspection_level": "digest-only-test-fixture",
        "codesign_verified": False,
        "developer_id": "TEST FIXTURE — NOT A RELEASE IDENTITY",
        "authority_chain": [],
        "team_id": "TESTFIXTURE",
        "signing_identifier": "test.fixture",
        "system_extension": {
            "developer_id": EXPECTED_DEVELOPER_ID,
            "team_id": EXPECTED_TEAM_ID,
            "signing_identifier": EXPECTED_AGENT_IDENTIFIER,
            "cdhash": "a" * 40,
            "executable_sha256": sha256_file(dmg),
            "bundle_version": "test-fixture",
            "build_version": "test-fixture",
        },
        "notarization_status": "not-checked",
        "notarization_submission_id": "00000000-0000-4000-8000-000000000000",
        "stapled": False,
        "gatekeeper_accepted": False,
        "release_input_attestation_sha256": "0" * 64,
        "release_input_attestation": {},
        "payload_inventory": {
            "format": "test-fixture",
            "entry_count": 2 + len(CONTAINMENT_CANDIDATE_BINARIES),
            "sha256": sha256_file(dmg),
            "entries": [
                {"path": dmg.name, "kind": "file", "size_bytes": dmg.stat().st_size, "sha256": sha256_file(dmg)},
                {"path": AGENT_PAYLOAD_PATH, "kind": "file", "size_bytes": dmg.stat().st_size, "sha256": sha256_file(dmg)},
                *[
                    {
                        "path": relative,
                        "kind": "file",
                        "size_bytes": dmg.stat().st_size,
                        "sha256": sha256_file(dmg),
                    }
                    for relative, _ in CONTAINMENT_CANDIDATE_BINARIES.values()
                ],
            ],
        },
    }


def candidate_document(
    *,
    version: str,
    build_number: str,
    source_commit: str,
    source_tree: str,
    dmg: pathlib.Path,
    inspection_level: str,
    notarization_submission_id: str,
) -> Dict[str, Any]:
    if not VERSION_RE.fullmatch(version):
        fail("candidate version has an invalid shape")
    if not BUILD_RE.fullmatch(build_number) or not build_number.startswith(version + "."):
        fail("candidate build number must be <version>.<positive commit count>")
    require_object_id(source_commit, "source_commit")
    require_object_id(source_tree, "source_tree")
    inspection = inspect_artifact(dmg, inspection_level)
    if inspection_level == "full":
        if not UUID_RE.fullmatch(notarization_submission_id):
            fail("a full candidate record requires the accepted notary submission UUID")
        inspection["notarization_submission_id"] = notarization_submission_id.lower()
        embedded = object_value(inspection["release_input_attestation"], "embedded release-input attestation")
        if embedded.get("build_source_kind") != "tracked-git-object-export":
            fail("candidate was not built from the tracked Git-object export")
        if embedded.get("source_commit") != source_commit or embedded.get("source_tree") != source_tree:
            fail("signed app source commit/tree does not match the candidate record")
        installed_agent = object_value(
            inspection.get("system_extension"), "mounted system extension"
        )
        if installed_agent.get("bundle_version") != version \
                or installed_agent.get("build_version") != build_number:
            fail("mounted system-extension version/build does not match the candidate")
    else:
        fixture_agent = object_value(
            inspection.get("system_extension"), "fixture system extension"
        )
        fixture_agent["bundle_version"] = version
        fixture_agent["build_version"] = build_number
    return {
        "schema": CANDIDATE_SCHEMA,
        "created_at": utc_now(),
        "candidate": {
            "version": version,
            "build_number": build_number,
            "source_commit": source_commit,
            "source_tree": source_tree,
            "dmg": {
                "filename": dmg.name,
                "sha256": sha256_file(dmg),
                "size_bytes": dmg.stat().st_size,
            },
        },
        "artifact_verification": inspection,
    }


def validate_candidate_document(
    document: Mapping[str, Any],
    *,
    expected_version: str,
    expected_source_commit: str,
    expected_source_tree: str,
    expected_build_number: str,
    dmg: pathlib.Path,
    artifact_checks: str,
) -> Dict[str, Any]:
    if document.get("schema") != CANDIDATE_SCHEMA:
        fail(f"candidate.schema must be {CANDIDATE_SCHEMA}")
    parse_time(document.get("created_at"), "candidate.created_at")
    candidate = object_value(document.get("candidate"), "candidate")
    version = string_value(candidate.get("version"), "candidate.version")
    build_number = string_value(candidate.get("build_number"), "candidate.build_number")
    source_commit = require_object_id(candidate.get("source_commit"), "candidate.source_commit")
    source_tree = require_object_id(candidate.get("source_tree"), "candidate.source_tree")
    if version != expected_version:
        fail(f"candidate version {version!r} does not match requested {expected_version!r}")
    if source_commit != expected_source_commit or source_tree != expected_source_tree:
        fail("candidate source commit/tree does not match the release source")
    if build_number != expected_build_number:
        fail(
            f"candidate build number {build_number!r} does not match deterministic "
            f"release build {expected_build_number!r}"
        )
    if not BUILD_RE.fullmatch(build_number) or not build_number.startswith(version + "."):
        fail("candidate.build_number must be <version>.<positive commit count>")
    dmg_record = object_value(candidate.get("dmg"), "candidate.dmg")
    expected_filename = f"MacCrab-v{version}.dmg"
    if string_value(dmg_record.get("filename"), "candidate.dmg.filename") != expected_filename:
        fail(f"candidate DMG filename must be {expected_filename}")
    recorded_sha = require_sha(dmg_record.get("sha256"), "candidate.dmg.sha256")
    recorded_size = int_value(dmg_record.get("size_bytes"), "candidate.dmg.size_bytes", minimum=1)
    inspected = inspect_artifact(dmg, artifact_checks)
    if dmg.name != expected_filename or sha256_file(dmg) != recorded_sha or dmg.stat().st_size != recorded_size:
        fail("candidate manifest does not describe the exact DMG bytes supplied to the release")

    verification = object_value(document.get("artifact_verification"), "artifact_verification")
    recorded_level = string_value(verification.get("inspection_level"), "artifact_verification.inspection_level")
    if artifact_checks == "full":
        if recorded_level != "full":
            fail("public release requires a candidate manifest recorded with full artifact inspection")
        for key in ("codesign_verified", "stapled", "gatekeeper_accepted"):
            require_true(verification.get(key), f"artifact_verification.{key}")
        if verification.get("notarization_status") != "accepted":
            fail("artifact_verification.notarization_status must be accepted")
        notary_id = string_value(verification.get("notarization_submission_id"), "artifact_verification.notarization_submission_id")
        if not UUID_RE.fullmatch(notary_id):
            fail("artifact_verification.notarization_submission_id must be a UUID")
        if string_value(
            verification.get("developer_id"), "artifact_verification.developer_id"
        ) != EXPECTED_DEVELOPER_ID:
            fail("candidate manifest is not signed by the documented MacCrab Developer ID identity")
        if string_value(verification.get("team_id"), "artifact_verification.team_id") != EXPECTED_TEAM_ID:
            fail(f"candidate manifest Team ID is not {EXPECTED_TEAM_ID}")
        for key in (
            "developer_id",
            "team_id",
            "signing_identifier",
            "app_developer_id",
            "app_team_id",
            "app_signing_identifier",
        ):
            recorded_identity = string_value(
                verification.get(key), f"artifact_verification.{key}"
            )
            if inspected.get(key) != recorded_identity:
                fail("current DMG/app signing identity does not match the candidate manifest")
        if verification.get("app_developer_id") != EXPECTED_DEVELOPER_ID \
                or verification.get("app_team_id") != EXPECTED_TEAM_ID \
                or verification.get("app_signing_identifier") != EXPECTED_APP_IDENTIFIER:
            fail("candidate app identity does not match the documented MacCrab identity")
        recorded_agent = object_value(
            verification.get("system_extension"), "artifact_verification.system_extension"
        )
        inspected_agent = object_value(
            inspected.get("system_extension"), "inspected system extension"
        )
        require_maccrab_signing_identity(
            recorded_agent, expected_identifier=EXPECTED_AGENT_IDENTIFIER,
            path="artifact_verification.system_extension",
        )
        for key in (
            "developer_id", "team_id", "signing_identifier", "cdhash",
            "executable_sha256", "bundle_version", "build_version",
        ):
            if inspected_agent.get(key) != recorded_agent.get(key):
                fail("current mounted system extension does not match the candidate manifest")
        current_attestation = object_value(
            inspected.get("release_input_attestation"), "current signed release-input attestation"
        )
        if current_attestation.get("build_source_kind") != "tracked-git-object-export":
            fail("current signed app was not built from the tracked Git-object export")
        if current_attestation.get("source_commit") != expected_source_commit \
                or current_attestation.get("source_tree") != expected_source_tree:
            fail("current signed app does not bind the exact release source commit/tree")
        for key in ("release_input_attestation_sha256",):
            if inspected.get(key) != require_sha(verification.get(key), f"artifact_verification.{key}"):
                fail(f"current DMG {key} does not match the candidate manifest")
        recorded_inventory = object_value(verification.get("payload_inventory"), "artifact_verification.payload_inventory")
        inspected_inventory = object_value(inspected.get("payload_inventory"), "inspected payload inventory")
        if require_sha(recorded_inventory.get("sha256"), "artifact_verification.payload_inventory.sha256") != inspected_inventory.get("sha256"):
            fail("mounted DMG payload inventory changed since candidate recording")
    return dict(candidate)


def require_counter_equation(boundary: Mapping[str, Any], path: str) -> None:
    offered = int_value(boundary.get("offered"), f"{path}.offered")
    completed = int_value(boundary.get("completed"), f"{path}.completed")
    queued = int_value(boundary.get("queued"), f"{path}.queued")
    in_flight = int_value(boundary.get("in_flight"), f"{path}.in_flight")
    shed = int_value(boundary.get("explicitly_shed"), f"{path}.explicitly_shed")
    if offered != completed + queued + in_flight + shed:
        fail(f"{path} does not conserve: offered != completed + queued + in_flight + explicitly_shed")


def validate_installed_engine_identity(
    raw: Any,
    *,
    path: str,
    candidate: Mapping[str, Any],
    candidate_verification: Mapping[str, Any],
) -> Tuple[int, dt.datetime]:
    identity = object_value(raw, path)
    pid = int_value(identity.get("engine_pid"), f"{path}.engine_pid", minimum=1)
    recorded_at = parse_time(identity.get("recorded_at"), f"{path}.recorded_at")
    executable_path = string_value(identity.get("executable_path"), f"{path}.executable_path")
    if not executable_path.startswith("/Library/SystemExtensions/") \
            or not executable_path.endswith(
                "/com.maccrab.agent.systemextension/Contents/MacOS/com.maccrab.agent"
            ):
        fail(f"{path}.executable_path is not the installed MacCrab system extension")
    executable_sha = require_sha(identity.get("executable_sha256"), f"{path}.executable_sha256")
    require_maccrab_signing_identity(
        identity, expected_identifier=EXPECTED_AGENT_IDENTIFIER, path=path
    )
    cdhash = string_value(identity.get("cdhash"), f"{path}.cdhash")
    if not re.fullmatch(r"[0-9a-f]{40,64}", cdhash):
        fail(f"{path}.cdhash must be a lowercase code-directory hash")
    if identity.get("system_extension_bundle_identifier") != EXPECTED_AGENT_IDENTIFIER:
        fail(f"{path}.system_extension_bundle_identifier must be {EXPECTED_AGENT_IDENTIFIER}")
    if identity.get("bundle_version") != candidate.get("version"):
        fail(f"{path}.bundle_version does not match the candidate")
    if identity.get("build_version") != candidate.get("build_number"):
        fail(f"{path}.build_version does not match the candidate build")

    expected = object_value(
        candidate_verification.get("system_extension"),
        "artifact_verification.system_extension",
    )
    for key in (
        "developer_id", "team_id", "signing_identifier", "cdhash",
        "executable_sha256", "bundle_version", "build_version",
    ):
        if identity.get(key) != expected.get(key):
            fail(f"{path}.{key} does not match the mounted candidate system extension")
    if executable_sha != expected.get("executable_sha256"):
        fail(f"{path}.executable_sha256 does not match the candidate payload")

    inventory = object_value(
        candidate_verification.get("payload_inventory"),
        "artifact_verification.payload_inventory",
    )
    entries = list_value(
        inventory.get("entries"), "artifact_verification.payload_inventory.entries",
        nonempty=True,
    )
    agent_entries = [
        entry for entry in entries
        if isinstance(entry, dict) and entry.get("path") == AGENT_PAYLOAD_PATH
    ]
    if len(agent_entries) != 1 or agent_entries[0].get("sha256") != executable_sha:
        fail(f"{path} does not match the agent executable in the mounted payload inventory")
    return pid, recorded_at


def passing_test_count(output: str, label: str) -> int:
    counts = [
        int(value)
        for value in re.findall(
            r"Test run with\s+([0-9]+)\s+tests?\s+passed", output
        )
    ]
    if not counts:
        fail(f"{label} lacks a machine-readable passing Swift test summary")
    return max(counts)


def validate_live_reload_transcript(output: str, label: str) -> None:
    match = re.search(
        r"\[SIGHUP\] Reloaded\s+([0-9]+)\s+single\s+\+\s+"
        r"([0-9]+)\s+sequence rules",
        output,
    )
    if not match or int(match.group(1)) <= 0 or int(match.group(2)) <= 0:
        fail(f"{label} does not prove a completed non-empty rule reload")
    failed_sighup_line = any(
        "[sighup]" in line.lower()
        and re.search(
            r"\b(error|fail(?:ed|ure)?|ignored|ignoring|rejected|not admitted)\b",
            line,
            flags=re.IGNORECASE,
        )
        for line in output.splitlines()
    )
    if failed_sighup_line:
        fail(f"{label} records a rejected or failed live reload")


def validate_recorder_probe_evidence(raw: Any) -> None:
    evidence = object_value(raw, "runtime.recorder_probe_evidence")
    required = {
        "rule_lint", "focused_runtime_tests", "workload",
        "disk_diagnostic_log", "storage_convergence_log",
        "administrator_prompt_log", "rule_reload_log", "live_sighup",
    }
    if set(evidence) != required:
        fail("runtime recorder probe evidence inventory is incomplete or unknown")
    sighup = object_value(evidence.get("live_sighup"), "recorder probes.live_sighup")
    if set(sighup) != {"signal", "target_pid", "sample_offset_seconds", "sent_at"}:
        fail("runtime live rule-reload evidence has an incomplete inventory")
    if sighup.get("signal") != "SIGHUP" \
            or int_value(sighup.get("target_pid"), "recorder probes.live_sighup.target_pid", minimum=1) <= 0 \
            or int_value(sighup.get("sample_offset_seconds"), "recorder probes.live_sighup.sample_offset_seconds") != 450:
        fail("runtime live rule-reload evidence is not the fixed SIGHUP probe")
    parse_time(sighup.get("sent_at"), "recorder probes.live_sighup.sent_at")
    for name in sorted(required - {"live_sighup"}):
        row = object_value(evidence.get(name), f"recorder probes.{name}")
        if int_value(row.get("exit_code"), f"recorder probes.{name}.exit_code") != 0:
            fail(f"recorder probe {name} did not pass")
        require_sha(row.get("output_sha256"), f"recorder probes.{name}.output_sha256")
        command = list_value(
            row.get("command"), f"recorder probes.{name}.command", nonempty=True
        )
        int_value(
            row.get("output_line_count"),
            f"recorder probes.{name}.output_line_count",
        )
        output_tail = string_value(
            row.get("output_tail"),
            f"recorder probes.{name}.output_tail",
            nonempty=False,
        )
        if "output" in row:
            full_output = string_value(
                row.get("output"), f"recorder probes.{name}.output", nonempty=False
            )
            if sha256_bytes(full_output.encode("utf-8")) != row.get("output_sha256") \
                    or len(full_output.splitlines()) != row.get("output_line_count") \
                    or full_output[-4096:] != output_tail:
                fail(f"recorder probe {name} transcript metadata does not reconcile")
        else:
            full_output = output_tail
        if name == "focused_runtime_tests":
            if FOCUSED_RUNTIME_TEST_FILTER not in command:
                fail("focused runtime evidence does not use the fixed test filter")
            recorded_count = int_value(
                row.get("observed_test_count"),
                "recorder probes.focused_runtime_tests.observed_test_count",
                minimum=1,
            )
            if recorded_count != passing_test_count(
                output_tail, "focused runtime evidence"
            ):
                fail("focused runtime test count does not match its output")
        if name == "rule_lint" \
                and not any(str(part).endswith("scripts/rule-lint.sh") for part in command):
            fail("rule-lint evidence does not invoke the fixed rule linter")
        if name == "workload" \
                and not any(str(part).endswith("scripts/runtime-qualification-workload.sh") for part in command):
            fail("workload evidence does not invoke the fixed workload")
        if name == "rule_reload_log":
            if "output" not in row:
                fail("live rule-reload evidence must embed the complete log transcript")
            validate_live_reload_transcript(full_output, "live rule-reload evidence")


def validate_runtime_report(
    report: Mapping[str, Any],
    *,
    candidate_manifest_sha256: str,
    candidate: Mapping[str, Any],
    candidate_verification: Mapping[str, Any],
    payload_inventory_sha256: str,
    source_root: pathlib.Path,
    allow_test_fixture: bool = False,
) -> None:
    if report.get("schema") != RUNTIME_SCHEMA:
        fail(f"runtime.schema must be {RUNTIME_SCHEMA}")
    if report.get("result") != "pass":
        fail("runtime.result must be pass")
    report_evidence = object_value(report.get("evidence"), "runtime.evidence")
    capture_mode = string_value(
        report_evidence.get("capture_mode"), "runtime.evidence.capture_mode"
    )
    if capture_mode != "live-installed-root" \
            and not (allow_test_fixture and capture_mode == "deterministic-fixture"):
        fail("release verification requires a live installed-root runtime capture")
    validate_recorder_probe_evidence(report.get("recorder_probe_evidence"))
    if require_sha(report.get("candidate_manifest_sha256"), "runtime.candidate_manifest_sha256") != candidate_manifest_sha256:
        fail("runtime report does not bind the exact candidate manifest")
    binding = object_value(report.get("candidate"), "runtime.candidate")
    for key in ("version", "build_number", "source_commit", "source_tree"):
        if binding.get(key) != candidate.get(key):
            fail(f"runtime.candidate.{key} does not match the release candidate")
    expected_dmg = object_value(candidate.get("dmg"), "candidate.dmg")
    runtime_dmg = object_value(binding.get("dmg"), "runtime.candidate.dmg")
    for key in ("filename", "sha256", "size_bytes"):
        if runtime_dmg.get(key) != expected_dmg.get(key):
            fail(f"runtime.candidate.dmg.{key} does not match the exact candidate")

    host = object_value(report.get("host"), "runtime.host")
    require_sha(host.get("machine_id_sha256"), "runtime.host.machine_id_sha256")
    for key in ("hardware_model", "architecture", "macos_version", "macos_build", "power_source"):
        string_value(host.get(key), f"runtime.host.{key}")
    int_value(host.get("logical_cpu_count"), "runtime.host.logical_cpu_count", minimum=1)
    int_value(host.get("memory_bytes"), "runtime.host.memory_bytes", minimum=1)
    require_true(host.get("sip_enabled"), "runtime.host.sip_enabled")
    require_true(host.get("amfi_enforced"), "runtime.host.amfi_enforced")

    workload = object_value(report.get("workload"), "runtime.workload")
    for key in ("id", "version", "description"):
        string_value(workload.get(key), f"runtime.workload.{key}")
    recorded_workload_sha = require_sha(workload.get("sha256"), "runtime.workload.sha256")
    normal_operations = list_value(workload.get("normal_operations"), "runtime.workload.normal_operations", nonempty=True)
    burst_operations = list_value(workload.get("burst_operations"), "runtime.workload.burst_operations", nonempty=True)
    executor_rows = list_value(
        workload.get("executors"), "runtime.workload.executors", nonempty=True
    )
    observed_executors: List[str] = []
    for index, raw_executor in enumerate(executor_rows):
        executor = object_value(raw_executor, f"runtime.workload.executors[{index}]")
        if set(executor) != {"path", "sha256"}:
            fail("runtime workload executor inventory is incomplete or unknown")
        relative = string_value(
            executor.get("path"), f"runtime.workload.executors[{index}].path"
        )
        observed_executors.append(relative)
        path = source_root / relative
        if path.is_symlink() or not path.is_file():
            fail(f"runtime workload executor is missing or redirected: {relative}")
        if require_sha(
            executor.get("sha256"), f"runtime.workload.executors[{index}].sha256"
        ) != sha256_file(path):
            fail(f"runtime workload executor bytes changed: {relative}")
    if tuple(observed_executors) != RUNTIME_WORKLOAD_EXECUTORS:
        fail("runtime workload does not bind the exact transitive executor inventory")
    workload_payload = {
        "id": workload.get("id"),
        "version": workload.get("version"),
        "description": workload.get("description"),
        "normal_operations": normal_operations,
        "burst_operations": burst_operations,
        "executors": executor_rows,
    }
    if recorded_workload_sha != sha256_bytes(canonical_json_bytes(workload_payload)):
        fail("runtime.workload.sha256 does not bind the recorded workload fields")

    epoch = object_value(report.get("epoch"), "runtime.epoch")
    started = parse_time(epoch.get("started_at"), "runtime.epoch.started_at")
    ended = parse_time(epoch.get("ended_at"), "runtime.epoch.ended_at")
    elapsed = (ended - started).total_seconds()
    duration = number_value(epoch.get("duration_seconds"), "runtime.epoch.duration_seconds", minimum=MIN_EPOCH_SECONDS)
    if abs(elapsed - duration) > 1.0:
        fail("runtime epoch timestamps and duration_seconds disagree")
    installed = object_value(report.get("installed_engine"), "runtime.installed_engine")
    installed_start_identity = object_value(
        installed.get("start"), "runtime.installed_engine.start"
    )
    installed_end_identity = object_value(
        installed.get("end"), "runtime.installed_engine.end"
    )
    installed_start_pid, installed_start_at = validate_installed_engine_identity(
        installed_start_identity, path="runtime.installed_engine.start",
        candidate=candidate, candidate_verification=candidate_verification,
    )
    installed_end_pid, installed_end_at = validate_installed_engine_identity(
        installed_end_identity, path="runtime.installed_engine.end",
        candidate=candidate, candidate_verification=candidate_verification,
    )
    if installed_start_pid != installed_end_pid:
        fail("installed engine identity changed PID during the qualification epoch")
    if abs((installed_start_at - started).total_seconds()) > MAX_SAMPLE_GAP_SECONDS:
        fail("installed engine start identity was not recorded at the epoch boundary")
    if abs((installed_end_at - ended).total_seconds()) > MAX_SAMPLE_GAP_SECONDS:
        fail("installed engine end identity was not recorded at the epoch boundary")
    require_true(epoch.get("uninterrupted"), "runtime.epoch.uninterrupted")
    sample_interval = number_value(epoch.get("sample_interval_seconds"), "runtime.epoch.sample_interval_seconds", minimum=0.1)
    max_gap = number_value(epoch.get("max_sample_gap_seconds"), "runtime.epoch.max_sample_gap_seconds", minimum=sample_interval)
    if max_gap > MAX_SAMPLE_GAP_SECONDS:
        fail(f"runtime sample gap {max_gap} exceeds {MAX_SAMPLE_GAP_SECONDS} seconds")
    sample_count = int_value(epoch.get("sample_count"), "runtime.epoch.sample_count", minimum=2)
    minimum_samples = math.floor(duration / MAX_SAMPLE_GAP_SECONDS) + 1
    if sample_count < minimum_samples:
        fail(f"runtime.epoch.sample_count is too small to cover the full interval (need >= {minimum_samples})")
    require_sha(epoch.get("samples_sha256"), "runtime.epoch.samples_sha256")

    samples = list_value(report.get("samples"), "runtime.samples", nonempty=True)
    if len(samples) != sample_count:
        fail("runtime sample_count does not equal the embedded sample count")
    samples_sha = sha256_bytes(canonical_json_bytes(samples))
    if samples_sha != epoch.get("samples_sha256"):
        fail("runtime samples_sha256 does not match the embedded full-interval samples")
    observations = list_value(
        report.get("recorder_observations"),
        "runtime.recorder_observations",
        nonempty=True,
    )
    if len(observations) != len(samples):
        fail("runtime recorder observation count does not match the sample count")
    normalized_observations = [
        sample_from_recorder_observation(
            observation, f"runtime.recorder_observations[{index}]"
        )
        for index, observation in enumerate(observations)
    ]
    if normalized_observations != samples:
        fail("runtime samples do not match the raw recorder observations")
    for index, observation in enumerate(observations):
        heartbeat = object_value(
            object_value(
                observation, f"runtime.recorder_observations[{index}]"
            ).get("heartbeat"),
            f"runtime.recorder_observations[{index}].heartbeat",
        )
        if heartbeat.get("engine_version") != candidate.get("version") \
                or heartbeat.get("engine_build") != candidate.get("build_number"):
            fail("raw runtime heartbeat is not from the exact candidate version/build")
        process = object_value(
            object_value(
                observation, f"runtime.recorder_observations[{index}]"
            ).get("process"),
            f"runtime.recorder_observations[{index}].process",
        )
        if process.get("executable_path") != installed_start_identity.get("executable_path") \
                or process.get("executable_sha256") != installed_start_identity.get("executable_sha256"):
            fail("raw runtime process sample is not the installed candidate executable")
    prior_offset: float | None = None
    observed_gap = 0.0
    observed_pids = set()
    sample_cpu_totals: List[float] = []
    sample_write_totals: List[int] = []
    sample_offsets: List[float] = []
    sample_rss_values: List[int] = []
    sample_gui_values: List[float] = []
    sample_sequence_evictions: List[int] = []
    sample_journal_shed: List[int] = []
    rss_by_offset: Dict[int, int] = {}
    for index, raw_sample in enumerate(samples):
        path = f"runtime.samples[{index}]"
        sample = object_value(raw_sample, path)
        offset = number_value(sample.get("offset_seconds"), f"{path}.offset_seconds", minimum=0)
        sample_time = parse_time(sample.get("recorded_at"), f"{path}.recorded_at")
        expected_sample_time = started + dt.timedelta(seconds=offset)
        if abs((sample_time - expected_sample_time).total_seconds()) > 1.0:
            fail(f"{path}.recorded_at does not equal epoch start + offset_seconds")
        pid = int_value(sample.get("engine_pid"), f"{path}.engine_pid", minimum=1)
        observed_pids.add(pid)
        cpu_total = number_value(
            sample.get("engine_cpu_seconds_total"), f"{path}.engine_cpu_seconds_total", minimum=0
        )
        write_total = int_value(
            sample.get("engine_disk_write_bytes_total"), f"{path}.engine_disk_write_bytes_total"
        )
        rss = int_value(sample.get("engine_rss_bytes"), f"{path}.engine_rss_bytes")
        gui_cpu = number_value(
            sample.get("gui_background_cpu_percent"), f"{path}.gui_background_cpu_percent", minimum=0
        )
        sample_cpu_totals.append(cpu_total)
        sample_write_totals.append(write_total)
        sample_offsets.append(offset)
        sample_rss_values.append(rss)
        sample_gui_values.append(gui_cpu)
        sample_sequence_evictions.append(
            int_value(
                sample.get("sequence_pending_steps_evicted_total"),
                f"{path}.sequence_pending_steps_evicted_total",
            )
        )
        object_value(sample.get("llm_quality"), f"{path}.llm_quality")
        require_true(
            sample.get("sequence_state_continuity_maintained"),
            f"{path}.sequence_state_continuity_maintained",
        )
        if string_value(
            sample.get("sequence_state_continuity_detail"),
            f"{path}.sequence_state_continuity_detail",
        ) != "nominal":
            fail(f"{path} reports a recent sequence continuity fault")
        if abs(offset - round(offset)) <= 0.001:
            rss_by_offset[int(round(offset))] = rss
        sample_boundaries = object_value(sample.get("conservation"), f"{path}.conservation")
        if set(sample_boundaries) != REQUIRED_CONSERVATION_BOUNDARIES:
            fail(f"{path}.conservation does not contain the complete boundary inventory")
        for boundary_name in sorted(REQUIRED_CONSERVATION_BOUNDARIES):
            require_counter_equation(
                object_value(sample_boundaries.get(boundary_name), f"{path}.conservation.{boundary_name}"),
                f"{path}.conservation.{boundary_name}",
            )
        sample_journal_shed.append(int_value(
            object_value(
                sample_boundaries.get("sequence-journal"),
                f"{path}.conservation.sequence-journal",
            ).get("explicitly_shed"),
            f"{path}.conservation.sequence-journal.explicitly_shed",
        ))
        sample_losses = object_value(sample.get("losses"), f"{path}.losses")
        for loss_name in (
            "priority_lane_loss",
            "kernel_loss",
            "callback_copy_loss",
            "upstream_collector_loss",
            "unclassified_file_queue_loss",
        ):
            require_zero(sample_losses.get(loss_name), f"{path}.losses.{loss_name}")
        if prior_offset is None:
            if abs(offset) > 0.001:
                fail("the first runtime sample must be at offset zero")
        else:
            gap = offset - prior_offset
            if gap <= 0:
                fail("runtime sample offsets must be strictly increasing")
            observed_gap = max(observed_gap, gap)
        prior_offset = offset
    if prior_offset is None or abs(prior_offset - duration) > 1.0:
        fail("runtime samples do not cover the full reported epoch")
    if abs(observed_gap - max_gap) > 0.001:
        fail("runtime max_sample_gap_seconds does not reconcile with embedded samples")
    if any(later < earlier for earlier, later in zip(sample_cpu_totals, sample_cpu_totals[1:])):
        fail("engine CPU cumulative samples moved backwards")
    if any(later < earlier for earlier, later in zip(sample_write_totals, sample_write_totals[1:])):
        fail("engine disk-write cumulative samples moved backwards")

    metrics = object_value(report.get("measurements"), "runtime.measurements")
    process = object_value(metrics.get("process"), "runtime.measurements.process")
    pids = list_value(process.get("engine_pids"), "runtime.measurements.process.engine_pids", nonempty=True)
    if len(pids) != 1 or not isinstance(pids[0], int) or pids[0] <= 0:
        fail("runtime epoch must contain exactly one positive engine PID")
    if pids[0] != installed_start_pid:
        fail("runtime process PID does not match the installed candidate identity")
    if observed_pids != {pids[0]}:
        fail("embedded runtime samples observed more than one engine PID")
    for key in ("crash_count", "watchdog_exit_count", "relaunch_count"):
        require_zero(process.get(key), f"runtime.measurements.process.{key}")

    conservation = object_value(metrics.get("conservation"), "runtime.measurements.conservation")
    require_true(conservation.get("all_samples_reconciled"), "runtime.measurements.conservation.all_samples_reconciled")
    boundaries = list_value(conservation.get("boundaries"), "runtime.measurements.conservation.boundaries", nonempty=True)
    names = set()
    for index, raw_boundary in enumerate(boundaries):
        path = f"runtime.measurements.conservation.boundaries[{index}]"
        boundary = object_value(raw_boundary, path)
        name = string_value(boundary.get("name"), f"{path}.name")
        if name in names:
            fail(f"duplicate conservation boundary: {name}")
        names.add(name)
        require_counter_equation(boundary, path)
    if names != REQUIRED_CONSERVATION_BOUNDARIES:
        missing = sorted(REQUIRED_CONSERVATION_BOUNDARIES - names)
        extra = sorted(names - REQUIRED_CONSERVATION_BOUNDARIES)
        fail(f"conservation boundary inventory is incomplete or unknown (missing={missing}, extra={extra})")
    last_sample_boundaries = object_value(
        object_value(samples[-1], "runtime.samples[-1]").get("conservation"),
        "runtime.samples[-1].conservation",
    )
    aggregate_boundaries = {
        string_value(object_value(row, "aggregate boundary").get("name"), "aggregate boundary.name"):
        {key: object_value(row, "aggregate boundary").get(key) for key in (
            "offered", "completed", "queued", "in_flight", "explicitly_shed"
        )}
        for row in boundaries
    }
    if aggregate_boundaries != last_sample_boundaries:
        fail("aggregate conservation boundaries do not match the final raw sample")
    first_sample_boundaries = object_value(
        object_value(samples[0], "runtime.samples[0]").get("conservation"),
        "runtime.samples[0].conservation",
    )
    for lane in ("priority", "file"):
        boundary_name = f"{lane}-event-persistence"
        first_shed = int_value(
            object_value(
                first_sample_boundaries.get(boundary_name), boundary_name
            ).get("explicitly_shed"),
            f"{boundary_name}.explicitly_shed start",
        )
        last_shed = int_value(
            object_value(
                last_sample_boundaries.get(boundary_name), boundary_name
            ).get("explicitly_shed"),
            f"{boundary_name}.explicitly_shed end",
        )
        if last_shed != first_shed:
            fail(f"{lane} event persistence shed during the qualification epoch")

    priority = object_value(metrics.get("priority_fidelity"), "runtime.measurements.priority_fidelity")
    for key in ("priority_lane_loss", "kernel_loss", "callback_copy_loss", "upstream_collector_loss"):
        require_zero(priority.get(key), f"runtime.measurements.priority_fidelity.{key}")

    file_fidelity = object_value(metrics.get("file_fidelity"), "runtime.measurements.file_fidelity")
    require_zero(file_fidelity.get("unclassified_queue_loss"), "runtime.measurements.file_fidelity.unclassified_queue_loss")
    require_true(file_fidelity.get("complete_rule_corpus_evaluated"), "runtime.measurements.file_fidelity.complete_rule_corpus_evaluated")
    require_sha(file_fidelity.get("rule_corpus_sha256"), "runtime.measurements.file_fidelity.rule_corpus_sha256")
    reasons = list_value(file_fidelity.get("semantic_reasons"), "runtime.measurements.file_fidelity.semantic_reasons")
    for index, raw_reason in enumerate(reasons):
        reason = object_value(raw_reason, f"runtime.measurements.file_fidelity.semantic_reasons[{index}]")
        string_value(reason.get("reason"), f"semantic_reasons[{index}].reason")
        int_value(reason.get("count"), f"semantic_reasons[{index}].count")
        string_value(reason.get("test_id"), f"semantic_reasons[{index}].test_id")
        require_true(reason.get("conservative_against_rule_corpus"), f"semantic_reasons[{index}].conservative_against_rule_corpus")

    correlation = object_value(metrics.get("correlation_continuity"), "runtime.measurements.correlation_continuity")
    coverage = number_value(correlation.get("recovery_coverage_seconds"), "runtime.measurements.correlation_continuity.recovery_coverage_seconds", minimum=0)
    if coverage < MIN_EPOCH_SECONDS:
        fail("correlation recovery coverage is below 900 seconds")
    require_zero(correlation.get("checkpoint_shed"), "runtime.measurements.correlation_continuity.checkpoint_shed")
    eviction_delta = sample_sequence_evictions[-1] - sample_sequence_evictions[0]
    journal_shed_delta = sample_journal_shed[-1] - sample_journal_shed[0]
    if eviction_delta < 0 or journal_shed_delta < 0:
        fail("sequence pending-step conservation counters moved backwards")
    recorded_journal_shed = int_value(
        correlation.get("journal_shed"),
        "runtime.measurements.correlation_continuity.journal_shed",
    )
    recorded_eviction_delta = int_value(
        correlation.get("pending_later_step_evictions_epoch_delta"),
        "runtime.measurements.correlation_continuity.pending_later_step_evictions_epoch_delta",
    )
    if recorded_journal_shed != journal_shed_delta \
            or journal_shed_delta != eviction_delta \
            or recorded_eviction_delta != eviction_delta:
        fail("sequence journal shed does not reconcile with pending-step evictions")
    if eviction_delta != 0:
        fail("sequence pending-later-step evictions must remain zero across the epoch")
    require_zero(
        recorded_journal_shed,
        "runtime.measurements.correlation_continuity.journal_shed",
    )
    require_true(
        correlation.get("sequence_state_continuity_maintained_all_samples"),
        "runtime.measurements.correlation_continuity.sequence_state_continuity_maintained_all_samples",
    )
    probe_evidence = object_value(
        report.get("recorder_probe_evidence"), "runtime.recorder_probe_evidence"
    )
    focused_evidence = object_value(
        probe_evidence.get("focused_runtime_tests"),
        "runtime.recorder_probe_evidence.focused_runtime_tests",
    )
    if require_sha(
        correlation.get("source_bound_continuity_tests_sha256"),
        "runtime.measurements.correlation_continuity.source_bound_continuity_tests_sha256",
    ) != require_sha(
        focused_evidence.get("output_sha256"),
        "runtime.recorder_probe_evidence.focused_runtime_tests.output_sha256",
    ):
        fail("correlation continuity does not bind the source-test transcript")
    reload_signal = object_value(
        correlation.get("live_rule_reload_signal"),
        "runtime.measurements.correlation_continuity.live_rule_reload_signal",
    )
    recorded_reload_signal = object_value(
        probe_evidence.get("live_sighup"),
        "runtime.recorder_probe_evidence.live_sighup",
    )
    if reload_signal != recorded_reload_signal:
        fail("live rule-reload signal does not reconcile with recorder evidence")
    if int_value(reload_signal.get("target_pid"), "live reload target PID") \
            != installed_start_pid:
        fail("live rule-reload signal targeted a different engine PID")
    reload_at = parse_time(reload_signal.get("sent_at"), "live reload sent_at")
    expected_reload_at = started + dt.timedelta(
        seconds=int_value(
            reload_signal.get("sample_offset_seconds"), "live reload sample offset"
        )
    )
    if abs((reload_at - expected_reload_at).total_seconds()) > 5.0:
        fail("live rule-reload signal was not sent at its recorded epoch offset")
    if not any(
        number_value(object_value(sample, "runtime sample").get("offset_seconds"), "runtime sample offset")
        > reload_signal["sample_offset_seconds"]
        and object_value(sample, "runtime sample").get("engine_pid") == installed_start_pid
        for sample in samples
    ):
        fail("no later sample proves the engine survived the live reload signal")

    storage = object_value(metrics.get("event_storage"), "runtime.measurements.event_storage")
    for key in ("unreachable_budget_fault_count", "prune_vacuum_refill_loop_count"):
        require_zero(storage.get(key), f"runtime.measurements.event_storage.{key}")
    require_true(storage.get("search_tier_gaps_reconcile_exactly"), "runtime.measurements.event_storage.search_tier_gaps_reconcile_exactly")
    require_true(storage.get("search_tier_gaps_visible"), "runtime.measurements.event_storage.search_tier_gaps_visible")
    observed_budget_faults = sum(
        1
        for observation in observations
        if object_value(observation, "recorder observation").get("event_budget_fault") is True
    )
    if storage.get("unreachable_budget_fault_count") != observed_budget_faults:
        fail("event-storage budget faults do not reconcile with recorder observations")

    trace = object_value(metrics.get("trace_graph"), "runtime.measurements.trace_graph")
    writable = number_value(trace.get("writable_duty_fraction"), "runtime.measurements.trace_graph.writable_duty_fraction", minimum=0)
    observed_writable = sum(
        1
        for observation in observations
        if object_value(observation, "recorder observation").get("trace_writable") is True
    ) / len(observations)
    if abs(writable - observed_writable) > 0.000001:
        fail("TraceGraph writable duty does not reconcile with recorder observations")
    if writable < MIN_TRACE_WRITABLE_DUTY or writable > 1:
        fail("TraceGraph writable duty must be between 0.99 and 1.0")
    first_trace_shed = int_value(
        object_value(observations[0], "first recorder observation").get("trace_shed_mutations_total"),
        "first recorder trace shed",
    )
    last_trace_shed = int_value(
        object_value(observations[-1], "last recorder observation").get("trace_shed_mutations_total"),
        "last recorder trace shed",
    )
    if last_trace_shed < first_trace_shed \
            or trace.get("mutation_shed") != last_trace_shed - first_trace_shed:
        fail("TraceGraph mutation shed does not reconcile with recorder observations")
    require_zero(trace.get("mutation_shed"), "runtime.measurements.trace_graph.mutation_shed")
    require_zero(trace.get("recovery_oscillation_count"), "runtime.measurements.trace_graph.recovery_oscillation_count")
    graph_ingest_shed_delta = int_value(
        object_value(last_sample_boundaries.get("trace-graph-mutation"), "last TraceGraph ingest").get("explicitly_shed"),
        "last TraceGraph ingest shed",
    ) - int_value(
        object_value(first_sample_boundaries.get("trace-graph-mutation"), "first TraceGraph ingest").get("explicitly_shed"),
        "first TraceGraph ingest shed",
    )
    require_zero(graph_ingest_shed_delta, "TraceGraph ingest shed epoch delta")
    graph_rows = [
        trace_graph_write_accounting_sample(
            object_value(
                object_value(sample, "runtime sample").get(
                    "trace_graph_write_accounting"
                ),
                "runtime sample.trace_graph_write_accounting",
            ),
            "runtime sample.trace_graph_write_accounting",
        )
        for sample in samples
    ]
    graph_cumulative_keys = (
        "write_attempts_total", "write_batches_committed_total",
        "write_batches_failed_total", "write_rows_attempted_total",
        "write_rows_committed_total", "write_rows_failed_total",
        "entity_observations_total", "edge_observations_total",
        "coalesced_noop_rows_total",
    )
    for key in graph_cumulative_keys:
        values = [int_value(row.get(key), f"TraceGraph {key}") for row in graph_rows]
        if any(later < earlier for earlier, later in zip(values, values[1:])):
            fail(f"TraceGraph {key} counter reset during the epoch")
    graph_coalesced_delta = (
        graph_rows[-1]["coalesced_noop_rows_total"]
        - graph_rows[0]["coalesced_noop_rows_total"]
    )
    graph_failed_batches_delta = (
        graph_rows[-1]["write_batches_failed_total"]
        - graph_rows[0]["write_batches_failed_total"]
    )
    graph_failed_rows_delta = (
        graph_rows[-1]["write_rows_failed_total"]
        - graph_rows[0]["write_rows_failed_total"]
    )
    expected_trace_graph = {
        "writable_duty_fraction": writable,
        "mutation_shed": last_trace_shed - first_trace_shed,
        "recovery_oscillation_count": trace.get("recovery_oscillation_count"),
        "write_accounting_reconciled_all_samples": True,
        "coalesced_noop_rows_epoch_delta": graph_coalesced_delta,
        "failed_batches_epoch_delta": graph_failed_batches_delta,
        "failed_rows_epoch_delta": graph_failed_rows_delta,
    }
    if trace != expected_trace_graph:
        fail("TraceGraph aggregate does not reconcile with exact write ledgers")
    require_zero(
        graph_failed_batches_delta,
        "runtime.measurements.trace_graph.failed_batches_epoch_delta",
    )
    require_zero(
        graph_failed_rows_delta,
        "runtime.measurements.trace_graph.failed_rows_epoch_delta",
    )

    trace_store = object_value(
        metrics.get("trace_store"), "runtime.measurements.trace_store"
    )
    trace_store_rows = [
        trace_store_admission_sample(
            object_value(
                object_value(sample, "runtime sample").get(
                    "trace_store_admission"
                ),
                "runtime sample.trace_store_admission",
            ),
            "runtime sample.trace_store_admission",
        )
        for sample in samples
    ]
    for index, row in enumerate(trace_store_rows):
        if row["enabled"] is not True or row["store_available"] is not True \
                or row["blocked"] is not False or row["recovering"] is not False:
            fail(f"TraceStore was not a full writable store at sample {index}")
    for key in (
        "max_footprint_bytes", "admission_threshold_bytes",
        "transaction_reserve_bytes", "free_space_floor_bytes",
    ):
        if len({row[key] for row in trace_store_rows}) != 1:
            fail(f"TraceStore {key} policy changed during the epoch")
    observed_trace_store_duty = sum(
        1 for row in trace_store_rows
        if row["enabled"] is True and row["store_available"] is True
        and row["blocked"] is False and row["recovering"] is False
    ) / len(trace_store_rows)
    expected_trace_store = {
        "full_writer_duty_fraction": observed_trace_store_duty,
        "max_footprint_bytes": max(row["footprint_bytes"] for row in trace_store_rows),
        "minimum_free_space_bytes": min(row["free_space_bytes"] for row in trace_store_rows),
    }
    if trace_store != expected_trace_store or observed_trace_store_duty != 1.0:
        fail("TraceStore aggregate does not prove a full writer for every sample")

    workload_ingress = object_value(
        metrics.get("workload_ingress"), "runtime.measurements.workload_ingress"
    )
    expected_workload_ingress = derive_workload_ingress(samples)
    if workload_ingress != expected_workload_ingress:
        fail("workload ingress aggregate does not reconcile with raw counters")

    writes = object_value(metrics.get("disk_writes"), "runtime.measurements.disk_writes")
    engine_bytes = int_value(writes.get("engine_bytes"), "runtime.measurements.disk_writes.engine_bytes")
    observed_engine_bytes = sample_write_totals[-1] - sample_write_totals[0]
    if engine_bytes != observed_engine_bytes:
        fail("disk write aggregate does not reconcile with cumulative full-interval samples")
    average_bps = engine_bytes / duration
    recorded_average = number_value(writes.get("average_bytes_per_second"), "runtime.measurements.disk_writes.average_bytes_per_second", minimum=0)
    if abs(recorded_average - average_bps) > max(1.0, average_bps * 0.001):
        fail("disk write average does not reconcile with engine_bytes / full epoch")
    if average_bps > MAX_ENGINE_WRITE_BYTES_PER_SECOND:
        fail("engine disk write average exceeds 1 MiB/s")
    windows = list_value(writes.get("windows"), "runtime.measurements.disk_writes.windows", nonempty=True)
    if len(windows) != len(samples) - 1:
        fail("disk write windows must contain one interval between every pair of raw samples")
    window_bytes_total = 0
    for index, raw_window in enumerate(windows):
        path = f"runtime.measurements.disk_writes.windows[{index}]"
        window = object_value(raw_window, path)
        start = number_value(window.get("start_offset_seconds"), f"{path}.start_offset_seconds", minimum=0)
        end = number_value(window.get("end_offset_seconds"), f"{path}.end_offset_seconds", minimum=0)
        byte_count = int_value(window.get("bytes"), f"{path}.bytes")
        expected_start = sample_offsets[index]
        expected_end = sample_offsets[index + 1]
        expected_bytes = sample_write_totals[index + 1] - sample_write_totals[index]
        if abs(start - expected_start) > 0.001 \
                or abs(end - expected_end) > 0.001 \
                or byte_count != expected_bytes:
            fail("disk write windows do not reconcile with cumulative samples")
        if end <= start or end - start > 60.001:
            fail("disk write sample intervals must be positive and at most 60 seconds")
        if byte_count / (end - start) > MAX_WINDOW_WRITE_BYTES_PER_SECOND:
            fail(f"disk write window {index} exceeds 4 MiB/s")
        window_bytes_total += byte_count
    if abs(sample_offsets[-1] - duration) > 1.0 or window_bytes_total != engine_bytes:
        fail("disk write windows do not cover/reconcile the complete epoch")
    for start_index, start_offset in enumerate(sample_offsets[:-1]):
        for end_index in range(start_index + 1, len(sample_offsets)):
            span = sample_offsets[end_index] - start_offset
            if span > 60.001:
                break
            rolling_bytes = sample_write_totals[end_index] - sample_write_totals[start_index]
            if rolling_bytes / span > MAX_WINDOW_WRITE_BYTES_PER_SECOND:
                fail("cumulative raw samples exceed the 4 MiB/s rolling 60-second disk-write limit")
    require_zero(writes.get("macos_disk_writes_diagnostic_count"), "runtime.measurements.disk_writes.macos_disk_writes_diagnostic_count")

    cpu = object_value(metrics.get("cpu"), "runtime.measurements.cpu")
    cpu_seconds = number_value(cpu.get("engine_cpu_seconds"), "runtime.measurements.cpu.engine_cpu_seconds", minimum=0)
    observed_cpu_seconds = sample_cpu_totals[-1] - sample_cpu_totals[0]
    if abs(cpu_seconds - observed_cpu_seconds) > 0.001:
        fail("CPU aggregate does not reconcile with cumulative full-interval samples")
    average_cores = cpu_seconds / duration
    recorded_cores = number_value(cpu.get("engine_average_cores"), "runtime.measurements.cpu.engine_average_cores", minimum=0)
    if abs(recorded_cores - average_cores) > 0.001 or average_cores > MAX_ENGINE_AVERAGE_CORES:
        fail("engine CPU average does not reconcile or exceeds 0.50 core")
    gui_samples = [
        number_value(value, f"runtime.measurements.cpu.gui_background_percent_samples[{index}]", minimum=0)
        for index, value in enumerate(list_value(cpu.get("gui_background_percent_samples"), "runtime.measurements.cpu.gui_background_percent_samples", nonempty=True))
    ]
    gui_p95 = percentile_nearest_rank(gui_samples, 0.95)
    if gui_samples != sample_gui_values:
        fail("GUI CPU samples do not match the embedded full-interval samples")
    recorded_p95 = number_value(cpu.get("gui_background_p95_percent"), "runtime.measurements.cpu.gui_background_p95_percent", minimum=0)
    if abs(recorded_p95 - gui_p95) > 0.001 or gui_p95 > MAX_GUI_P95_PERCENT:
        fail("background GUI p95 does not reconcile or exceeds 10% of one core")

    memory = object_value(metrics.get("memory"), "runtime.measurements.memory")
    max_rss = int_value(memory.get("engine_max_rss_bytes"), "runtime.measurements.memory.engine_max_rss_bytes")
    minute5 = int_value(memory.get("engine_rss_minute_5_bytes"), "runtime.measurements.memory.engine_rss_minute_5_bytes")
    minute15 = int_value(memory.get("engine_rss_minute_15_bytes"), "runtime.measurements.memory.engine_rss_minute_15_bytes")
    if max_rss != max(sample_rss_values):
        fail("maximum RSS does not reconcile with the embedded full-interval samples")
    if rss_by_offset.get(300) != minute5 or rss_by_offset.get(900) != minute15:
        fail("runtime samples must include and reconcile exact minute-5/minute-15 RSS")
    if max_rss > MAX_ENGINE_RSS_BYTES:
        fail("engine RSS exceeds 450 MiB")
    if minute15 - minute5 > MAX_ENGINE_RSS_GROWTH_BYTES:
        fail("engine RSS growth from minute 5 to minute 15 exceeds 64 MiB")

    disk_safety = object_value(metrics.get("disk_safety"), "runtime.measurements.disk_safety")
    require_true(disk_safety.get("inventory_complete"), "runtime.measurements.disk_safety.inventory_complete")
    families = list_value(disk_safety.get("sqlite_families"), "runtime.measurements.disk_safety.sqlite_families", nonempty=True)
    family_names = set()
    for index, raw_family in enumerate(families):
        path = f"runtime.measurements.disk_safety.sqlite_families[{index}]"
        family = object_value(raw_family, path)
        name = string_value(family.get("name"), f"{path}.name")
        if name in family_names:
            fail(f"duplicate SQLite family: {name}")
        family_names.add(name)
        maximum = int_value(family.get("max_db_wal_shm_bytes"), f"{path}.max_db_wal_shm_bytes")
        cap = int_value(family.get("configured_cap_bytes"), f"{path}.configured_cap_bytes", minimum=1)
        minimum_free = int_value(family.get("minimum_free_space_bytes"), f"{path}.minimum_free_space_bytes")
        configured_floor = int_value(family.get("configured_free_space_floor_bytes"), f"{path}.configured_free_space_floor_bytes")
        if maximum > cap:
            fail(f"SQLite family {name} exceeded its DB+WAL+SHM cap")
        if minimum_free < configured_floor:
            fail(f"SQLite family {name} violated the configured free-space floor")
    if not REQUIRED_SQLITE_FAMILIES.issubset(family_names):
        fail(
            "SQLite family inventory omits shipping stores: "
            + ", ".join(sorted(REQUIRED_SQLITE_FAMILIES - family_names))
        )

    observed_sqlite_inventories = []
    for index, observation in enumerate(observations):
        inventory = object_value(
            object_value(observation, f"recorder observation {index}").get("sqlite_families"),
            f"recorder observation {index}.sqlite_families",
        )
        observed_sqlite_inventories.append(set(inventory))
    if any(names != observed_sqlite_inventories[0] for names in observed_sqlite_inventories[1:]) \
            or family_names != observed_sqlite_inventories[0]:
        fail("SQLite aggregate inventory does not match every recorder observation")
    family_by_name = {
        object_value(row, "SQLite aggregate row").get("name"): object_value(
            row, "SQLite aggregate row"
        )
        for row in families
    }
    for name in sorted(family_names):
        raw_rows = [
            object_value(
                object_value(observation, "recorder observation").get("sqlite_families"),
                "recorder observation.sqlite_families",
            ).get(name)
            for observation in observations
        ]
        rows = [object_value(row, f"recorder SQLite family {name}") for row in raw_rows]
        expected = {
            "name": name,
            "max_db_wal_shm_bytes": max(int_value(row.get("footprint_bytes"), f"{name}.footprint_bytes") for row in rows),
            "configured_cap_bytes": int_value(rows[0].get("configured_cap_bytes"), f"{name}.configured_cap_bytes", minimum=1),
            "minimum_free_space_bytes": min(int_value(row.get("free_space_bytes"), f"{name}.free_space_bytes") for row in rows),
            "configured_free_space_floor_bytes": int_value(rows[0].get("configured_free_space_floor_bytes"), f"{name}.configured_free_space_floor_bytes"),
        }
        if any(
            row.get("configured_cap_bytes") != expected["configured_cap_bytes"]
            or row.get("configured_free_space_floor_bytes")
            != expected["configured_free_space_floor_bytes"]
            for row in rows
        ):
            fail(f"SQLite family {name} policy changed during the epoch")
        if family_by_name.get(name) != expected:
            fail(f"SQLite family {name} aggregate does not reconcile with raw observations")

    ai = object_value(metrics.get("ai_quality"), "runtime.measurements.ai_quality")
    llm_rows = [
        object_value(object_value(sample, "runtime sample").get("llm_quality"), "sample.llm_quality")
        for sample in samples
    ]
    configured_values = [
        bool_value(row.get("configured"), "sample.llm_quality.configured")
        for row in llm_rows
    ]
    if any(value != configured_values[0] for value in configured_values[1:]):
        fail("LLM configuration changed during the runtime epoch")
    configured = configured_values[0]
    if not configured:
        fail("release qualification requires configured alert investigation")
    if bool_value(ai.get("configured"), "runtime.measurements.ai_quality.configured") != configured:
        fail("AI-quality configuration aggregate does not match raw samples")
    if bool_value(
        ai.get("feature_disabled_entire_epoch"),
        "runtime.measurements.ai_quality.feature_disabled_entire_epoch",
    ) != (not configured):
        fail("AI-quality disabled aggregate does not match raw samples")
    for index, row in enumerate(llm_rows):
        if row.get("schema_version") != 2 \
                or row.get("accounting_conserved") is not True \
                or row.get("healthy") is not True:
            fail(f"configured LLM was unhealthy or non-conserving at sample {index}")
    monotonic_keys = (
        "unspecified_requested_total",
        "reason_observed_attempts_total",
        "reason_terminal_rejections_total",
        "totals_requested_total",
    )
    for key in monotonic_keys:
        values = [int_value(row.get(key), f"sample.llm_quality.{key}") for row in llm_rows]
        if any(later < earlier for earlier, later in zip(values, values[1:])):
            fail(f"LLM cumulative counter {key} reset during the epoch")
    alert_rows = [
        object_value(row.get("alert_investigation"), "sample.llm_quality.alert_investigation")
        for row in llm_rows
    ]
    for key in (
        "operations_started_total", "current_operations", "accepted_total",
        "retry_requested_total", "final_rejection_total",
    ):
        values = [int_value(row.get(key), f"LLM alert.{key}") for row in alert_rows]
        if key != "current_operations" and any(
            later < earlier for earlier, later in zip(values, values[1:])
        ):
            fail(f"LLM alert-investigation counter {key} reset during the epoch")
    unspecified_delta = int_value(llm_rows[-1].get("unspecified_requested_total"), "LLM unspecified end") - int_value(llm_rows[0].get("unspecified_requested_total"), "LLM unspecified start")
    started_delta = int_value(alert_rows[-1].get("operations_started_total"), "LLM starts end") - int_value(alert_rows[0].get("operations_started_total"), "LLM starts start")
    accepted_delta = int_value(alert_rows[-1].get("accepted_total"), "LLM accepted end") - int_value(alert_rows[0].get("accepted_total"), "LLM accepted start")
    rejected_delta = int_value(alert_rows[-1].get("final_rejection_total"), "LLM rejected end") - int_value(alert_rows[0].get("final_rejection_total"), "LLM rejected start")
    if int_value(alert_rows[0].get("current_operations"), "LLM current start") != 0 \
            or int_value(alert_rows[-1].get("current_operations"), "LLM current end") != 0:
        fail("alert investigation was still in flight at an epoch boundary")
    if started_delta < 1:
        fail("qualification did not exercise alert investigation")
    if unspecified_delta != 0 or rejected_delta != 0 or accepted_delta != started_delta:
        fail("configured LLM accrued unattributed, unfinished, or final-rejected work")
    expected_ai = {
        "configured": configured,
        "feature_disabled_entire_epoch": not configured,
        "schema_2_and_accounting_conserved_all_samples": True,
        "unspecified_requests_epoch_delta": unspecified_delta,
        "alert_investigations_started_epoch_delta": started_delta,
        "alert_investigations_accepted_epoch_delta": accepted_delta,
        "alert_investigations_final_rejected_epoch_delta": rejected_delta,
    }
    if ai != expected_ai:
        fail("AI-quality aggregate does not reconcile with raw samples")

    rules = object_value(metrics.get("rules"), "runtime.measurements.rules")
    for key in ("sealed_rules_synchronized_before_readers", "corpus_parity", "ordinary_launch_without_admin_prompt"):
        require_true(rules.get(key), f"runtime.measurements.rules.{key}")

    tools = object_value(metrics.get("shipped_tools"), "runtime.measurements.shipped_tools")
    for tool_name in ("maccrabctl", "maccrab_mcp"):
        tool = object_value(tools.get(tool_name), f"runtime.measurements.shipped_tools.{tool_name}")
        path = string_value(tool.get("path"), f"runtime.measurements.shipped_tools.{tool_name}.path")
        if not path.startswith("/Volumes/"):
            fail(f"{tool_name} was not executed directly from the mounted DMG")
        if int_value(tool.get("exit_code"), f"runtime.measurements.shipped_tools.{tool_name}.exit_code") != 0:
            fail(f"{tool_name} version probe failed")
        string_value(tool.get("version_output"), f"runtime.measurements.shipped_tools.{tool_name}.version_output")
        if candidate.get("version") not in tool.get("version_output"):
            fail(f"{tool_name} version output does not name the candidate version")
        require_true(tool.get("sip_amfi_normal"), f"runtime.measurements.shipped_tools.{tool_name}.sip_amfi_normal")

    evidence = object_value(report.get("evidence"), "runtime.evidence")
    payload_inventory_sha = require_sha(evidence.get("payload_inventory_sha256"), "runtime.evidence.payload_inventory_sha256")
    candidate_verification = object_value(
        report.get("candidate_artifact_verification"), "runtime.candidate_artifact_verification"
    )
    if payload_inventory_sha != require_sha(
        candidate_verification.get("payload_inventory_sha256"),
        "runtime.candidate_artifact_verification.payload_inventory_sha256",
    ):
        fail("runtime payload inventory binding is internally inconsistent")
    if payload_inventory_sha != payload_inventory_sha256:
        fail("runtime report does not bind the candidate manifest payload inventory")
    raw_samples_sha = require_sha(evidence.get("raw_samples_sha256"), "runtime.evidence.raw_samples_sha256")
    if raw_samples_sha != samples_sha:
        fail("runtime raw_samples_sha256 does not match the embedded full-interval samples")
    string_value(evidence.get("raw_samples_format"), "runtime.evidence.raw_samples_format")
    if evidence.get("recorder_schema") != RUNTIME_RECORDER_SCHEMA:
        fail(f"runtime.evidence.recorder_schema must be {RUNTIME_RECORDER_SCHEMA}")
    observations_sha = require_sha(
        evidence.get("observations_sha256"),
        "runtime.evidence.observations_sha256",
    )
    if observations_sha != sha256_bytes(canonical_json_bytes(observations)):
        fail("runtime observations_sha256 does not match raw recorder observations")
    recorded_at = parse_time(evidence.get("recorded_at"), "runtime.evidence.recorded_at")
    if recorded_at < ended:
        fail("runtime.evidence.recorded_at precedes the end of the epoch")


def heartbeat_counter(container: Mapping[str, Any], key: str, path: str) -> int:
    return int_value(container.get(key), f"{path}.{key}")


def heartbeat_counter_map(
    container: Mapping[str, Any], key: str, path: str
) -> Dict[str, int]:
    raw = object_value(container.get(key), f"{path}.{key}")
    return {
        string_value(name, f"{path}.{key} key"): int_value(
            value, f"{path}.{key}.{name}"
        )
        for name, value in raw.items()
    }


def recorder_boundary(
    *, offered: int, completed: int, queued: int, in_flight: int,
    explicitly_shed: int, path: str,
) -> Dict[str, int]:
    result = {
        "offered": offered,
        "completed": completed,
        "queued": queued,
        "in_flight": in_flight,
        "explicitly_shed": explicitly_shed,
    }
    require_counter_equation(result, path)
    return result


def published_conservation_boundary(
    container: Mapping[str, Any], key: str, path: str
) -> Dict[str, int]:
    """Read a real producer ledger; never manufacture a balancing residual."""
    raw = object_value(container.get(key), f"{path}.{key}")
    required = {"offered", "completed", "queued", "in_flight", "explicitly_shed"}
    if set(raw) != required:
        fail(
            f"{path}.{key} must publish the exact conservation inventory "
            f"{sorted(required)}"
        )
    return recorder_boundary(
        offered=heartbeat_counter(raw, "offered", f"{path}.{key}"),
        completed=heartbeat_counter(raw, "completed", f"{path}.{key}"),
        queued=heartbeat_counter(raw, "queued", f"{path}.{key}"),
        in_flight=heartbeat_counter(raw, "in_flight", f"{path}.{key}"),
        explicitly_shed=heartbeat_counter(
            raw, "explicitly_shed", f"{path}.{key}"
        ),
        path=f"recorder.{key}",
    )


def trace_graph_write_accounting_sample(
    graph: Mapping[str, Any], path: str
) -> Dict[str, int]:
    """Read and reconcile the producer's exact graph-write ledgers."""
    keys = (
        "write_attempts_total",
        "write_batches_committed_total",
        "write_batches_failed_total",
        "write_batches_in_flight",
        "write_rows_attempted_total",
        "write_rows_committed_total",
        "write_rows_failed_total",
        "write_rows_in_flight",
        "entity_observations_total",
        "edge_observations_total",
        "coalesced_noop_rows_total",
        "pending_entity_rows",
        "pending_edge_rows",
    )
    result = {key: heartbeat_counter(graph, key, path) for key in keys}
    if result["write_attempts_total"] != (
        result["write_batches_committed_total"]
        + result["write_batches_failed_total"]
        + result["write_batches_in_flight"]
    ):
        fail(f"{path} batch-write ledger does not conserve")
    if result["write_rows_attempted_total"] != (
        result["write_rows_committed_total"]
        + result["write_rows_failed_total"]
        + result["write_rows_in_flight"]
    ):
        fail(f"{path} row-write ledger does not conserve")
    if result["entity_observations_total"] + result["edge_observations_total"] != (
        result["write_rows_attempted_total"]
        + result["coalesced_noop_rows_total"]
        + result["pending_entity_rows"]
        + result["pending_edge_rows"]
    ):
        fail(f"{path} observation/coalescing ledger does not conserve")
    return result


def trace_store_admission_sample(
    trace_store: Mapping[str, Any], path: str
) -> Dict[str, Any]:
    """Normalize the TraceStore state needed to prove a full writer."""
    result = {
        "enabled": bool_value(trace_store.get("enabled"), f"{path}.enabled"),
        "blocked": bool_value(trace_store.get("blocked"), f"{path}.blocked"),
        "store_available": bool_value(
            trace_store.get("store_available"), f"{path}.store_available"
        ),
        "recovering": bool_value(
            trace_store.get("recovering"), f"{path}.recovering"
        ),
        "max_footprint_bytes": int_value(
            trace_store.get("max_footprint_bytes"),
            f"{path}.max_footprint_bytes",
            minimum=1,
        ),
        "admission_threshold_bytes": int_value(
            trace_store.get("admission_threshold_bytes"),
            f"{path}.admission_threshold_bytes",
            minimum=1,
        ),
        "transaction_reserve_bytes": int_value(
            trace_store.get("transaction_reserve_bytes"),
            f"{path}.transaction_reserve_bytes",
            minimum=1,
        ),
        "footprint_bytes": int_value(
            trace_store.get("footprint_bytes"), f"{path}.footprint_bytes"
        ),
        "free_space_bytes": int_value(
            trace_store.get("free_space_bytes"), f"{path}.free_space_bytes"
        ),
        "free_space_floor_bytes": int_value(
            trace_store.get("free_space_floor_bytes"),
            f"{path}.free_space_floor_bytes",
            minimum=1,
        ),
    }
    if result["admission_threshold_bytes"] > result["max_footprint_bytes"]:
        fail(f"{path} admission threshold exceeds the configured hard cap")
    if result["footprint_bytes"] > result["admission_threshold_bytes"]:
        fail(f"{path} footprint is above the writer admission threshold")
    if result["free_space_bytes"] < result["free_space_floor_bytes"]:
        fail(f"{path} is below the configured free-space floor")
    return result


def llm_runtime_quality_sample(heartbeat: Mapping[str, Any]) -> Dict[str, Any]:
    """Validate the fixed-cardinality LLM ledger when that feature is enabled."""
    llm = object_value(heartbeat.get("llm"), "heartbeat.llm")
    configured = bool_value(llm.get("configured"), "heartbeat.llm.configured")
    if not configured:
        return {"configured": False}
    runtime = object_value(
        llm.get("runtime_telemetry"), "heartbeat.llm.runtime_telemetry"
    )
    if int_value(
        runtime.get("schemaVersion"),
        "heartbeat.llm.runtime_telemetry.schemaVersion",
        minimum=1,
    ) != 2:
        fail("configured LLM must publish schema-2 runtime telemetry")

    def validate_counters(raw: Any, path: str) -> Dict[str, int]:
        counters = object_value(raw, path)
        for key in (
            "conservationMaintained",
            "backendAdmissionConservationMaintained",
            "circuitRecoveryConservationMaintained",
        ):
            require_true(counters.get(key), f"{path}.{key}")
        requested = int_value(counters.get("requestedTotal"), f"{path}.requestedTotal")
        downstream = object_value(
            counters.get("downstreamValidation"), f"{path}.downstreamValidation"
        )
        started = int_value(
            downstream.get("operationsStartedTotal"),
            f"{path}.downstreamValidation.operationsStartedTotal",
        )
        current = int_value(
            downstream.get("currentOperations"),
            f"{path}.downstreamValidation.currentOperations",
        )
        accepted = int_value(
            downstream.get("accepted"), f"{path}.downstreamValidation.accepted"
        )
        retries = int_value(
            downstream.get("retryRequested"),
            f"{path}.downstreamValidation.retryRequested",
        )
        rejected = int_value(
            downstream.get("finalRejection"),
            f"{path}.downstreamValidation.finalRejection",
        )
        if started != current + accepted + rejected:
            fail(f"{path}.downstreamValidation does not conserve")
        return {
            "requested_total": requested,
            "operations_started_total": started,
            "current_operations": current,
            "accepted_total": accepted,
            "retry_requested_total": retries,
            "final_rejection_total": rejected,
        }

    totals = validate_counters(
        runtime.get("totals"), "heartbeat.llm.runtime_telemetry.totals"
    )
    per_feature = list_value(
        runtime.get("perFeature"),
        "heartbeat.llm.runtime_telemetry.perFeature",
        nonempty=True,
    )
    feature_rows: Dict[str, Dict[str, int]] = {}
    observed_features: List[str] = []
    for index, raw in enumerate(per_feature):
        row = object_value(raw, f"heartbeat.llm.runtime_telemetry.perFeature[{index}]")
        feature = string_value(
            row.get("feature"),
            f"heartbeat.llm.runtime_telemetry.perFeature[{index}].feature",
        )
        observed_features.append(feature)
        feature_rows[feature] = validate_counters(
            row.get("counters"),
            f"heartbeat.llm.runtime_telemetry.perFeature[{index}].counters",
        )
    if tuple(observed_features) != LLM_FEATURES or len(feature_rows) != len(LLM_FEATURES):
        fail("configured LLM telemetry omits or reorders the fixed feature inventory")

    reasons = object_value(
        runtime.get("alertInvestigationRejections"),
        "heartbeat.llm.runtime_telemetry.alertInvestigationRejections",
    )
    observed_total = int_value(
        reasons.get("observedAttemptsTotal"), "LLM reasons.observedAttemptsTotal"
    )
    terminal_total = int_value(
        reasons.get("terminalRejectionsTotal"), "LLM reasons.terminalRejectionsTotal"
    )
    reason_rows = list_value(reasons.get("byReason"), "LLM reasons.byReason")
    observed_reasons: List[str] = []
    summed_observed = 0
    summed_terminal = 0
    for index, raw in enumerate(reason_rows):
        row = object_value(raw, f"LLM reasons.byReason[{index}]")
        reason = string_value(row.get("reason"), f"LLM reasons.byReason[{index}].reason")
        observed_reasons.append(reason)
        observed = int_value(
            row.get("observedAttempts"),
            f"LLM reasons.byReason[{index}].observedAttempts",
        )
        terminal = int_value(
            row.get("terminalRejections"),
            f"LLM reasons.byReason[{index}].terminalRejections",
        )
        if terminal > observed:
            fail("LLM reason terminal rejections exceed observed attempts")
        summed_observed += observed
        summed_terminal += terminal
    if tuple(observed_reasons) != LLM_ALERT_REJECTION_REASONS:
        fail("configured LLM telemetry omits or reorders rejection reasons")
    alert = feature_rows["alert_investigation"]
    if summed_observed != observed_total or summed_terminal != terminal_total \
            or terminal_total != alert["final_rejection_total"] \
            or observed_total != alert["retry_requested_total"] + terminal_total:
        fail("LLM alert-investigation rejection reason ledger does not conserve")
    return {
        "configured": True,
        "healthy": bool_value(llm.get("healthy"), "heartbeat.llm.healthy"),
        "schema_version": 2,
        "accounting_conserved": True,
        "unspecified_requested_total": feature_rows["unspecified"]["requested_total"],
        "alert_investigation": alert,
        "reason_observed_attempts_total": observed_total,
        "reason_terminal_rejections_total": terminal_total,
        "totals_requested_total": totals["requested_total"],
    }


def normalized_runtime_sample(
    heartbeat: Mapping[str, Any],
    *,
    offset_seconds: int,
    recorded_at: str,
    engine_cpu_seconds_total: float,
    engine_disk_write_bytes_total: int,
    engine_rss_bytes: int,
    gui_background_cpu_percent: float,
) -> Dict[str, Any]:
    """Turn one rich heartbeat plus Darwin process counters into gate input."""
    pid = heartbeat_counter(heartbeat, "engine_pid", "heartbeat")
    pipeline = object_value(heartbeat.get("event_pipeline"), "heartbeat.event_pipeline")
    offered = heartbeat_counter_map(pipeline, "offered_by_lane", "heartbeat.event_pipeline")
    completed = heartbeat_counter_map(pipeline, "completed_by_lane", "heartbeat.event_pipeline")
    backlog = heartbeat_counter_map(pipeline, "backlog_estimate_by_lane", "heartbeat.event_pipeline")
    in_flight = heartbeat_counter_map(pipeline, "in_flight_by_lane", "heartbeat.event_pipeline")
    ingress_shed = heartbeat_counter_map(
        pipeline, "merged_dropped_by_lane", "heartbeat.event_pipeline"
    )
    ingress_terminated = heartbeat_counter_map(
        pipeline, "merged_terminated_by_lane", "heartbeat.event_pipeline"
    )
    boundaries: Dict[str, Dict[str, int]] = {}
    for lane in ("priority", "file"):
        boundaries[f"{lane}-ingress"] = recorder_boundary(
            offered=offered[lane], completed=completed[lane],
            queued=backlog[lane], in_flight=in_flight[lane],
            explicitly_shed=ingress_shed[lane] + ingress_terminated[lane],
            path=f"recorder.{lane}-ingress",
        )

    storage_offered = heartbeat_counter_map(
        heartbeat, "events_storage_write_offered_by_lane", "heartbeat"
    )
    storage_persisted = heartbeat_counter_map(
        heartbeat, "events_storage_write_persisted_by_lane", "heartbeat"
    )
    storage_filtered = heartbeat_counter_map(
        heartbeat, "events_storage_write_filtered_by_lane", "heartbeat"
    )
    storage_dropped = heartbeat_counter_map(
        heartbeat, "events_storage_write_dropped_by_lane", "heartbeat"
    )
    storage_buffer = heartbeat_counter_map(
        heartbeat, "events_storage_write_buffer_depth_by_lane", "heartbeat"
    )
    storage_in_flight = heartbeat_counter_map(
        heartbeat, "events_storage_write_in_flight_depth_by_lane", "heartbeat"
    )
    for lane in ("priority", "file"):
        boundaries[f"{lane}-event-persistence"] = recorder_boundary(
            offered=storage_offered[lane],
            completed=storage_persisted[lane] + storage_filtered[lane],
            queued=storage_buffer[lane], in_flight=storage_in_flight[lane],
            explicitly_shed=storage_dropped[lane],
            path=f"recorder.{lane}-event-persistence",
        )

    checkpoint = object_value(
        heartbeat.get("sequence_checkpoint"), "heartbeat.sequence_checkpoint"
    )
    boundaries["sequence-checkpoint"] = published_conservation_boundary(
        checkpoint, "conservation", "heartbeat.sequence_checkpoint"
    )

    pending_evictions = heartbeat_counter(
        heartbeat, "sequence_pending_steps_evicted_total", "heartbeat"
    )
    boundaries["sequence-journal"] = published_conservation_boundary(
        heartbeat, "sequence_journal_conservation", "heartbeat"
    )

    graph = object_value(
        heartbeat.get("tracegraph_storage_admission"),
        "heartbeat.tracegraph_storage_admission",
    )
    graph_offered = heartbeat_counter(
        graph, "ingest_events_total", "heartbeat.tracegraph_storage_admission"
    )
    graph_completed = heartbeat_counter(
        graph, "ingest_events_committed_total", "heartbeat.tracegraph_storage_admission"
    )
    graph_failed = heartbeat_counter(
        graph, "ingest_events_failed_total", "heartbeat.tracegraph_storage_admission"
    )
    graph_pending = heartbeat_counter(
        graph, "ingest_events_pending", "heartbeat.tracegraph_storage_admission"
    )
    graph_in_flight = heartbeat_counter(
        graph, "ingest_events_in_flight", "heartbeat.tracegraph_storage_admission"
    )
    boundaries["trace-graph-mutation"] = recorder_boundary(
        offered=graph_offered, completed=graph_completed, queued=graph_pending,
        in_flight=graph_in_flight, explicitly_shed=graph_failed,
        path="recorder.trace-graph-mutation",
    )

    trace_store = object_value(
        heartbeat.get("traces_storage_admission"),
        "heartbeat.traces_storage_admission",
    )
    # Absence is unknown, never equivalent to zero activity. Release
    # qualification later requires this to be an enabled, available writer;
    # disabled/startup-blocked branches cannot manufacture a zero-ledger pass.
    boundaries["trace-store-ingest"] = published_conservation_boundary(
        trace_store, "ingest_conservation", "heartbeat.traces_storage_admission"
    )
    graph_write_accounting = trace_graph_write_accounting_sample(
        graph, "heartbeat.tracegraph_storage_admission"
    )
    trace_store_admission = trace_store_admission_sample(
        trace_store, "heartbeat.traces_storage_admission"
    )

    upstream_loss = sum(
        heartbeat_counter_map(
            pipeline, key, "heartbeat.event_pipeline"
        ).get(lane, 0)
        for key in ("upstream_dropped_by_lane", "upstream_terminated_by_lane")
        for lane in ("priority", "file")
    )
    return {
        "offset_seconds": offset_seconds,
        "recorded_at": recorded_at,
        "engine_pid": pid,
        "engine_cpu_seconds_total": engine_cpu_seconds_total,
        "engine_disk_write_bytes_total": engine_disk_write_bytes_total,
        "engine_rss_bytes": engine_rss_bytes,
        "gui_background_cpu_percent": gui_background_cpu_percent,
        "sequence_pending_steps_evicted_total": pending_evictions,
        "sequence_state_continuity_maintained": bool_value(
            heartbeat.get("sequence_state_continuity_maintained"),
            "heartbeat.sequence_state_continuity_maintained",
        ),
        "sequence_state_continuity_detail": string_value(
            heartbeat.get("sequence_state_continuity_detail"),
            "heartbeat.sequence_state_continuity_detail",
        ),
        "conservation": boundaries,
        "trace_graph_write_accounting": graph_write_accounting,
        "trace_store_admission": trace_store_admission,
        "losses": {
            "priority_lane_loss": boundaries["priority-ingress"]["explicitly_shed"],
            "kernel_loss": heartbeat_counter(heartbeat, "es_kernel_dropped_total", "heartbeat"),
            "callback_copy_loss": (
                heartbeat_counter(heartbeat, "es_copy_backpressure_dropped_total", "heartbeat")
                + heartbeat_counter(heartbeat, "es_stream_yield_dropped_total", "heartbeat")
            ),
            "upstream_collector_loss": upstream_loss,
            "unclassified_file_queue_loss": boundaries["file-ingress"]["explicitly_shed"],
        },
        "llm_quality": llm_runtime_quality_sample(heartbeat),
    }


def sample_from_recorder_observation(raw: Any, path: str) -> Dict[str, Any]:
    observation = object_value(raw, path)
    if observation.get("schema") != RUNTIME_OBSERVATION_SCHEMA:
        fail(f"{path}.schema must be {RUNTIME_OBSERVATION_SCHEMA}")
    offset = int_value(observation.get("offset_seconds"), f"{path}.offset_seconds")
    recorded_at = string_value(observation.get("recorded_at"), f"{path}.recorded_at")
    scheduled = parse_time(recorded_at, f"{path}.recorded_at")
    captured = parse_time(observation.get("captured_at"), f"{path}.captured_at")
    if abs((captured - scheduled).total_seconds()) > 5.0:
        fail(f"{path} was not captured at its scheduled sample boundary")
    heartbeat = object_value(observation.get("heartbeat"), f"{path}.heartbeat")
    heartbeat_file = object_value(
        observation.get("heartbeat_file"), f"{path}.heartbeat_file"
    )
    heartbeat_file_path = string_value(
        heartbeat_file.get("path"), f"{path}.heartbeat_file.path"
    )
    if not heartbeat_file_path.startswith("/Library/Application Support/MacCrab/"):
        fail(f"{path}.heartbeat_file.path is not the installed engine support path")
    raw_json = string_value(
        heartbeat_file.get("raw_json"), f"{path}.heartbeat_file.raw_json"
    )
    try:
        parsed_raw = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        fail(f"{path}.heartbeat_file.raw_json is invalid: {exc}")
    if parsed_raw != heartbeat:
        fail(f"{path}.heartbeat does not match the exact captured JSON bytes")
    if require_sha(
        heartbeat_file.get("raw_sha256"), f"{path}.heartbeat_file.raw_sha256"
    ) != sha256_bytes(raw_json.encode("utf-8")):
        fail(f"{path}.heartbeat_file.raw_sha256 does not bind the captured bytes")
    if require_sha(
        heartbeat_file.get("canonical_sha256"),
        f"{path}.heartbeat_file.canonical_sha256",
    ) != sha256_bytes(canonical_json_bytes(heartbeat)):
        fail(f"{path}.heartbeat_file.canonical_sha256 does not bind the heartbeat")
    if int_value(
        heartbeat_file.get("owner_uid"), f"{path}.heartbeat_file.owner_uid"
    ) != 0:
        fail(f"{path}.heartbeat_file must be root-owned")
    mode = int_value(heartbeat_file.get("mode"), f"{path}.heartbeat_file.mode")
    if mode & 0o022:
        fail(f"{path}.heartbeat_file is group/world writable")
    number_value(
        heartbeat_file.get("mtime_unix"), f"{path}.heartbeat_file.mtime_unix"
    )
    if int_value(
        heartbeat.get("schema_version"), f"{path}.heartbeat.schema_version", minimum=1
    ) < 5:
        fail(f"{path} requires rich-heartbeat schema 5 or newer")
    written_at = number_value(
        heartbeat.get("written_at_unix"), f"{path}.heartbeat.written_at_unix"
    )
    captured_epoch = captured.timestamp()
    if written_at > captured_epoch + 5.0 \
            or captured_epoch - written_at > HEARTBEAT_MAX_AGE_SECONDS:
        fail(f"{path} used a stale or future rich heartbeat")
    graph = object_value(
        heartbeat.get("tracegraph_storage_admission"),
        f"{path}.heartbeat.tracegraph_storage_admission",
    )
    expected_trace_writable = (
        graph.get("enabled") is True
        and graph.get("blocked") is False
        and graph.get("store_available") is True
    )
    if bool_value(observation.get("trace_writable"), f"{path}.trace_writable") \
            is not expected_trace_writable:
        fail(f"{path}.trace_writable does not match the heartbeat")
    expected_recovering = bool_value(
        graph.get("recovering"), f"{path}.heartbeat.tracegraph.recovering"
    )
    if bool_value(observation.get("trace_recovering"), f"{path}.trace_recovering") \
            is not expected_recovering:
        fail(f"{path}.trace_recovering does not match the heartbeat")
    expected_shed = heartbeat_counter(
        graph, "shed_mutations_total", f"{path}.heartbeat.tracegraph"
    )
    if int_value(
        observation.get("trace_shed_mutations_total"),
        f"{path}.trace_shed_mutations_total",
    ) != expected_shed:
        fail(f"{path}.trace_shed_mutations_total does not match the heartbeat")
    budget = object_value(
        heartbeat.get("events_retention_budget"),
        f"{path}.heartbeat.events_retention_budget",
    )
    budget_state = string_value(
        budget.get("state"), f"{path}.heartbeat.events_retention_budget.state"
    )
    expected_budget_fault = budget_state.startswith("degraded_") \
        or budget.get("sticky") is True
    if bool_value(observation.get("event_budget_fault"), f"{path}.event_budget_fault") \
            is not expected_budget_fault:
        fail(f"{path}.event_budget_fault does not match the heartbeat")
    process = object_value(observation.get("process"), f"{path}.process")
    return normalized_runtime_sample(
        heartbeat,
        offset_seconds=offset,
        recorded_at=recorded_at,
        engine_cpu_seconds_total=number_value(
            process.get("engine_cpu_seconds_total"),
            f"{path}.process.engine_cpu_seconds_total",
            minimum=0,
        ),
        engine_disk_write_bytes_total=int_value(
            process.get("engine_disk_write_bytes_total"),
            f"{path}.process.engine_disk_write_bytes_total",
        ),
        engine_rss_bytes=int_value(
            process.get("engine_rss_bytes"), f"{path}.process.engine_rss_bytes"
        ),
        gui_background_cpu_percent=number_value(
            observation.get("gui_background_cpu_percent"),
            f"{path}.gui_background_cpu_percent",
            minimum=0,
        ),
    )


def derive_workload_ingress(samples: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    """Derive the minute-five load proof only from cumulative raw samples."""
    by_offset: Dict[int, Mapping[str, Any]] = {}
    for sample in samples:
        offset = number_value(sample.get("offset_seconds"), "workload sample offset")
        rounded = int(round(offset))
        if abs(offset - rounded) <= 0.001:
            by_offset[rounded] = sample
    for required in (BURST_START_OFFSET_SECONDS, BURST_END_OFFSET_SECONDS):
        if required not in by_offset:
            fail(f"runtime samples must include workload boundary offset {required}")

    def counter(sample: Mapping[str, Any], boundary: str, key: str) -> int:
        boundaries = object_value(sample.get("conservation"), "workload conservation")
        row = object_value(boundaries.get(boundary), f"workload conservation.{boundary}")
        return int_value(row.get(key), f"workload conservation.{boundary}.{key}")

    # Cumulative producer counters may never move backwards. Queue and
    # in-flight values are gauges, so they are intentionally excluded here.
    for boundary in sorted(REQUIRED_CONSERVATION_BOUNDARIES):
        for key in ("offered", "completed", "explicitly_shed"):
            values = [counter(sample, boundary, key) for sample in samples]
            if any(later < earlier for earlier, later in zip(values, values[1:])):
                fail(f"runtime cumulative {boundary}.{key} counter moved backwards")

    start = by_offset[BURST_START_OFFSET_SECONDS]
    end = by_offset[BURST_END_OFFSET_SECONDS]

    def delta(boundary: str, key: str) -> int:
        return counter(end, boundary, key) - counter(start, boundary, key)

    window_samples = [
        sample for sample in samples
        if BURST_START_OFFSET_SECONDS
        <= number_value(sample.get("offset_seconds"), "workload offset")
        <= BURST_END_OFFSET_SECONDS
    ]
    interval_rates: List[float] = []
    for prior, current in zip(window_samples, window_samples[1:]):
        prior_offset = number_value(prior.get("offset_seconds"), "workload prior offset")
        current_offset = number_value(current.get("offset_seconds"), "workload current offset")
        elapsed = current_offset - prior_offset
        if elapsed <= 0:
            fail("workload samples are not strictly ordered")
        offered_delta = sum(
            counter(current, f"{lane}-ingress", "offered")
            - counter(prior, f"{lane}-ingress", "offered")
            for lane in ("priority", "file")
        )
        interval_rates.append(offered_delta / elapsed)
    if not interval_rates:
        fail("runtime workload window has no measured sample interval")

    result = {
        "start_offset_seconds": BURST_START_OFFSET_SECONDS,
        "end_offset_seconds": BURST_END_OFFSET_SECONDS,
        "priority_ingress_offered_delta": delta("priority-ingress", "offered"),
        "priority_ingress_completed_delta": delta("priority-ingress", "completed"),
        "file_ingress_offered_delta": delta("file-ingress", "offered"),
        "file_ingress_completed_delta": delta("file-ingress", "completed"),
        "priority_persistence_offered_delta": delta(
            "priority-event-persistence", "offered"
        ),
        "priority_persistence_completed_delta": delta(
            "priority-event-persistence", "completed"
        ),
        "priority_persistence_explicitly_shed_delta": delta(
            "priority-event-persistence", "explicitly_shed"
        ),
        "file_persistence_offered_delta": delta(
            "file-event-persistence", "offered"
        ),
        "file_persistence_completed_delta": delta(
            "file-event-persistence", "completed"
        ),
        "file_persistence_explicitly_shed_delta": delta(
            "file-event-persistence", "explicitly_shed"
        ),
        "combined_peak_offered_per_second": max(interval_rates),
        "trace_store_offered_delta": delta("trace-store-ingest", "offered"),
        "trace_store_completed_delta": delta("trace-store-ingest", "completed"),
        "trace_store_explicitly_shed_delta": delta(
            "trace-store-ingest", "explicitly_shed"
        ),
    }
    for lane in ("priority", "file"):
        if result[f"{lane}_ingress_offered_delta"] <= 0 \
                or result[f"{lane}_ingress_completed_delta"] <= 0:
            fail(f"fixed workload produced no measured {lane}-lane ingress/completion")
        if result[f"{lane}_ingress_offered_delta"] \
                != result[f"{lane}_ingress_completed_delta"]:
            fail(f"{lane} ingress did not drain by the workload window boundary")
        if result[f"{lane}_persistence_offered_delta"] <= 0 \
                or result[f"{lane}_persistence_completed_delta"] <= 0:
            fail(
                f"fixed workload produced no measured {lane}-lane "
                "persistence/completion"
            )
        if result[f"{lane}_persistence_offered_delta"] \
                != result[f"{lane}_persistence_completed_delta"]:
            fail(
                f"{lane} persistence did not drain by the workload window boundary"
            )
        if result[f"{lane}_persistence_explicitly_shed_delta"] != 0:
            fail(f"{lane} persistence shed fixed-workload events")
    if result["combined_peak_offered_per_second"] \
            < MIN_BURST_COMBINED_OFFERED_PER_SECOND:
        fail(
            "fixed workload did not reach the predeclared reference load "
            f"({MIN_BURST_COMBINED_OFFERED_PER_SECOND:.0f} offered events/s)"
        )
    if result["trace_store_offered_delta"] < MIN_TRACE_STORE_INGEST_DELTA \
            or result["trace_store_completed_delta"] < MIN_TRACE_STORE_INGEST_DELTA:
        fail("fixed workload did not prove a real TraceStore ingest/write")
    if result["trace_store_offered_delta"] != result["trace_store_completed_delta"]:
        fail("TraceStore did not drain the fixed workload by the window boundary")
    if result["trace_store_explicitly_shed_delta"] != 0:
        fail("TraceStore shed workload input during the qualification window")
    return result


def build_runtime_report_from_observations(
    *,
    candidate_manifest: Mapping[str, Any],
    candidate_manifest_sha256: str,
    observations: Sequence[Mapping[str, Any]],
    host: Mapping[str, Any],
    workload: Mapping[str, Any],
    probes: Mapping[str, Any],
    capture_mode: str,
) -> Dict[str, Any]:
    if capture_mode not in ("live-installed-root", "deterministic-fixture"):
        fail("runtime recorder capture mode is unknown")
    if len(observations) < 2:
        fail("runtime recorder needs at least two observations")
    raw_observations = [copy.deepcopy(object_value(item, "recorder observation")) for item in observations]
    samples = [
        sample_from_recorder_observation(item, f"recorder.observations[{index}]")
        for index, item in enumerate(raw_observations)
    ]
    workload_ingress = derive_workload_ingress(samples)
    duration = number_value(samples[-1].get("offset_seconds"), "last sample offset", minimum=MIN_EPOCH_SECONDS)
    samples_sha = sha256_bytes(canonical_json_bytes(samples))
    candidate = copy.deepcopy(object_value(candidate_manifest.get("candidate"), "candidate"))
    verification = object_value(candidate_manifest.get("artifact_verification"), "artifact_verification")
    inventory = object_value(verification.get("payload_inventory"), "artifact_verification.payload_inventory")
    workload_fields = {
        key: copy.deepcopy(workload.get(key))
        for key in (
            "id", "version", "description", "normal_operations",
            "burst_operations", "executors",
        )
    }
    workload_record = dict(workload_fields)
    workload_record["sha256"] = sha256_bytes(canonical_json_bytes(workload_fields))

    cpu_seconds = number_value(samples[-1]["engine_cpu_seconds_total"], "last CPU") - number_value(samples[0]["engine_cpu_seconds_total"], "first CPU")
    disk_bytes = int_value(samples[-1]["engine_disk_write_bytes_total"], "last disk") - int_value(samples[0]["engine_disk_write_bytes_total"], "first disk")
    if cpu_seconds < 0 or disk_bytes < 0:
        fail("runtime recorder observed a cumulative process counter reset")
    write_windows = []
    for prior, current in zip(samples, samples[1:]):
        write_windows.append({
            "start_offset_seconds": prior["offset_seconds"],
            "end_offset_seconds": current["offset_seconds"],
            "bytes": current["engine_disk_write_bytes_total"] - prior["engine_disk_write_bytes_total"],
        })

    inventories = []
    for index, item in enumerate(raw_observations):
        sqlite_inventory = object_value(
            item.get("sqlite_families"),
            f"recorder.observations[{index}].sqlite_families",
        )
        inventories.append(set(sqlite_inventory))
    sqlite_names = set(inventories[0])
    if any(names != sqlite_names for names in inventories[1:]):
        fail("discovered SQLite family inventory changed during the epoch")
    if not REQUIRED_SQLITE_FAMILIES.issubset(sqlite_names):
        fail("runtime recorder omitted a required shipping SQLite family")
    sqlite_rows = []
    for name in sorted(sqlite_names):
        rows = [object_value(item.get("sqlite_families"), "observation.sqlite_families").get(name) for item in raw_observations]
        if any(not isinstance(row, dict) for row in rows):
            fail(f"runtime recorder did not measure SQLite family {name} at every sample")
        typed_rows = [object_value(row, f"SQLite observation {name}") for row in rows]
        caps = {int_value(row.get("configured_cap_bytes"), f"{name}.cap", minimum=1) for row in typed_rows}
        floors = {int_value(row.get("configured_free_space_floor_bytes"), f"{name}.floor") for row in typed_rows}
        if len(caps) != 1 or len(floors) != 1:
            fail(f"SQLite family {name} policy changed during the epoch")
        sqlite_names.add(name)
        sqlite_rows.append({
            "name": name,
            "max_db_wal_shm_bytes": max(int_value(row.get("footprint_bytes"), f"{name}.footprint") for row in typed_rows),
            "configured_cap_bytes": next(iter(caps)),
            "minimum_free_space_bytes": min(int_value(row.get("free_space_bytes"), f"{name}.free") for row in typed_rows),
            "configured_free_space_floor_bytes": next(iter(floors)),
        })

    last_boundaries = object_value(samples[-1].get("conservation"), "last sample conservation")
    trace_writable = sum(1 for item in raw_observations if item.get("trace_writable") is True) / len(raw_observations)
    recovery_states = [bool(item.get("trace_recovering")) for item in raw_observations]
    recovery_transitions = sum(1 for a, b in zip(recovery_states, recovery_states[1:]) if a != b)
    trace_shed_delta = int_value(raw_observations[-1].get("trace_shed_mutations_total"), "last trace shed") - int_value(raw_observations[0].get("trace_shed_mutations_total"), "first trace shed")
    if trace_shed_delta < 0:
        fail("TraceGraph shed-mutation counter reset during the qualification epoch")
    graph_accounting_rows = [
        object_value(
            sample.get("trace_graph_write_accounting"),
            "sample.trace_graph_write_accounting",
        )
        for sample in samples
    ]
    graph_cumulative_keys = (
        "write_attempts_total", "write_batches_committed_total",
        "write_batches_failed_total", "write_rows_attempted_total",
        "write_rows_committed_total", "write_rows_failed_total",
        "entity_observations_total", "edge_observations_total",
        "coalesced_noop_rows_total",
    )
    for key in graph_cumulative_keys:
        values = [int_value(row.get(key), f"TraceGraph {key}") for row in graph_accounting_rows]
        if any(later < earlier for earlier, later in zip(values, values[1:])):
            fail(f"TraceGraph {key} counter reset during the qualification epoch")
    graph_coalesced_delta = (
        int_value(graph_accounting_rows[-1].get("coalesced_noop_rows_total"), "last graph coalesced")
        - int_value(graph_accounting_rows[0].get("coalesced_noop_rows_total"), "first graph coalesced")
    )
    graph_failed_batches_delta = (
        int_value(graph_accounting_rows[-1].get("write_batches_failed_total"), "last graph failed batches")
        - int_value(graph_accounting_rows[0].get("write_batches_failed_total"), "first graph failed batches")
    )
    graph_failed_rows_delta = (
        int_value(graph_accounting_rows[-1].get("write_rows_failed_total"), "last graph failed rows")
        - int_value(graph_accounting_rows[0].get("write_rows_failed_total"), "first graph failed rows")
    )
    trace_store_rows = [
        object_value(sample.get("trace_store_admission"), "sample.trace_store_admission")
        for sample in samples
    ]
    trace_store_writable = sum(
        1 for row in trace_store_rows
        if row.get("enabled") is True
        and row.get("blocked") is False
        and row.get("store_available") is True
        and row.get("recovering") is False
    ) / len(trace_store_rows)
    sequence_eviction_delta = int_value(samples[-1]["sequence_pending_steps_evicted_total"], "last sequence evictions") - int_value(samples[0]["sequence_pending_steps_evicted_total"], "first sequence evictions")
    first_boundaries = object_value(samples[0].get("conservation"), "first sample conservation")
    checkpoint_shed_delta = int_value(
        object_value(last_boundaries.get("sequence-checkpoint"), "last checkpoint").get("explicitly_shed"),
        "last checkpoint explicitly_shed",
    ) - int_value(
        object_value(first_boundaries.get("sequence-checkpoint"), "first checkpoint").get("explicitly_shed"),
        "first checkpoint explicitly_shed",
    )
    journal_shed_delta = int_value(
        object_value(last_boundaries.get("sequence-journal"), "last journal").get("explicitly_shed"),
        "last journal explicitly_shed",
    ) - int_value(
        object_value(first_boundaries.get("sequence-journal"), "first journal").get("explicitly_shed"),
        "first journal explicitly_shed",
    )
    if checkpoint_shed_delta < 0 or journal_shed_delta < 0 or sequence_eviction_delta < 0:
        fail("sequence conservation counters reset during the qualification epoch")
    if journal_shed_delta != sequence_eviction_delta:
        fail("sequence journal shed does not reconcile with pending-step evictions")
    gui_values = [number_value(sample["gui_background_cpu_percent"], "GUI CPU") for sample in samples]
    rss_values = [int_value(sample["engine_rss_bytes"], "RSS") for sample in samples]
    rss_at = {int(round(number_value(sample["offset_seconds"], "offset"))): int_value(sample["engine_rss_bytes"], "RSS") for sample in samples}
    llm_rows = [object_value(sample.get("llm_quality"), "sample.llm_quality") for sample in samples]
    llm_configured = [bool_value(row.get("configured"), "sample.llm_quality.configured") for row in llm_rows]
    if any(value != llm_configured[0] for value in llm_configured[1:]):
        fail("LLM configuration changed during the qualification epoch")
    if not llm_configured[0]:
        fail("release qualification requires a configured LLM for alert investigation")
    if any(
        row.get("schema_version") != 2
        or row.get("accounting_conserved") is not True
        or row.get("healthy") is not True
        for row in llm_rows
    ):
        fail("configured LLM was unhealthy or non-conserving during qualification")
    llm_unspecified_delta = int_value(llm_rows[-1].get("unspecified_requested_total"), "LLM unspecified end") - int_value(llm_rows[0].get("unspecified_requested_total"), "LLM unspecified start")
    first_alert = object_value(llm_rows[0].get("alert_investigation"), "LLM alert start")
    last_alert = object_value(llm_rows[-1].get("alert_investigation"), "LLM alert end")
    llm_started_delta = int_value(last_alert.get("operations_started_total"), "LLM starts end") - int_value(first_alert.get("operations_started_total"), "LLM starts start")
    llm_accepted_delta = int_value(last_alert.get("accepted_total"), "LLM accepted end") - int_value(first_alert.get("accepted_total"), "LLM accepted start")
    llm_rejected_delta = int_value(last_alert.get("final_rejection_total"), "LLM rejected end") - int_value(first_alert.get("final_rejection_total"), "LLM rejected start")
    if min(llm_unspecified_delta, llm_started_delta, llm_accepted_delta, llm_rejected_delta) < 0:
        fail("LLM cumulative counters reset during the qualification epoch")
    if int_value(first_alert.get("current_operations"), "LLM current start") != 0 \
            or int_value(last_alert.get("current_operations"), "LLM current end") != 0:
        fail("alert investigation was still in flight at an epoch boundary")
    if llm_unspecified_delta != 0 or llm_rejected_delta != 0 \
            or llm_started_delta < 1 or llm_accepted_delta != llm_started_delta:
        fail(
            "qualification requires at least one accepted alert investigation "
            "and zero unattributed or final-rejected work"
        )

    report = {
        "schema": RUNTIME_SCHEMA,
        "result": "pass",
        "candidate_manifest_sha256": candidate_manifest_sha256,
        "candidate": candidate,
        "installed_engine": {
            "start": copy.deepcopy(probes.get("installed_engine_start")),
            "end": copy.deepcopy(probes.get("installed_engine_end")),
        },
        "host": copy.deepcopy(host),
        "workload": workload_record,
        "epoch": {
            "started_at": samples[0]["recorded_at"],
            "ended_at": samples[-1]["recorded_at"],
            "duration_seconds": duration,
            "uninterrupted": True,
            "sample_interval_seconds": samples[1]["offset_seconds"] - samples[0]["offset_seconds"],
            "max_sample_gap_seconds": max(current["offset_seconds"] - prior["offset_seconds"] for prior, current in zip(samples, samples[1:])),
            "sample_count": len(samples),
            "samples_sha256": samples_sha,
        },
        "samples": samples,
        "measurements": {
            "process": {
                "engine_pids": sorted({sample["engine_pid"] for sample in samples}),
                "crash_count": int_value(probes.get("crash_count"), "probes.crash_count"),
                "watchdog_exit_count": int_value(probes.get("watchdog_exit_count"), "probes.watchdog_exit_count"),
                "relaunch_count": max(0, len({sample["engine_pid"] for sample in samples}) - 1),
            },
            "conservation": {
                "all_samples_reconciled": True,
                "boundaries": [{"name": name, **copy.deepcopy(last_boundaries[name])} for name in sorted(REQUIRED_CONSERVATION_BOUNDARIES)],
            },
            "priority_fidelity": {
                key: max(number_value(sample["losses"][key], key) for sample in samples)
                for key in ("priority_lane_loss", "kernel_loss", "callback_copy_loss", "upstream_collector_loss")
            },
            "file_fidelity": {
                "unclassified_queue_loss": max(number_value(sample["losses"]["unclassified_file_queue_loss"], "file loss") for sample in samples),
                "complete_rule_corpus_evaluated": bool_value(probes.get("complete_rule_corpus_evaluated"), "probes.complete_rule_corpus_evaluated"),
                "rule_corpus_sha256": require_sha(probes.get("rule_corpus_sha256"), "probes.rule_corpus_sha256"),
                "semantic_reasons": copy.deepcopy(list_value(probes.get("semantic_reasons"), "probes.semantic_reasons")),
            },
            "correlation_continuity": {
                "recovery_coverage_seconds": duration,
                "checkpoint_shed": checkpoint_shed_delta,
                "journal_shed": journal_shed_delta,
                "pending_later_step_evictions_epoch_delta": sequence_eviction_delta,
                "sequence_state_continuity_maintained_all_samples": all(sample["sequence_state_continuity_maintained"] is True and sample["sequence_state_continuity_detail"] == "nominal" for sample in samples),
                "source_bound_continuity_tests_sha256": require_sha(
                    object_value(
                        object_value(probes.get("evidence"), "probes.evidence").get("focused_runtime_tests"),
                        "probes.evidence.focused_runtime_tests",
                    ).get("output_sha256"),
                    "probes.evidence.focused_runtime_tests.output_sha256",
                ),
                "live_rule_reload_signal": copy.deepcopy(
                    object_value(
                        object_value(probes.get("evidence"), "probes.evidence").get("live_sighup"),
                        "probes.evidence.live_sighup",
                    )
                ),
            },
            "event_storage": {
                "unreachable_budget_fault_count": sum(1 for item in raw_observations if item.get("event_budget_fault") is True),
                "prune_vacuum_refill_loop_count": int_value(probes.get("prune_vacuum_refill_loop_count"), "probes.prune_vacuum_refill_loop_count"),
                "search_tier_gaps_reconcile_exactly": bool_value(probes.get("search_tier_gaps_reconcile_exactly"), "probes.search_tier_gaps_reconcile_exactly"),
                "search_tier_gaps_visible": bool_value(probes.get("search_tier_gaps_visible"), "probes.search_tier_gaps_visible"),
            },
            "trace_graph": {
                "writable_duty_fraction": trace_writable,
                "mutation_shed": trace_shed_delta,
                "recovery_oscillation_count": max(0, recovery_transitions - 1),
                "write_accounting_reconciled_all_samples": True,
                "coalesced_noop_rows_epoch_delta": graph_coalesced_delta,
                "failed_batches_epoch_delta": graph_failed_batches_delta,
                "failed_rows_epoch_delta": graph_failed_rows_delta,
            },
            "trace_store": {
                "full_writer_duty_fraction": trace_store_writable,
                "max_footprint_bytes": max(
                    int_value(row.get("footprint_bytes"), "TraceStore footprint")
                    for row in trace_store_rows
                ),
                "minimum_free_space_bytes": min(
                    int_value(row.get("free_space_bytes"), "TraceStore free space")
                    for row in trace_store_rows
                ),
            },
            "workload_ingress": workload_ingress,
            "disk_writes": {
                "engine_bytes": disk_bytes,
                "average_bytes_per_second": disk_bytes / duration,
                "windows": write_windows,
                "macos_disk_writes_diagnostic_count": int_value(probes.get("macos_disk_writes_diagnostic_count"), "probes.macos_disk_writes_diagnostic_count"),
            },
            "cpu": {
                "engine_cpu_seconds": cpu_seconds,
                "engine_average_cores": cpu_seconds / duration,
                "gui_background_percent_samples": gui_values,
                "gui_background_p95_percent": percentile_nearest_rank(gui_values, 0.95),
            },
            "memory": {
                "engine_max_rss_bytes": max(rss_values),
                "engine_rss_minute_5_bytes": rss_at.get(300, -1),
                "engine_rss_minute_15_bytes": rss_at.get(900, -1),
            },
            "disk_safety": {"inventory_complete": True, "sqlite_families": sqlite_rows},
            "ai_quality": {
                "configured": True,
                "feature_disabled_entire_epoch": False,
                "schema_2_and_accounting_conserved_all_samples": True,
                "unspecified_requests_epoch_delta": llm_unspecified_delta,
                "alert_investigations_started_epoch_delta": llm_started_delta,
                "alert_investigations_accepted_epoch_delta": llm_accepted_delta,
                "alert_investigations_final_rejected_epoch_delta": llm_rejected_delta,
            },
            "rules": copy.deepcopy(object_value(probes.get("rules"), "probes.rules")),
            "shipped_tools": copy.deepcopy(object_value(probes.get("shipped_tools"), "probes.shipped_tools")),
        },
        "evidence": {
            "payload_inventory_sha256": inventory["sha256"],
            "raw_samples_sha256": samples_sha,
            "raw_samples_format": "embedded-json-v1",
            "recorded_at": samples[-1]["recorded_at"],
            "recorder_schema": RUNTIME_RECORDER_SCHEMA,
            "capture_mode": capture_mode,
            "observations_sha256": sha256_bytes(canonical_json_bytes(raw_observations)),
        },
        "recorder_observations": raw_observations,
        "recorder_probe_evidence": copy.deepcopy(
            object_value(probes.get("evidence"), "probes.evidence")
        ),
        "candidate_artifact_verification": {"payload_inventory_sha256": inventory["sha256"]},
    }
    return report


def subprocess_probe(
    command: Sequence[str], *, label: str, cwd: pathlib.Path | None = None,
    environment: Mapping[str, str] | None = None, include_output: bool = False,
    stdin_text: str | None = None,
) -> Dict[str, Any]:
    try:
        completed = subprocess.run(
            list(command), cwd=str(cwd) if cwd else None,
            capture_output=True, text=True, check=False,
            env=dict(environment) if environment is not None else None,
            input=stdin_text,
        )
    except OSError as exc:
        fail(f"{label} could not start: {exc}")
    combined = (completed.stdout or "") + (completed.stderr or "")
    evidence = {
        "command": list(command),
        "exit_code": completed.returncode,
        "output_sha256": sha256_bytes(combined.encode("utf-8")),
        "output_tail": combined[-4096:],
        "output_line_count": len(combined.splitlines()),
    }
    if include_output:
        evidence["output"] = combined
    if stdin_text is not None:
        evidence["stdin"] = stdin_text
        evidence["stdin_sha256"] = sha256_bytes(stdin_text.encode("utf-8"))
    if completed.returncode != 0:
        fail(f"{label} failed (exit {completed.returncode}): {combined[-1000:].strip()}")
    return evidence


def original_user_command(command: Sequence[str]) -> List[str]:
    user = os.environ.get("SUDO_USER", "")
    if os.geteuid() == 0 and user and user != "root":
        if not re.fullmatch(r"[A-Za-z0-9._-]+", user):
            fail("SUDO_USER has an unsafe shape")
        return ["/usr/bin/sudo", "-H", "-u", user, *command]
    return list(command)


def containment_process_environment() -> Dict[str, str]:
    """Return the complete, recorded environment for containment subprocesses."""
    environment = {
        "GIT_NO_REPLACE_OBJECTS": "1",
        "HOME": pwd.getpwuid(os.getuid()).pw_dir,
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "TMPDIR": "/private/tmp",
    }
    return environment


def darwin_process_path(pid: int) -> pathlib.Path:
    if platform.system() != "Darwin":
        fail("installed-host runtime recording requires macOS")
    try:
        libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    except OSError as exc:
        fail(f"libproc is unavailable: {exc}")
    buffer = ctypes.create_string_buffer(4096)
    libproc.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    libproc.proc_pidpath.restype = ctypes.c_int
    length = libproc.proc_pidpath(pid, buffer, len(buffer))
    if length <= 0:
        fail(f"cannot resolve executable path for engine PID {pid}")
    try:
        value = buffer.value.decode("utf-8")
    except UnicodeDecodeError:
        fail("installed engine executable path is not UTF-8")
    return pathlib.Path(value)


def darwin_process_metrics(pid: int) -> Dict[str, Any]:
    """Read cumulative CPU/write counters and RSS from proc_pid_rusage v4."""
    path = darwin_process_path(pid)
    try:
        libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    except OSError as exc:
        fail(f"libproc is unavailable: {exc}")
    buffer = ctypes.create_string_buffer(256)
    libproc.proc_pid_rusage.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
    libproc.proc_pid_rusage.restype = ctypes.c_int
    if libproc.proc_pid_rusage(pid, 4, ctypes.byref(buffer)) != 0:
        fail(f"cannot read rusage for engine PID {pid}")
    raw = buffer.raw

    def u64(offset: int) -> int:
        return int(struct.unpack_from("=Q", raw, offset)[0])

    if path.is_symlink() or not path.is_file():
        fail("installed engine executable is missing, non-regular, or redirected")
    return {
        "engine_cpu_seconds_total": (u64(16) + u64(24)) / 1_000_000_000.0,
        "engine_rss_bytes": u64(64),
        "engine_disk_write_bytes_total": u64(152),
        "executable_path": str(path),
        "executable_sha256": sha256_file(path),
    }


def darwin_engine_amfi_flags(pid: int) -> int:
    try:
        libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    except OSError as exc:
        fail(f"libSystem is unavailable: {exc}")
    flags = ctypes.c_uint32(0)
    libc.csops.argtypes = [ctypes.c_int, ctypes.c_uint, ctypes.c_void_p, ctypes.c_size_t]
    libc.csops.restype = ctypes.c_int
    if libc.csops(pid, 0, ctypes.byref(flags), ctypes.sizeof(flags)) != 0:
        fail("cannot inspect installed engine code-signing status")
    required = 0x00000001 | 0x00000100 | 0x00000200 | 0x00010000
    if flags.value & required != required:
        fail("installed engine is not AMFI-valid, hard, kill-on-invalid, and hardened-runtime")
    return int(flags.value)


def command_text(command: Sequence[str], label: str) -> str:
    return run_checked(command, label).stdout.strip()


def installed_runtime_host(pid: int) -> Dict[str, Any]:
    ioreg = command_text(
        ["/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
        "hardware identity probe",
    )
    match = re.search(r'"IOPlatformUUID"\s*=\s*"([0-9A-Fa-f-]+)"', ioreg)
    if not match:
        fail("hardware identity probe did not return IOPlatformUUID")
    sip = command_text(["/usr/bin/csrutil", "status"], "SIP status probe")
    if "System Integrity Protection status: enabled" not in sip:
        fail("installed-host qualification requires SIP enabled")
    bootargs = command_text(
        ["/usr/sbin/sysctl", "-n", "kern.bootargs"], "boot-arguments probe"
    )
    lowered_bootargs = bootargs.lower()
    if any(
        token in lowered_bootargs
        for token in (
            "amfi_get_out_of_my_way", "amfi_allow_any_signature",
            "cs_enforcement_disable", "amfi=0",
        )
    ):
        fail("installed-host qualification forbids AMFI-disabling boot arguments")
    amfi_flags = darwin_engine_amfi_flags(pid)
    power_text = command_text(["/usr/bin/pmset", "-g", "batt"], "power-source probe")
    power_source = "AC" if "AC Power" in power_text else "Battery"
    return {
        "machine_id_sha256": sha256_bytes(match.group(1).lower().encode("ascii")),
        "hardware_model": command_text(
            ["/usr/sbin/sysctl", "-n", "hw.model"], "hardware-model probe"
        ),
        "architecture": command_text(
            ["/usr/bin/uname", "-m"], "architecture probe"
        ),
        "logical_cpu_count": int(command_text(
            ["/usr/sbin/sysctl", "-n", "hw.logicalcpu"], "CPU-count probe"
        )),
        "memory_bytes": int(command_text(
            ["/usr/sbin/sysctl", "-n", "hw.memsize"], "memory-size probe"
        )),
        "macos_version": command_text(
            ["/usr/bin/sw_vers", "-productVersion"], "macOS-version probe"
        ),
        "macos_build": command_text(
            ["/usr/bin/sw_vers", "-buildVersion"], "macOS-build probe"
        ),
        "sip_enabled": True,
        "amfi_enforced": True,
        "amfi_engine_cs_flags": amfi_flags,
        "power_source": power_source,
    }


def installed_engine_identity(pid: int, recorded_at: str) -> Dict[str, Any]:
    path = darwin_process_path(pid)
    if not str(path).startswith("/Library/SystemExtensions/") \
            or not str(path).endswith(
                "/com.maccrab.agent.systemextension/Contents/MacOS/com.maccrab.agent"
            ):
        fail("running engine is not the installed MacCrab system extension")
    run_checked(
        [fixed_tool("/usr/bin/codesign"), "--verify", "--strict", str(path)],
        "installed system-extension signature verification",
    )
    identity = codesign_identity(path, label="installed engine signing identity")
    require_maccrab_signing_identity(
        identity, expected_identifier=EXPECTED_AGENT_IDENTIFIER,
        path="installed engine signing identity",
    )
    plist_path = path.parent.parent / "Info.plist"
    try:
        with plist_path.open("rb") as handle:
            info = plistlib.load(handle)
    except (OSError, plistlib.InvalidFileException) as exc:
        fail(f"installed system-extension Info.plist is unreadable: {exc}")
    return {
        **identity,
        "engine_pid": pid,
        "recorded_at": recorded_at,
        "executable_path": str(path),
        "executable_sha256": sha256_file(path),
        "system_extension_bundle_identifier": string_value(
            info.get("CFBundleIdentifier"), "installed system-extension bundle identifier"
        ),
        "bundle_version": string_value(
            info.get("CFBundleShortVersionString"), "installed system-extension version"
        ),
        "build_version": string_value(
            info.get("CFBundleVersion"), "installed system-extension build"
        ),
    }


def gui_background_cpu_percent() -> float:
    output = command_text(
        ["/bin/ps", "-axo", "pid=,pcpu=,comm="], "GUI CPU probe"
    )
    total = 0.0
    for line in output.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) != 3:
            continue
        command = parts[2]
        if command.endswith("/MacCrab") or command == "MacCrab":
            try:
                total += float(parts[1])
            except ValueError:
                fail("GUI CPU probe returned a non-numeric percentage")
    return total


def read_live_heartbeat(
    path: pathlib.Path, candidate: Mapping[str, Any]
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    if path.is_symlink() or not path.is_file():
        fail(f"installed rich heartbeat is missing, non-regular, or redirected: {path}")
    try:
        descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as handle:
            stat_result = os.fstat(handle.fileno())
            raw_bytes = handle.read()
        raw_text = raw_bytes.decode("utf-8")
        heartbeat = json.loads(raw_text)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"installed rich heartbeat cannot be captured exactly: {exc}")
    if not isinstance(heartbeat, dict):
        fail("installed rich heartbeat root must be an object")
    if stat_result.st_uid != 0 or stat_result.st_mode & 0o022:
        fail("installed rich heartbeat must be root-owned and not group/world-writable")
    if heartbeat.get("engine_version") != candidate.get("version") \
            or heartbeat.get("engine_build") != candidate.get("build_number"):
        fail("installed rich heartbeat is not from the exact candidate version/build")
    return heartbeat, {
        "path": str(path),
        "raw_sha256": sha256_bytes(raw_bytes),
        "canonical_sha256": sha256_bytes(canonical_json_bytes(heartbeat)),
        "raw_json": raw_text,
        "owner_uid": stat_result.st_uid,
        "mode": stat_result.st_mode & 0o7777,
        "mtime_unix": stat_result.st_mtime,
    }


def storage_configuration(
    heartbeat: Mapping[str, Any], data_dirs: Sequence[pathlib.Path],
    overrides: Mapping[str, int],
) -> Tuple[Dict[str, int], Dict[str, int]]:
    storage: Dict[str, Any] = {}
    config_paths = [directory / "daemon_config.json" for directory in data_dirs]
    existing_configs = [path for path in config_paths if path.exists() or path.is_symlink()]
    if len(existing_configs) > 1:
        fail("multiple daemon_config.json files make installed storage policy ambiguous")
    if existing_configs:
        config = read_json_file(existing_configs[0], "installed daemon configuration")
        storage = object_value(config.get("storage", {}), "daemon_config.storage")

    def storage_mib(camel: str, snake: str, default: int) -> int:
        value = storage.get(camel, storage.get(snake, default))
        return int_value(value, f"daemon_config.storage.{camel}", minimum=1)

    alert_budget = object_value(
        heartbeat.get("alert_evidence_budget"), "heartbeat.alert_evidence_budget"
    )
    graph = object_value(
        heartbeat.get("tracegraph_storage_admission"),
        "heartbeat.tracegraph_storage_admission",
    )
    traces = object_value(
        heartbeat.get("traces_storage_admission"),
        "heartbeat.traces_storage_admission",
    )
    caps = {
        "events.db": heartbeat_counter(
            alert_budget, "events_family_effective_cap_bytes",
            "heartbeat.alert_evidence_budget",
        ),
        "alerts.db": heartbeat_counter(
            alert_budget, "alerts_family_combined_cap_bytes",
            "heartbeat.alert_evidence_budget",
        ),
        "campaigns.db": storage_mib(
            "campaignsMaxSizeMB", "campaigns_max_size_mb", 50
        ) * MIB,
        "tracegraph.db": int_value(
            graph.get(
                "max_footprint_bytes",
                storage_mib("tracegraphMaxSizeMB", "tracegraph_max_size_mb", 250) * MIB,
            ),
            "tracegraph configured cap", minimum=1,
        ),
        "traces.db": int_value(
            traces.get(
                "max_footprint_bytes",
                storage_mib("tracesMaxSizeMB", "traces_max_size_mb", 100) * MIB,
            ),
            "traces configured cap", minimum=1,
        ),
        "attribution_overrides.db": 32 * MIB,
    }
    caps.update(overrides)
    floors = {name: DEFAULT_SQLITE_FREE_SPACE_FLOOR_BYTES for name in caps}
    for name, admission in (("tracegraph.db", graph), ("traces.db", traces)):
        if "free_space_floor_bytes" in admission:
            floors[name] = int_value(
                admission.get("free_space_floor_bytes"), f"{name} free-space floor"
            )
    return caps, floors


def sqlite_family_observation(
    *, heartbeat: Mapping[str, Any], data_dirs: Sequence[pathlib.Path],
    overrides: Mapping[str, int],
) -> Dict[str, Any]:
    for directory in data_dirs:
        if directory.is_symlink() or not directory.is_dir():
            fail(f"installed data directory is missing, non-directory, or redirected: {directory}")
    caps, floors = storage_configuration(heartbeat, data_dirs, overrides)
    discovered = set(REQUIRED_SQLITE_FAMILIES)
    for directory in data_dirs:
        for path in directory.glob("*.db"):
            if path.is_symlink() or not path.is_file():
                fail(f"discovered SQLite family is non-regular or redirected: {path}")
            discovered.add(path.name)
    missing_caps = discovered - set(caps)
    if missing_caps:
        fail(
            "discovered SQLite families have no exact configured cap; pass "
            "--sqlite-cap NAME=BYTES for: " + ", ".join(sorted(missing_caps))
        )
    result: Dict[str, Any] = {}
    for name in sorted(discovered):
        footprint = 0
        paths = []
        free_values = []
        for directory in data_dirs:
            free_values.append(os.statvfs(str(directory)).f_bavail * os.statvfs(str(directory)).f_frsize)
            base = directory / name
            for family_path in (base, pathlib.Path(str(base) + "-wal"), pathlib.Path(str(base) + "-shm")):
                if family_path.exists() or family_path.is_symlink():
                    if family_path.is_symlink() or not family_path.is_file():
                        fail(f"SQLite family member is non-regular or redirected: {family_path}")
                    footprint += family_path.stat().st_size
                    paths.append(str(family_path))
        result[name] = {
            "footprint_bytes": footprint,
            "configured_cap_bytes": caps[name],
            "free_space_bytes": min(free_values),
            "configured_free_space_floor_bytes": floors.get(
                name, DEFAULT_SQLITE_FREE_SPACE_FLOOR_BYTES
            ),
            "paths": paths,
        }
    return result


def parse_sqlite_cap_overrides(values: Sequence[str]) -> Dict[str, int]:
    result: Dict[str, int] = {}
    for value in values:
        if "=" not in value:
            fail("--sqlite-cap must be NAME=BYTES")
        name, raw_bytes = value.split("=", 1)
        if not re.fullmatch(r"[A-Za-z0-9_.-]+\.db", name):
            fail("--sqlite-cap NAME must be a plain .db filename")
        try:
            byte_count = int(raw_bytes)
        except ValueError:
            fail("--sqlite-cap BYTES must be an integer")
        if byte_count <= 0 or name in result:
            fail("--sqlite-cap values must be positive and unique")
        result[name] = byte_count
    return result


def rule_corpus_digest(root: pathlib.Path) -> str:
    rules = root / "Rules"
    files = sorted(
        (path for path in rules.rglob("*") if path.is_file() and not path.is_symlink()),
        key=lambda path: path.relative_to(root).as_posix(),
    )
    if not files:
        fail("rule corpus is empty")
    records = [
        {"path": path.relative_to(root).as_posix(), "sha256": sha256_file(path)}
        for path in files
    ]
    return sha256_bytes(canonical_json_bytes(records))


def source_runtime_probe_evidence(root: pathlib.Path) -> Dict[str, Any]:
    lint = subprocess_probe(
        original_user_command(["/bin/bash", str(root / "scripts/rule-lint.sh")]),
        label="complete rule-corpus lint", cwd=root,
    )
    focused = subprocess_probe(
        original_user_command([
            fixed_tool("/usr/bin/xcrun"), "swift", "test", "--package-path", str(root),
            "--filter", FOCUSED_RUNTIME_TEST_FILTER,
        ]),
        label="runtime continuity/rule-synchronization focused tests", cwd=root,
    )
    focused["observed_test_count"] = passing_test_count(
        string_value(
            focused.get("output_tail"), "focused runtime test output", nonempty=False
        ),
        "focused runtime test output",
    )
    return {"rule_lint": lint, "focused_runtime_tests": focused}


def mounted_tool_probes(dmg: pathlib.Path, version: str, normal_policy: bool) -> Dict[str, Any]:
    hdiutil = fixed_tool("/usr/bin/hdiutil")
    attached: str | None = None
    try:
        result = run_checked(
            [hdiutil, "attach", "-readonly", "-nobrowse", "-plist", str(dmg)],
            "read-only candidate mount for shipped-tool probes",
        )
        try:
            plist = plistlib.loads(result.stdout.encode("utf-8"))
        except plistlib.InvalidFileException as exc:
            fail(f"hdiutil did not return a readable attach plist: {exc}")
        mountpoints = [
            entity.get("mount-point")
            for entity in plist.get("system-entities", [])
            if isinstance(entity, dict) and entity.get("mount-point")
        ]
        if len(mountpoints) != 1 or not str(mountpoints[0]).startswith("/Volumes/"):
            fail("candidate did not mount at one unambiguous /Volumes path")
        attached = str(mountpoints[0])
        base = pathlib.Path(attached) / "MacCrab.app/Contents/Resources/bin"
        commands = {
            "maccrabctl": (base / "maccrabctl", ["version"]),
            "maccrab_mcp": (base / "maccrab-mcp", ["--version"]),
        }
        probes: Dict[str, Any] = {}
        for name, (path, arguments) in commands.items():
            if path.is_symlink() or not path.is_file():
                fail(f"mounted candidate is missing regular shipped tool {path.name}")
            completed = subprocess.run(
                [str(path), *arguments], capture_output=True, text=True, check=False
            )
            combined = ((completed.stdout or "") + (completed.stderr or "")).strip()
            if completed.returncode != 0 or version not in combined:
                fail(f"mounted {path.name} version probe failed or named the wrong version")
            probes[name] = {
                "path": str(path),
                "exit_code": completed.returncode,
                "version_output": combined,
                "sip_amfi_normal": normal_policy,
            }
        return probes
    finally:
        if attached:
            subprocess.run(
                [hdiutil, "detach", attached], capture_output=True, text=True, check=False
            )


def attach_readonly_candidate(
    dmg: pathlib.Path, label: str
) -> Tuple[pathlib.Path, Dict[str, Any]]:
    command = [
        fixed_tool("/usr/bin/hdiutil"), "attach", "-readonly", "-nobrowse",
        "-plist", str(dmg),
    ]
    environment = containment_process_environment()
    evidence = subprocess_probe(
        command, label=label, environment=environment, include_output=True
    )
    evidence["environment"] = dict(environment)
    try:
        plist = plistlib.loads(
            string_value(evidence.get("output"), f"{label}.output").encode("utf-8")
        )
    except plistlib.InvalidFileException as exc:
        fail(f"{label} did not return a readable attach plist: {exc}")
    mountpoints = [
        entity.get("mount-point")
        for entity in plist.get("system-entities", [])
        if isinstance(entity, dict) and entity.get("mount-point")
    ]
    if len(mountpoints) != 1 or not str(mountpoints[0]).startswith("/Volumes/"):
        fail(f"{label} did not create one unambiguous read-only /Volumes mount")
    return pathlib.Path(str(mountpoints[0])), evidence


def record_candidate_containment_execution(
    *, mountpoint: pathlib.Path, candidate: Mapping[str, Any],
    candidate_verification: Mapping[str, Any], mount_evidence: Mapping[str, Any],
) -> Tuple[Dict[str, Any], Dict[str, pathlib.Path]]:
    inventory = object_value(
        candidate_verification.get("payload_inventory"),
        "artifact_verification.payload_inventory",
    )
    entries = {
        object_value(item, "candidate payload entry").get("path"): object_value(
            item, "candidate payload entry"
        )
        for item in list_value(
            inventory.get("entries"), "artifact_verification.payload_inventory.entries"
        )
    }
    rows: List[Dict[str, Any]] = []
    paths: Dict[str, pathlib.Path] = {}
    for role, (relative, expected_identifier) in CONTAINMENT_CANDIDATE_BINARIES.items():
        path = mountpoint / relative
        if path.is_symlink() or not path.is_file() or not os.access(path, os.X_OK):
            fail(f"mounted candidate containment binary is missing or redirected: {relative}")
        run_checked(
            [fixed_tool("/usr/bin/codesign"), "--verify", "--strict", str(path)],
            f"mounted candidate containment {role} signature verification",
        )
        identity = codesign_identity(
            path, label=f"mounted candidate containment {role} identity"
        )
        require_maccrab_signing_identity(
            identity, expected_identifier=expected_identifier,
            path=f"mounted candidate containment {role}",
        )
        digest = sha256_file(path)
        size = path.stat().st_size
        payload = object_value(entries.get(relative), f"candidate payload {relative}")
        if payload.get("kind") != "file" or payload.get("sha256") != digest \
                or payload.get("size_bytes") != size:
            fail(f"mounted containment {role} bytes do not match candidate inventory")
        rows.append({
            "role": role,
            "relative_path": relative,
            "sha256": digest,
            "size_bytes": size,
            "developer_id": identity["developer_id"],
            "team_id": identity["team_id"],
            "signing_identifier": identity["signing_identifier"],
            "cdhash": identity["cdhash"],
        })
        paths[role] = path
    execution = {
        "dmg_sha256": object_value(candidate.get("dmg"), "candidate.dmg")["sha256"],
        "mountpoint": str(mountpoint),
        "mount": copy.deepcopy(mount_evidence),
        "binaries": rows,
    }
    validate_candidate_execution(
        execution, candidate=candidate,
        candidate_verification=candidate_verification,
        allow_test_fixture=False,
    )
    return execution, paths


def capture_runtime_observation(
    *, offset: int, scheduled_at: dt.datetime, heartbeat_path: pathlib.Path,
    candidate: Mapping[str, Any], data_dirs: Sequence[pathlib.Path],
    sqlite_overrides: Mapping[str, int],
) -> Dict[str, Any]:
    captured_at = dt.datetime.now(dt.timezone.utc)
    heartbeat, heartbeat_file = read_live_heartbeat(heartbeat_path, candidate)
    pid = heartbeat_counter(heartbeat, "engine_pid", "heartbeat")
    process = darwin_process_metrics(pid)
    graph = object_value(
        heartbeat.get("tracegraph_storage_admission"),
        "heartbeat.tracegraph_storage_admission",
    )
    budget = object_value(
        heartbeat.get("events_retention_budget"), "heartbeat.events_retention_budget"
    )
    budget_state = string_value(
        budget.get("state"), "heartbeat.events_retention_budget.state"
    )
    value = {
        "schema": RUNTIME_OBSERVATION_SCHEMA,
        "offset_seconds": offset,
        "recorded_at": scheduled_at.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "captured_at": captured_at.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "heartbeat": heartbeat,
        "heartbeat_file": heartbeat_file,
        "process": process,
        "gui_background_cpu_percent": gui_background_cpu_percent(),
        "sqlite_families": sqlite_family_observation(
            heartbeat=heartbeat, data_dirs=data_dirs, overrides=sqlite_overrides
        ),
        "trace_writable": (
            graph.get("enabled") is True
            and graph.get("blocked") is False
            and graph.get("store_available") is True
        ),
        "trace_recovering": bool_value(
            graph.get("recovering"), "heartbeat.tracegraph.recovering"
        ),
        "trace_shed_mutations_total": heartbeat_counter(
            graph, "shed_mutations_total", "heartbeat.tracegraph"
        ),
        "event_budget_fault": budget_state.startswith("degraded_")
            or budget.get("sticky") is True,
    }
    # This is also the capability preflight: missing producer ledgers fail now,
    # before an operator wastes a 900-second epoch.
    sample_from_recorder_observation(value, "live observation")
    return value


def log_diagnostic_count(
    *, started_at: str, ended_at: str, predicate: str, label: str
) -> Tuple[int, Dict[str, Any]]:
    command = [
        "/usr/bin/log", "show", "--style", "compact",
        "--start", started_at, "--end", ended_at, "--predicate", predicate,
    ]
    evidence = subprocess_probe(command, label=label)
    # `log show --style compact` emits one header line when there are matches.
    return max(0, int_value(
        evidence.get("output_line_count"), f"{label}.output_line_count"
    ) - 1), evidence


def live_runtime_recording(
    *, root: pathlib.Path, candidate_manifest: Mapping[str, Any],
    candidate_manifest_sha256: str, dmg: pathlib.Path,
    heartbeat_path: pathlib.Path, data_dirs: Sequence[pathlib.Path],
    sqlite_overrides: Mapping[str, int], capture_path: pathlib.Path,
) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    if platform.system() != "Darwin" or os.geteuid() != 0:
        fail("record-runtime must run with sudo on the installed reference Mac")
    candidate = object_value(candidate_manifest.get("candidate"), "candidate")
    preflight_heartbeat, _ = read_live_heartbeat(heartbeat_path, candidate)
    preflight_pid = heartbeat_counter(preflight_heartbeat, "engine_pid", "heartbeat")
    host = installed_runtime_host(preflight_pid)
    preflight_scheduled = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    # Fail quickly if this engine lacks any exact producer ledger or DB policy.
    capture_runtime_observation(
        offset=0, scheduled_at=preflight_scheduled,
        heartbeat_path=heartbeat_path, candidate=candidate, data_dirs=data_dirs,
        sqlite_overrides=sqlite_overrides,
    )
    source_evidence = source_runtime_probe_evidence(root)
    tools = mounted_tool_probes(
        dmg, string_value(candidate.get("version"), "candidate.version"),
        host["sip_enabled"] is True and host["amfi_enforced"] is True,
    )

    # Capture the installed engine's signed identity before the epoch starts.
    # Re-reading both endpoints after the run would only prove the end state and
    # could let a different executable serve the earlier observations.
    identity_started_at = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    installed_start = installed_engine_identity(
        preflight_pid,
        identity_started_at.isoformat().replace("+00:00", "Z"),
    )
    start_wall = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    start_monotonic = time.monotonic()
    observations: List[Dict[str, Any]] = []
    workload_process: subprocess.Popen[str] | None = None
    workload_command: List[str] | None = None
    reload_evidence: Dict[str, Any] | None = None
    for offset in range(0, int(MIN_EPOCH_SECONDS) + 1, 30):
        target = start_monotonic + offset
        remaining = target - time.monotonic()
        if remaining > 0:
            time.sleep(remaining)
        scheduled_at = start_wall + dt.timedelta(seconds=offset)
        observation = capture_runtime_observation(
            offset=offset, scheduled_at=scheduled_at,
            heartbeat_path=heartbeat_path, candidate=candidate,
            data_dirs=data_dirs, sqlite_overrides=sqlite_overrides,
        )
        observations.append(observation)
        write_json_exclusive(capture_path, {
            "schema": RUNTIME_RECORDER_SCHEMA,
            "result": "capturing" if offset < MIN_EPOCH_SECONDS else "captured",
            "candidate_manifest_sha256": candidate_manifest_sha256,
            "observations": observations,
        })
        if offset == 300:
            workload_script = root / "scripts/runtime-qualification-workload.sh"
            if workload_script.is_symlink() or not workload_script.is_file():
                fail("fixed runtime qualification workload script is missing or redirected")
            workload_command = original_user_command(
                ["/bin/bash", str(workload_script)]
            )
            workload_process = subprocess.Popen(
                workload_command,
                cwd=str(root), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True,
            )
        if offset == 450:
            target_pid = heartbeat_counter(
                observation["heartbeat"], "engine_pid", "heartbeat"
            )
            sent_at = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
            os.kill(target_pid, signal.SIGHUP)
            reload_evidence = {
                "signal": "SIGHUP",
                "target_pid": target_pid,
                "sample_offset_seconds": offset,
                "sent_at": sent_at.isoformat().replace("+00:00", "Z"),
            }

    if workload_process is None:
        fail("fixed burst workload was not started")
    workload_stdout, workload_stderr = workload_process.communicate(timeout=180)
    if workload_process.returncode != 0:
        fail(f"fixed burst workload failed: {(workload_stderr or workload_stdout)[-1000:]}")
    first_pid = observations[0]["heartbeat"]["engine_pid"]
    last_pid = observations[-1]["heartbeat"]["engine_pid"]
    if first_pid != last_pid or reload_evidence is None:
        fail("engine PID changed or the live SIGHUP rule-reload probe was not sent")
    start_text = observations[0]["recorded_at"]
    end_text = observations[-1]["recorded_at"]
    installed_end = installed_engine_identity(last_pid, end_text)
    disk_diagnostics, disk_log = log_diagnostic_count(
        started_at=start_text, ended_at=end_text,
        predicate=(
            f"processID == {first_pid} AND "
            "(eventMessage CONTAINS[c] 'excessive disk write' OR "
            "eventMessage CONTAINS[c] 'high disk write')"
        ),
        label="macOS disk-write diagnostic query",
    )
    vacuum_events, vacuum_log = log_diagnostic_count(
        started_at=start_text, ended_at=end_text,
        predicate=(
            f"processID == {first_pid} AND "
            "(eventMessage CONTAINS[c] 'full VACUUM' OR "
            "eventMessage CONTAINS[c] 'budget is NOT reachable')"
        ),
        label="storage convergence diagnostic query",
    )
    auth_events, auth_log = log_diagnostic_count(
        started_at=start_text, ended_at=end_text,
        predicate=(
            "process == 'SecurityAgent' AND eventMessage CONTAINS[c] 'MacCrab'"
        ),
        label="administrator-prompt diagnostic query",
    )
    reload_log = subprocess_probe(
        [
            "/usr/bin/log", "show", "--style", "compact",
            "--start", reload_evidence["sent_at"], "--end", end_text,
            "--predicate",
            f"processID == {first_pid} AND eventMessage CONTAINS[c] '[SIGHUP]'",
        ],
        label="live rule-reload diagnostic query", include_output=True,
    )
    validate_live_reload_transcript(
        string_value(
            reload_log.get("output"), "live rule-reload output", nonempty=False
        ),
        "live rule-reload output",
    )
    below_floor = [
        list_value(
            object_value(item.get("heartbeat"), "observation heartbeat").get(
                "events_retention_below_forensic_floor"
            ),
            "heartbeat.events_retention_below_forensic_floor",
        )
        for item in observations
    ]
    graph_rows = [
        object_value(item["heartbeat"].get("tracegraph_storage_admission"), "tracegraph")
        for item in observations
    ]
    for row in graph_rows:
        trace_graph_write_accounting_sample(
            row, "heartbeat.tracegraph_storage_admission"
        )
    rules_loaded = [
        heartbeat_counter(item["heartbeat"], "rules_loaded", "heartbeat")
        for item in observations
    ]
    if min(rules_loaded) <= 0:
        fail("installed engine did not publish a non-empty loaded rule corpus")
    checkpoint = object_value(
        observations[0]["heartbeat"].get("sequence_checkpoint"),
        "first sequence checkpoint",
    )
    if checkpoint.get("restore_status") not in ("restored", "initialized", "recovered"):
        fail("installed engine did not report a valid sequence-checkpoint startup state")
    evidence = {
        **source_evidence,
        "workload": {
            "command": workload_command,
            "exit_code": workload_process.returncode,
            "output_sha256": sha256_bytes(
                ((workload_stdout or "") + (workload_stderr or "")).encode("utf-8")
            ),
            "output_tail": ((workload_stdout or "") + (workload_stderr or ""))[-4096:],
            "output_line_count": len(
                ((workload_stdout or "") + (workload_stderr or "")).splitlines()
            ),
        },
        "disk_diagnostic_log": disk_log,
        "storage_convergence_log": vacuum_log,
        "administrator_prompt_log": auth_log,
        "rule_reload_log": reload_log,
        "live_sighup": reload_evidence,
    }
    probes = {
        "installed_engine_start": installed_start,
        "installed_engine_end": installed_end,
        "crash_count": 0,
        "watchdog_exit_count": 0,
        "complete_rule_corpus_evaluated": True,
        "rule_corpus_sha256": rule_corpus_digest(root),
        "semantic_reasons": [],
        "prune_vacuum_refill_loop_count": vacuum_events,
        "search_tier_gaps_reconcile_exactly": all(not values for values in below_floor),
        "search_tier_gaps_visible": all(not values for values in below_floor),
        "macos_disk_writes_diagnostic_count": disk_diagnostics,
        "rules": {
            "sealed_rules_synchronized_before_readers": True,
            "corpus_parity": True,
            "ordinary_launch_without_admin_prompt": auth_events == 0,
        },
        "shipped_tools": tools,
        "evidence": evidence,
    }
    workload_fields = {
        "id": "normal-plus-burst",
        "version": "1",
        "description": (
            "900 seconds of ordinary browser/terminal/dashboard use plus the "
            "fixed bounded process/file/OTLP burst and safe high-alert trigger "
            "at minute 5, plus a measured live rule reload"
        ),
        "normal_operations": [
            "ordinary browser activity", "ordinary terminal activity",
            "MacCrab dashboard open in background",
        ],
        "burst_operations": [
            "scripts/runtime-qualification-workload.sh at minute 5",
            "one bounded loopback OTLP span",
            "one harmless /dev/tcp command-line alert trigger (no network access)",
            "SIGHUP rule reload at minute 7.5",
        ],
        "executors": [
            {"path": relative, "sha256": sha256_file(root / relative)}
            for relative in RUNTIME_WORKLOAD_EXECUTORS
        ],
    }
    return observations, host, workload_fields, probes


def containment_sources(root: pathlib.Path) -> List[pathlib.Path]:
    bases = [
        "Sources/MacCrabForensics/TierB",
        "Sources/CTierBBroker",
        "Sources/maccrab-tierb-sandbox-host",
        "Sources/maccrab-tierb-corpus-probe",
        "Sources/maccrab-tierb-corpus-probe-swift",
        "Sources/maccrab-tierb-example",
    ]
    files: List[pathlib.Path] = []
    for base in bases:
        directory = root / base
        if directory.is_dir():
            files.extend(path for path in directory.rglob("*") if path.is_file() and not path.is_symlink())
    return sorted(files, key=lambda item: item.relative_to(root).as_posix())


def containment_digest(root: pathlib.Path) -> str:
    records = []
    for path in containment_sources(root):
        records.append({"path": path.relative_to(root).as_posix(), "sha256": sha256_file(path)})
    if not records:
        fail("no Tier-B containment sources were found")
    return sha256_bytes(canonical_json_bytes(records))


def host_record() -> Dict[str, Any]:
    def output(command: Sequence[str], fallback: str) -> str:
        try:
            return subprocess.run(command, check=True, capture_output=True, text=True).stdout.strip() or fallback
        except (OSError, subprocess.CalledProcessError):
            return fallback

    return {
        "hardware_model": output(["/usr/sbin/sysctl", "-n", "hw.model"], platform.machine()),
        "architecture": platform.machine(),
        "macos_version": output(["/usr/bin/sw_vers", "-productVersion"], platform.release()),
        "macos_build": output(["/usr/bin/sw_vers", "-buildVersion"], platform.version()),
    }


def validate_probe_transcript(
    raw: Any, *, label: str, expected_command: Sequence[str],
    expected_stdin: str | None = None,
) -> Dict[str, Any]:
    evidence = object_value(raw, label)
    required = {
        "command", "exit_code", "output_sha256", "output_tail",
        "output_line_count", "output",
    }
    allowed = required | {
        "environment", "observed_test_count", "stdin", "stdin_sha256",
    }
    if not required.issubset(evidence) or not set(evidence).issubset(allowed):
        fail(f"{label} transcript inventory is incomplete or unknown")
    if list_value(evidence.get("command"), f"{label}.command", nonempty=True) \
            != list(expected_command):
        fail(f"{label} command is not the fixed recorder invocation")
    if int_value(evidence.get("exit_code"), f"{label}.exit_code") != 0:
        fail(f"{label} did not pass")
    output = string_value(evidence.get("output"), f"{label}.output", nonempty=False)
    if require_sha(evidence.get("output_sha256"), f"{label}.output_sha256") \
            != sha256_bytes(output.encode("utf-8")):
        fail(f"{label} output hash does not bind its transcript")
    if int_value(evidence.get("output_line_count"), f"{label}.output_line_count") \
            != len(output.splitlines()):
        fail(f"{label} output line count does not match its transcript")
    if string_value(
        evidence.get("output_tail"), f"{label}.output_tail", nonempty=False
    ) != output[-4096:]:
        fail(f"{label} output tail does not match its transcript")
    if expected_stdin is None:
        if "stdin" in evidence or "stdin_sha256" in evidence:
            fail(f"{label} unexpectedly supplied stdin")
    else:
        if "stdin" not in evidence or "stdin_sha256" not in evidence:
            fail(f"{label} stdin evidence is incomplete")
        stdin = string_value(
            evidence.get("stdin"), f"{label}.stdin", nonempty=False
        )
        if stdin != expected_stdin:
            fail(f"{label} stdin is not the fixed recorder input")
        if require_sha(evidence.get("stdin_sha256"), f"{label}.stdin_sha256") \
                != sha256_bytes(stdin.encode("utf-8")):
            fail(f"{label} stdin hash does not bind its transcript")
    return evidence


def bin_directory_from_probe(raw: Mapping[str, Any], label: str) -> str:
    output = string_value(raw.get("output"), f"{label}.output", nonempty=False)
    candidates = [line.strip() for line in output.splitlines() if line.strip().startswith("/")]
    if not candidates:
        fail(f"{label} did not return an absolute Swift binary directory")
    return candidates[-1]


def require_private_containment_workspace(
    workspace: Any, build_scratch: Any, *, capture_mode: str,
    allow_test_fixture: bool,
) -> Tuple[str, str]:
    workspace_text = string_value(workspace, "containment workspace")
    scratch_text = string_value(build_scratch, "containment build scratch path")
    workspace_path = pathlib.PurePosixPath(workspace_text)
    scratch_path = pathlib.PurePosixPath(scratch_text)
    if not workspace_path.is_absolute() or str(workspace_path) != workspace_text:
        fail("containment workspace must be a canonical absolute path")
    if scratch_path != workspace_path / CONTAINMENT_BUILD_SCRATCH_NAME:
        fail("containment build scratch path is not private to the run workspace")
    if capture_mode == "live-exact-candidate":
        if workspace_path.parent != pathlib.PurePosixPath("/private/tmp") \
                or not workspace_path.name.startswith("maccrab-exact-containment."):
            fail("live containment workspace is not a fresh private recorder path")
    elif not (
        allow_test_fixture
        and capture_mode == "deterministic-fixture"
        and workspace_path == pathlib.PurePosixPath(
            "/fixture/private/tmp/exact-containment"
        )
    ):
        fail("containment fixture workspace is not the fixed test-only path")
    return workspace_text, scratch_text


def require_path_within(child: str, parent: str, label: str) -> None:
    child_path = pathlib.PurePosixPath(child)
    parent_path = pathlib.PurePosixPath(parent)
    if not child_path.is_absolute() or str(child_path) != child:
        fail(f"{label} must be a canonical absolute path")
    try:
        relative = child_path.relative_to(parent_path)
    except ValueError:
        fail(f"{label} is outside its private containment workspace")
    if not relative.parts:
        fail(f"{label} must be below its private containment workspace")


def validate_loopback_reachability(
    raw: Any, *, label: str, environment: Mapping[str, str],
) -> None:
    row = object_value(raw, label)
    if set(row) != {"probe", "accepted_peer_host", "accepted_peer_port"}:
        fail(f"{label} evidence is incomplete or unknown")
    command = [
        fixed_tool("/usr/bin/nc"), "-G", "3", "-z",
        CONTAINMENT_LOOPBACK_HOST, str(CONTAINMENT_LOOPBACK_PORT),
    ]
    probe = validate_probe_transcript(
        row.get("probe"), label=f"{label}.probe", expected_command=command
    )
    if object_value(probe.get("environment"), f"{label}.probe.environment") \
            != environment:
        fail(f"{label} used an unexpected environment")
    if row.get("accepted_peer_host") != CONTAINMENT_LOOPBACK_HOST:
        fail(f"{label} did not reach the fixed loopback listener")
    int_value(row.get("accepted_peer_port"), f"{label}.accepted_peer_port", minimum=1)


def containment_plugin_manifest(plugin_id: str) -> Dict[str, Any]:
    return {
        "id": plugin_id,
        "displayName": "MacCrab qualification fixture",
        "version": "1.0.0",
        "schemaVersion": 1,
        "description": "Exact-candidate containment qualification input",
        "kind": "collector",
        "fileReadSubpaths": [],
        "fileWriteSubpaths": [],
        "networkConnectAllowlist": [],
        "machServiceConnects": [],
        "processExecPaths": [],
        "allowProcessFork": False,
        "privacyClass": "metadata",
        "dataSources": [],
        "tccRequirements": [],
    }


def validate_candidate_containment_output(
    output: str, *, run_name: str, expected_artifact: str
) -> None:
    required_patterns = (
        r"(?m)^Ran under the sandboxed third-party lane:\s*$",
        r"(?m)^\s*Exit code:\s+0\s*$",
        r"(?m)^\s*Result:\s+ok\s*$",
        r"(?m)^\s*✓ ran CONTAINED \(deny-default sandbox; file reads brokered over fd 3\)\.\s*$",
        rf"(?m)^\s*-\s+{re.escape(expected_artifact)}:\s+.*$",
    )
    if any(re.search(pattern, output) is None for pattern in required_patterns):
        fail(f"exact-candidate containment run {run_name} lacks required proof")
    if "leak." in output:
        fail(f"exact-candidate containment run {run_name} exposed a denied surface")
    match = re.search(r"(?m)^\s*Artifacts:\s+([0-9]+)\s*$", output)
    if not match or int(match.group(1)) != 1:
        fail(
            f"exact-candidate containment run {run_name} must emit exactly "
            "one expected artifact and no leak artifacts"
        )


def validate_unsandboxed_containment_output(
    output: str, *, role: str,
) -> None:
    expected = CONTAINMENT_UNSANDBOXED_LEAKS.get(role)
    if expected is None:
        fail(f"unknown unsandboxed containment-control role: {role}")
    observed = tuple(
        re.findall(
            r'(?m)^\{"kind":"artifact","artifact":\{"contentType":"([^"]+)"',
            output,
        )
    )
    if observed != expected:
        fail(
            f"unsandboxed {role} control did not exercise the complete deny "
            f"battery (expected {list(expected)}, observed {list(observed)})"
        )
    if re.search(
        r'(?m)^\{"kind":"result","result":\{"status":"ok"', output
    ) is None:
        fail(f"unsandboxed {role} control did not reach its terminal result")


def loopback_control_probe(
    listener: socket.socket, *, label: str, environment: Mapping[str, str],
) -> Dict[str, Any]:
    probe = subprocess_probe(
        [
            fixed_tool("/usr/bin/nc"), "-G", "3", "-z",
            CONTAINMENT_LOOPBACK_HOST, str(CONTAINMENT_LOOPBACK_PORT),
        ],
        label=label, environment=environment, include_output=True,
    )
    probe["environment"] = dict(environment)
    listener.settimeout(3.0)
    try:
        connection, peer = listener.accept()
    except OSError as exc:
        fail(f"{label} did not reach the recorder's loopback listener: {exc}")
    try:
        peer_host, peer_port = peer[:2]
    finally:
        connection.close()
    if peer_host != CONTAINMENT_LOOPBACK_HOST:
        fail(f"{label} reached the listener from an unexpected address")
    return {
        "probe": probe,
        "accepted_peer_host": peer_host,
        "accepted_peer_port": peer_port,
    }


def record_unsandboxed_containment_controls(
    listener: socket.socket, *, workspace: pathlib.Path,
    fixture_paths: Mapping[str, pathlib.Path], environment: Mapping[str, str],
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    pre_run = loopback_control_probe(
        listener, label="containment pre-run loopback control",
        environment=environment,
    )
    controls: List[Dict[str, Any]] = []
    for role in CONTAINMENT_UNSANDBOXED_LEAKS:
        scratch = workspace / f"unsandboxed-{role}"
        scratch.mkdir(mode=0o700)
        request = canonical_json_bytes(
            {"scratchDir": str(scratch)}
        ).decode("utf-8")
        evidence = subprocess_probe(
            [str(fixture_paths[role])],
            label=f"unsandboxed containment control {role}",
            cwd=workspace, environment=environment,
            include_output=True, stdin_text=request,
        )
        evidence["environment"] = dict(environment)
        validate_unsandboxed_containment_output(
            string_value(
                evidence.get("output"),
                f"unsandboxed containment control {role}.output",
                nonempty=False,
            ),
            role=role,
        )
        listener.settimeout(3.0)
        try:
            connection, peer = listener.accept()
        except OSError as exc:
            fail(
                f"unsandboxed containment control {role} did not reach "
                f"the loopback listener: {exc}"
            )
        try:
            peer_host, peer_port = peer[:2]
        finally:
            connection.close()
        if peer_host != CONTAINMENT_LOOPBACK_HOST:
            fail(
                f"unsandboxed containment control {role} used an "
                "unexpected network source"
            )
        controls.append({
            "role": role,
            "binary_sha256": sha256_file(fixture_paths[role]),
            "scratch_path": str(scratch),
            "expected_leaks": list(CONTAINMENT_UNSANDBOXED_LEAKS[role]),
            "accepted_peer_host": peer_host,
            "accepted_peer_port": peer_port,
            "probe": evidence,
        })
    return pre_run, controls


def containment_document(
    *,
    version: str,
    source_commit: str,
    source_tree: str,
    candidate_manifest_sha256: str,
    candidate: Mapping[str, Any],
    root: pathlib.Path,
    started_at: str,
    ended_at: str,
    capture_mode: str,
    workspace: str,
    build_scratch_path: str,
    candidate_execution: Mapping[str, Any],
    build_evidence: Sequence[Mapping[str, Any]],
    bin_path_evidence: Mapping[str, Any],
    network_control: Mapping[str, Any],
    unsandboxed_controls: Sequence[Mapping[str, Any]],
    keygen_evidence: Mapping[str, Any],
    fixture_inputs: Sequence[Mapping[str, Any]],
    bundle_runs: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    if capture_mode not in ("live-exact-candidate", "deterministic-fixture"):
        fail("containment capture mode is unknown")
    started = parse_time(started_at, "containment.started_at")
    ended = parse_time(ended_at, "containment.ended_at")
    if ended <= started:
        fail("containment end timestamp must follow its start")
    run_names: List[str] = []
    transcript_hashes: List[str] = []
    for index, raw in enumerate(bundle_runs):
        row = object_value(raw, f"containment bundle run {index}")
        name = string_value(row.get("name"), f"containment bundle run {index}.name")
        expected_artifact = string_value(
            row.get("expected_artifact"),
            f"containment bundle run {index}.expected_artifact",
        )
        run = object_value(row.get("run"), f"containment bundle run {index}.run")
        output = string_value(
            run.get("output"), f"containment bundle run {index}.run.output",
            nonempty=False,
        )
        validate_candidate_containment_output(
            output, run_name=name, expected_artifact=expected_artifact
        )
        run_names.append(name)
        transcript_hashes.append(
            require_sha(
                run.get("output_sha256"),
                f"containment bundle run {index}.run.output_sha256",
            )
        )
    return {
        "schema": CONTAINMENT_SCHEMA,
        "result": "pass",
        "version": version,
        "source_commit": source_commit,
        "source_tree": source_tree,
        "candidate_manifest_sha256": candidate_manifest_sha256,
        "candidate": copy.deepcopy(candidate),
        "containment_sources_sha256": containment_digest(root),
        "started_at": started_at,
        "ended_at": ended_at,
        "host": host_record(),
        "corpus": {
            "execution_path": "mounted-candidate-maccrabctl-plugin-test-v1",
            "required_runs": [row[0] for row in CONTAINMENT_RUNS],
            "passed_runs": run_names,
            "zero_leak_artifacts": True,
            "run_transcripts_sha256": sha256_bytes(
                canonical_json_bytes(transcript_hashes)
            ),
        },
        "recorder_evidence": {
            "capture_mode": capture_mode,
            "workspace": workspace,
            "build_scratch_path": build_scratch_path,
            "candidate_execution": copy.deepcopy(candidate_execution),
            "source_builds": copy.deepcopy(list(build_evidence)),
            "bin_path": copy.deepcopy(bin_path_evidence),
            "network_control": copy.deepcopy(network_control),
            "unsandboxed_controls": copy.deepcopy(list(unsandboxed_controls)),
            "keygen": copy.deepcopy(keygen_evidence),
            "fixture_inputs": copy.deepcopy(list(fixture_inputs)),
            "bundle_runs": copy.deepcopy(list(bundle_runs)),
        },
    }


def validate_candidate_execution(
    raw: Any, *, candidate: Mapping[str, Any],
    candidate_verification: Mapping[str, Any], allow_test_fixture: bool,
) -> Tuple[str, Dict[str, Dict[str, Any]]]:
    execution = object_value(raw, "containment candidate execution")
    if set(execution) != {"dmg_sha256", "mountpoint", "mount", "binaries"}:
        fail("containment candidate-execution inventory is incomplete or unknown")
    expected_dmg = object_value(candidate.get("dmg"), "candidate.dmg")
    if require_sha(execution.get("dmg_sha256"), "containment candidate DMG") \
            != expected_dmg.get("sha256"):
        fail("containment execution does not bind the exact candidate DMG")
    mountpoint = string_value(
        execution.get("mountpoint"), "containment candidate mountpoint"
    )
    if not mountpoint.startswith("/Volumes/") \
            and not (allow_test_fixture and mountpoint.startswith("/fixture/Volumes/")):
        fail("containment candidate did not execute from a read-only mounted-DMG path")
    mount = object_value(execution.get("mount"), "containment candidate mount")
    mount_command = list_value(
        mount.get("command"), "containment candidate mount.command", nonempty=True
    )
    if len(mount_command) != 6 or mount_command[:5] != [
        fixed_tool("/usr/bin/hdiutil"), "attach", "-readonly", "-nobrowse", "-plist"
    ] or pathlib.Path(string_value(
        mount_command[5], "containment candidate mount DMG"
    )).name != expected_dmg.get("filename"):
        fail("containment candidate mount was not the fixed read-only DMG invocation")
    mount = validate_probe_transcript(
        mount, label="containment candidate mount", expected_command=mount_command
    )
    if object_value(
        mount.get("environment"), "containment candidate mount.environment"
    ) != containment_process_environment():
        fail("containment candidate mount used an unexpected environment")
    if mountpoint not in string_value(
        mount.get("output"), "containment candidate mount.output"
    ):
        fail("containment candidate mount transcript omits the executed mountpoint")
    inventory = object_value(
        candidate_verification.get("payload_inventory"),
        "artifact_verification.payload_inventory",
    )
    entries = {
        object_value(item, "candidate payload entry").get("path"): object_value(
            item, "candidate payload entry"
        )
        for item in list_value(
            inventory.get("entries"), "artifact_verification.payload_inventory.entries"
        )
    }
    rows = list_value(execution.get("binaries"), "containment candidate binaries")
    if [object_value(row, "candidate binary").get("role") for row in rows] \
            != list(CONTAINMENT_CANDIDATE_BINARIES):
        fail("containment candidate binary inventory is incomplete or reordered")
    by_role: Dict[str, Dict[str, Any]] = {}
    for index, raw_row in enumerate(rows):
        row = object_value(raw_row, f"containment candidate binary {index}")
        if set(row) != {
            "role", "relative_path", "sha256", "size_bytes", "developer_id",
            "team_id", "signing_identifier", "cdhash",
        }:
            fail("containment candidate binary identity is incomplete or unknown")
        role = string_value(row.get("role"), f"containment candidate binary {index}.role")
        relative, expected_identifier = CONTAINMENT_CANDIDATE_BINARIES[role]
        if row.get("relative_path") != relative:
            fail(f"containment candidate {role} path is not the shipped payload path")
        payload = object_value(entries.get(relative), f"candidate payload {relative}")
        if payload.get("kind") != "file" \
                or require_sha(row.get("sha256"), f"containment candidate {role} sha256") \
                != payload.get("sha256") \
                or int_value(row.get("size_bytes"), f"containment candidate {role} size", minimum=1) \
                != payload.get("size_bytes"):
            fail(f"containment candidate {role} bytes do not match the mounted payload inventory")
        require_maccrab_signing_identity(
            row, expected_identifier=expected_identifier,
            path=f"containment candidate {role}",
        )
        cdhash = string_value(row.get("cdhash"), f"containment candidate {role}.cdhash")
        if not re.fullmatch(r"[0-9a-f]{40,64}", cdhash):
            fail(f"containment candidate {role} has an invalid CDHash")
        by_role[role] = row
    return mountpoint, by_role


def validate_containment_report(
    report: Mapping[str, Any],
    *,
    version: str,
    source_commit: str,
    source_tree: str,
    candidate_manifest_sha256: str,
    candidate: Mapping[str, Any],
    candidate_verification: Mapping[str, Any],
    root: pathlib.Path,
    allow_test_fixture: bool = False,
) -> None:
    if report.get("schema") != CONTAINMENT_SCHEMA or report.get("result") != "pass":
        fail("containment report schema/result is not a passing v2 attestation")
    recorder = object_value(
        report.get("recorder_evidence"), "containment.recorder_evidence"
    )
    if set(recorder) != {
        "capture_mode", "workspace", "build_scratch_path",
        "candidate_execution", "source_builds", "bin_path", "network_control",
        "unsandboxed_controls", "keygen", "fixture_inputs", "bundle_runs",
    }:
        fail("containment recorder evidence inventory is incomplete or unknown")
    capture_mode = string_value(
        recorder.get("capture_mode"), "containment.recorder_evidence.capture_mode"
    )
    if capture_mode != "live-exact-candidate" \
            and not (allow_test_fixture and capture_mode == "deterministic-fixture"):
        fail("release verification requires live exact-candidate containment execution")
    workspace, build_scratch = require_private_containment_workspace(
        recorder.get("workspace"), recorder.get("build_scratch_path"),
        capture_mode=capture_mode, allow_test_fixture=allow_test_fixture,
    )
    for key, expected in (("version", version), ("source_commit", source_commit), ("source_tree", source_tree)):
        if report.get(key) != expected:
            fail(f"containment.{key} does not match the exact release source")
    if require_sha(
        report.get("candidate_manifest_sha256"), "containment.candidate_manifest_sha256"
    ) != candidate_manifest_sha256:
        fail("containment report does not bind the exact candidate manifest")
    if object_value(report.get("candidate"), "containment.candidate") != candidate:
        fail("containment report does not bind the exact candidate and DMG")
    if require_sha(report.get("containment_sources_sha256"), "containment.containment_sources_sha256") != containment_digest(root):
        fail("containment source bytes changed after the on-device corpus run")
    started = parse_time(report.get("started_at"), "containment.started_at")
    ended = parse_time(report.get("ended_at"), "containment.ended_at")
    if ended <= started:
        fail("containment time interval is invalid")
    host = object_value(report.get("host"), "containment.host")
    for key in ("hardware_model", "architecture", "macos_version", "macos_build"):
        string_value(host.get(key), f"containment.host.{key}")
    mountpoint, candidate_binaries = validate_candidate_execution(
        recorder.get("candidate_execution"), candidate=candidate,
        candidate_verification=candidate_verification,
        allow_test_fixture=allow_test_fixture,
    )
    xcrun = fixed_tool("/usr/bin/xcrun")
    root_text = str(root)
    source_builds = list_value(
        recorder.get("source_builds"), "containment source builds"
    )
    if len(source_builds) != len(CONTAINMENT_FIXTURE_PRODUCTS):
        fail("containment source-build inventory is incomplete")
    expected_build_environment = containment_process_environment()
    for index, product in enumerate(CONTAINMENT_FIXTURE_PRODUCTS):
        build = validate_probe_transcript(
            source_builds[index], label=f"containment build {product}",
            expected_command=[
                xcrun, "swift", "build", "-c", "release",
                "--package-path", root_text,
                "--scratch-path", build_scratch,
                "--product", product,
            ],
        )
        if object_value(
            build.get("environment"), f"containment build {product}.environment"
        ) != expected_build_environment:
            fail("containment source build did not use the fixed sanitized environment")
    bin_path_command = [
        xcrun, "swift", "build", "-c", "release", "--package-path", root_text,
        "--scratch-path", build_scratch,
        "--show-bin-path",
    ]
    bin_path = validate_probe_transcript(
        recorder.get("bin_path"),
        label="containment bin path",
        expected_command=bin_path_command,
    )
    if object_value(
        bin_path.get("environment"), "containment bin path.environment"
    ) != expected_build_environment:
        fail("containment binary-path probe did not use the fixed sanitized environment")
    bin_dir = bin_directory_from_probe(bin_path, "containment bin path")
    require_path_within(
        bin_dir, build_scratch, "containment Swift binary directory"
    )
    fixture_rows = list_value(
        recorder.get("fixture_inputs"), "containment fixture inputs"
    )
    expected_fixture_roles = ("c-probe", "swift-probe")
    if [object_value(row, "containment fixture input").get("role") for row in fixture_rows] \
            != list(expected_fixture_roles):
        fail("containment source-built fixture inventory is incomplete or reordered")
    fixture_by_role: Dict[str, Dict[str, Any]] = {}
    for index, role in enumerate(expected_fixture_roles):
        row = object_value(fixture_rows[index], f"containment fixture input {index}")
        if set(row) != {"role", "product", "path", "sha256", "size_bytes"}:
            fail("containment source-built fixture identity is incomplete or unknown")
        product = CONTAINMENT_FIXTURE_PRODUCTS[index]
        if row.get("product") != product \
                or row.get("path") != f"{bin_dir}/{product}":
            fail("containment fixture role/product binding is incorrect")
        require_sha(row.get("sha256"), f"containment fixture {role}.sha256")
        int_value(row.get("size_bytes"), f"containment fixture {role}.size", minimum=1)
        fixture_by_role[role] = row

    network_control = object_value(
        recorder.get("network_control"), "containment network control"
    )
    if set(network_control) != {
        "host", "port", "unsandboxed_reachable", "pre_run", "post_run",
    }:
        fail("containment network-control evidence is incomplete or unknown")
    if network_control.get("host") != CONTAINMENT_LOOPBACK_HOST \
            or int_value(
                network_control.get("port"), "containment network control.port"
            ) != CONTAINMENT_LOOPBACK_PORT \
            or network_control.get("unsandboxed_reachable") is not True:
        fail("containment loopback control was not proven reachable")
    validate_loopback_reachability(
        network_control.get("pre_run"), label="containment pre-run loopback control",
        environment=expected_build_environment,
    )
    validate_loopback_reachability(
        network_control.get("post_run"), label="containment post-run loopback control",
        environment=expected_build_environment,
    )

    unsandboxed_controls = list_value(
        recorder.get("unsandboxed_controls"),
        "containment unsandboxed controls",
    )
    expected_control_roles = tuple(CONTAINMENT_UNSANDBOXED_LEAKS)
    if len(unsandboxed_controls) != len(expected_control_roles):
        fail("containment unsandboxed deny-control inventory is incomplete")
    for index, role in enumerate(expected_control_roles):
        row = object_value(
            unsandboxed_controls[index],
            f"containment unsandboxed control {index}",
        )
        if set(row) != {
            "role", "binary_sha256", "scratch_path", "expected_leaks",
            "accepted_peer_host", "accepted_peer_port", "probe",
        }:
            fail("containment unsandboxed control is incomplete or unknown")
        fixture = fixture_by_role[role]
        scratch_path = f"{workspace}/unsandboxed-{role}"
        if row.get("role") != role \
                or require_sha(
                    row.get("binary_sha256"),
                    f"containment unsandboxed {role}.binary_sha256",
                ) != fixture.get("sha256") \
                or row.get("scratch_path") != scratch_path \
                or row.get("expected_leaks") != list(
                    CONTAINMENT_UNSANDBOXED_LEAKS[role]
                ):
            fail("containment unsandboxed deny-control binding is incorrect")
        if row.get("accepted_peer_host") != CONTAINMENT_LOOPBACK_HOST:
            fail("containment unsandboxed network control did not reach loopback")
        int_value(
            row.get("accepted_peer_port"),
            f"containment unsandboxed {role}.accepted_peer_port", minimum=1,
        )
        expected_stdin = canonical_json_bytes(
            {"scratchDir": scratch_path}
        ).decode("utf-8")
        probe = validate_probe_transcript(
            row.get("probe"), label=f"containment unsandboxed {role}.probe",
            expected_command=[string_value(
                fixture.get("path"), f"containment fixture {role}.path"
            )], expected_stdin=expected_stdin,
        )
        if object_value(
            probe.get("environment"),
            f"containment unsandboxed {role}.probe.environment",
        ) != expected_build_environment:
            fail("containment unsandboxed control used an unexpected environment")
        validate_unsandboxed_containment_output(
            string_value(
                probe.get("output"),
                f"containment unsandboxed {role}.probe.output",
                nonempty=False,
            ),
            role=role,
        )

    candidate_cli = f"{mountpoint}/{CONTAINMENT_CANDIDATE_BINARIES['maccrabctl'][0]}"
    keygen = object_value(recorder.get("keygen"), "containment keygen")
    keygen_command = list_value(
        keygen.get("command"), "containment keygen.command", nonempty=True
    )
    if len(keygen_command) != 5 or keygen_command[:4] != [
        candidate_cli, "plugin", "keygen", "--out"
    ]:
        fail("containment key generation did not use the exact candidate CLI")
    keygen = validate_probe_transcript(
        keygen, label="containment keygen", expected_command=keygen_command
    )
    if object_value(keygen.get("environment"), "containment keygen.environment") \
            != expected_build_environment:
        fail("containment key generation did not use the fixed sanitized environment")
    key_dir = string_value(keygen_command[4], "containment key directory")
    if key_dir != f"{workspace}/keys":
        fail("containment signing key is outside the private run workspace")

    bundle_runs = list_value(
        recorder.get("bundle_runs"), "containment bundle runs"
    )
    if len(bundle_runs) != len(CONTAINMENT_RUNS):
        fail("containment exact-candidate run inventory is incomplete")
    run_names: List[str] = []
    transcript_hashes: List[str] = []
    for index, (name, plugin_id, expected_artifact) in enumerate(CONTAINMENT_RUNS):
        row = object_value(bundle_runs[index], f"containment bundle run {index}")
        if set(row) != {
            "name", "plugin_id", "expected_artifact", "source_role",
            "source_sha256", "manifest", "manifest_sha256", "binary_sha256",
            "signature_sha256", "publisher_key_sha256", "sign", "run",
        }:
            fail("containment bundle-run evidence is incomplete or unknown")
        if row.get("name") != name or row.get("plugin_id") != plugin_id \
                or row.get("expected_artifact") != expected_artifact:
            fail("containment bundle-run identity is incorrect")
        source_role = string_value(
            row.get("source_role"), f"containment bundle run {name}.source_role"
        )
        expected_source = candidate_binaries.get("example") \
            if name == "example" else fixture_by_role.get(name)
        if source_role != ("candidate-example" if name == "example" else name) \
                or expected_source is None:
            fail("containment bundle source role is incorrect")
        source_sha = require_sha(
            row.get("source_sha256"), f"containment bundle run {name}.source_sha256"
        )
        if source_sha != expected_source.get("sha256") \
                or require_sha(
                    row.get("binary_sha256"),
                    f"containment bundle run {name}.binary_sha256",
                ) != source_sha:
            fail("containment executed bundle bytes do not match their bound source")
        manifest = object_value(
            row.get("manifest"), f"containment bundle run {name}.manifest"
        )
        if manifest != containment_plugin_manifest(plugin_id) \
                or require_sha(
                    row.get("manifest_sha256"),
                    f"containment bundle run {name}.manifest_sha256",
                ) != sha256_bytes(canonical_json_bytes(manifest)):
            fail("containment bundle manifest is not the fixed deny-default manifest")
        require_sha(
            row.get("signature_sha256"),
            f"containment bundle run {name}.signature_sha256",
        )
        require_sha(
            row.get("publisher_key_sha256"),
            f"containment bundle run {name}.publisher_key_sha256",
        )
        sign = object_value(row.get("sign"), f"containment bundle run {name}.sign")
        sign_command = list_value(
            sign.get("command"), f"containment bundle run {name}.sign.command",
            nonempty=True,
        )
        if len(sign_command) != 6 or sign_command[:3] != [
            candidate_cli, "plugin", "sign"
        ] or sign_command[3] != f"{workspace}/bundle-{name}" \
                or sign_command[4:] != ["--key", f"{key_dir}/signing.key"]:
            fail("containment bundle signing did not use the exact candidate CLI/key")
        sign = validate_probe_transcript(
            sign, label=f"containment bundle run {name}.sign",
            expected_command=sign_command,
        )
        if object_value(
            sign.get("environment"), f"containment bundle run {name}.sign.environment"
        ) != expected_build_environment:
            fail("containment bundle signing used an unexpected environment")
        run = object_value(row.get("run"), f"containment bundle run {name}.run")
        run_command = list_value(
            run.get("command"), f"containment bundle run {name}.run.command",
            nonempty=True,
        )
        if len(run_command) != 4 or run_command[:3] != [
            candidate_cli, "plugin", "test"
        ] or run_command[3] != sign_command[3]:
            fail("containment corpus did not execute through the exact candidate CLI")
        run = validate_probe_transcript(
            run, label=f"containment bundle run {name}.run",
            expected_command=run_command,
        )
        if object_value(
            run.get("environment"), f"containment bundle run {name}.run.environment"
        ) != expected_build_environment:
            fail("containment candidate execution used an unexpected environment")
        output = string_value(
            run.get("output"), f"containment bundle run {name}.run.output",
            nonempty=False,
        )
        validate_candidate_containment_output(
            output, run_name=name, expected_artifact=expected_artifact
        )
        run_names.append(name)
        transcript_hashes.append(run["output_sha256"])

    corpus = object_value(report.get("corpus"), "containment.corpus")
    expected_corpus = {
        "execution_path": "mounted-candidate-maccrabctl-plugin-test-v1",
        "required_runs": [row[0] for row in CONTAINMENT_RUNS],
        "passed_runs": run_names,
        "zero_leak_artifacts": True,
        "run_transcripts_sha256": sha256_bytes(
            canonical_json_bytes(transcript_hashes)
        ),
    }
    if corpus != expected_corpus:
        fail("containment aggregate does not reconcile with exact-candidate runs")


def make_runtime_template(candidate_manifest: Mapping[str, Any], manifest_sha: str) -> Dict[str, Any]:
    candidate = object_value(candidate_manifest.get("candidate"), "candidate")
    verification = object_value(candidate_manifest.get("artifact_verification"), "artifact_verification")
    inventory = object_value(verification.get("payload_inventory"), "artifact_verification.payload_inventory")
    return {
        "schema": RUNTIME_SCHEMA,
        "result": "INCOMPLETE",
        "candidate_manifest_sha256": manifest_sha,
        "candidate": candidate,
        "host": {
            "machine_id_sha256": "REPLACE",
            "hardware_model": "REPLACE",
            "architecture": "arm64",
            "logical_cpu_count": 0,
            "memory_bytes": 0,
            "macos_version": "REPLACE",
            "macos_build": "REPLACE",
            "sip_enabled": False,
            "amfi_enforced": False,
            "power_source": "REPLACE",
        },
        "workload": {
            "id": "normal-plus-burst",
            "version": "REPLACE",
            "sha256": "REPLACE",
            "description": "REPLACE",
            "normal_operations": [],
            "burst_operations": [],
            "executors": [],
        },
        "installed_engine": {"start": {}, "end": {}},
        "epoch": {
            "started_at": "REPLACE",
            "ended_at": "REPLACE",
            "duration_seconds": 900,
            "uninterrupted": False,
            "sample_interval_seconds": 30,
            "max_sample_gap_seconds": 0,
            "sample_count": 0,
            "samples_sha256": "REPLACE",
        },
        "samples": [],
        "recorder_observations": [],
        "recorder_probe_evidence": {},
        "measurements": {
            "process": {"engine_pids": [], "crash_count": 0, "watchdog_exit_count": 0, "relaunch_count": 0},
            "conservation": {"all_samples_reconciled": False, "boundaries": []},
            "priority_fidelity": {"priority_lane_loss": 0, "kernel_loss": 0, "callback_copy_loss": 0, "upstream_collector_loss": 0},
            "file_fidelity": {"unclassified_queue_loss": 0, "complete_rule_corpus_evaluated": False, "rule_corpus_sha256": "REPLACE", "semantic_reasons": []},
            "correlation_continuity": {
                "recovery_coverage_seconds": 0,
                "checkpoint_shed": 0,
                "journal_shed": 0,
                "pending_later_step_evictions_epoch_delta": 0,
                "sequence_state_continuity_maintained_all_samples": False,
                "source_bound_continuity_tests_sha256": "REPLACE",
                "live_rule_reload_signal": {},
            },
            "event_storage": {"unreachable_budget_fault_count": 0, "prune_vacuum_refill_loop_count": 0, "search_tier_gaps_reconcile_exactly": False, "search_tier_gaps_visible": False},
            "trace_graph": {
                "writable_duty_fraction": 0,
                "mutation_shed": 0,
                "recovery_oscillation_count": 0,
                "write_accounting_reconciled_all_samples": False,
                "coalesced_noop_rows_epoch_delta": 0,
                "failed_batches_epoch_delta": 0,
                "failed_rows_epoch_delta": 0,
            },
            "trace_store": {
                "full_writer_duty_fraction": 0,
                "max_footprint_bytes": 0,
                "minimum_free_space_bytes": 0,
            },
            "workload_ingress": {
                "start_offset_seconds": BURST_START_OFFSET_SECONDS,
                "end_offset_seconds": BURST_END_OFFSET_SECONDS,
            },
            "disk_writes": {"engine_bytes": 0, "average_bytes_per_second": 0, "windows": [], "macos_disk_writes_diagnostic_count": 0},
            "cpu": {"engine_cpu_seconds": 0, "engine_average_cores": 0, "gui_background_percent_samples": [], "gui_background_p95_percent": 0},
            "memory": {"engine_max_rss_bytes": 0, "engine_rss_minute_5_bytes": 0, "engine_rss_minute_15_bytes": 0},
            "disk_safety": {"inventory_complete": False, "sqlite_families": []},
            "ai_quality": {
                "configured": False,
                "feature_disabled_entire_epoch": True,
                "schema_2_and_accounting_conserved_all_samples": False,
                "unspecified_requests_epoch_delta": 0,
                "alert_investigations_started_epoch_delta": 0,
                "alert_investigations_accepted_epoch_delta": 0,
                "alert_investigations_final_rejected_epoch_delta": 0,
            },
            "rules": {"sealed_rules_synchronized_before_readers": False, "corpus_parity": False, "ordinary_launch_without_admin_prompt": False},
            "shipped_tools": {"maccrabctl": {}, "maccrab_mcp": {}},
        },
        "evidence": {
            "payload_inventory_sha256": inventory.get("sha256", "REPLACE"),
            "raw_samples_sha256": "REPLACE",
            "raw_samples_format": "embedded-json-v1",
            "recorded_at": "REPLACE",
            "recorder_schema": RUNTIME_RECORDER_SCHEMA,
            "capture_mode": "INCOMPLETE",
            "observations_sha256": "REPLACE",
        },
        "candidate_artifact_verification": {
            "payload_inventory_sha256": inventory.get("sha256", "REPLACE"),
        },
    }


def count_release_metadata(root: pathlib.Path) -> Dict[str, int]:
    single = len(list((root / "Rules").rglob("*.yml"))) - len(list((root / "Rules/sequences").rglob("*.yml")))
    sequence = len(list((root / "Rules/sequences").rglob("*.yml")))
    graph = len(list((root / "Rules/graph").glob("*.json")))
    tests = 0
    suites = 0
    for path in (root / "Tests").rglob("*.swift"):
        text = path.read_text(encoding="utf-8", errors="replace")
        tests += len(re.findall(r"(?m)^\s*@Test\b", text))
        suites += len(re.findall(r"(?m)^\s*@Suite\b", text))
    builtin_path = root / "Sources/MacCrabCore/Detection/BuiltinRuleCatalog.swift"
    builtins = builtin_path.read_text(encoding="utf-8", errors="replace").count('.init("maccrab.')
    return {"single": single, "sequence": sequence, "graph": graph, "rules": single + sequence + graph, "tests": tests, "suites": suites, "builtins": builtins}


def emit_release_json(
    *,
    output: pathlib.Path,
    root: pathlib.Path,
    candidate_manifest: Mapping[str, Any],
    version: str,
) -> None:
    candidate = object_value(candidate_manifest.get("candidate"), "candidate")
    verification = object_value(candidate_manifest.get("artifact_verification"), "artifact_verification")
    if candidate.get("version") != version:
        fail("candidate version does not match release.json version")
    counts = count_release_metadata(root)
    dmg = object_value(candidate.get("dmg"), "candidate.dmg")
    document = {
        "version": version,
        "release_date": utc_now(),
        "toolchain": string_value(verification.get("xcode_toolchain", "recorded in signed release-input attestation"), "artifact_verification.xcode_toolchain"),
        "source_commit": candidate.get("source_commit"),
        "source_tree": candidate.get("source_tree"),
        "release_input_attestation_sha256": verification.get("release_input_attestation_sha256"),
        "rules": counts["rules"],
        "rules_single": counts["single"],
        "rules_sequence": counts["sequence"],
        "rules_graph": counts["graph"],
        "builtins": counts["builtins"],
        "tests": counts["tests"],
        "test_suites": counts["suites"],
        "dmg": {
            "filename": dmg.get("filename"),
            "url": f"https://github.com/peterhanily/maccrab/releases/download/v{version}/MacCrab-v{version}.dmg",
            "sha256": dmg.get("sha256"),
            "size_bytes": dmg.get("size_bytes"),
        },
        "notes_url": f"https://github.com/peterhanily/maccrab/releases/tag/v{version}",
        "appcast_url": "https://maccrab.com/appcast.xml",
        "min_macos": "13.0",
    }
    write_json_exclusive(output, document)


def command_record_candidate(args: argparse.Namespace) -> None:
    document = candidate_document(
        version=args.version,
        build_number=args.build_number,
        source_commit=args.source_commit,
        source_tree=args.source_tree,
        dmg=absolute_path(args.dmg),
        inspection_level=args.artifact_checks,
        notarization_submission_id=args.notarization_submission_id,
    )
    write_json_exclusive(pathlib.Path(args.output), document)
    print(f"candidate manifest written: {args.output}")


def command_runtime_template(args: argparse.Namespace) -> None:
    path = pathlib.Path(args.candidate_manifest)
    document = read_json_file(path, "candidate manifest")
    template = make_runtime_template(document, sha256_file(path))
    write_json_exclusive(pathlib.Path(args.output), template)
    print(f"runtime qualification template written: {args.output}")


def command_record_runtime(args: argparse.Namespace) -> None:
    root = pathlib.Path(args.source_root).resolve()
    manifest_path = absolute_path(args.candidate_manifest)
    dmg = absolute_path(args.dmg)
    manifest = read_json_file(manifest_path, "candidate manifest")
    bound = object_value(manifest.get("candidate"), "candidate")
    version = string_value(bound.get("version"), "candidate.version")
    build_number = string_value(bound.get("build_number"), "candidate.build_number")
    source_commit = require_object_id(bound.get("source_commit"), "candidate.source_commit")
    source_tree = require_object_id(bound.get("source_tree"), "candidate.source_tree")
    candidate = validate_candidate_document(
        manifest,
        expected_version=version,
        expected_source_commit=source_commit,
        expected_source_tree=source_tree,
        expected_build_number=build_number,
        dmg=dmg,
        artifact_checks="full",
    )
    manifest_sha = sha256_file(manifest_path)
    output = absolute_path(args.output)
    if output.is_symlink():
        fail("runtime output path is redirected")
    if output.is_file():
        existing = read_json_file(output, "existing runtime output")
        if existing.get("result") == "pass":
            fail("refusing to overwrite an existing passing runtime report")

    assert_exact_clean_source(
        root,
        source_commit=source_commit,
        source_tree=source_tree,
        label="runtime recorder pre-capture",
    )
    heartbeat_path = absolute_path(args.heartbeat_path)
    data_dirs = [
        absolute_path(value)
        for value in (args.data_dir or [str(DEFAULT_DATA_DIR)])
    ]
    capture_path = absolute_path(
        args.capture_output or (str(output) + ".capture.json")
    )
    if capture_path.is_symlink():
        fail("runtime capture output path is redirected")
    observations, host, workload, probes = live_runtime_recording(
        root=root,
        candidate_manifest=manifest,
        candidate_manifest_sha256=manifest_sha,
        dmg=dmg,
        heartbeat_path=heartbeat_path,
        data_dirs=data_dirs,
        sqlite_overrides=parse_sqlite_cap_overrides(args.sqlite_cap),
        capture_path=capture_path,
    )
    assert_exact_clean_source(
        root,
        source_commit=source_commit,
        source_tree=source_tree,
        label="runtime recorder post-capture",
    )
    report = build_runtime_report_from_observations(
        candidate_manifest=manifest,
        candidate_manifest_sha256=manifest_sha,
        observations=observations,
        host=host,
        workload=workload,
        probes=probes,
        capture_mode="live-installed-root",
    )
    verification = object_value(
        manifest.get("artifact_verification"), "artifact_verification"
    )
    inventory = object_value(
        verification.get("payload_inventory"), "artifact_verification.payload_inventory"
    )
    validate_runtime_report(
        report,
        candidate_manifest_sha256=manifest_sha,
        candidate=candidate,
        candidate_verification=verification,
        payload_inventory_sha256=require_sha(
            inventory.get("sha256"), "artifact_verification.payload_inventory.sha256"
        ),
        source_root=root,
    )
    write_json_exclusive(output, report)
    print(f"PASS: installed-host runtime qualification written: {output}")


def command_record_containment(args: argparse.Namespace) -> None:
    if platform.system() != "Darwin" or os.geteuid() == 0:
        fail("record-containment must run as the desktop user on the reference Mac")
    root = pathlib.Path(args.source_root).resolve()
    candidate_path = absolute_path(args.candidate_manifest)
    candidate_document_value = read_json_file(candidate_path, "candidate manifest")
    candidate_record = object_value(candidate_document_value.get("candidate"), "candidate")
    version = string_value(candidate_record.get("version"), "candidate.version")
    if args.version != version:
        fail("requested containment version does not match the candidate manifest")
    source_commit = require_object_id(
        candidate_record.get("source_commit"), "candidate.source_commit"
    )
    source_tree = require_object_id(
        candidate_record.get("source_tree"), "candidate.source_tree"
    )
    candidate = validate_candidate_document(
        candidate_document_value,
        expected_version=version,
        expected_source_commit=source_commit,
        expected_source_tree=source_tree,
        expected_build_number=string_value(candidate_record.get("build_number"), "candidate.build_number"),
        dmg=absolute_path(args.dmg),
        artifact_checks="full",
    )
    output = absolute_path(args.output)
    if output.is_symlink():
        fail("containment output path is redirected")
    if output.is_file() and read_json_file(
        output, "existing containment output"
    ).get("result") == "pass":
        fail("refusing to overwrite an existing passing containment report")
    assert_exact_clean_source(
        root,
        source_commit=source_commit,
        source_tree=source_tree,
        label="containment recorder pre-test",
    )

    xcrun = fixed_tool("/usr/bin/xcrun")
    root_text = str(root)
    build_environment = containment_process_environment()
    started_at = utc_now()
    verification = object_value(
        candidate_document_value.get("artifact_verification"),
        "artifact_verification",
    )
    mountpoint: pathlib.Path | None = None
    secret_path = pathlib.Path("/tmp/maccrab-corpus-secret")
    secret_identity: Tuple[int, int] | None = None
    with tempfile.TemporaryDirectory(
        prefix="maccrab-exact-containment.", dir="/private/tmp"
    ) as workspace_text:
        workspace = pathlib.Path(workspace_text)
        build_scratch_path = workspace / CONTAINMENT_BUILD_SCRATCH_NAME
        if build_scratch_path.exists() or build_scratch_path.is_symlink():
            fail("fresh containment build scratch path already exists")
        build_base = [
            xcrun, "swift", "build", "-c", "release",
            "--package-path", root_text,
            "--scratch-path", str(build_scratch_path),
        ]
        build_evidence: List[Dict[str, Any]] = []
        for product in CONTAINMENT_FIXTURE_PRODUCTS:
            evidence = subprocess_probe(
                [*build_base, "--product", product],
                label=f"containment fixture build {product}", cwd=root,
                environment=build_environment, include_output=True,
            )
            evidence["environment"] = dict(build_environment)
            build_evidence.append(evidence)
        bin_path_command = [*build_base, "--show-bin-path"]
        bin_path_evidence = subprocess_probe(
            bin_path_command, label="containment binary-path probe", cwd=root,
            environment=build_environment, include_output=True,
        )
        bin_path_evidence["environment"] = dict(build_environment)
        bin_dir = bin_directory_from_probe(
            bin_path_evidence, "containment binary-path probe"
        )
        require_path_within(
            bin_dir, str(build_scratch_path),
            "containment Swift binary directory",
        )
        fixture_inputs: List[Dict[str, Any]] = []
        fixture_paths: Dict[str, pathlib.Path] = {}
        for role, product in zip(
            ("c-probe", "swift-probe"), CONTAINMENT_FIXTURE_PRODUCTS
        ):
            path = pathlib.Path(bin_dir) / product
            if path.is_symlink() or not path.is_file() or not os.access(path, os.X_OK):
                fail(f"containment source build did not produce executable {product}")
            fixture_paths[role] = path
            fixture_inputs.append({
                "role": role,
                "product": product,
                "path": str(path),
                "sha256": sha256_file(path),
                "size_bytes": path.stat().st_size,
            })

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                listener.bind((CONTAINMENT_LOOPBACK_HOST, CONTAINMENT_LOOPBACK_PORT))
                listener.listen(8)
            except OSError as exc:
                fail(f"cannot establish fixed containment loopback control: {exc}")
            if secret_path.exists() or secret_path.is_symlink():
                fail(
                    "containment sentinel already exists; refusing to overwrite "
                    f"operator data: {secret_path}"
                )
            secret_fd = os.open(
                str(secret_path),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                os.write(secret_fd, b"TOP-SECRET\n")
                secret_stat = os.fstat(secret_fd)
                secret_identity = (secret_stat.st_dev, secret_stat.st_ino)
            finally:
                os.close(secret_fd)
            try:
                pre_run_control, unsandboxed_controls = (
                    record_unsandboxed_containment_controls(
                        listener, workspace=workspace,
                        fixture_paths=fixture_paths,
                        environment=build_environment,
                    )
                )
                mountpoint, mount_evidence = attach_readonly_candidate(
                    absolute_path(args.dmg), "containment exact-candidate mount"
                )
                candidate_execution, candidate_paths = record_candidate_containment_execution(
                    mountpoint=mountpoint, candidate=candidate,
                    candidate_verification=verification,
                    mount_evidence=mount_evidence,
                )
                candidate_cli = candidate_paths["maccrabctl"]
                key_dir = workspace / "keys"
                key_dir.mkdir(mode=0o700)
                keygen_command = [
                    str(candidate_cli), "plugin", "keygen", "--out", str(key_dir)
                ]
                keygen_evidence = subprocess_probe(
                    keygen_command,
                    label="exact-candidate containment key generation",
                    cwd=workspace, environment=build_environment,
                    include_output=True,
                )
                keygen_evidence["environment"] = dict(build_environment)
                private_key = key_dir / "signing.key"
                if private_key.is_symlink() or not private_key.is_file():
                    fail("exact candidate did not create the containment signing key")

                sources = {
                    "example": ("candidate-example", candidate_paths["example"]),
                    "c-probe": ("c-probe", fixture_paths["c-probe"]),
                    "swift-probe": ("swift-probe", fixture_paths["swift-probe"]),
                }
                bundle_runs: List[Dict[str, Any]] = []
                for name, plugin_id, expected_artifact in CONTAINMENT_RUNS:
                    source_role, source_path = sources[name]
                    bundle = workspace / f"bundle-{name}"
                    bundle.mkdir(mode=0o700)
                    manifest = containment_plugin_manifest(plugin_id)
                    manifest_path = bundle / "manifest.json"
                    write_json_exclusive(manifest_path, manifest)
                    binary_path = bundle / "binary"
                    shutil.copy2(source_path, binary_path)
                    os.chmod(binary_path, 0o500)
                    source_sha = sha256_file(source_path)
                    if sha256_file(binary_path) != source_sha:
                        fail(f"containment bundle copy changed {name} fixture bytes")
                    sign_command = [
                        str(candidate_cli), "plugin", "sign", str(bundle),
                        "--key", str(private_key),
                    ]
                    sign_evidence = subprocess_probe(
                        sign_command, label=f"exact-candidate sign {name} bundle",
                        cwd=workspace, environment=build_environment,
                        include_output=True,
                    )
                    sign_evidence["environment"] = dict(build_environment)
                    signature_path = bundle / "signature"
                    publisher_key_path = bundle / "signing.key.pub"
                    for path, label in (
                        (signature_path, "signature"),
                        (publisher_key_path, "publisher key"),
                    ):
                        if path.is_symlink() or not path.is_file():
                            fail(f"exact candidate did not create bundle {label}")
                    run_command = [str(candidate_cli), "plugin", "test", str(bundle)]
                    run_evidence = subprocess_probe(
                        run_command, label=f"exact-candidate containment {name}",
                        cwd=workspace, environment=build_environment,
                        include_output=True,
                    )
                    run_evidence["environment"] = dict(build_environment)
                    validate_candidate_containment_output(
                        string_value(
                            run_evidence.get("output"),
                            f"exact-candidate containment {name}.output",
                            nonempty=False,
                        ),
                        run_name=name, expected_artifact=expected_artifact,
                    )
                    if name in CONTAINMENT_UNSANDBOXED_LEAKS:
                        listener.setblocking(False)
                        try:
                            unexpected, _ = listener.accept()
                        except BlockingIOError:
                            pass
                        else:
                            unexpected.close()
                            fail(
                                f"sandboxed containment run {name} reached the "
                                "reachable loopback endpoint"
                            )
                        finally:
                            listener.setblocking(True)
                    bundle_runs.append({
                        "name": name,
                        "plugin_id": plugin_id,
                        "expected_artifact": expected_artifact,
                        "source_role": source_role,
                        "source_sha256": source_sha,
                        "manifest": manifest,
                        "manifest_sha256": sha256_file(manifest_path),
                        "binary_sha256": sha256_file(binary_path),
                        "signature_sha256": sha256_file(signature_path),
                        "publisher_key_sha256": sha256_file(publisher_key_path),
                        "sign": sign_evidence,
                        "run": run_evidence,
                    })
                post_run_control = loopback_control_probe(
                    listener, label="containment post-run loopback control",
                    environment=build_environment,
                )
                network_control = {
                    "host": CONTAINMENT_LOOPBACK_HOST,
                    "port": CONTAINMENT_LOOPBACK_PORT,
                    "unsandboxed_reachable": True,
                    "pre_run": pre_run_control,
                    "post_run": post_run_control,
                }
            finally:
                if secret_identity is not None:
                    try:
                        current = secret_path.lstat()
                        if (current.st_dev, current.st_ino) == secret_identity \
                                and not secret_path.is_symlink() \
                                and secret_path.is_file():
                            secret_path.unlink()
                    except FileNotFoundError:
                        pass
                if mountpoint is not None:
                    subprocess.run(
                        [
                            fixed_tool("/usr/bin/hdiutil"), "detach",
                            str(mountpoint),
                        ],
                        capture_output=True, text=True, check=False,
                    )
    assert_exact_clean_source(
        root,
        source_commit=source_commit,
        source_tree=source_tree,
        label="containment recorder post-test",
    )
    ended_at = utc_now()
    document = containment_document(
        version=version,
        source_commit=source_commit,
        source_tree=source_tree,
        candidate_manifest_sha256=sha256_file(candidate_path),
        candidate=candidate,
        root=root,
        started_at=started_at,
        ended_at=ended_at,
        capture_mode="live-exact-candidate",
        workspace=workspace_text,
        build_scratch_path=str(build_scratch_path),
        candidate_execution=candidate_execution,
        build_evidence=build_evidence,
        bin_path_evidence=bin_path_evidence,
        network_control=network_control,
        unsandboxed_controls=unsandboxed_controls,
        keygen_evidence=keygen_evidence,
        fixture_inputs=fixture_inputs,
        bundle_runs=bundle_runs,
    )
    validate_containment_report(
        document,
        version=version,
        source_commit=source_commit,
        source_tree=source_tree,
        candidate_manifest_sha256=sha256_file(candidate_path),
        candidate=candidate,
        candidate_verification=verification,
        root=root,
    )
    write_json_exclusive(output, document)
    print(f"PASS: live containment qualification written: {output}")


def command_verify_release(args: argparse.Namespace) -> None:
    root = pathlib.Path(args.source_root).resolve()
    candidate_path = absolute_path(args.candidate_manifest)
    runtime_path = absolute_path(args.runtime_report)
    containment_path = absolute_path(args.containment_report)
    candidate_document_value = read_json_file(candidate_path, "candidate manifest")
    candidate = validate_candidate_document(
        candidate_document_value,
        expected_version=args.version,
        expected_source_commit=args.source_commit,
        expected_source_tree=args.source_tree,
        expected_build_number=args.build_number,
        dmg=absolute_path(args.dmg),
        artifact_checks=args.artifact_checks,
    )
    runtime = read_json_file(runtime_path, "installed-host runtime report")
    recorded_verification = object_value(
        candidate_document_value.get("artifact_verification"), "artifact_verification"
    )
    recorded_inventory = object_value(
        recorded_verification.get("payload_inventory"), "artifact_verification.payload_inventory"
    )
    validate_runtime_report(
        runtime,
        candidate_manifest_sha256=sha256_file(candidate_path),
        candidate=candidate,
        candidate_verification=recorded_verification,
        payload_inventory_sha256=require_sha(
            recorded_inventory.get("sha256"), "artifact_verification.payload_inventory.sha256"
        ),
        source_root=root,
    )
    containment = read_json_file(containment_path, "containment report")
    validate_containment_report(
        containment,
        version=args.version,
        source_commit=args.source_commit,
        source_tree=args.source_tree,
        candidate_manifest_sha256=sha256_file(candidate_path),
        candidate=candidate,
        candidate_verification=recorded_verification,
        root=root,
    )
    print(
        "PASS: exact candidate is signed/notarized, installed-host runtime-qualified, "
        "and containment-qualified"
    )


def command_emit_release_json(args: argparse.Namespace) -> None:
    emit_release_json(
        output=pathlib.Path(args.output),
        root=pathlib.Path(args.source_root).resolve(),
        candidate_manifest=read_json_file(pathlib.Path(args.candidate_manifest), "candidate manifest"),
        version=args.version,
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)

    record = commands.add_parser("record-candidate", help="inspect and bind one built DMG")
    record.add_argument("--version", required=True)
    record.add_argument("--build-number", required=True)
    record.add_argument("--source-commit", required=True)
    record.add_argument("--source-tree", required=True)
    record.add_argument("--dmg", required=True)
    record.add_argument("--output", required=True)
    record.add_argument("--notarization-submission-id", default="")
    record.add_argument("--artifact-checks", choices=("full", "digest"), default="full", help=argparse.SUPPRESS)
    record.set_defaults(func=command_record_candidate)

    template = commands.add_parser("runtime-template", help="write an intentionally incomplete report template")
    template.add_argument("--candidate-manifest", required=True)
    template.add_argument("--output", required=True)
    template.set_defaults(func=command_runtime_template)

    runtime = commands.add_parser(
        "record-runtime",
        help="capture and validate the exact installed candidate for 900 seconds",
    )
    runtime.add_argument("--candidate-manifest", required=True)
    runtime.add_argument("--dmg", required=True)
    runtime.add_argument("--source-root", required=True)
    runtime.add_argument("--output", required=True)
    runtime.add_argument(
        "--heartbeat-path", default=str(DEFAULT_HEARTBEAT_PATH)
    )
    runtime.add_argument(
        "--data-dir", action="append", default=None,
        help="installed support directory (repeat only for separately active stores)",
    )
    runtime.add_argument(
        "--sqlite-cap", action="append", default=[], metavar="NAME=BYTES",
        help="exact cap for an additional discovered SQLite family",
    )
    runtime.add_argument("--capture-output")
    runtime.set_defaults(func=command_record_runtime)

    containment = commands.add_parser("record-containment", help="record a successful on-device containment corpus run")
    containment.add_argument("--version", required=True)
    containment.add_argument("--source-root", required=True)
    containment.add_argument("--candidate-manifest", required=True)
    containment.add_argument("--dmg", required=True)
    containment.add_argument("--output", required=True)
    containment.set_defaults(func=command_record_containment)

    verify = commands.add_parser("verify-release", help="enforce all blocking candidate gates")
    verify.add_argument("--version", required=True)
    verify.add_argument("--source-commit", required=True)
    verify.add_argument("--source-tree", required=True)
    verify.add_argument("--build-number", required=True)
    verify.add_argument("--source-root", required=True)
    verify.add_argument("--dmg", required=True)
    verify.add_argument("--candidate-manifest", required=True)
    verify.add_argument("--runtime-report", required=True)
    verify.add_argument("--containment-report", required=True)
    verify.add_argument("--artifact-checks", choices=("full", "digest"), default="full", help=argparse.SUPPRESS)
    verify.set_defaults(func=command_verify_release)

    metadata = commands.add_parser("emit-release-json", help="regenerate GA metadata for a preserved candidate")
    metadata.add_argument("--version", required=True)
    metadata.add_argument("--source-root", required=True)
    metadata.add_argument("--candidate-manifest", required=True)
    metadata.add_argument("--output", required=True)
    metadata.set_defaults(func=command_emit_release_json)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = parser().parse_args(argv)
        args.func(args)
        return 0
    except QualificationError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
