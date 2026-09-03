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
import ctypes.util
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
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, Iterable, List, Mapping, NoReturn, Sequence, Tuple


class DarwinRUsageInfoV4(ctypes.Structure):
    """Exact macOS ``struct rusage_info_v4`` from ``sys/resource.h``.

    Keep this typed instead of using an oversized byte guess: ``proc_pid_rusage``
    writes the complete 296-byte structure. A 256-byte buffer corrupts Python's
    heap by 40 bytes and can surface only later during interpreter finalization.
    """

    _fields_ = [
        ("ri_uuid", ctypes.c_uint8 * 16),
        ("ri_user_time", ctypes.c_uint64),
        ("ri_system_time", ctypes.c_uint64),
        ("ri_pkg_idle_wkups", ctypes.c_uint64),
        ("ri_interrupt_wkups", ctypes.c_uint64),
        ("ri_pageins", ctypes.c_uint64),
        ("ri_wired_size", ctypes.c_uint64),
        ("ri_resident_size", ctypes.c_uint64),
        ("ri_phys_footprint", ctypes.c_uint64),
        ("ri_proc_start_abstime", ctypes.c_uint64),
        ("ri_proc_exit_abstime", ctypes.c_uint64),
        ("ri_child_user_time", ctypes.c_uint64),
        ("ri_child_system_time", ctypes.c_uint64),
        ("ri_child_pkg_idle_wkups", ctypes.c_uint64),
        ("ri_child_interrupt_wkups", ctypes.c_uint64),
        ("ri_child_pageins", ctypes.c_uint64),
        ("ri_child_elapsed_abstime", ctypes.c_uint64),
        ("ri_diskio_bytesread", ctypes.c_uint64),
        ("ri_diskio_byteswritten", ctypes.c_uint64),
        ("ri_cpu_time_qos_default", ctypes.c_uint64),
        ("ri_cpu_time_qos_maintenance", ctypes.c_uint64),
        ("ri_cpu_time_qos_background", ctypes.c_uint64),
        ("ri_cpu_time_qos_utility", ctypes.c_uint64),
        ("ri_cpu_time_qos_legacy", ctypes.c_uint64),
        ("ri_cpu_time_qos_user_initiated", ctypes.c_uint64),
        ("ri_cpu_time_qos_user_interactive", ctypes.c_uint64),
        ("ri_billed_system_time", ctypes.c_uint64),
        ("ri_serviced_system_time", ctypes.c_uint64),
        ("ri_logical_writes", ctypes.c_uint64),
        ("ri_lifetime_max_phys_footprint", ctypes.c_uint64),
        ("ri_instructions", ctypes.c_uint64),
        ("ri_cycles", ctypes.c_uint64),
        ("ri_billed_energy", ctypes.c_uint64),
        ("ri_serviced_energy", ctypes.c_uint64),
        ("ri_interval_max_phys_footprint", ctypes.c_uint64),
        ("ri_runnable_time", ctypes.c_uint64),
    ]


CANDIDATE_SCHEMA = "com.maccrab.release-candidate.v1"
RUNTIME_SCHEMA = "com.maccrab.installed-host-qualification.v2"
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
# Measured as `ri_phys_footprint`, not `ri_resident_size`.  Resident size on
# macOS counts clean file-backed and shared pages the process is not charged
# for -- the stores' 64 MiB SQLite mmap windows and the dyld shared cache --
# so it overstates what the engine is responsible for by roughly 3x, and it is
# not the number the kernel enforces.  `phys_footprint` is what jetsam charges
# and what Activity Monitor shows as "Memory".  Measured live on the reference
# host: resident 1,101.1 MiB against a footprint of 371.5 MiB.  The bound below
# is unchanged; only the metric it reads was wrong.
MAX_ENGINE_MEMORY_FOOTPRINT_BYTES = 450 * MIB
MAX_ENGINE_MEMORY_FOOTPRINT_GROWTH_BYTES = 64 * MIB
MIN_TRACE_WRITABLE_DUTY = 0.99
# Foreground mutations may wait behind one bounded recovery SQLite quantum,
# but a candidate that ever reports a completed or currently-live wait above
# five seconds has not demonstrated responsive causal-evidence admission.
MAX_TRACE_RECOVERY_MUTATION_WAIT_NANOSECONDS = 5_000_000_000
TRACE_RECOVERY_MUTATION_WAITER_LIMIT = 1_024
BURST_START_OFFSET_SECONDS = 300
BURST_END_OFFSET_SECONDS = 390
BURST_DRAIN_OFFSET_SECONDS = 450
WORKLOAD_DEADLINE_SECONDS = (
    BURST_END_OFFSET_SECONDS - BURST_START_OFFSET_SECONDS
)
LLM_PREWARM_TIMEOUT_SECONDS = 180
RUNTIME_DRAIN_TIMEOUT_SECONDS = 300
# rc.42: a lane with a small, idle backlog whose cumulative `completed` counter
# ADVANCED between distinct telemetry snapshots is flowing, not stuck. The
# rich heartbeat refreshes on a ~30-second cadence, so the 2-second drain poll
# sees at most a handful of distinct snapshots per window — and demanding an
# instantaneous queued==0 from a 30-second gauge on a host with continuous
# event inflow is sampling aliasing, not a health check: one stale nonzero
# reading repeats for up to 30s of polls. (Observed live: "file-event-
# persistence queued=36 in_flight=0" held for a whole 120s window while the
# engine was demonstrably persisting.) A genuinely stuck lane has a FROZEN
# `completed` and still fails. The bound below keeps the tolerance honest:
# it matches the writer's bounded queue capacity, far below the 100k stream
# caps, so a real backlog cannot hide behind the flow clause.
RUNTIME_DRAIN_FLOWING_QUEUE_LIMIT = 512
READINESS_POLL_SECONDS = 2
# The failed reference-host capture reached 1,274 events/s while the earlier
# quiet capture reached only 98 events/s.  Qualification therefore has to
# exercise at least the observed failure-state rate; a conserving idle engine
# is not a load test.
MIN_BURST_COMBINED_OFFERED_PER_SECOND = 1_274.0
# The fixed burst size. This is the SAME number the workload script declares as
# BURST_ITERATIONS; it was previously written out again as a literal inside the
# output reconciliation, so resizing the burst in the script left the gate
# demanding the old count and failing a correct run at
# "fixed workload output does not reconcile with its bounded run".
# `test_fixed_workload_iterations_match_the_script` pins the two together.
FIXED_WORKLOAD_ITERATIONS = 6_000
MIN_TRACE_STORE_INGEST_DELTA = 1
# v1.22.0: the dashboard-starves-expiry recurrence signature is a journal
# index that keeps paying for a full rebuild instead of an append-only
# refresh while the journal is simultaneously expiring and appending. A
# handful of legitimate full rebuilds remain (cold start, index overflow,
# "everything previously indexed expired" -- see EventStore.swift's
# compactJournalIndex/rebuildJournalIndex fallback paths), so the allowance
# is small, not zero.
EVENT_JOURNAL_INDEX_FULL_REBUILD_ALLOWANCE = 2
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
RUNTIME_RECORDER_SCHEMA = "com.maccrab.installed-host-recorder.v2"
RUNTIME_OBSERVATION_SCHEMA = "com.maccrab.installed-host-observation.v1"
DEFAULT_HEARTBEAT_PATH = pathlib.Path(
    "/Library/Application Support/MacCrab/heartbeat_rich.json"
)
DEFAULT_DATA_DIR = pathlib.Path("/Library/Application Support/MacCrab")
HEARTBEAT_MAX_AGE_SECONDS = 75.0
# Recorder captures can land five seconds on either side of their scheduled
# boundary.  A heartbeat-backed rate therefore tolerates at most the combined
# endpoint skew before the two clocks cease to prove the same interval.
MAX_HEARTBEAT_CAPTURE_INTERVAL_DRIFT_SECONDS = 10.0

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
        "priority-event-terminal-persistence",
        "file-event-terminal-persistence",
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
    "events.db": 340 * MIB,
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
AGENT_RULE_MANIFEST_PATH = (
    "MacCrab.app/Contents/Library/SystemExtensions/"
    "com.maccrab.agent.systemextension/Contents/Resources/"
    "compiled_rules/manifest.json"
)

HEX_OBJECT_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
HEX_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[0-9]+)?$")
BUILD_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[0-9]+)?\.[0-9]+$")
UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)
WORKLOAD_RUN_ID_RE = re.compile(r"^[0-9a-f]{32}$")
WORKLOAD_ALERT_PATH_RE = re.compile(
    r"^/private/tmp/maccrab-runtime-alert\.([0-9a-f]{32})/"
    r"maccrab-qualification-alert$"
)
WORKLOAD_BULK_PATH_RE = re.compile(
    r"^/Users/Shared/MacCrabQualificationRuntime-([0-9a-f]{32})$"
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


def validate_payload_inventory_symlink_modes(
    entries: Sequence[Any], *, path: str
) -> None:
    """Reject candidate inventories whose links are unsafe after root install."""
    for index, raw_entry in enumerate(entries):
        entry = object_value(raw_entry, f"{path}[{index}]")
        if entry.get("kind") != "symlink":
            continue
        mode = int_value(entry.get("mode"), f"{path}[{index}].mode")
        if mode > 0o7777:
            fail(f"{path}[{index}].mode must be a filesystem permission mode")
        if mode & 0o555 != 0o555:
            fail(
                f"{path}[{index}] symbolic link is not readable/traversable "
                "by every user"
            )
        if mode & 0o022:
            fail(f"{path}[{index}] symbolic link is group/world writable")


def rule_corpus_artifact_evidence(raw: Any, path: str) -> Dict[str, Any]:
    evidence = object_value(raw, path)
    if set(evidence) != {
        "manifest_path",
        "manifest_sha256",
        "bundle_version",
        "manifest_hash_entry_count",
    }:
        fail(f"{path} inventory is incomplete or unknown")
    if string_value(
        evidence.get("manifest_path"), f"{path}.manifest_path"
    ) != AGENT_RULE_MANIFEST_PATH:
        fail(f"{path}.manifest_path is not the sealed System Extension corpus")
    return {
        "manifest_path": AGENT_RULE_MANIFEST_PATH,
        "manifest_sha256": require_sha(
            evidence.get("manifest_sha256"), f"{path}.manifest_sha256"
        ),
        "bundle_version": string_value(
            evidence.get("bundle_version"), f"{path}.bundle_version"
        ),
        "manifest_hash_entry_count": int_value(
            evidence.get("manifest_hash_entry_count"),
            f"{path}.manifest_hash_entry_count",
            minimum=1,
        ),
    }


def validate_payload_inventory_binding(
    inventory: Mapping[str, Any], *, rule_corpus: Mapping[str, Any], path: str
) -> None:
    entries = list_value(
        inventory.get("entries"), f"{path}.entries", nonempty=True
    )
    validate_payload_inventory_symlink_modes(entries, path=f"{path}.entries")
    if int_value(
        inventory.get("entry_count"), f"{path}.entry_count", minimum=1
    ) != len(entries):
        fail(f"{path}.entry_count does not match its entries")
    paths: List[str] = []
    for index, raw_entry in enumerate(entries):
        entry = object_value(raw_entry, f"{path}.entries[{index}]")
        paths.append(
            string_value(entry.get("path"), f"{path}.entries[{index}].path")
        )
    if len(set(paths)) != len(paths):
        fail(f"{path}.entries contains duplicate paths")
    if require_sha(inventory.get("sha256"), f"{path}.sha256") \
            != sha256_bytes(canonical_json_bytes(entries)):
        fail(f"{path}.sha256 does not bind its canonical entries")
    manifest_rows = [
        object_value(entry, f"{path}.manifest entry")
        for entry in entries
        if object_value(entry, f"{path}.entry").get("path")
        == AGENT_RULE_MANIFEST_PATH
    ]
    if len(manifest_rows) != 1:
        fail(f"{path} must contain exactly one sealed rule manifest row")
    manifest_row = manifest_rows[0]
    if manifest_row.get("kind") != "file" \
            or require_sha(
                manifest_row.get("sha256"), f"{path}.manifest.sha256"
            ) != rule_corpus["manifest_sha256"] \
            or int_value(
                manifest_row.get("size_bytes"),
                f"{path}.manifest.size_bytes",
                minimum=1,
            ) < 1:
        fail(f"{path} sealed rule manifest row is not the recorded corpus")


def inventory_mounted_payload(mountpoint: pathlib.Path) -> Tuple[List[Dict[str, Any]], str]:
    entries: List[Dict[str, Any]] = []
    for path in sorted(mountpoint.rglob("*"), key=lambda item: item.relative_to(mountpoint).as_posix()):
        relative = path.relative_to(mountpoint).as_posix()
        stat_result = path.lstat()
        mode = stat_result.st_mode & 0o7777
        if stat.S_ISLNK(stat_result.st_mode):
            # A release inspection normally runs as the build owner, so an
            # owner-only link can look usable here and then become unreadable
            # when install.sh changes ownership to root.  Enforce the numeric
            # cross-user contract and reject write authority for non-owners.
            # lstat/readlink never dereference an arbitrary signed link target.
            if mode & 0o555 != 0o555:
                fail(
                    "mounted payload symbolic link is not readable/traversable "
                    f"by every user: {relative}"
                )
            if mode & 0o022:
                fail(f"mounted payload symbolic link is group/world writable: {relative}")
            entries.append({
                "path": relative,
                "kind": "symlink",
                "target": os.readlink(str(path)),
                "mode": mode,
            })
        elif stat.S_ISREG(stat_result.st_mode):
            entries.append({
                "path": relative,
                "kind": "file",
                "size_bytes": stat_result.st_size,
                "sha256": sha256_file(path),
                "mode": mode,
            })
        elif stat.S_ISDIR(stat_result.st_mode):
            entries.append({
                "path": relative,
                "kind": "directory",
                "mode": mode,
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
        rule_manifest_path = mountpoint / AGENT_RULE_MANIFEST_PATH
        if rule_manifest_path.is_symlink() or not rule_manifest_path.is_file():
            fail("sealed System Extension rule manifest is missing or redirected")
        if rule_manifest_path.stat().st_size <= 0 \
                or rule_manifest_path.stat().st_size > 8 * MIB:
            fail("sealed System Extension rule manifest has an invalid size")
        rule_manifest_data = rule_manifest_path.read_bytes()
        try:
            rule_manifest = object_value(
                json.loads(rule_manifest_data), "sealed rule manifest"
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            fail(f"sealed System Extension rule manifest is invalid JSON: {exc}")
        if set(rule_manifest) != {"schema_version", "bundle_version", "hashes"}:
            fail("sealed System Extension rule manifest inventory is invalid")
        if int_value(
            rule_manifest.get("schema_version"),
            "sealed rule manifest.schema_version",
            minimum=1,
        ) != 1:
            fail("sealed System Extension rule manifest schema is unsupported")
        rule_hashes = object_value(
            rule_manifest.get("hashes"), "sealed rule manifest.hashes"
        )
        if not rule_hashes:
            fail("sealed System Extension rule manifest has no hash entries")
        for relative, digest in rule_hashes.items():
            string_value(relative, "sealed rule manifest hash path")
            require_sha(digest, f"sealed rule manifest hash {relative}")
        rule_corpus = {
            "manifest_path": AGENT_RULE_MANIFEST_PATH,
            "manifest_sha256": sha256_bytes(rule_manifest_data),
            "bundle_version": string_value(
                rule_manifest.get("bundle_version"),
                "sealed rule manifest.bundle_version",
            ),
            "manifest_hash_entry_count": len(rule_hashes),
        }
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
            "rule_corpus": rule_corpus,
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
    fixture_entries = [
        {
            "path": dmg.name,
            "kind": "file",
            "size_bytes": dmg.stat().st_size,
            "sha256": sha256_file(dmg),
        },
        {
            "path": AGENT_PAYLOAD_PATH,
            "kind": "file",
            "size_bytes": dmg.stat().st_size,
            "sha256": sha256_file(dmg),
        },
        {
            "path": AGENT_RULE_MANIFEST_PATH,
            "kind": "file",
            "size_bytes": dmg.stat().st_size,
            "sha256": sha256_file(dmg),
        },
        *[
            {
                "path": relative,
                "kind": "file",
                "size_bytes": dmg.stat().st_size,
                "sha256": sha256_file(dmg),
            }
            for relative, _ in CONTAINMENT_CANDIDATE_BINARIES.values()
        ],
    ]
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
        "rule_corpus": {
            "manifest_path": AGENT_RULE_MANIFEST_PATH,
            "manifest_sha256": sha256_file(dmg),
            "bundle_version": "test-fixture",
            "manifest_hash_entry_count": 1,
        },
        "notarization_status": "not-checked",
        "notarization_submission_id": "00000000-0000-4000-8000-000000000000",
        "stapled": False,
        "gatekeeper_accepted": False,
        "release_input_attestation_sha256": "0" * 64,
        "release_input_attestation": {},
        "payload_inventory": {
            "format": "test-fixture",
            "entry_count": len(fixture_entries),
            "sha256": sha256_bytes(canonical_json_bytes(fixture_entries)),
            "entries": fixture_entries,
        },
    }


def validate_preinstall_clean_ci(
    raw: Any, *, source_commit: str, source_tree: str, path: str
) -> Dict[str, Any]:
    """Validate the clean-CI receipt captured before the candidate was built.

    The installed-host recorder must not launch Swift builds or tests while the
    process epoch it intends to qualify is alive.  This receipt moves that
    source-bound proof to release phase 1, before the candidate is installed,
    and the candidate-manifest digest subsequently binds it to runtime evidence.
    """
    evidence = object_value(raw, path)
    required = {
        "command", "exit_code", "output_sha256", "output_tail",
        "output_line_count", "started_at", "completed_at", "source_commit",
        "source_tree", "clean_source_before", "clean_source_after",
    }
    if set(evidence) != required:
        fail(f"{path} inventory is incomplete or unknown")
    command = list_value(evidence.get("command"), f"{path}.command")
    if command != ["scripts/ci-local.sh", "--clean"]:
        fail(f"{path}.command is not the fixed clean local-CI gate")
    if int_value(evidence.get("exit_code"), f"{path}.exit_code") != 0:
        fail(f"{path} did not pass")
    require_sha(evidence.get("output_sha256"), f"{path}.output_sha256")
    output_tail = string_value(
        evidence.get("output_tail"), f"{path}.output_tail"
    )
    if "ALL CHECKS PASSED" not in output_tail:
        fail(f"{path}.output_tail lacks the terminal clean-CI success marker")
    int_value(
        evidence.get("output_line_count"), f"{path}.output_line_count", minimum=1
    )
    started = parse_time(evidence.get("started_at"), f"{path}.started_at")
    completed = parse_time(evidence.get("completed_at"), f"{path}.completed_at")
    if completed < started:
        fail(f"{path}.completed_at precedes its start")
    if require_object_id(
        evidence.get("source_commit"), f"{path}.source_commit"
    ) != source_commit or require_object_id(
        evidence.get("source_tree"), f"{path}.source_tree"
    ) != source_tree:
        fail(f"{path} is not bound to the candidate source commit/tree")
    require_true(evidence.get("clean_source_before"), f"{path}.clean_source_before")
    require_true(evidence.get("clean_source_after"), f"{path}.clean_source_after")
    return copy.deepcopy(evidence)


def preinstall_clean_ci_evidence(
    *, transcript_path: pathlib.Path, started_at: str, completed_at: str,
    source_commit: str, source_tree: str,
) -> Dict[str, Any]:
    """Create a bounded receipt from release.sh's already-completed clean CI."""
    descriptor = -1
    try:
        descriptor = os.open(
            str(transcript_path),
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size <= 0:
            fail("preinstall clean-CI transcript is empty or non-regular")
        if opened.st_size > 64 * MIB:
            fail("preinstall clean-CI transcript exceeds the 64 MiB evidence bound")
        chunks: List[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) != opened.st_size:
            fail("preinstall clean-CI transcript was truncated while reading")
        current = os.stat(transcript_path, follow_symlinks=False)
        if not stat.S_ISREG(current.st_mode) \
                or (current.st_dev, current.st_ino, current.st_size) != (
                    opened.st_dev, opened.st_ino, opened.st_size
                ):
            fail("preinstall clean-CI transcript identity changed while reading")
    except OSError as exc:
        fail(f"preinstall clean-CI transcript is unreadable: {exc}")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        output = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        fail(f"preinstall clean-CI transcript is not UTF-8: {exc}")
    evidence = {
        "command": ["scripts/ci-local.sh", "--clean"],
        "exit_code": 0,
        "output_sha256": sha256_bytes(raw),
        "output_tail": output[-4096:],
        "output_line_count": len(output.splitlines()),
        "started_at": started_at,
        "completed_at": completed_at,
        "source_commit": source_commit,
        "source_tree": source_tree,
        "clean_source_before": True,
        "clean_source_after": True,
    }
    return validate_preinstall_clean_ci(
        evidence, source_commit=source_commit, source_tree=source_tree,
        path="preinstall_clean_ci",
    )


def candidate_document(
    *,
    version: str,
    build_number: str,
    source_commit: str,
    source_tree: str,
    dmg: pathlib.Path,
    inspection_level: str,
    notarization_submission_id: str,
    preinstall_clean_ci: Mapping[str, Any],
) -> Dict[str, Any]:
    if not VERSION_RE.fullmatch(version):
        fail("candidate version has an invalid shape")
    if not BUILD_RE.fullmatch(build_number) or not build_number.startswith(version + "."):
        fail("candidate build number must be <version>.<positive commit count>")
    require_object_id(source_commit, "source_commit")
    require_object_id(source_tree, "source_tree")
    clean_ci = validate_preinstall_clean_ci(
        preinstall_clean_ci, source_commit=source_commit,
        source_tree=source_tree, path="preinstall_clean_ci",
    )
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
        fixture_rule_corpus = object_value(
            inspection.get("rule_corpus"), "fixture rule corpus"
        )
        fixture_rule_corpus["bundle_version"] = version
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
        "preinstall_clean_ci": clean_ci,
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
    if set(document) != {
        "schema", "created_at", "candidate", "artifact_verification",
        "preinstall_clean_ci",
    }:
        fail("candidate manifest inventory is incomplete or unknown")
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
    validate_preinstall_clean_ci(
        document.get("preinstall_clean_ci"), source_commit=source_commit,
        source_tree=source_tree, path="candidate.preinstall_clean_ci",
    )
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
    recorded_rule_corpus = rule_corpus_artifact_evidence(
        verification.get("rule_corpus"), "artifact_verification.rule_corpus"
    )
    recorded_inventory = object_value(
        verification.get("payload_inventory"),
        "artifact_verification.payload_inventory",
    )
    if recorded_rule_corpus["bundle_version"] != version:
        fail("candidate sealed rule corpus version does not match candidate version")
    validate_payload_inventory_binding(
        recorded_inventory,
        rule_corpus=recorded_rule_corpus,
        path="artifact_verification.payload_inventory",
    )
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
        inspected_inventory = object_value(inspected.get("payload_inventory"), "inspected payload inventory")
        if require_sha(recorded_inventory.get("sha256"), "artifact_verification.payload_inventory.sha256") != inspected_inventory.get("sha256"):
            fail("mounted DMG payload inventory changed since candidate recording")
        inspected_rule_corpus = rule_corpus_artifact_evidence(
            inspected.get("rule_corpus"), "inspected rule corpus"
        )
        if inspected_rule_corpus != recorded_rule_corpus:
            fail("mounted sealed rule corpus changed since candidate recording")
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


def validate_recorder_probe_evidence(
    raw: Any, *, source_root: pathlib.Path,
    expected_preinstall_clean_ci: Mapping[str, Any],
) -> None:
    evidence = object_value(raw, "runtime.recorder_probe_evidence")
    required = {
        "preinstall_clean_ci", "workload",
        "disk_diagnostic_log", "storage_convergence_log",
        "administrator_prompt_log", "rule_reload_log", "live_sighup",
        "llm_prewarm",
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
        if name == "preinstall_clean_ci":
            normalized = validate_preinstall_clean_ci(
                row,
                source_commit=require_object_id(
                    expected_preinstall_clean_ci.get("source_commit"),
                    "candidate preinstall_clean_ci.source_commit",
                ),
                source_tree=require_object_id(
                    expected_preinstall_clean_ci.get("source_tree"),
                    "candidate preinstall_clean_ci.source_tree",
                ),
                path="recorder probes.preinstall_clean_ci",
            )
            if normalized != expected_preinstall_clean_ci:
                fail(
                    "runtime preinstall clean-CI receipt does not match the "
                    "candidate manifest"
                )
        if name == "workload" \
                and not any(str(part).endswith("scripts/runtime-qualification-workload.sh") for part in command):
            fail("workload evidence does not invoke the fixed workload")
        if name in ("workload", "llm_prewarm"):
            if not any(
                str(part).endswith("scripts/runtime-qualification-workload.sh")
                for part in command
            ):
                fail(f"{name} evidence does not invoke the fixed workload")
            try:
                run_index = command.index("--run-id")
                run_id = string_value(command[run_index + 1], f"{name} run id")
            except (ValueError, IndexError):
                fail(f"{name} command omits its fixed unique run id")
            alert_path, bulk_path = workload_paths(run_id)
            if row.get("run_id") != run_id \
                    or row.get("alert_executable") != alert_path:
                fail(f"{name} identity does not reconcile with its command")
            started_at = parse_time(row.get("started_at"), f"{name}.started_at")
            completed_at = parse_time(row.get("completed_at"), f"{name}.completed_at")
            if completed_at < started_at:
                fail(f"{name} completion precedes its start")
            proof = object_value(
                row.get("alert_investigation"), f"recorder probes.{name}.alert"
            )
            validate_alert_investigation_proof(
                proof, f"recorder probes.{name}.alert_investigation"
            )
            if proof.get("process_path") != alert_path:
                fail(f"{name} alert proof does not bind its unique executable")
            if name == "llm_prewarm":
                if "--alert-only" not in command or proof.get("phase") != "prewarm":
                    fail("LLM prewarm did not use the fixed alert-only path")
            else:
                if "--alert-only" in command or proof.get("phase") != "epoch":
                    fail("measured workload did not use the full fixed path")
                if row.get("bulk_path") != bulk_path:
                    fail("workload bulk path does not reconcile with its run id")
                if int_value(
                    row.get("deadline_offset_seconds"),
                    "workload.deadline_offset_seconds",
                ) != BURST_END_OFFSET_SECONDS \
                        or int_value(
                            row.get("drain_offset_seconds"),
                            "workload.drain_offset_seconds",
                        ) != BURST_DRAIN_OFFSET_SECONDS:
                    fail("workload evidence does not bind the fixed deadline/drain")
                expected_isolation = validate_workload_sequence_path_isolation(
                    source_root, bulk_path
                )
                if row.get("sequence_path_isolation") != expected_isolation:
                    fail("workload stable-sequence path isolation does not reconcile")
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
    candidate_preinstall_clean_ci: Mapping[str, Any],
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
    validate_recorder_probe_evidence(
        report.get("recorder_probe_evidence"), source_root=source_root,
        expected_preinstall_clean_ci=candidate_preinstall_clean_ci,
    )
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
    sample_capture_times: List[dt.datetime] = []
    sample_capture_gaps: List[float] = []
    sample_heartbeat_times: List[float] = []
    sample_rss_values: List[int] = []
    sample_gui_values: List[float] = []
    sample_sequence_evictions: List[int] = []
    sample_journal_shed: List[int] = []
    sample_journal_index_full_rebuilds: List[int | None] = []
    sample_journal_index_append_refreshes: List[int | None] = []
    rss_by_offset: Dict[int, int] = {}
    for index, raw_sample in enumerate(samples):
        path = f"runtime.samples[{index}]"
        sample = object_value(raw_sample, path)
        offset = number_value(sample.get("offset_seconds"), f"{path}.offset_seconds", minimum=0)
        readiness_fatal, readiness_pending = runtime_readiness_failures(
            observations[index], f"runtime.recorder_observations[{index}]",
            expected_pid=installed_start_pid,
        )
        if readiness_fatal:
            fail(
                f"{path} contains a fail-fast readiness fault: "
                + "; ".join(readiness_fatal)
            )
        if any(
            abs(offset - boundary) <= 0.001
            for boundary in (0, BURST_DRAIN_OFFSET_SECONDS, MIN_EPOCH_SECONDS)
        ) and readiness_pending:
            fail(
                f"{path} is not drained at a fixed readiness boundary: "
                + "; ".join(readiness_pending)
            )
        sample_time = parse_time(sample.get("recorded_at"), f"{path}.recorded_at")
        expected_sample_time = started + dt.timedelta(seconds=offset)
        if abs((sample_time - expected_sample_time).total_seconds()) > 1.0:
            fail(f"{path}.recorded_at does not equal epoch start + offset_seconds")
        capture_time = parse_time(sample.get("captured_at"), f"{path}.captured_at")
        capture_gap: float | None = None
        if sample_capture_times:
            capture_gap = (
                capture_time - sample_capture_times[-1]
            ).total_seconds()
            if capture_gap <= 0:
                fail(
                    "runtime sample captured_at timestamps must be "
                    "strictly increasing"
                )
            if capture_gap > MAX_SAMPLE_GAP_SECONDS:
                fail(
                    f"runtime captured sample gap {capture_gap} exceeds "
                    f"{MAX_SAMPLE_GAP_SECONDS} seconds"
                )
            sample_capture_gaps.append(capture_gap)
        heartbeat_time = number_value(
            sample.get("heartbeat_written_at_unix"),
            f"{path}.heartbeat_written_at_unix",
        )
        if sample_heartbeat_times:
            heartbeat_gap = heartbeat_time - sample_heartbeat_times[-1]
            if heartbeat_gap <= 0:
                fail("runtime heartbeat timestamps must be strictly increasing")
            if capture_gap is None or abs(heartbeat_gap - capture_gap) \
                    > MAX_HEARTBEAT_CAPTURE_INTERVAL_DRIFT_SECONDS:
                fail(
                    "runtime heartbeat and capture intervals diverge by more "
                    f"than {MAX_HEARTBEAT_CAPTURE_INTERVAL_DRIFT_SECONDS} seconds"
                )
        pid = int_value(sample.get("engine_pid"), f"{path}.engine_pid", minimum=1)
        observed_pids.add(pid)
        cpu_total = number_value(
            sample.get("engine_cpu_seconds_total"), f"{path}.engine_cpu_seconds_total", minimum=0
        )
        write_total = int_value(
            sample.get("engine_disk_write_bytes_total"), f"{path}.engine_disk_write_bytes_total"
        )
        rss = int_value(sample.get("engine_memory_footprint_bytes"), f"{path}.engine_memory_footprint_bytes")
        gui_cpu = number_value(
            sample.get("gui_background_cpu_percent"), f"{path}.gui_background_cpu_percent", minimum=0
        )
        sample_cpu_totals.append(cpu_total)
        sample_write_totals.append(write_total)
        sample_offsets.append(offset)
        sample_capture_times.append(capture_time)
        sample_heartbeat_times.append(heartbeat_time)
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
        sample_journal_index = object_value(
            sample.get("event_journal_index"), f"{path}.event_journal_index"
        )
        if sample_journal_index.get("present"):
            sample_journal_index_full_rebuilds.append(
                int_value(
                    sample_journal_index.get("full_rebuilds_total"),
                    f"{path}.event_journal_index.full_rebuilds_total",
                )
            )
            sample_journal_index_append_refreshes.append(
                int_value(
                    sample_journal_index.get("append_refreshes_total"),
                    f"{path}.event_journal_index.append_refreshes_total",
                )
            )
        else:
            sample_journal_index_full_rebuilds.append(None)
            sample_journal_index_append_refreshes.append(None)
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
    captured_duration = (
        sample_capture_times[-1] - sample_capture_times[0]
    ).total_seconds()
    if captured_duration + 0.001 < MIN_EPOCH_SECONDS:
        fail("runtime captured sample duration is below 900 seconds")
    recorded_captured_duration = number_value(
        epoch.get("captured_duration_seconds"),
        "runtime.epoch.captured_duration_seconds",
        minimum=MIN_EPOCH_SECONDS,
    )
    recorded_captured_gap = number_value(
        epoch.get("max_captured_gap_seconds"),
        "runtime.epoch.max_captured_gap_seconds",
        minimum=0.000001,
    )
    if abs(recorded_captured_duration - captured_duration) > 0.001 \
            or abs(recorded_captured_gap - max(sample_capture_gaps)) > 0.001:
        fail("runtime captured timing summary does not reconcile with samples")

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
    # v1.22.0: recurrence gate for the dashboard-starves-expiry bug. A healthy
    # journal index keeps paying append-only refreshes as the journal expires
    # and appends; it does NOT keep paying full rebuilds. `present` is False
    # on any candidate whose heartbeat predates this wiring -- that is "not
    # sampled", not a pass, so it is surfaced with a NOTE rather than silently
    # skipped.
    if all(value is not None for value in sample_journal_index_full_rebuilds):
        journal_index_rebuild_delta = (
            sample_journal_index_full_rebuilds[-1]
            - sample_journal_index_full_rebuilds[0]
        )
        journal_index_append_delta = (
            sample_journal_index_append_refreshes[-1]
            - sample_journal_index_append_refreshes[0]
        )
        if journal_index_rebuild_delta < 0 or journal_index_append_delta < 0:
            fail("event journal index refresh/rebuild counters moved backwards")
        if journal_index_rebuild_delta > EVENT_JOURNAL_INDEX_FULL_REBUILD_ALLOWANCE \
                and journal_index_append_delta > 0:
            fail(
                "event journal index full_rebuilds_total increased by "
                f"{journal_index_rebuild_delta} while append_refreshes_total "
                f"also increased by {journal_index_append_delta} -- this is "
                "the dashboard-starves-expiry recurrence signature (v1.22.0)"
            )
    else:
        print(
            "NOTE: heartbeat.event_journal_index is not present on every "
            "runtime sample; skipping the full-rebuild-vs-append-refresh "
            "recurrence gate (instrumentation not yet wired on this "
            "candidate). This is a skip, not a pass."
        )
    probe_evidence = object_value(
        report.get("recorder_probe_evidence"), "runtime.recorder_probe_evidence"
    )
    clean_ci_evidence = object_value(
        probe_evidence.get("preinstall_clean_ci"),
        "runtime.recorder_probe_evidence.preinstall_clean_ci",
    )
    if require_sha(
        correlation.get("source_bound_clean_ci_sha256"),
        "runtime.measurements.correlation_continuity.source_bound_clean_ci_sha256",
    ) != require_sha(
        clean_ci_evidence.get("output_sha256"),
        "runtime.recorder_probe_evidence.preinstall_clean_ci.output_sha256",
    ):
        fail("correlation continuity does not bind the preinstall clean-CI transcript")
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
    count_windows = list_value(
        storage.get("event_type_count_windows"),
        "runtime.measurements.event_storage.event_type_count_windows",
    )
    if len(count_windows) != len(samples):
        fail("event-type count window evidence does not cover every sample")
    normalized_count_windows = [
        object_value(
            row,
            f"runtime.measurements.event_storage.event_type_count_windows[{index}]",
        )
        for index, row in enumerate(count_windows)
    ]
    sample_count_windows = [
        object_value(
            object_value(sample, f"runtime.samples[{index}]").get(
                "event_type_count_window"
            ),
            f"runtime.samples[{index}].event_type_count_window",
        )
        for index, sample in enumerate(samples)
    ]
    if normalized_count_windows != sample_count_windows:
        fail("event-type count window aggregate does not match raw samples")
    for index, row in enumerate(normalized_count_windows):
        if int_value(
            row.get("gap_records"),
            f"runtime event-type count window {index}.gap_records",
        ) != 0:
            fail("event-type count window contains exact-evidence gaps")
    search_rows = list_value(
        storage.get("event_search_projections"),
        "runtime.measurements.event_storage.event_search_projections",
    )
    if len(search_rows) != len(samples):
        fail("event-search coverage evidence does not cover every sample")
    normalized_search_rows = [
        object_value(
            row,
            f"runtime.measurements.event_storage.event_search_projections[{index}]",
        )
        for index, row in enumerate(search_rows)
    ]
    sample_search_rows = [
        object_value(
            object_value(sample, f"runtime.samples[{index}]").get(
                "event_search_projection"
            ),
            f"runtime.samples[{index}].event_search_projection",
        )
        for index, sample in enumerate(samples)
    ]
    if normalized_search_rows != sample_search_rows:
        fail("event-search coverage aggregate does not match raw samples")
    for index, row in enumerate(normalized_search_rows):
        if int_value(
            row.get("gap_records_total"),
            f"runtime event-search projection {index}.gap_records_total",
        ) != 0:
            fail("event-search coverage contains exact-evidence gaps")
    journal_recovery = object_value(
        storage.get("journal_recovery"),
        "runtime.measurements.event_storage.journal_recovery",
    )
    sample_journal_recovery = [
        object_value(
            object_value(sample, f"runtime.samples[{index}]").get(
                "event_journal_recovery"
            ),
            f"runtime.samples[{index}].event_journal_recovery",
        )
        for index, sample in enumerate(samples)
    ]
    if any(row != journal_recovery for row in sample_journal_recovery):
        fail("event-journal recovery aggregate does not match every sample")
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
    graph_barrier_rows = [
        trace_graph_recovery_barrier_sample(
            object_value(
                object_value(sample, "runtime sample").get(
                    "trace_graph_recovery_barrier"
                ),
                "runtime sample.trace_graph_recovery_barrier",
            ),
            "runtime sample.trace_graph_recovery_barrier",
        )
        for sample in samples
    ]
    accepting_duty = sum(
        1 for row in graph_barrier_rows
        if row["accepting_mutations"] is True
    ) / len(graph_barrier_rows)
    recorded_accepting_duty = number_value(
        trace.get("accepting_mutations_duty_fraction"),
        "runtime.measurements.trace_graph.accepting_mutations_duty_fraction",
        minimum=0,
    )
    if abs(recorded_accepting_duty - accepting_duty) > 0.000001:
        fail("TraceGraph accepting-mutations duty does not reconcile with samples")
    if accepting_duty < MIN_TRACE_WRITABLE_DUTY or accepting_duty > 1:
        fail("TraceGraph accepting-mutations duty must be between 0.99 and 1.0")
    if any(
        row["recovery_mutation_queue_saturated"] is not False
        for row in graph_barrier_rows
    ):
        fail("TraceGraph recovery mutation queue saturated during a sample")
    if len({row["recovery_mutation_waiter_limit"] for row in graph_barrier_rows}) != 1:
        fail("TraceGraph recovery mutation waiter limit changed during the epoch")
    if graph_barrier_rows[0]["recovery_mutation_waiter_limit"] \
            != TRACE_RECOVERY_MUTATION_WAITER_LIMIT:
        fail("TraceGraph recovery mutation waiter limit is not the fixed production bound")
    barrier_cumulative_keys = (
        "recovery_mutation_waiter_high_watermark",
        "recovery_mutation_waits_total",
        "recovery_mutation_wait_releases_total",
        "recovery_mutation_wait_cancellations_total",
        "recovery_mutation_wait_closed_total",
        "recovery_mutation_wait_saturations_total",
        "recovery_mutation_wait_nanoseconds_total",
        "recovery_mutation_max_wait_nanoseconds",
        "recovery_writer_preemptions_total",
    )
    for key in barrier_cumulative_keys:
        values = [row[key] for row in graph_barrier_rows]
        if any(later < earlier for earlier, later in zip(values, values[1:])):
            fail(f"TraceGraph barrier {key} counter reset during the epoch")

    def barrier_delta(key: str) -> int:
        return graph_barrier_rows[-1][key] - graph_barrier_rows[0][key]

    waits_delta = barrier_delta("recovery_mutation_waits_total")
    wait_releases_delta = barrier_delta(
        "recovery_mutation_wait_releases_total"
    )
    wait_cancellations_delta = barrier_delta(
        "recovery_mutation_wait_cancellations_total"
    )
    wait_closed_delta = barrier_delta("recovery_mutation_wait_closed_total")
    waiter_gauge_delta = (
        graph_barrier_rows[-1]["recovery_mutation_waiters"]
        - graph_barrier_rows[0]["recovery_mutation_waiters"]
    )
    if waits_delta != (
        waiter_gauge_delta + wait_releases_delta
        + wait_cancellations_delta + wait_closed_delta
    ):
        fail("TraceGraph recovery mutation waiter epoch ledger does not conserve")
    saturation_delta = barrier_delta("recovery_mutation_wait_saturations_total")
    require_zero(
        saturation_delta,
        "runtime.measurements.trace_graph.recovery_mutation_wait_saturations_epoch_delta",
    )
    maximum_completed_wait = max(
        row["recovery_mutation_max_wait_nanoseconds"]
        for row in graph_barrier_rows
    )
    maximum_oldest_wait = max(
        row["recovery_mutation_oldest_wait_nanoseconds"]
        for row in graph_barrier_rows
    )
    if maximum_completed_wait > MAX_TRACE_RECOVERY_MUTATION_WAIT_NANOSECONDS:
        fail("TraceGraph recovery mutation maximum wait exceeded five seconds")
    if maximum_oldest_wait > MAX_TRACE_RECOVERY_MUTATION_WAIT_NANOSECONDS:
        fail("TraceGraph oldest live recovery mutation wait exceeded five seconds")
    if graph_barrier_rows[-1]["recovery_mutation_waiters"] != 0 \
            or graph_barrier_rows[-1]["recovery_mutation_oldest_wait_nanoseconds"] != 0:
        fail("TraceGraph recovery mutation queue did not drain at the epoch boundary")
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
        "physical_write_suppressed_events_total",
        "physical_write_suppressed_rows_total",
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
    graph_suppressed_events_delta = (
        graph_rows[-1]["physical_write_suppressed_events_total"]
        - graph_rows[0]["physical_write_suppressed_events_total"]
    )
    graph_suppressed_rows_delta = (
        graph_rows[-1]["physical_write_suppressed_rows_total"]
        - graph_rows[0]["physical_write_suppressed_rows_total"]
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
        "accepting_mutations_duty_fraction": accepting_duty,
        "mutation_shed": last_trace_shed - first_trace_shed,
        "recovery_oscillation_count": trace.get("recovery_oscillation_count"),
        "recovery_mutation_queue_saturated_samples": 0,
        "recovery_mutation_waiter_limit": graph_barrier_rows[0][
            "recovery_mutation_waiter_limit"
        ],
        "recovery_mutation_waiter_high_watermark": max(
            row["recovery_mutation_waiter_high_watermark"]
            for row in graph_barrier_rows
        ),
        "recovery_mutation_waits_epoch_delta": waits_delta,
        "recovery_mutation_wait_releases_epoch_delta": wait_releases_delta,
        "recovery_mutation_wait_cancellations_epoch_delta":
            wait_cancellations_delta,
        "recovery_mutation_wait_closed_epoch_delta": wait_closed_delta,
        "recovery_mutation_wait_saturations_epoch_delta": saturation_delta,
        "recovery_writer_preemptions_epoch_delta": barrier_delta(
            "recovery_writer_preemptions_total"
        ),
        "recovery_mutation_max_wait_nanoseconds": maximum_completed_wait,
        "recovery_mutation_max_oldest_wait_nanoseconds": maximum_oldest_wait,
        "final_recovery_mutation_waiters": graph_barrier_rows[-1][
            "recovery_mutation_waiters"
        ],
        "final_recovery_mutation_oldest_wait_nanoseconds":
            graph_barrier_rows[-1][
                "recovery_mutation_oldest_wait_nanoseconds"
            ],
        "write_accounting_reconciled_all_samples": True,
        "coalesced_noop_rows_epoch_delta": graph_coalesced_delta,
        "physical_write_suppressed_events_epoch_delta":
            graph_suppressed_events_delta,
        "physical_write_suppressed_rows_epoch_delta": graph_suppressed_rows_delta,
        "failed_batches_epoch_delta": graph_failed_batches_delta,
        "failed_rows_epoch_delta": graph_failed_rows_delta,
        "failed_events_epoch_delta": graph_ingest_shed_delta,
    }
    if trace != expected_trace_graph:
        fail("TraceGraph aggregate does not reconcile with exact write ledgers")
    if graph_suppressed_events_delta <= 0 or graph_suppressed_rows_delta <= 0:
        fail("TraceGraph physical-write suppression was not exercised")
    if graph_suppressed_events_delta != graph_suppressed_rows_delta:
        fail("TraceGraph physical-write suppression event/row deltas diverge")
    require_zero(
        graph_failed_batches_delta,
        "runtime.measurements.trace_graph.failed_batches_epoch_delta",
    )
    require_zero(
        graph_failed_rows_delta,
        "runtime.measurements.trace_graph.failed_rows_epoch_delta",
    )
    require_zero(
        graph_ingest_shed_delta,
        "runtime.measurements.trace_graph.failed_events_epoch_delta",
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
    average_bps = engine_bytes / captured_duration
    recorded_average = number_value(writes.get("average_bytes_per_second"), "runtime.measurements.disk_writes.average_bytes_per_second", minimum=0)
    if abs(recorded_average - average_bps) > max(1.0, average_bps * 0.001):
        fail(
            "disk write average does not reconcile with engine_bytes / "
            "captured sample duration"
        )
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
        expected_captured_elapsed = (
            sample_capture_times[index + 1] - sample_capture_times[index]
        ).total_seconds()
        captured_elapsed = number_value(
            window.get("captured_elapsed_seconds"),
            f"{path}.captured_elapsed_seconds",
            minimum=0.000001,
        )
        if abs(start - expected_start) > 0.001 \
                or abs(end - expected_end) > 0.001 \
                or byte_count != expected_bytes \
                or abs(captured_elapsed - expected_captured_elapsed) > 0.001:
            fail("disk write windows do not reconcile with cumulative samples")
        if end <= start or end - start > 60.001:
            fail("disk write sample intervals must be positive and at most 60 seconds")
        if byte_count / captured_elapsed > MAX_WINDOW_WRITE_BYTES_PER_SECOND:
            fail(f"disk write window {index} exceeds 4 MiB/s")
        window_bytes_total += byte_count
    if abs(sample_offsets[-1] - duration) > 1.0 or window_bytes_total != engine_bytes:
        fail("disk write windows do not cover/reconcile the complete epoch")
    for start_index in range(len(sample_capture_times) - 1):
        for end_index in range(start_index + 1, len(sample_offsets)):
            span = (
                sample_capture_times[end_index] - sample_capture_times[start_index]
            ).total_seconds()
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
    average_cores = cpu_seconds / captured_duration
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
    max_rss = int_value(memory.get("engine_max_memory_footprint_bytes"), "runtime.measurements.memory.engine_max_memory_footprint_bytes")
    minute5 = int_value(memory.get("engine_memory_footprint_minute_5_bytes"), "runtime.measurements.memory.engine_memory_footprint_minute_5_bytes")
    minute15 = int_value(memory.get("engine_memory_footprint_minute_15_bytes"), "runtime.measurements.memory.engine_memory_footprint_minute_15_bytes")
    if max_rss != max(sample_rss_values):
        fail("maximum RSS does not reconcile with the embedded full-interval samples")
    if rss_by_offset.get(300) != minute5 or rss_by_offset.get(900) != minute15:
        fail("runtime samples must include and reconcile exact minute-5/minute-15 RSS")
    if max_rss > MAX_ENGINE_MEMORY_FOOTPRINT_BYTES:
        fail("engine RSS exceeds 450 MiB")
    if minute15 - minute5 > MAX_ENGINE_MEMORY_FOOTPRINT_GROWTH_BYTES:
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
    if configured:
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

        workload_probe = object_value(
            probe_evidence.get("workload"), "runtime recorder workload evidence"
        )
        causal_proof = object_value(
            workload_probe.get("alert_investigation"),
            "runtime recorder workload alert investigation",
        )
        validate_alert_investigation_proof(
            causal_proof, "runtime recorder workload alert investigation"
        )
        sample_by_offset = {
            int(round(number_value(sample.get("offset_seconds"), "runtime sample offset"))):
            object_value(sample, "runtime sample")
            for sample in samples
        }
        if causal_proof.get("telemetry_before") != object_value(
            sample_by_offset[BURST_START_OFFSET_SECONDS].get("llm_quality"),
            "minute-five LLM sample",
        ):
            fail("causal alert proof baseline is not the minute-five raw LLM sample")
        if causal_proof.get("telemetry_after") not in llm_rows:
            fail("causal alert proof completion is not a later raw LLM sample")
        trigger_at = parse_time(
            causal_proof.get("trigger_started_at"), "causal alert trigger_started_at"
        )
        workload_started = parse_time(
            workload_probe.get("started_at"), "workload evidence.started_at"
        )
        workload_completed = parse_time(
            workload_probe.get("completed_at"), "workload evidence.completed_at"
        )
        if abs((trigger_at - workload_started).total_seconds()) > 1.0:
            fail("causal alert boundary does not match workload start")
        if trigger_at < started + dt.timedelta(seconds=BURST_START_OFFSET_SECONDS - 1) \
                or trigger_at > started + dt.timedelta(seconds=BURST_START_OFFSET_SECONDS + 5):
            fail("causal alert trigger was not launched at the minute-five boundary")
        if workload_completed > started + dt.timedelta(
            seconds=BURST_END_OFFSET_SECONDS + 5
        ):
            fail("fixed workload completed after its declared deadline")
        if parse_time(causal_proof.get("observed_at"), "causal alert observed_at") \
                > started + dt.timedelta(seconds=BURST_DRAIN_OFFSET_SECONDS + 5):
            fail("causal alert investigation missed the fixed drain boundary")

        prewarm_probe = object_value(
            probe_evidence.get("llm_prewarm"), "runtime recorder LLM prewarm"
        )
        prewarm_proof = object_value(
            prewarm_probe.get("alert_investigation"),
            "runtime recorder LLM prewarm alert investigation",
        )
        validate_alert_investigation_proof(
            prewarm_proof, "runtime recorder LLM prewarm alert investigation"
        )
        if parse_time(prewarm_probe.get("completed_at"), "LLM prewarm completed_at") \
                >= started:
            fail("LLM prewarm did not complete before the qualification epoch")
        causal_alert = object_value(causal_proof.get("alert"), "causal alert")
        expected_ai = {
            "configured": configured,
            "feature_disabled_entire_epoch": not configured,
            "schema_2_and_accounting_conserved_all_samples": True,
            "unspecified_requests_epoch_delta": unspecified_delta,
            "alert_investigations_started_epoch_delta": started_delta,
            "alert_investigations_accepted_epoch_delta": accepted_delta,
            "alert_investigations_final_rejected_epoch_delta": rejected_delta,
            "causal_alert_id": causal_alert.get("id"),
            "causal_investigation_sha256": causal_proof.get("investigation_sha256"),
        }
        if ai != expected_ai:
            fail("AI-quality aggregate does not reconcile with raw samples")
    else:
        # rc.44: unconfigured LLM is a SUPPORTED shipping configuration
        # (features degrade gracefully — documented). Assert that contract via
        # the aggregate the recorder already computes, then let all non-LLM
        # validation below run unchanged. Full alert-investigation coverage is
        # verified separately on a host WITH an LLM configured.
        if not bool_value(
            ai.get("feature_disabled_entire_epoch"),
            "runtime.measurements.ai_quality.feature_disabled_entire_epoch",
        ):
            fail("unconfigured LLM did not report the feature disabled for the whole epoch")
        for row in llm_rows:
            if int_value(
                row.get("totals_requested_total") or 0,
                "sample.llm_quality.totals_requested_total", minimum=0,
            ) != 0:
                fail("unconfigured LLM performed requests (not degrading gracefully)")
        for key in (
            "unspecified_requests_epoch_delta",
            "alert_investigations_started_epoch_delta",
            "alert_investigations_accepted_epoch_delta",
            "alert_investigations_final_rejected_epoch_delta",
        ):
            if int_value(ai.get(key) or 0,
                         f"runtime.measurements.ai_quality.{key}", minimum=0) != 0:
                fail(f"unconfigured LLM shows {key} activity (not degrading gracefully)")
        expected_ai = {
            "configured": False,
            "feature_disabled_entire_epoch": True,
            "schema_2_and_accounting_conserved_all_samples": True,
            "unspecified_requests_epoch_delta": 0,
            "alert_investigations_started_epoch_delta": 0,
            "alert_investigations_accepted_epoch_delta": 0,
            "alert_investigations_final_rejected_epoch_delta": 0,
            "causal_alert_id": None,
            "causal_investigation_sha256": None,
        }
        if ai != expected_ai:
            fail("disabled AI-quality aggregate does not reconcile with raw samples")

    rules = object_value(metrics.get("rules"), "runtime.measurements.rules")
    for key in ("sealed_rules_synchronized_before_readers", "corpus_parity", "ordinary_launch_without_admin_prompt"):
        require_true(rules.get(key), f"runtime.measurements.rules.{key}")
    observed_rule_sync = object_value(
        rules.get("observed_sync"),
        "runtime.measurements.rules.observed_sync",
    )
    candidate_rule_corpus = rule_corpus_artifact_evidence(
        rules.get("candidate_corpus"),
        "runtime.measurements.rules.candidate_corpus",
    )
    manifest_rule_corpus = rule_corpus_artifact_evidence(
        candidate_verification.get("rule_corpus"),
        "candidate.artifact_verification.rule_corpus",
    )
    if candidate_rule_corpus != manifest_rule_corpus:
        fail("runtime rule evidence does not bind the candidate manifest corpus")
    if observed_rule_sync.get("installed_manifest_sha256") \
            != candidate_rule_corpus["manifest_sha256"] \
            or observed_rule_sync.get("installed_manifest_hash_entry_count") \
            != candidate_rule_corpus["manifest_hash_entry_count"] \
            or observed_rule_sync.get("version") \
            != candidate_rule_corpus["bundle_version"]:
        fail("installed rule corpus digest/count/version does not match candidate")
    sample_rule_sync = [
        object_value(
            object_value(sample, f"runtime.samples[{index}]").get("rule_sync"),
            f"runtime.samples[{index}].rule_sync",
        )
        for index, sample in enumerate(samples)
    ]
    if any(row != observed_rule_sync for row in sample_rule_sync):
        fail("rule synchronization aggregate does not match every sample")

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
    runtime_candidate_verification = object_value(
        report.get("candidate_artifact_verification"), "runtime.candidate_artifact_verification"
    )
    if payload_inventory_sha != require_sha(
        runtime_candidate_verification.get("payload_inventory_sha256"),
        "runtime.candidate_artifact_verification.payload_inventory_sha256",
    ):
        fail("runtime payload inventory binding is internally inconsistent")
    if payload_inventory_sha != payload_inventory_sha256:
        fail("runtime report does not bind the candidate manifest payload inventory")
    runtime_rule_corpus = rule_corpus_artifact_evidence(
        runtime_candidate_verification.get("rule_corpus"),
        "runtime.candidate_artifact_verification.rule_corpus",
    )
    expected_rule_corpus = rule_corpus_artifact_evidence(
        candidate_verification.get("rule_corpus"),
        "candidate.artifact_verification.rule_corpus",
    )
    if runtime_rule_corpus != expected_rule_corpus:
        fail("runtime report does not bind the candidate rule corpus")
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


def heartbeat_lane_counter_map(
    container: Mapping[str, Any], map_key: str, total_key: str, path: str
) -> Tuple[Dict[str, int], int]:
    """Read a fixed two-lane ledger and bind it to its published scalar."""
    result = heartbeat_counter_map(container, map_key, path)
    required_lanes = {"priority", "file"}
    if set(result) != required_lanes:
        fail(
            f"{path}.{map_key} must publish the exact lane inventory "
            f"{sorted(required_lanes)}"
        )
    total = heartbeat_counter(container, total_key, path)
    if sum(result.values()) != total:
        fail(f"{path}.{map_key} does not reconcile with {path}.{total_key}")
    return result, total


def event_type_count_window_sample(
    heartbeat: Mapping[str, Any], path: str = "heartbeat"
) -> Dict[str, Any]:
    """Normalize and verify the exact count-window evidence ledger."""
    window_path = f"{path}.event_type_count_window"
    window = object_value(
        heartbeat.get("event_type_count_window"), window_path
    )
    available = bool_value(
        window.get("query_available"), f"{window_path}.query_available"
    )
    if not available:
        fail(f"{window_path} is unavailable")
    result = {
        "query_available": available,
        "mutation_generation": int_value(
            window.get("mutation_generation"),
            f"{window_path}.mutation_generation",
        ),
        "requested_duration_seconds": int_value(
            window.get("requested_duration_seconds"),
            f"{window_path}.requested_duration_seconds",
            minimum=1,
        ),
        "effective_duration_seconds": int_value(
            window.get("effective_duration_seconds"),
            f"{window_path}.effective_duration_seconds",
        ),
        "requested_window_complete": bool_value(
            window.get("requested_window_complete"),
            f"{window_path}.requested_window_complete",
        ),
        "complete": bool_value(
            window.get("complete"), f"{window_path}.complete"
        ),
        "canonical_poison_records": heartbeat_counter(
            window, "canonical_poison_records", window_path
        ),
        "corrupt_legacy_records": heartbeat_counter(
            window, "corrupt_legacy_records", window_path
        ),
        "inherited_legacy_loss_records": heartbeat_counter(
            window, "inherited_legacy_loss_records", window_path
        ),
        "resource_limited_records": heartbeat_counter(
            window, "resource_limited_records", window_path
        ),
        "gap_records": heartbeat_counter(window, "gap_records", window_path),
    }
    reason_total = sum(
        result[key]
        for key in (
            "canonical_poison_records",
            "corrupt_legacy_records",
            "inherited_legacy_loss_records",
            "resource_limited_records",
        )
    )
    if result["gap_records"] != reason_total:
        fail(f"{window_path}.gap_records does not equal its reason ledger")
    expected_complete = (
        result["requested_window_complete"] and reason_total == 0
    )
    if result["complete"] is not expected_complete:
        fail(f"{window_path}.complete hides an incomplete window or evidence gap")
    if result["requested_window_complete"] \
            and result["effective_duration_seconds"] \
            != result["requested_duration_seconds"]:
        fail(f"{window_path} complete window has a different effective duration")
    return result


def event_search_projection_sample(
    heartbeat: Mapping[str, Any], path: str = "heartbeat"
) -> Dict[str, Any]:
    """Normalize the sparse-search coverage ledger without claiming exactness."""
    search_path = f"{path}.event_search_projection"
    search = object_value(
        heartbeat.get("event_search_projection"), search_path
    )
    available = bool_value(
        search.get("query_available"), f"{search_path}.query_available"
    )
    if not available:
        fail(f"{search_path} is unavailable")
    result = {
        "query_available": available,
        "mutation_generation": int_value(
            search.get("mutation_generation"),
            f"{search_path}.mutation_generation",
        ),
        "requested_duration_seconds": int_value(
            search.get("requested_duration_seconds"),
            f"{search_path}.requested_duration_seconds",
            minimum=1,
        ),
        "effective_duration_seconds": int_value(
            search.get("effective_duration_seconds"),
            f"{search_path}.effective_duration_seconds",
        ),
        "requested_window_complete": bool_value(
            search.get("requested_window_complete"),
            f"{search_path}.requested_window_complete",
        ),
        "projection_considered": heartbeat_counter(
            search, "projection_considered", search_path
        ),
        "projection_materialized": heartbeat_counter(
            search, "projection_materialized", search_path
        ),
        "projection_omitted_quota": heartbeat_counter(
            search, "projection_omitted_quota", search_path
        ),
        "projection_omitted_replaced": heartbeat_counter(
            search, "projection_omitted_replaced", search_path
        ),
        "projection_omitted_physical": heartbeat_counter(
            search, "projection_omitted_physical", search_path
        ),
        "projection_omitted_external": heartbeat_counter(
            search, "projection_omitted_external", search_path
        ),
        "projection_omitted_migration": heartbeat_counter(
            search, "projection_omitted_migration", search_path
        ),
        "projection_pending": heartbeat_counter(
            search, "projection_pending", search_path
        ),
        "projection_omitted_total": heartbeat_counter(
            search, "projection_omitted_total", search_path
        ),
        "canonical_poison_records": heartbeat_counter(
            search, "canonical_poison_records", search_path
        ),
        "corrupt_legacy_records": heartbeat_counter(
            search, "corrupt_legacy_records", search_path
        ),
        "inherited_legacy_loss_records": heartbeat_counter(
            search, "inherited_legacy_loss_records", search_path
        ),
        "resource_limited_records": heartbeat_counter(
            search, "resource_limited_records", search_path
        ),
        "gap_records_total": heartbeat_counter(
            search, "gap_records_total", search_path
        ),
        "complete": bool_value(
            search.get("complete"), f"{search_path}.complete"
        ),
    }
    omitted_total = sum(
        result[key]
        for key in (
            "projection_omitted_quota",
            "projection_omitted_replaced",
            "projection_omitted_physical",
            "projection_omitted_external",
            "projection_omitted_migration",
            "projection_pending",
        )
    )
    if result["projection_omitted_total"] != omitted_total:
        fail(f"{search_path}.projection_omitted_total does not reconcile")
    if result["projection_considered"] != (
        result["projection_materialized"] + omitted_total
    ):
        fail(f"{search_path} projection coverage does not conserve")
    gap_total = sum(
        result[key]
        for key in (
            "canonical_poison_records",
            "corrupt_legacy_records",
            "inherited_legacy_loss_records",
            "resource_limited_records",
        )
    )
    if result["gap_records_total"] != gap_total:
        fail(f"{search_path}.gap_records_total does not equal its reason ledger")
    expected_complete = (
        result["requested_window_complete"]
        and gap_total == 0
        and omitted_total == 0
        and result["projection_considered"]
        == result["projection_materialized"]
    )
    if result["complete"] is not expected_complete:
        fail(f"{search_path}.complete hides sparse or gapped coverage")
    return result


def rule_sync_sample(
    heartbeat: Mapping[str, Any], path: str = "heartbeat"
) -> Dict[str, Any]:
    sync_path = f"{path}.rule_sync"
    sync = object_value(heartbeat.get("rule_sync"), sync_path)
    status = string_value(sync.get("status"), f"{sync_path}.status")
    if status not in ("installed", "unchanged"):
        fail(f"{sync_path} did not verify and synchronize the sealed corpus")
    result = {
        "status": status,
        "version": string_value(sync.get("version"), f"{sync_path}.version"),
        "bundled_tampered": bool_value(
            sync.get("bundled_tampered"), f"{sync_path}.bundled_tampered"
        ),
        "installed_tampered": bool_value(
            sync.get("installed_tampered"), f"{sync_path}.installed_tampered"
        ),
        "installed_corpus_verified": bool_value(
            sync.get("installed_corpus_verified"),
            f"{sync_path}.installed_corpus_verified",
        ),
        "installed_manifest_sha256": require_sha(
            sync.get("installed_manifest_sha256"),
            f"{sync_path}.installed_manifest_sha256",
        ),
        "installed_manifest_hash_entry_count": int_value(
            sync.get("installed_manifest_hash_entry_count"),
            f"{sync_path}.installed_manifest_hash_entry_count",
            minimum=1,
        ),
    }
    if result["bundled_tampered"] or result["installed_tampered"] \
            or not result["installed_corpus_verified"]:
        fail(f"{sync_path} reports an unverified or tampered rule corpus")
    return result


def event_journal_recovery_sample(
    heartbeat: Mapping[str, Any], path: str = "heartbeat"
) -> Dict[str, Any]:
    recovery_path = f"{path}.event_journal_recovery"
    recovery = object_value(
        heartbeat.get("event_journal_recovery"), recovery_path
    )
    result = {
        "source_events": heartbeat_counter(
            recovery, "source_events", recovery_path
        ),
        "migrated_events": heartbeat_counter(
            recovery, "migrated_events", recovery_path
        ),
        "rolled_expired_events": heartbeat_counter(
            recovery, "rolled_expired_events", recovery_path
        ),
        "corrupt_preserved_events": heartbeat_counter(
            recovery, "corrupt_preserved_events", recovery_path
        ),
        "remaining_events": heartbeat_counter(
            recovery, "remaining_events", recovery_path
        ),
        "complete": bool_value(
            recovery.get("complete"), f"{recovery_path}.complete"
        ),
        "conserved": bool_value(
            recovery.get("conserved"), f"{recovery_path}.conserved"
        ),
    }
    accounted = sum(
        result[key]
        for key in (
            "migrated_events",
            "rolled_expired_events",
            "corrupt_preserved_events",
            "remaining_events",
        )
    )
    expected_conserved = result["source_events"] == accounted
    if result["conserved"] is not expected_conserved:
        fail(f"{recovery_path}.conserved does not match its event ledger")
    if not result["conserved"] or not result["complete"] \
            or result["remaining_events"] != 0:
        fail(f"{recovery_path} is not a complete conserving boundary")
    return result


def event_journal_index_sample(
    heartbeat: Mapping[str, Any], path: str = "heartbeat"
) -> Dict[str, Any]:
    """Normalize the journal-index refresh/rebuild counters (v1.22.0).

    Unlike every other heartbeat section in this file, absence here is not a
    schema violation: `event_journal_index` is new wiring that may not yet be
    present on a candidate's heartbeat. Callers must treat `present: False`
    as "not sampled" and skip with a NOTE -- never as a passing zero, which
    would silently hide the dashboard-starves-expiry recurrence gate.
    """
    index = heartbeat.get("event_journal_index")
    if not isinstance(index, dict):
        return {
            "present": False,
            "full_rebuilds_total": None,
            "append_refreshes_total": None,
        }
    index_path = f"{path}.event_journal_index"
    return {
        "present": True,
        "full_rebuilds_total": heartbeat_counter(
            index, "full_rebuilds_total", index_path
        ),
        "append_refreshes_total": heartbeat_counter(
            index, "append_refreshes_total", index_path
        ),
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
        "ingest_events_total",
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
        "physical_write_suppressed_events_total",
        "physical_write_suppressed_rows_total",
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
        + result["physical_write_suppressed_rows_total"]
        + result["pending_entity_rows"]
        + result["pending_edge_rows"]
    ):
        fail(f"{path} observation/coalescing ledger does not conserve")
    if result["physical_write_suppressed_events_total"] \
            > heartbeat_counter(graph, "ingest_events_total", path):
        fail(f"{path} physical-write suppressed events exceed ingested events")
    return result


def trace_graph_recovery_barrier_sample(
    graph: Mapping[str, Any], path: str
) -> Dict[str, Any]:
    """Read the exact bounded recovery-writer queue and prove its ledger."""
    result: Dict[str, Any] = {
        "accepting_mutations": bool_value(
            graph.get("accepting_mutations"), f"{path}.accepting_mutations"
        ),
        "recovering": bool_value(graph.get("recovering"), f"{path}.recovering"),
        "recovery_mutation_queue_saturated": bool_value(
            graph.get("recovery_mutation_queue_saturated"),
            f"{path}.recovery_mutation_queue_saturated",
        ),
    }
    counter_keys = (
        "recovery_mutation_waiters",
        "recovery_mutation_waiter_limit",
        "recovery_mutation_waiter_high_watermark",
        "recovery_mutation_waits_total",
        "recovery_mutation_wait_releases_total",
        "recovery_mutation_wait_cancellations_total",
        "recovery_mutation_wait_closed_total",
        "recovery_mutation_wait_saturations_total",
        "recovery_mutation_wait_nanoseconds_total",
        "recovery_mutation_max_wait_nanoseconds",
        "recovery_mutation_oldest_wait_nanoseconds",
        "recovery_writer_preemptions_total",
    )
    result.update({key: heartbeat_counter(graph, key, path) for key in counter_keys})
    waiters = result["recovery_mutation_waiters"]
    limit = result["recovery_mutation_waiter_limit"]
    high_watermark = result["recovery_mutation_waiter_high_watermark"]
    if limit < 1:
        fail(f"{path}.recovery_mutation_waiter_limit must be >= 1")
    if limit != TRACE_RECOVERY_MUTATION_WAITER_LIMIT:
        fail(
            f"{path}.recovery_mutation_waiter_limit must equal the fixed "
            f"production limit {TRACE_RECOVERY_MUTATION_WAITER_LIMIT}"
        )
    if waiters > limit:
        fail(f"{path} recovery mutation waiters exceed the fixed queue limit")
    if high_watermark < waiters or high_watermark > limit:
        fail(f"{path} recovery mutation waiter high-watermark is outside the queue bounds")
    if result["recovery_mutation_waits_total"] != (
        waiters
        + result["recovery_mutation_wait_releases_total"]
        + result["recovery_mutation_wait_cancellations_total"]
        + result["recovery_mutation_wait_closed_total"]
    ):
        fail(f"{path} recovery mutation waiter ledger does not conserve")
    expected_saturated = result["recovering"] and waiters >= limit
    if result["recovery_mutation_queue_saturated"] is not expected_saturated:
        fail(f"{path} recovery mutation queue saturation gauge is inconsistent")
    if result["recovery_mutation_queue_saturated"] \
            and result["accepting_mutations"]:
        fail(f"{path} saturated recovery queue cannot accept mutations")
    if waiters == 0 and result["recovery_mutation_oldest_wait_nanoseconds"] != 0:
        fail(f"{path} empty recovery queue reports a non-zero oldest wait")
    if result["recovery_mutation_max_wait_nanoseconds"] \
            > result["recovery_mutation_wait_nanoseconds_total"]:
        fail(f"{path} recovery maximum wait exceeds total completed wait time")
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


def alert_storage_admission_sample(
    heartbeat: Mapping[str, Any], path: str = "heartbeat"
) -> Dict[str, Any]:
    """Normalize the alert/evidence store's fail-closed admission ledger."""
    budget = object_value(
        heartbeat.get("alert_evidence_budget"), f"{path}.alert_evidence_budget"
    )
    result = {
        "family_footprint_bytes": heartbeat_counter(
            budget, "alerts_family_footprint_bytes",
            f"{path}.alert_evidence_budget",
        ),
        "family_admission_cap_bytes": int_value(
            budget.get("alerts_family_admission_cap_bytes"),
            f"{path}.alert_evidence_budget.alerts_family_admission_cap_bytes",
            minimum=1,
        ),
        "family_combined_cap_bytes": int_value(
            budget.get("alerts_family_combined_cap_bytes"),
            f"{path}.alert_evidence_budget.alerts_family_combined_cap_bytes",
            minimum=1,
        ),
        "family_transaction_reserve_bytes": int_value(
            budget.get("alerts_family_transaction_reserve_bytes"),
            f"{path}.alert_evidence_budget.alerts_family_transaction_reserve_bytes",
            minimum=1,
        ),
        "family_admission_boundary_bytes": int_value(
            budget.get("alerts_family_admission_boundary_bytes"),
            f"{path}.alert_evidence_budget.alerts_family_admission_boundary_bytes",
            minimum=1,
        ),
        "family_recovery_target_bytes": int_value(
            budget.get("alerts_family_recovery_target_bytes"),
            f"{path}.alert_evidence_budget.alerts_family_recovery_target_bytes",
            minimum=1,
        ),
        "family_blocked": bool_value(
            budget.get("alerts_family_blocked"),
            f"{path}.alert_evidence_budget.alerts_family_blocked",
        ),
        "family_reason": string_value(
            budget.get("alerts_family_reason"),
            f"{path}.alert_evidence_budget.alerts_family_reason",
            nonempty=False,
        ),
        "evidence_over_budget": bool_value(
            budget.get("over_budget"),
            f"{path}.alert_evidence_budget.over_budget",
        ),
        "capture_offered_total": heartbeat_counter(
            budget, "capture_offered_total", f"{path}.alert_evidence_budget"
        ),
        "capture_completed_total": heartbeat_counter(
            budget, "capture_completed_total", f"{path}.alert_evidence_budget"
        ),
        "capture_failures_total": heartbeat_counter(
            budget, "capture_failures_total", f"{path}.alert_evidence_budget"
        ),
        "capture_shed_total": heartbeat_counter(
            budget, "capture_shed_total", f"{path}.alert_evidence_budget"
        ),
        # v1.22.0: alert_insert_errors_total is a top-level heartbeat key
        # (sibling of event_insert_errors_total), not nested under
        # alert_evidence_budget -- absent on any heartbeat that predates the
        # DaemonTimers wiring, which is treated as zero rather than failed.
        "insert_errors_total": (
            heartbeat_counter(heartbeat, "alert_insert_errors_total", path)
            if "alert_insert_errors_total" in heartbeat
            else 0
        ),
        "capture_pending": heartbeat_counter(
            budget, "capture_pending", f"{path}.alert_evidence_budget"
        ),
        "capture_in_flight": heartbeat_counter(
            budget, "capture_in_flight", f"{path}.alert_evidence_budget"
        ),
        "capture_accepting": bool_value(
            budget.get("capture_accepting"),
            f"{path}.alert_evidence_budget.capture_accepting",
        ),
        "capture_conserved": bool_value(
            budget.get("capture_conserved"),
            f"{path}.alert_evidence_budget.capture_conserved",
        ),
        "legacy_transition_measurement_failed": bool_value(
            budget.get("legacy_transition_measurement_failed"),
            f"{path}.alert_evidence_budget.legacy_transition_measurement_failed",
        ),
    }
    if result["family_admission_cap_bytes"] > result["family_combined_cap_bytes"]:
        fail(f"{path}.alert_evidence_budget admission cap exceeds its family cap")
    if result["family_admission_boundary_bytes"] != (
        result["family_admission_cap_bytes"]
        - result["family_transaction_reserve_bytes"]
    ):
        fail(f"{path}.alert_evidence_budget admission boundary does not reconcile")
    if result["family_recovery_target_bytes"] != (
        result["family_admission_boundary_bytes"]
        - result["family_transaction_reserve_bytes"]
    ):
        fail(f"{path}.alert_evidence_budget recovery target does not reconcile")
    if result["family_footprint_bytes"] > result["family_admission_boundary_bytes"]:
        fail(f"{path}.alert_evidence_budget footprint exceeds alert admission boundary")
    if result["capture_offered_total"] != (
        result["capture_completed_total"]
        + result["capture_failures_total"]
        + result["capture_shed_total"]
        + result["capture_pending"]
        + result["capture_in_flight"]
    ):
        fail(f"{path}.alert_evidence_budget capture ledger does not conserve")
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

    def validate_counters(raw: Any, path: str) -> Dict[str, Any]:
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
        outcomes = object_value(counters.get("outcomes"), f"{path}.outcomes")
        outcome_values = {
            key: int_value(outcomes.get(key), f"{path}.outcomes.{key}")
            for key in (
                "success", "cacheHit", "backendFailure", "circuitRejection",
                "privacyRejection", "admissionShed", "cancellation",
                "responseOversize",
            )
        }
        current_in_flight = int_value(
            counters.get("currentInFlight"), f"{path}.currentInFlight"
        )
        current_admitted = int_value(
            counters.get("currentAdmittedBackendRequests"),
            f"{path}.currentAdmittedBackendRequests",
        )
        current_recovery = int_value(
            counters.get("currentCircuitRecoveryProbes"),
            f"{path}.currentCircuitRecoveryProbes",
        )
        if requested != current_in_flight + sum(outcome_values.values()):
            fail(f"{path} request outcome ledger does not conserve")
        return {
            "requested_total": requested,
            "current_in_flight": current_in_flight,
            "current_admitted_backend_requests": current_admitted,
            "current_circuit_recovery_probes": current_recovery,
            "outcomes": outcome_values,
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
    last_success_raw = llm.get("last_success_unix")
    last_success = None if last_success_raw is None else number_value(
        last_success_raw, "heartbeat.llm.last_success_unix", minimum=0
    )
    return {
        "configured": True,
        "healthy": bool_value(llm.get("healthy"), "heartbeat.llm.healthy"),
        "last_success_unix": last_success,
        "provider": string_value(llm.get("provider"), "heartbeat.llm.provider"),
        "model": string_value(llm.get("model"), "heartbeat.llm.model"),
        "consecutive_failures": int_value(
            llm.get("consecutive_failures"), "heartbeat.llm.consecutive_failures"
        ),
        "circuit_open": bool_value(
            llm.get("circuit_open"), "heartbeat.llm.circuit_open"
        ),
        "schema_version": 2,
        "accounting_conserved": True,
        "unspecified_requested_total": feature_rows["unspecified"]["requested_total"],
        "alert_investigation": alert,
        "reason_observed_attempts_total": observed_total,
        "reason_terminal_rejections_total": terminal_total,
        "totals_requested_total": totals["requested_total"],
        "totals_current_in_flight": totals["current_in_flight"],
        "totals_current_admitted_backend_requests": totals[
            "current_admitted_backend_requests"
        ],
        "totals_current_circuit_recovery_probes": totals[
            "current_circuit_recovery_probes"
        ],
        "totals_outcomes": totals["outcomes"],
    }


def normalized_runtime_sample(
    heartbeat: Mapping[str, Any],
    *,
    offset_seconds: int,
    recorded_at: str,
    captured_at: str,
    heartbeat_written_at_unix: float,
    engine_cpu_seconds_total: float,
    engine_disk_write_bytes_total: int,
    engine_memory_footprint_bytes: int,
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

    # v1.21.6-rc.34: LIVENESS, not merely conservation.
    #
    # Every boundary above is an accounting identity, and a completely stalled
    # pipeline satisfies all of them: an installed host conserved exactly at
    # offered=1099, completed=0, in_flight=1098 while persisting nothing at all.
    # `completed` also folds in `filtered`, so a build that filters everything
    # passes the drain gate with zero rows written. Ten candidates reached an
    # installed host without this check, and every one of them was accepted by
    # the identities right up until somebody read the row count by hand.
    #
    # A candidate that stored no events is not a candidate.
    total_persisted = sum(storage_persisted[lane] for lane in ("priority", "file"))
    total_offered = sum(storage_offered[lane] for lane in ("priority", "file"))
    if total_offered > 0 and total_persisted <= 0:
        fail(
            "recorder.event-persistence: the engine offered "
            f"{total_offered} event(s) and persisted {total_persisted}. "
            "Conservation can hold across a fully stalled pipeline; "
            "persistence cannot. The candidate is not ingesting."
        )

    # NOTE: shedding at this boundary is deliberately NOT re-checked here. The
    # epoch gate already rejects it — see the `explicitly_shed` first-vs-last
    # comparison that fails with "event persistence shed during the qualification
    # epoch", whose `explicitly_shed` input is exactly `storage_dropped[lane]`.
    # An absolute check here duplicates that protection and fires earlier in the
    # pipeline, which masks the more precise epoch diagnosis.
    #
    # What was genuinely missing was LIVENESS, not loss detection: every gate in
    # this file was an accounting identity, and identities hold across a totally
    # stalled pipeline.

    terminal_offered, terminal_offered_total = heartbeat_lane_counter_map(
        heartbeat,
        "event_terminal_revision_offered_by_lane",
        "event_terminal_revision_offered_total",
        "heartbeat",
    )
    terminal_unchanged, terminal_unchanged_total = heartbeat_lane_counter_map(
        heartbeat,
        "event_terminal_revision_unchanged_by_lane",
        "event_terminal_revision_unchanged_total",
        "heartbeat",
    )
    terminal_durable, terminal_durable_total = heartbeat_lane_counter_map(
        heartbeat,
        "event_terminal_revision_durable_by_lane",
        "event_terminal_revision_durable_total",
        "heartbeat",
    )
    terminal_dropped, terminal_dropped_total = heartbeat_lane_counter_map(
        heartbeat,
        "event_terminal_revision_dropped_by_lane",
        "event_terminal_revision_dropped_total",
        "heartbeat",
    )
    terminal_poisoned, terminal_poisoned_total = heartbeat_lane_counter_map(
        heartbeat,
        "event_terminal_revision_poisoned_by_lane",
        "event_terminal_revision_poisoned_total",
        "heartbeat",
    )
    terminal_buffer, terminal_buffer_total = heartbeat_lane_counter_map(
        heartbeat,
        "event_terminal_revision_buffer_depth_by_lane",
        "event_terminal_revision_buffer_depth",
        "heartbeat",
    )
    terminal_in_flight, terminal_in_flight_total = heartbeat_lane_counter_map(
        heartbeat,
        "event_terminal_revision_in_flight_depth_by_lane",
        "event_terminal_revision_in_flight_depth",
        "heartbeat",
    )
    terminal_conservation = bool_value(
        heartbeat.get("event_terminal_revision_conservation"),
        "heartbeat.event_terminal_revision_conservation",
    )
    computed_terminal_conservation = terminal_offered_total == (
        terminal_unchanged_total
        + terminal_durable_total
        + terminal_dropped_total
        + terminal_poisoned_total
        + terminal_buffer_total
        + terminal_in_flight_total
    )
    if terminal_conservation is not computed_terminal_conservation:
        fail(
            "heartbeat.event_terminal_revision_conservation does not match "
            "the published terminal counters"
        )
    terminal_evidence_poisoned = bool_value(
        heartbeat.get("event_terminal_revision_evidence_poisoned"),
        "heartbeat.event_terminal_revision_evidence_poisoned",
    )
    computed_terminal_evidence_poisoned = (
        terminal_dropped_total > 0
        or terminal_poisoned_total > 0
        or not computed_terminal_conservation
    )
    if terminal_evidence_poisoned is not computed_terminal_evidence_poisoned:
        fail(
            "heartbeat.event_terminal_revision_evidence_poisoned does not "
            "match the published terminal counters"
        )
    terminal_repair_payload_expired_total = heartbeat_counter(
        heartbeat, "event_journal_repair_payload_expired_total", "heartbeat"
    )
    for lane in ("priority", "file"):
        boundaries[f"{lane}-event-terminal-persistence"] = recorder_boundary(
            offered=terminal_offered[lane],
            completed=terminal_unchanged[lane] + terminal_durable[lane],
            queued=terminal_buffer[lane],
            in_flight=terminal_in_flight[lane],
            explicitly_shed=(
                terminal_dropped[lane] + terminal_poisoned[lane]
            ),
            path=f"recorder.{lane}-event-terminal-persistence",
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
    pending_steps_current = heartbeat_counter(
        heartbeat, "sequence_pending_steps_current", "heartbeat"
    )
    if boundaries["sequence-journal"]["queued"] != pending_steps_current:
        fail(
            "heartbeat.sequence_journal_conservation.queued does not match "
            "heartbeat.sequence_pending_steps_current"
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
    graph_recovery_barrier = trace_graph_recovery_barrier_sample(
        graph, "heartbeat.tracegraph_storage_admission"
    )
    trace_store_admission = trace_store_admission_sample(
        trace_store, "heartbeat.traces_storage_admission"
    )
    alert_storage_admission = alert_storage_admission_sample(heartbeat)
    event_type_count_window = event_type_count_window_sample(heartbeat)
    event_search_projection = event_search_projection_sample(heartbeat)
    rule_sync = rule_sync_sample(heartbeat)
    event_journal_recovery = event_journal_recovery_sample(heartbeat)
    event_journal_index = event_journal_index_sample(heartbeat)

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
        "captured_at": captured_at,
        "heartbeat_written_at_unix": heartbeat_written_at_unix,
        "engine_pid": pid,
        "engine_cpu_seconds_total": engine_cpu_seconds_total,
        "engine_disk_write_bytes_total": engine_disk_write_bytes_total,
        "engine_memory_footprint_bytes": engine_memory_footprint_bytes,
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
        "event_terminal_revision_conservation": terminal_conservation,
        "event_terminal_revision_evidence_poisoned":
            terminal_evidence_poisoned,
        "event_journal_repair_payload_expired_total":
            terminal_repair_payload_expired_total,
        "conservation": boundaries,
        "trace_graph_write_accounting": graph_write_accounting,
        "trace_graph_recovery_barrier": graph_recovery_barrier,
        "trace_store_admission": trace_store_admission,
        "alert_storage_admission": alert_storage_admission,
        "event_type_count_window": event_type_count_window,
        "event_search_projection": event_search_projection,
        "rule_sync": rule_sync,
        "event_journal_recovery": event_journal_recovery,
        "event_journal_index": event_journal_index,
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
        captured_at=string_value(
            observation.get("captured_at"), f"{path}.captured_at"
        ),
        heartbeat_written_at_unix=written_at,
        engine_cpu_seconds_total=number_value(
            process.get("engine_cpu_seconds_total"),
            f"{path}.process.engine_cpu_seconds_total",
            minimum=0,
        ),
        engine_disk_write_bytes_total=int_value(
            process.get("engine_disk_write_bytes_total"),
            f"{path}.process.engine_disk_write_bytes_total",
        ),
        engine_memory_footprint_bytes=int_value(
            process.get("engine_memory_footprint_bytes"), f"{path}.process.engine_memory_footprint_bytes"
        ),
        gui_background_cpu_percent=number_value(
            observation.get("gui_background_cpu_percent"),
            f"{path}.gui_background_cpu_percent",
            minimum=0,
        ),
    )


def runtime_readiness_failures(
    raw: Any, path: str, *, expected_pid: int | None = None,
    require_llm_ready: bool = True,
) -> Tuple[List[str], List[str]]:
    """Return permanent faults and transient drain work for one observation.

    Permanent faults make a zero-loss epoch impossible without repairing the
    candidate or gracefully starting a new process epoch. Drain work is
    allowed while a known prewarm/workload operation is completing, but must
    be empty immediately before t0 and at the fixed post-burst boundary.
    """
    observation = object_value(raw, path)
    sample = sample_from_recorder_observation(observation, path)
    fatal: List[str] = []
    pending: List[str] = []

    heartbeat = object_value(
        observation.get("heartbeat"), f"{path}.heartbeat"
    )
    deferred_buffer = object_value(
        heartbeat.get("deferred_enrichment_buffer"),
        f"{path}.heartbeat.deferred_enrichment_buffer",
    )
    rejected_patches = int_value(
        deferred_buffer.get("identity_rejected_patches_total"),
        f"{path}.heartbeat.deferred_enrichment_buffer."
        "identity_rejected_patches_total",
    )
    if rejected_patches:
        fatal.append(
            "cumulative deferred-enrichment identity-rejected patches="
            f"{rejected_patches}"
        )
    for key in (
        "reservation_conserved", "slots_conserved", "events_conserved",
        "raw_event_bytes_conserved", "patches_conserved",
        "patch_bytes_conserved", "within_capacity",
    ):
        if deferred_buffer.get(key) is not True:
            fatal.append(f"deferred-enrichment {key} is not holding")

    pid = int_value(sample.get("engine_pid"), f"{path}.engine_pid", minimum=1)
    if expected_pid is not None and pid != expected_pid:
        fatal.append(f"engine PID changed from {expected_pid} to {pid}")

    losses = object_value(sample.get("losses"), f"{path}.losses")
    for key, value in losses.items():
        if int_value(value, f"{path}.losses.{key}") != 0:
            fatal.append(f"cumulative loss {key}={value}")

    boundaries = object_value(sample.get("conservation"), f"{path}.conservation")
    for name in sorted(REQUIRED_CONSERVATION_BOUNDARIES):
        row = object_value(boundaries.get(name), f"{path}.conservation.{name}")
        shed = int_value(
            row.get("explicitly_shed"),
            f"{path}.conservation.{name}.explicitly_shed",
        )
        if shed != 0:
            fatal.append(f"cumulative {name} explicitly_shed={shed}")
        queued = int_value(row.get("queued"), f"{path}.conservation.{name}.queued")
        in_flight = int_value(
            row.get("in_flight"), f"{path}.conservation.{name}.in_flight"
        )
        # The sequence journal's `queued` gauge is the durable working set of
        # out-of-order later steps waiting for an earlier step. Those entries
        # can legitimately span the entire qualification epoch and are not an
        # asynchronous writer backlog. Its producer is actor-synchronous and
        # publishes `in_flight=0`; conservation, shed/eviction, continuity and
        # the exact queued/current cross-check above gate its health.
        if in_flight or (queued and name != "sequence-journal"):
            pending.append(f"{name} queued={queued} in_flight={in_flight}")

    if sample.get("event_terminal_revision_conservation") is not True:
        fatal.append("event terminal revision conservation is not holding")
    if sample.get("event_terminal_revision_evidence_poisoned") is not False:
        fatal.append("event terminal revision evidence is poisoned")
    repair_payload_expired = int_value(
        sample.get("event_journal_repair_payload_expired_total"),
        f"{path}.event_journal_repair_payload_expired_total",
    )
    if repair_payload_expired:
        fatal.append(
            "cumulative event journal repair payload expirations="
            f"{repair_payload_expired}"
        )

    count_window = object_value(
        sample.get("event_type_count_window"),
        f"{path}.event_type_count_window",
    )
    count_window_gaps = int_value(
        count_window.get("gap_records"),
        f"{path}.event_type_count_window.gap_records",
    )
    if count_window_gaps:
        fatal.append(
            f"exact event-type count window evidence gaps={count_window_gaps}"
        )
    search_projection = object_value(
        sample.get("event_search_projection"),
        f"{path}.event_search_projection",
    )
    search_gaps = int_value(
        search_projection.get("gap_records_total"),
        f"{path}.event_search_projection.gap_records_total",
    )
    if search_gaps:
        fatal.append(f"event search exact-evidence gaps={search_gaps}")

    sequence_evictions = int_value(
        sample.get("sequence_pending_steps_evicted_total"),
        f"{path}.sequence_pending_steps_evicted_total",
    )
    if sequence_evictions:
        fatal.append(
            "cumulative sequence pending-step evictions="
            f"{sequence_evictions}"
        )
    if sample.get("sequence_state_continuity_maintained") is not True \
            or sample.get("sequence_state_continuity_detail") != "nominal":
        fatal.append("sequence state continuity is not nominal")

    graph = object_value(
        sample.get("trace_graph_write_accounting"),
        f"{path}.trace_graph_write_accounting",
    )
    for key in ("write_batches_failed_total", "write_rows_failed_total"):
        value = int_value(graph.get(key), f"{path}.trace_graph_write_accounting.{key}")
        if value:
            fatal.append(f"cumulative TraceGraph {key}={value}")
    for key in (
        "write_batches_in_flight", "write_rows_in_flight",
        "pending_entity_rows", "pending_edge_rows",
    ):
        value = int_value(graph.get(key), f"{path}.trace_graph_write_accounting.{key}")
        if value:
            pending.append(f"TraceGraph {key}={value}")

    barrier = object_value(
        sample.get("trace_graph_recovery_barrier"),
        f"{path}.trace_graph_recovery_barrier",
    )
    if barrier.get("accepting_mutations") is not True:
        fatal.append("TraceGraph recovery barrier is not accepting mutations")
    if barrier.get("recovery_mutation_queue_saturated") is not False:
        fatal.append("TraceGraph recovery mutation queue is saturated")
    saturation_total = int_value(
        barrier.get("recovery_mutation_wait_saturations_total"),
        f"{path}.trace_graph_recovery_barrier.recovery_mutation_wait_saturations_total",
    )
    if saturation_total:
        fatal.append(
            "cumulative TraceGraph recovery mutation queue saturations="
            f"{saturation_total}"
        )
    max_wait = int_value(
        barrier.get("recovery_mutation_max_wait_nanoseconds"),
        f"{path}.trace_graph_recovery_barrier.recovery_mutation_max_wait_nanoseconds",
    )
    oldest_wait = int_value(
        barrier.get("recovery_mutation_oldest_wait_nanoseconds"),
        f"{path}.trace_graph_recovery_barrier.recovery_mutation_oldest_wait_nanoseconds",
    )
    if max_wait > MAX_TRACE_RECOVERY_MUTATION_WAIT_NANOSECONDS:
        fatal.append(f"TraceGraph recovery maximum mutation wait is {max_wait}ns")
    if oldest_wait > MAX_TRACE_RECOVERY_MUTATION_WAIT_NANOSECONDS:
        fatal.append(f"TraceGraph oldest live recovery mutation wait is {oldest_wait}ns")
    waiters = int_value(
        barrier.get("recovery_mutation_waiters"),
        f"{path}.trace_graph_recovery_barrier.recovery_mutation_waiters",
    )
    if waiters:
        pending.append(f"TraceGraph recovery mutation waiters={waiters}")

    if observation.get("trace_writable") is not True:
        fatal.append("TraceGraph is not writable")
    # Recovery is orthogonal to hard storage admission. A recovering graph is
    # healthy while its bounded barrier remains accepting, unsaturated and
    # conserving; the queue gauges above determine whether a drain must wait.
    graph_shed = int_value(
        observation.get("trace_shed_mutations_total"),
        f"{path}.trace_shed_mutations_total",
    )
    if graph_shed:
        fatal.append(f"cumulative TraceGraph shed_mutations_total={graph_shed}")
    if observation.get("event_budget_fault") is not False:
        fatal.append("event retention budget is degraded or sticky")

    trace_store = object_value(
        sample.get("trace_store_admission"), f"{path}.trace_store_admission"
    )
    if trace_store.get("enabled") is not True \
            or trace_store.get("store_available") is not True \
            or trace_store.get("blocked") is not False \
            or trace_store.get("recovering") is not False:
        fatal.append("TraceStore is not an enabled full writer")

    alerts = object_value(
        sample.get("alert_storage_admission"),
        f"{path}.alert_storage_admission",
    )
    if alerts.get("family_blocked") is not False:
        fatal.append(
            "alert family is admission-blocked: "
            + str(alerts.get("family_reason", "unknown"))
        )
    if alerts.get("evidence_over_budget") is not False:
        fatal.append("alert evidence budget is over its cap")
    if alerts.get("capture_accepting") is not True:
        fatal.append("alert evidence capture is not accepting")
    if alerts.get("capture_conserved") is not True:
        fatal.append("alert evidence capture ledger is not conserving")
    if alerts.get("legacy_transition_measurement_failed") is not False:
        fatal.append("alert legacy-transition measurement failed")
    for key in ("capture_failures_total", "capture_shed_total"):
        value = int_value(alerts.get(key), f"{path}.alert_storage_admission.{key}")
        if value:
            fatal.append(f"cumulative alert evidence {key}={value}")
    alert_insert_errors = int_value(
        alerts.get("insert_errors_total"),
        f"{path}.alert_storage_admission.insert_errors_total",
    )
    if alert_insert_errors:
        fatal.append(f"cumulative alert insert errors={alert_insert_errors}")
    for key in ("capture_pending", "capture_in_flight"):
        value = int_value(alerts.get(key), f"{path}.alert_storage_admission.{key}")
        if value:
            pending.append(f"alert evidence {key}={value}")

    llm = object_value(sample.get("llm_quality"), f"{path}.llm_quality")
    if llm.get("configured") is not True:
        # rc.44: an unconfigured LLM is a SUPPORTED shipping configuration.
        # MacCrab documents that LLM features degrade gracefully with no backend,
        # so mandating one in the release gate tested something stricter than the
        # product promises (and coupled qualification to a 4.7 GB external
        # model). Assert the actual contract instead — the engine performs NO
        # LLM work when unconfigured — which also adds runtime coverage of the
        # graceful-degradation guarantee that no test previously exercised.
        # A host WITH an LLM configured still gets the full strict checks below.
        requested = int_value(
            llm.get("totals_requested_total") or 0,
            f"{path}.llm_quality.totals_requested_total", minimum=0,
        )
        if requested != 0:
            fatal.append(
                "unconfigured LLM shows request activity (not degrading gracefully)"
            )
    else:
        if llm.get("schema_version") != 2 \
                or llm.get("accounting_conserved") is not True:
            fatal.append("LLM is non-schema-2 or non-conserving")
        if require_llm_ready and llm.get("healthy") is not True:
            fatal.append("LLM is not healthy after alert-specific prewarm")
        elif not require_llm_ready and llm.get("healthy") is not True \
                and (
                    llm.get("last_success_unix") is not None
                    or int_value(
                        llm.get("totals_requested_total"),
                        f"{path}.llm_quality.totals_requested_total",
                    ) != 0
                ):
            # `healthy` means "has succeeded at least once", so a first-ever
            # investigation is unhealthy-but-used for as long as it runs -- on
            # the reference host a local 7B model takes 15-30s. The prewarm
            # phase exists precisely to drive that first investigation, so
            # reading this state as a fault made the prewarm trip a check on
            # its own action, and it only passed when some earlier alert had
            # already made the backend healthy. Judge it by evidence of
            # FAILURE, not by the absence of a success that is still pending.
            alert_flight = object_value(
                llm.get("alert_investigation"),
                f"{path}.llm_quality.alert_investigation",
            )
            in_flight = int_value(
                alert_flight.get("current_operations"),
                f"{path}.llm_quality.alert_investigation.current_operations",
                minimum=0,
            )
            failures = int_value(
                llm.get("consecutive_failures"),
                f"{path}.llm_quality.consecutive_failures", minimum=0,
            )
            circuit_open = bool_value(
                llm.get("circuit_open"), f"{path}.llm_quality.circuit_open"
            )
            if failures or circuit_open or in_flight == 0:
                fatal.append(
                    "unhealthy LLM is not the expected never-used/no-success "
                    "state and is not a first investigation still in flight "
                    f"(failures={failures} circuit_open={circuit_open} "
                    f"in_flight={in_flight})"
                )
        if int_value(
            llm.get("consecutive_failures"),
            f"{path}.llm_quality.consecutive_failures",
        ) != 0:
            fatal.append("LLM has a non-zero consecutive failure streak")
        if llm.get("circuit_open") is not False:
            fatal.append("LLM circuit is open")
        if int_value(
            llm.get("unspecified_requested_total"),
            f"{path}.llm_quality.unspecified_requested_total",
        ) != 0:
            fatal.append("LLM has cumulative unattributed requests")
        alert = object_value(
            llm.get("alert_investigation"),
            f"{path}.llm_quality.alert_investigation",
        )
        if int_value(
            alert.get("final_rejection_total"),
            f"{path}.llm_quality.alert_investigation.final_rejection_total",
        ) != 0:
            fatal.append("LLM has cumulative final-rejected alert investigations")
        outcomes = object_value(
            llm.get("totals_outcomes"), f"{path}.llm_quality.totals_outcomes"
        )
        for key in (
            "backendFailure", "circuitRejection", "privacyRejection",
            "admissionShed", "cancellation", "responseOversize",
        ):
            value = int_value(outcomes.get(key), f"{path}.llm_quality.outcomes.{key}")
            if value:
                fatal.append(f"cumulative LLM outcome {key}={value}")
        for key in (
            "totals_current_in_flight",
            "totals_current_admitted_backend_requests",
            "totals_current_circuit_recovery_probes",
        ):
            value = int_value(llm.get(key), f"{path}.llm_quality.{key}")
            if value:
                pending.append(f"LLM {key}={value}")
        current_alerts = int_value(
            alert.get("current_operations"),
            f"{path}.llm_quality.alert_investigation.current_operations",
        )
        if current_alerts:
            pending.append(f"LLM alert current_operations={current_alerts}")

    sqlite_rows = object_value(
        observation.get("sqlite_families"), f"{path}.sqlite_families"
    )
    if not REQUIRED_SQLITE_FAMILIES.issubset(sqlite_rows):
        fatal.append("SQLite inventory omits a required shipping family")
    for name, raw_row in sorted(sqlite_rows.items()):
        row = object_value(raw_row, f"{path}.sqlite_families.{name}")
        footprint = int_value(
            row.get("footprint_bytes"), f"{path}.sqlite_families.{name}.footprint"
        )
        cap = int_value(
            row.get("configured_cap_bytes"),
            f"{path}.sqlite_families.{name}.cap",
            minimum=1,
        )
        free = int_value(
            row.get("free_space_bytes"), f"{path}.sqlite_families.{name}.free"
        )
        floor = int_value(
            row.get("configured_free_space_floor_bytes"),
            f"{path}.sqlite_families.{name}.floor",
        )
        if footprint > cap:
            fatal.append(f"SQLite family {name} footprint exceeds configured cap")
        if free < floor:
            fatal.append(f"SQLite family {name} is below its free-space floor")
    return fatal, pending


def validate_runtime_readiness(
    raw: Any, path: str, *, phase: str, require_drained: bool,
    expected_pid: int | None = None, require_llm_ready: bool = True,
) -> Dict[str, Any]:
    fatal, pending = runtime_readiness_failures(
        raw, path, expected_pid=expected_pid,
        require_llm_ready=require_llm_ready,
    )
    if fatal:
        fail(f"{phase} runtime readiness failed: " + "; ".join(fatal))
    if require_drained and pending:
        fail(f"{phase} runtime queues are not drained: " + "; ".join(pending))
    return sample_from_recorder_observation(raw, path)


def derive_workload_ingress(samples: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    """Derive the minute-five load proof only from cumulative raw samples."""
    by_offset: Dict[int, Mapping[str, Any]] = {}
    for sample in samples:
        offset = number_value(sample.get("offset_seconds"), "workload sample offset")
        rounded = int(round(offset))
        if abs(offset - rounded) <= 0.001:
            by_offset[rounded] = sample
    for required in (
        BURST_START_OFFSET_SECONDS, BURST_END_OFFSET_SECONDS,
        BURST_DRAIN_OFFSET_SECONDS,
    ):
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
    drain_end = by_offset[BURST_DRAIN_OFFSET_SECONDS]

    graph_start = trace_graph_write_accounting_sample(
        object_value(
            start.get("trace_graph_write_accounting"),
            "workload start.trace_graph_write_accounting",
        ),
        "workload start.trace_graph_write_accounting",
    )
    graph_drain = trace_graph_write_accounting_sample(
        object_value(
            drain_end.get("trace_graph_write_accounting"),
            "workload drain.trace_graph_write_accounting",
        ),
        "workload drain.trace_graph_write_accounting",
    )

    def delta(boundary: str, key: str) -> int:
        return counter(drain_end, boundary, key) - counter(start, boundary, key)

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
        scheduled_elapsed = current_offset - prior_offset
        if scheduled_elapsed <= 0:
            fail("workload samples are not strictly ordered")
        captured_elapsed = (
            parse_time(current.get("captured_at"), "workload current captured_at")
            - parse_time(prior.get("captured_at"), "workload prior captured_at")
        ).total_seconds()
        if captured_elapsed <= 0:
            fail("workload capture timestamps are not strictly ordered")
        heartbeat_elapsed = number_value(
            current.get("heartbeat_written_at_unix"),
            "workload current heartbeat_written_at_unix",
        ) - number_value(
            prior.get("heartbeat_written_at_unix"),
            "workload prior heartbeat_written_at_unix",
        )
        if heartbeat_elapsed <= 0:
            fail("workload heartbeat timestamps are not strictly ordered")
        if abs(heartbeat_elapsed - captured_elapsed) \
                > MAX_HEARTBEAT_CAPTURE_INTERVAL_DRIFT_SECONDS:
            fail("workload heartbeat and capture intervals do not reconcile")
        offered_delta = sum(
            counter(current, f"{lane}-ingress", "offered")
            - counter(prior, f"{lane}-ingress", "offered")
            for lane in ("priority", "file")
        )
        # These counters belong to heartbeat snapshots, while the Darwin
        # recorder owns captured_at.  The longer reconciled clock is
        # conservative for the minimum-load gate and cannot overstate rate.
        interval_rates.append(
            offered_delta / max(captured_elapsed, heartbeat_elapsed)
        )
    if not interval_rates:
        fail("runtime workload window has no measured sample interval")

    result = {
        "start_offset_seconds": BURST_START_OFFSET_SECONDS,
        "end_offset_seconds": BURST_END_OFFSET_SECONDS,
        "drain_offset_seconds": BURST_DRAIN_OFFSET_SECONDS,
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
        "priority_terminal_persistence_offered_delta": delta(
            "priority-event-terminal-persistence", "offered"
        ),
        "priority_terminal_persistence_completed_delta": delta(
            "priority-event-terminal-persistence", "completed"
        ),
        "priority_terminal_persistence_explicitly_shed_delta": delta(
            "priority-event-terminal-persistence", "explicitly_shed"
        ),
        "file_terminal_persistence_offered_delta": delta(
            "file-event-terminal-persistence", "offered"
        ),
        "file_terminal_persistence_completed_delta": delta(
            "file-event-terminal-persistence", "completed"
        ),
        "file_terminal_persistence_explicitly_shed_delta": delta(
            "file-event-terminal-persistence", "explicitly_shed"
        ),
        "combined_peak_offered_per_second": max(interval_rates),
        "trace_store_offered_delta": delta("trace-store-ingest", "offered"),
        "trace_store_completed_delta": delta("trace-store-ingest", "completed"),
        "trace_store_explicitly_shed_delta": delta(
            "trace-store-ingest", "explicitly_shed"
        ),
        "sequence_journal_offered_delta": delta(
            "sequence-journal", "offered"
        ),
        "sequence_journal_completed_delta": delta(
            "sequence-journal", "completed"
        ),
        "sequence_journal_explicitly_shed_delta": delta(
            "sequence-journal", "explicitly_shed"
        ),
        "sequence_journal_in_flight_start": counter(
            start, "sequence-journal", "in_flight"
        ),
        "sequence_journal_in_flight_drain": counter(
            drain_end, "sequence-journal", "in_flight"
        ),
        "sequence_journal_queued_start": counter(
            start, "sequence-journal", "queued"
        ),
        "sequence_journal_queued_drain": counter(
            drain_end, "sequence-journal", "queued"
        ),
        "trace_graph_physical_write_suppressed_events_delta": (
            graph_drain["physical_write_suppressed_events_total"]
            - graph_start["physical_write_suppressed_events_total"]
        ),
        "trace_graph_physical_write_suppressed_rows_delta": (
            graph_drain["physical_write_suppressed_rows_total"]
            - graph_start["physical_write_suppressed_rows_total"]
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
        if result[f"{lane}_terminal_persistence_offered_delta"] <= 0 \
                or result[f"{lane}_terminal_persistence_completed_delta"] <= 0:
            fail(
                f"fixed workload produced no measured {lane}-lane terminal "
                "persistence/completion"
            )
        if result[f"{lane}_terminal_persistence_offered_delta"] \
                != result[f"{lane}_terminal_persistence_completed_delta"]:
            fail(
                f"{lane} terminal persistence did not drain by the workload "
                "window boundary"
            )
        if result[f"{lane}_terminal_persistence_explicitly_shed_delta"] != 0:
            fail(f"{lane} terminal persistence shed fixed-workload revisions")
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
    if result["sequence_journal_offered_delta"] < 1 \
            or result["sequence_journal_completed_delta"] < 1:
        fail("fixed sequence-continuity probe did not move the sequence journal")
    # The sequence journal is judged by flow, not by an aliased instant.  Its
    # `queued` gauge is the durable set of out-of-order partial sequence steps
    # -- steps parked waiting for an earlier step that may never be offered in
    # this window at all -- so it is ambient host state, not a writer backlog.
    # Requiring offered-delta == completed-delta is equivalent (through the
    # conservation identity, with in-flight and shed pinned at zero below) to
    # requiring that gauge to land back on its exact window-start value, which
    # is the same aliasing the readiness path already exempts by name.
    #
    # Nothing is conceded by dropping it: the pending set stays bounded because
    # the engine trims it only by evicting, and cumulative pending-step
    # evictions are separately gated at absolute zero over the whole capture --
    # a pending set that ever reached its design ceiling would already have
    # failed the run.  Loss is gated by the shed delta below and by the
    # absolute cumulative shed check, and ordering by
    # `sequence_state_continuity_maintained`.
    if result["sequence_journal_in_flight_start"] != 0 \
            or result["sequence_journal_in_flight_drain"] != 0:
        fail("sequence journal held in-flight work across a fixed boundary")
    if result["sequence_journal_explicitly_shed_delta"] != 0:
        fail("sequence-continuity probe shed journal work")
    suppressed_events = result[
        "trace_graph_physical_write_suppressed_events_delta"
    ]
    suppressed_rows = result[
        "trace_graph_physical_write_suppressed_rows_delta"
    ]
    if suppressed_events <= 0 or suppressed_rows <= 0:
        fail(
            "fixed workload produced no measured TraceGraph physical-write "
            "suppression"
        )
    if suppressed_events != suppressed_rows:
        fail(
            "fixed workload violated the one-row-per-event physical-write "
            "suppression contract"
        )
    # Every writer must be empty at the fixed drain boundary.  `sequence-journal`
    # is exempt from `queued` alone, for the reason readiness already exempts it
    # by name: that gauge is the durable set of out-of-order partial sequence
    # steps, each parked for an earlier step that may never be offered during
    # this window, so it is ambient host state rather than an unfinished write.
    # Requiring it to be exactly empty at t+drain requires no sequence rule
    # anywhere on the host to hold a partial match at that instant.  It is NOT
    # exempt from `in_flight`, which is the actor-synchronous producer contract
    # the exemption depends on and which is checked at both endpoints above.
    for boundary in sorted(REQUIRED_CONSERVATION_BOUNDARIES):
        for key in ("queued", "in_flight"):
            if boundary == "sequence-journal" and key == "queued":
                continue
            value = counter(drain_end, boundary, key)
            if value != 0:
                fail(
                    f"{boundary} {key}={value} at the fixed workload drain boundary"
                )
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
    event_type_count_windows = [
        object_value(
            sample.get("event_type_count_window"),
            f"sample[{index}].event_type_count_window",
        )
        for index, sample in enumerate(samples)
    ]
    count_window_generations = [
        int_value(
            row.get("mutation_generation"),
            f"sample[{index}].event_type_count_window.mutation_generation",
        )
        for index, row in enumerate(event_type_count_windows)
    ]
    if any(
        later < earlier
        for earlier, later in zip(
            count_window_generations, count_window_generations[1:]
        )
    ):
        fail("event-type count mutation generation regressed during the epoch")
    event_search_projections = [
        object_value(
            sample.get("event_search_projection"),
            f"sample[{index}].event_search_projection",
        )
        for index, sample in enumerate(samples)
    ]
    search_generations = [
        int_value(
            row.get("mutation_generation"),
            f"sample[{index}].event_search_projection.mutation_generation",
        )
        for index, row in enumerate(event_search_projections)
    ]
    if any(
        later < earlier
        for earlier, later in zip(search_generations, search_generations[1:])
    ):
        fail("event-search mutation generation regressed during the epoch")
    workload_ingress = derive_workload_ingress(samples)
    duration = number_value(samples[-1].get("offset_seconds"), "last sample offset", minimum=MIN_EPOCH_SECONDS)
    captured_times = [
        parse_time(sample.get("captured_at"), f"sample {index}.captured_at")
        for index, sample in enumerate(samples)
    ]
    captured_gaps = [
        (current - prior).total_seconds()
        for prior, current in zip(captured_times, captured_times[1:])
    ]
    if any(gap <= 0 for gap in captured_gaps):
        fail("runtime captured sample timestamps must be strictly increasing")
    if any(gap > MAX_SAMPLE_GAP_SECONDS for gap in captured_gaps):
        fail(
            "runtime captured sample gap exceeds "
            f"{MAX_SAMPLE_GAP_SECONDS} seconds"
        )
    heartbeat_times = [
        number_value(
            sample.get("heartbeat_written_at_unix"),
            f"sample {index}.heartbeat_written_at_unix",
        )
        for index, sample in enumerate(samples)
    ]
    heartbeat_gaps = [
        current - prior
        for prior, current in zip(heartbeat_times, heartbeat_times[1:])
    ]
    if any(gap <= 0 for gap in heartbeat_gaps):
        fail("runtime heartbeat timestamps must be strictly increasing")
    if any(
        abs(heartbeat_gap - capture_gap)
        > MAX_HEARTBEAT_CAPTURE_INTERVAL_DRIFT_SECONDS
        for heartbeat_gap, capture_gap in zip(heartbeat_gaps, captured_gaps)
    ):
        fail(
            "runtime heartbeat and capture intervals diverge by more than "
            f"{MAX_HEARTBEAT_CAPTURE_INTERVAL_DRIFT_SECONDS} seconds"
        )
    captured_duration = (captured_times[-1] - captured_times[0]).total_seconds()
    if captured_duration + 0.001 < MIN_EPOCH_SECONDS:
        fail("runtime captured sample duration is below 900 seconds")
    samples_sha = sha256_bytes(canonical_json_bytes(samples))
    candidate = copy.deepcopy(object_value(candidate_manifest.get("candidate"), "candidate"))
    verification = object_value(candidate_manifest.get("artifact_verification"), "artifact_verification")
    inventory = object_value(verification.get("payload_inventory"), "artifact_verification.payload_inventory")
    candidate_rule_corpus = rule_corpus_artifact_evidence(
        verification.get("rule_corpus"),
        "artifact_verification.rule_corpus",
    )
    rule_sync_rows = [
        object_value(
            sample.get("rule_sync"), f"sample[{index}].rule_sync"
        )
        for index, sample in enumerate(samples)
    ]
    if any(row != rule_sync_rows[0] for row in rule_sync_rows[1:]):
        fail("rule synchronization evidence changed during the epoch")
    observed_rule_sync = rule_sync_rows[0]
    if observed_rule_sync["installed_manifest_sha256"] \
            != candidate_rule_corpus["manifest_sha256"] \
            or observed_rule_sync["installed_manifest_hash_entry_count"] \
            != candidate_rule_corpus["manifest_hash_entry_count"] \
            or observed_rule_sync["version"] \
            != candidate_rule_corpus["bundle_version"]:
        fail("installed rule corpus does not match the sealed candidate corpus")
    journal_recovery_rows = [
        object_value(
            sample.get("event_journal_recovery"),
            f"sample[{index}].event_journal_recovery",
        )
        for index, sample in enumerate(samples)
    ]
    if any(row != journal_recovery_rows[0] for row in journal_recovery_rows[1:]):
        fail("event-journal recovery evidence changed during the epoch")
    observed_journal_recovery = journal_recovery_rows[0]
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
    for index, (prior, current) in enumerate(zip(samples, samples[1:])):
        write_windows.append({
            "start_offset_seconds": prior["offset_seconds"],
            "end_offset_seconds": current["offset_seconds"],
            "captured_elapsed_seconds": (
                captured_times[index + 1] - captured_times[index]
            ).total_seconds(),
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
    graph_barrier_rows = [
        trace_graph_recovery_barrier_sample(
            object_value(
                sample.get("trace_graph_recovery_barrier"),
                "sample.trace_graph_recovery_barrier",
            ),
            "sample.trace_graph_recovery_barrier",
        )
        for sample in samples
    ]
    graph_accepting_duty = sum(
        1 for row in graph_barrier_rows
        if row["accepting_mutations"] is True
    ) / len(graph_barrier_rows)
    graph_barrier_cumulative_keys = (
        "recovery_mutation_waiter_high_watermark",
        "recovery_mutation_waits_total",
        "recovery_mutation_wait_releases_total",
        "recovery_mutation_wait_cancellations_total",
        "recovery_mutation_wait_closed_total",
        "recovery_mutation_wait_saturations_total",
        "recovery_mutation_wait_nanoseconds_total",
        "recovery_mutation_max_wait_nanoseconds",
        "recovery_writer_preemptions_total",
    )
    for key in graph_barrier_cumulative_keys:
        values = [int_value(row.get(key), f"TraceGraph barrier {key}") for row in graph_barrier_rows]
        if any(later < earlier for earlier, later in zip(values, values[1:])):
            fail(f"TraceGraph barrier {key} counter reset during the qualification epoch")
    graph_waiter_limits = {
        int_value(row.get("recovery_mutation_waiter_limit"), "TraceGraph waiter limit")
        for row in graph_barrier_rows
    }
    if len(graph_waiter_limits) != 1:
        fail("TraceGraph recovery mutation waiter limit changed during the epoch")
    if graph_waiter_limits != {TRACE_RECOVERY_MUTATION_WAITER_LIMIT}:
        fail("TraceGraph recovery mutation waiter limit is not the fixed production bound")

    def graph_barrier_delta(key: str) -> int:
        return int_value(graph_barrier_rows[-1].get(key), f"last TraceGraph {key}") \
            - int_value(graph_barrier_rows[0].get(key), f"first TraceGraph {key}")

    graph_waits_delta = graph_barrier_delta("recovery_mutation_waits_total")
    graph_wait_releases_delta = graph_barrier_delta(
        "recovery_mutation_wait_releases_total"
    )
    graph_wait_cancellations_delta = graph_barrier_delta(
        "recovery_mutation_wait_cancellations_total"
    )
    graph_wait_closed_delta = graph_barrier_delta(
        "recovery_mutation_wait_closed_total"
    )
    graph_wait_saturations_delta = graph_barrier_delta(
        "recovery_mutation_wait_saturations_total"
    )
    graph_writer_preemptions_delta = graph_barrier_delta(
        "recovery_writer_preemptions_total"
    )
    graph_waiter_gauge_delta = (
        graph_barrier_rows[-1]["recovery_mutation_waiters"]
        - graph_barrier_rows[0]["recovery_mutation_waiters"]
    )
    if graph_waits_delta != (
        graph_waiter_gauge_delta
        + graph_wait_releases_delta
        + graph_wait_cancellations_delta
        + graph_wait_closed_delta
    ):
        fail("TraceGraph recovery mutation waiter epoch ledger does not conserve")
    graph_cumulative_keys = (
        "write_attempts_total", "write_batches_committed_total",
        "write_batches_failed_total", "write_rows_attempted_total",
        "write_rows_committed_total", "write_rows_failed_total",
        "entity_observations_total", "edge_observations_total",
        "physical_write_suppressed_events_total",
        "physical_write_suppressed_rows_total",
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
    graph_suppressed_events_delta = (
        int_value(
            graph_accounting_rows[-1].get("physical_write_suppressed_events_total"),
            "last graph physical-write suppressed events",
        )
        - int_value(
            graph_accounting_rows[0].get("physical_write_suppressed_events_total"),
            "first graph physical-write suppressed events",
        )
    )
    graph_suppressed_rows_delta = (
        int_value(
            graph_accounting_rows[-1].get("physical_write_suppressed_rows_total"),
            "last graph physical-write suppressed rows",
        )
        - int_value(
            graph_accounting_rows[0].get("physical_write_suppressed_rows_total"),
            "first graph physical-write suppressed rows",
        )
    )
    graph_failed_batches_delta = (
        int_value(graph_accounting_rows[-1].get("write_batches_failed_total"), "last graph failed batches")
        - int_value(graph_accounting_rows[0].get("write_batches_failed_total"), "first graph failed batches")
    )
    graph_failed_rows_delta = (
        int_value(graph_accounting_rows[-1].get("write_rows_failed_total"), "last graph failed rows")
        - int_value(graph_accounting_rows[0].get("write_rows_failed_total"), "first graph failed rows")
    )
    graph_failed_events_delta = (
        int_value(
            object_value(last_boundaries.get("trace-graph-mutation"), "last TraceGraph mutation").get("explicitly_shed"),
            "last TraceGraph failed events",
        )
        - int_value(
            object_value(
                object_value(samples[0].get("conservation"), "first sample conservation").get("trace-graph-mutation"),
                "first TraceGraph mutation",
            ).get("explicitly_shed"),
            "first TraceGraph failed events",
        )
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
    rss_values = [int_value(sample["engine_memory_footprint_bytes"], "RSS") for sample in samples]
    rss_at = {int(round(number_value(sample["offset_seconds"], "offset"))): int_value(sample["engine_memory_footprint_bytes"], "RSS") for sample in samples}
    llm_rows = [object_value(sample.get("llm_quality"), "sample.llm_quality") for sample in samples]
    llm_configured = [bool_value(row.get("configured"), "sample.llm_quality.configured") for row in llm_rows]
    if any(value != llm_configured[0] for value in llm_configured[1:]):
        fail("LLM configuration changed during the qualification epoch")
    # rc.44: qualify BOTH shipping configurations. With an LLM configured, the
    # full strict investigation checks apply. Without one — a supported,
    # documented configuration — assert graceful degradation (no LLM work across
    # the epoch) instead of failing. The "config changed during the epoch" check
    # above still applies to both. Full alert-investigation coverage is verified
    # separately on a host WITH an LLM.
    if llm_configured[0]:
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
        recorder_evidence = object_value(probes.get("evidence"), "probes.evidence")
        workload_evidence = object_value(
            recorder_evidence.get("workload"), "probes.evidence.workload"
        )
        causal_proof = object_value(
            workload_evidence.get("alert_investigation"),
            "probes.evidence.workload.alert_investigation",
        )
        validate_alert_investigation_proof(
            causal_proof, "probes.evidence.workload.alert_investigation"
        )
        causal_alert = object_value(causal_proof.get("alert"), "causal alert proof")
    else:
        for row in llm_rows:
            if int_value(
                row.get("totals_requested_total") or 0,
                "sample.llm_quality.totals_requested_total", minimum=0,
            ) != 0:
                fail(
                    "unconfigured LLM performed requests during qualification "
                    "(not degrading gracefully)"
                )
        # Graceful degradation is a shipping configuration, so it has to be able
        # to produce a report.  These four deltas are bound only by the
        # configured branch above; without them the recorder raised NameError
        # here and no host without a backend could ever be recorded.
        llm_unspecified_delta = 0
        llm_started_delta = 0
        llm_accepted_delta = 0
        llm_rejected_delta = 0
        causal_proof = {}
        causal_alert = {}

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
            "captured_duration_seconds": captured_duration,
            "uninterrupted": True,
            "sample_interval_seconds": samples[1]["offset_seconds"] - samples[0]["offset_seconds"],
            "max_sample_gap_seconds": max(current["offset_seconds"] - prior["offset_seconds"] for prior, current in zip(samples, samples[1:])),
            "max_captured_gap_seconds": max(captured_gaps),
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
                "source_bound_clean_ci_sha256": require_sha(
                    object_value(
                        object_value(probes.get("evidence"), "probes.evidence").get("preinstall_clean_ci"),
                        "probes.evidence.preinstall_clean_ci",
                    ).get("output_sha256"),
                    "probes.evidence.preinstall_clean_ci.output_sha256",
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
                "event_type_count_windows": copy.deepcopy(
                    event_type_count_windows
                ),
                "event_search_projections": copy.deepcopy(
                    event_search_projections
                ),
                "journal_recovery": copy.deepcopy(
                    observed_journal_recovery
                ),
                "search_tier_gaps_reconcile_exactly": all(
                    row["gap_records_total"]
                    == row["canonical_poison_records"]
                    + row["corrupt_legacy_records"]
                    + row["inherited_legacy_loss_records"]
                    + row["resource_limited_records"]
                    and row["projection_considered"]
                    == row["projection_materialized"]
                    + row["projection_omitted_total"]
                    for row in event_search_projections
                ),
                "search_tier_gaps_visible": all(
                    row["query_available"] is True
                    and row["complete"] is (
                        row["requested_window_complete"]
                        and row["gap_records_total"] == 0
                        and row["projection_omitted_total"] == 0
                    )
                    for row in event_search_projections
                ),
            },
            "trace_graph": {
                "writable_duty_fraction": trace_writable,
                "accepting_mutations_duty_fraction": graph_accepting_duty,
                "mutation_shed": trace_shed_delta,
                "recovery_oscillation_count": max(0, recovery_transitions - 1),
                "recovery_mutation_queue_saturated_samples": sum(
                    1 for row in graph_barrier_rows
                    if row["recovery_mutation_queue_saturated"] is True
                ),
                "recovery_mutation_waiter_limit": next(iter(graph_waiter_limits)),
                "recovery_mutation_waiter_high_watermark": max(
                    row["recovery_mutation_waiter_high_watermark"]
                    for row in graph_barrier_rows
                ),
                "recovery_mutation_waits_epoch_delta": graph_waits_delta,
                "recovery_mutation_wait_releases_epoch_delta":
                    graph_wait_releases_delta,
                "recovery_mutation_wait_cancellations_epoch_delta":
                    graph_wait_cancellations_delta,
                "recovery_mutation_wait_closed_epoch_delta": graph_wait_closed_delta,
                "recovery_mutation_wait_saturations_epoch_delta":
                    graph_wait_saturations_delta,
                "recovery_writer_preemptions_epoch_delta":
                    graph_writer_preemptions_delta,
                "recovery_mutation_max_wait_nanoseconds": max(
                    row["recovery_mutation_max_wait_nanoseconds"]
                    for row in graph_barrier_rows
                ),
                "recovery_mutation_max_oldest_wait_nanoseconds": max(
                    row["recovery_mutation_oldest_wait_nanoseconds"]
                    for row in graph_barrier_rows
                ),
                "final_recovery_mutation_waiters": graph_barrier_rows[-1][
                    "recovery_mutation_waiters"
                ],
                "final_recovery_mutation_oldest_wait_nanoseconds":
                    graph_barrier_rows[-1][
                        "recovery_mutation_oldest_wait_nanoseconds"
                    ],
                "write_accounting_reconciled_all_samples": True,
                "coalesced_noop_rows_epoch_delta": graph_coalesced_delta,
                "physical_write_suppressed_events_epoch_delta":
                    graph_suppressed_events_delta,
                "physical_write_suppressed_rows_epoch_delta":
                    graph_suppressed_rows_delta,
                "failed_batches_epoch_delta": graph_failed_batches_delta,
                "failed_rows_epoch_delta": graph_failed_rows_delta,
                "failed_events_epoch_delta": graph_failed_events_delta,
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
                "average_bytes_per_second": disk_bytes / captured_duration,
                "windows": write_windows,
                "macos_disk_writes_diagnostic_count": int_value(probes.get("macos_disk_writes_diagnostic_count"), "probes.macos_disk_writes_diagnostic_count"),
            },
            "cpu": {
                "engine_cpu_seconds": cpu_seconds,
                "engine_average_cores": cpu_seconds / captured_duration,
                "gui_background_percent_samples": gui_values,
                "gui_background_p95_percent": percentile_nearest_rank(gui_values, 0.95),
            },
            "memory": {
                "engine_max_memory_footprint_bytes": max(rss_values),
                "engine_memory_footprint_minute_5_bytes": rss_at.get(300, -1),
                "engine_memory_footprint_minute_15_bytes": rss_at.get(900, -1),
            },
            "disk_safety": {"inventory_complete": True, "sqlite_families": sqlite_rows},
            "ai_quality": {
                "configured": llm_configured[0],
                "feature_disabled_entire_epoch": not llm_configured[0],
                "schema_2_and_accounting_conserved_all_samples": True,
                "unspecified_requests_epoch_delta": llm_unspecified_delta,
                "alert_investigations_started_epoch_delta": llm_started_delta,
                "alert_investigations_accepted_epoch_delta": llm_accepted_delta,
                "alert_investigations_final_rejected_epoch_delta": llm_rejected_delta,
                "causal_alert_id": causal_alert.get("id"),
                "causal_investigation_sha256": causal_proof.get(
                    "investigation_sha256"
                ),
            },
            "rules": {
                "sealed_rules_synchronized_before_readers": (
                    observed_rule_sync["installed_corpus_verified"] is True
                ),
                "corpus_parity": (
                    observed_rule_sync["installed_manifest_sha256"]
                    == candidate_rule_corpus["manifest_sha256"]
                    and observed_rule_sync[
                        "installed_manifest_hash_entry_count"
                    ] == candidate_rule_corpus["manifest_hash_entry_count"]
                    and observed_rule_sync["version"]
                    == candidate_rule_corpus["bundle_version"]
                ),
                "ordinary_launch_without_admin_prompt": bool_value(
                    object_value(
                        probes.get("rules"), "probes.rules"
                    ).get("ordinary_launch_without_admin_prompt"),
                    "probes.rules.ordinary_launch_without_admin_prompt",
                ),
                "observed_sync": copy.deepcopy(observed_rule_sync),
                "candidate_corpus": copy.deepcopy(candidate_rule_corpus),
            },
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
        "candidate_artifact_verification": {
            "payload_inventory_sha256": inventory["sha256"],
            "rule_corpus": copy.deepcopy(candidate_rule_corpus),
        },
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
    usage = DarwinRUsageInfoV4()
    libproc.proc_pid_rusage.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
    libproc.proc_pid_rusage.restype = ctypes.c_int
    if libproc.proc_pid_rusage(pid, 4, ctypes.byref(usage)) != 0:
        fail(f"cannot read rusage for engine PID {pid}")

    if path.is_symlink() or not path.is_file():
        fail("installed engine executable is missing, non-regular, or redirected")
    return {
        "engine_cpu_seconds_total": (
            int(usage.ri_user_time) + int(usage.ri_system_time)
        ) / 1_000_000_000.0,
        "engine_memory_footprint_bytes": int(usage.ri_phys_footprint),
        "engine_disk_write_bytes_total": int(usage.ri_diskio_byteswritten),
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
        if name in REQUIRED_SQLITE_FAMILIES:
            fail(
                "--sqlite-cap cannot override a shipping store; its installed "
                "candidate policy must be measured without a recorder override"
            )
        result[name] = byte_count
    return result


def workload_paths(run_id: str) -> Tuple[str, str]:
    if not WORKLOAD_RUN_ID_RE.fullmatch(run_id):
        fail("runtime workload run id must be exactly 32 lowercase hex characters")
    return (
        f"/private/tmp/maccrab-runtime-alert.{run_id}/"
        "maccrab-qualification-alert",
        f"/Users/Shared/MacCrabQualificationRuntime-{run_id}",
    )


def stable_sequence_file_path_predicates(
    root: pathlib.Path,
) -> List[Dict[str, str]]:
    """Extract fixed TargetFilename literals from the source-bound stable set."""
    rows: List[Dict[str, str]] = []
    sequence_root = root / "Rules/sequences"
    for rule_path in sorted(sequence_root.glob("*.yml")):
        if rule_path.is_symlink() or not rule_path.is_file():
            fail(f"sequence rule is missing, non-regular, or redirected: {rule_path}")
        text = rule_path.read_text(encoding="utf-8")
        if not re.search(r"(?m)^status:\s*stable\s*$", text):
            continue
        lines = text.splitlines()
        index = 0
        while index < len(lines):
            line = lines[index]
            match = re.match(
                r"^(\s*)TargetFilename\|(startswith|contains|endswith):"
                r"\s*(.*?)\s*$",
                line,
            )
            if not match:
                index += 1
                continue
            indent, operation, scalar = match.groups()
            literals: List[str] = []
            if scalar:
                literals.append(scalar)
            else:
                cursor = index + 1
                while cursor < len(lines):
                    following = lines[cursor]
                    if not following.strip():
                        cursor += 1
                        continue
                    following_indent = len(following) - len(following.lstrip())
                    if following_indent <= len(indent):
                        break
                    item = re.match(r"^\s*-\s*(.*?)\s*$", following)
                    if item:
                        literals.append(item.group(1))
                    cursor += 1
                index = cursor - 1
            for raw_literal in literals:
                literal = raw_literal.split(" #", 1)[0].strip().strip("'\"")
                if literal:
                    rows.append({
                        "rule": rule_path.relative_to(root).as_posix(),
                        "operation": operation,
                        "literal": literal,
                    })
            index += 1
    if not rows:
        fail("stable sequence rules publish no fixed file-path predicates")
    return rows


def validate_workload_sequence_path_isolation(
    root: pathlib.Path, bulk_path: str
) -> Dict[str, Any]:
    match = WORKLOAD_BULK_PATH_RE.fullmatch(bulk_path)
    if not match:
        fail("runtime workload bulk path is not the fixed /Users/Shared form")
    candidates = (
        bulk_path,
        bulk_path + "/event-00001.txt",
        bulk_path + "/renamed-00001.txt",
    )
    predicates = stable_sequence_file_path_predicates(root)
    collisions = []
    for row in predicates:
        operation = row["operation"]
        literal = row["literal"]
        for candidate in candidates:
            matched = (
                (operation == "startswith" and candidate.startswith(literal))
                or (operation == "contains" and literal in candidate)
                or (operation == "endswith" and candidate.endswith(literal))
            )
            if matched:
                collisions.append({**row, "candidate": candidate})
    if collisions:
        fail(
            "runtime bulk pressure path matches a stable sequence file predicate: "
            + json.dumps(collisions, sort_keys=True)
        )
    return {
        "bulk_path": bulk_path,
        "stable_predicate_count": len(predicates),
        "stable_predicates_sha256": sha256_bytes(canonical_json_bytes(predicates)),
    }


def installed_alert_database(data_dirs: Sequence[pathlib.Path]) -> pathlib.Path:
    candidates = []
    for directory in data_dirs:
        path = directory / "alerts.db"
        if path.exists() or path.is_symlink():
            candidates.append(path)
    if len(candidates) != 1:
        fail(
            "exact alert proof requires one unambiguous installed alerts.db; "
            f"found {len(candidates)}"
        )
    path = candidates[0]
    if path.is_symlink() or not path.is_file():
        fail("installed alerts.db is missing, non-regular, or redirected")
    return path


def readonly_alert_rows_for_process(
    *, database_path: pathlib.Path, process_path: str,
    triggered_after_unix: float,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Query an exact alert path through SQLite READONLY|NOFOLLOW.

    Python's sqlite3 module does not expose SQLITE_OPEN_NOFOLLOW, so this
    deliberately uses the narrow C API needed for one bound, read-only query.
    WAL visibility is retained; immutable mode would incorrectly hide a live
    writer's uncheckpointed alert or investigation update.
    """
    if not process_path.startswith("/"):
        fail("causal alert process path must be absolute")
    library_name = ctypes.util.find_library("sqlite3")
    if not library_name:
        fail("system SQLite library is unavailable for exact alert proof")
    library = ctypes.CDLL(library_name)
    database_handle = ctypes.c_void_p()
    statement = ctypes.c_void_p()
    library.sqlite3_open_v2.argtypes = [
        ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_int,
        ctypes.c_char_p,
    ]
    library.sqlite3_open_v2.restype = ctypes.c_int
    library.sqlite3_close_v2.argtypes = [ctypes.c_void_p]
    library.sqlite3_close_v2.restype = ctypes.c_int
    library.sqlite3_errmsg.argtypes = [ctypes.c_void_p]
    library.sqlite3_errmsg.restype = ctypes.c_char_p
    library.sqlite3_prepare_v2.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int,
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_char_p),
    ]
    library.sqlite3_prepare_v2.restype = ctypes.c_int
    library.sqlite3_bind_text.argtypes = [
        ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
        ctypes.c_void_p,
    ]
    library.sqlite3_bind_text.restype = ctypes.c_int
    library.sqlite3_bind_double.argtypes = [
        ctypes.c_void_p, ctypes.c_int, ctypes.c_double,
    ]
    library.sqlite3_bind_double.restype = ctypes.c_int
    library.sqlite3_step.argtypes = [ctypes.c_void_p]
    library.sqlite3_step.restype = ctypes.c_int
    library.sqlite3_column_text.argtypes = [ctypes.c_void_p, ctypes.c_int]
    library.sqlite3_column_text.restype = ctypes.c_void_p
    library.sqlite3_column_double.argtypes = [ctypes.c_void_p, ctypes.c_int]
    library.sqlite3_column_double.restype = ctypes.c_double
    library.sqlite3_column_type.argtypes = [ctypes.c_void_p, ctypes.c_int]
    library.sqlite3_column_type.restype = ctypes.c_int
    library.sqlite3_finalize.argtypes = [ctypes.c_void_p]
    library.sqlite3_finalize.restype = ctypes.c_int
    library.sqlite3_busy_timeout.argtypes = [ctypes.c_void_p, ctypes.c_int]
    library.sqlite3_busy_timeout.restype = ctypes.c_int

    flags = 0x00000001 | 0x00000040 | 0x01000000  # READONLY | URI | NOFOLLOW
    descriptor = -1
    rows: List[Dict[str, Any]] = []
    try:
        descriptor = os.open(
            str(database_path),
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        opened_stat = os.fstat(descriptor)
        if not stat.S_ISREG(opened_stat.st_mode):
            fail("installed alerts.db is not a regular file")
        result = library.sqlite3_open_v2(
            os.fsencode(database_path), ctypes.byref(database_handle), flags, None
        )
        if result != 0:
            detail = (
                library.sqlite3_errmsg(database_handle).decode("utf-8", "replace")
                if database_handle.value else f"SQLite result {result}"
            )
            fail(f"read-only no-follow alerts.db open failed: {detail}")
        library.sqlite3_busy_timeout(database_handle, 5_000)
        sql = (
            b"SELECT id,timestamp,rule_id,severity,process_path,"
            b"llm_investigation_json FROM alerts "
            b"WHERE process_path = ?1 AND timestamp >= ?2 "
            b"ORDER BY timestamp ASC,id ASC"
        )
        result = library.sqlite3_prepare_v2(
            database_handle, sql, -1, ctypes.byref(statement), None
        )
        if result != 0:
            fail(
                "exact alert query prepare failed: "
                + library.sqlite3_errmsg(database_handle).decode("utf-8", "replace")
            )
        encoded_path = process_path.encode("utf-8")
        if library.sqlite3_bind_text(
            statement, 1, encoded_path, len(encoded_path), ctypes.c_void_p(-1)
        ) != 0 or library.sqlite3_bind_double(
            statement, 2, float(triggered_after_unix)
        ) != 0:
            fail("exact alert query parameter binding failed")

        def column_text(index: int, *, nullable: bool = False) -> str | None:
            if library.sqlite3_column_type(statement, index) == 5:  # SQLITE_NULL
                if nullable:
                    return None
                fail(f"exact alert query column {index} is unexpectedly NULL")
            pointer = library.sqlite3_column_text(statement, index)
            if not pointer:
                return ""
            return ctypes.string_at(pointer).decode("utf-8", "strict")

        while True:
            result = library.sqlite3_step(statement)
            if result == 101:  # SQLITE_DONE
                break
            if result != 100:  # SQLITE_ROW
                fail(
                    "exact alert query failed: "
                    + library.sqlite3_errmsg(database_handle).decode(
                        "utf-8", "replace"
                    )
                )
            rows.append({
                "id": column_text(0),
                "timestamp_unix": float(library.sqlite3_column_double(statement, 1)),
                "rule_id": column_text(2),
                "severity": column_text(3),
                "process_path": column_text(4),
                "llm_investigation_json": column_text(5, nullable=True),
            })
        current_stat = os.stat(database_path, follow_symlinks=False)
        if not stat.S_ISREG(current_stat.st_mode) \
                or (current_stat.st_dev, current_stat.st_ino) != (
                    opened_stat.st_dev, opened_stat.st_ino
                ):
            fail("installed alerts.db identity changed during the no-follow query")
        evidence = {
            "path": str(database_path),
            "owner_uid": opened_stat.st_uid,
            "mode": opened_stat.st_mode & 0o7777,
            "device": opened_stat.st_dev,
            "inode": opened_stat.st_ino,
            "read_only": True,
            "no_follow": True,
            "bound_process_path": process_path,
            "triggered_after_unix": float(triggered_after_unix),
        }
        return rows, evidence
    except (OSError, UnicodeDecodeError) as exc:
        fail(f"read-only no-follow alert query failed: {exc}")
    finally:
        if statement.value:
            library.sqlite3_finalize(statement)
        if database_handle.value:
            library.sqlite3_close_v2(database_handle)
        if descriptor >= 0:
            os.close(descriptor)


def validate_investigation_json(raw: Any, alert_id: str, path: str) -> str:
    text = string_value(raw, path)
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        fail(f"{path} is not valid JSON: {exc}")
    investigation = object_value(value, path)
    expected = {
        "alertId", "confidence", "verdict", "summary", "evidenceChain",
        "mitreReasoning", "suggestedActions", "confidencePenalties",
        "modelVersion", "generatedAt",
    }
    if set(investigation) != expected:
        fail(f"{path} has an incomplete or unknown investigation inventory")
    if investigation.get("alertId") != alert_id:
        fail(f"{path}.alertId does not match the exact persisted alert")
    confidence = number_value(
        investigation.get("confidence"), f"{path}.confidence", minimum=0
    )
    if confidence > 1:
        fail(f"{path}.confidence must be between 0 and 1")
    if investigation.get("verdict") not in {
        "likely_malicious", "likely_benign", "needs_human",
        "insufficient_evidence",
    }:
        fail(f"{path}.verdict is unknown")
    string_value(investigation.get("summary"), f"{path}.summary")
    string_value(investigation.get("modelVersion"), f"{path}.modelVersion")
    generated = investigation.get("generatedAt")
    if not isinstance(generated, str):
        number_value(generated, f"{path}.generatedAt")
    for key in (
        "evidenceChain", "mitreReasoning", "suggestedActions",
        "confidencePenalties",
    ):
        list_value(investigation.get(key), f"{path}.{key}")
    return text


def validate_causal_llm_transition(
    before_raw: Any, after_raw: Any, path: str, *, allow_uninitialized_before: bool
) -> Dict[str, int]:
    before = object_value(before_raw, f"{path}.before")
    after = object_value(after_raw, f"{path}.after")
    for label, row in (("before", before), ("after", after)):
        if row.get("configured") is not True or row.get("schema_version") != 2 \
                or row.get("accounting_conserved") is not True:
            fail(f"{path}.{label} is not a configured conserving LLM snapshot")
        if row.get("circuit_open") is not False \
                or int_value(
                    row.get("consecutive_failures"),
                    f"{path}.{label}.consecutive_failures",
                ) != 0:
            fail(f"{path}.{label} has a failed/open LLM backend")
    if before.get("healthy") is not True:
        if not allow_uninitialized_before \
                or before.get("last_success_unix") is not None \
                or int_value(
                    before.get("totals_requested_total"),
                    f"{path}.before.totals_requested_total",
                ) != 0:
            fail(
                f"{path}.before is neither healthy nor an expected "
                "never-used/no-success prewarm state"
            )
    if after.get("healthy") is not True:
        fail(f"{path}.after is not healthy after alert-specific prewarm/triage")
    before_alert = object_value(
        before.get("alert_investigation"), f"{path}.before.alert_investigation"
    )
    after_alert = object_value(
        after.get("alert_investigation"), f"{path}.after.alert_investigation"
    )

    def delta(container_before: Mapping[str, Any], container_after: Mapping[str, Any], key: str) -> int:
        start = int_value(container_before.get(key), f"{path}.before.{key}")
        end = int_value(container_after.get(key), f"{path}.after.{key}")
        if end < start:
            fail(f"{path} cumulative {key} moved backwards")
        return end - start

    started = delta(before_alert, after_alert, "operations_started_total")
    accepted = delta(before_alert, after_alert, "accepted_total")
    rejected = delta(before_alert, after_alert, "final_rejection_total")
    unspecified = delta(before, after, "unspecified_requested_total")
    if started < 1 or accepted != started or rejected != 0 or unspecified != 0:
        fail(
            f"{path} must prove one or more completed alert investigations "
            "with zero final rejection or unattributed work"
        )
    if int_value(
        after_alert.get("current_operations"),
        f"{path}.after.alert_investigation.current_operations",
    ) != 0:
        fail(f"{path} alert investigation is still in flight")
    return {
        "started_delta": started,
        "accepted_delta": accepted,
        "final_rejection_delta": rejected,
        "unspecified_delta": unspecified,
    }


def validate_alert_investigation_proof(raw: Any, path: str) -> Dict[str, int]:
    proof = object_value(raw, path)
    required = {
        "phase", "database", "process_path", "trigger_started_at",
        "alert", "observed_alerts", "investigation_json",
        "investigation_sha256",
        "telemetry_before", "telemetry_after", "observed_at",
    }
    if set(proof) != required:
        fail(f"{path} inventory is incomplete or unknown")
    if proof.get("phase") not in ("prewarm", "epoch"):
        fail(f"{path}.phase is unknown")
    process_path = string_value(proof.get("process_path"), f"{path}.process_path")
    if not WORKLOAD_ALERT_PATH_RE.fullmatch(process_path):
        fail(f"{path}.process_path is not the fixed unique alert executable")
    triggered = parse_time(proof.get("trigger_started_at"), f"{path}.trigger_started_at")
    observed = parse_time(proof.get("observed_at"), f"{path}.observed_at")
    if observed < triggered:
        fail(f"{path}.observed_at precedes the trigger")
    database = object_value(proof.get("database"), f"{path}.database")
    expected_database_keys = {
        "path", "owner_uid", "mode", "device", "inode", "read_only",
        "no_follow", "bound_process_path", "triggered_after_unix",
    }
    if set(database) != expected_database_keys:
        fail(f"{path}.database inventory is incomplete or unknown")
    database_path = string_value(database.get("path"), f"{path}.database.path")
    if not database_path.startswith("/Library/Application Support/MacCrab/") \
            or not database_path.endswith("/alerts.db"):
        fail(f"{path}.database.path is not the installed alerts.db")
    if int_value(database.get("owner_uid"), f"{path}.database.owner_uid") != 0:
        fail(f"{path}.database is not root-owned")
    if int_value(database.get("mode"), f"{path}.database.mode") & 0o022:
        fail(f"{path}.database is group/world writable")
    int_value(database.get("device"), f"{path}.database.device")
    int_value(database.get("inode"), f"{path}.database.inode", minimum=1)
    require_true(database.get("read_only"), f"{path}.database.read_only")
    require_true(database.get("no_follow"), f"{path}.database.no_follow")
    if database.get("bound_process_path") != process_path:
        fail(f"{path}.database query was not bound to the exact process path")
    boundary = number_value(
        database.get("triggered_after_unix"), f"{path}.database.triggered_after_unix"
    )
    if abs(boundary - triggered.timestamp()) > 1.0:
        fail(f"{path}.database query boundary does not match the trigger")
    alert = object_value(proof.get("alert"), f"{path}.alert")
    if set(alert) != {"id", "timestamp_unix", "rule_id", "severity"}:
        fail(f"{path}.alert inventory is incomplete or unknown")
    alert_id = string_value(alert.get("id"), f"{path}.alert.id")
    if not UUID_RE.fullmatch(alert_id):
        fail(f"{path}.alert.id is not a UUID")
    timestamp = number_value(alert.get("timestamp_unix"), f"{path}.alert.timestamp_unix")
    if timestamp < boundary or timestamp > observed.timestamp() + 5.0:
        fail(f"{path}.alert timestamp is outside the exact trigger/observation interval")
    string_value(alert.get("rule_id"), f"{path}.alert.rule_id")
    if alert.get("severity") not in ("high", "critical"):
        fail(f"{path}.alert did not persist as HIGH or CRITICAL")
    # Every alert the one trigger produced. The bound alert above carries the
    # causal proof; this records how many detection tiers actually caught it,
    # which the removed uniqueness check used to discard. It is evidence, so it
    # is validated as strictly as the rest: an unknown key here would otherwise
    # be a free-form field inside a signed evidence document.
    observed_alerts = list_value(
        proof.get("observed_alerts"), f"{path}.observed_alerts", nonempty=True
    )
    for index, entry in enumerate(observed_alerts):
        row = object_value(entry, f"{path}.observed_alerts[{index}]")
        if set(row) != {"id", "rule_id", "severity"}:
            fail(f"{path}.observed_alerts[{index}] inventory is incomplete or unknown")
        # Only the BOUND alert is required to be a UUID (checked above). This
        # is a census of every tier that caught the same trigger, and tiers do
        # not share one id format -- requiring UUIDs here rejected a real
        # multi-tier observation on the reference host.
        string_value(row.get("id"), f"{path}.observed_alerts[{index}].id")
        string_value(row.get("rule_id"), f"{path}.observed_alerts[{index}].rule_id")
        string_value(row.get("severity"), f"{path}.observed_alerts[{index}].severity")
    if alert_id not in {
        string_value(row.get("id"), f"{path}.observed_alerts id") for row in observed_alerts
    }:
        fail(f"{path}.alert is not among the alerts the trigger was observed to produce")
    investigation = validate_investigation_json(
        proof.get("investigation_json"), alert_id, f"{path}.investigation_json"
    )
    if require_sha(
        proof.get("investigation_sha256"), f"{path}.investigation_sha256"
    ) != sha256_bytes(investigation.encode("utf-8")):
        fail(f"{path}.investigation_sha256 does not bind the persisted JSON")
    return validate_causal_llm_transition(
        proof.get("telemetry_before"), proof.get("telemetry_after"),
        f"{path}.telemetry",
        allow_uninitialized_before=proof.get("phase") == "prewarm",
    )


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


def source_runtime_probe_evidence(
    candidate_manifest: Mapping[str, Any],
) -> Dict[str, Any]:
    """Return phase-1 source evidence without launching monitored processes.

    Running SwiftPM or the rule linter here would contaminate the installed
    daemon's cumulative process epoch before t0.  The exact candidate-manifest
    digest already binds the clean local-CI receipt captured before the
    candidate was built and installed, so the recorder only validates/copies it.
    """
    candidate = object_value(candidate_manifest.get("candidate"), "candidate")
    evidence = validate_preinstall_clean_ci(
        candidate_manifest.get("preinstall_clean_ci"),
        source_commit=require_object_id(
            candidate.get("source_commit"), "candidate.source_commit"
        ),
        source_tree=require_object_id(
            candidate.get("source_tree"), "candidate.source_tree"
        ),
        path="candidate.preinstall_clean_ci",
    )
    return {"preinstall_clean_ci": evidence}


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


def process_probe_evidence(
    command: Sequence[str], returncode: int, stdout: str, stderr: str
) -> Dict[str, Any]:
    combined = (stdout or "") + (stderr or "")
    return {
        "command": list(command),
        "exit_code": returncode,
        "output_sha256": sha256_bytes(combined.encode("utf-8")),
        "output_tail": combined[-4096:],
        "output_line_count": len(combined.splitlines()),
    }


def terminate_process_group(process: subprocess.Popen[str]) -> Tuple[str, str]:
    """Reap a workload and every child in its dedicated process group."""
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            return process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    try:
        return process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        fail("runtime workload process group could not be reaped")


# v1.22.0: mirror of MacCrabCore `LLMBatchTriage.representative`
# (Sources/MacCrabCore/LLM/LLMBatchTriage.swift:15-35).
#
# The causal proof means "the engine investigated the alert this trigger
# caused". It can only mean that if the gate binds the SAME alert the engine
# chose to investigate. One trigger legitimately produces several alerts across
# the five detection tiers, and the engine picks exactly one of them: severity
# >= high, excluding campaign and llm-derived rules, then highest severity,
# earliest timestamp, lowest id.
#
# Binding anything else — including the first row of a timestamp-ordered query —
# selects an alert that will never carry an investigation, so the proof can
# never land and the run fails at the offset-450 boundary having proved nothing.
# It also risks binding a non-UUID id (campaign alerts are `CAMP-<hex>`), which
# hard-fails UUID_RE.
#
# Keep in lockstep with the Swift. If the engine's choice changes, this must.
CAUSAL_ALERT_EXCLUDED_RULE_PREFIXES = ("maccrab.campaign.", "maccrab.llm.")
CAUSAL_ALERT_SEVERITY_RANK = {
    "informational": 0, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}
CAUSAL_ALERT_MINIMUM_SEVERITY = CAUSAL_ALERT_SEVERITY_RANK["high"]


def triage_representative_row(rows: Sequence[Mapping[str, Any]]) -> Dict[str, Any] | None:
    """The row the engine's own batch triage would investigate, or None."""
    candidates = []
    for row in rows:
        rank = CAUSAL_ALERT_SEVERITY_RANK.get(
            str(row.get("severity", "")).strip().lower(), -1
        )
        if rank < CAUSAL_ALERT_MINIMUM_SEVERITY:
            continue
        if str(row.get("rule_id", "")).startswith(
            CAUSAL_ALERT_EXCLUDED_RULE_PREFIXES
        ):
            continue
        candidates.append((rank, row))
    if not candidates:
        return None
    # Highest severity, then earliest timestamp, then lowest id — exactly
    # `isPreferred` in the Swift.
    best = min(
        candidates,
        key=lambda pair: (
            -pair[0],
            number_value(pair[1].get("timestamp_unix"), "causal alert timestamp"),
            str(pair[1].get("id", "")),
        ),
    )
    return dict(best[1])


def causal_alert_proof_if_ready(
    *, phase: str, database_path: pathlib.Path, process_path: str,
    trigger_started_at: dt.datetime, telemetry_before: Mapping[str, Any],
    observation: Mapping[str, Any], stable_alert_id: str | None,
) -> Tuple[Dict[str, Any] | None, str | None]:
    rows, database = readonly_alert_rows_for_process(
        database_path=database_path, process_path=process_path,
        triggered_after_unix=trigger_started_at.timestamp(),
    )
    if not rows:
        return None, stable_alert_id
    # rc.45: one trigger legitimately produces SEVERAL alerts.
    #
    # This required exactly one row and failed the whole run on more. That
    # assumption only ever held by luck: the qualification executable is
    # deliberately suspicious, so it can trip any of the five detection tiers,
    # and which ones fire depends on the host's accumulated history. Observed
    # 2026-08-31 on an installed host — ONE exec, five alerts in the same
    # second: a targeted rule (critical), a second rule (low),
    # `baseline-anomaly`, `maccrab.behavior.composite`, and
    # `maccrab.campaign.coordinated_attack`. The 2026-08-23 run produced four
    # (no campaign); an earlier one produced a single alert, which is the only
    # reason this check ever passed.
    #
    # Failing there rejects the product for detecting well, which is the
    # opposite of what this gate is for. Every row is already constrained to the
    # exact per-run executable path by the query, so multiplicity is richness,
    # not ambiguity: bind ONE alert for the causal proof and record them all.
    if stable_alert_id is not None:
        pinned = next(
            (row for row in rows if row.get("id") == stable_alert_id), None
        )
        if pinned is None:
            fail("causal alert identity disappeared while awaiting investigation")
        row = pinned
    else:
        representative = triage_representative_row(rows)
        if representative is None:
            # Every alert the trigger produced was below the investigation
            # threshold or campaign/llm-derived. Not a proof yet, and not a
            # failure: keep polling rather than binding an alert the engine
            # will never investigate.
            return None, stable_alert_id
        row = representative
    alert_id = string_value(row.get("id"), "causal alert id")
    if not UUID_RE.fullmatch(alert_id):
        fail("causal alert id is not a UUID")
    if row.get("process_path") != process_path:
        fail("causal alert query returned a different process path")
    investigation = row.get("llm_investigation_json")
    if not isinstance(investigation, str) or not investigation.strip():
        return None, alert_id
    sample = sample_from_recorder_observation(
        observation, f"{phase} causal alert observation"
    )
    # The persisted investigation appears in alerts.db BEFORE the next heartbeat
    # publishes the health flip it caused -- heartbeats are ~30s apart, so the
    # evidence is visible first and `telemetry_after` would embed a snapshot
    # that still reports unhealthy. The validator then rejects the proof for
    # `.after is not healthy`, which is true of that snapshot but not of the
    # engine. This is a polling loop with a 180s budget: the proof is simply not
    # ready until the telemetry it embeds agrees with the database it cites.
    pending = object_value(
        sample.get("llm_quality"), f"{phase} causal LLM telemetry result"
    )
    if pending.get("configured") is True and pending.get("healthy") is not True:
        return None, alert_id
    # Same lag, second field. `healthy` is already true by the epoch (the
    # prewarm made it so), but the investigation this proof cites can be
    # persisted in alerts.db while the heartbeat still shows it started and not
    # yet accepted -- heartbeats are ~30s apart. The validator then computes
    # accepted_delta != started_delta and rejects a proof describing a perfectly
    # good investigation. Observed on the reference host at the epoch boundary
    # with started=2, accepted=2, final_rejection=0 by the time it was read
    # back. Wait for the telemetry to agree instead of emitting the proof.
    if pending.get("configured") is True and isinstance(telemetry_before, Mapping) \
            and telemetry_before.get("alert_investigation") is not None:
        before_alert = object_value(
            telemetry_before.get("alert_investigation"),
            f"{phase} causal LLM telemetry baseline.alert_investigation",
        )
        after_alert = object_value(
            pending.get("alert_investigation"),
            f"{phase} causal LLM telemetry result.alert_investigation",
        )

        def _moved(key: str) -> int:
            return int_value(
                after_alert.get(key), f"{phase} causal after.{key}", minimum=0
            ) - int_value(
                before_alert.get(key), f"{phase} causal before.{key}", minimum=0
            )

        started = _moved("operations_started_total")
        accepted = _moved("accepted_total")
        in_flight = int_value(
            after_alert.get("current_operations"),
            f"{phase} causal after.current_operations", minimum=0,
        )
        if in_flight != 0 or started < 1 or accepted != started:
            return None, alert_id
    proof = {
        "phase": phase,
        "database": database,
        "process_path": process_path,
        "trigger_started_at": trigger_started_at.isoformat().replace("+00:00", "Z"),
        "alert": {
            "id": alert_id,
            "timestamp_unix": number_value(
                row.get("timestamp_unix"), "causal alert timestamp"
            ),
            "rule_id": string_value(row.get("rule_id"), "causal alert rule id"),
            "severity": string_value(row.get("severity"), "causal alert severity"),
        },
        # Every alert the one trigger produced. The bound alert above carries
        # the causal proof; this records how many detection tiers actually
        # caught it, which the previous uniqueness check discarded.
        "observed_alerts": [
            {
                "id": string_value(other.get("id"), "observed alert id"),
                "rule_id": string_value(
                    other.get("rule_id"), "observed alert rule id"
                ),
                "severity": string_value(
                    other.get("severity"), "observed alert severity"
                ),
            }
            for other in rows
        ],
        "investigation_json": investigation,
        "investigation_sha256": sha256_bytes(investigation.encode("utf-8")),
        "telemetry_before": copy.deepcopy(
            object_value(telemetry_before, "causal LLM telemetry baseline")
        ),
        # NOTE: the caller must not reach here until `sample.llm_quality`
        # reports healthy -- see the readiness gate above this return.
        "telemetry_after": copy.deepcopy(
            object_value(sample.get("llm_quality"), "causal LLM telemetry result")
        ),
        "observed_at": string_value(
            observation.get("captured_at"), "causal alert observation.captured_at"
        ),
    }
    validate_alert_investigation_proof(proof, f"{phase} alert proof")
    return proof, alert_id


def wait_for_runtime_drain(
    *, initial: Mapping[str, Any], phase: str, heartbeat_path: pathlib.Path,
    candidate: Mapping[str, Any], data_dirs: Sequence[pathlib.Path],
    sqlite_overrides: Mapping[str, int], expected_pid: int,
    timeout_seconds: int = RUNTIME_DRAIN_TIMEOUT_SECONDS,
    require_llm_ready: bool = True,
) -> Dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    observation = dict(initial)
    last_completed: Dict[str, int] = {}
    proven_flowing: set = set()
    while True:
        fatal, pending = runtime_readiness_failures(
            observation, f"{phase} observation", expected_pid=expected_pid,
            require_llm_ready=require_llm_ready,
        )
        if fatal:
            fail(f"{phase} runtime readiness failed: " + "; ".join(fatal))
        # rc.42: forgive lanes that are provably FLOWING (see
        # RUNTIME_DRAIN_FLOWING_QUEUE_LIMIT). A lane qualifies only when its
        # backlog is small, nothing is mid-transaction, and its cumulative
        # `completed` advanced across distinct telemetry snapshots — the one
        # thing a stuck writer cannot fake.
        boundaries = observation.get("conservation")
        if pending and isinstance(boundaries, Mapping):
            still_pending = []
            for entry in pending:
                name = entry.split(" ", 1)[0]
                row = boundaries.get(name)
                if not isinstance(row, Mapping):
                    still_pending.append(entry)
                    continue
                completed = row.get("completed")
                queued = row.get("queued")
                in_flight = row.get("in_flight")
                previous = last_completed.get(name)
                if isinstance(completed, int) and previous is not None \
                        and completed > previous:
                    proven_flowing.add(name)
                if name in proven_flowing and in_flight == 0 \
                        and isinstance(queued, int) \
                        and 0 <= queued <= RUNTIME_DRAIN_FLOWING_QUEUE_LIMIT:
                    continue
                still_pending.append(entry)
            pending = still_pending
        if isinstance(boundaries, Mapping):
            for name, row in boundaries.items():
                if isinstance(row, Mapping) and isinstance(row.get("completed"), int):
                    previous = last_completed.get(name)
                    if previous is None or row["completed"] != previous:
                        last_completed[name] = row["completed"]
        if not pending:
            return observation
        if time.monotonic() >= deadline:
            fail(
                f"{phase} runtime queues did not drain: " + "; ".join(pending)
                + f" (flow-proven lanes this window: {sorted(proven_flowing) or 'none'})"
            )
        time.sleep(READINESS_POLL_SECONDS)
        scheduled_at = dt.datetime.now(dt.timezone.utc)
        observation = capture_runtime_observation(
            offset=0, scheduled_at=scheduled_at,
            heartbeat_path=heartbeat_path, candidate=candidate,
            data_dirs=data_dirs, sqlite_overrides=sqlite_overrides,
        )


def prewarm_alert_investigation(
    *, root: pathlib.Path, baseline: Mapping[str, Any],
    heartbeat_path: pathlib.Path, candidate: Mapping[str, Any],
    data_dirs: Sequence[pathlib.Path], sqlite_overrides: Mapping[str, int],
    expected_pid: int,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    workload_script = root / "scripts/runtime-qualification-workload.sh"
    if workload_script.is_symlink() or not workload_script.is_file():
        fail("fixed runtime qualification workload script is missing or redirected")
    run_id = secrets.token_hex(16)
    alert_path, _ = workload_paths(run_id)
    command = original_user_command([
        "/bin/bash", str(workload_script), "--alert-only", "--run-id", run_id,
    ])
    trigger_started_at = dt.datetime.now(dt.timezone.utc)
    process = subprocess.Popen(
        command, cwd=str(root), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, start_new_session=True,
    )
    try:
        try:
            stdout, stderr = process.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            stdout, stderr = terminate_process_group(process)
            fail("fixed LLM prewarm alert trigger exceeded 30 seconds")
    finally:
        if process.poll() is None:
            terminate_process_group(process)
    probe = process_probe_evidence(
        command, int(process.returncode or 0), stdout, stderr
    )
    if process.returncode != 0:
        fail(f"fixed LLM prewarm trigger failed: {(stderr or stdout)[-1000:]}")
    if f"run_id={run_id}" not in (stdout + stderr) \
            or f"alert_executable={alert_path}" not in (stdout + stderr):
        fail("fixed LLM prewarm output does not reconcile with its run identity")

    baseline_sample = validate_runtime_readiness(
        baseline, "LLM prewarm baseline", phase="LLM prewarm baseline",
        require_drained=True, expected_pid=expected_pid,
        require_llm_ready=False,
    )
    database_path = installed_alert_database(data_dirs)
    deadline = time.monotonic() + LLM_PREWARM_TIMEOUT_SECONDS
    stable_alert_id: str | None = None
    latest = dict(baseline)
    proof: Dict[str, Any] | None = None
    while time.monotonic() <= deadline:
        scheduled_at = dt.datetime.now(dt.timezone.utc)
        latest = capture_runtime_observation(
            offset=0, scheduled_at=scheduled_at,
            heartbeat_path=heartbeat_path, candidate=candidate,
            data_dirs=data_dirs, sqlite_overrides=sqlite_overrides,
        )
        validate_runtime_readiness(
            latest, "LLM prewarm poll", phase="LLM prewarm",
            require_drained=False, expected_pid=expected_pid,
            require_llm_ready=False,
        )
        proof, stable_alert_id = causal_alert_proof_if_ready(
            phase="prewarm", database_path=database_path,
            process_path=alert_path, trigger_started_at=trigger_started_at,
            telemetry_before=object_value(
                baseline_sample.get("llm_quality"), "LLM prewarm baseline quality"
            ),
            observation=latest, stable_alert_id=stable_alert_id,
        )
        if proof is not None:
            break
        time.sleep(READINESS_POLL_SECONDS)
    if proof is None:
        fail(
            "LLM prewarm timed out without one exact committed alert and "
            "persisted accepted investigation"
        )
    drained = wait_for_runtime_drain(
        initial=latest, phase="post-prewarm", heartbeat_path=heartbeat_path,
        candidate=candidate, data_dirs=data_dirs,
        sqlite_overrides=sqlite_overrides, expected_pid=expected_pid,
    )
    probe.update({
        "run_id": run_id,
        "alert_executable": alert_path,
        "started_at": trigger_started_at.isoformat().replace("+00:00", "Z"),
        "completed_at": string_value(
            proof.get("observed_at"), "LLM prewarm proof observed_at"
        ),
        "alert_investigation": proof,
    })
    return probe, drained


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
) -> Tuple[List[Dict[str, Any]], Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    if platform.system() != "Darwin" or os.geteuid() != 0:
        fail("record-runtime must run with sudo on the installed reference Mac")
    candidate = object_value(candidate_manifest.get("candidate"), "candidate")
    observations: List[Dict[str, Any]] = []
    readiness_observations: List[Dict[str, Any]] = []
    workload_process: subprocess.Popen[str] | None = None
    workload_command: List[str] | None = None
    workload_stdout = ""
    workload_stderr = ""
    workload_completed_at: dt.datetime | None = None
    workload_run_id: str | None = None
    workload_alert_path: str | None = None
    workload_bulk_path: str | None = None
    workload_isolation: Dict[str, Any] | None = None
    workload_trigger_started_at: dt.datetime | None = None
    workload_baseline_llm: Dict[str, Any] | None = None
    workload_alert_id: str | None = None
    workload_alert_proof: Dict[str, Any] | None = None
    prewarm_evidence: Dict[str, Any] | None = None
    reload_evidence: Dict[str, Any] | None = None
    phase = "initial-readiness"

    def persist_capture(result: str, *, reason: str | None = None) -> None:
        document: Dict[str, Any] = {
            "schema": RUNTIME_RECORDER_SCHEMA,
            "result": result,
            "phase": phase,
            "candidate_manifest_sha256": candidate_manifest_sha256,
            "readiness_observations": readiness_observations,
            "observations": observations,
        }
        if prewarm_evidence is not None:
            document["llm_prewarm"] = prewarm_evidence
        if workload_run_id is not None:
            document["workload"] = {
                "run_id": workload_run_id,
                "command": workload_command,
                "alert_executable": workload_alert_path,
                "bulk_path": workload_bulk_path,
                "trigger_started_at": (
                    workload_trigger_started_at.isoformat().replace("+00:00", "Z")
                    if workload_trigger_started_at is not None else None
                ),
                "completed_at": (
                    workload_completed_at.isoformat().replace("+00:00", "Z")
                    if workload_completed_at is not None else None
                ),
                "stdout_tail": workload_stdout[-4096:],
                "stderr_tail": workload_stderr[-4096:],
                "sequence_path_isolation": workload_isolation,
                "alert_investigation": workload_alert_proof,
            }
        if reason is not None:
            document["failure"] = reason
        write_json_exclusive(capture_path, document)

    try:
        preflight_heartbeat, _ = read_live_heartbeat(heartbeat_path, candidate)
        preflight_pid = heartbeat_counter(
            preflight_heartbeat, "engine_pid", "heartbeat"
        )
        host = installed_runtime_host(preflight_pid)
        initial = capture_runtime_observation(
            offset=0, scheduled_at=dt.datetime.now(dt.timezone.utc),
            heartbeat_path=heartbeat_path, candidate=candidate,
            data_dirs=data_dirs, sqlite_overrides=sqlite_overrides,
        )
        readiness_observations.append(initial)
        # A never-used configured backend is expected to be healthy=false until
        # the exact alert prewarm below. Storage, loss, accounting, circuit and
        # failure state are still fail-closed here.
        validate_runtime_readiness(
            initial, "initial readiness", phase="initial readiness",
            require_drained=False, expected_pid=preflight_pid,
            require_llm_ready=False,
        )
        persist_capture("checking-readiness")

        phase = "source-and-artifact-probes"
        source_evidence = source_runtime_probe_evidence(candidate_manifest)
        tools = mounted_tool_probes(
            dmg, string_value(candidate.get("version"), "candidate.version"),
            host["sip_enabled"] is True and host["amfi_enforced"] is True,
        )
        after_probes = capture_runtime_observation(
            offset=0, scheduled_at=dt.datetime.now(dt.timezone.utc),
            heartbeat_path=heartbeat_path, candidate=candidate,
            data_dirs=data_dirs, sqlite_overrides=sqlite_overrides,
        )
        readiness_observations.append(after_probes)
        drained_before_prewarm = wait_for_runtime_drain(
            initial=after_probes, phase="pre-prewarm",
            heartbeat_path=heartbeat_path, candidate=candidate,
            data_dirs=data_dirs, sqlite_overrides=sqlite_overrides,
            expected_pid=preflight_pid, require_llm_ready=False,
        )
        readiness_observations.append(drained_before_prewarm)

        phase = "llm-alert-prewarm"
        prewarm_evidence, post_prewarm = prewarm_alert_investigation(
            root=root, baseline=drained_before_prewarm,
            heartbeat_path=heartbeat_path, candidate=candidate,
            data_dirs=data_dirs, sqlite_overrides=sqlite_overrides,
            expected_pid=preflight_pid,
        )
        readiness_observations.append(post_prewarm)
        validate_runtime_readiness(
            post_prewarm, "post-prewarm readiness",
            phase="post-prewarm readiness", require_drained=True,
            expected_pid=preflight_pid,
        )

        # Capture signed identity only after all unmeasured probes and before
        # t0. Re-reading endpoints later cannot substitute for this boundary.
        phase = "epoch"
        identity_started_at = dt.datetime.now(dt.timezone.utc).replace(
            microsecond=0
        )
        installed_start = installed_engine_identity(
            preflight_pid,
            identity_started_at.isoformat().replace("+00:00", "Z"),
        )
        start_wall = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        start_monotonic = time.monotonic()
        first = capture_runtime_observation(
            offset=0, scheduled_at=start_wall,
            heartbeat_path=heartbeat_path, candidate=candidate,
            data_dirs=data_dirs, sqlite_overrides=sqlite_overrides,
        )
        validate_runtime_readiness(
            first, "epoch t0", phase="epoch t0", require_drained=True,
            expected_pid=preflight_pid,
        )
        observations.append(first)
        persist_capture("capturing")

        database_path = installed_alert_database(data_dirs)
        for offset in range(30, int(MIN_EPOCH_SECONDS) + 1, 30):
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
            validate_runtime_readiness(
                observation, f"epoch sample {offset}", phase=f"epoch sample {offset}",
                require_drained=offset in (
                    BURST_DRAIN_OFFSET_SECONDS, int(MIN_EPOCH_SECONDS)
                ),
                expected_pid=preflight_pid,
            )
            observations.append(observation)

            if offset == BURST_START_OFFSET_SECONDS:
                workload_script = root / "scripts/runtime-qualification-workload.sh"
                if workload_script.is_symlink() or not workload_script.is_file():
                    fail("fixed runtime qualification workload script is missing or redirected")
                workload_run_id = secrets.token_hex(16)
                workload_alert_path, workload_bulk_path = workload_paths(
                    workload_run_id
                )
                workload_isolation = validate_workload_sequence_path_isolation(
                    root, workload_bulk_path
                )
                workload_command = original_user_command([
                    "/bin/bash", str(workload_script),
                    "--run-id", workload_run_id,
                ])
                workload_baseline_llm = copy.deepcopy(
                    object_value(
                        sample_from_recorder_observation(
                            observation, "minute-five workload baseline"
                        ).get("llm_quality"),
                        "minute-five workload baseline LLM",
                    )
                )
                workload_trigger_started_at = dt.datetime.now(dt.timezone.utc)
                workload_process = subprocess.Popen(
                    workload_command, cwd=str(root), stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True, start_new_session=True,
                )

            if workload_process is not None \
                    and workload_completed_at is None \
                    and workload_process.poll() is not None:
                workload_stdout, workload_stderr = workload_process.communicate(
                    timeout=5
                )
                workload_completed_at = dt.datetime.now(dt.timezone.utc)
                if workload_process.returncode != 0:
                    fail(
                        "fixed burst workload failed: "
                        + (workload_stderr or workload_stdout)[-1000:]
                    )
                output = workload_stdout + workload_stderr
                if workload_run_id is None or workload_alert_path is None \
                        or workload_bulk_path is None \
                        or f"run_id={workload_run_id}" not in output \
                        or f"alert_executable={workload_alert_path}" not in output \
                        or f"bulk_path={workload_bulk_path}" not in output \
                        or f"iterations={FIXED_WORKLOAD_ITERATIONS}" not in output \
                        or "sequence_probes=1" not in output:
                    fail("fixed workload output does not reconcile with its bounded run")

            if offset == BURST_START_OFFSET_SECONDS + WORKLOAD_DEADLINE_SECONDS \
                    and (workload_process is None or workload_process.poll() is None):
                fail(
                    "fixed burst workload missed its 90-second deadline; "
                    "the process group will be terminated"
                )

            if offset > BURST_START_OFFSET_SECONDS \
                    and offset <= BURST_DRAIN_OFFSET_SECONDS \
                    and workload_alert_proof is None:
                if workload_alert_path is None \
                        or workload_trigger_started_at is None \
                        or workload_baseline_llm is None:
                    fail("workload causal-alert identity was not initialized")
                workload_alert_proof, workload_alert_id = (
                    causal_alert_proof_if_ready(
                        phase="epoch", database_path=database_path,
                        process_path=workload_alert_path,
                        trigger_started_at=workload_trigger_started_at,
                        telemetry_before=workload_baseline_llm,
                        observation=observation,
                        stable_alert_id=workload_alert_id,
                    )
                )

            if offset == BURST_DRAIN_OFFSET_SECONDS:
                if workload_completed_at is None:
                    fail("fixed workload has no completed bounded transcript")
                if workload_alert_proof is None:
                    fail(
                        "fixed workload did not produce its exact persisted "
                        "accepted alert investigation by the drain boundary"
                    )
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
            persist_capture(
                "capturing" if offset < MIN_EPOCH_SECONDS else "captured"
            )
    except BaseException as exc:
        if workload_process is not None and workload_process.poll() is None:
            terminate_process_group(workload_process)
        try:
            persist_capture("failed", reason=str(exc))
        except BaseException:
            pass
        raise
    finally:
        if workload_process is not None and workload_process.poll() is None:
            terminate_process_group(workload_process)

    if workload_process is None or workload_command is None \
            or workload_completed_at is None or workload_trigger_started_at is None \
            or workload_run_id is None or workload_alert_path is None \
            or workload_bulk_path is None or workload_isolation is None \
            or workload_alert_proof is None or prewarm_evidence is None:
        fail("fixed workload/prewarm evidence is incomplete")
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
        "llm_prewarm": prewarm_evidence,
        "workload": {
            **process_probe_evidence(
                workload_command, int(workload_process.returncode or 0),
                workload_stdout, workload_stderr,
            ),
            "run_id": workload_run_id,
            "alert_executable": workload_alert_path,
            "bulk_path": workload_bulk_path,
            "started_at": workload_trigger_started_at.isoformat().replace(
                "+00:00", "Z"
            ),
            "completed_at": workload_completed_at.isoformat().replace(
                "+00:00", "Z"
            ),
            "deadline_offset_seconds": BURST_END_OFFSET_SECONDS,
            "drain_offset_seconds": BURST_DRAIN_OFFSET_SECONDS,
            "sequence_path_isolation": workload_isolation,
            "alert_investigation": workload_alert_proof,
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
        "macos_disk_writes_diagnostic_count": disk_diagnostics,
        "rules": {
            "ordinary_launch_without_admin_prompt": auth_events == 0,
        },
        "shipped_tools": tools,
        "evidence": evidence,
    }
    workload_fields = {
        "id": "normal-plus-burst",
        "version": "2",
        "description": (
            "900 seconds of ordinary browser/terminal/dashboard use plus the "
            "fixed bounded /Users/Shared process/file/OTLP pressure burst, a "
            "separate safe sequence-continuity probe, and an exact causal "
            "high-alert investigation at minute 5, plus a measured live reload"
        ),
        "normal_operations": [
            "ordinary browser activity", "ordinary terminal activity",
            "MacCrab dashboard open in background",
        ],
        "burst_operations": [
            "scripts/runtime-qualification-workload.sh at minute 5",
            "one bounded loopback OTLP span",
            "one harmless /dev/tcp command-line alert trigger (no network access)",
            "one non-networking shell sequence pending/expiry probe",
            "workload exit by 390 seconds and full drain by 450 seconds",
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
            "captured_duration_seconds": 0,
            "uninterrupted": False,
            "sample_interval_seconds": 30,
            "max_sample_gap_seconds": 0,
            "max_captured_gap_seconds": 0,
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
                "source_bound_clean_ci_sha256": "REPLACE",
                "live_rule_reload_signal": {},
            },
            "event_storage": {"unreachable_budget_fault_count": 0, "prune_vacuum_refill_loop_count": 0, "search_tier_gaps_reconcile_exactly": False, "search_tier_gaps_visible": False},
            "trace_graph": {
                "writable_duty_fraction": 0,
                "accepting_mutations_duty_fraction": 0,
                "mutation_shed": 0,
                "recovery_oscillation_count": 0,
                "recovery_mutation_queue_saturated_samples": 0,
                "recovery_mutation_waiter_limit":
                    TRACE_RECOVERY_MUTATION_WAITER_LIMIT,
                "recovery_mutation_waiter_high_watermark": 0,
                "recovery_mutation_waits_epoch_delta": 0,
                "recovery_mutation_wait_releases_epoch_delta": 0,
                "recovery_mutation_wait_cancellations_epoch_delta": 0,
                "recovery_mutation_wait_closed_epoch_delta": 0,
                "recovery_mutation_wait_saturations_epoch_delta": 0,
                "recovery_writer_preemptions_epoch_delta": 0,
                "recovery_mutation_max_wait_nanoseconds": 0,
                "recovery_mutation_max_oldest_wait_nanoseconds": 0,
                "final_recovery_mutation_waiters": 0,
                "final_recovery_mutation_oldest_wait_nanoseconds": 0,
                "write_accounting_reconciled_all_samples": False,
                "coalesced_noop_rows_epoch_delta": 0,
                "physical_write_suppressed_events_epoch_delta": 0,
                "physical_write_suppressed_rows_epoch_delta": 0,
                "failed_batches_epoch_delta": 0,
                "failed_rows_epoch_delta": 0,
                "failed_events_epoch_delta": 0,
            },
            "trace_store": {
                "full_writer_duty_fraction": 0,
                "max_footprint_bytes": 0,
                "minimum_free_space_bytes": 0,
            },
            "workload_ingress": {
                "start_offset_seconds": BURST_START_OFFSET_SECONDS,
                "end_offset_seconds": BURST_END_OFFSET_SECONDS,
                "drain_offset_seconds": BURST_DRAIN_OFFSET_SECONDS,
                "priority_terminal_persistence_offered_delta": 0,
                "priority_terminal_persistence_completed_delta": 0,
                "priority_terminal_persistence_explicitly_shed_delta": 0,
                "file_terminal_persistence_offered_delta": 0,
                "file_terminal_persistence_completed_delta": 0,
                "file_terminal_persistence_explicitly_shed_delta": 0,
                "trace_graph_physical_write_suppressed_events_delta": 0,
                "trace_graph_physical_write_suppressed_rows_delta": 0,
            },
            "disk_writes": {"engine_bytes": 0, "average_bytes_per_second": 0, "windows": [], "macos_disk_writes_diagnostic_count": 0},
            "cpu": {"engine_cpu_seconds": 0, "engine_average_cores": 0, "gui_background_percent_samples": [], "gui_background_p95_percent": 0},
            "memory": {"engine_max_memory_footprint_bytes": 0, "engine_memory_footprint_minute_5_bytes": 0, "engine_memory_footprint_minute_15_bytes": 0},
            "disk_safety": {"inventory_complete": False, "sqlite_families": []},
            "ai_quality": {
                "configured": False,
                "feature_disabled_entire_epoch": True,
                "schema_2_and_accounting_conserved_all_samples": False,
                "unspecified_requests_epoch_delta": 0,
                "alert_investigations_started_epoch_delta": 0,
                "alert_investigations_accepted_epoch_delta": 0,
                "alert_investigations_final_rejected_epoch_delta": 0,
                "causal_alert_id": "REPLACE",
                "causal_investigation_sha256": "REPLACE",
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
    root = pathlib.Path(args.source_root).resolve()
    assert_exact_clean_source(
        root, source_commit=args.source_commit, source_tree=args.source_tree,
        label="candidate clean-CI receipt preflight",
    )
    clean_ci = preinstall_clean_ci_evidence(
        transcript_path=absolute_path(args.clean_ci_transcript),
        started_at=args.clean_ci_started_at,
        completed_at=args.clean_ci_completed_at,
        source_commit=args.source_commit,
        source_tree=args.source_tree,
    )
    document = candidate_document(
        version=args.version,
        build_number=args.build_number,
        source_commit=args.source_commit,
        source_tree=args.source_tree,
        dmg=absolute_path(args.dmg),
        inspection_level=args.artifact_checks,
        notarization_submission_id=args.notarization_submission_id,
        preinstall_clean_ci=clean_ci,
    )
    assert_exact_clean_source(
        root, source_commit=args.source_commit, source_tree=args.source_tree,
        label="candidate clean-CI receipt postflight",
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
        candidate_preinstall_clean_ci=object_value(
            manifest.get("preinstall_clean_ci"), "candidate.preinstall_clean_ci"
        ),
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
        candidate_preinstall_clean_ci=object_value(
            candidate_document_value.get("preinstall_clean_ci"),
            "candidate.preinstall_clean_ci",
        ),
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
    record.add_argument("--source-root", required=True)
    record.add_argument("--dmg", required=True)
    record.add_argument("--output", required=True)
    record.add_argument("--notarization-submission-id", default="")
    record.add_argument("--clean-ci-transcript", required=True)
    record.add_argument("--clean-ci-started-at", required=True)
    record.add_argument("--clean-ci-completed-at", required=True)
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
