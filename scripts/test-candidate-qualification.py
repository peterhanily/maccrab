#!/usr/bin/env python3
"""Deterministic offline fixtures for candidate-qualification.py."""

from __future__ import annotations

import copy
import ctypes
import datetime as dt
import hashlib
import importlib.util
import inspect
import re
import json
import os
import pathlib
import signal
import sqlite3
import subprocess
import tempfile
import time
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parent.parent
MODULE_PATH = ROOT / "scripts/candidate-qualification.py"
SPEC = importlib.util.spec_from_file_location("candidate_qualification", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
qualification = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(qualification)

COMMIT = "1" * 40
TREE = "2" * 40
VERSION = "9.9.9-rc.1"
BUILD_NUMBER = VERSION + ".123"


def iso(offset: int) -> str:
    value = dt.datetime(2026, 8, 10, 12, 0, tzinfo=dt.timezone.utc) + dt.timedelta(seconds=offset)
    return value.isoformat().replace("+00:00", "Z")


def preinstall_clean_ci_fixture() -> dict:
    output = "Passed: 20\nFailed: 0\nALL CHECKS PASSED\n"
    return {
        "command": ["scripts/ci-local.sh", "--clean"],
        "exit_code": 0,
        "output_sha256": qualification.sha256_bytes(output.encode("utf-8")),
        "output_tail": output,
        "output_line_count": len(output.splitlines()),
        "started_at": iso(-3600),
        "completed_at": iso(-3000),
        "source_commit": COMMIT,
        "source_tree": TREE,
        "clean_source_before": True,
        "clean_source_after": True,
    }


def llm_heartbeat_payload(*, healthy: bool, started: int = 0, accepted: int = 0,
                          retries: int = 0, rejected: int = 0,
                          current: int = 0) -> dict:
    def counters(feature: str) -> dict:
        is_alert = feature in ("alert_investigation", "totals")
        return {
            "requestedTotal": started if is_alert else 0,
            "currentInFlight": 0,
            "currentAdmittedBackendRequests": 0,
            "currentCircuitRecoveryProbes": 0,
            "outcomes": {
                "success": started if is_alert else 0,
                "cacheHit": 0,
                "backendFailure": 0,
                "circuitRejection": 0,
                "privacyRejection": 0,
                "admissionShed": 0,
                "cancellation": 0,
                "responseOversize": 0,
            },
            "conservationMaintained": True,
            "backendAdmissionConservationMaintained": True,
            "circuitRecoveryConservationMaintained": True,
            "downstreamValidation": {
                "operationsStartedTotal": started if is_alert else 0,
                "currentOperations": current if is_alert else 0,
                "accepted": accepted if is_alert else 0,
                "retryRequested": retries if is_alert else 0,
                "finalRejection": rejected if is_alert else 0,
            },
        }

    reason_rows = [
        {
            "reason": reason,
            "observedAttempts": (retries + rejected) if index == 0 else 0,
            "terminalRejections": rejected if index == 0 else 0,
        }
        for index, reason in enumerate(qualification.LLM_ALERT_REJECTION_REASONS)
    ]
    result = {
        "configured": True,
        "healthy": healthy,
        "provider": "fixture",
        "model": "fixture-model",
        "consecutive_failures": 0,
        "circuit_open": False,
        "runtime_telemetry": {
            "schemaVersion": 2,
            "totals": counters("totals"),
            "perFeature": [
                {"feature": feature, "counters": counters(feature)}
                for feature in qualification.LLM_FEATURES
            ],
            "alertInvestigationRejections": {
                "observedAttemptsTotal": retries + rejected,
                "terminalRejectionsTotal": rejected,
                "byReason": reason_rows,
            },
        },
    }
    if healthy or started > 0:
        result["last_success_unix"] = 1_786_363_200.0
    return result


def passing_runtime(manifest: dict, manifest_sha: str) -> dict:
    candidate = copy.deepcopy(manifest["candidate"])
    inventory_sha = manifest["artifact_verification"]["payload_inventory"]["sha256"]
    write_windows = [
        {"start_offset_seconds": offset, "end_offset_seconds": offset + 30, "bytes": 512 * 1024}
        for offset in range(0, 900, 30)
    ]
    engine_write_bytes = sum(window["bytes"] for window in write_windows)
    samples = []
    for offset in range(0, 901, 30):
        counter_value = offset + (40_000 if offset >= 330 else 0)
        graph_suppressed = 40_000 if offset >= 330 else 0
        llm_started = 11 if offset >= 330 else 10
        llm_payload = llm_heartbeat_payload(
            healthy=True, started=llm_started, accepted=llm_started
        )
        if offset <= 300:
            rss = 200 * 1024 * 1024
        else:
            rss = 200 * 1024 * 1024 + (offset - 300) * 20 * 1024 * 1024 // 600
        samples.append(
            {
                "offset_seconds": offset,
                "recorded_at": iso(offset),
                "engine_pid": 4321,
                "engine_cpu_seconds_total": offset * 0.1,
                "engine_disk_write_bytes_total": engine_write_bytes * offset // 900,
                "engine_memory_footprint_bytes": rss,
                "gui_background_cpu_percent": 5.0,
                "sequence_pending_steps_evicted_total": 0,
                "sequence_state_continuity_maintained": True,
                "sequence_state_continuity_detail": "nominal",
                "conservation": {
                    name: {
                        "offered": counter_value,
                        "completed": counter_value,
                        "queued": 0,
                        "in_flight": 0,
                        "explicitly_shed": 0,
                    }
                    for name in sorted(qualification.REQUIRED_CONSERVATION_BOUNDARIES)
                },
                "losses": {
                    "priority_lane_loss": 0,
                    "kernel_loss": 0,
                    "callback_copy_loss": 0,
                    "upstream_collector_loss": 0,
                    "unclassified_file_queue_loss": 0,
                },
                "trace_graph_write_accounting": {
                    "ingest_events_total": counter_value,
                    "write_attempts_total": counter_value - graph_suppressed,
                    "write_batches_committed_total": counter_value - graph_suppressed,
                    "write_batches_failed_total": 0,
                    "write_batches_in_flight": 0,
                    "write_rows_attempted_total": (
                        counter_value * 2 - graph_suppressed
                    ),
                    "write_rows_committed_total": (
                        counter_value * 2 - graph_suppressed
                    ),
                    "write_rows_failed_total": 0,
                    "write_rows_in_flight": 0,
                    "entity_observations_total": counter_value,
                    "edge_observations_total": counter_value,
                    "physical_write_suppressed_events_total": graph_suppressed,
                    "physical_write_suppressed_rows_total": graph_suppressed,
                    "coalesced_noop_rows_total": 0,
                    "pending_entity_rows": 0,
                    "pending_edge_rows": 0,
                },
                "trace_graph_recovery_barrier": {
                    "accepting_mutations": True,
                    "recovering": False,
                    "recovery_mutation_waiters": 0,
                    "recovery_mutation_waiter_limit": 1_024,
                    "recovery_mutation_queue_saturated": False,
                    "recovery_mutation_waiter_high_watermark": 0,
                    "recovery_mutation_waits_total": 0,
                    "recovery_mutation_wait_releases_total": 0,
                    "recovery_mutation_wait_cancellations_total": 0,
                    "recovery_mutation_wait_closed_total": 0,
                    "recovery_mutation_wait_saturations_total": 0,
                    "recovery_mutation_wait_nanoseconds_total": 0,
                    "recovery_mutation_max_wait_nanoseconds": 0,
                    "recovery_mutation_oldest_wait_nanoseconds": 0,
                    "recovery_writer_preemptions_total": 0,
                },
                "trace_store_admission": {
                    "enabled": True,
                    "blocked": False,
                    "store_available": True,
                    "recovering": False,
                    "max_footprint_bytes": 200 * 1024 * 1024,
                    "admission_threshold_bytes": 180 * 1024 * 1024,
                    "transaction_reserve_bytes": 8 * 1024 * 1024,
                    "footprint_bytes": 100 * 1024 * 1024,
                    "free_space_bytes": 20 * 1024 * 1024 * 1024,
                    "free_space_floor_bytes": 10 * 1024 * 1024 * 1024,
                },
                "llm_quality": qualification.llm_runtime_quality_sample(
                    {"llm": llm_payload}
                ),
            }
        )
    samples_sha = qualification.sha256_bytes(qualification.canonical_json_bytes(samples))
    gui_samples = [5.0] * len(samples)
    workload_payload = {
        "id": "normal-plus-burst",
        "version": "1",
        "description": "Deterministic fixture normal work plus bounded file/process burst",
        "normal_operations": ["browser", "terminal", "dashboard"],
        "burst_operations": ["process-exec burst", "file-create burst"],
        "executors": [
            {
                "path": relative,
                "sha256": qualification.sha256_file(ROOT / relative),
            }
            for relative in qualification.RUNTIME_WORKLOAD_EXECUTORS
        ],
    }
    workload = dict(workload_payload)
    workload["sha256"] = qualification.sha256_bytes(
        qualification.canonical_json_bytes(workload_payload)
    )
    installed_agent = copy.deepcopy(
        manifest["artifact_verification"]["system_extension"]
    )
    installed_identity = {
        **installed_agent,
        "engine_pid": 4321,
        "executable_path": (
            "/Library/SystemExtensions/fixture/"
            "com.maccrab.agent.systemextension/Contents/MacOS/com.maccrab.agent"
        ),
        "system_extension_bundle_identifier": qualification.EXPECTED_AGENT_IDENTIFIER,
    }
    sqlite_rows = [
        {
            "name": name,
            "max_db_wal_shm_bytes": 100 * 1024 * 1024,
            "configured_cap_bytes": 200 * 1024 * 1024,
            "minimum_free_space_bytes": 20 * 1024 * 1024 * 1024,
            "configured_free_space_floor_bytes": 10 * 1024 * 1024 * 1024,
        }
        for name in sorted(qualification.REQUIRED_SQLITE_FAMILIES)
    ]
    observations = []
    for sample in samples:
        boundaries = sample["conservation"]
        pipeline = {}
        for key, boundary_key in (
            ("offered_by_lane", "offered"),
            ("completed_by_lane", "completed"),
            ("backlog_estimate_by_lane", "queued"),
            ("in_flight_by_lane", "in_flight"),
            ("merged_dropped_by_lane", "explicitly_shed"),
        ):
            pipeline[key] = {
                lane: boundaries[f"{lane}-ingress"][boundary_key]
                for lane in ("priority", "file")
            }
        pipeline["merged_terminated_by_lane"] = {"priority": 0, "file": 0}
        pipeline["upstream_dropped_by_lane"] = {"priority": 0, "file": 0}
        pipeline["upstream_terminated_by_lane"] = {"priority": 0, "file": 0}
        heartbeat = {
            "schema_version": 5,
            "written_at_unix": qualification.parse_time(
                sample["recorded_at"], "fixture sample time"
            ).timestamp(),
            "engine_pid": sample["engine_pid"],
            "engine_version": VERSION,
            "engine_build": BUILD_NUMBER,
            "event_pipeline": pipeline,
            "events_storage_write_offered_by_lane": {
                lane: boundaries[f"{lane}-event-persistence"]["offered"]
                for lane in ("priority", "file")
            },
            "events_storage_write_persisted_by_lane": {
                lane: boundaries[f"{lane}-event-persistence"]["completed"]
                for lane in ("priority", "file")
            },
            "events_storage_write_filtered_by_lane": {"priority": 0, "file": 0},
            "events_storage_write_dropped_by_lane": {
                lane: boundaries[f"{lane}-event-persistence"]["explicitly_shed"]
                for lane in ("priority", "file")
            },
            "events_storage_write_buffer_depth_by_lane": {
                lane: boundaries[f"{lane}-event-persistence"]["queued"]
                for lane in ("priority", "file")
            },
            "events_storage_write_in_flight_depth_by_lane": {
                lane: boundaries[f"{lane}-event-persistence"]["in_flight"]
                for lane in ("priority", "file")
            },
            "event_terminal_revision_offered_total": sum(
                boundaries[f"{lane}-event-terminal-persistence"]["offered"]
                for lane in ("priority", "file")
            ),
            "event_terminal_revision_offered_by_lane": {
                lane: boundaries[f"{lane}-event-terminal-persistence"]["offered"]
                for lane in ("priority", "file")
            },
            "event_terminal_revision_unchanged_total": sum(
                boundaries[f"{lane}-event-terminal-persistence"]["completed"]
                for lane in ("priority", "file")
            ),
            "event_terminal_revision_unchanged_by_lane": {
                lane: boundaries[f"{lane}-event-terminal-persistence"]["completed"]
                for lane in ("priority", "file")
            },
            "event_terminal_revision_durable_total": 0,
            "event_terminal_revision_durable_by_lane": {
                "priority": 0, "file": 0
            },
            "event_terminal_revision_dropped_total": sum(
                boundaries[f"{lane}-event-terminal-persistence"][
                    "explicitly_shed"
                ]
                for lane in ("priority", "file")
            ),
            "event_terminal_revision_dropped_by_lane": {
                lane: boundaries[f"{lane}-event-terminal-persistence"][
                    "explicitly_shed"
                ]
                for lane in ("priority", "file")
            },
            "event_terminal_revision_poisoned_total": 0,
            "event_terminal_revision_poisoned_by_lane": {
                "priority": 0, "file": 0
            },
            "event_terminal_revision_retried_total": 0,
            "event_terminal_revision_retried_by_lane": {
                "priority": 0, "file": 0
            },
            "event_terminal_revision_buffer_depth": sum(
                boundaries[f"{lane}-event-terminal-persistence"]["queued"]
                for lane in ("priority", "file")
            ),
            "event_terminal_revision_buffer_depth_by_lane": {
                lane: boundaries[f"{lane}-event-terminal-persistence"]["queued"]
                for lane in ("priority", "file")
            },
            "event_terminal_revision_buffer_bytes": 0,
            "event_terminal_revision_buffer_bytes_by_lane": {
                "priority": 0, "file": 0
            },
            "event_terminal_revision_in_flight_depth": sum(
                boundaries[f"{lane}-event-terminal-persistence"]["in_flight"]
                for lane in ("priority", "file")
            ),
            "event_terminal_revision_in_flight_depth_by_lane": {
                lane: boundaries[f"{lane}-event-terminal-persistence"]["in_flight"]
                for lane in ("priority", "file")
            },
            "event_terminal_revision_in_flight_bytes": 0,
            "event_terminal_revision_in_flight_bytes_by_lane": {
                "priority": 0, "file": 0
            },
            "event_terminal_revision_conservation": True,
            "event_terminal_revision_evidence_poisoned": False,
            "event_terminal_revision_storage_mutation_generation": 0,
            "event_journal_repairable_gap_count": 0,
            "event_journal_repair_payload_lease_count": 0,
            "event_journal_repair_payload_expired_total": 0,
            "sequence_checkpoint": {
                "conservation": boundaries["sequence-checkpoint"]
            },
            "sequence_pending_steps_evicted_total": sample[
                "sequence_pending_steps_evicted_total"
            ],
            "sequence_pending_steps_current": boundaries[
                "sequence-journal"
            ]["queued"],
            "sequence_journal_conservation": boundaries["sequence-journal"],
            "sequence_state_continuity_maintained": True,
            "sequence_state_continuity_detail": "nominal",
            "tracegraph_storage_admission": {
                "enabled": True,
                **sample["trace_graph_recovery_barrier"],
                "blocked": False,
                "store_available": True,
                "recovering": False,
                "shed_mutations_total": 0,
                "ingest_events_total": boundaries["trace-graph-mutation"]["offered"],
                "ingest_events_committed_total": boundaries["trace-graph-mutation"]["completed"],
                "ingest_events_failed_total": boundaries["trace-graph-mutation"]["explicitly_shed"],
                "ingest_events_pending": boundaries["trace-graph-mutation"]["queued"],
                "ingest_events_in_flight": boundaries["trace-graph-mutation"]["in_flight"],
                **sample["trace_graph_write_accounting"],
            },
            "traces_storage_admission": {
                "enabled": True,
                "blocked": False,
                "store_available": True,
                "recovering": False,
                "shed_mutations_total": 0,
                "ingest_conservation": boundaries["trace-store-ingest"],
                "max_footprint_bytes": 200 * 1024 * 1024,
                "admission_threshold_bytes": 180 * 1024 * 1024,
                "transaction_reserve_bytes": 8 * 1024 * 1024,
                "footprint_bytes": 100 * 1024 * 1024,
                "free_space_bytes": 20 * 1024 * 1024 * 1024,
                "free_space_floor_bytes": 10 * 1024 * 1024 * 1024,
            },
            "event_type_count_window": {
                "query_available": True,
                "mutation_generation": counter_value,
                "requested_duration_seconds": 3_600,
                "effective_duration_seconds": min(
                    900, sample["offset_seconds"]
                ),
                "requested_window_complete": False,
                "complete": False,
                "canonical_poison_records": 0,
                "corrupt_legacy_records": 0,
                "inherited_legacy_loss_records": 0,
                "resource_limited_records": 0,
                "gap_records": 0,
            },
            "event_search_projection": {
                "query_available": True,
                "mutation_generation": counter_value,
                "requested_duration_seconds": 3_600,
                "effective_duration_seconds": min(
                    900, sample["offset_seconds"]
                ),
                "requested_window_complete": False,
                "projection_considered": counter_value,
                "projection_materialized": min(counter_value, 4),
                "projection_omitted_quota": max(0, counter_value - 4),
                "projection_omitted_replaced": 0,
                "projection_omitted_physical": 0,
                "projection_omitted_external": 0,
                "projection_omitted_migration": 0,
                "projection_pending": 0,
                "projection_omitted_total": max(0, counter_value - 4),
                "canonical_poison_records": 0,
                "corrupt_legacy_records": 0,
                "inherited_legacy_loss_records": 0,
                "resource_limited_records": 0,
                "gap_records_total": 0,
                "complete": False,
            },
            "rule_sync": {
                "status": "unchanged",
                "version": manifest["artifact_verification"]["rule_corpus"][
                    "bundle_version"
                ],
                "bundled_tampered": False,
                "installed_tampered": False,
                "installed_corpus_verified": True,
                "installed_manifest_sha256": manifest[
                    "artifact_verification"
                ]["rule_corpus"]["manifest_sha256"],
                "installed_manifest_hash_entry_count": manifest[
                    "artifact_verification"
                ]["rule_corpus"]["manifest_hash_entry_count"],
            },
            "event_journal_recovery": {
                "source_events": 10,
                "migrated_events": 8,
                "rolled_expired_events": 1,
                "corrupt_preserved_events": 1,
                "remaining_events": 0,
                "complete": True,
                "conserved": True,
            },
            "events_retention_budget": {
                "state": "converged",
                "sticky": False,
            },
            "alert_evidence_budget": {
                "events_family_effective_cap_bytes": 340 * 1024 * 1024,
                "alerts_family_combined_cap_bytes": 200 * 1024 * 1024,
                "alerts_family_footprint_bytes": 100 * 1024 * 1024,
                "alerts_family_admission_cap_bytes": 200 * 1024 * 1024,
                "alerts_family_transaction_reserve_bytes": 8 * 1024 * 1024,
                "alerts_family_admission_boundary_bytes": 192 * 1024 * 1024,
                "alerts_family_recovery_target_bytes": 184 * 1024 * 1024,
                "alerts_family_blocked": False,
                "alerts_family_reason": "",
                "over_budget": False,
                "capture_offered_total": 0,
                "capture_completed_total": 0,
                "capture_failures_total": 0,
                "capture_shed_total": 0,
                "capture_pending": 0,
                "capture_in_flight": 0,
                "capture_accepting": True,
                "capture_conserved": True,
                "legacy_transition_measurement_failed": False,
            },
            "es_kernel_dropped_total": 0,
            "es_copy_backpressure_dropped_total": 0,
            "es_stream_yield_dropped_total": 0,
            "deferred_enrichment_buffer": {
                "identity_rejected_patches_total": 0,
                "reservation_conserved": True,
                "slots_conserved": True,
                "events_conserved": True,
                "raw_event_bytes_conserved": True,
                "patches_conserved": True,
                "patch_bytes_conserved": True,
                "within_capacity": True,
            },
            "llm": llm_heartbeat_payload(
                healthy=True,
                started=11 if sample["offset_seconds"] >= 330 else 10,
                accepted=11 if sample["offset_seconds"] >= 330 else 10,
            ),
        }
        heartbeat_raw_json = qualification.canonical_json_bytes(heartbeat).decode(
            "utf-8"
        )
        observations.append(
            {
                "schema": qualification.RUNTIME_OBSERVATION_SCHEMA,
                "offset_seconds": sample["offset_seconds"],
                "recorded_at": sample["recorded_at"],
                "captured_at": sample["recorded_at"],
                "heartbeat": heartbeat,
                "heartbeat_file": {
                    "path": "/Library/Application Support/MacCrab/heartbeat_rich.json",
                    "raw_json": heartbeat_raw_json,
                    "raw_sha256": qualification.sha256_bytes(
                        heartbeat_raw_json.encode("utf-8")
                    ),
                    "canonical_sha256": qualification.sha256_bytes(
                        qualification.canonical_json_bytes(heartbeat)
                    ),
                    "owner_uid": 0,
                    "mode": 0o600,
                    "mtime_unix": heartbeat["written_at_unix"],
                },
                "process": {
                    "engine_cpu_seconds_total": sample["engine_cpu_seconds_total"],
                    "engine_disk_write_bytes_total": sample[
                        "engine_disk_write_bytes_total"
                    ],
                    "engine_memory_footprint_bytes": sample["engine_memory_footprint_bytes"],
                    "executable_path": installed_identity["executable_path"],
                    "executable_sha256": installed_identity["executable_sha256"],
                },
                "gui_background_cpu_percent": sample[
                    "gui_background_cpu_percent"
                ],
                "sqlite_families": {
                    row["name"]: {
                        "footprint_bytes": row["max_db_wal_shm_bytes"],
                        "configured_cap_bytes": row["configured_cap_bytes"],
                        "free_space_bytes": row["minimum_free_space_bytes"],
                        "configured_free_space_floor_bytes": row[
                            "configured_free_space_floor_bytes"
                        ],
                    }
                    for row in sqlite_rows
                },
                "trace_writable": True,
                "trace_recovering": False,
                "trace_shed_mutations_total": 0,
                "event_budget_fault": False,
            }
        )
    def probe(command: list[str], output: str = "") -> dict:
        return {
            "command": command,
            "exit_code": 0,
            "output_sha256": qualification.sha256_bytes(output.encode("utf-8")),
            "output_tail": output[-4096:],
            "output_line_count": len(output.splitlines()),
        }

    reload_output = (
        "[SIGHUP] Reloaded 438 single + 41 sequence rules "
        "(rule_profile stable governs the sequence/graph reload)\n"
    )
    def investigation_json(alert_id: str) -> str:
        return json.dumps(
            {
                "alertId": alert_id,
                "confidence": 0.75,
                "verdict": "needs_human",
                "summary": "Deterministic qualification investigation.",
                "evidenceChain": [],
                "mitreReasoning": [],
                "suggestedActions": [],
                "confidencePenalties": [],
                "modelVersion": "fixture-model",
                "generatedAt": 0.0,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def alert_proof(
        *, phase: str, run_id: str, alert_id: str, trigger_offset: int,
        observed_offset: int, before: dict, after: dict,
    ) -> dict:
        alert_path, _ = qualification.workload_paths(run_id)
        investigation = investigation_json(alert_id)
        trigger_time = qualification.parse_time(
            iso(trigger_offset), "fixture alert trigger"
        )
        return {
            "phase": phase,
            "database": {
                "path": "/Library/Application Support/MacCrab/alerts.db",
                "owner_uid": 0,
                "mode": 0o600,
                "device": 1,
                "inode": 1,
                "read_only": True,
                "no_follow": True,
                "bound_process_path": alert_path,
                "triggered_after_unix": trigger_time.timestamp(),
            },
            "process_path": alert_path,
            "trigger_started_at": iso(trigger_offset),
            "alert": {
                "id": alert_id,
                "timestamp_unix": trigger_time.timestamp() + 0.25,
                "rule_id": "maccrab.qualification.reverse-shell",
                "severity": "high",
            },
            # Mirrors what causal_alert_proof_if_ready actually emits. This
            # fixture used to build the proof by hand without it, so the suite
            # stayed green while the real recorder failed its own inventory
            # check on the first installed-host run.
            "observed_alerts": [
                {
                    "id": alert_id,
                    "rule_id": "maccrab.qualification.reverse-shell",
                    "severity": "high",
                },
            ],
            "investigation_json": investigation,
            "investigation_sha256": qualification.sha256_bytes(
                investigation.encode("utf-8")
            ),
            "telemetry_before": copy.deepcopy(before),
            "telemetry_after": copy.deepcopy(after),
            "observed_at": iso(observed_offset),
        }

    prewarm_run_id = "b" * 32
    workload_run_id = "c" * 32
    prewarm_before = qualification.llm_runtime_quality_sample(
        {"llm": llm_heartbeat_payload(healthy=False, started=0, accepted=0)}
    )
    prewarm_after = qualification.llm_runtime_quality_sample(
        {"llm": llm_heartbeat_payload(healthy=True, started=1, accepted=1)}
    )
    prewarm_proof = alert_proof(
        phase="prewarm", run_id=prewarm_run_id,
        alert_id="11111111-1111-4111-8111-111111111111",
        trigger_offset=-120, observed_offset=-60,
        before=prewarm_before, after=prewarm_after,
    )
    workload_before = next(
        sample["llm_quality"] for sample in samples
        if sample["offset_seconds"] == qualification.BURST_START_OFFSET_SECONDS
    )
    workload_after = next(
        sample["llm_quality"] for sample in samples
        if sample["offset_seconds"] == 330
    )
    workload_proof = alert_proof(
        phase="epoch", run_id=workload_run_id,
        alert_id="22222222-2222-4222-8222-222222222222",
        trigger_offset=qualification.BURST_START_OFFSET_SECONDS,
        observed_offset=330, before=workload_before, after=workload_after,
    )
    prewarm_alert_path, _ = qualification.workload_paths(prewarm_run_id)
    workload_alert_path, workload_bulk_path = qualification.workload_paths(
        workload_run_id
    )
    prewarm_output = (
        f"IDENTITY: run_id={prewarm_run_id} "
        f"alert_executable={prewarm_alert_path} "
        f"bulk_path=/Users/Shared/MacCrabQualificationRuntime-{prewarm_run_id}\n"
        f"PASS: fixed alert-only workload completed run_id={prewarm_run_id} "
        "alert_triggers=1\n"
    )
    workload_output = (
        f"IDENTITY: run_id={workload_run_id} "
        f"alert_executable={workload_alert_path} bulk_path={workload_bulk_path}\n"
        f"PASS: fixed workload completed run_id={workload_run_id} "
        "iterations=20000 otlp_spans=1 alert_triggers=1 sequence_probes=1\n"
    )
    evidence = {
        "preinstall_clean_ci": copy.deepcopy(manifest["preinstall_clean_ci"]),
        "llm_prewarm": {
            **probe(
                [
                    "/bin/bash", str(ROOT / "scripts/runtime-qualification-workload.sh"),
                    "--alert-only", "--run-id", prewarm_run_id,
                ],
                prewarm_output,
            ),
            "run_id": prewarm_run_id,
            "alert_executable": prewarm_alert_path,
            "started_at": iso(-120),
            "completed_at": iso(-60),
            "alert_investigation": prewarm_proof,
        },
        "workload": {
            **probe(
                [
                    "/bin/bash", str(ROOT / "scripts/runtime-qualification-workload.sh"),
                    "--run-id", workload_run_id,
                ],
                workload_output,
            ),
            "run_id": workload_run_id,
            "alert_executable": workload_alert_path,
            "bulk_path": workload_bulk_path,
            "started_at": iso(qualification.BURST_START_OFFSET_SECONDS),
            "completed_at": iso(360),
            "deadline_offset_seconds": qualification.BURST_END_OFFSET_SECONDS,
            "drain_offset_seconds": qualification.BURST_DRAIN_OFFSET_SECONDS,
            "sequence_path_isolation":
                qualification.validate_workload_sequence_path_isolation(
                    ROOT, workload_bulk_path
                ),
            "alert_investigation": workload_proof,
        },
        "disk_diagnostic_log": probe(["/usr/bin/log", "show", "disk"]),
        "storage_convergence_log": probe(["/usr/bin/log", "show", "storage"]),
        "administrator_prompt_log": probe(["/usr/bin/log", "show", "auth"]),
        "rule_reload_log": {
            **probe(["/usr/bin/log", "show", "reload"], reload_output),
            "output": reload_output,
        },
        "live_sighup": {
            "signal": "SIGHUP",
            "target_pid": 4321,
            "sample_offset_seconds": 450,
            "sent_at": iso(450),
        },
    }
    probes = {
        "installed_engine_start": {**installed_identity, "recorded_at": iso(0)},
        "installed_engine_end": {**installed_identity, "recorded_at": iso(900)},
        "crash_count": 0,
        "watchdog_exit_count": 0,
        "complete_rule_corpus_evaluated": True,
        "rule_corpus_sha256": "c" * 64,
        "semantic_reasons": [],
        "prune_vacuum_refill_loop_count": 0,
        "macos_disk_writes_diagnostic_count": 0,
        "rules": {
            "sealed_rules_synchronized_before_readers": True,
            "corpus_parity": True,
            "ordinary_launch_without_admin_prompt": True,
        },
        "shipped_tools": {
            "maccrabctl": {
                "path": "/Volumes/MacCrab/MacCrab.app/Contents/Resources/bin/maccrabctl",
                "exit_code": 0,
                "version_output": "maccrabctl " + VERSION,
                "sip_amfi_normal": True,
            },
            "maccrab_mcp": {
                "path": "/Volumes/MacCrab/MacCrab.app/Contents/Resources/bin/maccrab-mcp",
                "exit_code": 0,
                "version_output": "maccrab-mcp " + VERSION,
                "sip_amfi_normal": True,
            },
        },
        "evidence": evidence,
    }
    host = {
        "machine_id_sha256": "a" * 64,
        "hardware_model": "Mac15,1",
        "architecture": "arm64",
        "logical_cpu_count": 10,
        "memory_bytes": 16 * 1024 * 1024 * 1024,
        "macos_version": "26.0",
        "macos_build": "25A123",
        "sip_enabled": True,
        "amfi_enforced": True,
        "power_source": "AC",
    }
    return qualification.build_runtime_report_from_observations(
        candidate_manifest=manifest,
        candidate_manifest_sha256=manifest_sha,
        observations=observations,
        host=host,
        workload=workload,
        probes=probes,
        capture_mode="deterministic-fixture",
    )


class CandidateQualificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="maccrab-qualification-test.")
        self.root = pathlib.Path(self.temporary.name)
        self.dmg = self.root / f"MacCrab-v{VERSION}.dmg"
        self.dmg.write_bytes(b"deterministic signed candidate fixture\n")
        self.manifest = qualification.candidate_document(
            version=VERSION,
            build_number=BUILD_NUMBER,
            source_commit=COMMIT,
            source_tree=TREE,
            dmg=self.dmg,
            inspection_level="digest",
            notarization_submission_id="",
            preinstall_clean_ci=preinstall_clean_ci_fixture(),
        )
        self.manifest_path = self.root / "candidate.json"
        qualification.write_json_exclusive(self.manifest_path, self.manifest)
        self.manifest_sha = qualification.sha256_file(self.manifest_path)
        self.runtime = passing_runtime(self.manifest, self.manifest_sha)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def validate_candidate(self) -> dict:
        return qualification.validate_candidate_document(
            self.manifest,
            expected_version=VERSION,
            expected_source_commit=COMMIT,
            expected_source_tree=TREE,
            expected_build_number=BUILD_NUMBER,
            dmg=self.dmg,
            artifact_checks="digest",
        )

    @staticmethod
    def rehash_payload_inventory(manifest: dict) -> None:
        inventory = manifest["artifact_verification"]["payload_inventory"]
        inventory["entry_count"] = len(inventory["entries"])
        inventory["sha256"] = qualification.sha256_bytes(
            qualification.canonical_json_bytes(inventory["entries"])
        )

    def validate_runtime(self, report: dict | None = None) -> None:
        qualification.validate_runtime_report(
            self.runtime if report is None else report,
            candidate_manifest_sha256=self.manifest_sha,
            candidate=self.validate_candidate(),
            candidate_verification=self.manifest["artifact_verification"],
            candidate_preinstall_clean_ci=self.manifest["preinstall_clean_ci"],
            payload_inventory_sha256=self.manifest["artifact_verification"]["payload_inventory"]["sha256"],
            source_root=ROOT,
            allow_test_fixture=True,
        )

    def test_runtime_template_tracks_exact_trace_graph_aggregate_schema(self) -> None:
        """The deliberately failing template must still name every live field.

        Operators use this document to see what evidence the recorder must
        produce.  Omitting newly required ledger fields makes the template
        stale even though its overall result remains intentionally INCOMPLETE.
        """
        template = qualification.make_runtime_template(
            self.manifest, self.manifest_sha
        )
        template_trace = template["measurements"]["trace_graph"]
        live_trace = self.runtime["measurements"]["trace_graph"]
        self.assertEqual(set(template_trace), set(live_trace))
        self.assertEqual(template["result"], "INCOMPLETE")

    def recorder_probes(self) -> dict:
        measurements = self.runtime["measurements"]
        process = measurements["process"]
        return {
            "installed_engine_start": copy.deepcopy(
                self.runtime["installed_engine"]["start"]
            ),
            "installed_engine_end": copy.deepcopy(
                self.runtime["installed_engine"]["end"]
            ),
            "crash_count": process["crash_count"],
            "watchdog_exit_count": process["watchdog_exit_count"],
            "complete_rule_corpus_evaluated": measurements["file_fidelity"][
                "complete_rule_corpus_evaluated"
            ],
            "rule_corpus_sha256": measurements["file_fidelity"][
                "rule_corpus_sha256"
            ],
            "semantic_reasons": copy.deepcopy(
                measurements["file_fidelity"]["semantic_reasons"]
            ),
            "prune_vacuum_refill_loop_count": measurements["event_storage"][
                "prune_vacuum_refill_loop_count"
            ],
            "search_tier_gaps_reconcile_exactly": measurements["event_storage"][
                "search_tier_gaps_reconcile_exactly"
            ],
            "search_tier_gaps_visible": measurements["event_storage"][
                "search_tier_gaps_visible"
            ],
            "macos_disk_writes_diagnostic_count": measurements["disk_writes"][
                "macos_disk_writes_diagnostic_count"
            ],
            "rules": copy.deepcopy(measurements["rules"]),
            "shipped_tools": copy.deepcopy(measurements["shipped_tools"]),
            "evidence": copy.deepcopy(self.runtime["recorder_probe_evidence"]),
        }

    def rebuild_runtime_from_observations(
        self, observations: list[dict]
    ) -> dict:
        return qualification.build_runtime_report_from_observations(
            candidate_manifest=self.manifest,
            candidate_manifest_sha256=self.manifest_sha,
            observations=observations,
            host=copy.deepcopy(self.runtime["host"]),
            workload=copy.deepcopy(self.runtime["workload"]),
            probes=self.recorder_probes(),
            capture_mode="deterministic-fixture",
        )

    def containment_report(self) -> dict:
        def transcript(command: list[str], output: str) -> dict:
            return {
                "command": command,
                "exit_code": 0,
                "output_sha256": qualification.sha256_bytes(
                    output.encode("utf-8")
                ),
                "output_tail": output[-4096:],
                "output_line_count": len(output.splitlines()),
                "output": output,
            }

        root_text = str(ROOT)
        environment = qualification.containment_process_environment()
        workspace = "/fixture/private/tmp/exact-containment"
        build_scratch = (
            f"{workspace}/{qualification.CONTAINMENT_BUILD_SCRATCH_NAME}"
        )
        builds = []
        for product in qualification.CONTAINMENT_FIXTURE_PRODUCTS:
            build = transcript(
                [
                    "/usr/bin/xcrun", "swift", "build", "-c", "release", "--package-path",
                    root_text, "--scratch-path", build_scratch,
                    "--product", product,
                ],
                f"Build of {product} complete! (0.1s)\n",
            )
            build["environment"] = copy.deepcopy(environment)
            builds.append(build)
        bin_dir = f"{build_scratch}/arm64-apple-macosx/release"
        bin_path = transcript(
            [
                "/usr/bin/xcrun", "swift", "build", "-c", "release", "--package-path",
                root_text, "--scratch-path", build_scratch, "--show-bin-path",
            ],
            bin_dir + "\n",
        )
        bin_path["environment"] = copy.deepcopy(environment)
        mountpoint = "/fixture/Volumes/MacCrab"
        payload_entries = {
            row["path"]: row
            for row in self.manifest["artifact_verification"]["payload_inventory"]["entries"]
        }
        candidate_binaries = []
        for role, (relative, identifier) in qualification.CONTAINMENT_CANDIDATE_BINARIES.items():
            payload = payload_entries[relative]
            candidate_binaries.append(
                {
                    "role": role,
                    "relative_path": relative,
                    "sha256": payload["sha256"],
                    "size_bytes": payload["size_bytes"],
                    "developer_id": qualification.EXPECTED_DEVELOPER_ID,
                    "team_id": qualification.EXPECTED_TEAM_ID,
                    "signing_identifier": identifier,
                    "cdhash": "a" * 40,
                }
            )
        candidate_execution = {
            "dmg_sha256": self.manifest["candidate"]["dmg"]["sha256"],
            "mountpoint": mountpoint,
            "mount": transcript(
                [
                    "/usr/bin/hdiutil", "attach", "-readonly", "-nobrowse",
                    "-plist", str(self.dmg),
                ],
                f"<plist><string>{mountpoint}</string></plist>\n",
            ),
            "binaries": candidate_binaries,
        }
        candidate_execution["mount"]["environment"] = copy.deepcopy(environment)
        fixture_inputs = [
            {
                "role": role,
                "product": product,
                "path": f"{bin_dir}/{product}",
                "sha256": digest,
                "size_bytes": 4096,
            }
            for role, product, digest in (
                ("c-probe", qualification.CONTAINMENT_FIXTURE_PRODUCTS[0], "b" * 64),
                ("swift-probe", qualification.CONTAINMENT_FIXTURE_PRODUCTS[1], "c" * 64),
            )
        ]
        loopback_command = [
            "/usr/bin/nc", "-G", "3", "-z",
            qualification.CONTAINMENT_LOOPBACK_HOST,
            str(qualification.CONTAINMENT_LOOPBACK_PORT),
        ]

        def reachability(peer_port: int) -> dict:
            probe = transcript(loopback_command, "")
            probe["environment"] = copy.deepcopy(environment)
            return {
                "probe": probe,
                "accepted_peer_host": qualification.CONTAINMENT_LOOPBACK_HOST,
                "accepted_peer_port": peer_port,
            }

        network_control = {
            "host": qualification.CONTAINMENT_LOOPBACK_HOST,
            "port": qualification.CONTAINMENT_LOOPBACK_PORT,
            "unsandboxed_reachable": True,
            "pre_run": reachability(51001),
            "post_run": reachability(51004),
        }
        fixture_by_role = {row["role"]: row for row in fixture_inputs}
        unsandboxed_controls = []
        for index, role in enumerate(qualification.CONTAINMENT_UNSANDBOXED_LEAKS):
            scratch = f"{workspace}/unsandboxed-{role}"
            request = qualification.canonical_json_bytes(
                {"scratchDir": scratch}
            ).decode("utf-8")
            output = "".join(
                "{\"kind\":\"artifact\",\"artifact\":{"
                f"\"contentType\":\"{leak}\","
                "\"privacyClass\":\"metadata\",\"summary\":\"control\","
                "\"data\":{}}}\n"
                for leak in qualification.CONTAINMENT_UNSANDBOXED_LEAKS[role]
            )
            output += (
                "{\"kind\":\"result\",\"result\":{\"status\":\"ok\","
                "\"notes\":[\"control complete\"]}}\n"
            )
            probe = transcript([fixture_by_role[role]["path"]], output)
            probe["environment"] = copy.deepcopy(environment)
            probe["stdin"] = request
            probe["stdin_sha256"] = qualification.sha256_bytes(
                request.encode("utf-8")
            )
            unsandboxed_controls.append(
                {
                    "role": role,
                    "binary_sha256": fixture_by_role[role]["sha256"],
                    "scratch_path": scratch,
                    "expected_leaks": list(
                        qualification.CONTAINMENT_UNSANDBOXED_LEAKS[role]
                    ),
                    "accepted_peer_host": qualification.CONTAINMENT_LOOPBACK_HOST,
                    "accepted_peer_port": 51002 + index,
                    "probe": probe,
                }
            )

        key_dir = f"{workspace}/keys"
        candidate_cli = (
            mountpoint + "/"
            + qualification.CONTAINMENT_CANDIDATE_BINARIES["maccrabctl"][0]
        )
        keygen = transcript(
            [candidate_cli, "plugin", "keygen", "--out", key_dir],
            "Generated Tier-B signing keypair:\n  Public hex:   fixture\n",
        )
        keygen["environment"] = copy.deepcopy(environment)
        candidate_by_role = {row["role"]: row for row in candidate_binaries}
        bundle_runs = []
        for name, plugin_id, expected_artifact in qualification.CONTAINMENT_RUNS:
            bundle = f"/fixture/private/tmp/exact-containment/bundle-{name}"
            manifest = qualification.containment_plugin_manifest(plugin_id)
            source_role = "candidate-example" if name == "example" else name
            source_sha = (
                candidate_by_role["example"]["sha256"]
                if name == "example" else fixture_by_role[name]["sha256"]
            )
            sign = transcript(
                [
                    candidate_cli, "plugin", "sign", bundle,
                    "--key", f"{key_dir}/signing.key",
                ],
                f"Signed bundle {bundle}\n",
            )
            sign["environment"] = copy.deepcopy(environment)
            run_output = (
                f"Testing {plugin_id} v1.0.0\n"
                "Ran under the sandboxed third-party lane:\n"
                "  Exit code:    0\n"
                "  Result:       ok\n"
                "  Artifacts:    1\n"
                f"    - {expected_artifact}: qualification fixture\n"
                "  ✓ ran CONTAINED (deny-default sandbox; file reads brokered over fd 3).\n"
            )
            run = transcript(
                [candidate_cli, "plugin", "test", bundle], run_output
            )
            run["environment"] = copy.deepcopy(environment)
            bundle_runs.append(
                {
                    "name": name,
                    "plugin_id": plugin_id,
                    "expected_artifact": expected_artifact,
                    "source_role": source_role,
                    "source_sha256": source_sha,
                    "manifest": manifest,
                    "manifest_sha256": qualification.sha256_bytes(
                        qualification.canonical_json_bytes(manifest)
                    ),
                    "binary_sha256": source_sha,
                    "signature_sha256": "d" * 64,
                    "publisher_key_sha256": "e" * 64,
                    "sign": sign,
                    "run": run,
                }
            )
        return qualification.containment_document(
            version=VERSION,
            source_commit=COMMIT,
            source_tree=TREE,
            candidate_manifest_sha256=self.manifest_sha,
            candidate=self.manifest["candidate"],
            root=ROOT,
            started_at=iso(0),
            ended_at=iso(10),
            capture_mode="deterministic-fixture",
            workspace=workspace,
            build_scratch_path=build_scratch,
            candidate_execution=candidate_execution,
            build_evidence=builds,
            bin_path_evidence=bin_path,
            network_control=network_control,
            unsandboxed_controls=unsandboxed_controls,
            keygen_evidence=keygen,
            fixture_inputs=fixture_inputs,
            bundle_runs=bundle_runs,
        )

    def validate_containment(self, report: dict) -> None:
        qualification.validate_containment_report(
            report,
            version=VERSION,
            source_commit=COMMIT,
            source_tree=TREE,
            candidate_manifest_sha256=self.manifest_sha,
            candidate=self.manifest["candidate"],
            candidate_verification=self.manifest["artifact_verification"],
            root=ROOT,
            allow_test_fixture=True,
        )

    @staticmethod
    def rehash_samples(report: dict) -> None:
        digest = qualification.sha256_bytes(
            qualification.canonical_json_bytes(report["samples"])
        )
        report["epoch"]["samples_sha256"] = digest
        report["evidence"]["raw_samples_sha256"] = digest
        report["evidence"]["observations_sha256"] = qualification.sha256_bytes(
            qualification.canonical_json_bytes(report["recorder_observations"])
        )

    @staticmethod
    def rebind_observation_heartbeat(observation: dict) -> None:
        heartbeat_raw_json = qualification.canonical_json_bytes(
            observation["heartbeat"]
        ).decode("utf-8")
        observation["heartbeat_file"]["raw_json"] = heartbeat_raw_json
        observation["heartbeat_file"]["raw_sha256"] = qualification.sha256_bytes(
            heartbeat_raw_json.encode("utf-8")
        )
        observation["heartbeat_file"][
            "canonical_sha256"
        ] = qualification.sha256_bytes(
            qualification.canonical_json_bytes(observation["heartbeat"])
        )
        observation["heartbeat_file"]["mtime_unix"] = observation["heartbeat"][
            "written_at_unix"
        ]

    @classmethod
    def rederive_sample(cls, report: dict, index: int) -> None:
        observation = report["recorder_observations"][index]
        cls.rebind_observation_heartbeat(observation)
        report["samples"][index] = qualification.sample_from_recorder_observation(
            observation,
            f"fixture.observations[{index}]",
        )
        cls.rehash_samples(report)

    def test_complete_report_passes_every_threshold(self) -> None:
        self.validate_runtime()

    def test_darwin_rusage_v4_layout_covers_native_write(self) -> None:
        self.assertEqual(ctypes.sizeof(qualification.DarwinRUsageInfoV4), 296)
        self.assertEqual(
            qualification.DarwinRUsageInfoV4.ri_diskio_byteswritten.offset,
            152,
        )
        # The memory bound reads this field, so its offset is load-bearing:
        # a wrong one silently gates on some other counter entirely.
        self.assertEqual(
            qualification.DarwinRUsageInfoV4.ri_phys_footprint.offset,
            72,
        )
        self.assertEqual(
            qualification.DarwinRUsageInfoV4.ri_resident_size.offset,
            64,
        )

    def test_prewarm_readiness_allows_a_first_investigation_in_flight(self) -> None:
        """`healthy` means "has succeeded once", so the first one is in limbo.

        Mirrors the live prewarm poll, which passes require_drained=False --
        an investigation in flight is exactly what that phase is waiting for.

        The prewarm phase exists to drive the first alert investigation. While
        a local 7B model works on it (15-30s on the reference host) the backend
        is unhealthy AND used -- the state this check used to call fatal, so
        the prewarm tripped on its own action and only passed when some earlier
        alert had already made the backend healthy. Judge by evidence of
        failure, not by a success that is still pending.
        """
        report = copy.deepcopy(self.runtime)
        observation = report["recorder_observations"][0]

        # First investigation running: unhealthy, used, in flight, no failures.
        observation["heartbeat"]["llm"] = llm_heartbeat_payload(
            healthy=False, started=1, accepted=0, current=1
        )
        self.rederive_sample(report, 0)
        qualification.validate_runtime_readiness(
            observation, "fixture prewarm", phase="fixture prewarm",
            require_drained=False, expected_pid=4321, require_llm_ready=False,
        )

        # Used, unhealthy, and NOT in flight: it produced nothing. Still fatal.
        # "Used" is marked by a prior success rather than a started count, so
        # the fixture keeps downstreamValidation conserving
        # (started == current + accepted + rejection).
        observation["heartbeat"]["llm"] = llm_heartbeat_payload(
            healthy=False, started=0, accepted=0, current=0
        )
        observation["heartbeat"]["llm"]["last_success_unix"] = 1_786_363_200.0
        self.rederive_sample(report, 0)
        with self.assertRaisesRegex(
            qualification.QualificationError, "not a first investigation still in flight"
        ):
            qualification.validate_runtime_readiness(
                observation, "fixture prewarm", phase="fixture prewarm",
                require_drained=False, expected_pid=4321, require_llm_ready=False,
            )

        # In flight but the backend is already failing: still fatal.
        observation["heartbeat"]["llm"] = llm_heartbeat_payload(
            healthy=False, started=1, accepted=0, current=1
        )
        observation["heartbeat"]["llm"]["consecutive_failures"] = 2
        self.rederive_sample(report, 0)
        with self.assertRaisesRegex(
            qualification.QualificationError, "not a first investigation still in flight"
        ):
            qualification.validate_runtime_readiness(
                observation, "fixture prewarm", phase="fixture prewarm",
                require_drained=False, expected_pid=4321, require_llm_ready=False,
            )

        # In flight but the circuit is open: still fatal.
        observation["heartbeat"]["llm"] = llm_heartbeat_payload(
            healthy=False, started=1, accepted=0, current=1
        )
        observation["heartbeat"]["llm"]["circuit_open"] = True
        self.rederive_sample(report, 0)
        with self.assertRaisesRegex(
            qualification.QualificationError, "not a first investigation still in flight"
        ):
            qualification.validate_runtime_readiness(
                observation, "fixture prewarm", phase="fixture prewarm",
                require_drained=False, expected_pid=4321, require_llm_ready=False,
            )

    def test_pre_prewarm_readiness_allows_only_uninitialized_llm(self) -> None:
        report = copy.deepcopy(self.runtime)
        observation = report["recorder_observations"][0]
        observation["heartbeat"]["llm"] = llm_heartbeat_payload(
            healthy=False, started=0, accepted=0
        )
        self.rederive_sample(report, 0)
        qualification.validate_runtime_readiness(
            observation, "fixture prewarm", phase="fixture prewarm",
            require_drained=True, expected_pid=4321,
            require_llm_ready=False,
        )
        with self.assertRaisesRegex(
            qualification.QualificationError, "not healthy"
        ):
            qualification.validate_runtime_readiness(
                observation, "fixture post-prewarm", phase="fixture post-prewarm",
                require_drained=True, expected_pid=4321,
                require_llm_ready=True,
            )

        observation["heartbeat"]["llm"]["last_success_unix"] = 1_786_363_200.0
        self.rederive_sample(report, 0)
        with self.assertRaisesRegex(
            qualification.QualificationError, "never-used/no-success"
        ):
            qualification.validate_runtime_readiness(
                observation, "fixture stale unhealthy", phase="fixture stale unhealthy",
                require_drained=True, expected_pid=4321,
                require_llm_ready=False,
            )

        del observation["heartbeat"]["llm"]["last_success_unix"]
        observation["heartbeat"]["llm"]["consecutive_failures"] = 1
        self.rederive_sample(report, 0)
        with self.assertRaisesRegex(
            qualification.QualificationError, "failure streak"
        ):
            qualification.validate_runtime_readiness(
                observation, "fixture failed backend", phase="fixture failed backend",
                require_drained=True, expected_pid=4321,
                require_llm_ready=False,
            )

    def test_readiness_allows_durable_sequence_pending_history(self) -> None:
        report = copy.deepcopy(self.runtime)
        observation = report["recorder_observations"][0]
        journal = observation["heartbeat"]["sequence_journal_conservation"]
        journal["offered"] += 2
        journal["queued"] += 2
        observation["heartbeat"]["sequence_pending_steps_current"] += 2
        self.rederive_sample(report, 0)

        qualification.validate_runtime_readiness(
            observation, "fixture durable sequence history",
            phase="fixture durable sequence history", require_drained=True,
            expected_pid=4321,
        )

        observation["heartbeat"]["sequence_pending_steps_current"] -= 1
        with self.assertRaisesRegex(
            qualification.QualificationError,
            "sequence_pending_steps_current",
        ):
            self.rederive_sample(report, 0)

    def test_readiness_rejects_deferred_enrichment_identity_failure(self) -> None:
        report = copy.deepcopy(self.runtime)
        observation = report["recorder_observations"][0]
        observation["heartbeat"]["deferred_enrichment_buffer"][
            "identity_rejected_patches_total"
        ] = 1
        self.rederive_sample(report, 0)
        with self.assertRaisesRegex(
            qualification.QualificationError,
            "identity-rejected patches=1",
        ):
            qualification.validate_runtime_readiness(
                observation, "fixture rejected enrichment",
                phase="fixture rejected enrichment", require_drained=True,
                expected_pid=4321,
            )

    def test_initial_loss_fails_before_source_probes_or_epoch_sleep(self) -> None:
        report = copy.deepcopy(self.runtime)
        observation = report["recorder_observations"][0]
        pipeline = observation["heartbeat"]["event_pipeline"]
        pipeline["offered_by_lane"]["file"] += 1
        pipeline["merged_dropped_by_lane"]["file"] = 1
        self.rederive_sample(report, 0)
        source_probe = mock.Mock()
        capture_path = self.root / "failed-readiness.capture.json"
        with mock.patch.object(qualification.platform, "system", return_value="Darwin"), \
                mock.patch.object(qualification.os, "geteuid", return_value=0), \
                mock.patch.object(
                    qualification, "read_live_heartbeat",
                    return_value=(observation["heartbeat"], {}),
                ), \
                mock.patch.object(
                    qualification, "installed_runtime_host",
                    return_value=copy.deepcopy(self.runtime["host"]),
                ), \
                mock.patch.object(
                    qualification, "capture_runtime_observation",
                    return_value=observation,
                ), \
                mock.patch.object(
                    qualification, "source_runtime_probe_evidence", source_probe
                ), \
                mock.patch.object(qualification.time, "sleep") as sleep_probe:
            with self.assertRaisesRegex(
                qualification.QualificationError, "cumulative loss"
            ):
                qualification.live_runtime_recording(
                    root=ROOT, candidate_manifest=self.manifest,
                    candidate_manifest_sha256=self.manifest_sha,
                    dmg=self.dmg,
                    heartbeat_path=pathlib.Path(
                        "/Library/Application Support/MacCrab/heartbeat_rich.json"
                    ),
                    data_dirs=[self.root], sqlite_overrides={},
                    capture_path=capture_path,
                )
        source_probe.assert_not_called()
        sleep_probe.assert_not_called()
        failure = qualification.read_json_file(capture_path, "failed readiness")
        self.assertEqual(failure["result"], "failed")
        self.assertEqual(failure["phase"], "initial-readiness")

    def test_alert_reserve_boundary_and_blocked_state_fail_readiness(self) -> None:
        report = copy.deepcopy(self.runtime)
        observation = report["recorder_observations"][0]
        budget = observation["heartbeat"]["alert_evidence_budget"]
        self.assertLess(
            budget["alerts_family_admission_boundary_bytes"],
            budget["alerts_family_admission_cap_bytes"],
        )
        budget["alerts_family_footprint_bytes"] = 193 * 1024 * 1024
        with self.assertRaisesRegex(
            qualification.QualificationError, "admission boundary"
        ):
            self.rederive_sample(report, 0)

        report = copy.deepcopy(self.runtime)
        observation = report["recorder_observations"][0]
        budget = observation["heartbeat"]["alert_evidence_budget"]
        budget["alerts_family_blocked"] = True
        budget["alerts_family_reason"] = "fixture admission latch"
        self.rederive_sample(report, 0)
        with self.assertRaisesRegex(
            qualification.QualificationError, "admission-blocked"
        ):
            qualification.validate_runtime_readiness(
                observation, "fixture alerts", phase="fixture alerts",
                require_drained=True,
            )

    def test_sticky_event_budget_and_sqlite_cap_fail_readiness(self) -> None:
        report = copy.deepcopy(self.runtime)
        observation = report["recorder_observations"][0]
        observation["heartbeat"]["events_retention_budget"]["sticky"] = True
        observation["event_budget_fault"] = True
        self.rederive_sample(report, 0)
        with self.assertRaisesRegex(
            qualification.QualificationError, "retention budget"
        ):
            qualification.validate_runtime_readiness(
                observation, "fixture event budget", phase="fixture event budget",
                require_drained=True,
            )

        report = copy.deepcopy(self.runtime)
        observation = report["recorder_observations"][0]
        family = observation["sqlite_families"]["campaigns.db"]
        family["footprint_bytes"] = family["configured_cap_bytes"] + 1
        with self.assertRaisesRegex(
            qualification.QualificationError, "footprint exceeds configured cap"
        ):
            qualification.validate_runtime_readiness(
                observation, "fixture SQLite", phase="fixture SQLite",
                require_drained=True,
            )

    def test_shipping_sqlite_cap_cannot_be_overridden_by_recorder(self) -> None:
        self.assertEqual(
            qualification.DEFAULT_SQLITE_CAP_BYTES["events.db"],
            340 * qualification.MIB,
        )
        with self.assertRaisesRegex(
            qualification.QualificationError, "cannot override a shipping store"
        ):
            qualification.parse_sqlite_cap_overrides(["alerts.db=999999999"])

    def test_causal_proof_rejects_unrelated_only_telemetry(self) -> None:
        proof = copy.deepcopy(
            self.runtime["recorder_probe_evidence"]["workload"][
                "alert_investigation"
            ]
        )
        proof["telemetry_after"] = copy.deepcopy(proof["telemetry_before"])
        with self.assertRaisesRegex(
            qualification.QualificationError, "one or more completed"
        ):
            qualification.validate_alert_investigation_proof(
                proof, "fixture causal proof"
            )

    def test_causal_proof_allows_concurrent_accepted_investigations(self) -> None:
        proof = copy.deepcopy(
            self.runtime["recorder_probe_evidence"]["workload"][
                "alert_investigation"
            ]
        )
        proof["telemetry_after"] = qualification.llm_runtime_quality_sample(
            {"llm": llm_heartbeat_payload(healthy=True, started=12, accepted=12)}
        )
        delta = qualification.validate_alert_investigation_proof(
            proof, "fixture concurrent causal proof"
        )
        self.assertEqual(delta["started_delta"], 2)
        self.assertEqual(delta["accepted_delta"], 2)

    def test_causal_proof_rejects_negative_investigation_confidence(self) -> None:
        proof = copy.deepcopy(
            self.runtime["recorder_probe_evidence"]["workload"][
                "alert_investigation"
            ]
        )
        investigation = json.loads(proof["investigation_json"])
        investigation["confidence"] = -0.01
        proof["investigation_json"] = json.dumps(
            investigation, sort_keys=True, separators=(",", ":")
        )
        proof["investigation_sha256"] = qualification.sha256_bytes(
            proof["investigation_json"].encode("utf-8")
        )
        with self.assertRaisesRegex(
            qualification.QualificationError, "must be >= 0"
        ):
            qualification.validate_alert_investigation_proof(
                proof, "fixture negative confidence"
            )

    def test_live_runtime_source_evidence_launches_no_build_or_lint(self) -> None:
        with mock.patch.object(qualification, "subprocess_probe") as process_probe:
            evidence = qualification.source_runtime_probe_evidence(self.manifest)
        process_probe.assert_not_called()
        self.assertEqual(
            evidence["preinstall_clean_ci"], self.manifest["preinstall_clean_ci"]
        )
        live_source = inspect.getsource(qualification.live_runtime_recording)
        source_evidence_source = inspect.getsource(
            qualification.source_runtime_probe_evidence
        )
        self.assertNotIn("xcrun", live_source + source_evidence_source)
        self.assertNotIn('"swift"', live_source + source_evidence_source)

    def test_runtime_cannot_substitute_clean_ci_receipt(self) -> None:
        report = copy.deepcopy(self.runtime)
        receipt = report["recorder_probe_evidence"]["preinstall_clean_ci"]
        receipt["output_sha256"] = "f" * 64
        report["measurements"]["correlation_continuity"][
            "source_bound_clean_ci_sha256"
        ] = "f" * 64
        with self.assertRaisesRegex(
            qualification.QualificationError, "does not match the candidate manifest"
        ):
            self.validate_runtime(report)

    def test_readonly_nofollow_alert_query_binds_exact_path(self) -> None:
        database = (self.root / "alerts.db").resolve()
        connection = sqlite3.connect(database)
        connection.execute(
            "CREATE TABLE alerts (id TEXT, timestamp REAL, rule_id TEXT, "
            "severity TEXT, process_path TEXT, llm_investigation_json TEXT)"
        )
        exact_path, _ = qualification.workload_paths("d" * 32)
        connection.executemany(
            "INSERT INTO alerts VALUES (?1,?2,?3,?4,?5,?6)",
            [
                (
                    "33333333-3333-4333-8333-333333333333", 101.0,
                    "fixture.rule", "high", exact_path, None,
                ),
                (
                    "44444444-4444-4444-8444-444444444444", 102.0,
                    "fixture.other", "high", exact_path + "-other", None,
                ),
            ],
        )
        connection.commit()
        connection.close()
        rows, evidence = qualification.readonly_alert_rows_for_process(
            database_path=database, process_path=exact_path,
            triggered_after_unix=100.0,
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["process_path"], exact_path)
        self.assertTrue(evidence["read_only"])
        self.assertTrue(evidence["no_follow"])

        redirected = self.root / "redirected-alerts.db"
        os.symlink(database, redirected)
        with self.assertRaisesRegex(
            qualification.QualificationError, "no-follow alert query failed"
        ):
            qualification.readonly_alert_rows_for_process(
                database_path=redirected, process_path=exact_path,
                triggered_after_unix=100.0,
            )

    def test_multiple_detection_tiers_do_not_fail_the_causal_proof(self) -> None:
        # rc.45: ONE trigger legitimately produces SEVERAL alerts. This used to
        # `fail("unique qualification executable produced ambiguous duplicate
        # alerts")` on more than one row, which rejects the product for
        # detecting well. Observed on an installed host 2026-08-31 — one exec of
        # the qualification executable, five alerts in the same second across
        # five detection tiers (targeted rule, second rule, baseline anomaly,
        # behaviour composite, campaign correlation). The 2026-08-23 run
        # produced four; an earlier one produced a single alert, which is the
        # only reason this check ever passed.
        #
        # Empty investigation JSON returns before observation validation, which
        # isolates exactly the behaviour under test: multiplicity is accepted
        # and the bound identity is deterministic.
        database = (self.root / "multi-alerts.db").resolve()
        connection = sqlite3.connect(database)
        connection.execute(
            "CREATE TABLE alerts (id TEXT, timestamp REAL, rule_id TEXT, "
            "severity TEXT, process_path TEXT, llm_investigation_json TEXT)"
        )
        exact_path, _ = qualification.workload_paths("e" * 32)
        connection.executemany(
            "INSERT INTO alerts VALUES (?1,?2,?3,?4,?5,?6)",
            [
                (
                    "11111111-1111-4111-8111-111111111111", 200.0,
                    "d1a2b3c4-0042", "critical", exact_path, "",
                ),
                (
                    "22222222-2222-4222-8222-222222222222", 200.0,
                    "baseline-anomaly", "medium", exact_path, "",
                ),
                (
                    "33333333-3333-4333-8333-333333333333", 200.0,
                    "maccrab.campaign.coordinated_attack", "high", exact_path, "",
                ),
            ],
        )
        connection.commit()
        connection.close()

        rows, _ = qualification.readonly_alert_rows_for_process(
            database_path=database, process_path=exact_path,
            triggered_after_unix=100.0,
        )
        self.assertEqual(len(rows), 3, "fixture must present the multi-tier case")

        proof, alert_id = qualification.causal_alert_proof_if_ready(
            phase="fixture",
            database_path=database,
            process_path=exact_path,
            trigger_started_at=dt.datetime.fromtimestamp(100.0, dt.timezone.utc),
            telemetry_before={},
            observation={},
            stable_alert_id=None,
        )
        # No investigation yet, so no proof — but crucially, no ambiguity abort.
        self.assertIsNone(proof)
        self.assertEqual(alert_id, "11111111-1111-4111-8111-111111111111")

        # The pin must survive across polls while other tiers are present.
        _, pinned_id = qualification.causal_alert_proof_if_ready(
            phase="fixture",
            database_path=database,
            process_path=exact_path,
            trigger_started_at=dt.datetime.fromtimestamp(100.0, dt.timezone.utc),
            telemetry_before={},
            observation={},
            stable_alert_id="22222222-2222-4222-8222-222222222222",
        )
        self.assertEqual(
            pinned_id, "22222222-2222-4222-8222-222222222222",
            "a pinned alert must stay bound even when it is not the first row",
        )

    def test_fixed_workload_iterations_match_the_script(self) -> None:
        """The burst size must not live in two places.

        The reconciliation check spelled the count out as a literal, so
        resizing BURST_ITERATIONS in the workload script left the gate
        demanding the previous number and failing a correct run.
        """
        script = (ROOT / "scripts/runtime-qualification-workload.sh").read_text()
        declared = re.search(r"^BURST_ITERATIONS=(\d+)$", script, re.M)
        self.assertIsNotNone(declared, "workload script must declare BURST_ITERATIONS")
        self.assertEqual(
            int(declared.group(1)), qualification.FIXED_WORKLOAD_ITERATIONS,
            "workload script and qualification gate disagree on the burst size",
        )

    def test_causal_proof_records_every_tier_that_fired(self) -> None:
        # The uniqueness check discarded the fact that several tiers caught the
        # trigger. That is evidence, not noise: keep it in the proof.
        source = inspect.getsource(qualification.causal_alert_proof_if_ready)
        self.assertIn('"observed_alerts"', source)
        self.assertNotIn("ambiguous duplicate", source)

    def test_proof_producer_and_proof_validator_agree_on_the_inventory(self) -> None:
        """The producer's keys must be exactly the validator's required set.

        This is the check that was missing. `observed_alerts` was added to the
        producer and to the fixture, but the validator's inventory is strict
        set-equality, so the first real installed-host run died on
        `prewarm alert proof inventory is incomplete or unknown` while all 117
        tests were green -- the fixture built proofs by hand and the only
        assertion about the new field was a substring match on source text.
        Compare the two directly so they cannot drift again.
        """
        producer = inspect.getsource(qualification.causal_alert_proof_if_ready)
        validator = inspect.getsource(
            qualification.validate_alert_investigation_proof
        )
        required = set(
            re.findall(r'"([a-z0-9_]+)"', validator.split("required = {", 1)[1].split("}", 1)[0])
        )
        self.assertIn("observed_alerts", required)
        # Every key the producer emits into the returned proof must be required.
        emitted = set(
            re.findall(r'^\s{8}"([a-z0-9_]+)":', producer, flags=re.MULTILINE)
        )
        self.assertTrue(emitted, "could not read the producer's emitted keys")
        self.assertEqual(
            emitted - required, set(),
            "producer emits proof keys the validator will reject",
        )
        self.assertEqual(
            required - emitted, set(),
            "validator requires proof keys the producer never emits",
        )

    def test_fixture_proof_satisfies_the_real_validator(self) -> None:
        # The fixture is only useful if it is the shape the validator accepts.
        proof = copy.deepcopy(
            self.runtime["recorder_probe_evidence"]["llm_prewarm"]
                ["alert_investigation"]
        )
        qualification.validate_alert_investigation_proof(proof, "fixture proof")

        missing = copy.deepcopy(proof)
        del missing["observed_alerts"]
        with self.assertRaisesRegex(
            qualification.QualificationError, "inventory is incomplete or unknown"
        ):
            qualification.validate_alert_investigation_proof(missing, "fixture proof")

        # Non-UUID ids are legitimate: detection tiers do not share one id
        # format, and only the bound alert must be a UUID.
        mixed = copy.deepcopy(proof)
        mixed["observed_alerts"] = list(mixed["observed_alerts"]) + [
            {"id": "campaign:kill-chain:7", "rule_id": "tier-2", "severity": "high"},
        ]
        qualification.validate_alert_investigation_proof(mixed, "fixture proof")

        unbound = copy.deepcopy(proof)
        unbound["observed_alerts"] = [
            {
                "id": "99999999-9999-4999-8999-999999999999",
                "rule_id": "other-tier",
                "severity": "high",
            },
        ]
        with self.assertRaisesRegex(
            qualification.QualificationError,
            "not among the alerts the trigger was observed to produce",
        ):
            qualification.validate_alert_investigation_proof(unbound, "fixture proof")

    def test_causal_proof_waits_for_telemetry_to_catch_up(self) -> None:
        """Evidence lands in alerts.db before the heartbeat reports the health flip.

        Heartbeats are ~30s apart, so a persisted investigation is visible in
        the database while `llm_quality` still says unhealthy. Emitting a proof
        then embeds a stale `telemetry_after` and the validator rejects it for
        `.after is not healthy` -- true of the snapshot, false of the engine.
        The producer must report not-ready so the 180s poll continues.
        """
        observation = copy.deepcopy(self.runtime["recorder_observations"][-1])
        observation["heartbeat"]["llm"] = llm_heartbeat_payload(
            healthy=False, started=1, accepted=0, current=1
        )
        self.rebind_observation_heartbeat(observation)
        database = (self.root / "telemetry-lag.db").resolve()
        exact_path, _ = qualification.workload_paths("f" * 32)
        connection = sqlite3.connect(str(database))
        connection.execute(
            "CREATE TABLE alerts (id TEXT, timestamp REAL, rule_id TEXT, "
            "severity TEXT, process_path TEXT, llm_investigation_json TEXT)"
        )
        connection.execute(
            "INSERT INTO alerts VALUES (?1,?2,?3,?4,?5,?6)",
            ("44444444-4444-4444-8444-444444444444", 200.0,
             "maccrab.qualification.reverse-shell", "critical", exact_path,
             '{"summary":"x"}'),
        )
        connection.commit()
        connection.close()

        proof, _ = qualification.causal_alert_proof_if_ready(
            phase="fixture",
            database_path=database,
            process_path=exact_path,
            trigger_started_at=dt.datetime.fromtimestamp(100.0, dt.timezone.utc),
            telemetry_before={},
            observation=observation,
            stable_alert_id=None,
        )
        self.assertIsNone(
            proof,
            "a proof must not be emitted while its own telemetry still lags",
        )

    def test_causal_proof_waits_for_an_accepted_investigation(self) -> None:
        """A started-but-not-yet-accepted investigation is not proof yet.

        By the epoch the backend is already healthy (the prewarm made it so),
        so the health guard does not help. The investigation can be persisted
        in alerts.db while the ~30s heartbeat still reports it started and not
        accepted; the validator then sees accepted_delta != started_delta and
        rejects a proof describing a perfectly good investigation.
        """
        observation = copy.deepcopy(self.runtime["recorder_observations"][-1])
        # healthy, one investigation started, none accepted yet, still running.
        observation["heartbeat"]["llm"] = llm_heartbeat_payload(
            healthy=True, started=1, accepted=0, current=1
        )
        self.rebind_observation_heartbeat(observation)
        before = qualification.llm_runtime_quality_sample(
            {"llm": llm_heartbeat_payload(healthy=True, started=0, accepted=0)}
        )
        database = (self.root / "accept-lag.db").resolve()
        exact_path, _ = qualification.workload_paths("a" * 32)
        connection = sqlite3.connect(str(database))
        connection.execute(
            "CREATE TABLE alerts (id TEXT, timestamp REAL, rule_id TEXT, "
            "severity TEXT, process_path TEXT, llm_investigation_json TEXT)"
        )
        connection.execute(
            "INSERT INTO alerts VALUES (?1,?2,?3,?4,?5,?6)",
            ("55555555-5555-4555-8555-555555555555", 200.0,
             "maccrab.qualification.reverse-shell", "critical", exact_path,
             '{"summary":"x"}'),
        )
        connection.commit()
        connection.close()

        proof, _ = qualification.causal_alert_proof_if_ready(
            phase="fixture",
            database_path=database,
            process_path=exact_path,
            trigger_started_at=dt.datetime.fromtimestamp(100.0, dt.timezone.utc),
            telemetry_before=before,
            observation=observation,
            stable_alert_id=None,
        )
        self.assertIsNone(
            proof,
            "a proof must not be emitted while the investigation it cites is "
            "still in flight",
        )

    def test_causal_proof_rejects_a_vanished_pinned_alert(self) -> None:
        # Loosening the uniqueness check must not loosen identity stability: a
        # pinned alert that disappears mid-run is still a hard failure.
        database = (self.root / "vanished-alert.db").resolve()
        connection = sqlite3.connect(database)
        connection.execute(
            "CREATE TABLE alerts (id TEXT, timestamp REAL, rule_id TEXT, "
            "severity TEXT, process_path TEXT, llm_investigation_json TEXT)"
        )
        exact_path, _ = qualification.workload_paths("f" * 32)
        connection.execute(
            "INSERT INTO alerts VALUES (?1,?2,?3,?4,?5,?6)",
            (
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", 300.0,
                "fixture.rule", "high", exact_path, '{"summary": "fixture"}',
            ),
        )
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(
            qualification.QualificationError, "identity disappeared"
        ):
            qualification.causal_alert_proof_if_ready(
                phase="fixture",
                database_path=database,
                process_path=exact_path,
                trigger_started_at=dt.datetime.fromtimestamp(100.0, dt.timezone.utc),
                telemetry_before={},
                observation=self.runtime["recorder_observations"][0],
                stable_alert_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            )

    def test_tracegraph_physical_suppression_is_conserving_not_loss(self) -> None:
        report = copy.deepcopy(self.runtime)
        for index, observation in enumerate(report["recorder_observations"]):
            if observation["offset_seconds"] >= 330:
                graph = observation["heartbeat"]["tracegraph_storage_admission"]
                graph["physical_write_suppressed_events_total"] += 1
                graph["physical_write_suppressed_rows_total"] += 1
                graph["entity_observations_total"] += 1
                self.rederive_sample(report, index)
        report["measurements"]["trace_graph"][
            "physical_write_suppressed_events_epoch_delta"
        ] += 1
        report["measurements"]["trace_graph"][
            "physical_write_suppressed_rows_epoch_delta"
        ] += 1
        report["measurements"]["workload_ingress"][
            "trace_graph_physical_write_suppressed_events_delta"
        ] += 1
        report["measurements"]["workload_ingress"][
            "trace_graph_physical_write_suppressed_rows_delta"
        ] += 1
        self.validate_runtime(report)

    def test_tracegraph_recovery_waiter_ledger_must_conserve(self) -> None:
        observation = copy.deepcopy(self.runtime["recorder_observations"][8])
        graph = observation["heartbeat"]["tracegraph_storage_admission"]
        graph["recovery_mutation_waits_total"] = 1
        self.rebind_observation_heartbeat(observation)
        with self.assertRaisesRegex(
            qualification.QualificationError, "waiter ledger does not conserve"
        ):
            qualification.sample_from_recorder_observation(
                observation, "fixture broken recovery ledger"
            )

    def test_tracegraph_recovery_waiter_limit_is_fixed_at_production_bound(self) -> None:
        observations = copy.deepcopy(self.runtime["recorder_observations"])
        for observation in observations:
            observation["heartbeat"]["tracegraph_storage_admission"][
                "recovery_mutation_waiter_limit"
            ] = 2_048
            self.rebind_observation_heartbeat(observation)
        with self.assertRaisesRegex(
            qualification.QualificationError,
            "must equal the fixed production limit 1024",
        ):
            self.rebuild_runtime_from_observations(observations)

    def test_tracegraph_must_accept_mutations_for_ninety_nine_percent(self) -> None:
        observations = copy.deepcopy(self.runtime["recorder_observations"])
        observations[8]["heartbeat"]["tracegraph_storage_admission"][
            "accepting_mutations"
        ] = False
        self.rebind_observation_heartbeat(observations[8])
        report = self.rebuild_runtime_from_observations(observations)
        with self.assertRaisesRegex(
            qualification.QualificationError,
            "recovery barrier is not accepting mutations",
        ):
            self.validate_runtime(report)

    def test_tracegraph_hidden_recovery_queue_saturation_delta_is_rejected(self) -> None:
        observations = copy.deepcopy(self.runtime["recorder_observations"])
        for observation in observations:
            if observation["offset_seconds"] >= 330:
                observation["heartbeat"]["tracegraph_storage_admission"][
                    "recovery_mutation_wait_saturations_total"
                ] = 1
                self.rebind_observation_heartbeat(observation)
        report = self.rebuild_runtime_from_observations(observations)
        with self.assertRaisesRegex(
            qualification.QualificationError,
            "cumulative TraceGraph recovery mutation queue saturations=1",
        ):
            self.validate_runtime(report)

    def test_tracegraph_prior_recovery_queue_saturation_poisoned_epoch_is_rejected(self) -> None:
        observations = copy.deepcopy(self.runtime["recorder_observations"])
        for observation in observations:
            observation["heartbeat"]["tracegraph_storage_admission"][
                "recovery_mutation_wait_saturations_total"
            ] = 1
            self.rebind_observation_heartbeat(observation)
        report = self.rebuild_runtime_from_observations(observations)
        self.assertEqual(
            report["measurements"]["trace_graph"][
                "recovery_mutation_wait_saturations_epoch_delta"
            ],
            0,
        )
        with self.assertRaisesRegex(
            qualification.QualificationError,
            "cumulative TraceGraph recovery mutation queue saturations=1",
        ):
            self.validate_runtime(report)

    def test_tracegraph_recovery_is_orthogonal_while_barrier_accepts(self) -> None:
        observations = copy.deepcopy(self.runtime["recorder_observations"])
        for observation in observations:
            if observation["offset_seconds"] >= 450:
                observation["heartbeat"]["tracegraph_storage_admission"][
                    "recovering"
                ] = True
                observation["trace_recovering"] = True
                self.rebind_observation_heartbeat(observation)
        report = self.rebuild_runtime_from_observations(observations)
        self.validate_runtime(report)

    def test_tracegraph_recovery_mutation_wait_is_bounded_to_five_seconds(self) -> None:
        observations = copy.deepcopy(self.runtime["recorder_observations"])
        excessive = qualification.MAX_TRACE_RECOVERY_MUTATION_WAIT_NANOSECONDS + 1
        for observation in observations:
            if observation["offset_seconds"] >= 330:
                graph = observation["heartbeat"]["tracegraph_storage_admission"]
                graph["recovery_mutation_waiter_high_watermark"] = 1
                graph["recovery_mutation_waits_total"] = 1
                graph["recovery_mutation_wait_releases_total"] = 1
                graph["recovery_mutation_wait_nanoseconds_total"] = excessive
                graph["recovery_mutation_max_wait_nanoseconds"] = excessive
                graph["recovery_writer_preemptions_total"] = 1
                self.rebind_observation_heartbeat(observation)
        report = self.rebuild_runtime_from_observations(observations)
        with self.assertRaisesRegex(
            qualification.QualificationError,
            "recovery maximum mutation wait is 5000000001ns",
        ):
            self.validate_runtime(report)

    def test_tracegraph_final_recovery_mutation_waiter_must_drain(self) -> None:
        observations = copy.deepcopy(self.runtime["recorder_observations"])
        graph = observations[-1]["heartbeat"]["tracegraph_storage_admission"]
        graph["recovering"] = True
        graph["recovery_mutation_waiters"] = 1
        graph["recovery_mutation_waiter_high_watermark"] = 1
        graph["recovery_mutation_waits_total"] = 1
        graph["recovery_mutation_oldest_wait_nanoseconds"] = 1
        observations[-1]["trace_recovering"] = True
        self.rebind_observation_heartbeat(observations[-1])
        report = self.rebuild_runtime_from_observations(observations)
        with self.assertRaisesRegex(
            qualification.QualificationError, "not drained at a fixed readiness boundary"
        ):
            self.validate_runtime(report)

    def test_tracegraph_bridge_event_batch_and_row_failure_deltas_are_rejected(self) -> None:
        for failure_kind, expected in (
            ("event", "trace-graph-mutation explicitly_shed=1"),
            ("batch", "write_batches_failed_total=1"),
            ("row", "write_rows_failed_total=1"),
        ):
            with self.subTest(failure_kind=failure_kind):
                observations = copy.deepcopy(
                    self.runtime["recorder_observations"]
                )
                for observation in observations:
                    if observation["offset_seconds"] < 330:
                        continue
                    graph = observation["heartbeat"][
                        "tracegraph_storage_admission"
                    ]
                    if failure_kind == "event":
                        graph["ingest_events_total"] += 1
                        graph["ingest_events_failed_total"] += 1
                    elif failure_kind == "batch":
                        graph["write_attempts_total"] += 1
                        graph["write_batches_failed_total"] += 1
                    else:
                        graph["write_rows_attempted_total"] += 1
                        graph["write_rows_failed_total"] += 1
                        graph["entity_observations_total"] += 1
                    self.rebind_observation_heartbeat(observation)
                report = self.rebuild_runtime_from_observations(observations)
                with self.assertRaisesRegex(
                    qualification.QualificationError, expected
                ):
                    self.validate_runtime(report)

    def test_zero_tracegraph_physical_suppression_cannot_pass_workload(self) -> None:
        report = copy.deepcopy(self.runtime)
        for index, observation in enumerate(report["recorder_observations"]):
            graph = observation["heartbeat"]["tracegraph_storage_admission"]
            suppressed = graph["physical_write_suppressed_rows_total"]
            graph["write_attempts_total"] += suppressed
            graph["write_batches_committed_total"] += suppressed
            graph["write_rows_attempted_total"] += suppressed
            graph["write_rows_committed_total"] += suppressed
            graph["physical_write_suppressed_events_total"] = 0
            graph["physical_write_suppressed_rows_total"] = 0
            self.rederive_sample(report, index)
        report["measurements"]["trace_graph"][
            "physical_write_suppressed_events_epoch_delta"
        ] = 0
        report["measurements"]["trace_graph"][
            "physical_write_suppressed_rows_epoch_delta"
        ] = 0
        with self.assertRaisesRegex(
            qualification.QualificationError, "suppression was not exercised"
        ):
            self.validate_runtime(report)

    def test_workload_path_isolated_and_invalid_identity_is_rejected(self) -> None:
        run_id = "e" * 32
        _, bulk_path = qualification.workload_paths(run_id)
        isolation = qualification.validate_workload_sequence_path_isolation(
            ROOT, bulk_path
        )
        self.assertGreater(isolation["stable_predicate_count"], 0)
        completed = subprocess.run(
            [
                "/bin/bash", str(ROOT / "scripts/runtime-qualification-workload.sh"),
                "--alert-only", "--run-id", "unsafe",
            ],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(completed.returncode, 64)

    def test_workload_process_group_cleanup_reaps_children(self) -> None:
        process = subprocess.Popen(
            ["/bin/sh", "-c", "/bin/sleep 60 & wait"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            start_new_session=True,
        )
        try:
            time.sleep(0.05)
            qualification.terminate_process_group(process)
            self.assertIsNotNone(process.poll())
            # The parent is reaped before this probe. On macOS the numeric
            # process-group ID may already have been reused by an inaccessible
            # group, in which case signal 0 reports EPERM instead of ESRCH.
            # Either result proves none of our same-UID workload children
            # remain signalable in the original group.
            with self.assertRaises((ProcessLookupError, PermissionError)):
                os.killpg(process.pid, 0)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)

    def test_report_builder_normalizes_and_verifies_raw_observations(self) -> None:
        report = qualification.build_runtime_report_from_observations(
            candidate_manifest=self.manifest,
            candidate_manifest_sha256=self.manifest_sha,
            observations=copy.deepcopy(self.runtime["recorder_observations"]),
            host=copy.deepcopy(self.runtime["host"]),
            workload=copy.deepcopy(self.runtime["workload"]),
            probes=self.recorder_probes(),
            capture_mode="deterministic-fixture",
        )
        self.validate_runtime(report)

    def test_record_runtime_cli_has_no_fixture_input_bypass(self) -> None:
        with self.assertRaises(SystemExit):
            qualification.parser().parse_args(
                [
                    "record-runtime",
                    "--candidate-manifest", str(self.manifest_path),
                    "--dmg", str(self.dmg),
                    "--source-root", str(ROOT),
                    "--output", str(self.root / "runtime-output.json"),
                    "--recording-input", str(self.root / "fixture.json"),
                ]
            )

    def test_fixture_runtime_is_rejected_by_release_validation(self) -> None:
        with self.assertRaisesRegex(
            qualification.QualificationError, "live installed-root"
        ):
            qualification.validate_runtime_report(
                self.runtime,
                candidate_manifest_sha256=self.manifest_sha,
                candidate=self.validate_candidate(),
                candidate_verification=self.manifest["artifact_verification"],
                candidate_preinstall_clean_ci=self.manifest["preinstall_clean_ci"],
                payload_inventory_sha256=self.manifest["artifact_verification"]["payload_inventory"]["sha256"],
                source_root=ROOT,
            )

    def test_raw_observation_mutation_without_rebinding_is_rejected(self) -> None:
        report = copy.deepcopy(self.runtime)
        report["recorder_observations"][3]["process"][
            "engine_disk_write_bytes_total"
        ] += 1
        with self.assertRaisesRegex(qualification.QualificationError, "raw recorder"):
            self.validate_runtime(report)

    def test_configured_llm_unhealthy_sample_is_rejected(self) -> None:
        report = copy.deepcopy(self.runtime)
        for index, observation in enumerate(report["recorder_observations"]):
            observation["heartbeat"]["llm"] = llm_heartbeat_payload(
                healthy=index != len(report["recorder_observations"]) - 1
            )
            self.rederive_sample(report, index)
        report["measurements"]["ai_quality"] = {
            "configured": True,
            "feature_disabled_entire_epoch": False,
            "schema_2_and_accounting_conserved_all_samples": False,
            "unspecified_requests_epoch_delta": 0,
            "alert_investigations_started_epoch_delta": 0,
            "alert_investigations_accepted_epoch_delta": 0,
            "alert_investigations_final_rejected_epoch_delta": 0,
        }
        with self.assertRaisesRegex(qualification.QualificationError, "not healthy"):
            self.validate_runtime(report)

    def test_configured_llm_final_rejection_is_rejected(self) -> None:
        report = copy.deepcopy(self.runtime)
        last = len(report["recorder_observations"]) - 1
        for index, observation in enumerate(report["recorder_observations"]):
            observation["heartbeat"]["llm"] = llm_heartbeat_payload(
                healthy=True,
                started=1 if index == last else 0,
                accepted=0,
                rejected=1 if index == last else 0,
            )
            self.rederive_sample(report, index)
        report["measurements"]["ai_quality"] = {
            "configured": True,
            "feature_disabled_entire_epoch": False,
            "schema_2_and_accounting_conserved_all_samples": True,
            "unspecified_requests_epoch_delta": 0,
            "alert_investigations_started_epoch_delta": 1,
            "alert_investigations_accepted_epoch_delta": 0,
            "alert_investigations_final_rejected_epoch_delta": 1,
        }
        with self.assertRaisesRegex(qualification.QualificationError, "final-rejected"):
            self.validate_runtime(report)

    def test_zero_alert_investigations_is_not_a_pass(self) -> None:
        report = copy.deepcopy(self.runtime)
        for index, observation in enumerate(report["recorder_observations"]):
            observation["heartbeat"]["llm"] = llm_heartbeat_payload(
                healthy=True, started=10, accepted=10
            )
            self.rederive_sample(report, index)
        report["measurements"]["ai_quality"].update(
            {
                "alert_investigations_started_epoch_delta": 0,
                "alert_investigations_accepted_epoch_delta": 0,
            }
        )
        with self.assertRaisesRegex(
            qualification.QualificationError, "did not exercise alert investigation"
        ):
            self.validate_runtime(report)

    def test_gracefully_disabled_llm_qualifies(self) -> None:
        # rc.44: an unconfigured LLM is a SUPPORTED shipping configuration —
        # MacCrab documents that LLM features degrade gracefully with no backend.
        # The release gate no longer mandates a configured LLM; instead it
        # asserts the graceful-degradation contract (feature disabled the whole
        # epoch, zero LLM work). A gracefully-disabled run must QUALIFY.
        report = copy.deepcopy(self.runtime)
        for index, observation in enumerate(report["recorder_observations"]):
            observation["heartbeat"]["llm"] = {"configured": False}
            self.rederive_sample(report, index)
        report["measurements"]["ai_quality"] = {
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
        # Must NOT raise: graceful degradation is a passing configuration.
        self.validate_runtime(report)

    def test_disabled_llm_that_still_did_work_is_rejected(self) -> None:
        # The contract's teeth: "unconfigured" must mean NO LLM activity. A run
        # claiming disabled while showing requests is not degrading gracefully
        # and must still fail.
        report = copy.deepcopy(self.runtime)
        for index, observation in enumerate(report["recorder_observations"]):
            observation["heartbeat"]["llm"] = {"configured": False}
            self.rederive_sample(report, index)
        # Claims disabled, but the aggregate shows alert-investigation work —
        # not graceful degradation.
        report["measurements"]["ai_quality"] = {
            "configured": False,
            "feature_disabled_entire_epoch": True,
            "schema_2_and_accounting_conserved_all_samples": True,
            "unspecified_requests_epoch_delta": 0,
            "alert_investigations_started_epoch_delta": 1,
            "alert_investigations_accepted_epoch_delta": 1,
            "alert_investigations_final_rejected_epoch_delta": 0,
            "causal_alert_id": None,
            "causal_investigation_sha256": None,
        }
        with self.assertRaisesRegex(
            qualification.QualificationError, "not degrading gracefully"
        ):
            self.validate_runtime(report)

    def test_swapped_in_flight_alert_operation_is_rejected(self) -> None:
        report = copy.deepcopy(self.runtime)
        last = len(report["recorder_observations"]) - 1
        for index, observation in enumerate(report["recorder_observations"]):
            started = 11 if index == last else 10
            accepted = 10 if index == last else 9
            observation["heartbeat"]["llm"] = llm_heartbeat_payload(
                healthy=True, started=started, accepted=accepted, current=1
            )
            self.rederive_sample(report, index)
        report["measurements"]["ai_quality"].update(
            {
                "alert_investigations_started_epoch_delta": 1,
                "alert_investigations_accepted_epoch_delta": 1,
            }
        )
        with self.assertRaisesRegex(
            qualification.QualificationError, "not drained"
        ):
            self.validate_runtime(report)

    def test_candidate_byte_mutation_is_rejected(self) -> None:
        self.dmg.write_bytes(b"different bytes\n")
        with self.assertRaisesRegex(qualification.QualificationError, "exact DMG bytes"):
            self.validate_candidate()

    def test_payload_inventory_rejects_unsafe_symlink_modes(self) -> None:
        mountpoint = self.root / "mounted-payload"
        mountpoint.mkdir()
        target = self.root / "outside-target"
        target.write_text("outside bytes\n", encoding="utf-8")
        link = mountpoint / "Current"
        link.symlink_to(target)

        for mode in (0o700, 0o644):
            with self.subTest(mode=oct(mode)):
                os.chmod(link, mode, follow_symlinks=False)
                with self.assertRaisesRegex(
                    qualification.QualificationError,
                    "not readable/traversable by every user",
                ):
                    qualification.inventory_mounted_payload(mountpoint)

        os.chmod(link, 0o777, follow_symlinks=False)
        with self.assertRaisesRegex(
            qualification.QualificationError, "group/world writable"
        ):
            qualification.inventory_mounted_payload(mountpoint)

    def test_candidate_document_rejects_recorded_unsafe_symlink_modes(self) -> None:
        for mode, diagnostic in (
            (0o700, "not readable/traversable by every user"),
            (0o644, "not readable/traversable by every user"),
            (0o777, "group/world writable"),
        ):
            with self.subTest(mode=oct(mode)):
                manifest = copy.deepcopy(self.manifest)
                manifest["artifact_verification"]["payload_inventory"][
                    "entries"
                ].append({
                    "path": "MacCrab.app/Contents/Frameworks/F.framework/Current",
                    "kind": "symlink",
                    "target": "A",
                    "mode": mode,
                })
                with self.assertRaisesRegex(
                    qualification.QualificationError, diagnostic
                ):
                    qualification.validate_candidate_document(
                        manifest,
                        expected_version=VERSION,
                        expected_source_commit=COMMIT,
                        expected_source_tree=TREE,
                        expected_build_number=BUILD_NUMBER,
                        dmg=self.dmg,
                        artifact_checks="digest",
                    )

    def test_candidate_rule_corpus_version_must_match_candidate(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["artifact_verification"]["rule_corpus"][
            "bundle_version"
        ] = "0.0.0"
        with self.assertRaisesRegex(
            qualification.QualificationError,
            "rule corpus version does not match candidate version",
        ):
            qualification.validate_candidate_document(
                manifest,
                expected_version=VERSION,
                expected_source_commit=COMMIT,
                expected_source_tree=TREE,
                expected_build_number=BUILD_NUMBER,
                dmg=self.dmg,
                artifact_checks="digest",
            )

    def test_candidate_rule_manifest_inventory_row_is_authoritative(self) -> None:
        def manifest_row(manifest: dict) -> dict:
            return next(
                row
                for row in manifest["artifact_verification"][
                    "payload_inventory"
                ]["entries"]
                if row["path"] == qualification.AGENT_RULE_MANIFEST_PATH
            )

        mutations = {
            "missing": lambda manifest: manifest["artifact_verification"][
                "payload_inventory"
            ]["entries"].remove(manifest_row(manifest)),
            "duplicate": lambda manifest: manifest["artifact_verification"][
                "payload_inventory"
            ]["entries"].append(copy.deepcopy(manifest_row(manifest))),
            "wrong-kind": lambda manifest: manifest_row(manifest).__setitem__(
                "kind", "directory"
            ),
            "wrong-sha": lambda manifest: manifest_row(manifest).__setitem__(
                "sha256", "f" * 64
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(mutation=name):
                manifest = copy.deepcopy(self.manifest)
                mutate(manifest)
                self.rehash_payload_inventory(manifest)
                with self.assertRaisesRegex(
                    qualification.QualificationError,
                    "duplicate paths|exactly one sealed rule manifest row|"
                    "sealed rule manifest row is not the recorded corpus",
                ):
                    qualification.validate_candidate_document(
                        manifest,
                        expected_version=VERSION,
                        expected_source_commit=COMMIT,
                        expected_source_tree=TREE,
                        expected_build_number=BUILD_NUMBER,
                        dmg=self.dmg,
                        artifact_checks="digest",
                    )

    def test_candidate_payload_inventory_count_and_digest_are_bound(self) -> None:
        for field in ("entry_count", "sha256"):
            with self.subTest(field=field):
                manifest = copy.deepcopy(self.manifest)
                inventory = manifest["artifact_verification"][
                    "payload_inventory"
                ]
                inventory[field] = (
                    inventory["entry_count"] + 1
                    if field == "entry_count"
                    else "f" * 64
                )
                with self.assertRaisesRegex(
                    qualification.QualificationError,
                    "entry_count does not match|sha256 does not bind",
                ):
                    qualification.validate_candidate_document(
                        manifest,
                        expected_version=VERSION,
                        expected_source_commit=COMMIT,
                        expected_source_tree=TREE,
                        expected_build_number=BUILD_NUMBER,
                        dmg=self.dmg,
                        artifact_checks="digest",
                    )

    def test_payload_inventory_records_safe_link_without_traversing_target(self) -> None:
        mountpoint = self.root / "mounted-payload"
        mountpoint.mkdir()
        outside = self.root / "outside-directory"
        outside.mkdir()
        (outside / "must-not-be-inventoried").write_text("secret\n", encoding="utf-8")
        link = mountpoint / "Current"
        link.symlink_to(outside, target_is_directory=True)
        os.chmod(link, 0o755, follow_symlinks=False)

        entries, _ = qualification.inventory_mounted_payload(mountpoint)
        self.assertEqual(
            entries,
            [{
                "path": "Current",
                "kind": "symlink",
                "target": str(outside),
                "mode": 0o755,
            }],
        )

    def test_source_tree_mismatch_is_rejected(self) -> None:
        with self.assertRaisesRegex(qualification.QualificationError, "source commit/tree"):
            qualification.validate_candidate_document(
                self.manifest,
                expected_version=VERSION,
                expected_source_commit=COMMIT,
                expected_source_tree="3" * 40,
                expected_build_number=BUILD_NUMBER,
                dmg=self.dmg,
                artifact_checks="digest",
            )

    def test_runtime_candidate_digest_mismatch_is_rejected(self) -> None:
        report = copy.deepcopy(self.runtime)
        report["candidate"]["dmg"]["sha256"] = "d" * 64
        with self.assertRaisesRegex(qualification.QualificationError, "exact candidate"):
            self.validate_runtime(report)

    def test_installed_engine_from_older_candidate_is_rejected(self) -> None:
        report = copy.deepcopy(self.runtime)
        report["installed_engine"]["end"]["build_version"] = VERSION + ".122"
        with self.assertRaisesRegex(qualification.QualificationError, "candidate build"):
            self.validate_runtime(report)

    def test_wrong_documented_team_identity_is_rejected(self) -> None:
        identity = {
            "developer_id": qualification.EXPECTED_DEVELOPER_ID,
            "team_id": "ABCDEFGHIJ",
            "signing_identifier": qualification.EXPECTED_AGENT_IDENTIFIER,
        }
        with self.assertRaisesRegex(qualification.QualificationError, "team_id"):
            qualification.require_maccrab_signing_identity(
                identity,
                expected_identifier=qualification.EXPECTED_AGENT_IDENTIFIER,
                path="fixture",
            )

    def test_wrong_system_extension_signing_identifier_is_rejected(self) -> None:
        identity = {
            "developer_id": qualification.EXPECTED_DEVELOPER_ID,
            "team_id": qualification.EXPECTED_TEAM_ID,
            "signing_identifier": qualification.EXPECTED_APP_IDENTIFIER,
        }
        with self.assertRaisesRegex(qualification.QualificationError, "signing_identifier"):
            qualification.require_maccrab_signing_identity(
                identity,
                expected_identifier=qualification.EXPECTED_AGENT_IDENTIFIER,
                path="fixture",
            )

    def test_short_epoch_is_rejected(self) -> None:
        report = copy.deepcopy(self.runtime)
        report["epoch"]["duration_seconds"] = 899
        with self.assertRaises(qualification.QualificationError):
            self.validate_runtime(report)

    def test_truncated_sample_interval_is_rejected(self) -> None:
        report = copy.deepcopy(self.runtime)
        report["samples"].pop()
        with self.assertRaisesRegex(qualification.QualificationError, "sample_count"):
            self.validate_runtime(report)

    def test_sample_timestamp_not_bound_to_offset_is_rejected(self) -> None:
        report = copy.deepcopy(self.runtime)
        report["recorder_observations"][5]["recorded_at"] = iso(999)
        report["recorder_observations"][5]["captured_at"] = iso(999)
        report["recorder_observations"][5]["heartbeat"][
            "written_at_unix"
        ] = qualification.parse_time(iso(999), "fixture timestamp").timestamp()
        self.rederive_sample(report, 5)
        with self.assertRaisesRegex(qualification.QualificationError, "epoch start"):
            self.validate_runtime(report)

    def test_legal_capture_jitter_cannot_false_pass_workload_rate(self) -> None:
        samples = copy.deepcopy(self.runtime["samples"])
        for sample in samples:
            offset = sample["offset_seconds"]
            if offset == qualification.BURST_START_OFFSET_SECONDS + 30:
                sample["captured_at"] = iso(offset + 5)
            if offset >= qualification.BURST_START_OFFSET_SECONDS + 30:
                for lane in ("priority", "file"):
                    boundary = sample["conservation"][f"{lane}-ingress"]
                    boundary["offered"] = offset + 19_100
                    boundary["completed"] = offset + 19_100

        start = samples[qualification.BURST_START_OFFSET_SECONDS // 30]
        end = samples[(qualification.BURST_START_OFFSET_SECONDS + 30) // 30]
        offered_delta = sum(
            end["conservation"][f"{lane}-ingress"]["offered"]
            - start["conservation"][f"{lane}-ingress"]["offered"]
            for lane in ("priority", "file")
        )
        scheduled_rate = offered_delta / 30
        captured_rate = offered_delta / 35
        self.assertGreaterEqual(
            scheduled_rate,
            qualification.MIN_BURST_COMBINED_OFFERED_PER_SECOND,
        )
        self.assertLess(
            captured_rate,
            qualification.MIN_BURST_COMBINED_OFFERED_PER_SECOND,
        )
        with self.assertRaisesRegex(
            qualification.QualificationError, "predeclared reference load"
        ):
            qualification.derive_workload_ingress(samples)

    def test_unconfigured_llm_host_can_be_recorded_and_validated(self) -> None:
        """Graceful degradation has to be able to produce evidence, not crash.

        The validator has accepted an unconfigured backend since rc.44 -- the
        product documents that LLM features degrade gracefully with no backend.
        The recorder, though, bound its four LLM epoch deltas only on the
        configured path, so building a report for a host without a backend
        raised NameError and that shipping configuration could never be
        qualified at all.  The unconfigured aggregate is also derived now
        rather than hardcoded to the configured answer.
        """
        observations = copy.deepcopy(self.runtime["recorder_observations"])
        for observation in observations:
            observation["heartbeat"]["llm"] = {"configured": False}
            self.rebind_observation_heartbeat(observation)
        report = self.rebuild_runtime_from_observations(observations)

        self.assertEqual(
            report["measurements"]["ai_quality"],
            {
                "configured": False,
                "feature_disabled_entire_epoch": True,
                "schema_2_and_accounting_conserved_all_samples": True,
                "unspecified_requests_epoch_delta": 0,
                "alert_investigations_started_epoch_delta": 0,
                "alert_investigations_accepted_epoch_delta": 0,
                "alert_investigations_final_rejected_epoch_delta": 0,
                "causal_alert_id": None,
                "causal_investigation_sha256": None,
            },
        )
        self.validate_runtime(report)

    def test_builder_rejects_short_actual_capture_coverage(self) -> None:
        observations = copy.deepcopy(self.runtime["recorder_observations"])
        observations[0]["captured_at"] = iso(5)
        with self.assertRaisesRegex(
            qualification.QualificationError,
            "captured sample duration is below 900 seconds",
        ):
            self.rebuild_runtime_from_observations(observations)

    def test_builder_rejects_actual_capture_gap_above_limit(self) -> None:
        observations = copy.deepcopy(self.runtime["recorder_observations"])
        observations[10]["captured_at"] = iso(295)
        observations[11]["captured_at"] = iso(335)
        with self.assertRaisesRegex(
            qualification.QualificationError, "captured sample gap exceeds"
        ):
            self.rebuild_runtime_from_observations(observations)

    def test_builder_rejects_reused_heartbeat_tick(self) -> None:
        observations = copy.deepcopy(self.runtime["recorder_observations"])
        observations[5]["heartbeat"]["written_at_unix"] = observations[4][
            "heartbeat"
        ]["written_at_unix"]
        self.rebind_observation_heartbeat(observations[5])
        with self.assertRaisesRegex(
            qualification.QualificationError,
            "heartbeat timestamps must be strictly increasing",
        ):
            self.rebuild_runtime_from_observations(observations)

    def test_builder_rejects_skipped_heartbeat_tick(self) -> None:
        observations = copy.deepcopy(self.runtime["recorder_observations"])
        for index, observation in enumerate(observations):
            offset = observation["offset_seconds"]
            heartbeat_offset = offset - 25 if index <= 4 else offset + 5
            observation["heartbeat"]["written_at_unix"] = (
                qualification.parse_time(
                    iso(heartbeat_offset), "fixture heartbeat"
                ).timestamp()
            )
            self.rebind_observation_heartbeat(observation)
        with self.assertRaisesRegex(
            qualification.QualificationError,
            "heartbeat and capture intervals diverge",
        ):
            self.rebuild_runtime_from_observations(observations)

    def test_raw_sample_missing_conservation_boundary_is_rejected(self) -> None:
        report = copy.deepcopy(self.runtime)
        report["recorder_observations"][7]["heartbeat"]["event_pipeline"].pop(
            "merged_dropped_by_lane"
        )
        report["recorder_observations"][7]["heartbeat_file"][
            "raw_json"
        ] = qualification.canonical_json_bytes(
            report["recorder_observations"][7]["heartbeat"]
        ).decode("utf-8")
        report["recorder_observations"][7]["heartbeat_file"][
            "raw_sha256"
        ] = qualification.sha256_bytes(
            report["recorder_observations"][7]["heartbeat_file"]["raw_json"].encode(
                "utf-8"
            )
        )
        report["recorder_observations"][7]["heartbeat_file"][
            "canonical_sha256"
        ] = qualification.sha256_bytes(
            qualification.canonical_json_bytes(
                report["recorder_observations"][7]["heartbeat"]
            )
        )
        with self.assertRaisesRegex(qualification.QualificationError, "merged_dropped_by_lane"):
            self.validate_runtime(report)

    def test_raw_sample_loss_is_rejected(self) -> None:
        report = copy.deepcopy(self.runtime)
        report["recorder_observations"][9]["heartbeat"]["es_kernel_dropped_total"] = 1
        self.rederive_sample(report, 9)
        with self.assertRaisesRegex(qualification.QualificationError, "cumulative loss"):
            self.validate_runtime(report)

    def test_workload_digest_mismatch_is_rejected(self) -> None:
        report = copy.deepcopy(self.runtime)
        report["workload"]["burst_operations"].append("unrecorded changed burst")
        with self.assertRaisesRegex(qualification.QualificationError, "workload.sha256"):
            self.validate_runtime(report)

    def test_missing_conservation_boundary_is_rejected(self) -> None:
        report = copy.deepcopy(self.runtime)
        report["measurements"]["conservation"]["boundaries"].pop()
        with self.assertRaisesRegex(qualification.QualificationError, "boundary inventory"):
            self.validate_runtime(report)

    def test_missing_sqlite_family_is_rejected(self) -> None:
        report = copy.deepcopy(self.runtime)
        report["measurements"]["disk_safety"]["sqlite_families"] = [
            family
            for family in report["measurements"]["disk_safety"]["sqlite_families"]
            if family["name"] != "events.db"
        ]
        with self.assertRaisesRegex(qualification.QualificationError, "omits shipping stores"):
            self.validate_runtime(report)

    def test_priority_loss_is_rejected(self) -> None:
        report = copy.deepcopy(self.runtime)
        report["measurements"]["priority_fidelity"]["priority_lane_loss"] = 1
        with self.assertRaisesRegex(qualification.QualificationError, "must be zero"):
            self.validate_runtime(report)

    def test_successful_workload_without_ingress_movement_is_rejected(self) -> None:
        report = copy.deepcopy(self.runtime)
        for index, observation in enumerate(report["recorder_observations"]):
            if 330 <= observation["offset_seconds"] <= 390:
                pipeline = observation["heartbeat"]["event_pipeline"]
                for key in ("offered_by_lane", "completed_by_lane"):
                    pipeline[key] = {"priority": 300, "file": 300}
                heartbeat = observation["heartbeat"]
                heartbeat["events_storage_write_offered_by_lane"] = {
                    "priority": 300, "file": 300
                }
                heartbeat["events_storage_write_persisted_by_lane"] = {
                    "priority": 300, "file": 300
                }
                self.rederive_sample(report, index)
        with self.assertRaisesRegex(
            qualification.QualificationError, "predeclared reference load"
        ):
            self.validate_runtime(report)

    def test_priority_persistence_backlog_cannot_masquerade_as_delivery(self) -> None:
        report = copy.deepcopy(self.runtime)
        for index, observation in enumerate(report["recorder_observations"]):
            if 330 <= observation["offset_seconds"] <= 450:
                heartbeat = observation["heartbeat"]
                heartbeat["events_storage_write_offered_by_lane"]["priority"] = 40_300
                heartbeat["events_storage_write_persisted_by_lane"]["priority"] = 301
                heartbeat["events_storage_write_buffer_depth_by_lane"]["priority"] = 39_999
                self.rederive_sample(report, index)
        with self.assertRaisesRegex(
            qualification.QualificationError, "not drained"
        ):
            self.validate_runtime(report)

    def test_priority_persistence_shed_during_epoch_is_rejected(self) -> None:
        report = copy.deepcopy(self.runtime)
        for index, observation in enumerate(report["recorder_observations"]):
            if observation["offset_seconds"] >= 330:
                heartbeat = observation["heartbeat"]
                heartbeat["events_storage_write_offered_by_lane"]["priority"] += 1
                heartbeat["events_storage_write_dropped_by_lane"]["priority"] = 1
                self.rederive_sample(report, index)
        aggregate = next(
            row for row in report["measurements"]["conservation"]["boundaries"]
            if row["name"] == "priority-event-persistence"
        )
        aggregate["offered"] += 1
        aggregate["explicitly_shed"] = 1
        with self.assertRaisesRegex(
            qualification.QualificationError, "explicitly_shed"
        ):
            self.validate_runtime(report)

    def test_terminal_drop_and_poison_are_rejected_as_shed(self) -> None:
        for result_name in ("dropped", "poisoned"):
            with self.subTest(result=result_name):
                observations = copy.deepcopy(
                    self.runtime["recorder_observations"]
                )
                for observation in observations:
                    if observation["offset_seconds"] < 480:
                        continue
                    heartbeat = observation["heartbeat"]
                    heartbeat["event_terminal_revision_offered_total"] += 1
                    heartbeat[
                        "event_terminal_revision_offered_by_lane"
                    ]["priority"] += 1
                    heartbeat[
                        f"event_terminal_revision_{result_name}_total"
                    ] = 1
                    heartbeat[
                        f"event_terminal_revision_{result_name}_by_lane"
                    ]["priority"] = 1
                    heartbeat[
                        "event_terminal_revision_evidence_poisoned"
                    ] = True
                    self.rebind_observation_heartbeat(observation)
                report = self.rebuild_runtime_from_observations(observations)
                with self.assertRaisesRegex(
                    qualification.QualificationError,
                    "priority-event-terminal-persistence explicitly_shed=1",
                ):
                    self.validate_runtime(report)

    def test_terminal_queue_and_in_flight_must_drain(self) -> None:
        for gauge in ("buffer_depth", "in_flight_depth"):
            with self.subTest(gauge=gauge):
                observations = copy.deepcopy(
                    self.runtime["recorder_observations"]
                )
                observation = observations[-1]
                heartbeat = observation["heartbeat"]
                heartbeat["event_terminal_revision_offered_total"] += 1
                heartbeat[
                    "event_terminal_revision_offered_by_lane"
                ]["priority"] += 1
                heartbeat[f"event_terminal_revision_{gauge}"] = 1
                heartbeat[
                    f"event_terminal_revision_{gauge}_by_lane"
                ]["priority"] = 1
                self.rebind_observation_heartbeat(observation)
                report = self.rebuild_runtime_from_observations(observations)
                with self.assertRaisesRegex(
                    qualification.QualificationError,
                    "not drained at a fixed readiness boundary",
                ):
                    self.validate_runtime(report)

    def test_terminal_zero_ledger_cannot_claim_workload_persistence(self) -> None:
        observations = copy.deepcopy(self.runtime["recorder_observations"])
        for observation in observations:
            heartbeat = observation["heartbeat"]
            for outcome in ("offered", "unchanged", "durable"):
                heartbeat[f"event_terminal_revision_{outcome}_total"] = 0
                heartbeat[
                    f"event_terminal_revision_{outcome}_by_lane"
                ] = {"priority": 0, "file": 0}
            self.rebind_observation_heartbeat(observation)
        with self.assertRaisesRegex(
            qualification.QualificationError,
            "no measured priority-lane terminal persistence",
        ):
            self.rebuild_runtime_from_observations(observations)

    def test_terminal_repair_payload_expiry_poison_is_rejected(self) -> None:
        observations = copy.deepcopy(self.runtime["recorder_observations"])
        for observation in observations:
            if observation["offset_seconds"] >= 330:
                observation["heartbeat"][
                    "event_journal_repair_payload_expired_total"
                ] = 1
                self.rebind_observation_heartbeat(observation)
        report = self.rebuild_runtime_from_observations(observations)
        with self.assertRaisesRegex(
            qualification.QualificationError,
            "event journal repair payload expirations=1",
        ):
            self.validate_runtime(report)

    def test_event_type_count_window_unavailable_is_rejected(self) -> None:
        observation = copy.deepcopy(self.runtime["recorder_observations"][0])
        observation["heartbeat"]["event_type_count_window"][
            "query_available"
        ] = False
        self.rebind_observation_heartbeat(observation)
        with self.assertRaisesRegex(
            qualification.QualificationError, "count_window is unavailable"
        ):
            qualification.sample_from_recorder_observation(
                observation, "fixture unavailable count window"
            )

    def test_event_type_count_window_reason_sum_must_reconcile(self) -> None:
        observation = copy.deepcopy(self.runtime["recorder_observations"][0])
        observation["heartbeat"]["event_type_count_window"][
            "canonical_poison_records"
        ] = 1
        self.rebind_observation_heartbeat(observation)
        with self.assertRaisesRegex(
            qualification.QualificationError, "does not equal its reason ledger"
        ):
            qualification.sample_from_recorder_observation(
                observation, "fixture inconsistent count window"
            )

    def test_event_type_count_window_cannot_hide_incompleteness(self) -> None:
        observation = copy.deepcopy(self.runtime["recorder_observations"][0])
        observation["heartbeat"]["event_type_count_window"]["complete"] = True
        self.rebind_observation_heartbeat(observation)
        with self.assertRaisesRegex(
            qualification.QualificationError, "hides an incomplete window"
        ):
            qualification.sample_from_recorder_observation(
                observation, "fixture hidden incomplete count window"
            )

    def test_event_type_count_window_evidence_gap_is_rejected(self) -> None:
        observations = copy.deepcopy(self.runtime["recorder_observations"])
        window = observations[-1]["heartbeat"]["event_type_count_window"]
        window["canonical_poison_records"] = 1
        window["gap_records"] = 1
        self.rebind_observation_heartbeat(observations[-1])
        report = self.rebuild_runtime_from_observations(observations)
        with self.assertRaisesRegex(
            qualification.QualificationError,
            "exact event-type count window evidence gaps=1",
        ):
            self.validate_runtime(report)

    def test_event_search_projection_unavailable_is_rejected(self) -> None:
        observation = copy.deepcopy(self.runtime["recorder_observations"][0])
        observation["heartbeat"]["event_search_projection"][
            "query_available"
        ] = False
        self.rebind_observation_heartbeat(observation)
        with self.assertRaisesRegex(
            qualification.QualificationError,
            "event_search_projection is unavailable",
        ):
            qualification.sample_from_recorder_observation(
                observation, "fixture unavailable search projection"
            )

    def test_event_search_projection_omission_ledger_must_reconcile(self) -> None:
        observation = copy.deepcopy(self.runtime["recorder_observations"][1])
        observation["heartbeat"]["event_search_projection"][
            "projection_omitted_total"
        ] += 1
        self.rebind_observation_heartbeat(observation)
        with self.assertRaisesRegex(
            qualification.QualificationError,
            "projection_omitted_total does not reconcile",
        ):
            qualification.sample_from_recorder_observation(
                observation, "fixture inconsistent search projection"
            )

    def test_event_search_projection_cannot_hide_sparse_coverage(self) -> None:
        observation = copy.deepcopy(self.runtime["recorder_observations"][1])
        observation["heartbeat"]["event_search_projection"]["complete"] = True
        self.rebind_observation_heartbeat(observation)
        with self.assertRaisesRegex(
            qualification.QualificationError,
            "complete hides sparse or gapped coverage",
        ):
            qualification.sample_from_recorder_observation(
                observation, "fixture hidden sparse search projection"
            )

    def test_rule_sync_must_match_sealed_candidate_manifest(self) -> None:
        observations = copy.deepcopy(self.runtime["recorder_observations"])
        for observation in observations:
            observation["heartbeat"]["rule_sync"][
                "installed_manifest_sha256"
            ] = "f" * 64
            self.rebind_observation_heartbeat(observation)
        with self.assertRaisesRegex(
            qualification.QualificationError,
            "installed rule corpus does not match the sealed candidate corpus",
        ):
            self.rebuild_runtime_from_observations(observations)

    def test_rule_sync_skipped_or_unverified_is_rejected(self) -> None:
        for mutation in (
            {"status": "skipped"},
            {"installed_corpus_verified": False},
        ):
            with self.subTest(mutation=mutation):
                observation = copy.deepcopy(
                    self.runtime["recorder_observations"][0]
                )
                observation["heartbeat"]["rule_sync"].update(mutation)
                self.rebind_observation_heartbeat(observation)
                with self.assertRaisesRegex(
                    qualification.QualificationError,
                    "did not verify|unverified or tampered",
                ):
                    qualification.sample_from_recorder_observation(
                        observation, "fixture invalid rule sync"
                    )

    def test_event_journal_recovery_ledger_must_conserve(self) -> None:
        observation = copy.deepcopy(self.runtime["recorder_observations"][0])
        observation["heartbeat"]["event_journal_recovery"][
            "migrated_events"
        ] += 1
        self.rebind_observation_heartbeat(observation)
        with self.assertRaisesRegex(
            qualification.QualificationError,
            "conserved does not match its event ledger",
        ):
            qualification.sample_from_recorder_observation(
                observation, "fixture broken journal recovery"
            )

    def test_event_journal_recovery_must_be_complete_and_drained(self) -> None:
        observation = copy.deepcopy(self.runtime["recorder_observations"][0])
        recovery = observation["heartbeat"]["event_journal_recovery"]
        recovery["migrated_events"] -= 1
        recovery["remaining_events"] = 1
        recovery["complete"] = False
        self.rebind_observation_heartbeat(observation)
        with self.assertRaisesRegex(
            qualification.QualificationError,
            "not a complete conserving boundary",
        ):
            qualification.sample_from_recorder_observation(
                observation, "fixture incomplete journal recovery"
            )

    def test_unavailable_trace_store_is_rejected(self) -> None:
        report = copy.deepcopy(self.runtime)
        report["recorder_observations"][12]["heartbeat"][
            "traces_storage_admission"
        ]["store_available"] = False
        self.rederive_sample(report, 12)
        with self.assertRaisesRegex(
            qualification.QualificationError, "not an enabled full writer"
        ):
            self.validate_runtime(report)

    def test_zero_trace_store_workload_is_rejected(self) -> None:
        report = copy.deepcopy(self.runtime)
        for index, observation in enumerate(report["recorder_observations"]):
            if 330 <= observation["offset_seconds"] <= 450:
                ledger = observation["heartbeat"]["traces_storage_admission"][
                    "ingest_conservation"
                ]
                ledger["offered"] = 300
                ledger["completed"] = 300
                self.rederive_sample(report, index)
        with self.assertRaisesRegex(
            qualification.QualificationError, "real TraceStore ingest"
        ):
            self.validate_runtime(report)

    def test_trace_graph_coalescing_claim_cannot_replace_raw_accounting(self) -> None:
        report = copy.deepcopy(self.runtime)
        graph = report["recorder_observations"][8]["heartbeat"][
            "tracegraph_storage_admission"
        ]
        graph["coalesced_noop_rows_total"] += 1
        with self.assertRaisesRegex(
            qualification.QualificationError, "observation/coalescing ledger"
        ):
            self.rederive_sample(report, 8)

    def test_live_reload_error_transcript_is_rejected(self) -> None:
        report = copy.deepcopy(self.runtime)
        evidence = report["recorder_probe_evidence"]["rule_reload_log"]
        output = (
            "[SIGHUP] ERROR: qualification fixture failure\n"
            "[SIGHUP] Reloaded 12 single + 3 sequence rules\n"
        )
        evidence.update(
            {
                "output": output,
                "output_sha256": qualification.sha256_bytes(output.encode("utf-8")),
                "output_tail": output,
                "output_line_count": 2,
            }
        )
        with self.assertRaisesRegex(
            qualification.QualificationError, "rejected or failed live reload"
        ):
            self.validate_runtime(report)

    def test_runtime_workload_uses_dedup_safe_unique_alert_executable(self) -> None:
        workload = (ROOT / "scripts/runtime-qualification-workload.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn('ALERT_EXECUTABLE="$ALERT_DIR/', workload)
        self.assertIn(
            'BULK_DIR="/Users/Shared/MacCrabQualificationRuntime-$RUN_ID"',
            workload,
        )
        self.assertIn('"$ALERT_EXECUTABLE"', workload)
        self.assertNotIn("/bin/echo '/dev/tcp/", workload)

    def test_transitive_workload_executor_hash_is_recomputed(self) -> None:
        report = copy.deepcopy(self.runtime)
        report["workload"]["executors"][1]["sha256"] = "f" * 64
        payload = {
            key: copy.deepcopy(report["workload"][key])
            for key in (
                "id", "version", "description", "normal_operations",
                "burst_operations", "executors",
            )
        }
        report["workload"]["sha256"] = qualification.sha256_bytes(
            qualification.canonical_json_bytes(payload)
        )
        with self.assertRaisesRegex(
            qualification.QualificationError, "executor bytes changed"
        ):
            self.validate_runtime(report)

    def test_disk_window_above_four_mib_per_second_is_rejected(self) -> None:
        report = copy.deepcopy(self.runtime)
        report["measurements"]["disk_writes"]["windows"][0]["bytes"] = 5 * 1024 * 1024 * 60
        report["measurements"]["disk_writes"]["engine_bytes"] += 5 * 1024 * 1024 * 60 - 1024 * 1024
        report["measurements"]["disk_writes"]["average_bytes_per_second"] = report["measurements"]["disk_writes"]["engine_bytes"] / 900
        with self.assertRaises(qualification.QualificationError):
            self.validate_runtime(report)

    def test_legal_capture_jitter_cannot_false_pass_max_write_rate(self) -> None:
        observations = copy.deepcopy(self.runtime["recorder_observations"])
        observations[1]["captured_at"] = iso(35)
        observations[2]["captured_at"] = iso(55)
        scheduled_passing_bytes = 7 * qualification.MIB * 15
        first_total = observations[1]["process"][
            "engine_disk_write_bytes_total"
        ]
        original_second_total = observations[2]["process"][
            "engine_disk_write_bytes_total"
        ]
        adjustment = (
            first_total + scheduled_passing_bytes - original_second_total
        )
        for observation in observations[2:]:
            observation["process"]["engine_disk_write_bytes_total"] += adjustment

        report = self.rebuild_runtime_from_observations(observations)
        first_window = report["measurements"]["disk_writes"]["windows"][1]
        self.assertLess(
            first_window["bytes"]
            / (
                first_window["end_offset_seconds"]
                - first_window["start_offset_seconds"]
            ),
            qualification.MAX_WINDOW_WRITE_BYTES_PER_SECOND,
        )
        self.assertGreater(
            first_window["bytes"] / first_window["captured_elapsed_seconds"],
            qualification.MAX_WINDOW_WRITE_BYTES_PER_SECOND,
        )
        with self.assertRaisesRegex(
            qualification.QualificationError, "disk write window 1"
        ):
            self.validate_runtime(report)

    def test_full_epoch_cpu_rate_uses_legal_capture_jitter(self) -> None:
        observations = copy.deepcopy(self.runtime["recorder_observations"])
        observations[-1]["captured_at"] = iso(905)
        observations[-1]["process"]["engine_cpu_seconds_total"] = 451.0

        report = self.rebuild_runtime_from_observations(observations)
        cpu = report["measurements"]["cpu"]
        self.assertGreater(
            cpu["engine_cpu_seconds"] / qualification.MIN_EPOCH_SECONDS,
            qualification.MAX_ENGINE_AVERAGE_CORES,
        )
        self.assertLess(
            cpu["engine_average_cores"],
            qualification.MAX_ENGINE_AVERAGE_CORES,
        )
        self.validate_runtime(report)

    def test_disk_windows_cannot_redistribute_raw_sample_bytes(self) -> None:
        report = copy.deepcopy(self.runtime)
        report["measurements"]["disk_writes"]["windows"][0]["bytes"] = 0
        report["measurements"]["disk_writes"]["windows"][1]["bytes"] += 512 * 1024
        with self.assertRaisesRegex(qualification.QualificationError, "cumulative samples"):
            self.validate_runtime(report)

    def test_sequence_eviction_during_epoch_is_rejected(self) -> None:
        report = copy.deepcopy(self.runtime)
        report["recorder_observations"][-1]["heartbeat"][
            "sequence_pending_steps_evicted_total"
        ] = 8
        journal = report["recorder_observations"][-1]["heartbeat"][
            "sequence_journal_conservation"
        ]
        journal["offered"] += 1
        journal["explicitly_shed"] += 1
        self.rederive_sample(report, -1)
        aggregate = next(
            row
            for row in report["measurements"]["conservation"]["boundaries"]
            if row["name"] == "sequence-journal"
        )
        aggregate["offered"] += 1
        aggregate["explicitly_shed"] += 1
        report["measurements"]["correlation_continuity"][
            "pending_later_step_evictions_epoch_delta"
        ] = 1
        report["measurements"]["correlation_continuity"]["journal_shed"] = 1
        with self.assertRaisesRegex(qualification.QualificationError, "evictions"):
            self.validate_runtime(report)

    def test_sequence_journal_shed_must_reconcile_with_eviction_counter(self) -> None:
        report = copy.deepcopy(self.runtime)
        journal = report["recorder_observations"][-1]["heartbeat"][
            "sequence_journal_conservation"
        ]
        journal["offered"] += 1
        journal["explicitly_shed"] += 1
        self.rederive_sample(report, -1)
        aggregate = next(
            row
            for row in report["measurements"]["conservation"]["boundaries"]
            if row["name"] == "sequence-journal"
        )
        aggregate["offered"] += 1
        aggregate["explicitly_shed"] += 1
        report["measurements"]["correlation_continuity"]["journal_shed"] = 1
        with self.assertRaisesRegex(qualification.QualificationError, "explicitly_shed"):
            self.validate_runtime(report)

    def test_durable_pending_steps_do_not_fail_the_fixed_drain_boundary(self) -> None:
        """Out-of-order pending steps are durable state, not a writer backlog.

        The journal's `queued` gauge holds partial sequence steps parked for an
        earlier step that may never be offered inside this window at all.
        Judging the drain by offered-delta == completed-delta silently required
        that gauge to land back on its window-start value, which is a property
        of ambient host activity rather than of journal health -- the same
        aliasing readiness already exempts by name.  Loss and unbounded growth
        stay gated by the shed and eviction checks, which stay zero here.
        """
        report = copy.deepcopy(self.runtime)
        drained = [
            index
            for index, sample in enumerate(report["samples"])
            if sample["offset_seconds"]
            >= qualification.BURST_DRAIN_OFFSET_SECONDS
        ]
        self.assertTrue(drained)
        for index in drained:
            heartbeat = report["recorder_observations"][index]["heartbeat"]
            heartbeat["sequence_journal_conservation"]["offered"] += 2
            heartbeat["sequence_journal_conservation"]["queued"] += 2
            heartbeat["sequence_pending_steps_current"] += 2
            self.rederive_sample(report, index)
        aggregate = next(
            row
            for row in report["measurements"]["conservation"]["boundaries"]
            if row["name"] == "sequence-journal"
        )
        aggregate["offered"] += 2
        aggregate["queued"] += 2
        # The recorder derives this block from the same samples; the
        # reconciliation exists to catch a forged aggregate, not a moved host.
        report["measurements"]["workload_ingress"] = (
            qualification.derive_workload_ingress(report["samples"])
        )

        self.validate_runtime(report)

        window = qualification.derive_workload_ingress(report["samples"])
        self.assertEqual(
            window["sequence_journal_queued_drain"],
            window["sequence_journal_queued_start"] + 2,
        )
        self.assertNotEqual(
            window["sequence_journal_offered_delta"],
            window["sequence_journal_completed_delta"],
        )

    def test_sequence_journal_in_flight_at_a_fixed_boundary_is_rejected(self) -> None:
        """in_flight=0 is the assumption the readiness exemption rests on.

        Readiness exempts `sequence-journal` from its queued check because the
        producer is actor-synchronous and publishes in_flight=0.  Nothing used
        to verify that, so an asynchronous journal would inherit the exemption
        and hide a genuine writer backlog.  The fixed boundary pins it at both
        ends of the window.
        """
        for boundary in (
            qualification.BURST_START_OFFSET_SECONDS,
            qualification.BURST_DRAIN_OFFSET_SECONDS,
        ):
            with self.subTest(boundary=boundary):
                samples = copy.deepcopy(self.runtime["samples"])
                for sample in samples:
                    if sample["offset_seconds"] >= boundary:
                        journal = sample["conservation"]["sequence-journal"]
                        journal["offered"] += 1
                        journal["in_flight"] = 1
                with self.assertRaisesRegex(
                    qualification.QualificationError,
                    "in-flight work across a fixed boundary",
                ):
                    qualification.derive_workload_ingress(samples)

    def test_memory_growth_above_64_mib_is_rejected(self) -> None:
        report = copy.deepcopy(self.runtime)
        report["recorder_observations"][-1]["process"][
            "engine_memory_footprint_bytes"
        ] = 300 * 1024 * 1024
        self.rederive_sample(report, -1)
        report["measurements"]["memory"]["engine_max_memory_footprint_bytes"] = 300 * 1024 * 1024
        report["measurements"]["memory"]["engine_memory_footprint_minute_15_bytes"] = 300 * 1024 * 1024
        with self.assertRaisesRegex(qualification.QualificationError, "growth"):
            self.validate_runtime(report)

    def test_containment_source_digest_mismatch_is_rejected(self) -> None:
        report = self.containment_report()
        report["containment_sources_sha256"] = "e" * 64
        with self.assertRaisesRegex(qualification.QualificationError, "source bytes changed"):
            self.validate_containment(report)

    def test_exact_source_assertion_rejects_post_capture_mutation(self) -> None:
        source = self.root / "source-fixture"
        source.mkdir()
        tracked = source / "tracked.txt"
        tracked.write_text("candidate bytes\n", encoding="utf-8")
        subprocess.run(
            ["/usr/bin/git", "init", "-q", str(source)], check=True
        )
        subprocess.run(
            ["/usr/bin/git", "-C", str(source), "add", "tracked.txt"], check=True
        )
        subprocess.run(
            [
                "/usr/bin/git", "-C", str(source),
                "-c", "user.name=Qualification Fixture",
                "-c", "user.email=qualification@example.invalid",
                "commit", "-q", "-m", "fixture",
            ],
            check=True,
        )
        commit = subprocess.run(
            ["/usr/bin/git", "-C", str(source), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        tree = subprocess.run(
            ["/usr/bin/git", "-C", str(source), "rev-parse", "HEAD^{tree}"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        qualification.assert_exact_clean_source(
            source.resolve(), source_commit=commit, source_tree=tree,
            label="fixture pre-capture",
        )
        tracked.write_text("mutated after capture started\n", encoding="utf-8")
        with self.assertRaisesRegex(
            qualification.QualificationError, "clean exact candidate"
        ):
            qualification.assert_exact_clean_source(
                source.resolve(), source_commit=commit, source_tree=tree,
                label="fixture post-capture",
            )

    def test_containment_fixture_passes_only_in_test_mode(self) -> None:
        report = self.containment_report()
        self.validate_containment(report)
        with self.assertRaisesRegex(
            qualification.QualificationError, "live exact-candidate"
        ):
            qualification.validate_containment_report(
                report,
                version=VERSION,
                source_commit=COMMIT,
                source_tree=TREE,
                candidate_manifest_sha256=self.manifest_sha,
                candidate=self.manifest["candidate"],
                candidate_verification=self.manifest["artifact_verification"],
                root=ROOT,
            )

    def test_incomplete_containment_transcript_cannot_self_attest(self) -> None:
        report = self.containment_report()
        run = report["recorder_evidence"]["bundle_runs"][1]["run"]
        output = run["output"].replace("broker.read.ok", "unexpected.empty")
        run.update(
            {
                "output": output,
                "output_sha256": qualification.sha256_bytes(output.encode("utf-8")),
                "output_tail": output[-4096:],
                "output_line_count": len(output.splitlines()),
            }
        )
        with self.assertRaisesRegex(
            qualification.QualificationError, "lacks required proof"
        ):
            self.validate_containment(report)

    def test_failed_containment_process_is_rejected(self) -> None:
        report = self.containment_report()
        report["recorder_evidence"]["bundle_runs"][0]["run"]["exit_code"] = 1
        with self.assertRaisesRegex(
            qualification.QualificationError, "did not pass"
        ):
            self.validate_containment(report)

    def test_containment_ambient_environment_is_rejected(self) -> None:
        report = self.containment_report()
        report["recorder_evidence"]["bundle_runs"][0]["run"]["environment"][
            "DYLD_INSERT_LIBRARIES"
        ] = "/private/tmp/fixture.dylib"
        with self.assertRaisesRegex(
            qualification.QualificationError, "unexpected environment"
        ):
            self.validate_containment(report)

    def test_containment_cached_build_output_is_rejected(self) -> None:
        report = self.containment_report()
        cached_bin = str(ROOT / ".build/arm64-apple-macosx/release")
        bin_probe = report["recorder_evidence"]["bin_path"]
        output = cached_bin + "\n"
        bin_probe.update(
            {
                "output": output,
                "output_sha256": qualification.sha256_bytes(output.encode("utf-8")),
                "output_tail": output,
                "output_line_count": 1,
            }
        )
        for row in report["recorder_evidence"]["fixture_inputs"]:
            row["path"] = f"{cached_bin}/{row['product']}"
        with self.assertRaisesRegex(
            qualification.QualificationError, "outside its private"
        ):
            self.validate_containment(report)

    def test_containment_requires_reachable_network_control(self) -> None:
        report = self.containment_report()
        report["recorder_evidence"]["network_control"][
            "unsandboxed_reachable"
        ] = False
        with self.assertRaisesRegex(
            qualification.QualificationError, "not proven reachable"
        ):
            self.validate_containment(report)

        report = self.containment_report()
        del report["recorder_evidence"]["network_control"]
        with self.assertRaisesRegex(
            qualification.QualificationError, "inventory is incomplete"
        ):
            self.validate_containment(report)

    def test_containment_requires_complete_unsandboxed_deny_control(self) -> None:
        report = self.containment_report()
        probe = report["recorder_evidence"]["unsandboxed_controls"][0]["probe"]
        output = probe["output"].replace(
            '{"kind":"artifact","artifact":{"contentType":"leak.network",'
            '"privacyClass":"metadata","summary":"control","data":{}}}\n',
            "",
        )
        probe.update(
            {
                "output": output,
                "output_sha256": qualification.sha256_bytes(output.encode("utf-8")),
                "output_tail": output[-4096:],
                "output_line_count": len(output.splitlines()),
            }
        )
        with self.assertRaisesRegex(
            qualification.QualificationError, "complete deny battery"
        ):
            self.validate_containment(report)

    def test_tampered_candidate_containment_binary_is_rejected(self) -> None:
        report = self.containment_report()
        report["recorder_evidence"]["candidate_execution"]["binaries"][1][
            "sha256"
        ] = "f" * 64
        with self.assertRaisesRegex(
            qualification.QualificationError, "do not match the mounted payload"
        ):
            self.validate_containment(report)

    def test_containment_probes_self_seed_only_the_runner_scratch_path(self) -> None:
        c_probe = (
            ROOT / "Sources/maccrab-tierb-corpus-probe/main.c"
        ).read_text(encoding="utf-8")
        swift_probe = (
            ROOT / "Sources/maccrab-tierb-corpus-probe-swift/main.swift"
        ).read_text(encoding="utf-8")
        self.assertIn('snprintf(path, sizeof(path), "%s/allowed.txt", scratch)', c_probe)
        self.assertIn("O_WRONLY | O_CREAT | O_TRUNC", c_probe)
        self.assertIn('let path = scratch + "/allowed.txt"', swift_probe)
        self.assertIn('Data("BROKER-OK".utf8).write', swift_probe)
        self.assertIn('inet_pton(AF_INET, "127.0.0.1"', c_probe)
        self.assertIn('inet_pton(AF_INET, "127.0.0.1"', swift_probe)
        self.assertIn("htons(49373)", c_probe)
        self.assertIn("in_port_t(49373).bigEndian", swift_probe)
        self.assertIn("maccrab_tierb_recv_fd(3", c_probe)
        self.assertIn("maccrab_tierb_recv_fd(3", swift_probe)

    def test_containment_run_must_use_the_mounted_candidate_cli(self) -> None:
        report = self.containment_report()
        report["recorder_evidence"]["bundle_runs"][0]["run"]["command"][0] = (
            "/fixture/Volumes/Other/MacCrab.app/Contents/Resources/bin/maccrabctl"
        )
        with self.assertRaisesRegex(
            qualification.QualificationError, "exact candidate CLI"
        ):
            self.validate_containment(report)

    def test_containment_leak_artifact_is_rejected_even_with_rebound_transcript(self) -> None:
        report = self.containment_report()
        run = report["recorder_evidence"]["bundle_runs"][1]["run"]
        output = run["output"].replace(
            "  Artifacts:    1\n",
            "  Artifacts:    2\n    - leak.network: egress succeeded\n",
        )
        run.update(
            {
                "output": output,
                "output_sha256": qualification.sha256_bytes(output.encode("utf-8")),
                "output_tail": output[-4096:],
                "output_line_count": len(output.splitlines()),
            }
        )
        with self.assertRaisesRegex(
            qualification.QualificationError, "exposed a denied surface"
        ):
            self.validate_containment(report)

    def test_record_containment_rejects_external_timestamps(self) -> None:
        with self.assertRaises(SystemExit):
            qualification.parser().parse_args(
                [
                    "record-containment",
                    "--version", VERSION,
                    "--source-root", str(ROOT),
                    "--candidate-manifest", str(self.manifest_path),
                    "--dmg", str(self.dmg),
                    "--output", str(self.root / "containment.json"),
                    "--started-at", iso(0),
                    "--ended-at", iso(10),
                ]
            )

    def test_containment_candidate_mismatch_is_rejected(self) -> None:
        report = self.containment_report()
        report["candidate"]["dmg"]["sha256"] = "f" * 64
        with self.assertRaisesRegex(qualification.QualificationError, "exact candidate and DMG"):
            self.validate_containment(report)


if __name__ == "__main__":
    unittest.main(verbosity=2)
