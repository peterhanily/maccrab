#!/usr/bin/env python3
"""Deterministic offline fixtures for candidate-qualification.py."""

from __future__ import annotations

import copy
import contextlib
import ctypes
import datetime as dt
import hashlib
import importlib.util
import inspect
import re
import json
import io
import os
import pathlib
import signal
import sqlite3
import subprocess
import sys
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
BUILD_NUMBER = "9.9.9.123"


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
                    "oldest_outstanding_age_seconds": 0.0,
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
        "pid": 4321,
        "process_start_abstime": 987654321,
        "running_cdhash": installed_agent["cdhashes"]["arm64"],
        "cdhash": installed_agent["cdhashes"]["arm64"],
        "architecture": "arm64",
        "executable_path": (
            "/Library/SystemExtensions/fixture/"
            "com.maccrab.agent.systemextension/Contents/MacOS/com.maccrab.agent"
        ),
        "system_extension_bundle_identifier": qualification.EXPECTED_AGENT_IDENTIFIER,
    }
    gui_image = next(entry for entry in manifest["artifact_verification"]["payload_inventory"]["entries"]
                     if entry["path"] == qualification.GUI_PAYLOAD_PATH)
    gui_process = {
        "pid": 5432, "process_start_abstime": 123456789,
        "executable_path": "/Applications/" + qualification.GUI_PAYLOAD_PATH,
        "executable_sha256": gui_image["sha256"],
        "running_cdhash": manifest["artifact_verification"]["app_cdhashes"]["arm64"],
    }
    gui_identity = {
        **gui_process, "developer_id": qualification.EXPECTED_DEVELOPER_ID,
        "team_id": qualification.EXPECTED_TEAM_ID,
        "signing_identifier": qualification.EXPECTED_APP_IDENTIFIER,
        "cdhash": "b" * 40, "bundle_identifier": qualification.EXPECTED_APP_IDENTIFIER,
        "architecture": "arm64",
        "bundle_version": candidate["version"], "build_version": candidate["build_number"],
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
            "engine_started_at_unix": qualification.parse_time(iso(-600), "fixture boot").timestamp(),
            "engine_uptime_seconds": 600 + sample["offset_seconds"],
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
            "events_storage_write_admitted_generation": sum(
                boundaries[f"{lane}-event-persistence"]["offered"] for lane in ("priority", "file")
            ),
            "events_storage_write_terminal_generation": sum(
                boundaries[f"{lane}-event-persistence"]["completed"]
                + boundaries[f"{lane}-event-persistence"]["explicitly_shed"]
                for lane in ("priority", "file")
            ),
            "events_storage_write_poisoned_total": 0,
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
                "search_index_degraded": False,
                "search_index_reason": "healthy",
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
            "es_mode": "native client",
            "es_client_split_degraded": False,
            "es_sensor_degraded": False,
            "es_sensor_degraded_detail": "nominal",
            "collector_health": [
                {
                    "name": "ESCollector", "enabled": True,
                    "state": "healthy", "healthy": True,
                    "reason": "native callbacks active",
                    "error_count": 0,
                    "native_canary_checks_total": 1,
                    "native_canary_failures_total": 0,
                    "native_canary_outcome": "healthy",
                    "native_callback_age_seconds": 1.0,
                    "native_canary_age_seconds": 20.0,
                },
                {
                    "name": "FSEventsCollector", "enabled": False,
                    "state": "disabled", "healthy": False,
                    "reason": "Endpoint Security provides file monitoring",
                },
                {
                    "name": "UltrasonicMonitor", "enabled": False,
                    "state": "disabled", "healthy": False,
                    "reason": "Optional microphone monitoring is turned off",
                },
            ],
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
            "event_journal_index": {
                "refreshes_total": 1 + sample["offset_seconds"] // 30,
                "slow_refreshes_total": 0,
                "last_refresh_ms": 1,
                "full_rebuilds_total": 1,
                "append_refreshes_total": sample["offset_seconds"] // 30,
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
                    "pid": installed_identity["pid"],
                    "process_start_abstime": installed_identity["process_start_abstime"],
                    "running_cdhash": installed_identity["running_cdhash"],
                    "engine_cpu_seconds_total": sample["engine_cpu_seconds_total"],
                    "engine_disk_write_bytes_total": sample[
                        "engine_disk_write_bytes_total"
                    ],
                    "engine_memory_footprint_bytes": sample["engine_memory_footprint_bytes"],
                    "executable_path": installed_identity["executable_path"],
                    "executable_sha256": installed_identity["executable_sha256"],
                },
                "gui_process": copy.deepcopy(gui_process),
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
        f"iterations={qualification.FIXED_WORKLOAD_ITERATIONS} "
        "otlp_spans=1 alert_triggers=1 sequence_probes=1\n"
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
            "completed_at": iso(322),
            "timing_source": qualification.WORKLOAD_TIMING_SOURCE,
            "elapsed_monotonic_seconds": 22.0,
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
            "sample_offset_seconds": qualification.BURST_DRAIN_OFFSET_SECONDS,
            "sent_at": iso(qualification.BURST_DRAIN_OFFSET_SECONDS),
        },
    }
    probes = {
        "installed_engine_start": {**installed_identity, "inspection_started_at": iso(0), "recorded_at": iso(0)},
        "installed_engine_end": {**installed_identity, "inspection_started_at": iso(900), "recorded_at": iso(900)},
        "installed_gui_start": {**gui_identity, "inspection_started_at": iso(0), "recorded_at": iso(0)},
        "installed_gui_end": {**gui_identity, "inspection_started_at": iso(900), "recorded_at": iso(900)},
        "crash_count": 0,
        "watchdog_exit_count": 0,
        "source_rule_corpus_sha256": qualification.rule_corpus_digest(ROOT),
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
    def test_process_scope_records_boot_and_monotonic_age(self) -> None:
        process = self.runtime["measurements"]["process"]
        self.assertEqual(process["engine_uptime_seconds_at_t0"], 600)
        self.assertEqual(process["engine_uptime_seconds_at_end"], 1500)
        self.assertEqual(self.runtime["counter_scope_policy"], qualification.RUNTIME_COUNTER_SCOPE_POLICY)
        self.validate_runtime()

    def test_same_pid_with_new_boot_is_not_one_epoch(self) -> None:
        observations = copy.deepcopy(self.runtime["recorder_observations"])
        observations[-1]["heartbeat"]["engine_started_at_unix"] += 1
        self.rebind_observation_heartbeat(observations[-1])
        with self.assertRaisesRegex(qualification.QualificationError, "process start changed"):
            self.rebuild_runtime_from_observations(observations)

    def test_process_uptime_is_required_and_cannot_reset(self) -> None:
        observations = copy.deepcopy(self.runtime["recorder_observations"])
        observations[-1]["heartbeat"]["engine_uptime_seconds"] = 1
        self.rebind_observation_heartbeat(observations[-1])
        with self.assertRaisesRegex(qualification.QualificationError, "uptime did not advance"):
            self.rebuild_runtime_from_observations(observations)
        del observations[-1]["heartbeat"]["engine_uptime_seconds"]
        self.rebind_observation_heartbeat(observations[-1])
        with self.assertRaisesRegex(qualification.QualificationError, "engine_uptime_seconds"):
            self.rebuild_runtime_from_observations(observations)

    def test_steady_epoch_requires_completed_warmup(self) -> None:
        observations = copy.deepcopy(self.runtime["recorder_observations"])
        for observation in observations:
            observation["heartbeat"]["engine_uptime_seconds"] = 10 + observation["offset_seconds"]
            self.rebind_observation_heartbeat(observation)
        with self.assertRaisesRegex(qualification.QualificationError, "250-second engine warmup"):
            self.rebuild_runtime_from_observations(observations)

    def test_present_candidate_gui_identity_is_bound_to_all_samples(self) -> None:
        process = self.runtime["samples"][0]["gui_process"]
        self.assertEqual(process["pid"], 5432)
        self.assertEqual(self.runtime["measurements"]["cpu"]["gui_cpu_statistic"], "ps-pcpu-snapshot")
        self.validate_runtime()

    def test_absent_gui_process_evidence_cannot_mean_zero_cpu(self) -> None:
        observations = copy.deepcopy(self.runtime["recorder_observations"])
        observations[-1].pop("gui_process")
        observations[-1]["gui_background_cpu_percent"] = 0
        with self.assertRaisesRegex(qualification.QualificationError, "gui_process"):
            self.rebuild_runtime_from_observations(observations)

    def test_present_idle_candidate_gui_can_have_measured_zero_cpu(self) -> None:
        observations = copy.deepcopy(self.runtime["recorder_observations"])
        for observation in observations:
            observation["gui_background_cpu_percent"] = 0
        report = self.rebuild_runtime_from_observations(observations)
        self.assertEqual(report["measurements"]["cpu"]["gui_background_p95_percent"], 0)
        self.validate_runtime(report)

    def test_gui_restart_and_reused_pid_fail_epoch_continuity(self) -> None:
        for field in ("pid", "process_start_abstime"):
            with self.subTest(field=field):
                observations = copy.deepcopy(self.runtime["recorder_observations"])
                observations[-1]["gui_process"][field] += 1
                with self.assertRaisesRegex(qualification.QualificationError, "GUI process identity changed"):
                    self.rebuild_runtime_from_observations(observations)

    def test_another_gui_image_cannot_supply_candidate_cpu_samples(self) -> None:
        observations = copy.deepcopy(self.runtime["recorder_observations"])
        observations[-1]["gui_process"]["executable_sha256"] = "c" * 64
        with self.assertRaisesRegex(qualification.QualificationError, "exact candidate GUI image"):
            self.rebuild_runtime_from_observations(observations)

    def test_gui_endpoint_requires_same_signed_candidate_and_process(self) -> None:
        for key, value, reason in (
            ("build_version", "prior-build", "version/build/identifier"),
            ("pid", 5433, "every sampled process"),
            ("process_start_abstime", 123456790, "every sampled process"),
        ):
            with self.subTest(key=key):
                report = copy.deepcopy(self.runtime)
                report["installed_gui"]["end"][key] = value
                with self.assertRaisesRegex(qualification.QualificationError, reason):
                    self.validate_runtime(report)

    def test_gui_probe_requires_exactly_one_present_process(self) -> None:
        line = "5432 5.0 /Applications/MacCrab.app/Contents/MacOS/MacCrab\n"
        for output in ("1 0.0 /sbin/launchd\n", line + line.replace("5432", "6543")):
            with self.subTest(output=output), mock.patch.object(qualification, "command_text", return_value=output):
                with self.assertRaisesRegex(qualification.QualificationError, "exactly one running MacCrab GUI"):
                    qualification.gui_process_observation()

    def test_gui_probe_records_present_process_and_focused_ps_snapshot(self) -> None:
        process = copy.deepcopy(self.runtime["samples"][0]["gui_process"])
        usage = qualification.DarwinRUsageInfoV4()
        usage.ri_proc_start_abstime = process["process_start_abstime"]
        discovery = f"5432 5.0 {process['executable_path']}\n"
        measured = f"5432 7.5 {process['executable_path']}\n"
        with mock.patch.object(qualification, "command_text", side_effect=[discovery, measured]), \
                mock.patch.object(qualification, "darwin_process_metrics", return_value=process), \
                mock.patch.object(qualification, "darwin_process_cdhash", return_value=process["running_cdhash"]), \
                mock.patch.object(qualification, "darwin_process_rusage", return_value=usage), \
                mock.patch.object(qualification, "darwin_process_path", return_value=pathlib.Path(process["executable_path"])):
            observed = qualification.gui_process_observation()
        self.assertEqual(observed, {"process": process, "cpu_percent": 7.5})

    def test_gui_probe_detects_disappearance_and_restart_during_sample(self) -> None:
        process = copy.deepcopy(self.runtime["samples"][0]["gui_process"])
        line = f"5432 5.0 {process['executable_path']}\n"
        usage = qualification.DarwinRUsageInfoV4()
        usage.ri_proc_start_abstime = process["process_start_abstime"] + 1
        for second, reason in (("", "disappeared"), (line, "changed while")):
            with self.subTest(reason=reason), \
                    mock.patch.object(qualification, "command_text", side_effect=[line, second]), \
                    mock.patch.object(qualification, "darwin_process_metrics", return_value=process), \
                    mock.patch.object(qualification, "darwin_process_cdhash", return_value=process["running_cdhash"]), \
                    mock.patch.object(qualification, "darwin_process_rusage", return_value=usage), \
                    mock.patch.object(qualification, "darwin_process_path", return_value=pathlib.Path(process["executable_path"])):
                with self.assertRaisesRegex(qualification.QualificationError, reason):
                    qualification.gui_process_observation()

    def test_prior_running_gui_hash_does_not_match_replaced_candidate_disk_image(self) -> None:
        observations = copy.deepcopy(self.runtime["recorder_observations"])
        # Ordinary upgrade state: disk now holds this candidate while the older
        # GUI process still owns its previous CodeDirectory identity.
        observations[-1]["gui_process"]["running_cdhash"] = "e" * 40
        with self.assertRaisesRegex(qualification.QualificationError, "running CDHash"):
            self.rebuild_runtime_from_observations(observations)
        observations[-1]["gui_process"].pop("running_cdhash")
        with self.assertRaisesRegex(qualification.QualificationError, "running_cdhash"):
            self.rebuild_runtime_from_observations(observations)

    def test_both_signed_candidate_gui_slices_can_be_the_running_image(self) -> None:
        observations = copy.deepcopy(self.runtime["recorder_observations"])
        for observation in observations:
            observation["gui_process"]["running_cdhash"] = "d" * 40
        report = self.rebuild_runtime_from_observations(observations)
        for endpoint in report["installed_gui"].values():
            endpoint.update(running_cdhash="d" * 40, cdhash="d" * 40, architecture="x86_64")
        self.validate_runtime(report)

    def test_gui_native_query_uses_operation_five_and_twenty_byte_result(self) -> None:
        expected = bytes(range(1, 21))
        def query(pid, operation, buffer, size):
            self.assertEqual((pid, operation, size), (5432, 5, 20))
            qualification.ctypes.memmove(buffer, expected, size)
            return 0
        library = mock.Mock()
        library.csops.side_effect = query
        with mock.patch.object(qualification.ctypes, "CDLL", return_value=library):
            self.assertEqual(qualification.darwin_process_cdhash(5432), expected.hex())
        library.csops.side_effect = None
        library.csops.return_value = -1
        with mock.patch.object(qualification.ctypes, "CDLL", return_value=library):
            with self.assertRaisesRegex(qualification.QualificationError, "cannot inspect running process"):
                qualification.darwin_process_cdhash(5432)

    def test_gui_endpoint_rejects_delayed_actual_inspection(self) -> None:
        report = copy.deepcopy(self.runtime)
        report["installed_gui"]["end"]["recorded_at"] = iso(940)
        with self.assertRaisesRegex(qualification.QualificationError, "bounded interval"):
            self.validate_runtime(report)
        report["installed_gui"]["end"]["inspection_started_at"] = iso(940)
        with self.assertRaisesRegex(qualification.QualificationError, "epoch boundary"):
            self.validate_runtime(report)

    def test_gui_endpoint_records_actual_inspection_times(self) -> None:
        process = copy.deepcopy(self.runtime["samples"][0]["gui_process"])
        identity = copy.deepcopy(self.runtime["installed_gui"]["start"])
        usage = qualification.DarwinRUsageInfoV4()
        usage.ri_proc_start_abstime = process["process_start_abstime"]
        start = qualification.parse_time(iso(900), "fixture time")
        end = qualification.parse_time(iso(902), "fixture time")
        plist = qualification.plistlib.dumps({
            "CFBundleIdentifier": qualification.EXPECTED_APP_IDENTIFIER,
            "CFBundleShortVersionString": VERSION, "CFBundleVersion": BUILD_NUMBER,
        })
        with mock.patch.object(qualification, "darwin_process_metrics", return_value=process), \
                mock.patch.object(qualification, "darwin_process_cdhash", return_value=process["running_cdhash"]), \
                mock.patch.object(qualification, "darwin_process_rusage", return_value=usage), \
                mock.patch.object(qualification, "darwin_process_path", return_value=pathlib.Path(process["executable_path"])), \
                mock.patch.object(qualification, "run_checked"), \
                mock.patch.object(qualification, "fixed_tool", side_effect=lambda path: path), \
                mock.patch.object(qualification, "gui_slice_signing_identities", return_value={"arm64": identity}), \
                mock.patch.object(pathlib.Path, "open", return_value=io.BytesIO(plist)), \
                mock.patch.object(qualification.dt, "datetime") as clock:
            clock.now.side_effect = [start, end]
            observed = qualification.installed_gui_identity(5432)
        self.assertEqual(observed["inspection_started_at"], start.isoformat())
        self.assertEqual(observed["recorded_at"], end.isoformat())

    def test_gui_candidate_requires_both_architecture_identities(self) -> None:
        verification = copy.deepcopy(self.manifest["artifact_verification"])
        verification["app_cdhashes"].pop("x86_64")
        with self.assertRaisesRegex(qualification.QualificationError, "both supported architecture"):
            qualification.validate_gui_candidate_process(
                self.runtime["samples"][0]["gui_process"], candidate_verification=verification, path="fixture GUI"
            )

    def test_prior_running_engine_hash_cannot_borrow_new_candidate_disk_image(self) -> None:
        observations = copy.deepcopy(self.runtime["recorder_observations"])
        observations[-1]["process"]["running_cdhash"] = "e" * 40
        with self.assertRaisesRegex(qualification.QualificationError, "running CDHash.*engine slice"):
            self.rebuild_runtime_from_observations(observations)
        observations[-1]["process"].pop("running_cdhash")
        with self.assertRaisesRegex(qualification.QualificationError, "running_cdhash"):
            self.rebuild_runtime_from_observations(observations)

    def test_engine_epoch_accepts_the_attested_intel_slice(self) -> None:
        observations = copy.deepcopy(self.runtime["recorder_observations"])
        for observation in observations:
            observation["process"]["running_cdhash"] = "c" * 40
        report = self.rebuild_runtime_from_observations(observations)
        for endpoint in report["installed_engine"].values():
            endpoint.update(running_cdhash="c" * 40, cdhash="c" * 40, architecture="x86_64")
        self.validate_runtime(report)

    def test_engine_native_start_is_required_to_remain_stable(self) -> None:
        observations = copy.deepcopy(self.runtime["recorder_observations"])
        observations[-1]["process"]["process_start_abstime"] += 1
        with self.assertRaisesRegex(qualification.QualificationError, "native engine process identity changed"):
            self.rebuild_runtime_from_observations(observations)

    def test_engine_observation_brackets_native_image_identity(self) -> None:
        metrics = copy.deepcopy(self.runtime["recorder_observations"][0]["process"])
        usage = qualification.DarwinRUsageInfoV4()
        usage.ri_proc_start_abstime = metrics["process_start_abstime"]
        for after_hash, succeeds in (("a" * 40, True), ("c" * 40, False)):
            with self.subTest(succeeds=succeeds), \
                    mock.patch.object(qualification, "darwin_process_metrics", return_value=metrics), \
                    mock.patch.object(qualification, "darwin_process_cdhash", side_effect=["a" * 40, after_hash]), \
                    mock.patch.object(qualification, "darwin_process_rusage", return_value=usage), \
                    mock.patch.object(qualification, "darwin_process_path", return_value=pathlib.Path(metrics["executable_path"])):
                if succeeds:
                    self.assertEqual(qualification.engine_process_observation(4321)["running_cdhash"], "a" * 40)
                else:
                    with self.assertRaisesRegex(qualification.QualificationError, "engine process changed"):
                        qualification.engine_process_observation(4321)

    def test_engine_endpoint_records_actual_inspection_times(self) -> None:
        metrics = copy.deepcopy(self.runtime["recorder_observations"][0]["process"])
        identity = copy.deepcopy(self.runtime["installed_engine"]["start"])
        usage = qualification.DarwinRUsageInfoV4()
        usage.ri_proc_start_abstime = metrics["process_start_abstime"]
        start = qualification.parse_time(iso(900), "fixture time")
        end = qualification.parse_time(iso(902), "fixture time")
        plist = qualification.plistlib.dumps({
            "CFBundleIdentifier": qualification.EXPECTED_AGENT_IDENTIFIER,
            "CFBundleShortVersionString": VERSION, "CFBundleVersion": BUILD_NUMBER,
        })
        with mock.patch.object(qualification, "engine_process_observation", return_value=metrics), \
                mock.patch.object(qualification, "darwin_process_cdhash", return_value=metrics["running_cdhash"]), \
                mock.patch.object(qualification, "darwin_process_rusage", return_value=usage), \
                mock.patch.object(qualification, "darwin_process_path", return_value=pathlib.Path(metrics["executable_path"])), \
                mock.patch.object(qualification, "run_checked"), \
                mock.patch.object(qualification, "fixed_tool", side_effect=lambda path: path), \
                mock.patch.object(qualification, "slice_signing_identities", return_value={"arm64": identity}), \
                mock.patch.object(pathlib.Path, "open", return_value=io.BytesIO(plist)), \
                mock.patch.object(qualification.dt, "datetime") as clock:
            clock.now.side_effect = [start, end]
            observed = qualification.installed_engine_identity(4321)
        self.assertEqual(observed["inspection_started_at"], start.isoformat())
        self.assertEqual(observed["recorded_at"], end.isoformat())

    def test_engine_endpoint_rejects_delayed_actual_capture(self) -> None:
        report = copy.deepcopy(self.runtime)
        report["installed_engine"]["end"]["recorded_at"] = iso(940)
        with self.assertRaisesRegex(qualification.QualificationError, "bounded interval"):
            self.validate_runtime(report)
        report["installed_engine"]["end"]["inspection_started_at"] = iso(940)
        with self.assertRaisesRegex(qualification.QualificationError, "epoch boundary"):
            self.validate_runtime(report)

    def test_candidate_engine_requires_both_signed_architecture_slices(self) -> None:
        self.manifest["artifact_verification"]["system_extension"]["cdhashes"].pop("x86_64")
        with self.assertRaisesRegex(qualification.QualificationError, "both supported architecture"):
            self.validate_candidate()

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

    def test_rc_marketing_version_uses_numeric_build_identity(self) -> None:
        candidate = self.validate_candidate()
        self.assertEqual(candidate["version"], "9.9.9-rc.1")
        self.assertEqual(candidate["build_number"], "9.9.9.123")

    def test_candidate_rejects_rc_suffix_missing_revision_and_wrong_numeric_base(self) -> None:
        for build in (VERSION + ".123", "9.9.9", "9.9.9.0", "9.9.8.123"):
            with self.subTest(build=build):
                with self.assertRaisesRegex(qualification.QualificationError, "numeric base version"):
                    qualification.candidate_document(
                        version=VERSION, build_number=build, source_commit=COMMIT,
                        source_tree=TREE, dmg=self.dmg, inspection_level="digest",
                        notarization_submission_id="",
                        preinstall_clean_ci=preinstall_clean_ci_fixture(),
                    )
                changed = copy.deepcopy(self.manifest)
                changed["candidate"]["build_number"] = build
                with self.assertRaisesRegex(qualification.QualificationError, "numeric base version"):
                    qualification.validate_candidate_document(
                        changed, expected_version=VERSION, expected_source_commit=COMMIT,
                        expected_source_tree=TREE, expected_build_number=build,
                        dmg=self.dmg, artifact_checks="digest",
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

    def resource_baseline_fixture(self) -> dict:
        # A 1 KiB/s background, one extra 60 KiB in the 300..330 interval,
        # and two GUI CPU outliers distinguish mean/window/p95 statistics.
        identities = {}
        endpoints = {}
        for role in ("engine", "gui"):
            image = qualification.RESOURCE_REFERENCE_IMAGES[role]
            identities[role] = copy.deepcopy(self.runtime["samples"][0][role + "_process"])
            identities[role].update(
                executable_sha256=image["sha256"], running_cdhash=image["cdhashes"]["arm64"]
            )
            endpoints[role] = copy.deepcopy(self.runtime["installed_" + role])
            for endpoint in endpoints[role].values():
                endpoint.update(
                    **identities[role], cdhash=image["cdhashes"]["arm64"],
                    cdhashes=copy.deepcopy(image["cdhashes"]),
                    bundle_version="1.21.5", build_version="1.21.5.1018",
                )
        completion = copy.deepcopy(self.runtime["recorder_probe_evidence"]["workload"])
        completion["output"] = completion["output_tail"]
        return {
            "schema": qualification.RESOURCE_BASELINE_SCHEMA,
            "status": "accepted",
            "reference": {
                "version": "1.21.5", "source_commit": qualification.RESOURCE_REFERENCE_COMMIT,
                "dmg_sha256": qualification.RESOURCE_REFERENCE_DMG_SHA256,
                "engine_sha256": qualification.RESOURCE_REFERENCE_IMAGES["engine"]["sha256"],
                "gui_sha256": qualification.RESOURCE_REFERENCE_IMAGES["gui"]["sha256"],
            },
            "host": copy.deepcopy(self.runtime["host"]),
            "host_end": copy.deepcopy(self.runtime["host"]),
            "recorder": {
                "path": "scripts/candidate-qualification.py",
                "sha256": qualification.sha256_file(MODULE_PATH),
            },
            "installed_engine": endpoints["engine"], "installed_gui": endpoints["gui"],
            "engine_uptime_at_start_seconds": 600.0,
            "uptime_source": "mach_absolute_time-ri_proc_start_abstime",
            "workload": {
                "recording_source_root": str(ROOT),
                "script_sha256": qualification.sha256_file(ROOT / qualification.RUNTIME_WORKLOAD_EXECUTORS[0]),
                "executors": copy.deepcopy(self.runtime["workload"]["executors"]),
                "burst_start_offset_seconds": 300, "iterations": 3000,
                "sample_interval_seconds": 30, "completion": completion,
            },
            "statistics": copy.deepcopy(qualification.RESOURCE_STATISTICS),
            "samples": [
                {
                    "offset_seconds": offset, "recorded_at": iso(offset), "captured_at": iso(offset),
                    "engine_disk_write_bytes_total": 1_000_000 + offset * 1024 + (61_440 if offset >= 330 else 0),
                    "gui_background_cpu_percent": {300: 7.0, 330: 20.0}.get(offset, 2.0),
                    "engine_process": copy.deepcopy(identities["engine"]),
                    "gui_process": copy.deepcopy(identities["gui"]),
                } for offset in range(0, 901, 30)
            ],
            "measurements": {
                "engine_average_write_bytes_per_second": 983_040 / 900,
                "engine_max_window_write_bytes_per_second": 3072.0,
                "gui_p95_percent": 7.0,
            },
            "acceptance": {
                "reviewer": "fixture release owner", "accepted_at": iso(960),
                "rationale": "Reviewed reference-host budgets before candidate construction.",
            },
            "limits": {
                "engine_average_write_bytes_per_second": 1500.0,
                "engine_max_window_write_bytes_per_second": 4096.0,
                "gui_p95_percent": 10.0,
            },
        }

    def validate_resource_baseline(self, baseline: dict, *, source_root: pathlib.Path = ROOT) -> dict:
        return qualification.validate_resource_baseline(
            baseline, source_root=source_root, host=self.runtime["host"]
        )

    def run_resource_recorder_control(self, fault: str = "healthy") -> dict:
        """Run the full recorder with a virtual clock and no native execution."""
        baseline = self.resource_baseline_fixture()
        endpoint = {role: copy.deepcopy(baseline["installed_" + role]["start"])
                    for role in ("engine", "gui")}
        identity = {role: copy.deepcopy(baseline["samples"][0][role + "_process"])
                    for role in ("engine", "gui")}
        if fault == "old_engine_version":
            endpoint["engine"]["bundle_version"] = "1.21.4"
        elif fault == "candidate_engine_image":
            endpoint["engine"]["executable_sha256"] = "a" * 64
        elif fault == "candidate_gui_image":
            endpoint["gui"]["executable_sha256"] = "a" * 64
        original_datetime = dt.datetime
        base = qualification.parse_time(iso(0), "virtual resource epoch")
        clock = {"now": 0.0, "timers": []}
        state = {"workload_started": 0, "workload_closed": 0, "samples": 0}
        output = self.root / ("recorder-control-" + fault + ".json")

        class VirtualDateTime(original_datetime):
            @classmethod
            def now(cls, tz=None):
                return (base + dt.timedelta(seconds=clock["now"])).astimezone(tz)

        class VirtualTimer:
            def __init__(self, delay, callback):
                self.deadline = clock["now"] + delay
                self.callback = callback
                self.cancelled = False

            def start(self):
                clock["timers"].append(self)

            def cancel(self):
                self.cancelled = True

            def join(self, timeout=None):
                pass

            def is_alive(self):
                return False

        def advance(seconds):
            target = clock["now"] + seconds
            for timer in list(clock["timers"]):
                if not timer.cancelled and timer.deadline <= target:
                    clock["now"] = timer.deadline
                    timer.cancelled = True
                    timer.callback()
            clock["now"] = target

        class VirtualWorkload:
            def __init__(self, command, *, cwd, deadline_seconds):
                state["workload_started"] += 1
                state["workload_command"] = list(command)
                self.started_at = VirtualDateTime.now(dt.timezone.utc)
                self.completed_at = self.started_at + dt.timedelta(seconds=22)
                self.elapsed_monotonic_seconds = 22.0
                self.finished = mock.Mock()
                self.finished.is_set.side_effect = lambda: VirtualDateTime.now(dt.timezone.utc) >= self.completed_at
                self.process = mock.Mock(returncode=1 if fault == "workload_failure" else 0)
                self.error = None
                run_id = command[-1]
                alert_path, bulk_path = qualification.workload_paths(run_id)
                self.stdout = (
                    f"IDENTITY: run_id={run_id} alert_executable={alert_path} bulk_path={bulk_path}\n"
                    f"PASS: fixed workload completed run_id={run_id} iterations={qualification.FIXED_WORKLOAD_ITERATIONS} "
                    "otlp_spans=1 alert_triggers=1 sequence_probes=1\n"
                )
                self.stderr = ""
                if fault == "workload_transcript":
                    self.stdout += self.stdout.splitlines()[-1] + "\n"

            def close(self):
                state["workload_closed"] += 1

        def engine_observation(pid):
            state["samples"] += 1
            offset = round(clock["now"] - 1)
            value = {
                **identity["engine"],
                "engine_disk_write_bytes_total": 1_000_000 + offset * 1024 + (61_440 if offset >= 330 else 0),
            }
            if fault == "process_restart" and offset >= 330:
                value["process_start_abstime"] += 1
            return value

        def gui_observation():
            offset = round(clock["now"] - 1)
            return {"process": copy.deepcopy(identity["gui"]),
                    "cpu_percent": {300: 7.0, 330: 20.0}.get(offset, 2.0)}

        def signed_endpoint(role):
            result = copy.deepcopy(endpoint[role])
            recorded = VirtualDateTime.now(dt.timezone.utc).isoformat()
            result.update(inspection_started_at=recorded, recorded_at=recorded)
            return result

        inventory = [baseline["recorder"], *baseline["workload"]["executors"]]
        final_inventory = copy.deepcopy(inventory)
        if fault == "executor_changed":
            final_inventory[-1]["sha256"] = "f" * 64
        host_end = copy.deepcopy(baseline["host"])
        if fault == "host_changed":
            host_end["power_source"] = "different power source"
        with contextlib.ExitStack() as stack:
            patches = (
                (qualification.platform, "system", {"return_value": "Darwin"}),
                (qualification, "resource_baseline_executor_inventory", {"side_effect": [inventory, final_inventory]}),
                (qualification, "installed_runtime_host", {"side_effect": [baseline["host"], host_end]}),
                (qualification, "installed_engine_identity", {"side_effect": lambda pid: signed_endpoint("engine")}),
                (qualification, "installed_gui_identity", {"side_effect": lambda pid: signed_endpoint("gui")}),
                (qualification, "engine_process_observation", {"side_effect": engine_observation}),
                (qualification, "gui_process_observation", {"side_effect": gui_observation}),
                (qualification, "resource_baseline_native_uptime_seconds", {"return_value": 249.0 if fault == "cold_engine" else 600.0}),
                (qualification, "original_user_command", {"side_effect": lambda command: command}),
                (qualification.secrets, "token_hex", {"return_value": "d" * 32}),
                (qualification.time, "monotonic", {"side_effect": lambda: clock["now"]}),
                (qualification.time, "sleep", {"side_effect": advance}),
                (qualification.threading, "Timer", {"new": VirtualTimer}),
                (qualification, "TimedWorkload", {"new": VirtualWorkload}),
                (qualification.dt, "datetime", {"new": VirtualDateTime}),
            )
            for owner, name, kwargs in patches:
                stack.enter_context(mock.patch.object(owner, name, **kwargs))
            stack.enter_context(mock.patch("sys.stdout", new=io.StringIO()))
            try:
                qualification.command_record_resource_baseline(qualification.argparse.Namespace(
                    engine_pid=identity["engine"]["pid"], source_root=str(ROOT), output=str(output),
                ))
            except qualification.QualificationError as exc:
                state["failure"] = str(exc)
        state["document"] = json.loads(output.read_text()) if output.exists() else None
        state["virtual_elapsed"] = clock["now"]
        return state

    def test_reference_recorder_produces_only_unaccepted_measurements(self) -> None:
        state = self.run_resource_recorder_control()
        self.assertNotIn("failure", state)
        document = state["document"]
        self.assertEqual(document["status"], "measured-awaiting-acceptance")
        self.assertIsNone(document["limits"])
        self.assertIsNone(document["acceptance"])
        self.assertEqual([row["offset_seconds"] for row in document["samples"]], list(range(0, 901, 30)))
        self.assertEqual(document["measurements"], self.resource_baseline_fixture()["measurements"])
        self.assertEqual(state["virtual_elapsed"], 901)
        self.assertEqual(state["workload_started"], 1)
        self.assertEqual(state["workload_closed"], 1)
        self.assertEqual(qualification.validate_resource_baseline(
            document, source_root=ROOT, require_acceptance=False), {})
        with self.assertRaisesRegex(qualification.QualificationError, "not accepted"):
            qualification.validate_resource_baseline(document, source_root=ROOT)

    def test_reference_recorder_refuses_wrong_installed_images_and_cold_engine_before_workload(self) -> None:
        for fault in ("old_engine_version", "candidate_engine_image", "candidate_gui_image", "cold_engine"):
            with self.subTest(fault=fault):
                state = self.run_resource_recorder_control(fault)
                self.assertIn("failure", state)
                self.assertIsNone(state["document"])
                self.assertEqual(state["samples"], 0)
                self.assertEqual(state["workload_started"], 0)
                self.assertEqual(state["virtual_elapsed"], 0)

    def test_reference_recorder_rejects_process_source_host_and_workload_failures(self) -> None:
        cases = {
            "process_restart": "process restarted or changed",
            "executor_changed": "executor bytes changed",
            "host_changed": "host or power configuration changed",
            "workload_failure": "successful completion",
            "workload_transcript": "prescribed completed burst",
        }
        for fault, reason in cases.items():
            with self.subTest(fault=fault):
                state = self.run_resource_recorder_control(fault)
                self.assertIn(reason, state.get("failure", ""))
                self.assertIsNone(state["document"])
                self.assertEqual(state["workload_started"], 1)
                self.assertEqual(state["workload_closed"], 1)
                if fault in ("process_restart", "workload_failure", "workload_transcript"):
                    self.assertLess(state["samples"], 31)

    def test_reference_recorder_warmup_uses_native_mach_units_and_rejects_future_start(self) -> None:
        library = mock.Mock()
        library.mach_absolute_time.return_value = 48_000_000_000
        with mock.patch.object(qualification.ctypes, "CDLL", return_value=library), \
                mock.patch.object(qualification, "darwin_mach_timebase", return_value=(125, 3)):
            self.assertEqual(qualification.resource_baseline_native_uptime_seconds(24_000_000_000), 1000.0)
            self.assertEqual(library.mach_absolute_time.argtypes, [])
            self.assertIs(library.mach_absolute_time.restype, ctypes.c_uint64)
            with self.assertRaisesRegex(qualification.QualificationError, "later than native monotonic"):
                qualification.resource_baseline_native_uptime_seconds(48_000_000_001)

    def resource_baseline_source(self) -> pathlib.Path:
        directory = self.root / "baseline-source"
        for relative in (*qualification.RUNTIME_WORKLOAD_EXECUTORS, "scripts/candidate-qualification.py"):
            path = directory / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((ROOT / relative).read_bytes())
        return directory

    @staticmethod
    def rebind_resource_workload_output(baseline: dict, output: str) -> None:
        receipt = baseline["workload"]["completion"]
        receipt.update(
            output=output, output_tail=output[-4096:],
            output_line_count=len(output.splitlines()),
            output_sha256=hashlib.sha256(output.encode()).hexdigest(),
        )

    def test_resource_baseline_accepts_measured_reference_and_portable_checkout_path(self) -> None:
        baseline = self.resource_baseline_fixture()
        self.assertEqual(self.validate_resource_baseline(baseline), baseline["limits"])
        baseline["workload"]["recording_source_root"] = "/Users/reference/release-source"
        command = baseline["workload"]["completion"]["command"]
        command[1] = "/Users/reference/release-source/scripts/runtime-qualification-workload.sh"
        baseline["workload"]["completion"]["command"] = ["/usr/bin/sudo", "-H", "-u", "reference", *command]
        self.assertEqual(self.validate_resource_baseline(baseline), baseline["limits"])

    def test_resource_baseline_requires_signed_endpoint_pairs_and_native_uptime_source(self) -> None:
        for role in ("engine", "gui"):
            with self.subTest(missing="installed_" + role):
                baseline = self.resource_baseline_fixture()
                del baseline["installed_" + role]
                with self.assertRaisesRegex(qualification.QualificationError, "must be an object"):
                    self.validate_resource_baseline(baseline)
            for phase in ("start", "end"):
                with self.subTest(role=role, missing=phase):
                    baseline = self.resource_baseline_fixture()
                    del baseline["installed_" + role][phase]
                    with self.assertRaisesRegex(qualification.QualificationError, "must be an object"):
                        self.validate_resource_baseline(baseline)
        for source in (None, "heartbeat_uptime_seconds", ""):
            with self.subTest(uptime_source=source):
                baseline = self.resource_baseline_fixture()
                if source is None:
                    del baseline["uptime_source"]
                else:
                    baseline["uptime_source"] = source
                with self.assertRaisesRegex(qualification.QualificationError, "native Mach uptime source"):
                    self.validate_resource_baseline(baseline)

    def test_resource_baseline_signed_endpoints_must_match_sampled_reference_processes(self) -> None:
        for role in ("engine", "gui"):
            for phase in ("start", "end"):
                for field in ("pid", "process_start_abstime", "build_version"):
                    with self.subTest(role=role, phase=phase, field=field):
                        baseline = self.resource_baseline_fixture()
                        endpoint = baseline["installed_" + role][phase]
                        if field == "build_version":
                            endpoint[field] = "1.22.0.1137"
                            reason = "requires the signed published v1.21.5"
                        else:
                            endpoint[field] += 1
                            reason = "does not match the sampled reference process"
                        with self.assertRaisesRegex(qualification.QualificationError, reason):
                            self.validate_resource_baseline(baseline)

    def test_resource_baseline_endpoint_timing_allows_sequential_inspections_and_rejects_stale_proof(self) -> None:
        baseline = self.resource_baseline_fixture()
        for role, phase, start, end in (
            ("engine", "start", -70, -35), ("gui", "start", -35, 0),
            ("engine", "end", 900, 935), ("gui", "end", 935, 970),
        ):
            baseline["installed_" + role][phase].update(
                inspection_started_at=iso(start), recorded_at=iso(end),
            )
        baseline["acceptance"]["accepted_at"] = iso(990)
        self.assertEqual(self.validate_resource_baseline(baseline), baseline["limits"])
        early_approval = copy.deepcopy(baseline)
        early_approval["acceptance"]["accepted_at"] = iso(960)
        with self.assertRaisesRegex(qualification.QualificationError, "before reference measurement completes"):
            self.validate_resource_baseline(early_approval)
        for phase, start, end, reason in (
            ("start", -90, -70, "epoch boundary"),
            ("start", 1, 2, "epoch boundary"),
            ("end", 880, 890, "epoch boundary"),
            ("end", 960, 980, "epoch boundary"),
            ("end", 900, 936, "bounded interval"),
            ("end", 910, 905, "bounded interval"),
        ):
            with self.subTest(phase=phase, start=start, end=end):
                changed = copy.deepcopy(baseline)
                changed["installed_engine"][phase].update(
                    inspection_started_at=iso(start), recorded_at=iso(end),
                )
                with self.assertRaisesRegex(qualification.QualificationError, reason):
                    self.validate_resource_baseline(changed)
    def test_live_runtime_requires_baseline_even_when_fixture_support_is_enabled(self) -> None:
        report = copy.deepcopy(self.runtime)
        report["evidence"]["capture_mode"] = "live-installed-root"
        path = self.root / "missing-resource-baseline.json"
        with mock.patch.object(qualification, "RESOURCE_BASELINE_PATH", str(path)):
            with self.assertRaisesRegex(qualification.QualificationError, "baseline is missing"):
                self.validate_runtime(report)
            pending = self.resource_baseline_fixture()
            pending["status"] = "measured-awaiting-acceptance"
            path.write_text(json.dumps(pending), encoding="utf-8")
            with self.assertRaisesRegex(qualification.QualificationError, "baseline is not accepted"):
                self.validate_runtime(report)

    def test_resource_baseline_must_exist_unchanged_in_candidate_source_commit(self) -> None:
        baseline = self.resource_baseline_fixture()
        directory = self.resource_baseline_source()
        path = directory / qualification.RESOURCE_BASELINE_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        serialized = json.dumps(baseline, indent=2) + "\n"
        path.write_text(serialized, encoding="utf-8")
        expected_command = ["/usr/bin/git", "-C", str(directory), "show", f"{COMMIT}:{qualification.RESOURCE_BASELINE_PATH}"]
        with mock.patch.object(qualification.subprocess, "run", return_value=subprocess.CompletedProcess(expected_command, 0, serialized, "")) as git:
            self.assertEqual(qualification.release_resource_limits(directory, COMMIT, host=self.runtime["host"]), baseline["limits"])
            git.assert_called_once_with(expected_command, check=True, capture_output=True, text=True)
        with mock.patch.object(qualification.subprocess, "run", side_effect=subprocess.CalledProcessError(128, expected_command, stderr="path does not exist in source commit")):
            with self.assertRaisesRegex(qualification.QualificationError, "candidate-bound resource baseline failed"):
                qualification.release_resource_limits(directory, COMMIT, host=self.runtime["host"])
        with mock.patch.object(qualification.subprocess, "run", return_value=subprocess.CompletedProcess(expected_command, 0, "{}\n", "")):
            with self.assertRaisesRegex(qualification.QualificationError, "not frozen in the candidate source commit"):
                qualification.release_resource_limits(directory, COMMIT, host=self.runtime["host"])

    def test_resource_baseline_cannot_substitute_candidate_or_invent_reference_images(self) -> None:
        baseline = self.resource_baseline_fixture()
        baseline["reference"].update(version=VERSION, source_commit=COMMIT)
        with self.assertRaisesRegex(qualification.QualificationError, "last shipped"):
            self.validate_resource_baseline(baseline)
        for role in ("engine", "gui"):
            with self.subTest(role=role, alteration="self-consistent wrong image"):
                baseline = self.resource_baseline_fixture()
                baseline["reference"][role + "_sha256"] = "f" * 64
                for sample in baseline["samples"]:
                    sample[role + "_process"]["executable_sha256"] = "f" * 64
                with self.assertRaisesRegex(qualification.QualificationError, "published v1.21.5 executable"):
                    self.validate_resource_baseline(baseline)
            with self.subTest(role=role, alteration="wrong running slice"):
                baseline = self.resource_baseline_fixture()
                for sample in baseline["samples"]:
                    sample[role + "_process"]["running_cdhash"] = "f" * 40
                with self.assertRaisesRegex(qualification.QualificationError, "published v1.21.5 .* slice"):
                    self.validate_resource_baseline(baseline)
        baseline = self.resource_baseline_fixture()
        baseline["reference"]["dmg_sha256"] = "f" * 64
        with self.assertRaisesRegex(qualification.QualificationError, "published v1.21.5 DMG"):
            self.validate_resource_baseline(baseline)

    def test_resource_baseline_preserves_sample_cadence_and_capture_boundaries(self) -> None:
        baseline = self.resource_baseline_fixture()
        baseline["samples"] = [
            {**copy.deepcopy(baseline["samples"][0]), "offset_seconds": index * 7.5,
             "recorded_at": iso(index * 7.5), "captured_at": iso(index * 7.5)}
            for index in range(121)
        ]
        with self.assertRaisesRegex(qualification.QualificationError, "exactly 31"):
            self.validate_resource_baseline(baseline)
        for key, value, reason in (
            ("offset_seconds", 301, "exactly 31"),
            ("recorded_at", iso(307), "scheduled sample time"),
            ("captured_at", iso(306), "five seconds"),
        ):
            with self.subTest(key=key):
                baseline = self.resource_baseline_fixture()
                baseline["samples"][10][key] = value
                with self.assertRaisesRegex(qualification.QualificationError, reason):
                    self.validate_resource_baseline(baseline)

    def test_resource_baseline_must_match_candidate_host_and_stable_capture_host(self) -> None:
        for key, value in (("machine_id_sha256", "b" * 64), ("power_source", "Battery")):
            with self.subTest(key=key):
                baseline = self.resource_baseline_fixture()
                baseline["host"][key] = value
                baseline["host_end"][key] = value
                with self.assertRaisesRegex(qualification.QualificationError, "same reference host"):
                    self.validate_resource_baseline(baseline)
        baseline = self.resource_baseline_fixture()
        baseline["host_end"]["power_source"] = "Battery"
        with self.assertRaises(qualification.QualificationError):
            self.validate_resource_baseline(baseline)

    def test_resource_baseline_binds_transitive_workload_and_recorder_bytes(self) -> None:
        baseline = self.resource_baseline_fixture()
        baseline["workload"]["executors"].pop()
        with self.assertRaisesRegex(qualification.QualificationError, "transitive workload executor inventory"):
            self.validate_resource_baseline(baseline)
        directory = self.resource_baseline_source()
        child = directory / "scripts/test-otlp-curl.sh"
        child.write_bytes(child.read_bytes() + b"\n# changed after reference capture\n")
        with self.assertRaisesRegex(qualification.QualificationError, "executor bytes changed"):
            self.validate_resource_baseline(self.resource_baseline_fixture(), source_root=directory)
        baseline = self.resource_baseline_fixture()
        baseline["recorder"]["sha256"] = "f" * 64
        with self.assertRaises(qualification.QualificationError):
            self.validate_resource_baseline(baseline)

    def test_resource_baseline_requires_successful_full_workload_and_matching_run_identity(self) -> None:
        baseline = self.resource_baseline_fixture()
        baseline["workload"].pop("completion")
        with self.assertRaisesRegex(qualification.QualificationError, "completion"):
            self.validate_resource_baseline(baseline)
        for key, value, reason in (
            ("exit_code", 1, "exit successfully"),
            ("run_id", "d" * 32, "unique run id"),
            ("command", ["/bin/bash", str(ROOT / qualification.RUNTIME_WORKLOAD_EXECUTORS[0]), "--alert-only"], "full fixed workload"),
        ):
            with self.subTest(key=key):
                baseline = self.resource_baseline_fixture()
                baseline["workload"]["completion"][key] = value
                with self.assertRaisesRegex(qualification.QualificationError, reason):
                    self.validate_resource_baseline(baseline)

    def test_resource_baseline_rejects_polling_timestamps_and_forged_workload_duration(self) -> None:
        for changes, reason in (
            ({"timing_source": "heartbeat-poll"}, "independent process-exit timing"),
            ({"elapsed_monotonic_seconds": 0}, "elapsed_monotonic_seconds"),
            ({"elapsed_monotonic_seconds": 91, "completed_at": iso(391)}, "independent elapsed deadline"),
            ({"completed_at": iso(330)}, "wall clock.*monotonic duration disagree"),
            ({"started_at": iso(330), "completed_at": iso(352)}, "minute-five boundary"),
            ({"elapsed_monotonic_seconds": 0.5, "completed_at": iso(299.5)}, "completion must follow"),
        ):
            with self.subTest(changes=changes):
                baseline = self.resource_baseline_fixture()
                baseline["workload"]["completion"].update(changes)
                with self.assertRaisesRegex(qualification.QualificationError, reason):
                    self.validate_resource_baseline(baseline)

    def test_resource_baseline_requires_complete_hashed_output_and_exact_success_summary(self) -> None:
        baseline = self.resource_baseline_fixture()
        baseline["workload"]["completion"].pop("output")
        with self.assertRaisesRegex(qualification.QualificationError, "complete workload output"):
            self.validate_resource_baseline(baseline)
        baseline = self.resource_baseline_fixture()
        baseline["workload"]["completion"]["output"] += "unbound transcript bytes\n"
        with self.assertRaisesRegex(qualification.QualificationError, "output does not reconcile"):
            self.validate_resource_baseline(baseline)
        for alteration in ("iterations", "duplicate-run", "other-run"):
            with self.subTest(alteration=alteration):
                baseline = self.resource_baseline_fixture()
                receipt = baseline["workload"]["completion"]
                output = receipt["output"]
                if alteration == "iterations":
                    output = output.replace("iterations=3000", "iterations=2999")
                elif alteration == "duplicate-run":
                    output += output
                else:
                    output = output.replace(receipt["run_id"], "d" * 32)
                self.rebind_resource_workload_output(baseline, output)
                with self.assertRaisesRegex(qualification.QualificationError, "one completed fixed run"):
                    self.validate_resource_baseline(baseline)

    def test_resource_baseline_recomputes_the_statistics_used_by_candidate_gates(self) -> None:
        baseline = self.resource_baseline_fixture()
        baseline["statistics"]["gui_p95_percent"] = "arithmetic-mean"
        with self.assertRaisesRegex(qualification.QualificationError, "statistics differ"):
            self.validate_resource_baseline(baseline)
        for index, key, value in (
            (30, "engine_disk_write_bytes_total", 1_984_064),
            (11, "engine_disk_write_bytes_total", 1_400_384),
            (29, "gui_background_cpu_percent", 8.0),
        ):
            with self.subTest(index=index, key=key):
                baseline = self.resource_baseline_fixture()
                baseline["samples"][index][key] = value
                with self.assertRaisesRegex(qualification.QualificationError, "measurements do not reconcile"):
                    self.validate_resource_baseline(baseline)

    def test_live_runtime_enforces_each_reviewed_resource_ceiling(self) -> None:
        report = copy.deepcopy(self.runtime)
        report["evidence"]["capture_mode"] = "live-installed-root"
        generous = {key: 1_000_000_000.0 for key in qualification.RESOURCE_STATISTICS}
        with mock.patch.object(qualification, "release_resource_limits", return_value=generous) as budgets:
            self.validate_runtime(report)
            budgets.assert_called_once_with(ROOT, COMMIT, host=self.runtime["host"])
        for key, reason in (
            ("engine_average_write_bytes_per_second", "disk write average exceeds"),
            ("engine_max_window_write_bytes_per_second", "disk write window .* exceeds"),
            ("gui_p95_percent", "background GUI p95"),
        ):
            with self.subTest(key=key):
                strict = {**generous, key: 1.0}
                with mock.patch.object(qualification, "release_resource_limits", return_value=strict):
                    with self.assertRaisesRegex(qualification.QualificationError, reason):
                        self.validate_runtime(report)

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
            "installed_gui_start": copy.deepcopy(self.runtime["installed_gui"]["start"]),
            "installed_gui_end": copy.deepcopy(self.runtime["installed_gui"]["end"]),
            "installed_engine_start": copy.deepcopy(
                self.runtime["installed_engine"]["start"]
            ),
            "installed_engine_end": copy.deepcopy(
                self.runtime["installed_engine"]["end"]
            ),
            "crash_count": process["crash_count"],
            "watchdog_exit_count": process["watchdog_exit_count"],
            "source_rule_corpus_sha256": measurements["file_fidelity"][
                "source_rule_corpus_sha256"
            ],
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
        self, observations: list[dict], *, probes: dict | None = None
    ) -> dict:
        return qualification.build_runtime_report_from_observations(
            candidate_manifest=self.manifest,
            candidate_manifest_sha256=self.manifest_sha,
            observations=observations,
            host=copy.deepcopy(self.runtime["host"]),
            workload=copy.deepcopy(self.runtime["workload"]),
            probes=probes if probes is not None else self.recorder_probes(),
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
    def rebind_observation_heartbeat(observation: dict, *, reconcile_writer_prefix: bool = True) -> None:
        # Ordinary synthetic fixtures settle admissions in order. Tests of an
        # old stuck prefix opt out and preserve their explicit watermark data.
        if reconcile_writer_prefix:
            heartbeat = observation["heartbeat"]
            heartbeat["events_storage_write_admitted_generation"] = sum(
                heartbeat["events_storage_write_offered_by_lane"].values()
            )
            heartbeat["events_storage_write_terminal_generation"] = sum(
                sum(heartbeat[f"events_storage_write_{key}_by_lane"].values())
                for key in ("persisted", "filtered", "dropped")
            )
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

    def produce_unconfigured_alert_proofs(self, evidence: dict) -> None:
        """Use the live proof producer with ordinary committed-alert fixtures."""
        for name in ("llm_prewarm", "workload"):
            template = evidence[name]["alert_investigation"]
            observation = copy.deepcopy(self.runtime["recorder_observations"][0])
            observation["heartbeat"]["llm"] = {"configured": False}
            observation["captured_at"] = template["observed_at"]
            observation["recorded_at"] = template["observed_at"]
            observation["heartbeat"]["written_at_unix"] = qualification.parse_time(
                template["observed_at"], "fixture observation"
            ).timestamp()
            self.rebind_observation_heartbeat(observation)
            row = {
                **template["alert"], "process_path": template["process_path"],
                "llm_investigation_json": None,
            }
            with mock.patch.object(
                qualification, "readonly_alert_rows_for_process",
                return_value=([row], copy.deepcopy(template["database"])),
            ):
                proof, alert_id = qualification.causal_alert_proof_if_ready(
                    phase=template["phase"],
                    database_path=pathlib.Path(template["database"]["path"]),
                    process_path=template["process_path"],
                    trigger_started_at=qualification.parse_time(
                        template["trigger_started_at"], "fixture trigger"
                    ),
                    telemetry_before={"configured": False},
                    observation=observation, stable_alert_id=None,
                )
            self.assertIsNotNone(proof)
            self.assertEqual(alert_id, row["id"])
            self.assertIsNone(proof["investigation_json"])
            self.assertIsNone(proof["investigation_sha256"])
            evidence[name]["alert_investigation"] = proof

    def test_live_reload_producer_evidence_passes_validator(self) -> None:
        evidence = copy.deepcopy(self.runtime["recorder_probe_evidence"])
        with mock.patch.object(qualification.os, "kill") as send:
            evidence["live_sighup"] = qualification.send_live_rule_reload_probe(
                target_pid=4321, offset=qualification.BURST_DRAIN_OFFSET_SECONDS,
            )
        send.assert_called_once_with(4321, qualification.signal.SIGHUP)
        qualification.validate_recorder_probe_evidence(
            evidence, source_root=ROOT,
            expected_preinstall_clean_ci=self.manifest["preinstall_clean_ci"],
        )
        evidence["live_sighup"]["sample_offset_seconds"] = 450
        with self.assertRaisesRegex(qualification.QualificationError, "fixed SIGHUP probe"):
            qualification.validate_recorder_probe_evidence(
                evidence, source_root=ROOT,
                expected_preinstall_clean_ci=self.manifest["preinstall_clean_ci"],
            )

    def test_unconfigured_proof_still_requires_committed_high_alert(self) -> None:
        evidence = copy.deepcopy(self.runtime["recorder_probe_evidence"])
        self.produce_unconfigured_alert_proofs(evidence)
        proof = evidence["workload"]["alert_investigation"]
        for field, value, message in (
            ("alert", None, "must be an object"),
            ("investigation_json", "{}", "must not claim"),
            ("telemetry_after", {"configured": True}, "configuration changed"),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(proof)
                changed[field] = value
                with self.assertRaisesRegex(qualification.QualificationError, message):
                    qualification.validate_alert_investigation_proof(changed, "fixture proof")
        proof["alert"]["severity"] = "low"
        with self.assertRaisesRegex(qualification.QualificationError, "HIGH or CRITICAL"):
            qualification.validate_alert_investigation_proof(proof, "fixture proof")

    def test_flowing_queue_uses_one_live_and_reported_drain_contract(self) -> None:
        observations = copy.deepcopy(self.runtime["recorder_observations"])
        drain = qualification.BURST_DRAIN_OFFSET_SECONDS
        for observation in observations:
            if observation["offset_seconds"] in (drain - 30, drain):
                heartbeat = observation["heartbeat"]
                heartbeat["events_storage_write_offered_by_lane"]["file"] += 1
                heartbeat["events_storage_write_buffer_depth_by_lane"]["file"] += 1
                self.rebind_observation_heartbeat(observation)
        previous = qualification.sample_from_recorder_observation(
            observations[drain // 30 - 1], "previous flow observation"
        )
        current = observations[drain // 30]
        qualification.validate_runtime_readiness(
            current, "flow observation", phase="drain", require_drained=True,
            expected_pid=4321, previous_sample=previous,
        )
        # A nonzero t0 queue still lacks earlier epoch evidence of progress.
        with self.assertRaisesRegex(qualification.QualificationError, "not drained"):
            qualification.validate_runtime_readiness(
                current, "flow observation", phase="t0", require_drained=True,
            )
        with mock.patch.object(
            qualification, "capture_runtime_observation", return_value=current,
        ), mock.patch.object(qualification.time, "sleep"):
            drained = qualification.wait_for_runtime_drain(
                initial=observations[drain // 30 - 1], phase="fixture drain",
                heartbeat_path=self.root / "unused-heartbeat.json",
                candidate=self.manifest["candidate"], data_dirs=[self.root],
                sqlite_overrides={}, expected_pid=4321,
            )
        self.assertEqual(drained, current)
        report = self.rebuild_runtime_from_observations(observations)
        self.validate_runtime(report)
        window = qualification.derive_workload_ingress(report["samples"], report["recorder_probe_evidence"]["workload"])
        self.assertEqual(
            window["file_persistence_offered_delta"]
            - window["file_persistence_completed_delta"], 1,
        )

    def test_flowing_queue_never_forgives_unproven_or_unbounded_work(self) -> None:
        name = "file-event-persistence"
        previous = copy.deepcopy(self.runtime["samples"][24])
        healthy = copy.deepcopy(self.runtime["samples"][25])
        previous["conservation"][name] = {
            "offered": 101, "completed": 100, "queued": 1,
            "in_flight": 0, "explicitly_shed": 0,
        }
        healthy["conservation"][name] = {
            "offered": 201, "completed": 200, "queued": 1,
            "in_flight": 0, "explicitly_shed": 0,
        }
        pending = [f"{name} queued=1 in_flight=0"]
        self.assertEqual(
            qualification.forgive_flowing_boundary_lanes(pending, healthy, previous), [],
        )
        for changes in (
            {"completed": 100}, {"in_flight": 1},
            {"queued": qualification.RUNTIME_DRAIN_FLOWING_QUEUE_LIMIT + 1},
        ):
            with self.subTest(changes=changes):
                current = copy.deepcopy(healthy)
                current["conservation"][name].update(changes)
                self.assertEqual(
                    qualification.forgive_flowing_boundary_lanes(pending, current, previous),
                    pending,
                )

    def fresh_boundary_work_observations(self, *, boundary_offset: int | None = None) -> list[dict]:
        """Synthetic new work shaped like GA3's failure, with real prefix proof.

        GA3 did not publish that proof; this fixture does not repair its receipt.
        """
        observations = copy.deepcopy(self.runtime["recorder_observations"])
        drain = qualification.BURST_DRAIN_OFFSET_SECONDS if boundary_offset is None else boundary_offset
        for observation in observations:
            offset = observation["offset_seconds"]
            if offset < drain:
                continue
            heartbeat = observation["heartbeat"]
            for lane, count in (("file", 63), ("priority", 1)):
                heartbeat["events_storage_write_offered_by_lane"][lane] += count
                key = "buffer_depth" if offset == drain else "persisted"
                heartbeat[f"events_storage_write_{key}_by_lane"][lane] += count
            graph = heartbeat["tracegraph_storage_admission"]
            graph["ingest_events_total"] += 1
            graph["entity_observations_total"] += 2
            graph["edge_observations_total"] += 1
            if offset == drain:
                graph["ingest_events_pending"] += 1
                graph["pending_entity_rows"] += 2
                graph["pending_edge_rows"] += 1
                graph["oldest_outstanding_age_seconds"] = 0.05
            else:
                graph["ingest_events_committed_total"] += 1
                for key in ("write_attempts_total", "write_batches_committed_total"):
                    graph[key] += 1
                for key in ("write_rows_attempted_total", "write_rows_committed_total"):
                    graph[key] += 3
            self.rebind_observation_heartbeat(observation)
        return observations

    def test_new_boundary_work_requires_prefix_and_graph_age_in_all_paths(self) -> None:
        observations = self.fresh_boundary_work_observations()
        index = qualification.BURST_DRAIN_OFFSET_SECONDS // 30
        current = observations[index]
        previous = qualification.sample_from_recorder_observation(observations[index - 1], "prior")
        qualification.validate_runtime_readiness(
            current, "new work", phase="drain", require_drained=True, previous_sample=previous,
        )
        report = self.rebuild_runtime_from_observations(observations)
        self.validate_runtime(report)
        qualification.derive_workload_ingress(report["samples"], report["recorder_probe_evidence"]["workload"])
        with self.assertRaisesRegex(qualification.QualificationError, "not drained"):
            qualification.validate_runtime_readiness(current, "new work", phase="t0", require_drained=True)
        # Drain polling must use the same proof, including a repeated current
        # heartbeat; it cannot invent a predecessor from the same publication.
        prior_observation = copy.deepcopy(observations[index - 1])
        prior_heartbeat = prior_observation["heartbeat"]
        prior_heartbeat["events_storage_write_offered_by_lane"]["file"] += 1
        prior_heartbeat["events_storage_write_buffer_depth_by_lane"]["file"] += 1
        self.rebind_observation_heartbeat(prior_observation)
        with mock.patch.object(qualification, "capture_runtime_observation", return_value=current), \
                mock.patch.object(qualification.time, "sleep"):
            self.assertEqual(qualification.wait_for_runtime_drain(
                initial=prior_observation, phase="new work", heartbeat_path=self.root / "unused",
                candidate=self.manifest["candidate"], data_dirs=[self.root], sqlite_overrides={}, expected_pid=4321,
            ), current)

    def test_increasing_completions_cannot_hide_an_older_unsettled_prefix(self) -> None:
        observations = self.fresh_boundary_work_observations()
        index = qualification.BURST_DRAIN_OFFSET_SECONDS // 30
        before = observations[index - 1]["heartbeat"]
        before["events_storage_write_offered_by_lane"]["file"] += 1
        before["events_storage_write_buffer_depth_by_lane"]["file"] += 1
        self.rebind_observation_heartbeat(observations[index - 1])
        current = observations[index]
        current["heartbeat"]["events_storage_write_terminal_generation"] = before["events_storage_write_terminal_generation"]
        self.rebind_observation_heartbeat(current, reconcile_writer_prefix=False)
        previous = qualification.sample_from_recorder_observation(observations[index - 1], "prior stuck admission")
        with self.assertRaisesRegex(qualification.QualificationError, "not drained"):
            qualification.validate_runtime_readiness(current, "stuck prefix", phase="drain", require_drained=True, previous_sample=previous)
        with self.assertRaisesRegex(qualification.QualificationError, "not drained"):
            self.rebuild_runtime_from_observations(observations)
        report = self.rebuild_runtime_from_observations(self.fresh_boundary_work_observations())
        report["recorder_observations"] = observations
        report["samples"] = [qualification.sample_from_recorder_observation(row, "stuck prefix") for row in observations]
        self.rehash_samples(report)
        with self.assertRaisesRegex(qualification.QualificationError, "not drained"):
            self.validate_runtime(report)

    def test_writer_prefix_metadata_is_required_reconciled_and_unsigned(self) -> None:
        base = self.runtime["recorder_observations"][20]
        for key, value in (
            ("events_storage_write_admitted_generation", None),
            ("events_storage_write_terminal_generation", True),
            ("events_storage_write_terminal_generation", -1),
            ("events_storage_write_admitted_generation", 1 << 64),
            ("events_storage_write_terminal_generation", 1 << 64),
            ("events_storage_write_admitted_generation", 0),
        ):
            with self.subTest(key=key, value=value):
                changed = copy.deepcopy(base)
                if value is None:
                    del changed["heartbeat"][key]
                else:
                    changed["heartbeat"][key] = value
                self.rebind_observation_heartbeat(changed, reconcile_writer_prefix=False)
                with self.assertRaises(qualification.QualificationError):
                    qualification.sample_from_recorder_observation(changed, "invalid prefix")
        current = self.fresh_boundary_work_observations()[26]
        current["heartbeat"]["events_storage_write_terminal_generation"] = current["heartbeat"]["events_storage_write_admitted_generation"]
        self.rebind_observation_heartbeat(current, reconcile_writer_prefix=False)
        with self.assertRaisesRegex(qualification.QualificationError, "settled base events|unresolved base admissions"):
            qualification.sample_from_recorder_observation(current, "forged settlement")

    def test_prefix_regression_is_rejected_between_adjacent_repeated_captures(self) -> None:
        previous = copy.deepcopy(self.runtime["samples"][20])
        current = copy.deepcopy(previous)
        current["event_writer_admission_prefix"]["terminal_generation"] -= 1
        with self.assertRaisesRegex(qualification.QualificationError, "regressed"):
            qualification.validate_event_writer_prefix_sequence([previous, current])
        observation = copy.deepcopy(self.runtime["recorder_observations"][20])
        observation["heartbeat"]["events_storage_write_terminal_generation"] -= 1
        self.rebind_observation_heartbeat(observation, reconcile_writer_prefix=False)
        with self.assertRaisesRegex(qualification.QualificationError, "regressed"):
            qualification.validate_runtime_readiness(observation, "repeated capture", phase="sample", require_drained=False, adjacent_sample=previous)

    def test_prefix_never_excuses_poison_or_repairable_gaps(self) -> None:
        for key in ("events_storage_write_poisoned_total", "event_journal_repairable_gap_count"):
            with self.subTest(key=key):
                observation = copy.deepcopy(self.runtime["recorder_observations"][20])
                observation["heartbeat"][key] = 1
                self.rebind_observation_heartbeat(observation)
                with self.assertRaisesRegex(qualification.QualificationError, "poisoned_total|repairable_gap_count"):
                    qualification.validate_runtime_readiness(observation, "unsafe prefix", phase="sample", require_drained=False)
                samples = copy.deepcopy(self.runtime["samples"])
                samples[20] = qualification.sample_from_recorder_observation(observation, "unsafe prefix")
                with self.assertRaisesRegex(qualification.QualificationError, "poisoned_total|repairable_gap_count"):
                    qualification.derive_workload_ingress(samples, self.runtime["recorder_probe_evidence"]["workload"])

    def test_graph_age_is_required_finite_and_bounded_before_drain(self) -> None:
        observations = self.fresh_boundary_work_observations(boundary_offset=600)
        current = observations[20]
        for value in (None, -1, True, float("nan"), float("inf"), 10.251):
            with self.subTest(value=value):
                observation = copy.deepcopy(current)
                graph = observation["heartbeat"]["tracegraph_storage_admission"]
                if value is None:
                    del graph["oldest_outstanding_age_seconds"]
                else:
                    graph["oldest_outstanding_age_seconds"] = value
                self.rebind_observation_heartbeat(observation)
                with self.assertRaises(qualification.QualificationError):
                    qualification.validate_runtime_readiness(observation, "graph age", phase="ordinary sample", require_drained=False)
        idle = copy.deepcopy(self.runtime["recorder_observations"][20])
        idle["heartbeat"]["tracegraph_storage_admission"]["oldest_outstanding_age_seconds"] = 0.1
        self.rebind_observation_heartbeat(idle)
        with self.assertRaisesRegex(qualification.QualificationError, "idle TraceGraph"):
            qualification.sample_from_recorder_observation(idle, "idle age")
        report = self.rebuild_runtime_from_observations(observations)
        observation = report["recorder_observations"][20]
        observation["heartbeat"]["tracegraph_storage_admission"]["oldest_outstanding_age_seconds"] = 10.251
        self.rebind_observation_heartbeat(observation)
        report["samples"][20] = qualification.sample_from_recorder_observation(observation, "stale non-boundary graph")
        self.rehash_samples(report)
        with self.assertRaisesRegex(qualification.QualificationError, "oldest outstanding write age"):
            self.validate_runtime(report)
        with self.assertRaisesRegex(qualification.QualificationError, "oldest outstanding write age"):
            qualification.derive_workload_ingress(report["samples"], report["recorder_probe_evidence"]["workload"])

    def test_graph_flow_requires_fresh_bounded_work_and_no_inflight(self) -> None:
        observations = self.fresh_boundary_work_observations()
        sample = qualification.sample_from_recorder_observation(observations[26], "graph flow")
        previous = qualification.sample_from_recorder_observation(observations[25], "previous graph flow")
        pending = ["trace-graph-mutation queued=1 in_flight=0", "TraceGraph pending_entity_rows=2", "TraceGraph pending_edge_rows=1"]
        self.assertEqual(qualification.forgive_flowing_boundary_lanes(pending, sample, previous), [])
        for kind in ("event flight", "batch flight", "row flight", "rows", "queue", "no progress", "old heartbeat", "same heartbeat"):
            with self.subTest(kind=kind):
                current = copy.deepcopy(sample)
                row = current["conservation"]["trace-graph-mutation"]
                graph = current["trace_graph_write_accounting"]
                if kind == "event flight": row["in_flight"] = 1
                elif kind == "batch flight": graph["write_batches_in_flight"] = 1
                elif kind == "row flight": graph["write_rows_in_flight"] = 1
                elif kind == "rows": graph["pending_entity_rows"] = 1024
                elif kind == "queue": row["queued"] = 513
                elif kind == "no progress": row["completed"] = previous["conservation"]["trace-graph-mutation"]["completed"]
                elif kind == "old heartbeat": current["captured_at"] = iso(791)
                elif kind == "same heartbeat": current["heartbeat_written_at_unix"] = previous["heartbeat_written_at_unix"]
                self.assertEqual(qualification.forgive_flowing_boundary_lanes(pending, current, previous), pending)

    def test_complete_report_passes_every_threshold(self) -> None:
        self.validate_runtime()

    def test_file_fidelity_claims_source_test_coverage_with_recomputed_corpus_binding(self) -> None:
        fidelity = self.runtime["measurements"]["file_fidelity"]
        self.assertEqual(fidelity, {
            "unclassified_queue_loss": 0,
            "source_rule_corpus_sha256": qualification.rule_corpus_digest(ROOT),
            "semantic_validation_scope": "source-tests-only",
        })
        template = qualification.make_runtime_template(self.manifest, self.manifest_sha)
        self.assertEqual(set(template["measurements"]["file_fidelity"]), set(fidelity))
        self.validate_runtime()

    def test_file_fidelity_rejects_forged_source_digest_and_runtime_semantic_scope(self) -> None:
        for key, value, message in (
            ("source_rule_corpus_sha256", "c" * 64, "source rule corpus digest"),
            ("semantic_validation_scope", "runtime-reason-histogram", "limited to source tests"),
        ):
            with self.subTest(key=key):
                report = copy.deepcopy(self.runtime)
                report["measurements"]["file_fidelity"][key] = value
                with self.assertRaisesRegex(qualification.QualificationError, message):
                    self.validate_runtime(report)

    def test_file_fidelity_rejects_legacy_empty_semantic_attestation(self) -> None:
        legacy = {
            "unclassified_queue_loss": 0,
            "complete_rule_corpus_evaluated": True,
            "rule_corpus_sha256": qualification.rule_corpus_digest(ROOT),
            "semantic_reasons": [],
        }
        report = copy.deepcopy(self.runtime)
        report["measurements"]["file_fidelity"] = legacy
        with self.assertRaisesRegex(qualification.QualificationError, "file fidelity inventory"):
            self.validate_runtime(report)
        for key in ("complete_rule_corpus_evaluated", "semantic_reasons", "rule_corpus_sha256"):
            with self.subTest(key=key):
                report = copy.deepcopy(self.runtime)
                report["measurements"]["file_fidelity"][key] = legacy[key]
                with self.assertRaisesRegex(qualification.QualificationError, "file fidelity inventory"):
                    self.validate_runtime(report)

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

    def test_mach_cpu_ticks_convert_for_native_timebases(self) -> None:
        for ticks, ratio, expected in (
            (0, (1, 1), 0.0),
            (1_000_000_000, (1, 1), 1.0),
            (2_500_000_000, (1, 1), 2.5),
            (24_000_000, (125, 3), 1.0),
            (72_000_000, (125, 3), 3.0),
            (12_000_000, (125, 3), 0.5),
            (1, (125, 3), 125 / 3_000_000_000),
        ):
            with self.subTest(ticks=ticks, ratio=ratio):
                self.assertEqual(
                    qualification.mach_absolute_ticks_to_seconds(ticks, timebase=ratio),
                    expected,
                )

    def test_mach_cpu_conversion_rejects_invalid_input_and_ratios(self) -> None:
        for ticks in (-1, True, None, 1.5, float("inf")):
            with self.subTest(ticks=ticks):
                with self.assertRaisesRegex(qualification.QualificationError, "Mach CPU ticks"):
                    qualification.mach_absolute_ticks_to_seconds(ticks, timebase=(1, 1))
        for ratio in (
            (), (1,), (1, 1, 1), [1, 1], "1:1", (0, 1), (1, 0),
            (-1, 1), (1, -1), (True, 1), (1, True), (1.0, 1), (1, 1.0),
            (1, None), (1, float("inf")), (1, float("nan")),
            (0x1_0000_0000, 1), (1, 0x1_0000_0000),
        ):
            with self.subTest(ratio=ratio):
                with self.assertRaisesRegex(qualification.QualificationError, "Mach timebase"):
                    qualification.mach_absolute_ticks_to_seconds(1, timebase=ratio)

    def test_mach_timebase_query_uses_native_abi_and_caches_success(self) -> None:
        self.assertEqual(ctypes.sizeof(qualification.DarwinMachTimebaseInfo), 8)
        self.assertEqual(qualification.DarwinMachTimebaseInfo.numer.offset, 0)
        self.assertEqual(qualification.DarwinMachTimebaseInfo.denom.offset, 4)

        def query(pointer):
            info = ctypes.cast(pointer, ctypes.POINTER(qualification.DarwinMachTimebaseInfo)).contents
            info.numer = 125
            info.denom = 3
            return 0

        library = mock.Mock()
        library.mach_timebase_info.side_effect = query
        qualification.darwin_mach_timebase.cache_clear()
        try:
            with mock.patch.object(qualification.platform, "system", return_value="Darwin"), \
                    mock.patch.object(qualification.ctypes, "CDLL", return_value=library) as load:
                self.assertEqual(qualification.darwin_mach_timebase(), (125, 3))
                self.assertEqual(qualification.darwin_mach_timebase(), (125, 3))
                self.assertEqual(qualification.mach_absolute_ticks_to_seconds(24_000_000), 1.0)
            load.assert_called_once_with("/usr/lib/libSystem.B.dylib", use_errno=True)
            library.mach_timebase_info.assert_called_once()
            self.assertEqual(
                library.mach_timebase_info.argtypes,
                [ctypes.POINTER(qualification.DarwinMachTimebaseInfo)],
            )
            self.assertIs(library.mach_timebase_info.restype, ctypes.c_int)
        finally:
            qualification.darwin_mach_timebase.cache_clear()

    def test_mach_timebase_query_rejects_errors_and_does_not_cache_failure(self) -> None:
        for result, numer, denom in ((5, 125, 3), (0, 0, 3), (0, 125, 0)):
            with self.subTest(result=result, numer=numer, denom=denom):
                def query(pointer):
                    info = ctypes.cast(pointer, ctypes.POINTER(qualification.DarwinMachTimebaseInfo)).contents
                    info.numer = numer
                    info.denom = denom
                    return result

                library = mock.Mock()
                library.mach_timebase_info.side_effect = query
                qualification.darwin_mach_timebase.cache_clear()
                try:
                    with mock.patch.object(qualification.platform, "system", return_value="Darwin"), \
                            mock.patch.object(qualification.ctypes, "CDLL", return_value=library):
                        for _ in range(2):
                            with self.assertRaisesRegex(qualification.QualificationError, "Mach timebase query"):
                                qualification.darwin_mach_timebase()
                    self.assertEqual(library.mach_timebase_info.call_count, 2)
                finally:
                    qualification.darwin_mach_timebase.cache_clear()

    def test_mach_timebase_query_requires_available_native_api(self) -> None:
        qualification.darwin_mach_timebase.cache_clear()
        try:
            with mock.patch.object(qualification.platform, "system", return_value="Linux"), \
                    mock.patch.object(qualification.ctypes, "CDLL") as load:
                with self.assertRaisesRegex(qualification.QualificationError, "requires macOS"):
                    qualification.darwin_mach_timebase()
                load.assert_not_called()
            with mock.patch.object(qualification.platform, "system", return_value="Darwin"), \
                    mock.patch.object(qualification.ctypes, "CDLL", side_effect=OSError("fixture unavailable")):
                with self.assertRaisesRegex(qualification.QualificationError, "Mach timebase query is unavailable"):
                    qualification.darwin_mach_timebase()
        finally:
            qualification.darwin_mach_timebase.cache_clear()

    def test_native_engine_cpu_conversion_preserves_process_start_identity(self) -> None:
        identity = self.runtime["samples"][0]["engine_process"]
        usage = qualification.DarwinRUsageInfoV4()
        usage.ri_user_time = 48_000_000
        usage.ri_system_time = 24_000_000
        usage.ri_proc_start_abstime = identity["process_start_abstime"]
        usage.ri_phys_footprint = 123_456
        usage.ri_diskio_byteswritten = 654_321
        with mock.patch.object(qualification, "darwin_process_path", return_value=pathlib.Path(identity["executable_path"])), \
                mock.patch.object(qualification, "darwin_process_rusage", return_value=usage), \
                mock.patch.object(qualification, "darwin_process_cdhash", return_value=identity["running_cdhash"]), \
                mock.patch.object(qualification, "darwin_mach_timebase", return_value=(125, 3)), \
                mock.patch.object(qualification, "sha256_file", return_value=identity["executable_sha256"]), \
                mock.patch.object(pathlib.Path, "is_symlink", return_value=False), \
                mock.patch.object(pathlib.Path, "is_file", return_value=True):
            observed = qualification.engine_process_observation(identity["pid"])
        self.assertEqual(observed["engine_cpu_seconds_total"], 3.0)
        self.assertEqual(observed["process_start_abstime"], identity["process_start_abstime"])
        self.assertEqual(observed["engine_memory_footprint_bytes"], 123_456)
        self.assertEqual(observed["engine_disk_write_bytes_total"], 654_321)
        self.assertEqual(observed["running_cdhash"], identity["running_cdhash"])

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

    def test_native_es_canary_failure_rejects_readiness_with_zero_loss(self) -> None:
        report = copy.deepcopy(self.runtime)
        observation = report["recorder_observations"][0]
        observation["heartbeat"]["collector_health"][0].update({
            "enabled": True, "healthy": False, "state": "failed",
            "reason": "coverage canary: storeQueryUnknown",
            "native_canary_outcome": "storeQueryUnknown",
            "native_canary_failures_total": 1,
        })
        self.rederive_sample(report, 0)
        self.assertTrue(all(value == 0 for value in report["samples"][0]["losses"].values()))
        for require_llm_ready in (False, True):
            with self.subTest(require_llm_ready=require_llm_ready):
                with self.assertRaisesRegex(
                    qualification.QualificationError,
                    "ESCollector.*coverage canary: storeQueryUnknown",
                ):
                    qualification.validate_runtime_readiness(
                        observation, "fixture native ES", phase="fixture native ES",
                        require_drained=True, expected_pid=4321,
                        require_llm_ready=require_llm_ready,
                    )

    def test_native_es_canary_failure_rejects_middle_and_final_runtime_samples(self) -> None:
        for index in (len(self.runtime["samples"]) // 2, len(self.runtime["samples"]) - 1):
            with self.subTest(index=index):
                report = copy.deepcopy(self.runtime)
                report["recorder_observations"][index]["heartbeat"]["collector_health"][0].update({
                    "healthy": False, "state": "failed",
                    "reason": "coverage canary: storeQueryUnknown",
                    "native_canary_outcome": "storeQueryUnknown",
                    "native_canary_failures_total": 1,
                })
                self.rederive_sample(report, index)
                with self.assertRaisesRegex(
                    qualification.QualificationError,
                    "fail-fast readiness fault:.*storeQueryUnknown",
                ):
                    self.validate_runtime(report)

    def test_native_es_required_fields_are_not_defaulted(self) -> None:
        for target, keys in (
            ("heartbeat", (
                "es_mode", "es_client_split_degraded", "es_sensor_degraded",
                "collector_health",
            )),
            ("collector", ("name", "enabled", "healthy", "state", "reason")),
        ):
            for key in keys:
                with self.subTest(target=target, missing=key):
                    heartbeat = copy.deepcopy(self.runtime["recorder_observations"][0]["heartbeat"])
                    row = heartbeat if target == "heartbeat" else heartbeat["collector_health"][0]
                    del row[key]
                    with self.assertRaisesRegex(qualification.QualificationError, re.escape(key)):
                        qualification.native_es_readiness_failures(heartbeat, "fixture heartbeat")

    def test_native_es_rejects_malformed_field_types(self) -> None:
        for target, key, values in (
            ("heartbeat", "es_mode", (None, False, 1, [], {}, "")),
            ("heartbeat", "es_client_split_degraded", (None, 0, 1, "false", [])),
            ("heartbeat", "es_sensor_degraded", (None, 0, 1, "false", [])),
            ("collector", "name", (None, False, 1, [], {}, "")),
            ("collector", "enabled", (None, 0, 1, "true", [])),
            ("collector", "healthy", (None, 0, 1, "true", [])),
            ("collector", "state", (None, False, 1, [], {}, "", "unrecognized")),
            ("collector", "reason", (None, False, 1, [], {})),
            ("collector", "last_error", (None, False, 1, [], {})),
            ("collector", "native_canary_outcome", (None, False, 1, [], {}, "", "unknown")),
        ):
            for value in values:
                with self.subTest(target=target, key=key, value=value):
                    heartbeat = copy.deepcopy(self.runtime["recorder_observations"][0]["heartbeat"])
                    row = heartbeat if target == "heartbeat" else heartbeat["collector_health"][0]
                    row[key] = value
                    with self.assertRaisesRegex(qualification.QualificationError, re.escape(key)):
                        qualification.native_es_readiness_failures(heartbeat, "fixture heartbeat")

    def test_native_es_inventory_must_be_well_formed_and_unambiguous(self) -> None:
        original = self.runtime["recorder_observations"][0]["heartbeat"]
        healthy = copy.deepcopy(original["collector_health"][0])
        failed = {**healthy, "state": "failed", "healthy": False, "reason": "fixture failure"}
        disabled = copy.deepcopy(original["collector_health"][1])
        for rows in (None, {}, "ESCollector", [], [None], [{}], [disabled],
                     [healthy, healthy], [healthy, failed], [failed, healthy]):
            with self.subTest(rows=rows):
                heartbeat = copy.deepcopy(original)
                heartbeat["collector_health"] = rows
                with self.assertRaisesRegex(qualification.QualificationError, "collector_health"):
                    qualification.native_es_readiness_failures(heartbeat, "fixture heartbeat")

    def test_native_es_missing_and_duplicate_evidence_rejects_final_runtime(self) -> None:
        for defect in ("missing mode", "duplicate ESCollector"):
            with self.subTest(defect=defect):
                report = copy.deepcopy(self.runtime)
                index = len(report["samples"]) - 1
                heartbeat = report["recorder_observations"][index]["heartbeat"]
                if defect == "missing mode":
                    del heartbeat["es_mode"]
                    expected = "es_mode"
                else:
                    heartbeat["collector_health"].append(copy.deepcopy(heartbeat["collector_health"][0]))
                    expected = "exactly one ESCollector"
                self.rederive_sample(report, index)
                with self.assertRaisesRegex(qualification.QualificationError, expected):
                    self.validate_runtime(report)

    def test_native_es_rejects_degraded_modes_flags_and_collector_states(self) -> None:
        cases = [
            ("heartbeat", "es_mode", "eslogger proxy", "not native client"),
            ("heartbeat", "es_mode", "kdebug", "not native client"),
            ("heartbeat", "es_mode", "none", "not native client"),
            ("heartbeat", "es_client_split_degraded", True, "split is degraded"),
            ("heartbeat", "es_sensor_degraded", True, "sensor is degraded"),
            ("collector", "enabled", False, "not enabled and healthy"),
            ("collector", "healthy", False, "not enabled and healthy"),
        ]
        cases.extend(
            ("collector", "state", state, "not enabled and healthy")
            for state in ("disabled", "starting", "failed", "stalled")
        )
        cases.extend(
            ("collector", "native_canary_outcome", outcome, f"canary outcome is {outcome}")
            for outcome in (
                "kernelGap", "ingestHandoffGap", "evictionGap",
                "storeQueryUnknown", "spawnFailed", "cancelled",
            )
        )
        for target, key, value, expected in cases:
            with self.subTest(target=target, key=key, value=value):
                heartbeat = copy.deepcopy(self.runtime["recorder_observations"][0]["heartbeat"])
                row = heartbeat if target == "heartbeat" else heartbeat["collector_health"][0]
                row[key] = value
                failures = qualification.native_es_readiness_failures(heartbeat, "fixture heartbeat")
                self.assertRegex("; ".join(failures), expected)

    def test_native_es_current_recovery_and_disabled_optional_collectors_pass(self) -> None:
        report = copy.deepcopy(self.runtime)
        for index, observation in enumerate(report["recorder_observations"]):
            es = observation["heartbeat"]["collector_health"][0]
            es.update({
                "reason": "回復済み — callbacks active",
                "last_error": "coverage canary: storeQueryUnknown",
                "error_count": 1,
                "native_canary_checks_total": 2,
                "native_canary_failures_total": 1,
                "native_canary_outcome": "healthy",
            })
            self.rederive_sample(report, index)
        first = report["recorder_observations"][0]
        optional = first["heartbeat"]["collector_health"][1:]
        self.assertEqual({row["name"] for row in optional}, {"FSEventsCollector", "UltrasonicMonitor"})
        self.assertTrue(all(row["enabled"] is False and row["healthy"] is False for row in optional))
        qualification.validate_runtime_readiness(
            first, "fixture recovered ES", phase="fixture recovered ES",
            require_drained=True, expected_pid=4321,
        )
        self.validate_runtime(report)

    def test_native_es_initial_canary_grace_does_not_claim_a_completed_probe(self) -> None:
        heartbeat = copy.deepcopy(self.runtime["recorder_observations"][0]["heartbeat"])
        es = heartbeat["collector_health"][0]
        del es["native_canary_outcome"]
        es["native_canary_checks_total"] = 0
        es["native_canary_age_seconds"] = 250.0
        self.assertEqual(
            qualification.native_es_readiness_failures(heartbeat, "fixture initial ES grace"),
            [],
        )
        self.assertNotIn("native_canary_outcome", es)
        self.assertEqual(es["native_canary_checks_total"], 0)

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
        self.rederive_sample(report, 0)
        self.assertEqual(
            report["samples"][0]["alert_storage_admission"]["family_footprint_bytes"],
            193 * 1024 * 1024,
        )
        with self.assertRaisesRegex(
            qualification.QualificationError, "admission boundary"
        ):
            qualification.validate_runtime_readiness(
                observation, "fixture alerts", phase="fixture alerts",
                require_drained=True,
            )
        with self.assertRaisesRegex(
            qualification.QualificationError, "admission boundary"
        ):
            self.validate_runtime(report)

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

    def test_live_recorder_retains_rejected_alert_pressure_sample(self) -> None:
        """A failed t0 or later sample must survive in the failed capture."""
        initial = copy.deepcopy(self.runtime["recorder_observations"][0])
        for offset in (0, 30):
            with self.subTest(offset=offset):
                rejected = copy.deepcopy(self.runtime["recorder_observations"][offset // 30])
                rejected["heartbeat"]["alert_evidence_budget"]["alerts_family_footprint_bytes"] = 193 * 1024 * 1024
                self.rebind_observation_heartbeat(rejected)
                captured = [initial, initial, rejected] if offset == 0 else [initial, initial, initial, rejected]
                capture_path = self.root / f"failed-alert-pressure-{offset}.capture.json"
                with mock.patch.object(qualification.platform, "system", return_value="Darwin"), \
                        mock.patch.object(qualification.os, "geteuid", return_value=0), \
                        mock.patch.object(qualification, "read_live_heartbeat", return_value=(initial["heartbeat"], {})), \
                        mock.patch.object(qualification, "installed_runtime_host", return_value=self.runtime["host"]), \
                        mock.patch.object(qualification, "capture_runtime_observation", side_effect=captured), \
                        mock.patch.object(qualification, "source_runtime_probe_evidence", return_value={}), \
                        mock.patch.object(qualification, "mounted_tool_probes", return_value={}), \
                        mock.patch.object(qualification, "wait_for_runtime_drain", return_value=initial), \
                        mock.patch.object(qualification, "prewarm_alert_investigation", return_value=({}, initial)), \
                        mock.patch.object(qualification, "installed_engine_identity", return_value=self.runtime["installed_engine"]["start"]), \
                        mock.patch.object(qualification, "installed_gui_identity", return_value=self.runtime["installed_gui"]["start"]), \
                        mock.patch.object(qualification, "installed_alert_database", return_value=self.root / "alerts.db"), \
                        mock.patch.object(qualification.time, "monotonic", return_value=0), \
                        mock.patch.object(qualification.time, "sleep"):
                    with self.assertRaisesRegex(qualification.QualificationError, "admission boundary"):
                        qualification.live_runtime_recording(
                            root=ROOT, candidate_manifest=self.manifest,
                            candidate_manifest_sha256=self.manifest_sha, dmg=self.dmg,
                            heartbeat_path=self.root / "heartbeat_rich.json",
                            data_dirs=[self.root], sqlite_overrides={}, capture_path=capture_path,
                        )
                failure = qualification.read_json_file(capture_path, "failed alert pressure")
                self.assertEqual(failure["result"], "failed")
                self.assertEqual(failure["phase"], "epoch")
                self.assertEqual([row["offset_seconds"] for row in failure["observations"]], [0] if offset == 0 else [0, 30])
                self.assertEqual(failure["observations"][-1], rejected)

    def test_cumulative_alert_insert_errors_fail_readiness(self) -> None:
        """v1.22.0: alert_insert_errors_total mirrors capture_failures_total."""
        observation = copy.deepcopy(self.runtime["recorder_observations"][0])
        observation["heartbeat"]["alert_insert_errors_total"] = 4
        self.rebind_observation_heartbeat(observation)
        with self.assertRaisesRegex(
            qualification.QualificationError,
            "cumulative alert insert errors=4",
        ):
            qualification.validate_runtime_readiness(
                observation, "fixture alerts", phase="fixture alerts",
                require_drained=True,
            )

    def test_zero_alert_insert_errors_passes_readiness(self) -> None:
        observation = copy.deepcopy(self.runtime["recorder_observations"][0])
        observation["heartbeat"]["alert_insert_errors_total"] = 0
        self.rebind_observation_heartbeat(observation)
        qualification.validate_runtime_readiness(
            observation, "fixture alerts", phase="fixture alerts",
            require_drained=True,
        )

    def test_missing_alert_insert_errors_key_is_treated_as_zero(self) -> None:
        observation = copy.deepcopy(self.runtime["recorder_observations"][0])
        self.assertNotIn("alert_insert_errors_total", observation["heartbeat"])
        self.assertEqual(
            qualification.alert_storage_admission_sample(
                observation["heartbeat"]
            )["insert_errors_total"],
            0,
        )
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
            telemetry_before={"configured": True},
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
            telemetry_before={"configured": True},
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
            telemetry_before={"configured": True},
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
                telemetry_before={"configured": True},
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
            qualification.QualificationError, "completion is not a later raw LLM sample"
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
        self.produce_unconfigured_alert_proofs(report["recorder_probe_evidence"])
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
        self.produce_unconfigured_alert_proofs(report["recorder_probe_evidence"])
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

    def test_legal_capture_jitter_does_not_change_burst_mean_verdict(self) -> None:
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
        result = qualification.derive_workload_ingress(
            samples, self.runtime["recorder_probe_evidence"]["workload"],
        )
        self.assertEqual(result["combined_bracketed_offered_volume"], offered_delta)
        self.assertAlmostEqual(result["combined_offered_per_burst_second"], offered_delta / 22)

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
        probes = self.recorder_probes()
        self.produce_unconfigured_alert_proofs(probes["evidence"])
        report = self.rebuild_runtime_from_observations(observations, probes=probes)

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

    def test_builder_rejects_changed_content_with_reused_heartbeat_tick(self) -> None:
        observations = copy.deepcopy(self.runtime["recorder_observations"])
        observations[5]["heartbeat"]["written_at_unix"] = observations[4][
            "heartbeat"
        ]["written_at_unix"]
        self.rebind_observation_heartbeat(observations[5])
        with self.assertRaisesRegex(
            qualification.QualificationError,
            "reused heartbeat timestamp with different content",
        ):
            self.rebuild_runtime_from_observations(observations)

    def test_fresh_repeated_heartbeat_and_next_two_tick_jump_qualify(self) -> None:
        observations = copy.deepcopy(self.runtime["recorder_observations"])
        # A producer publication slips just past one recorder poll. The exact
        # prior snapshot repeats; the next independent poll sees a two-tick jump.
        observations[5]["heartbeat"] = copy.deepcopy(observations[4]["heartbeat"])
        self.rebind_observation_heartbeat(observations[5])
        report = self.rebuild_runtime_from_observations(observations)
        self.validate_runtime(report)
        self.assertEqual(report["samples"][4]["heartbeat_snapshot_sha256"],
                         report["samples"][5]["heartbeat_snapshot_sha256"])
        self.assertGreater(report["samples"][5]["engine_cpu_seconds_total"],
                           report["samples"][4]["engine_cpu_seconds_total"])

    def test_repeated_heartbeat_cannot_hide_staleness_or_excessive_producer_gap(self) -> None:
        observations = copy.deepcopy(self.runtime["recorder_observations"])
        for index in (5, 6, 7):
            observations[index]["heartbeat"] = copy.deepcopy(observations[4]["heartbeat"])
            self.rebind_observation_heartbeat(observations[index])
        with self.assertRaisesRegex(qualification.QualificationError, "stale or future"):
            self.rebuild_runtime_from_observations(observations)

        observations = copy.deepcopy(self.runtime["recorder_observations"])
        for index, observation in enumerate(observations):
            lag = 45 if index < 5 else -5
            heartbeat = observation["heartbeat"]
            heartbeat["written_at_unix"] -= lag
            heartbeat["engine_uptime_seconds"] -= lag
            self.rebind_observation_heartbeat(observation)
        with self.assertRaisesRegex(qualification.QualificationError, "distinct heartbeat gap"):
            self.rebuild_runtime_from_observations(observations)

    def test_fresh_repeated_workload_snapshot_still_measures_complete_burst(self) -> None:
        observations = copy.deepcopy(self.runtime["recorder_observations"])
        observations[11]["heartbeat"] = copy.deepcopy(observations[10]["heartbeat"])
        self.rebind_observation_heartbeat(observations[11])
        report = self.rebuild_runtime_from_observations(observations)
        self.validate_runtime(report)
        self.assertGreaterEqual(report["measurements"]["workload_ingress"]["combined_bracketed_offered_volume"],
                                qualification.MIN_BURST_COMBINED_OFFERED_VOLUME)

    def test_zero_new_base_persistence_with_prewarm_history_fails_builder_and_verifier(self) -> None:
        for frozen_lanes in (("priority",), ("file",), ("priority", "file")):
            with self.subTest(frozen_lanes=frozen_lanes):
                report = copy.deepcopy(self.runtime)
                for index, observation in enumerate(report["recorder_observations"]):
                    heartbeat = observation["heartbeat"]
                    for lane in frozen_lanes:
                        completed = heartbeat["events_storage_write_persisted_by_lane"][lane]
                        heartbeat["events_storage_write_offered_by_lane"][lane] += 1
                        heartbeat["events_storage_write_persisted_by_lane"][lane] = 1
                        heartbeat["events_storage_write_filtered_by_lane"][lane] = completed
                    self.rederive_sample(report, index)
                # Reconcile unrelated aggregates so the verifier reaches the
                # actual missing-persistence assertion, not a stale fixture hash.
                final = report["samples"][-1]["conservation"]
                for row in report["measurements"]["conservation"]["boundaries"]:
                    row.update(final[row["name"]])
                with self.assertRaisesRegex(qualification.QualificationError, "persisted base events"):
                    self.rebuild_runtime_from_observations(report["recorder_observations"])
                with self.assertRaisesRegex(qualification.QualificationError, "persisted base events"):
                    self.validate_runtime(report)

    def test_healthy_persistence_and_filtering_remain_separate_measured_outcomes(self) -> None:
        observations = copy.deepcopy(self.runtime["recorder_observations"])
        for observation in observations:
            heartbeat = observation["heartbeat"]
            for lane in ("priority", "file"):
                completed = heartbeat["events_storage_write_persisted_by_lane"][lane]
                heartbeat["events_storage_write_persisted_by_lane"][lane] = completed - completed // 2
                heartbeat["events_storage_write_filtered_by_lane"][lane] = completed // 2
            self.rebind_observation_heartbeat(observation)
        report = self.rebuild_runtime_from_observations(observations)
        self.validate_runtime(report)
        window = report["measurements"]["workload_ingress"]
        for lane in ("priority", "file"):
            self.assertGreater(window[f"{lane}_persistence_persisted_delta"], 0)
            self.assertGreater(window[f"{lane}_persistence_filtered_delta"], 0)
            self.assertEqual(window[f"{lane}_persistence_completed_delta"],
                             window[f"{lane}_persistence_persisted_delta"]
                             + window[f"{lane}_persistence_filtered_delta"])

    def test_persistence_outcome_reset_cannot_hide_in_constant_completion_total(self) -> None:
        observations = copy.deepcopy(self.runtime["recorder_observations"])
        for observation in observations:
            if observation["offset_seconds"] >= 450:
                heartbeat = observation["heartbeat"]
                heartbeat["events_storage_write_filtered_by_lane"]["file"] = heartbeat["events_storage_write_persisted_by_lane"]["file"]
                heartbeat["events_storage_write_persisted_by_lane"]["file"] = 0
                self.rebind_observation_heartbeat(observation)
        with self.assertRaisesRegex(qualification.QualificationError, "file persisted counter moved backwards"):
            self.rebuild_runtime_from_observations(observations)

    def test_burst_load_verdict_is_independent_of_all_300_heartbeat_phases(self) -> None:
        timing = self.runtime["recorder_probe_evidence"]["workload"]
        epoch = qualification.parse_time(iso(0), "fixture epoch").timestamp()
        peaks = []
        for tenth in range(300):
            samples = copy.deepcopy(self.runtime["samples"])
            phase = tenth / 10
            for sample in samples:
                tick = sample["offset_seconds"] - phase
                sample["heartbeat_written_at_unix"] = epoch + tick
                volume = round(49_200 * min(1, max(0, (tick - 300) / 22)))
                for lane in ("priority", "file"):
                    boundary = sample["conservation"][f"{lane}-ingress"]
                    boundary["offered"] = boundary["completed"] = 1_000 + round(tick) + volume // 2
            result = qualification.derive_workload_ingress(samples, timing)
            self.assertGreaterEqual(result["combined_bracketed_offered_volume"], 49_200)
            self.assertGreater(result["combined_offered_per_burst_second"], 2_200)
            peaks.append(result["combined_peak_offered_per_second"])
        self.assertLess(min(peaks), qualification.MIN_BURST_COMBINED_OFFERED_PER_SECOND)
        self.assertGreater(max(peaks), qualification.MIN_BURST_COMBINED_OFFERED_PER_SECOND)

    def test_burst_mean_and_volume_are_independent_required_load_controls(self) -> None:
        timing = copy.deepcopy(self.runtime["recorder_probe_evidence"]["workload"])
        timing["completed_at"] = iso(370)
        timing["elapsed_monotonic_seconds"] = 70
        with self.assertRaisesRegex(qualification.QualificationError, "reference load mean"):
            qualification.derive_workload_ingress(self.runtime["samples"], timing)
        samples = copy.deepcopy(self.runtime["samples"])
        for sample in samples:
            if sample["offset_seconds"] >= 330:
                for lane in ("priority", "file"):
                    boundary = sample["conservation"][f"{lane}-ingress"]
                    boundary["offered"] -= 35_000
                    boundary["completed"] -= 35_000
        timing["completed_at"] = iso(301)
        timing["elapsed_monotonic_seconds"] = 1
        with self.assertRaisesRegex(qualification.QualificationError, "reference load volume"):
            qualification.derive_workload_ingress(samples, timing)

    def test_workload_exit_receipt_requires_independent_reconciled_timing(self) -> None:
        for changes, message in (
            ({"timing_source": "thirty-second-poll"}, "independent process-exit"),
            ({"elapsed_monotonic_seconds": 1}, "duration disagree"),
            ({"completed_at": iso(391), "elapsed_monotonic_seconds": 91}, "elapsed deadline"),
        ):
            with self.subTest(changes=changes):
                evidence = copy.deepcopy(self.runtime["recorder_probe_evidence"])
                evidence["workload"].update(changes)
                with self.assertRaisesRegex(qualification.QualificationError, message):
                    qualification.validate_recorder_probe_evidence(
                        evidence, source_root=ROOT,
                        expected_preinstall_clean_ci=self.manifest["preinstall_clean_ci"],
                    )

    def test_workload_waiter_records_exit_before_delayed_telemetry_poll(self) -> None:
        job = qualification.TimedWorkload(
            [sys.executable, "-c", "import time; time.sleep(0.05); print('completed')"], cwd=self.root,
        )
        try:
            self.assertTrue(job.finished.wait(timeout=5))
            self.assertIsNone(job.error)
            time.sleep(0.12)  # The telemetry consumer discovers exit later.
            discovered_at = dt.datetime.now(dt.timezone.utc)
            self.assertGreater((discovered_at - job.completed_at).total_seconds(), 0.1)
            self.assertEqual(job.stdout.strip(), "completed")
            self.assertEqual(job.process.returncode, 0)
            self.assertAlmostEqual((job.completed_at - job.started_at).total_seconds(),
                                   job.elapsed_monotonic_seconds, delta=0.1)
        finally:
            job.close()

    def test_workload_waiter_enforces_deadline_without_a_telemetry_poll(self) -> None:
        job = qualification.TimedWorkload(
            [sys.executable, "-c", "import time; time.sleep(30)"], cwd=self.root,
            deadline_seconds=0.05,
        )
        try:
            self.assertTrue(job.finished.wait(timeout=5))
            self.assertIn("independent elapsed deadline", str(job.error))
            self.assertIsNotNone(job.process.returncode)
            self.assertIsNone(job.completed_at)
        finally:
            job.close()

    def test_builder_rejects_heartbeat_and_uptime_clock_disagreement(self) -> None:
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
            "engine monotonic uptime and heartbeat intervals diverge",
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
            if 330 <= observation["offset_seconds"] <= \
                    qualification.BURST_DRAIN_OFFSET_SECONDS:
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
                    # Inject AFTER the drain boundary, so the cumulative
                    # shed/poison check is what rejects this and not the
                    # stricter burst-window conservation check that spans
                    # burst start -> drain end.
                    if observation["offset_seconds"] <= \
                            qualification.BURST_DRAIN_OFFSET_SECONDS:
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

    def test_healthy_complete_search_index_remains_verified_in_report(self) -> None:
        observations = copy.deepcopy(self.runtime["recorder_observations"])
        search = observations[0]["heartbeat"]["event_search_projection"]
        search.update(requested_window_complete=True, effective_duration_seconds=3_600, complete=True)
        search.update(projection_materialized=search["projection_considered"],
                      projection_omitted_quota=0, projection_omitted_total=0)
        self.rebind_observation_heartbeat(observations[0])
        report = self.rebuild_runtime_from_observations(observations)
        row = report["samples"][0]["event_search_projection"]
        self.assertTrue(row["complete"])
        self.assertFalse(row["search_index_degraded"])
        self.assertEqual(row["search_index_reason"], "healthy")
        self.assertEqual(row, report["measurements"]["event_storage"]["event_search_projections"][0])
        self.validate_runtime(report)

    def test_degraded_search_index_is_preserved_as_incomplete_and_refuses_qualification(self) -> None:
        observations = copy.deepcopy(self.runtime["recorder_observations"])
        search = observations[0]["heartbeat"]["event_search_projection"]
        # All coverage is otherwise complete. Index degradation alone must
        # account for complete=False without discarding the measured evidence.
        search.update(requested_window_complete=True, effective_duration_seconds=3_600,
                      search_index_degraded=True, search_index_reason="fts_repair_pending", complete=False)
        search.update(projection_materialized=search["projection_considered"],
                      projection_omitted_quota=0, projection_omitted_total=0)
        self.rebind_observation_heartbeat(observations[0])
        report = self.rebuild_runtime_from_observations(observations)
        row = report["samples"][0]["event_search_projection"]
        self.assertFalse(row["complete"])
        self.assertTrue(row["search_index_degraded"])
        self.assertEqual(row["search_index_reason"], "fts_repair_pending")
        self.assertEqual(row, report["measurements"]["event_storage"]["event_search_projections"][0])
        self.assertTrue(report["measurements"]["event_storage"]["search_tier_gaps_visible"])
        with self.assertRaisesRegex(qualification.QualificationError, "index is degraded"):
            qualification.validate_runtime_readiness(
                observations[0], "degraded reference observation", phase="preflight",
                require_drained=True, expected_pid=4321,
            )
        with self.assertRaisesRegex(qualification.QualificationError, "index is degraded"):
            self.validate_runtime(report)

    def test_search_index_completeness_reason_and_required_fields_cannot_be_forged(self) -> None:
        mutations = (
            ({"search_index_degraded": True, "search_index_reason": "fts_repair_pending", "complete": True}, None, "complete hides"),
            ({"search_index_degraded": True, "search_index_reason": "healthy", "complete": False}, None, "reason does not match"),
            ({"search_index_reason": "fts_repair_pending"}, None, "reason does not match"),
            ({}, "search_index_degraded", "must be a boolean"),
            ({}, "search_index_reason", "must be a non-empty string"),
        )
        for changes, missing, reason in mutations:
            with self.subTest(changes=changes, missing=missing):
                observation = copy.deepcopy(self.runtime["recorder_observations"][0])
                search = observation["heartbeat"]["event_search_projection"]
                search.update(requested_window_complete=True, effective_duration_seconds=3_600, complete=True)
                search.update(projection_materialized=search["projection_considered"],
                              projection_omitted_quota=0, projection_omitted_total=0)
                search.update(changes)
                if missing is not None:
                    del search[missing]
                self.rebind_observation_heartbeat(observation)
                with self.assertRaisesRegex(qualification.QualificationError, reason):
                    qualification.sample_from_recorder_observation(observation, "forged search index evidence")

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

    def test_event_journal_index_sample_requires_current_telemetry(self) -> None:
        for heartbeat in ({}, {"event_journal_index": None}):
            with self.subTest(heartbeat=heartbeat):
                with self.assertRaisesRegex(
                    qualification.QualificationError, "event_journal_index must be an object",
                ):
                    qualification.event_journal_index_sample(heartbeat)
        for missing in ("full_rebuilds_total", "append_refreshes_total"):
            counters = {"full_rebuilds_total": 1, "append_refreshes_total": 1}
            del counters[missing]
            with self.subTest(missing=missing):
                with self.assertRaisesRegex(qualification.QualificationError, missing):
                    qualification.event_journal_index_sample({"event_journal_index": counters})

    def test_event_journal_index_sample_normalizes_present_counters(self) -> None:
        result = qualification.event_journal_index_sample(
            {
                "event_journal_index": {
                    "full_rebuilds_total": 3,
                    "append_refreshes_total": 7,
                }
            }
        )
        self.assertEqual(
            result,
            {
                "present": True,
                "full_rebuilds_total": 3,
                "append_refreshes_total": 7,
            },
        )

    def test_event_journal_index_full_rebuild_recurrence_fails_when_appends_climb(
        self,
    ) -> None:
        """v1.22.0 recurrence gate: the dashboard-starves-expiry signature."""
        report = copy.deepcopy(self.runtime)
        observations = report["recorder_observations"]
        last_index = len(observations) - 1
        for index, observation in enumerate(observations):
            observation["heartbeat"]["event_journal_index"] = {
                "full_rebuilds_total": 5 if index == last_index else 0,
                "append_refreshes_total": 10 if index == last_index else 0,
            }
            self.rederive_sample(report, index)
        with self.assertRaisesRegex(
            qualification.QualificationError,
            "dashboard-starves-expiry recurrence signature",
        ):
            self.validate_runtime(report)

    def test_event_journal_index_recurrence_passes_when_only_appends_climb(
        self,
    ) -> None:
        report = copy.deepcopy(self.runtime)
        observations = report["recorder_observations"]
        for index, observation in enumerate(observations):
            observation["heartbeat"]["event_journal_index"] = {
                "full_rebuilds_total": 1,
                "append_refreshes_total": index,
            }
            self.rederive_sample(report, index)
        self.validate_runtime(report)

    def test_event_journal_index_recurrence_fails_when_appends_stay_flat(
        self,
    ) -> None:
        """The worst case: every refresh took the expensive path, never the cheap one.

        This is the defect at 100% severity, and the gate used to pass it. It
        required append_refreshes_total to ALSO be climbing before it would
        fire, which is the engine's own description of HEALTHY operation --
        DaemonTimers publishes the pair with "full_rebuilds_total should stay
        flat while append_refreshes_total climbs", and EventStore's slow-refresh
        log says "rebuilds climbing WITH append refreshes flat means expiry is
        again forcing full rebuilds". So append_delta == 0 switched the gate off
        exactly when it mattered most.
        """
        report = copy.deepcopy(self.runtime)
        observations = report["recorder_observations"]
        last_index = len(observations) - 1
        for index, observation in enumerate(observations):
            observation["heartbeat"]["event_journal_index"] = {
                "full_rebuilds_total": 9 if index == last_index else 0,
                "append_refreshes_total": 0,
            }
            self.rederive_sample(report, index)
        with self.assertRaisesRegex(
            qualification.QualificationError,
            "dashboard-starves-expiry recurrence signature",
        ):
            self.validate_runtime(report)

    def test_event_journal_index_recurrence_allows_legitimate_rebuilds(
        self,
    ) -> None:
        """A cold start's handful of real rebuilds must not fail the gate.

        Dropping the append conjunct leaves the allowance as the only thing
        separating a legitimate rebuild from the recurrence signature, so pin
        that it still carries them.
        """
        report = copy.deepcopy(self.runtime)
        observations = report["recorder_observations"]
        last_index = len(observations) - 1
        for index, observation in enumerate(observations):
            observation["heartbeat"]["event_journal_index"] = {
                "full_rebuilds_total": (
                    qualification.EVENT_JOURNAL_INDEX_FULL_REBUILD_ALLOWANCE
                    if index == last_index
                    else 0
                ),
                "append_refreshes_total": 0,
            }
            self.rederive_sample(report, index)
        self.validate_runtime(report)

    def test_missing_journal_index_sample_cannot_build_or_validate_pass(self) -> None:
        report = copy.deepcopy(self.runtime)
        del report["recorder_observations"][12]["heartbeat"]["event_journal_index"]
        self.rebind_observation_heartbeat(report["recorder_observations"][12])
        with self.assertRaisesRegex(qualification.QualificationError, "event_journal_index"):
            self.rebuild_runtime_from_observations(report["recorder_observations"])
        with self.assertRaisesRegex(qualification.QualificationError, "event_journal_index"):
            self.validate_runtime(report)

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
            if 330 <= observation["offset_seconds"] <= \
                    qualification.BURST_DRAIN_OFFSET_SECONDS:
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
        # Derived from the cap, not a literal: the captured interval here is
        # 20s against a 30s scheduled one, so any byte count strictly between
        # 20x and 30x the cap passes on the scheduled rate while failing on the
        # captured rate -- which is the jitter this test exists to catch. 25x
        # sits in the middle of that band at whatever the cap currently is.
        scheduled_passing_bytes = int(
            qualification.MAX_WINDOW_WRITE_BYTES_PER_SECOND * 25
        )
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
            qualification.derive_workload_ingress(report["samples"], report["recorder_probe_evidence"]["workload"])
        )

        self.validate_runtime(report)

        window = qualification.derive_workload_ingress(report["samples"], report["recorder_probe_evidence"]["workload"])
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
                    qualification.derive_workload_ingress(samples, self.runtime["recorder_probe_evidence"]["workload"])

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
