#!/usr/bin/env python3
"""Deterministic offline fixtures for candidate-qualification.py."""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import importlib.util
import pathlib
import subprocess
import tempfile
import unittest


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


def llm_heartbeat_payload(*, healthy: bool, started: int = 0, accepted: int = 0,
                          retries: int = 0, rejected: int = 0,
                          current: int = 0) -> dict:
    def counters(feature: str) -> dict:
        is_alert = feature in ("alert_investigation", "totals")
        return {
            "requestedTotal": started if is_alert else 0,
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
    return {
        "configured": True,
        "healthy": healthy,
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
                "engine_rss_bytes": rss,
                "gui_background_cpu_percent": 5.0,
                "sequence_pending_steps_evicted_total": 7,
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
                    "write_attempts_total": counter_value,
                    "write_batches_committed_total": counter_value,
                    "write_batches_failed_total": 0,
                    "write_batches_in_flight": 0,
                    "write_rows_attempted_total": counter_value * 2,
                    "write_rows_committed_total": counter_value * 2,
                    "write_rows_failed_total": 0,
                    "write_rows_in_flight": 0,
                    "entity_observations_total": counter_value,
                    "edge_observations_total": counter_value,
                    "coalesced_noop_rows_total": 0,
                    "pending_entity_rows": 0,
                    "pending_edge_rows": 0,
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
            "sequence_checkpoint": {
                "conservation": boundaries["sequence-checkpoint"]
            },
            "sequence_pending_steps_evicted_total": sample[
                "sequence_pending_steps_evicted_total"
            ],
            "sequence_journal_conservation": boundaries["sequence-journal"],
            "sequence_state_continuity_maintained": True,
            "sequence_state_continuity_detail": "nominal",
            "tracegraph_storage_admission": {
                "enabled": True,
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
            "events_retention_budget": {
                "state": "converged",
                "sticky": False,
            },
            "es_kernel_dropped_total": 0,
            "es_copy_backpressure_dropped_total": 0,
            "es_stream_yield_dropped_total": 0,
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
                    "engine_rss_bytes": sample["engine_rss_bytes"],
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

    focused_output = "✔ Test run with 27 tests passed after 0.2 seconds.\n"
    reload_output = (
        "[SIGHUP] Reloaded 438 single + 41 sequence rules "
        "(rule_profile stable governs the sequence/graph reload)\n"
    )
    evidence = {
        "rule_lint": probe(["/bin/bash", str(ROOT / "scripts/rule-lint.sh")]),
        "focused_runtime_tests": {
            **probe(
                [
                    "/usr/bin/xcrun", "swift", "test", "--package-path",
                    str(ROOT), "--filter", qualification.FOCUSED_RUNTIME_TEST_FILTER,
                ],
                focused_output,
            ),
            "observed_test_count": 27,
        },
        "workload": probe(
            ["/bin/bash", str(ROOT / "scripts/runtime-qualification-workload.sh")],
            "PASS: fixed workload completed iterations=20000 otlp_spans=1 alert_triggers=1\n",
        ),
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
        "search_tier_gaps_reconcile_exactly": True,
        "search_tier_gaps_visible": True,
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

    def validate_runtime(self, report: dict | None = None) -> None:
        qualification.validate_runtime_report(
            self.runtime if report is None else report,
            candidate_manifest_sha256=self.manifest_sha,
            candidate=self.validate_candidate(),
            candidate_verification=self.manifest["artifact_verification"],
            payload_inventory_sha256=self.manifest["artifact_verification"]["payload_inventory"]["sha256"],
            source_root=ROOT,
            allow_test_fixture=True,
        )

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

    @classmethod
    def rederive_sample(cls, report: dict, index: int) -> None:
        observation = report["recorder_observations"][index]
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
        report["samples"][index] = qualification.sample_from_recorder_observation(
            observation,
            f"fixture.observations[{index}]",
        )
        cls.rehash_samples(report)

    def test_complete_report_passes_every_threshold(self) -> None:
        self.validate_runtime()

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
        with self.assertRaisesRegex(qualification.QualificationError, "unhealthy"):
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

    def test_disabled_llm_is_not_a_release_qualification(self) -> None:
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
        }
        with self.assertRaisesRegex(
            qualification.QualificationError, "requires configured"
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
            qualification.QualificationError, "still in flight"
        ):
            self.validate_runtime(report)

    def test_candidate_byte_mutation_is_rejected(self) -> None:
        self.dmg.write_bytes(b"different bytes\n")
        with self.assertRaisesRegex(qualification.QualificationError, "exact DMG bytes"):
            self.validate_candidate()

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
        with self.assertRaisesRegex(qualification.QualificationError, "must be zero"):
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
            qualification.QualificationError, "produced no measured priority"
        ):
            self.validate_runtime(report)

    def test_priority_persistence_backlog_cannot_masquerade_as_delivery(self) -> None:
        report = copy.deepcopy(self.runtime)
        for index, observation in enumerate(report["recorder_observations"]):
            if 330 <= observation["offset_seconds"] <= 390:
                heartbeat = observation["heartbeat"]
                heartbeat["events_storage_write_offered_by_lane"]["priority"] = 40_300
                heartbeat["events_storage_write_persisted_by_lane"]["priority"] = 301
                heartbeat["events_storage_write_buffer_depth_by_lane"]["priority"] = 39_999
                self.rederive_sample(report, index)
        with self.assertRaisesRegex(
            qualification.QualificationError, "priority persistence did not drain"
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
            qualification.QualificationError, "priority event persistence shed"
        ):
            self.validate_runtime(report)

    def test_unavailable_trace_store_is_rejected(self) -> None:
        report = copy.deepcopy(self.runtime)
        report["recorder_observations"][12]["heartbeat"][
            "traces_storage_admission"
        ]["store_available"] = False
        self.rederive_sample(report, 12)
        with self.assertRaisesRegex(
            qualification.QualificationError, "not a full writable store"
        ):
            self.validate_runtime(report)

    def test_zero_trace_store_workload_is_rejected(self) -> None:
        report = copy.deepcopy(self.runtime)
        for index, observation in enumerate(report["recorder_observations"]):
            if 330 <= observation["offset_seconds"] <= 390:
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
        self.assertIn('ALERT_EXECUTABLE="$WORKLOAD_DIR/', workload)
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
        with self.assertRaisesRegex(qualification.QualificationError, "must remain zero"):
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
        with self.assertRaisesRegex(qualification.QualificationError, "does not reconcile"):
            self.validate_runtime(report)

    def test_memory_growth_above_64_mib_is_rejected(self) -> None:
        report = copy.deepcopy(self.runtime)
        report["recorder_observations"][-1]["process"][
            "engine_rss_bytes"
        ] = 300 * 1024 * 1024
        self.rederive_sample(report, -1)
        report["measurements"]["memory"]["engine_max_rss_bytes"] = 300 * 1024 * 1024
        report["measurements"]["memory"]["engine_rss_minute_15_bytes"] = 300 * 1024 * 1024
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
