.PHONY: build test test-corpus compile-rules install uninstall clean run dev restart app stop status test-detection test-campaign dmg breakdown check-counts benchmark-fp

PREFIX ?= /usr/local
SUPPORT_DIR = /Library/Application\ Support/MacCrab
BUILD_DIR = .build/debug
RULES_DIR = $(BUILD_DIR)/compiled_rules

# ─── Quick development cycle ─────────────────────────────────────────

# One command: build + codesign + compile rules + restart daemon
# Activate the version-controlled git hooks (.githooks/pre-push runs local CI).
# Required once per clone: git does not track .git/hooks/, so a fresh checkout
# has NO push gate until this runs. MacCrab's CI is local — see docs/CI-ARCHITECTURE.md.
hooks:
	@git config core.hooksPath .githooks
	@chmod +x .githooks/*
	@echo "git hooks activated (core.hooksPath=.githooks) — pre-push runs scripts/ci-local.sh"

# Run the full local CI gate. `make ci-clean` wipes .build first (release gate).
ci:
	@./scripts/ci-local.sh

ci-clean:
	@./scripts/ci-local.sh --clean

dev:
	@./scripts/dev.sh

# Dev without sudo (no ES, limited sources)
dev-no-es:
	@./scripts/dev.sh --no-es

# Build + sign only (no start)
dev-build:
	@./scripts/dev.sh --build

# Restart daemon only (no rebuild)
restart: stop
	@$(BUILD_DIR)/maccrabd &
	@sleep 2
	@$(BUILD_DIR)/maccrabctl status

# Create .app bundle from bare executable
bundle-app:
	@./scripts/bundle-app.sh

# Open the GUI app
app: bundle-app
	@open $(BUILD_DIR)/MacCrab.app 2>/dev/null

# Stop daemon and app
stop:
	@pkill -x maccrabd 2>/dev/null || true
	@pkill -x MacCrabApp 2>/dev/null || true
	@sleep 1

# Show status
status:
	@$(BUILD_DIR)/maccrabctl status

# Live alert stream
watch:
	@$(BUILD_DIR)/maccrabctl watch

# ─── Build ────────────────────────────────────────────────────────────

build:
	@# pipefail: the recipe's status is otherwise `tail`'s, which is always 0 —
	@# a compile failure exited green, and `dmg: release` / `install: release`
	@# happily proceeded to package a build that never linked.
	@set -o pipefail; swift build 2>&1 | tail -1

release:
	@set -o pipefail; swift build -c release 2>&1 | tail -1

compile-rules:
	@python3 Compiler/compile_rules.py \
		--input-dir Rules/ \
		--output-dir $(RULES_DIR)
	@# v1.11.1: compile any YAML graph rules to their JSON siblings
	@# under Rules/graph/. JSON is canonical; YAML is convenience.
	@python3 Compiler/compile_graph_rules.py \
		--input-dir Rules/graph --output-dir Rules/graph
	@mkdir -p "$(HOME)/Library/Application Support/MacCrab/compiled_rules/sequences"
	@cp -f $(RULES_DIR)/*.json "$(HOME)/Library/Application Support/MacCrab/compiled_rules/" 2>/dev/null || true
	@cp -f $(RULES_DIR)/sequences/*.json "$(HOME)/Library/Application Support/MacCrab/compiled_rules/sequences/" 2>/dev/null || true

# ─── Test ─────────────────────────────────────────────────────────────

test:
	@# pipefail: without it the recipe's status is grep's, and grep MATCHES the
	@# ✘ lines a failing run emits — so `make test` exited 0 on a red suite.
	@set -o pipefail; swift test 2>&1 | grep -E "✔|✘|Test run"

test-full:
	./scripts/test.sh

test-fp:
	./scripts/false-positive-test.sh

# Measure per-rule false-positive RATE over a window of accumulated alerts on a
# benign machine. Run MacCrab normally (detection-only) for the window, then this.
# See BENCHMARK.md for methodology + docs/CONTRIBUTING_FP_DATA.md to contribute.
benchmark-fp:
	./scripts/fp-rate-benchmark.sh --days 28

test-integration:
	./scripts/integration-test.sh

# Containment corpus — the on-device proof that the sandboxed third-party Tier-B
# lane actually CONTAINS (undeclared read / network / fork / metadata-stat /
# undeclared mach-lookup are OS-denied; a declared read is brokered over fd 3).
# Gated behind MACCRAB_CORPUS so plain `make test` stays host-agnostic; this
# runs the real spawn under sandbox_init on a physical macOS host. MANDATORY
# pre-release gate for ANY change under Sources/MacCrabForensics/
# TierB or the trampoline/broker C targets — record the run in the release
# checklist. (audit #2: the only containment proof must not run nowhere.)
# candidate-qualification.py mounts the exact DMG read-only and drives the
# candidate's shipped maccrabctl + runner/broker + signed trampoline against the
# shipped example and fresh-private-build C/Swift deny probes, including a
# reachable-loopback/throwaway-file unsandboxed positive control. It records the
# exact candidate binary identities, transcripts, source commit/tree, host, interval,
# and a canonical containment-source digest. release.sh independently recomputes
# those bindings at its non-bypassable publication gate.
test-corpus:
	@set -o pipefail; \
	ver="$${VERSION:-$$(grep -E '^[[:space:]]*public static let fallback:' Sources/MacCrabCore/MacCrabVersion.swift | head -1 | sed -E 's/.*"([^"]+)".*/\1/')}"; \
	candidate=".qualification-evidence/MacCrab-v$$ver.candidate.json"; \
	dmg=".build/MacCrab-v$$ver.dmg"; \
	if [ ! -f "$$candidate" ] || [ -L "$$candidate" ] || [ ! -s "$$candidate" ] \
			|| [ ! -f "$$dmg" ] || [ -L "$$dmg" ] || [ ! -s "$$dmg" ]; then \
		echo "✗ build the preserved release.sh candidate before recording containment"; \
		echo "  expected $$candidate and $$dmg"; \
		exit 2; \
	fi; \
	out=".qualification-evidence/MacCrab-v$$ver.containment.json"; \
	python3 -I scripts/candidate-qualification.py record-containment \
		--version "$$ver" \
		--source-root . \
		--candidate-manifest "$$candidate" \
		--dmg "$$dmg" \
		--output "$$out"

# Also see scripts/check-promotion.sh <rule-id|--all> — advisory checker for
# the experimental→stable promotion bar (CONTRIBUTING.md "Rule Promotion Criteria").
lint-rules:
	./scripts/rule-lint.sh

# Single source of truth for headline rule counts. Fails if README / MODULES /
# ModuleStatus drift from the canonical total derived from the rules tree.
check-counts:
	python3 scripts/coverage_matrix.py --check Rules

test-stress:
	./scripts/stress-test.sh 60

# v1.21.5: burst load benchmark — storms the engine with process spawns +
# /tmp file writes, then diffs the daemon's own drop gauges. Fails if the
# PRIORITY event stream (exec/network/tcc) dropped anything.
test-burst:
	./scripts/burst-bench.sh

# Diagnostic — print event volume + composition from the running sysext's
# events.db. Used to validate that EventInsertFilter is dropping what we
# think it's dropping. Reads only; safe to run while the daemon is alive.
breakdown:
	@sudo ./scripts/event-breakdown.sh

# v1.8.1: regenerate docs/COVERAGE.md from the rule corpus. Run on every
# rule add/remove/status change. Output is checked-in (so a casual repo
# browser can read it on github.com without running anything), but it's
# generated — don't hand-edit.
coverage-doc:
	@python3 scripts/generate-coverage-doc.py > docs/COVERAGE.md
	@echo "✓ docs/COVERAGE.md regenerated ($$(wc -l < docs/COVERAGE.md | tr -d ' ') lines)"

# v1.10.1: regenerate the rule-count table inside README.md between
# <!-- COVERAGE-START --> / <!-- COVERAGE-END --> markers. The release
# script runs this before tagging so README never ships stale numbers.
# Run by hand when you add/remove rules outside a release cycle.
readme-coverage:
	@python3 scripts/coverage_matrix.py --update-readme README.md Rules/

# ─── Install (system-wide, requires sudo) ─────────────────────────────

install: release
	sudo ./scripts/install.sh

uninstall:
	sudo ./scripts/uninstall.sh

# NOTE: the 'pkg' target was removed — scripts/build-pkg.sh no longer
# exists. Use 'make dmg' for a release artifact.

# Create .dmg release (for GitHub releases)
dmg: release
	./scripts/build-release.sh

# ─── Utilities ────────────────────────────────────────────────────────

# Clear all data (events, alerts) — uses sudo for system DB
# Only events.db + alerts.jsonl were removed here, so alerts.db, campaigns.db,
# tracegraph.db and traces.db survived a "clear" — the alert store and the
# causal-graph store are the two richest records of activity, and both stayed
# on disk while `make help` / README claimed the data was gone. Cover every
# store (the `*` picks up the -wal / -shm sidecars).
clear-data: stop
	@rm -rf "$(HOME)/Library/Application Support/MacCrab/events.db"* 2>/dev/null || true
	@rm -rf "$(HOME)/Library/Application Support/MacCrab/alerts.db"* 2>/dev/null || true
	@rm -rf "$(HOME)/Library/Application Support/MacCrab/campaigns.db"* 2>/dev/null || true
	@rm -rf "$(HOME)/Library/Application Support/MacCrab/tracegraph.db"* 2>/dev/null || true
	@rm -rf "$(HOME)/Library/Application Support/MacCrab/traces.db"* 2>/dev/null || true
	@rm -rf "$(HOME)/Library/Application Support/MacCrab/alerts.jsonl" 2>/dev/null || true
	@sudo rm -rf "/Library/Application Support/MacCrab/events.db"* 2>/dev/null || true
	@sudo rm -rf "/Library/Application Support/MacCrab/alerts.db"* 2>/dev/null || true
	@sudo rm -rf "/Library/Application Support/MacCrab/campaigns.db"* 2>/dev/null || true
	@sudo rm -rf "/Library/Application Support/MacCrab/tracegraph.db"* 2>/dev/null || true
	@sudo rm -rf "/Library/Application Support/MacCrab/traces.db"* 2>/dev/null || true
	@sudo rm -rf "/Library/Application Support/MacCrab/alerts.jsonl" 2>/dev/null || true
	@echo "All data cleared (events, alerts, campaigns, tracegraph, traces)"

# Run daemon as root (full ES support) — needs Terminal for password
run-root: build compile-rules
	sudo $(BUILD_DIR)/maccrabd

# Create a new rule from template
new-rule:
	@echo "Categories: process_creation, file_event, network_connection, tcc_event, sequence"
	@read -p "Category: " cat; $(BUILD_DIR)/maccrabctl rule create $$cat

clean:
	swift package clean
	rm -rf $(RULES_DIR)

help:
	@echo "MacCrab Development Commands:"
	@echo ""
	@echo "  make dev          Build + restart daemon + open app (one command)"
	@echo "  make restart      Restart daemon (no rebuild)"
	@echo "  make stop         Stop daemon and app"
	@echo "  make status       Show daemon status"
	@echo "  make watch        Live stream alerts"
	@echo "  make app          Open the GUI dashboard"
	@echo ""
	@echo "  make build        Build debug binaries"
	@echo "  make test         Run tests (summary only)"
	@echo "  make test-full    Run full test suite"
	@echo "  make compile-rules Compile YAML rules to JSON"
	@echo "  make clear-data   Delete all local data (events/alerts/campaigns/traces)"
	@echo "  make new-rule     Create rule from template"
	@echo ""
	@echo "  make install      Install system-wide (sudo)"
	@echo "  make uninstall    Remove system install (sudo)"
	@echo "  make run-root     Run with Endpoint Security (sudo)"

# Run detection test suite (triggers all detection categories safely)
test-detection:
	./scripts/detection-test.sh

# Run multi-tactic campaign simulation (exercises Campaigns panel)
# Use 'make test-campaign SUSTAINED=1' for a slower 12-minute simulation
test-campaign:
	./scripts/campaign-test.sh $(if $(SUSTAINED),--sustained,)
