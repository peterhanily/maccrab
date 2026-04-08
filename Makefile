.PHONY: build test compile-rules install uninstall clean run dev restart app stop status test-detection test-campaign

PREFIX ?= /usr/local
SUPPORT_DIR = /Library/Application\ Support/MacCrab
BUILD_DIR = .build/debug
RULES_DIR = $(BUILD_DIR)/compiled_rules

# ─── Quick development cycle ─────────────────────────────────────────

# One command: build + codesign + compile rules + restart daemon
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
	@swift build 2>&1 | tail -1

release:
	@swift build -c release 2>&1 | tail -1

compile-rules:
	@python3 Compiler/compile_rules.py \
		--input-dir Rules/ \
		--output-dir $(RULES_DIR) 2>&1 | tail -1
	@mkdir -p "$(HOME)/Library/Application Support/MacCrab/compiled_rules/sequences"
	@cp -f $(RULES_DIR)/*.json "$(HOME)/Library/Application Support/MacCrab/compiled_rules/" 2>/dev/null || true
	@cp -f $(RULES_DIR)/sequences/*.json "$(HOME)/Library/Application Support/MacCrab/compiled_rules/sequences/" 2>/dev/null || true

# ─── Test ─────────────────────────────────────────────────────────────

test:
	@swift test 2>&1 | grep -E "✔|✘|Test run"

test-full:
	./scripts/test.sh

test-fp:
	./scripts/false-positive-test.sh

test-integration:
	./scripts/integration-test.sh

lint-rules:
	./scripts/rule-lint.sh

test-stress:
	./scripts/stress-test.sh 60

# ─── Install (system-wide, requires sudo) ─────────────────────────────

install: release
	sudo ./scripts/install.sh

uninstall:
	sudo ./scripts/uninstall.sh

# ─── Utilities ────────────────────────────────────────────────────────

# Clear all data (events, alerts) — uses sudo for system DB
clear-data: stop
	@rm -rf "$(HOME)/Library/Application Support/MacCrab/events.db"* 2>/dev/null || true
	@rm -rf "$(HOME)/Library/Application Support/MacCrab/alerts.jsonl" 2>/dev/null || true
	@sudo rm -rf "/Library/Application Support/MacCrab/events.db"* 2>/dev/null || true
	@sudo rm -rf "/Library/Application Support/MacCrab/alerts.jsonl" 2>/dev/null || true
	@echo "All data cleared"

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
	@echo "  make clear-data   Delete local events/alerts"
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
