.PHONY: build test compile-rules install uninstall clean run

PREFIX ?= /usr/local
SUPPORT_DIR = /Library/Application\ Support/HawkEye

# Build debug binaries
build:
	swift build

# Build release binaries
release:
	swift build -c release

# Run tests
test:
	./scripts/test.sh

# Compile detection rules to build directory (for development)
compile-rules:
	python3 Compiler/compile_rules.py \
		--input-dir Rules/ \
		--output-dir .build/debug/compiled_rules

# Run daemon locally (non-root, for development)
run: build compile-rules
	.build/debug/hawkeyed

# Run daemon with root (full ES support)
run-root: build compile-rules
	sudo .build/debug/hawkeyed

# Install system-wide (requires sudo)
install: release
	sudo ./scripts/install.sh

# Uninstall (requires sudo)
uninstall:
	sudo ./scripts/uninstall.sh

# Clean build artifacts
clean:
	swift package clean
	rm -rf .build/debug/compiled_rules
