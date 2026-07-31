#!/bin/bash
# ci-local.sh — Run all CI checks locally (replaces GitHub Actions)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

# --clean: wipe the build tree and re-resolve before running.
#
# Local CI runs on the machine that already has the toolchain, a warm .build and
# resolved dependencies — so it cannot see environment drift the way a hosted
# runner on a fresh image could. That difference is exactly the "green locally,
# red in CI" class this project has been bitten by before (a poisoned /tmp cache,
# Xcode integer-literal arithmetic inside #expect, `runner` colliding with a
# sanitizer reserved word). The pre-push hook passes --clean automatically on a
# TAG push, so every release is gated on a from-scratch build.
CLEAN_TREE=0
for arg in "$@"; do
    case "$arg" in
        --clean) CLEAN_TREE=1 ;;
        -h|--help)
            echo "usage: ci-local.sh [--clean]"
            echo "  --clean   remove .build and re-resolve first (slower; used for releases)"
            exit 0 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

if [ "$CLEAN_TREE" = "1" ]; then
    echo "Clean run: removing .build and re-resolving dependencies…"
    rm -rf .build
    swift package resolve
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

PASS=0
FAIL=0
START=$(date +%s)

check() {
    local name="$1"
    shift
    printf "  %-40s " "$name"
    if "$@" > /tmp/ci_local_output.txt 2>&1; then
        echo -e "${GREEN}PASS${NC}"
        PASS=$((PASS + 1))
    else
        echo -e "${RED}FAIL${NC}"
        tail -5 /tmp/ci_local_output.txt | sed 's/^/    /'
        FAIL=$((FAIL + 1))
    fi
}

echo ""
echo -e "${BOLD}MacCrab Local CI${NC}"
echo "════════════════════════════════════════"
echo ""

echo -e "${BOLD}Build${NC}"
check "Swift build (debug)" swift build
check "Swift build tests" swift build --build-tests

echo ""
echo -e "${BOLD}Tests${NC}"
check "Swift test suite" swift test

echo ""
echo -e "${BOLD}Rules${NC}"
# The compiler EXITS 0 even when it SKIPS a malformed rule, so a rule can drop
# out of the shipped corpus silently. The deleted ci.yml asserted
# `Rules skipped: 0`; nothing did after CI moved local — assert it here.
check "Compile rules (YAML → JSON)" bash -c 'out=$(python3 Compiler/compile_rules.py --input-dir Rules/ --output-dir /tmp/ci_compiled_rules) || exit 1; echo "$out"; echo "$out" | grep -qE "Rules skipped:[[:space:]]+0[[:space:]]*$"'
# make check-counts — headline rule-count drift across README / MODULES /
# ModuleStatus. Automated nowhere before this line.
check "Rule counts consistent (README/MODULES)" python3 scripts/coverage_matrix.py --check Rules
check "Rule lint (filter coverage)" ./scripts/rule-lint.sh

echo ""
echo -e "${BOLD}Required gates (mirrors .github/workflows/ci.yml)${NC}"
# These are REQUIRED jobs on GitHub. Under the private-remote dev branch they
# do not run there (macOS minutes bill 10x against a private repo's allowance),
# so this script is the gate. Keep the invocations byte-identical to ci.yml.
check "Broker fd fuzz (ASan/UBSan)" ./scripts/test-broker-fuzz.sh
check "Architectural audit (deterministic)" \
    env MACCRAB_AUDIT_SCOPE=deterministic ./scripts/pre-release-audit.sh

# Publication gate. `main` is public and dev squash-merges into it, so
# anything on dev is on a path to publication. Scans ADDED lines only —
# the repo legitimately contains ~100 credential-shaped strings (honeyfile
# canaries, sanitizer test fixtures) and a whole-tree scan reports all of
# them every run until someone switches it off.
check "No secrets or host paths in the diff" ./scripts/check-secrets.sh

echo ""
echo -e "${BOLD}Assessment harness (non-shipping sub-package)${NC}"
# Tools/AssessmentHarness is deliberately invisible to the root package, so
# `swift build` and `swift test` above never touch it. Before this block it was
# referenced by nothing in .github/workflows, this script, or the Makefile —
# the component that grades the detection engine was itself ungated, and could
# have stopped compiling without anyone noticing.
check "Harness builds" swift build --package-path Tools/AssessmentHarness
check "Harness tests" swift test --package-path Tools/AssessmentHarness
check "Harness stays out of the shipped build" ./Tools/AssessmentHarness/scripts/check-harness-isolation.sh

echo ""
echo -e "${BOLD}Code Quality${NC}"
check "No force unwraps in Sources" bash -c '! grep -rn "\.first!" Sources/ --include="*.swift" | grep -v ".build/" | grep -v "// OK:"'
check "No TODO/FIXME in Sources" bash -c 'count=$(grep -rn "TODO\|FIXME" Sources/ --include="*.swift" | grep -v ".build/" | wc -l); [ "$count" -lt 10 ]'

END=$(date +%s)
DURATION=$((END - START))

echo ""
echo "════════════════════════════════════════"
echo -e "  ${GREEN}Passed:${NC} $PASS"
echo -e "  ${RED}Failed:${NC} $FAIL"
echo -e "  Time:   ${DURATION}s"
echo "════════════════════════════════════════"

if [ "$FAIL" -gt 0 ]; then
    echo -e "\n${RED}CI FAILED${NC}"
    exit 1
else
    echo -e "\n${GREEN}ALL CHECKS PASSED${NC}"
fi
