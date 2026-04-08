#!/bin/bash
# ci-local.sh — Run all CI checks locally (replaces GitHub Actions)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

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
check "Compile rules (YAML → JSON)" python3 Compiler/compile_rules.py --input-dir Rules/ --output-dir /tmp/ci_compiled_rules
check "Rule lint (filter coverage)" ./scripts/rule-lint.sh

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
