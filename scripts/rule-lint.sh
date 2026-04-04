#!/bin/bash
#
# rule-lint.sh — Validate that all Sigma detection rules have adequate
# system process filters to prevent false positives.
#
# Checks:
#   1. Every rule has at least one filter block (filter_system, filter_apple,
#      filter_apple_signed, filter_signed, etc.)
#   2. Rules that detect process creation have path-based or signer-based filters
#   3. No rule has a condition that is ONLY a selection with no filter
#   4. Sequence rules have filters in at least one step
#
# Usage:
#   ./scripts/rule-lint.sh              # Lint all rules
#   ./scripts/rule-lint.sh --strict     # Fail on warnings too
#   ./scripts/rule-lint.sh --fix-hint   # Show suggested fixes
#
# Intended for CI: exits 0 if all rules pass, 1 if any fail.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
RULES_DIR="$PROJECT_DIR/Rules"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

ERRORS=0
WARNINGS=0
PASS=0
TOTAL=0
STRICT=false
FIX_HINT=false

for arg in "$@"; do
    case "$arg" in
        --strict) STRICT=true ;;
        --fix-hint) FIX_HINT=true ;;
    esac
done

error() { TOTAL=$((TOTAL+1)); ERRORS=$((ERRORS+1)); echo -e "  ${RED}✘ ERROR${NC} $*"; }
warning() { TOTAL=$((TOTAL+1)); WARNINGS=$((WARNINGS+1)); echo -e "  ${YELLOW}⚠ WARN${NC}  $*"; }
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }

echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════╗"
echo "║     MacCrab Rule Lint                            ║"
echo "║     Validates system process filter coverage     ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

# ─── Rule directories exempt from system filter requirements ──────────
# These rule categories are inherently targeted at specific malicious
# behaviors that Apple system processes would never exhibit, so requiring
# system filters would be noise.
EXEMPT_DIRS=(
    "ai_safety"            # Only fire when parent is an AI coding tool
    "supply_chain"         # Package manager / dependency attacks
    "command_and_control"  # Reverse shells, tunnels, C2 beacons
    "exfiltration"         # Data staging and upload
    "lateral_movement"     # SSH pivoting, remote execution
)

# ─── Acceptable filter names ──────────────────────────────────────────
# Any of these in the detection block means the rule has some filtering
FILTER_PATTERNS=(
    "filter_system"
    "filter_apple"
    "filter_apple_signed"
    "filter_signed"
    "filter_opendirectory"
    "filter_logrotate"
    "filter_known"
    "filter_apple_parent"
    "filter_parent"
    "SignerType:"
    "filter_"
)

# ─── Check each rule ─────────────────────────────────────────────────

check_rule() {
    local file="$1"
    local relpath="${file#$RULES_DIR/}"

    # Skip non-YAML
    [[ "$file" != *.yml ]] && return

    local content
    content=$(cat "$file")

    # Skip sequence rules (they use steps, not detection:)
    if echo "$content" | grep -q "^type: sequence"; then
        pass
        return
    fi

    # Check if this rule is in an exempt directory
    local rule_dir
    rule_dir=$(echo "$relpath" | cut -d'/' -f1)
    for exempt in "${EXEMPT_DIRS[@]}"; do
        if [ "$rule_dir" = "$exempt" ]; then
            pass
            return
        fi
    done

    # Extract the detection section
    local detection
    detection=$(echo "$content" | sed -n '/^detection:/,/^[a-z]/p' | head -50)

    # Extract the condition line
    local condition
    condition=$(echo "$content" | grep -E "^\s+condition:" | head -1 | sed 's/.*condition:\s*//')

    # Check 1: Does the rule have any filter block?
    local has_filter=false
    for pattern in "${FILTER_PATTERNS[@]}"; do
        if echo "$detection" | grep -q "$pattern"; then
            has_filter=true
            break
        fi
    done

    # Check 2: Does the condition reference a filter?
    local condition_has_filter=false
    if echo "$condition" | grep -qE "not\s+filter|and\s+not"; then
        condition_has_filter=true
    fi

    # Check 3: What category is this rule?
    local category
    category=$(echo "$content" | grep -E "^\s+category:" | head -1 | sed 's/.*category:\s*//')

    # Some rules are intentionally unfiltered because they detect behaviors
    # that are always suspicious regardless of the process (e.g., reverse shells,
    # SIP disable, gatekeeper override). These use specific command-line patterns
    # that Apple processes would never match.
    # We only ERROR on rules in high-FP categories that lack filters.
    if [ "$has_filter" = false ]; then
        case "$rule_dir" in
            credential_access)
                # Credential access rules without filters are high-risk for FPs
                error "$relpath — NO filter block (category: $category)"
                if [ "$FIX_HINT" = true ]; then
                    echo -e "    ${CYAN}Add to detection section:${NC}"
                    echo "        filter_system:"
                    echo "            ParentImage|startswith:"
                    echo "                - '/System/'"
                    echo "                - '/usr/libexec/'"
                    echo "                - '/usr/sbin/'"
                    echo "        filter_apple_signed:"
                    echo "            SignerType: 'apple'"
                    echo "        condition: selection and not filter_system and not filter_apple_signed"
                fi
                ;;
            persistence)
                # Persistence rules should filter system installers
                error "$relpath — NO filter block (category: $category)"
                ;;
            *)
                # Other categories — warning only (many are intentionally unfiltered)
                warning "$relpath — no filter block (category: $category)"
                ;;
        esac
        return
    fi

    # Check 4: Has filter defined but condition doesn't use it?
    if [ "$has_filter" = true ] && [ "$condition_has_filter" = false ]; then
        if ! echo "$condition" | grep -q "not"; then
            warning "$relpath — has filter block but condition doesn't exclude it: $condition"
            return
        fi
    fi

    # Check 5: For credential_access rules, verify system path filter
    if [ "$rule_dir" = "credential_access" ]; then
        if ! echo "$detection" | grep -qE "ParentImage\|startswith|Image\|startswith|SignerType:"; then
            warning "$relpath — credential_access rule lacks path/signer filter"
            return
        fi
    fi

    pass
}

# ─── Scan all rules ──────────────────────────────────────────────────

RULE_COUNT=0
for rule_file in $(find "$RULES_DIR" -name "*.yml" -not -path "*/sequences/*" | sort); do
    check_rule "$rule_file"
    RULE_COUNT=$((RULE_COUNT + 1))
done

# ─── Check sequence rules separately ─────────────────────────────────

echo ""
echo -e "${BOLD}Sequence rules:${NC}"
SEQ_COUNT=0
for seq_file in $(find "$RULES_DIR/sequences" -name "*.yml" 2>/dev/null | sort); do
    SEQ_COUNT=$((SEQ_COUNT + 1))
    local_name=$(basename "$seq_file")

    # Sequence rules should have at least one step with a filter
    content=$(cat "$seq_file")
    if echo "$content" | grep -qE "filter_|SignerType:"; then
        pass
    else
        warning "sequences/$local_name — no filter in any step"
    fi
done
echo -e "  ${BLUE}▸${NC} $SEQ_COUNT sequence rules checked"

# ─── Duplicate rule ID check ─────────────────────────────────────────

echo ""
echo -e "${BOLD}Duplicate ID check:${NC}"
DUPES=$(grep -rh "^id:" "$RULES_DIR" 2>/dev/null | sort | uniq -d)
if [ -n "$DUPES" ]; then
    DUPE_COUNT=$(echo "$DUPES" | wc -l | tr -d ' ')
    error "$DUPE_COUNT duplicate rule ID(s):"
    echo "$DUPES" | sed 's/^/    /'
else
    pass
    echo -e "  ${GREEN}✔${NC} No duplicate rule IDs"
fi

# ─── Required fields check ───────────────────────────────────────────

echo ""
echo -e "${BOLD}Required fields check:${NC}"
MISSING_FIELDS=0
for rule_file in $(find "$RULES_DIR" -name "*.yml" | sort); do
    relpath="${rule_file#$RULES_DIR/}"
    content=$(cat "$rule_file")

    # Sequence rules use steps: instead of detection:
    is_sequence=false
    if echo "$content" | grep -q "^type: sequence"; then
        is_sequence=true
    fi

    for field in "title:" "id:" "level:"; do
        if ! echo "$content" | grep -q "^${field}"; then
            error "$relpath — missing required field: $field"
            MISSING_FIELDS=$((MISSING_FIELDS + 1))
        fi
    done

    if [ "$is_sequence" = true ]; then
        if ! echo "$content" | grep -q "^steps:"; then
            error "$relpath — sequence rule missing required field: steps:"
            MISSING_FIELDS=$((MISSING_FIELDS + 1))
        fi
    else
        if ! echo "$content" | grep -q "^detection:"; then
            error "$relpath — missing required field: detection:"
            MISSING_FIELDS=$((MISSING_FIELDS + 1))
        fi
    fi
done

if [ "$MISSING_FIELDS" -eq 0 ]; then
    pass
    echo -e "  ${GREEN}✔${NC} All rules have required fields (title, id, detection, level)"
fi

# ─── Summary ──────────────────────────────────────────────────────────

echo ""
echo "════════════════════════════════════════════════════"
echo -e "  Rules scanned:  $RULE_COUNT single + $SEQ_COUNT sequence"
echo -e "  ${GREEN}Passed:${NC}   $PASS"
echo -e "  ${RED}Errors:${NC}   $ERRORS"
echo -e "  ${YELLOW}Warnings:${NC} $WARNINGS"
echo "════════════════════════════════════════════════════"

if [ "$ERRORS" -gt 0 ]; then
    echo -e "\n${RED}FAILED — $ERRORS rule(s) have critical filter issues.${NC}"
    if [ "$FIX_HINT" = false ]; then
        echo "Run with --fix-hint for suggested fixes."
    fi
    exit 1
elif [ "$STRICT" = true ] && [ "$WARNINGS" -gt 0 ]; then
    echo -e "\n${YELLOW}FAILED (strict mode) — $WARNINGS warning(s).${NC}"
    exit 1
else
    echo -e "\n${GREEN}PASSED — all rules have adequate filter coverage.${NC}"
    exit 0
fi
