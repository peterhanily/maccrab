#!/bin/bash
# publish-rules.sh
#
# Build a signed, tamper-evident MacCrab rule bundle for distribution.
# Operators fetch the bundle + signature; MacCrab verifies before loading.
#
# Requirements:
#   - cosign installed (brew install cosign)
#   - GitHub OIDC token in CI, OR a keyed cosign key locally
#
# Usage (CI, keyless via GitHub OIDC):
#   ./scripts/publish-rules.sh
#
# Usage (local, with a cosign key):
#   COSIGN_KEY=./cosign.key ./scripts/publish-rules.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${MACCRAB_RULES_VERSION:-$(date +%Y.%m.%d)}"
BUNDLE="maccrab-rules-${VERSION}.tar.gz"
DIST_DIR="${ROOT}/dist"

mkdir -p "${DIST_DIR}"

echo ">>> Compiling rules ${VERSION} to dist/"
python3 "${ROOT}/Compiler/compile_rules.py" \
    --input-dir "${ROOT}/Rules" \
    --output-dir "${DIST_DIR}/compiled_rules"

echo ">>> Packaging rule bundle"
tar -czf "${DIST_DIR}/${BUNDLE}" \
    -C "${DIST_DIR}" \
    compiled_rules

echo ">>> Bundle summary"
ls -la "${DIST_DIR}/${BUNDLE}"
echo "SHA-256:"
shasum -a 256 "${DIST_DIR}/${BUNDLE}"

if ! command -v cosign >/dev/null 2>&1; then
    echo ">>> cosign not installed — bundle built but NOT signed"
    echo "    brew install cosign, then re-run to produce a signature"
    exit 0
fi

echo ">>> Signing with cosign"
if [ "${CI:-}" = "true" ]; then
    # Keyless — GitHub Actions OIDC → Fulcio certificate → Rekor log.
    cosign sign-blob \
        --yes \
        --output-signature "${DIST_DIR}/${BUNDLE}.sig" \
        --output-certificate "${DIST_DIR}/${BUNDLE}.pem" \
        "${DIST_DIR}/${BUNDLE}"
else
    # Local — requires COSIGN_KEY env set to a key path.
    : "${COSIGN_KEY:?Set COSIGN_KEY to the path of your cosign.key}"
    cosign sign-blob \
        --yes \
        --key "${COSIGN_KEY}" \
        --output-signature "${DIST_DIR}/${BUNDLE}.sig" \
        "${DIST_DIR}/${BUNDLE}"
fi

echo ">>> Done. Artifacts in ${DIST_DIR}:"
ls -la "${DIST_DIR}/${BUNDLE}"*

echo ""
echo "Verify with:"
echo "  cosign verify-blob \\"
echo "    --signature ${BUNDLE}.sig \\"
if [ "${CI:-}" = "true" ]; then
    echo "    --certificate ${BUNDLE}.pem \\"
    echo "    --certificate-identity-regexp 'peterhanily' \\"
    echo "    --certificate-oidc-issuer-regexp 'github.com' \\"
fi
echo "    ${BUNDLE}"
