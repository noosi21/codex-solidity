#!/bin/bash
# Static Analysis Script for Smart Contract Audits
# Integrates with Slither, Aderyn, and custom Codex patterns

set -e

TARGET="${1:-.}"
OUTPUT_DIR="${2:-./audit-reports/static}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$OUTPUT_DIR"

echo "[*] Codex Solidity — Static Analysis Scan"
echo "[*] Target: $TARGET"
echo "[*] Output: $OUTPUT_DIR"
echo ""

# Check for available tools
has_slither=false
has_aderyn=false
has_solc=false

command -v slither &> /dev/null && has_slither=true
command -v aderyn &> /dev/null && has_aderyn=true
command -v solc &> /dev/null && has_solc=true

# Step 1: Compile check
echo "[1/5] Checking compilation..."
if [ "$has_solc" = true ]; then
    for f in $(find "$TARGET" -name "*.sol" 2>/dev/null); do
        solc --bin "$f" > /dev/null 2>&1 && echo "  [OK] $f compiles" || echo "  [FAIL] $f does NOT compile"
    done
else
    echo "  [SKIP] solc not installed — skipping compilation check"
fi
echo ""

# Step 2: Slither analysis
echo "[2/5] Running Slither..."
if [ "$has_slither" = true ]; then
    slither "$TARGET" --json "$OUTPUT_DIR/slither_${TIMESTAMP}.json" 2>/dev/null || true
    slither "$TARGET" --print human-summary 2>/dev/null > "$OUTPUT_DIR/slither_summary_${TIMESTAMP}.txt" || true
    echo "  [OK] Slither output saved"
else
    echo "  [SKIP] Slither not installed — install with: pip3 install slither-analyzer"
    echo "  [ALT] Using Codex built-in pattern detection instead"
    node "$(dirname "$0")/../../bin/codex-sol.js" audit -t "$TARGET" -s unchecked-returns,shadowing,pragma-bugs -o "$OUTPUT_DIR" 2>/dev/null || true
fi
echo ""

# Step 3: Aderyn analysis
echo "[3/5] Running Aderyn..."
if [ "$has_aderyn" = true ]; then
    aderyn "$TARGET" --output "$OUTPUT_DIR/aderyn_${TIMESTAMP}.json" 2>/dev/null || true
    echo "  [OK] Aderyn output saved"
else
    echo "  [SKIP] Aderyn not installed — install with: cargo install aderyn"
fi
echo ""

# Step 4: Custom Codex pattern scan
echo "[4/5] Running Codex deep pattern scan..."
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CODEX_BIN="$SCRIPT_DIR/../../bin/codex-sol.js"
if [ -f "$CODEX_BIN" ]; then
    node "$CODEX_BIN" audit -t "$TARGET" -o "$OUTPUT_DIR" 2>/dev/null || true
    echo "  [OK] Codex scan complete"
else
    echo "  [FAIL] Codex CLI not found at $CODEX_BIN"
fi
echo ""

# Step 5: Summary
echo "[5/5] Generating summary..."
SUMMARY_FILE="$OUTPUT_DIR/summary_${TIMESTAMP}.txt"
echo "Static Analysis Summary — $(date)" > "$SUMMARY_FILE"
echo "Target: $TARGET" >> "$SUMMARY_FILE"
echo "---" >> "$SUMMARY_FILE"
find "$OUTPUT_DIR" -name "*.json" -newer "$SUMMARY_FILE" -o -name "*.json" | head -5 >> "$SUMMARY_FILE" 2>/dev/null || true
echo "" >> "$SUMMARY_FILE"
echo "Tools used:" >> "$SUMMARY_FILE"
echo "  Slither: $has_slither" >> "$SUMMARY_FILE"
echo "  Aderyn: $has_aderyn" >> "$SUMMARY_FILE"
echo "  Codex:  always" >> "$SUMMARY_FILE"
echo "" >> "$SUMMARY_FILE"
echo "Review full findings in: $OUTPUT_DIR/" >> "$SUMMARY_FILE"

cat "$SUMMARY_FILE"
echo ""
echo "[*] Static analysis complete. Results in $OUTPUT_DIR/"
