#!/bin/bash
# scripts/test_cic_capture.sh
# Phase 1 acceptance test for CICFlowMeter live capture.
#
# This script:
#   1. Verifies cicflowmeter is installed
#   2. Runs a short capture (configurable, default 30s)
#   3. Generates test traffic during capture
#   4. Stops capture
#   5. Validates the output CSV
#
# Usage:
#   sudo ./scripts/test_cic_capture.sh              # eth0, 30s
#   sudo ./scripts/test_cic_capture.sh lo 15         # loopback, 15s
#   sudo ./scripts/test_cic_capture.sh eth0 60       # eth0, 60s

set -euo pipefail

INTERFACE="${1:-eth0}"
DURATION="${2:-30}"

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BASE_DIR="$(dirname "$DIR")"
OUTDIR="$BASE_DIR/data/cic/flows"
OUTFILE="$OUTDIR/test_capture_$(date -u +%Y%m%d_%H%M%S).csv"

# Resolve venv Python and our CIC wrapper script.
# The wrapper works around a positional-argument bug in cicflowmeter
# 0.5.0's main() — see src/collector/cic_wrapper.py for details.
VENV_PYTHON="$BASE_DIR/.venv/bin/python"
if [ ! -x "$VENV_PYTHON" ]; then
    VENV_PYTHON="$BASE_DIR/.venv/bin/python3"
fi
CIC_WRAPPER="$BASE_DIR/src/collector/cic_wrapper.py"

PASS=0
FAIL=0
pass() { echo "  ✓ PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  ✗ FAIL: $1"; FAIL=$((FAIL + 1)); }

echo "============================================"
echo " CICFlowMeter Acceptance Test"
echo "============================================"
echo " Python:     $VENV_PYTHON"
echo " Wrapper:    $CIC_WRAPPER"
echo " Interface:  $INTERFACE"
echo " Duration:   ${DURATION}s"
echo " Output:     $OUTFILE"
echo "============================================"
echo ""

# ------------------------------------------------------------------
# Step 1: Verify cicflowmeter wrapper is available
# ------------------------------------------------------------------
echo "[Step 1] Checking cicflowmeter installation..."
if [ -x "$VENV_PYTHON" ] && [ -f "$CIC_WRAPPER" ]; then
    # Also verify the cicflowmeter package is importable
    if "$VENV_PYTHON" -c "import cicflowmeter" 2>/dev/null; then
        pass "cicflowmeter installed, wrapper at $CIC_WRAPPER"
    else
        fail "cicflowmeter package not importable"
        echo "  Install with: $BASE_DIR/.venv/bin/pip install cicflowmeter"
        echo "  Aborting."
        exit 1
    fi
else
    fail "venv or wrapper not found"
    echo "  Venv Python: $VENV_PYTHON (exists: $([ -x "$VENV_PYTHON" ] && echo yes || echo no))"
    echo "  Wrapper: $CIC_WRAPPER (exists: $([ -f "$CIC_WRAPPER" ] && echo yes || echo no))"
    echo "  Aborting."
    exit 1
fi

# ------------------------------------------------------------------
# Step 2: Check interface exists
# ------------------------------------------------------------------
echo "[Step 2] Checking interface $INTERFACE..."
if ip link show "$INTERFACE" &> /dev/null; then
    pass "Interface $INTERFACE exists"
else
    fail "Interface $INTERFACE not found"
    echo "  Available interfaces:"
    ip -brief link show 2>/dev/null || ip link show
    echo "  Aborting."
    exit 1
fi

OUTLOG="$OUTDIR/test_capture_$(date -u +%Y%m%d_%H%M%S).log"

# ------------------------------------------------------------------
# Cleanup and Validation Logic (runs on normal exit OR Ctrl+C)
# ------------------------------------------------------------------
finish_and_validate() {
    # Remove the trap so we don't double-trigger on subsequent signals
    trap - SIGINT SIGTERM

    echo ""
    echo "[Step 5] Stopping capture..."
    if [ -n "${CIC_PID:-}" ] && kill -0 "$CIC_PID" 2>/dev/null; then
        echo "  Sending SIGINT to CICFlowMeter (PID $CIC_PID)..."
        kill -INT "$CIC_PID" 2>/dev/null || true
        echo "  Waiting for flows to flush (this may take up to 10 seconds)..."
        for i in {1..10}; do
            if ! kill -0 "$CIC_PID" 2>/dev/null; then
                break
            fi
            sleep 1
        done
        
        if kill -0 "$CIC_PID" 2>/dev/null; then
            echo "  Process did not exit gracefully. Forcing termination..."
            kill -9 "$CIC_PID" 2>/dev/null || true
        fi
    fi

    echo ""
    echo "[Step 6] Validating output CSV..."
    echo ""

    if [ ! -f "$OUTFILE" ]; then
        fail "Output file does not exist: $OUTFILE"
        echo "=== Process Log ($OUTLOG) ==="
        cat "$OUTLOG" 2>/dev/null || echo "(No log found)"
        exit 1
    fi

    FILE_SIZE=$(stat -c%s "$OUTFILE" 2>/dev/null || echo "0")
    LINE_COUNT=$(wc -l < "$OUTFILE" 2>/dev/null || echo "0")

    echo "  File: $OUTFILE"
    echo "  Size: $FILE_SIZE bytes"
    echo "  Lines: $LINE_COUNT"
    echo ""

    if [ "$FILE_SIZE" -gt 0 ]; then
        pass "File has content ($FILE_SIZE bytes)"
    else
        fail "File is empty (0 bytes)"
        echo "=== Process Log ($OUTLOG) ==="
        cat "$OUTLOG" 2>/dev/null || echo "(No log found)"
        exit 1
    fi

    if [ "$LINE_COUNT" -ge 2 ]; then
        pass "File has data rows ($((LINE_COUNT - 1)) flows)"
    else
        fail "File has fewer than 2 lines (expected header + data)"
        echo "=== Process Log ($OUTLOG) ==="
        cat "$OUTLOG" 2>/dev/null || echo "(No log found)"
        exit 1
    fi

    HEADER=$(head -1 "$OUTFILE")
    check_column() {
        if echo "$HEADER" | grep -qi "$1"; then
            pass "Column found: $1"
        else
            fail "Column missing: $1"
        fi
    }

    echo "  Checking essential columns..."
    check_column "src_ip"
    check_column "dst_ip"
    check_column "src_port"
    check_column "dst_port"
    check_column "protocol"

    NUM_COLS=$(head -1 "$OUTFILE" | awk -F',' '{print NF}')
    echo ""
    echo "  Total columns in output: $NUM_COLS"
    if [ "$NUM_COLS" -ge 70 ]; then
        pass "Has $NUM_COLS columns (expected 70+)"
    else
        fail "Only $NUM_COLS columns (expected 70+)"
    fi

    echo ""
    echo "============================================"
    echo " RESULTS: $PASS passed, $FAIL failed"
    echo "============================================"

    if [ "$FAIL" -gt 0 ]; then
        echo ""
        echo " Some checks failed. Review the output above."
        echo "=== Process Log ($OUTLOG) ==="
        cat "$OUTLOG" 2>/dev/null || echo "(No log found)"
        exit 1
    else
        echo ""
        echo " All checks passed!"
        echo " Output preserved at: $OUTFILE"
        exit 0
    fi
}

# Trap EXIT so cleanup happens on normal completion, errors, AND signals (like SIGINT)
trap finish_and_validate EXIT

# ------------------------------------------------------------------
# Step 3: Start capture
# ------------------------------------------------------------------
echo "[Step 3] Starting capture for ${DURATION}s..."
mkdir -p "$OUTDIR"

# Redirect output to log file to capture tracebacks or verbose output
"$VENV_PYTHON" "$CIC_WRAPPER" -i "$INTERFACE" -c "$OUTFILE" > "$OUTLOG" 2>&1 &
CIC_PID=$!
echo "  CICFlowMeter PID: $CIC_PID"
echo "  Log file: $OUTLOG"

# ------------------------------------------------------------------
# Step 4: Generate test traffic
# ------------------------------------------------------------------
echo "[Step 4] Generating test traffic..."
sleep 2  # let capture initialize

echo "  -> DNS queries..."
nslookup example.com > /dev/null 2>&1 || host example.com > /dev/null 2>&1 || true
echo "  -> HTTP/HTTPS requests..."
curl -s -o /dev/null https://example.com 2>/dev/null || true
echo "  -> ICMP ping..."
ping -c 3 -W 2 8.8.8.8 > /dev/null 2>&1 || true

echo "  Waiting for remaining capture time... Press Ctrl+C to stop early."
REMAINING=$((DURATION - 5))
if [ "$REMAINING" -gt 0 ]; then
    sleep "$REMAINING"
fi
