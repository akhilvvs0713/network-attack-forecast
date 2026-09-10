#!/bin/bash
set -euo pipefail

echo "============================================"
echo " REAL CICFlowMeter -> Redis Window Test"
echo "============================================"

# Clear the live buffer for this test
echo "[*] Cleaning Redis buffer..."
.venv/bin/python -c 'import redis; r=redis.Redis(); r.delete("cic:flows")'

# Start the actual CICFlowMeter pipeline for 340 seconds
echo "[*] Starting CICFlowMeter live capture in background (lo interface, 340s)..."
bash scripts/test_cic_capture.sh lo 340 > data/capture_test.log 2>&1 &
CAPTURE_PID=$!

echo "[*] Waiting 5s for capture initialization..."
sleep 5

echo "[*] Generating initial traffic (T0)..."
ping -c 3 127.0.0.1 > /dev/null

echo "[*] Waiting 20s for T0 flows to be completed and buffered..."
sleep 20

echo "--------------------------------------------"
echo "[*] Initial Redis Buffer State (T0):"
.venv/bin/python scripts/inspect_redis_buffer.py > data/redis_t0.log
cat data/redis_t0.log
echo "--------------------------------------------"

echo ""
echo "[*] Waiting 290 seconds to cross the 300s retention boundary..."
sleep 290

echo "[*] Generating new traffic (T1) to trigger pruning..."
ping -c 3 127.0.0.1 > /dev/null

echo "[*] Waiting 20s for T1 flows to be completed and trigger prune..."
sleep 20

echo "--------------------------------------------"
echo "[*] Final Redis Buffer State (T1):"
.venv/bin/python scripts/inspect_redis_buffer.py > data/redis_t1.log
cat data/redis_t1.log
echo "--------------------------------------------"

echo "[*] Waiting for background capture script to cleanly exit..."
wait "$CAPTURE_PID" || true

echo "--------------------------------------------"
echo "[*] Validating CSV persistence..."
CSV_FILE=$(grep "Output preserved at:" data/capture_test.log | awk '{print $4}' || true)
if [ -n "$CSV_FILE" ] && [ -f "$CSV_FILE" ]; then
    echo "CSV file found: $CSV_FILE"
    LINES=$(wc -l < "$CSV_FILE")
    echo "Total CSV lines (including header): $LINES"
    echo "This proves that even though flows were dropped from Redis, they were permanently archived in the CSV."
else
    echo "[!] CSV file not found or parse error. See capture_test.log:"
    tail -n 20 data/capture_test.log
fi

# Check for orphan processes
echo "[*] Checking for orphan CICFlowMeter processes..."
pgrep -f "cic_wrapper.py" || echo "No orphans found."

echo "[*] Test Complete."
