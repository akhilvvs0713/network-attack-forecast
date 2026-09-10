#!/bin/bash
# scripts/stop_cic.sh
# Stop a running CICFlowMeter capture started by start_cic.sh.

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PID_FILE="$DIR/.cic.pid"

if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    echo "Stopping CICFlowMeter (PID $PID)..."
    
    if kill -0 "$PID" 2>/dev/null; then
        kill -INT "$PID" 2>/dev/null || true
        echo "Waiting for process to flush and exit..."
        # Wait up to 10 seconds for graceful exit
        for i in {1..10}; do
            if ! kill -0 "$PID" 2>/dev/null; then
                break
            fi
            sleep 1
        done
        
        # If still running, force kill
        if kill -0 "$PID" 2>/dev/null; then
            echo "Process didn't exit. Forcing stop..."
            kill -9 "$PID" 2>/dev/null || true
        fi
    fi
    
    rm -f "$PID_FILE"
    echo "CICFlowMeter stopped."
else
    echo "Checking for running cicflowmeter processes..."
    pkill -f cicflowmeter 2>/dev/null || true
    echo "CICFlowMeter stopped."
fi
