#!/bin/bash
# scripts/stop_zeek.sh

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BASE_DIR="$(dirname "$DIR")"
PID_FILE="$BASE_DIR/scripts/.zeek.pid"

if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    echo "Stopping Zeek (PID $PID)..."
    sudo kill "$PID" 2>/dev/null
    rm "$PID_FILE"
    echo "Zeek stopped."
else
    echo "Checking for running zeek processes..."
    sudo pkill zeek
    echo "Zeek stopped."
fi
