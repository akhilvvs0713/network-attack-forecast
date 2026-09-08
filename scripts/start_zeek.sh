#!/bin/bash
# scripts/start_zeek.sh

# Get directory relative to this script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BASE_DIR="$(dirname "$DIR")"

# Load env variables if they exist
if [ -f "$BASE_DIR/.env" ]; then
    export $(cat "$BASE_DIR/.env" | grep -v '#' | awk '/=/ {print $1}')
fi

INTERFACE=${NETWORK_INTERFACE:-eth0}
ZEEK_DIR=${ZEEK_LOG_DIR:-$BASE_DIR/data/zeek}

# Make sure Zeek log dir exists
mkdir -p "$ZEEK_DIR"

echo "Starting Zeek on interface $INTERFACE..."
echo "Logs will be written to $ZEEK_DIR"

# Check if Zeek is installed
if ! command -v zeek &> /dev/null; then
    echo "Error: zeek command not found. Please install Zeek."
    exit 1
fi

# Run Zeek in the background
cd "$ZEEK_DIR"
sudo zeek -i "$INTERFACE" local &
echo $! > "$BASE_DIR/scripts/.zeek.pid"

echo "Zeek started."
