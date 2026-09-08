#!/bin/bash
# scripts/test_pipeline.sh

echo "=== Pipeline Verification ==="

# Check Python env
if ! command -v python3 &> /dev/null; then
    echo "FAILED: Python 3 is not installed"
    exit 1
fi
echo "PASS: Python 3 is installed"

# Run tests
echo "Running pytest..."
python3 -m pytest tests/
if [ $? -ne 0 ]; then
    echo "FAILED: Pytest suite failed"
    exit 1
fi
echo "PASS: All tests passed"

# Check directories
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BASE_DIR="$(dirname "$DIR")"

echo "Checking directories..."
for d in "data/zeek" "data/events" "logs" "config" "src"; do
    if [ ! -d "$BASE_DIR/$d" ]; then
        echo "FAILED: Directory $d is missing"
        exit 1
    fi
done
echo "PASS: Core directories exist"

echo "Pipeline verification complete and successful."
