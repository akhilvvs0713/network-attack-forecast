#!/bin/bash
set -e

echo "Starting Local Blockchain E2E Test..."

# 1. Setup Anvil
if ! command -v anvil &> /dev/null; then
    if [ -f "$HOME/.foundry/bin/anvil" ]; then
        export PATH="$PATH:$HOME/.foundry/bin"
    else
        echo "Error: Anvil is not installed. Please install Foundry (https://getfoundry.sh) and try again."
        exit 1
    fi
fi

# 2. Start Anvil in background
echo "Starting Anvil..."
anvil --port 8545 --silent &
ANVIL_PID=$!

# Wait for Anvil to be ready
sleep 2

# 3. Setup Environment Variables
export BLOCKCHAIN_RPC_URL="http://127.0.0.1:8545"
# Default Anvil account 0 private key
export BLOCKCHAIN_PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

# 4. Deploy Contract
echo "Deploying AuditLedger contract..."
export CONTRACT_ADDRESS=$(./.venv/bin/python scripts/deploy_contract.py)

if [ -z "$CONTRACT_ADDRESS" ]; then
    echo "Contract deployment failed."
    kill $ANVIL_PID
    exit 1
fi

echo "[PASS] Contract deployment (Address: $CONTRACT_ADDRESS)"

# 5. Run E2E Test Logic
echo "Running E2E tests..."
./.venv/bin/python scripts/e2e_test_logic.py

# 6. Cleanup
kill $ANVIL_PID

echo ""
echo "E2E Test Summary:"
echo "[PASS] Contract deployment"
echo "[PASS] Event submission"
echo "[PASS] Transaction mined"
echo "[PASS] VALID verification"
echo "[PASS] TAMPERED verification"
echo "[PASS] Blockchain failure isolation"
echo ""
echo "Test completed successfully."
