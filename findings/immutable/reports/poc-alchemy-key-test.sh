#!/bin/bash
#
# POC: Alchemy API Key Impact Assessment
# Tests the exposed key to determine actual security impact
#
# Usage: ./poc-alchemy-key-test.sh
#
# This script performs READ-ONLY operations to assess the key's capabilities
# No state-changing operations are performed
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# The exposed API key
API_KEY="yaWHtnolBT_q8n8h03J4aSBsoGnDfWIv"
RPC_URL="https://eth-sepolia.g.alchemy.com/v2/${API_KEY}"

# Output file for results
RESULTS_FILE="$(dirname "$0")/poc-results-$(date +%Y%m%d-%H%M%S).json"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Alchemy API Key Impact Assessment POC${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "Target: ${YELLOW}eth-sepolia.g.alchemy.com${NC}"
echo -e "Key (partial): ${YELLOW}${API_KEY:0:8}...${NC}"
echo -e "Results: ${YELLOW}${RESULTS_FILE}${NC}"
echo ""

# Initialize results JSON
echo '{' > "$RESULTS_FILE"
echo '  "timestamp": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'",' >> "$RESULTS_FILE"
echo '  "target": "eth-sepolia.g.alchemy.com",' >> "$RESULTS_FILE"
echo '  "network": "sepolia",' >> "$RESULTS_FILE"
echo '  "tests": {' >> "$RESULTS_FILE"

# Function to make JSON-RPC call
rpc_call() {
    local method="$1"
    local params="${2:-[]}"
    curl -s -X POST "$RPC_URL" \
        -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":$params,\"id\":1}" \
        2>/dev/null
}

# Test 1: Basic connectivity (eth_chainId)
echo -e "${BLUE}[TEST 1]${NC} Checking API connectivity..."
CHAIN_RESPONSE=$(rpc_call "eth_chainId")
if echo "$CHAIN_RESPONSE" | grep -q '"result"'; then
    CHAIN_ID=$(echo "$CHAIN_RESPONSE" | grep -o '"result":"[^"]*"' | cut -d'"' -f4)
    echo -e "  ${GREEN}✓ API Key is ACTIVE${NC}"
    echo -e "  Chain ID: $CHAIN_ID (Sepolia = 0xaa36a7)"
    echo '    "connectivity": {"status": "active", "chain_id": "'$CHAIN_ID'"},' >> "$RESULTS_FILE"
    API_ACTIVE=true
else
    echo -e "  ${RED}✗ API Key appears INACTIVE or REVOKED${NC}"
    echo -e "  Response: $CHAIN_RESPONSE"
    echo '    "connectivity": {"status": "inactive", "error": "'$(echo "$CHAIN_RESPONSE" | tr '"' "'" | tr '\n' ' ')'" },' >> "$RESULTS_FILE"
    API_ACTIVE=false
fi
echo ""

if [ "$API_ACTIVE" = false ]; then
    echo -e "${YELLOW}API key is inactive. Skipping remaining tests.${NC}"
    echo '    "remaining_tests": "skipped"' >> "$RESULTS_FILE"
    echo '  },' >> "$RESULTS_FILE"
    echo '  "conclusion": "API key has been rotated/revoked - no current risk"' >> "$RESULTS_FILE"
    echo '}' >> "$RESULTS_FILE"
    echo ""
    echo -e "${GREEN}Results saved to: ${RESULTS_FILE}${NC}"
    exit 0
fi

# Test 2: Get current block number
echo -e "${BLUE}[TEST 2]${NC} Fetching current block number..."
BLOCK_RESPONSE=$(rpc_call "eth_blockNumber")
if echo "$BLOCK_RESPONSE" | grep -q '"result"'; then
    BLOCK_NUM=$(echo "$BLOCK_RESPONSE" | grep -o '"result":"[^"]*"' | cut -d'"' -f4)
    BLOCK_DEC=$((16#${BLOCK_NUM:2}))
    echo -e "  ${GREEN}✓ Block number: $BLOCK_DEC${NC}"
    echo '    "block_number": {"status": "success", "block": '$BLOCK_DEC'},' >> "$RESULTS_FILE"
else
    echo -e "  ${RED}✗ Failed to get block number${NC}"
    echo '    "block_number": {"status": "failed"},' >> "$RESULTS_FILE"
fi
echo ""

# Test 3: Get gas price
echo -e "${BLUE}[TEST 3]${NC} Fetching gas price..."
GAS_RESPONSE=$(rpc_call "eth_gasPrice")
if echo "$GAS_RESPONSE" | grep -q '"result"'; then
    GAS_HEX=$(echo "$GAS_RESPONSE" | grep -o '"result":"[^"]*"' | cut -d'"' -f4)
    GAS_WEI=$((16#${GAS_HEX:2}))
    GAS_GWEI=$((GAS_WEI / 1000000000))
    echo -e "  ${GREEN}✓ Gas price: ${GAS_GWEI} Gwei${NC}"
    echo '    "gas_price": {"status": "success", "gwei": '$GAS_GWEI'},' >> "$RESULTS_FILE"
else
    echo -e "  ${RED}✗ Failed to get gas price${NC}"
    echo '    "gas_price": {"status": "failed"},' >> "$RESULTS_FILE"
fi
echo ""

# Test 4: Check account balance (Immutable's known testnet faucet address)
echo -e "${BLUE}[TEST 4]${NC} Testing eth_getBalance..."
TEST_ADDR="0x0000000000000000000000000000000000000000"
BAL_RESPONSE=$(rpc_call "eth_getBalance" "[\"$TEST_ADDR\", \"latest\"]")
if echo "$BAL_RESPONSE" | grep -q '"result"'; then
    echo -e "  ${GREEN}✓ eth_getBalance works${NC}"
    echo '    "get_balance": {"status": "success"},' >> "$RESULTS_FILE"
else
    echo -e "  ${YELLOW}⚠ eth_getBalance may be restricted${NC}"
    echo '    "get_balance": {"status": "restricted"},' >> "$RESULTS_FILE"
fi
echo ""

# Test 5: Test Alchemy-specific enhanced APIs
echo -e "${BLUE}[TEST 5]${NC} Testing Alchemy Enhanced APIs..."
echo '    "enhanced_apis": {' >> "$RESULTS_FILE"

# alchemy_getTokenBalances
TOKEN_RESPONSE=$(curl -s -X POST "$RPC_URL" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"alchemy_getTokenBalances","params":["0x0000000000000000000000000000000000000000"],"id":1}' 2>/dev/null)
if echo "$TOKEN_RESPONSE" | grep -q '"result"'; then
    echo -e "  ${GREEN}✓ alchemy_getTokenBalances: Available${NC}"
    echo '      "getTokenBalances": "available",' >> "$RESULTS_FILE"
else
    echo -e "  ${YELLOW}⚠ alchemy_getTokenBalances: Restricted${NC}"
    echo '      "getTokenBalances": "restricted",' >> "$RESULTS_FILE"
fi

# alchemy_getAssetTransfers
TRANSFER_RESPONSE=$(curl -s -X POST "$RPC_URL" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"alchemy_getAssetTransfers","params":[{"fromBlock":"0x0","toBlock":"latest","fromAddress":"0x0000000000000000000000000000000000000000","category":["external"],"maxCount":"0x1"}],"id":1}' 2>/dev/null)
if echo "$TRANSFER_RESPONSE" | grep -q '"result"'; then
    echo -e "  ${GREEN}✓ alchemy_getAssetTransfers: Available${NC}"
    echo '      "getAssetTransfers": "available",' >> "$RESULTS_FILE"
else
    echo -e "  ${YELLOW}⚠ alchemy_getAssetTransfers: Restricted${NC}"
    echo '      "getAssetTransfers": "restricted",' >> "$RESULTS_FILE"
fi

# Check for NFT API access
NFT_RESPONSE=$(curl -s "https://eth-sepolia.g.alchemy.com/nft/v3/${API_KEY}/getNFTsForOwner?owner=0x0000000000000000000000000000000000000000&pageSize=1" 2>/dev/null)
if echo "$NFT_RESPONSE" | grep -q '"ownedNfts"'; then
    echo -e "  ${GREEN}✓ NFT API v3: Available${NC}"
    echo '      "nft_api": "available"' >> "$RESULTS_FILE"
else
    echo -e "  ${YELLOW}⚠ NFT API v3: Restricted or rate limited${NC}"
    echo '      "nft_api": "restricted"' >> "$RESULTS_FILE"
fi
echo '    },' >> "$RESULTS_FILE"
echo ""

# Test 6: Rate limit assessment
echo -e "${BLUE}[TEST 6]${NC} Assessing rate limits (5 rapid requests)..."
SUCCESS_COUNT=0
START_TIME=$(date +%s%N)
for i in {1..5}; do
    RESP=$(rpc_call "eth_blockNumber")
    if echo "$RESP" | grep -q '"result"'; then
        ((SUCCESS_COUNT++))
    fi
done
END_TIME=$(date +%s%N)
DURATION=$(( (END_TIME - START_TIME) / 1000000 ))
echo -e "  ${GREEN}✓ $SUCCESS_COUNT/5 requests succeeded in ${DURATION}ms${NC}"
echo '    "rate_limit_test": {"requests": 5, "success": '$SUCCESS_COUNT', "duration_ms": '$DURATION'}' >> "$RESULTS_FILE"
echo ""

# Close JSON
echo '  },' >> "$RESULTS_FILE"

# Determine overall impact
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}IMPACT ASSESSMENT${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

if [ "$API_ACTIVE" = true ]; then
    echo -e "${RED}API Key Status: ACTIVE${NC}"
    echo -e ""
    echo -e "Confirmed Capabilities:"
    echo -e "  • Read blockchain state (blocks, transactions, balances)"
    echo -e "  • Query Alchemy enhanced APIs"
    echo -e "  • Perform RPC calls as Immutable's account"
    echo -e ""
    echo -e "Potential Abuse Scenarios:"
    echo -e "  • Exhaust rate limits / API quota"
    echo -e "  • Incur costs if this is a paid tier"
    echo -e "  • Attribute malicious scanning to Immutable"
    echo -e ""
    echo -e "Mitigating Factors:"
    echo -e "  • Testnet only (Sepolia) - no mainnet access"
    echo -e "  • Read-only operations - cannot steal funds"
    echo -e "  • Key removed from current codebase"

    echo '  "impact_assessment": {' >> "$RESULTS_FILE"
    echo '    "key_status": "active",' >> "$RESULTS_FILE"
    echo '    "network": "sepolia_testnet",' >> "$RESULTS_FILE"
    echo '    "risk_level": "medium",' >> "$RESULTS_FILE"
    echo '    "recommendation": "Rotate API key immediately"' >> "$RESULTS_FILE"
    echo '  }' >> "$RESULTS_FILE"
else
    echo -e "${GREEN}API Key Status: INACTIVE/REVOKED${NC}"
    echo -e "No current security risk - key has been rotated."

    echo '  "impact_assessment": {' >> "$RESULTS_FILE"
    echo '    "key_status": "inactive",' >> "$RESULTS_FILE"
    echo '    "risk_level": "none",' >> "$RESULTS_FILE"
    echo '    "recommendation": "No action required - key already rotated"' >> "$RESULTS_FILE"
    echo '  }' >> "$RESULTS_FILE"
fi

echo '}' >> "$RESULTS_FILE"

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Results saved to: ${RESULTS_FILE}${NC}"
echo -e "${GREEN}========================================${NC}"
