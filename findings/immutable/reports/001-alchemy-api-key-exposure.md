# Security Report: Alchemy API Key Exposure in Git History

**Report ID**: IMM-001
**Date**: 2025-12-19
**Severity**: Low (Testnet API key, public infrastructure provider)
**Status**: Verified - Ready for Submission

---

## Summary

A verified active Alchemy API key was discovered exposed in the public git history of the `ts-immutable-sdk` repository. While the key has been removed from the current codebase, it remains accessible to anyone who clones the repository and examines the commit history.

---

## Vulnerability Details

| Field | Value |
|-------|-------|
| **Type** | Hardcoded Secret / API Key Exposure |
| **Secret Type** | Alchemy API Key |
| **Network** | Ethereum Sepolia Testnet |
| **Verification Status** | Verified Active (by Trufflehog) |
| **Current Exposure** | Git history only (removed from HEAD) |

### Affected Commits

| Commit | Date | Author | File |
|--------|------|--------|------|
| `53388b819ace` | 2023-05-23 | mikhala.kurtjak@immutable.com | DexConfigOverrides.ts |
| `4660e50aeeff` | 2023-05-24 | andrea.rampin@gmail.com | configs/overrides.ts |
| `edf2a7c8afd6` | 2023-05-25 | imx-mikhala | DexConfigOverrides.ts |
| `ac52aed7ab58` | 2023-06-16 | imx-mikhala | dexConfigOverrides.ts |

### Exposed Secret

```
API Key: yaWHtnolBT_q8n8h03J4aSBsoGnDfWIv
Full URL: https://eth-sepolia.g.alchemy.com/v2/yaWHtnolBT_q8n8h03J4aSBsoGnDfWIv
```

### Original Code Context

```typescript
// From commit edf2a7c8afd6
export const getDexConfigOverrides = (): any => ({
  rpcURL: 'https://eth-sepolia.g.alchemy.com/v2/yaWHtnolBT_q8n8h03J4aSBsoGnDfWIv',
  exchangeContracts: contractOverrides,
  commonRoutingTokens,
  nativeToken: { /* ... */ },
});
```

---

## Impact Assessment

### Confirmed Capabilities (POC Verified)

- [x] API key is active and accepts requests
- [x] Standard Ethereum RPC methods available
- [x] Alchemy enhanced APIs (getTokenBalances, getAssetTransfers) available
- [x] Can make ~7+ requests/second without throttling
- [ ] Account tier unknown (likely free tier based on NFT API restriction)

### Verified Impact

| Impact | Severity | Description |
|--------|----------|-------------|
| Rate Limit Abuse | Low | Attacker can exhaust Immutable's API quota |
| Cost to Org | Low | Likely free tier; if paid, attacker could rack up charges |
| Attribution | Low | Requests logged under Immutable's Alchemy account |
| Data Exposure | None | Blockchain data is public; no sensitive data accessed |
| Testnet Only | Mitigating | No mainnet funds or production systems at risk |

### Context: Alchemy is Public Infrastructure

Alchemy is a public blockchain node provider (similar to Infura). Key considerations:
- **Free tier available**: Anyone can obtain their own Alchemy API key for free
- **Public data**: The blockchain data accessible via this key is publicly available
- **Testnet network**: Sepolia is a test network with no real value at stake
- **No privileged access**: Key provides standard RPC access, not admin capabilities

### Remaining Attack Scenarios

1. **Quota Exhaustion**: Attacker makes sustained requests, exhausting Immutable's rate limits
2. **Cost Inflation**: If paid tier, attacker could increase usage-based billing
3. **False Attribution**: Malicious activity logged under Immutable's account in Alchemy dashboard

---

## Reproduction Steps

### 1. Extract Key from Git History

```bash
cd immutable/ts-immutable-sdk
git show edf2a7c8afd6:packages/checkout/widgets-lib/src/widgets/swap/DexConfigOverrides.ts | grep alchemy
```

### 2. Verify Key is Active

```bash
# Run the POC script
./findings/immutable/reports/poc-alchemy-key-test.sh
```

### 3. Confirm Current Removal

```bash
# Verify key is not in current codebase
grep -r "yaWHtnolBT" . 2>/dev/null
# Should return no results
```

---

## Evidence

### Trufflehog Detection

```
[VERIFIED] Alchemy
  File: packages/checkout/widgets-lib/src/widgets/swap/DexConfigOverrides.ts:38
  Commit: edf2a7c8afd6
  Secret: yaWHtnol...
```

### POC Results (2025-12-19)

**API KEY IS CONFIRMED ACTIVE**

```
API Status: ACTIVE
Network: Sepolia Testnet (Chain ID: 0xaa36a7)
Current Block: 9,874,445

Available Methods:
  ✓ eth_chainId - Working
  ✓ eth_blockNumber - Working
  ✓ eth_gasPrice - Working
  ✓ eth_getBalance - Working
  ✓ alchemy_getTokenBalances - Working
  ✓ alchemy_getAssetTransfers - Working
  ⚠ NFT API v3 - Rate limited/Restricted

Rate Limit Test:
  5/5 requests succeeded in 679ms (~7.4 req/sec sustained)
```

**Full POC Results**: `poc-results-20251219-120700.json`

---

## Recommendations

### Immediate Actions

1. **Rotate the API Key**
   - Generate new key in Alchemy dashboard
   - Update any systems still using this key
   - Revoke the exposed key

2. **Audit Access Logs**
   - Check Alchemy dashboard for unauthorized usage
   - Look for unusual request patterns since May 2023

### Long-term Improvements

1. **Remove from Git History** (optional, high effort)
   ```bash
   # Using BFG Repo Cleaner
   bfg --replace-text passwords.txt ts-immutable-sdk.git
   ```

2. **Implement Secret Scanning**
   - Enable GitHub secret scanning
   - Add pre-commit hooks for secret detection

3. **Use Environment Variables**
   - Already implemented in current code
   - Ensure .env files are in .gitignore

---

## Why This Is Still Worth Reporting

Despite the low severity, this finding demonstrates:

1. **Credential Hygiene Issue**: Secrets should never be committed to public repositories, even for testnets
2. **Verified Active**: The key still works 18+ months after initial commit, suggesting no rotation policy
3. **Best Practice Violation**: Immutable's own SDK serves as an example for developers - hardcoded keys set a bad precedent
4. **Defense in Depth**: Even low-risk exposures should be addressed to maintain security posture

## Program Considerations

Before submitting, verify:

- [ ] Secrets in git history are in scope
- [ ] Testnet-only findings are accepted
- [ ] Low-severity/informational findings are rewarded
- [ ] Check for any duplicate reports

---

## References

- Repository: https://github.com/immutable/ts-immutable-sdk
- Alchemy API Docs: https://docs.alchemy.com/reference/api-overview
- Commit: https://github.com/immutable/ts-immutable-sdk/commit/edf2a7c8afd6
