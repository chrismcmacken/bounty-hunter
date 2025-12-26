# Disclosure of Secrets - Alchemy API Key in Public Git History

**Status:** 🅿️ PARKED - Disputed by Bugcrowd as lacking impact. Alchemy API keys only access public blockchain data. Limited to potential billing abuse (~$1,800/day max) or rate limit exhaustion. Low priority.

## Summary

Disclosure of secrets for a publicly available asset occurs when sensitive data is not behind an authorization barrier. A verified active Alchemy API key is exposed in the public git history of the `ts-immutable-sdk` repository. While removed from the current codebase, the key remains accessible to anyone who clones the repository and is confirmed still functional.

## Business Impact

Disclosure of secrets for a publicly available asset can lead to indirect financial loss due to an attacker abusing the exposed API key to exhaust rate limits or incur usage-based charges. Reputational damage can occur as malicious activity would be attributed to Immutable's Alchemy account. The severity is reduced as this is a testnet-only key accessing public blockchain data.

## Steps to Reproduce

1. Navigate to the exposed commit in the public GitHub repository:
   https://github.com/immutable/ts-immutable-sdk/blob/edf2a7c8afd6f4485c868b4229f293888cfd47de/packages/checkout/widgets-lib/src/widgets/swap/DexConfigOverrides.ts#L38

2. Observe the hardcoded Alchemy API key on line 38:
   ```
   rpcURL: 'https://eth-sepolia.g.alchemy.com/v2/yaWHtnolBT_q8n8h03J4aSBsoGnDfWIv'
   ```

3. Verify the key is still active by making an RPC request:
   ```bash
   curl -s -X POST "https://eth-sepolia.g.alchemy.com/v2/yaWHtnolBT_q8n8h03J4aSBsoGnDfWIv" \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'
   ```

4. Observe successful response confirming the key is active:
   ```json
   {"jsonrpc":"2.0","id":1,"result":"0xaa36a7"}
   ```

## Proof of Concept (PoC)

The exposed secret in the public git history:

| Field | Value |
|-------|-------|
| Repository | immutable/ts-immutable-sdk |
| Commit | edf2a7c8afd6f4485c868b4229f293888cfd47de |
| File | packages/checkout/widgets-lib/src/widgets/swap/DexConfigOverrides.ts |
| Line | 38 |
| Secret | `yaWHtnolBT_q8n8h03J4aSBsoGnDfWIv` |
| Status | **Verified Active** |
| Exposed Since | May 2023 (~18 months) |

**API Key Verification:**
```
API Status: ACTIVE
Network: Sepolia Testnet (Chain ID: 0xaa36a7)
Methods Available: eth_chainId, eth_blockNumber, eth_getBalance, alchemy_getTokenBalances, alchemy_getAssetTransfers
```

## Recommendation

1. Rotate the Alchemy API key immediately
2. Audit Alchemy dashboard for unauthorized usage since May 2023
3. Consider removing the secret from git history using BFG Repo Cleaner
4. Enable GitHub secret scanning to prevent future exposures

---

## Triage Notes

**Status**: Disputed by Bugcrowd - lacks impact

**Research Findings**:
- Alchemy API keys only access public blockchain data (not private)
- No Gas Manager policies found - Immutable uses Passport relayer for gas sponsorship
- Account/billing data requires Auth Token, not accessible via API key
- Cross-chain access confirmed (works on mainnet) but still public data only

**Impact Assessment**:
| Vector | Feasibility | Impact |
|--------|-------------|--------|
| Private data exfiltration | Not possible | None |
| Gas sponsorship abuse | Not possible | None |
| Billing abuse (~$1,800/day max) | Possible | Low-Medium |
| Rate limit exhaustion (DoS) | Possible | Low |

**Conclusion**: Valid finding but limited to financial/availability impact. No private data at risk. Bugcrowd's assessment is technically correct - this is likely P4/Informational severity.

**Decision**: Low priority - move on to higher-impact findings
