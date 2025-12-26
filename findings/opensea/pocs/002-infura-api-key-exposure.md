# POC-002: Verified Infura API Key in Git History

## Metadata

| Field | Value |
|-------|-------|
| **ID** | POC-002 |
| **Title** | Verified Active Infura API Key Exposed in Git History |
| **Severity** | ~~Medium~~ → **Not Reportable** |
| **Type** | Secret Exposure |
| **Repository** | [ProjectOpenSea/opensea-js](https://github.com/ProjectOpenSea/opensea-js) |
| **File** | `src/constants.ts` (historical) |
| **Platform** | Bugcrowd |
| **Status** | **ARCHIVED - Not Reportable** |
| **Date Discovered** | 2025-12-26 |
| **Date Archived** | 2025-12-26 |

## Why Not Reportable

1. **No Demonstrable Impact**: Infura keys only provide read-only access to public Ethereum blockchain data.
2. **Prior Rejection**: Similar Infura key findings have been rejected by this program - no impact means no bounty.
3. **Public Data**: Blockchain data is inherently public; this key doesn't expose any private OpenSea systems or user data.
4. **Billing Impact Unlikely**: Without evidence of paid tier or significant quota abuse potential, this is informational only.

---

## Executive Summary

An Infura API key has been exposed in the `opensea-js` repository's git history since November 2018. Despite being removed from the current codebase in December 2021, the key remains accessible in git history and has been **verified as still active** by Trufflehog. This key provides Ethereum JSON-RPC access via Infura's infrastructure.

Additionally, two Alchemy API keys were discovered in the same file that were not detected by automated scanners.

---

## Vulnerability Details

### Exposed Secrets

#### 1. Infura API Key (VERIFIED ACTIVE)

| Field | Value |
|-------|-------|
| **Key** | `e8695bce67944848aa95459fac052f8e` |
| **Variable Name** | `DEP_INFURA_KEY` |
| **Format** | 32-character hexadecimal |
| **Verification** | Confirmed active by Trufflehog |

#### 2. Alchemy API Key - Mainnet (UNVERIFIED)

| Field | Value |
|-------|-------|
| **Key** | `y5dLONzfAJh-oCY02DCP3UWCT2pSEXMo` |
| **URL** | `https://eth-mainnet.alchemyapi.io/jsonrpc/y5dLONzfAJh-oCY02DCP3UWCT2pSEXMo` |
| **Verification** | Not verified (no Alchemy detector in Trufflehog) |

#### 3. Alchemy API Key - Rinkeby (UNVERIFIED)

| Field | Value |
|-------|-------|
| **Key** | `-yDg7wmgGw5LdsP4p4kyxRYuDzCkXtoI` |
| **URL** | `https://eth-rinkeby.alchemyapi.io/jsonrpc/-yDg7wmgGw5LdsP4p4kyxRYuDzCkXtoI` |
| **Verification** | Not verified (Rinkeby testnet is deprecated) |

### Affected Code (Historical)

**File**: `src/constants.ts` (commit `44e23151`)

```typescript
import {WyvernProtocol} from 'wyvern-js'

export const DEFAULT_GAS_INCREASE_FACTOR = 1.1
export const NULL_ADDRESS = WyvernProtocol.NULL_ADDRESS
export const NULL_BLOCK_HASH = '0x0000000000000000000000000000000000000000000000000000000000000000'
export const OPENSEA_FEE_RECIPIENT = '0x5b3256965e7c3cf26e11fcaf296dfc8807c01073'
export const DEP_INFURA_KEY = 'e8695bce67944848aa95459fac052f8e'  // <-- EXPOSED
export const MAINNET_PROVIDER_URL = 'https://eth-mainnet.alchemyapi.io/jsonrpc/y5dLONzfAJh-oCY02DCP3UWCT2pSEXMo'  // <-- EXPOSED
export const RINKEBY_PROVIDER_URL = 'https://eth-rinkeby.alchemyapi.io/jsonrpc/-yDg7wmgGw5LdsP4p4kyxRYuDzCkXtoI'  // <-- EXPOSED
export const INVERSE_BASIS_POINT = 10000
export const MAX_UINT_256 = WyvernProtocol.MAX_UINT_256
// ... more constants
```

---

## Timeline

| Date | Event | Commit |
|------|-------|--------|
| 2018-11-07 | Key first introduced in `src/constants.ts` | `44e23151` |
| 2018-12-10 | Commit titled "remove Infura dependency" (key NOT removed) | `cda0e608` |
| 2021-12-14 | Last appearance in code | `2d8f32e6` |
| 2021-12-15 | Key removed from codebase (ESLint cleanup) | `6d76c938` |
| 2025-12-26 | Key discovered and verified still active | - |

**Total Exposure**:
- In active code: ~3 years (2018-2021)
- In git history: ~7 years (2018-present)
- Key status: **NEVER ROTATED**

---

## Proof of Concept

### POC 1: Verify Infura Key is Active

```bash
# Test Infura key with eth_blockNumber RPC call
curl -X POST \
  -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
  "https://mainnet.infura.io/v3/e8695bce67944848aa95459fac052f8e"

# Expected response if active:
# {"jsonrpc":"2.0","id":1,"result":"0x..."}
```

### POC 2: Enumerate Rate Limits

```bash
# Determine rate limits on the key
for i in {1..100}; do
  curl -s -X POST \
    -H "Content-Type: application/json" \
    --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
    "https://mainnet.infura.io/v3/e8695bce67944848aa95459fac052f8e" &
done
wait
```

### POC 3: Test Alchemy Keys

```bash
# Test Mainnet Alchemy key
curl -X POST \
  -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
  "https://eth-mainnet.alchemyapi.io/jsonrpc/y5dLONzfAJh-oCY02DCP3UWCT2pSEXMo"
```

### POC 4: Extract from Git History

```bash
# Clone repository and extract key from history
git clone https://github.com/ProjectOpenSea/opensea-js.git
cd opensea-js

# Find the key in git history
git log --all --oneline -S "e8695bce67944848aa95459fac052f8e"

# View the commit that introduced it
git show 44e23151:src/constants.ts | grep -A1 "DEP_INFURA_KEY"
```

---

## Impact Assessment

### Confidentiality Impact: LOW

- The key provides read-only access to public blockchain data
- No user data or OpenSea infrastructure is exposed
- Blockchain data is inherently public

### Integrity Impact: NONE

- Cannot modify blockchain state (no private key)
- Cannot affect OpenSea systems

### Availability Impact: MEDIUM

- **Rate Limit Abuse**: Attacker could exhaust OpenSea's Infura quota
- **Billing Impact**: If on paid plan, could incur costs for OpenSea
- **Service Degradation**: If OpenSea systems still use this key, abuse could cause outages

### Financial Impact

| Scenario | Risk |
|----------|------|
| Infura Free Tier | Rate limits may affect legitimate use |
| Infura Paid Tier | Billing abuse, potential significant costs |
| Key Still in Production | Service disruption for OpenSea SDK users |

### CVSS 3.1 Estimate

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L
Score: 5.3 (Medium)
```

Note: Score could be higher if billing impact is significant or if the key is still used in production.

---

## Evidence

### Trufflehog Detection

```
Detector: infura
Verified: true
Raw: e8695bce67944848aa95459fac052f8e
File: src/constants.ts
Commit: cdfc92595e7d (and 5 other commits)
```

### Git History Analysis

```bash
# Commits containing the key
43cc4eeb Docs ci (#293)
6d76c938 chore: setup eslint
2300c62d chore: code quality
33397eb6 remove gasPrice
44e23151 Add types to match Django models + minor code refac
8f3686ac remove test files from build
6f7d0787 remove FungibleAsset type, replace with universal asset logic
1295c296 apiBaseUrl settings for api config
cda0e608 remove Infura dependency
```

### Variable Naming Analysis

The variable name `DEP_INFURA_KEY` suggests:
- "DEP" likely means "deprecated" or "default"
- This was intentionally included as a fallback/development key
- Developers were aware this was for development use

---

## Remediation Recommendations

### Immediate Actions

1. **Rotate the Infura API Key**
   - Log into Infura dashboard
   - Generate new API key
   - Revoke the exposed key: `e8695bce67944848aa95459fac052f8e`

2. **Rotate Alchemy API Keys**
   - Mainnet: `y5dLONzfAJh-oCY02DCP3UWCT2pSEXMo`
   - Verify Rinkeby key is no longer needed (testnet deprecated)

3. **Audit Usage Logs**
   - Check Infura dashboard for unauthorized API calls
   - Look for unusual traffic patterns since key was first exposed

### Long-term Actions

1. **Purge from Git History** (Optional)
   ```bash
   # Using git-filter-repo (recommended)
   git filter-repo --replace-text <(echo "e8695bce67944848aa95459fac052f8e==>REDACTED")

   # Force push to all branches
   git push --force --all
   ```

2. **Implement Secret Scanning**
   - Enable GitHub secret scanning on the repository
   - Add pre-commit hooks to prevent future secret commits

3. **Environment Variable Best Practices**
   - Use environment variables or secret managers for API keys
   - Never commit keys to source code, even for "development" use

---

## Future Research

### 1. Verify Key Activity

- [ ] Test Infura key directly (requires execution, not automated)
- [ ] Check if key is on free or paid tier
- [ ] Determine if key is still used in any OpenSea systems

### 2. Alchemy Key Verification

```bash
# Manual test required
curl -X POST \
  -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
  "https://eth-mainnet.g.alchemy.com/v2/y5dLONzfAJh-oCY02DCP3UWCT2pSEXMo"
```

### 3. Search for Other Secrets

```bash
# Search for other potential secrets in opensea-js history
trufflehog git file://./opensea-js --only-verified
```

### 4. Related Repositories

Check if similar keys exist in other OpenSea repositories:
- `seaport`
- `seaport-js`
- `stream-js`

### 5. Third-Party Usage

Search for this key in other repositories (may indicate widespread accidental sharing):
```bash
gh search code "e8695bce67944848aa95459fac052f8e" --limit 100
```

---

## Bug Bounty Considerations

### Strengths of This Finding

1. **Verified Active**: Trufflehog confirmed the key works
2. **Long Exposure**: 7+ years in git history
3. **Never Rotated**: Despite removal from code, key still active
4. **Clear Evidence**: Easy to reproduce and verify

### Weaknesses / Potential Rejections

1. **Limited Impact**: Infura provides read-only blockchain access
2. **Public Data**: Blockchain data is inherently public
3. **"Won't Fix"**: OpenSea may argue this is low priority
4. **Known Exposure**: Key has been public for years

### Recommended Framing

Focus on:
- **Billing Risk**: Potential for cost abuse on Infura paid tiers
- **Operational Risk**: If still used in production, abuse could cause service issues
- **Best Practice Violation**: Credentials should never be in git history
- **Multiple Keys**: Three different API keys exposed, suggesting systemic issue

---

## References

- [Infura API Documentation](https://docs.infura.io/)
- [Alchemy API Documentation](https://docs.alchemy.com/)
- [Trufflehog Infura Detector](https://github.com/trufflesecurity/trufflehog)
- [GitHub: Removing Sensitive Data](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)

---

## Appendix

### All Detected Secrets Summary

| Secret Type | Key/Value | Status | Location |
|-------------|-----------|--------|----------|
| Infura API Key | `e8695bce67944848aa95459fac052f8e` | **VERIFIED ACTIVE** | `src/constants.ts` |
| Alchemy Mainnet | `y5dLONzfAJh-oCY02DCP3UWCT2pSEXMo` | Unverified | `src/constants.ts` |
| Alchemy Rinkeby | `-yDg7wmgGw5LdsP4p4kyxRYuDzCkXtoI` | Likely Dead (testnet) | `src/constants.ts` |

### OpenSea Fee Recipient Address

Also found in the same file (not a secret, but useful context):
```
OPENSEA_FEE_RECIPIENT = '0x5b3256965e7c3cf26e11fcaf296dfc8807c01073'
```

### Original Constants File (Full Context)

```typescript
import {WyvernProtocol} from 'wyvern-js'

export const DEFAULT_GAS_INCREASE_FACTOR = 1.1
export const NULL_ADDRESS = WyvernProtocol.NULL_ADDRESS
export const NULL_BLOCK_HASH = '0x0000000000000000000000000000000000000000000000000000000000000000'
export const OPENSEA_FEE_RECIPIENT = '0x5b3256965e7c3cf26e11fcaf296dfc8807c01073'
export const DEP_INFURA_KEY = 'e8695bce67944848aa95459fac052f8e'
export const MAINNET_PROVIDER_URL = 'https://eth-mainnet.alchemyapi.io/jsonrpc/y5dLONzfAJh-oCY02DCP3UWCT2pSEXMo'
export const RINKEBY_PROVIDER_URL = 'https://eth-rinkeby.alchemyapi.io/jsonrpc/-yDg7wmgGw5LdsP4p4kyxRYuDzCkXtoI'
export const INVERSE_BASIS_POINT = 10000
export const MAX_UINT_256 = WyvernProtocol.MAX_UINT_256
export const WYVERN_EXCHANGE_ADDRESS_MAINNET = '0x7be8076f4ea4a4ad08075c2508e481d6c946d12b'
export const WYVERN_EXCHANGE_ADDRESS_RINKEBY = '0x5206e78b21ce315ce284fb24cf05e0585a93b1d9'
export const ENJIN_COIN_ADDRESS = '0xf629cbd94d3791c9250152bd8dfbdf380e2a3b9c'
export const ENJIN_ADDRESS = '0xfaaFDc07907ff5120a76b34b731b278c38d6043C'
export const ENJIN_LEGACY_ADDRESS = '0x8562c38485B1E8cCd82E44F89823dA76C98eb0Ab'
export const CK_ADDRESS = '0x06012c8cf97bead5deae237070f9587f8e7a266d'
export const CK_RINKEBY_ADDRESS = '0x16baf0de678e52367adc69fd067e5edd1d33e3bf'
export const WRAPPED_NFT_FACTORY_ADDRESS_MAINNET = '0xf11b5815b143472b7f7c52af0bfa6c6a2c8f40e1'
export const WRAPPED_NFT_FACTORY_ADDRESS_RINKEBY = '0x94c71c87244b862cfd64d36af468309e4804ec09'
export const WRAPPED_NFT_LIQUIDATION_PROXY_ADDRESS_MAINNET = '0x995835145dd85c012f3e2d7d5561abd626658c04'
export const WRAPPED_NFT_LIQUIDATION_PROXY_ADDRESS_RINKEBY = '0xaa775Eb452353aB17f7cf182915667c2598D43d3'
export const UNISWAP_FACTORY_ADDRESS_MAINNET = '0xc0a47dFe034B400B47bDaD5FecDa2621de6c4d95'
export const UNISWAP_FACTORY_ADDRESS_RINKEBY = '0xf5D915570BC477f9B8D6C0E980aA81757A3AaC36'
export const DEFAULT_WRAPPED_NFT_LIQUIDATION_UNISWAP_SLIPPAGE_IN_BASIS_POINTS = 1000
export const CHEEZE_WIZARDS_GUILD_ADDRESS = WyvernProtocol.NULL_ADDRESS
export const CHEEZE_WIZARDS_GUILD_RINKEBY_ADDRESS = '0x095731b672b76b00A0b5cb9D8258CD3F6E976cB2'
export const CHEEZE_WIZARDS_BASIC_TOURNAMENT_ADDRESS = WyvernProtocol.NULL_ADDRESS
export const CHEEZE_WIZARDS_BASIC_TOURNAMENT_RINKEBY_ADDRESS = '0x8852f5F7d1BB867AAf8fdBB0851Aa431d1df5ca1'
export const DECENTRALAND_ESTATE_ADDRESS = '0x959e104e1a4db6317fa58f8295f586e1a978c297'
```
