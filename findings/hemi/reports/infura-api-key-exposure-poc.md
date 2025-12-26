# POC: Infura API Key Exposure in Git History

**Status:** 🅿️ PARKED - Free tier key with minimal impact. Can only exhaust 3M daily credits (DoS in ~75 seconds). No private data access, no financial loss beyond service disruption.

**Target:** Hemi (hemilabs)
**Platform:** Bugcrowd
**Date:** 2025-12-21
**Severity:** Low (Free Tier - Limited Impact)

---

## Summary

An active Infura API key was accidentally committed to the `docs` repository and remains accessible in git history. The key has been verified as active and tied to a private Infura project account.

---

## Exposed Credential

| Attribute | Value |
|-----------|-------|
| **Key** | `c89b638d56f144cba995ae0666f37c11` |
| **Endpoint** | `https://hemi-mainnet.infura.io/v3/c89b638d56f144cba995ae0666f37c11` |
| **Repository** | `hemilabs/docs` |
| **Commit** | `69710ad81bf5125e2dde527532b8579cbbf88e7d` |
| **File** | `main/network-details.md` |
| **Commit Date** | 2025-10-21 10:19:14 UTC |
| **Author** | Pranjal Bhardwaj <pranjal@hemi.xyz> |

---

## Evidence This Is NOT a Public Test Key

### 1. Key Validation is Enforced

Invalid keys are rejected by Infura's authentication system:

```bash
# Valid key - returns successful response
$ curl -s "https://hemi-mainnet.infura.io/v3/c89b638d56f144cba995ae0666f37c11" \
  -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'
{"jsonrpc":"2.0","id":1,"result":"0xa867"}

# Invalid key - rejected
$ curl -s "https://hemi-mainnet.infura.io/v3/00000000000000000000000000000000" \
  -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'
invalid project id

# No key - no response
$ curl -s "https://hemi-mainnet.infura.io/" \
  -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'
[empty response]
```

**Conclusion:** If this were a public endpoint, it would not require authentication. The rejection of invalid keys proves this is a project-specific credential.

### 2. Key Was Removed After Discovery

The current version of the documentation shows a placeholder:

**Git History (exposed):**
```html
<a href="https://hemi-mainnet.infura.io/v3/c89b638d56f144cba995ae0666f37c11">
```

**Current HEAD (fixed):**
```html
<a href="https://hemi-mainnet.infura.io/v3/">https://hemi-mainnet.infura.io/v3/</a>YOUR_API_KEY
```

**Conclusion:** The intentional removal and replacement with `YOUR_API_KEY` placeholder confirms this was accidental exposure of a private key, not an intentionally public key.

### 3. Documentation Instructs Users to Get Their Own Key

From `main/network-details.md` (current):
```
## Third-Party Providers

We partner with leading node providers...

| Name | Https Url |
|------|-----------|
| DIN  | https://hemi-mainnet.infura.io/v3/YOUR_API_KEY |
```

**Conclusion:** The documentation explicitly requires users to provide their own API key. There is no "public" key for DIN/Infura access.

### 4. Infrastructure Analysis Confirms Real Infura Backend

```bash
$ dig +short hemi-mainnet.infura.io
hemi-mainnet.infura-router.public.blockchain-networks-1-prod-us-east-1.eks.infura.org.
98.86.239.210
54.242.151.126
54.173.133.250
```

**Conclusion:** This resolves to Infura's production infrastructure on AWS EKS (us-east-1), not a test/mock environment.

### 5. Key Returns Production Data

```bash
$ curl -s "https://hemi-mainnet.infura.io/v3/c89b638d56f144cba995ae0666f37c11" \
  -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
{"jsonrpc":"2.0","id":1,"result":"0x337b45"}

$ curl -s "https://hemi-mainnet.infura.io/v3/c89b638d56f144cba995ae0666f37c11" \
  -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":1}'
{"jsonrpc":"2.0","id":1,"result":"Geth/v0.1.0-untagged-6ba3f1d0-20251201/linux-amd64/go1.24.2"}
```

| Response | Value | Meaning |
|----------|-------|---------|
| Chain ID | `0xa867` (43111) | Hemi Mainnet |
| Block Number | `0x337b45` (3,374,917) | Live production chain |
| Client | Geth/v0.1.0 | Production node software |

---

## Tier Determination

Testing was performed to determine whether this is a free or paid tier key.

### Multi-Network Access

The key provides access to multiple Infura-supported networks:

```bash
# Hemi Mainnet (Chain 43111)
$ curl -s "https://hemi-mainnet.infura.io/v3/c89b638d56f144cba995ae0666f37c11" \
  -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'
{"jsonrpc":"2.0","id":1,"result":"0xa867"}

# Linea Mainnet (Chain 59144)
$ curl -s "https://linea-mainnet.infura.io/v3/c89b638d56f144cba995ae0666f37c11" \
  -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'
{"jsonrpc":"2.0","id":1,"result":"0xe708"}

# Ethereum Mainnet (Chain 1)
$ curl -s "https://mainnet.infura.io/v3/c89b638d56f144cba995ae0666f37c11" \
  -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'
{"jsonrpc":"2.0","id":1,"result":"0x1"}
```

### Debug/Trace API Testing (Paid-Tier Feature)

Per Infura pricing, Debug/Trace APIs are only available on Developer ($50/mo) and higher tiers. Testing on Ethereum mainnet (which supports these methods):

```bash
$ curl -s "https://mainnet.infura.io/v3/c89b638d56f144cba995ae0666f37c11" \
  -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"debug_traceBlockByNumber","params":["latest",{"tracer":"callTracer"}],"id":1}'
{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"The method debug_traceBlockByNumber does not exist/is not available"}}

$ curl -s "https://mainnet.infura.io/v3/c89b638d56f144cba995ae0666f37c11" \
  -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"trace_block","params":["latest"],"id":1}'
{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"The method trace_block does not exist/is not available"}}
```

**Conclusion:** Debug/Trace methods are unavailable, indicating this is a **Core (free) tier** key.

---

## Business Impact

**Note:** Given this appears to be a free tier key, impact is limited to quota exhaustion rather than direct financial loss. This may be considered low severity.

### Infura Pricing Model

Infura uses a credit-based pricing system (Source: [MetaMask Docs](https://support.metamask.io/develop/account/billing-pricing/understand-credit-pricing/)):

| Tier | Daily Credits | Per-Second Limit | Cost |
|------|--------------|------------------|------|
| Core (free) | 3,000,000 | 500 | $0 |
| Developer | 15,000,000 | 4,000 | $50/month |
| Team | 75,000,000 | 40,000 | $225/month |

### Credit Costs Per Call

| Method | Credits |
|--------|---------|
| `eth_chainId` | 5 |
| `eth_blockNumber` | 80 |
| `eth_call` | 80 |
| `eth_estimateGas` | 300 |

### Attack Scenarios (Free Tier)

Given this is a Core (free) tier key, attack scenarios are limited:

#### Scenario 1: Quota Exhaustion

An attacker can exhaust the free tier's 3M daily credits:

| Method | Credits | Calls to Exhaust | Time at 500/sec |
|--------|---------|------------------|-----------------|
| eth_blockNumber | 80 | 37,500 | ~75 seconds |
| eth_call | 80 | 37,500 | ~75 seconds |

**Impact:** If any Hemi test/dev systems rely on this key, they would receive HTTP 402 errors until the next day. However, this is likely low impact if used only for development/testing purposes.

#### Scenario 2: Key Suspension

Abuse patterns may trigger Infura's abuse detection, causing key suspension. Impact depends on whether this key is used in any active systems.

---

## Reproduction Steps

### Step 1: Extract Key from Git History

```bash
git clone https://github.com/hemilabs/docs.git
cd docs
git show 69710ad81bf5125e2dde527532b8579cbbf88e7d:main/network-details.md | grep infura
```

Output:
```
<td><a href="https://hemi-mainnet.infura.io/v3/c89b638d56f144cba995ae0666f37c11">
```

### Step 2: Verify Key is Active

```bash
curl -s "https://hemi-mainnet.infura.io/v3/c89b638d56f144cba995ae0666f37c11" \
  -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'
```

Expected output:
```json
{"jsonrpc":"2.0","id":1,"result":"0xa867"}
```

### Step 3: Confirm Authentication is Required

```bash
curl -s "https://hemi-mainnet.infura.io/v3/00000000000000000000000000000000" \
  -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'
```

Expected output:
```
invalid project id
```

---

## Recommendations

1. **Immediate:** Rotate the Infura API key in the MetaMask Developer dashboard
2. **Short-term:** Consider scrubbing git history using BFG Repo-Cleaner or git filter-repo
3. **Long-term:** Implement pre-commit hooks to detect API keys before commit

---

## References

- [Infura Daily Limits](https://support.metamask.io/develop/account/limits/daily-limits/)
- [Infura Credit Pricing](https://docs.metamask.io/services/get-started/pricing/credit-cost/)
- [Infura Per-Second Limits](https://support.metamask.io/develop/account/limits/limits-per-second/)
- [MetaMask Developer Dashboard](https://developer.metamask.io/)

---

## Appendix: Full API Response Headers

```
HTTP/2 200
date: Sun, 21 Dec 2025 21:44:59 GMT
content-type: application/json
content-length: 42
access-control-allow-origin: *
vary: Accept-Encoding
```

Note: `access-control-allow-origin: *` indicates the endpoint is designed for browser access (typical for RPC endpoints), but this does not make the API key public.
