# OpenSea Bug Bounty Findings - POC Index

**Organization**: opensea (GitHub: ProjectOpenSea)
**Platform**: Bugcrowd
**Review Date**: 2025-12-26
**Status**: **ARCHIVED - No Reportable Findings**

---

## Summary

| ID | Title | Initial Severity | Final Status | Reason |
|----|-------|------------------|--------------|--------|
| [POC-001](./001-github-actions-command-injection.md) | GitHub Actions Command Injection | Critical | **Not Reportable** | Requires write access |
| [POC-002](./002-infura-api-key-exposure.md) | Infura API Key in Git History | Medium | **Not Reportable** | No demonstrable impact |

---

## Archive Reasoning

### POC-001: GitHub Actions Command Injection

**Technical Finding**: Valid command injection in `seaport-1.6/.github/workflows/run-custom-command.yml`

**Why Not Reportable**:
- `workflow_dispatch` requires **write access** to trigger
- External attackers cannot exploit this vulnerability
- Only exploitable via insider threat or compromised collaborator account
- Development repo (`seaport-1.6`) may not be in explicit scope

**Lesson Learned**: Always verify access control requirements for GitHub Actions triggers before classifying severity.

---

### POC-002: Infura API Key Exposure

**Technical Finding**: Verified active Infura key in git history since 2018

**Why Not Reportable**:
- Infura keys only provide read-only access to **public** blockchain data
- No private OpenSea systems or user data accessible
- Prior similar findings rejected by program
- No demonstrable security impact

**Lesson Learned**: Infura/Alchemy keys without billing abuse evidence or infrastructure access are informational only.

---

## Repositories Reviewed

| Repository | Findings | Reportable |
|------------|----------|------------|
| opensea-js | 1 (Infura key) | No |
| seaport-1.6 | 1 (GHA injection) | No |
| seaport | 0 | - |
| seaport-js | 0 | - |
| seadrop | 1 (blockhash - needs investigation) | TBD |
| shipyard-core | 0 | - |
| stream-js | 0 | - |

---

## Conclusion

OpenSea's public repositories are primarily smart contracts and SDKs with limited attack surface. The findings discovered have mitigating factors that prevent them from being reportable:

1. **Access control barriers** (GitHub Actions)
2. **No real security impact** (blockchain API keys)

These POCs are archived for reference but will not be submitted.

---

## File Structure

```
findings/opensea/pocs/
├── README.md                                # This file
├── 001-github-actions-command-injection.md  # Archived - requires write access
└── 002-infura-api-key-exposure.md           # Archived - no impact
```
