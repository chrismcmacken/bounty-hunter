# Wise Research Opportunities

**Organization**: Wise (GitHub: transferwise)
**Platform**: Bugcrowd
**Last Reviewed**: 2025-12-26
**Status**: Public repos exhausted - pivot to production testing

---

## Executive Summary

Static analysis of Wise's 44 public GitHub repositories yielded **0 reportable findings**. The repositories contain internal tooling, ML libraries, and sample code - no production application code is exposed. Future research should focus on dynamic testing of production assets.

---

## Repository Intelligence Gathered

### Technology Stack (from inventory scan)
Based on the public repos, Wise uses:
- **Backend**: Python (pipelinewise, cicada, ML libs), Go (crypto), Java (idempotence4j)
- **Frontend**: TypeScript/JavaScript (widgets, samples)
- **Infrastructure**: Docker, GitHub Actions
- **Data**: PostgreSQL, MongoDB, MySQL, Snowflake (ETL targets)
- **Cloud**: AWS (S3 bucket `staging-model-data` confirmed in eu-central-1)

### Key Internal Tools Identified
| Tool | Purpose | Relevance |
|------|---------|-----------|
| pipelinewise | ETL data pipeline | Understanding data flow patterns |
| cicada | Job scheduler | Internal scheduling architecture |
| crypto | Cryptographic operations | Encryption patterns (DES for legacy, RSA, PGP) |
| digital-signatures | Document signing | Signature verification patterns |

### API Intelligence
- `public-api-postman-collection` - Contains API endpoint documentation
- `api.transferwise.com` - Production API endpoint confirmed
- `widgets.wise.com` - CDN for embeddable widgets (S3 backend)

---

## Future Research Vectors

### 1. Production Web Application (wise.com)

**Priority**: HIGH

The public repos contain no production web code. Direct testing of wise.com should focus on:

- [ ] OAuth/authentication flows (sample code shows popup-based OAuth pattern)
- [ ] API endpoint testing (use Postman collection as reference)
- [ ] Widget embedding security (cross-origin communication)
- [ ] Payment flow manipulation
- [ ] Account takeover vectors

**Reference**: `wise-platform-samples/oauth-connect-popup/` shows OAuth integration patterns

### 2. API Security Testing

**Priority**: HIGH

Endpoints to investigate:
- [ ] `api.transferwise.com` - Main API
- [ ] Rate limiting and abuse potential
- [ ] IDOR on transfer/recipient endpoints
- [ ] JWT/token handling

**Resource**: Import `public-api-postman-collection` into Postman for structured testing

### 3. PostMessage Security (Widget Integration)

**Priority**: MEDIUM

The sample code at `wise-platform-samples/oauth-connect-popup/src/popupHandler.ts:34` lacks origin validation:

```typescript
window.addEventListener('message', handleEvents);
// No origin check in handler
```

**Research opportunity**: Test if production widgets.wise.com or OAuth flows have similar issues.

- [ ] Identify all postMessage listeners on wise.com
- [ ] Test cross-origin message injection
- [ ] Check OAuth redirect handling

### 4. Mobile Applications

**Priority**: MEDIUM

`banks-reference-android` shows Android development patterns. Production mobile apps may share patterns.

- [ ] Android app APK analysis
- [ ] iOS app binary analysis
- [ ] Deep link handling
- [ ] Certificate pinning bypass

### 5. Third-Party Integrations

**Priority**: MEDIUM

From code analysis, Wise integrates with:
- [ ] Snowflake (data warehouse) - credential exposure vectors
- [ ] Various bank APIs (patterns in pipelinewise connectors)
- [ ] Cloudflare (prometheus exporter suggests CF usage)

### 6. Historical Git Analysis

**Priority**: LOW

The trufflehog scan focused on current state. Deep git history analysis may reveal:

- [ ] Rotated but still-valid credentials
- [ ] Removed but cached secrets
- [ ] Development branch leaks

```bash
# Command for deeper historical scan
trufflehog git file://./repos/transferwise/<repo> --since-commit=<first-commit> --only-verified
```

---

## Assets Verified as Secure

These were tested and confirmed not exploitable:

| Asset | Test Result | Notes |
|-------|-------------|-------|
| `staging-model-data` S3 bucket | 403 AccessDenied | Properly configured |
| `api.transferwise.com` | 404 on root | Expected API behavior |
| `widgets.wise.com` | 403 on root | S3 CDN, requires valid paths |

---

## Scope Considerations (Bugcrowd)

Before testing, verify current Bugcrowd scope:
- Check if wise.com web app is in scope
- Check if mobile apps are in scope
- Check if API endpoints have rate limit restrictions
- Check for any specific exclusions (e.g., DoS, social engineering)

---

## Custom Semgrep Rule Opportunities

Based on code patterns observed, potential custom rules:

### 1. PostMessage Without Origin Validation
```yaml
# Pattern seen in wise-platform-samples
rules:
  - id: postmessage-no-origin-check
    patterns:
      - pattern: window.addEventListener('message', $HANDLER)
      - pattern-not-inside: |
          if ($EVENT.origin === $ORIGIN) { ... }
    message: "postMessage handler without origin validation"
    severity: WARNING
```

### 2. ETL SQL Injection (Internal Tools Pattern)
```yaml
# Pattern from cicada/pipelinewise - useful for similar internal tools
rules:
  - id: etl-sql-format-string
    pattern: |
      $QUERY = f"... {$VAR} ..."
      $CURSOR.execute($QUERY)
    message: "SQL query with f-string formatting"
    severity: ERROR
```

---

## Next Steps

1. **Immediate**: Review Bugcrowd program scope for wise.com
2. **Short-term**: Import Postman collection and map API attack surface
3. **Medium-term**: Dynamic testing of OAuth flows and widget embedding
4. **Ongoing**: Monitor transferwise GitHub for new repos

---

## Files Referenced

- Scan results: `scans/wise/`
- Catalog metadata: `catalog/tracked/wise/meta.json`
- Source code: `repos/transferwise/`
- Postman collection: `repos/transferwise/public-api-postman-collection/`
