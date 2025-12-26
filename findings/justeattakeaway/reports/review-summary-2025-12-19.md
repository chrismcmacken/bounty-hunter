# Security Review Summary: justeattakeaway

**Review Date:** 2025-12-19
**Repositories Scanned:** 22
**Result:** No high-confidence reportable vulnerabilities found

---

## Scanner Results

| Scanner | Findings | Verified Vulnerabilities |
|---------|----------|-------------------------|
| Trufflehog (Secrets) | 0 | 0 |
| Semgrep (Code) | ~150 | 0 (all false positives) |
| Artifacts | 1 archive | 0 secrets |
| KICS (IaC) | 20 | 0 (dev configs only) |

---

## Analysis Summary

### Secrets (Trufflehog)
No exposed secrets detected in any repository.

### Code Vulnerabilities (Semgrep)
All findings were false positives:
- GitHub Actions shell injection: Uses `workflow_call` inputs, not attacker-controlled
- JWT tokens: Test fixtures with fake data
- API keys: Public Algolia search-only key (intentional)
- innerHTML XSS: Self-XSS only or static content
- Command injection: Development tooling only

### Artifacts
- JETSans.zip: Font files only, no secrets

### Infrastructure as Code (KICS)
- 20 docker-compose best practice findings
- All in test/development configurations
- No production cloud resources identified

---

## Repository Characteristics

The justeattakeaway public GitHub organization contains:

1. **Frontend Design Systems**
   - `pie` - Primary design system
   - `pie-aperture` - Visual testing
   - `fozzie-components` - Vue component library
   - `pie-iconography`, `pie-illustrations`, `pie-logos`

2. **Development Tools**
   - `AwsWatchman` - AWS resource monitoring
   - `JustSaying` - .NET messaging library
   - `JustEat.StatsD` - StatsD client
   - `httpclient-interception` - HTTP testing library
   - `bq-sql-antipattern-checker` - BigQuery linter

3. **Sample/Demo Applications**
   - `android-deep-links` - Android sample
   - `ApplePayJSSample` - Apple Pay demo
   - `IntervalAnnotatedString` - Android sample

4. **Coding Challenges**
   - `scoober-code-challenge-boilerplate`
   - `skipthedishes-react-test`
   - `ui-coding-exercise`

---

## Future Investigation Areas

### 1. Dynamic Testing of Production Endpoints

**Priority:** High
**Rationale:** Static analysis of public repositories revealed no vulnerabilities, but production applications may have issues not detectable via source code review.

**Actions:**
- Identify production domains from HackerOne program scope
- Run subdomain enumeration against `*.just-eat.com`, `*.justeat.com`, `*.takeaway.com`
- Perform API endpoint discovery on production services
- Test authentication flows, payment processing, order management

### 2. Private Repository Access

**Priority:** Medium
**Rationale:** Public repos are primarily frontend/tooling. Production backend code containing business logic, authentication, payment processing, and database access is likely in private repositories.

**Actions:**
- Check if HackerOne program offers private repository access
- Look for any leaked internal repository references in public code
- Monitor for accidental exposure of internal repos

### 3. Dependency Vulnerability Scanning

**Priority:** Medium
**Rationale:** Supply chain vulnerabilities in third-party packages can affect production systems.

**Actions:**
- Run `npm audit` / `yarn audit` on JavaScript repositories
- Check for vulnerable NuGet packages in .NET projects
- Look for outdated dependencies with known CVEs
- Focus on: fozzie-components, pie, JustSaying

### 4. Mobile Application Analysis

**Priority:** Medium
**Rationale:** Sample Android apps exist in public repos; production mobile apps may have vulnerabilities.

**Actions:**
- Download Just Eat / Takeaway production apps from app stores
- Decompile and analyze for hardcoded secrets
- Test API endpoints used by mobile apps
- Check certificate pinning implementation

### 5. Historical Commit Analysis

**Priority:** Low
**Rationale:** Secrets may have been committed and subsequently removed but could still be valid.

**Actions:**
- Use truffleHog with `--include-detectors all` and history scanning
- Check for rotated secrets that might still be active
- Look for configuration files in old commits

### 6. Infrastructure Reconnaissance

**Priority:** Low
**Rationale:** KICS found docker-compose configs but no cloud infrastructure. Production AWS/GCP resources may be discoverable.

**Actions:**
- Search for S3 bucket naming patterns based on org name
- Check for exposed CloudFront distributions
- Look for public-facing API Gateway endpoints
- Test any discovered cloud resources for misconfiguration

---

## Files Reviewed

```
findings/justeattakeaway/
├── semgrep-results/      # 22 repos scanned
├── trufflehog-results/   # 22 repos scanned
├── artifact-results/     # 1 archive found
├── kics-results/         # 22 repos scanned
└── reports/              # This summary
```

---

## Conclusion

The justeattakeaway public GitHub presence is well-maintained with no exposed secrets or exploitable code vulnerabilities. Future hunting efforts should focus on dynamic testing of production applications and services, which are likely not represented in these public repositories.
