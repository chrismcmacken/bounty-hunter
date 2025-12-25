# Review Dynamic Analysis Findings

Review dynamic scan results for: **$ARGUMENTS**

## Objective

Triage dynamic analysis findings to identify **exploitable vulnerabilities** for bug bounty submission. Focus on confirmed vulnerabilities with verifiable impact.

## Results Location

All dynamic results are in: `findings/$ARGUMENTS/dynamic-results/`

```
dynamic-results/
├── recon/              # Subdomain and live host data
│   ├── subdomains.txt
│   └── live-hosts.json
├── targets.txt         # Master target list
├── nuclei/             # Vulnerability scan results
│   └── scan-*.json
├── ffuf/               # Fuzzing results
│   └── *-dirs.json
└── oob/                # Out-of-band interaction results
    ├── interactions-*.json
    └── payloads-*.txt
```

## Review Process

### Step 1: Check What Results Exist

First, identify what scan results are available:

```bash
ls -la findings/$ARGUMENTS/dynamic-results/
ls -la findings/$ARGUMENTS/dynamic-results/nuclei/ 2>/dev/null
ls -la findings/$ARGUMENTS/dynamic-results/ffuf/ 2>/dev/null
ls -la findings/$ARGUMENTS/dynamic-results/oob/ 2>/dev/null
```

### Step 2: Nuclei Findings (Priority)

Extract and review vulnerability findings, starting with critical/high:

```bash
./scripts/extract-nuclei-findings.sh $ARGUMENTS critical
```

For all findings:
```bash
./scripts/extract-nuclei-findings.sh $ARGUMENTS summary
```

**Prioritize by severity:**
- **Critical**: RCE, auth bypass, SSRF to internal - verify and report immediately
- **High**: SQLi, XSS, LFI, significant data exposure - investigate thoroughly
- **Medium**: Info disclosure, misconfigurations - assess actual impact
- **Low/Info**: Usually not reportable unless chained

**For each finding:**
1. Verify the vulnerability actually exists (nuclei templates can have false positives)
2. Confirm it's exploitable in the specific context
3. Assess real-world impact
4. Document reproduction steps

### Step 3: FFUF Discoveries

Check for interesting endpoints discovered through fuzzing:

```bash
./scripts/extract-ffuf-findings.sh $ARGUMENTS
```

**Look for:**
- Hidden admin panels (even 403 may be bypassable)
- API endpoints not in public documentation
- Backup files (.bak, .old, .sql)
- Debug/development endpoints
- Version control artifacts (.git, .svn)

### Step 4: OOB Interactions (High Value)

Any interaction here confirms a blind vulnerability:

```bash
cat findings/$ARGUMENTS/dynamic-results/oob/interactions-*.json 2>/dev/null | jq '.'
```

**Interaction types indicate:**
- HTTP callback = SSRF confirmed
- DNS callback = Blind command injection or SSRF
- Both = Strong indicator of exploitable blind vulnerability

**If interactions found:**
1. Identify which payload triggered the callback
2. Trace back to the vulnerable endpoint
3. Document the full attack chain
4. Assess maximum impact (can you reach internal services? AWS metadata?)

### Step 5: Cross-Reference with Static Findings

If you have static analysis results, correlate:

```bash
# Check if dynamic findings match static code analysis
./scripts/extract-semgrep-findings.sh $ARGUMENTS summary 2>/dev/null | head -50
```

**Valuable correlations:**
- Nuclei SSRF finding → Semgrep URL handling finding = stronger case
- OOB callback → Semgrep command injection pattern = confirmed RCE
- FFUF hidden endpoint → Semgrep auth bypass = chain opportunity

## Output Format

### Confirmed Vulnerabilities

For each exploitable finding, document:

```
## [SEVERITY] Vulnerability Title

**Type:** CVE/Misconfig/Injection/etc.
**Template:** nuclei-template-id
**Target:** https://example.com/vulnerable/endpoint

### Evidence
[Nuclei output, callback data, or screenshot]

### Reproduction Steps
1. Step one
2. Step two
3. Step three

### Impact
What can an attacker actually do with this vulnerability?

### Recommendation
How should the target remediate this?
```

### Requires Manual Verification

Findings that need additional testing before reporting.

### False Positives

Document why findings were dismissed to avoid re-analysis.

## Priority Findings

Focus your review on these high-value vulnerability classes:

1. **Remote Code Execution** - Any confirmed RCE is critical
2. **Authentication Bypass** - Access without credentials
3. **SSRF to Internal** - Especially if AWS metadata accessible
4. **SQL Injection** - Data extraction or auth bypass
5. **Sensitive Data Exposure** - PII, credentials, API keys
6. **Subdomain Takeover** - Confirmed with PoC

## Safety Reminders

- NEVER exploit without explicit authorization
- Verify the target is in scope before reporting
- Document everything for responsible disclosure
- Rate limit all testing to avoid service disruption
- If you find something critical, consider reporting immediately
