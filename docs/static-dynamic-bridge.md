# Static → Dynamic Bridge: Targeted Validation Tools

## Overview

Build tooling that uses existing static analysis findings to generate targeted dynamic tests. This bridges the gap between "found in code" and "actually exploitable."

```
KICS resource name → verify-cloud-exposure.sh → Confirmed public bucket
Semgrep vuln pattern → generate-targeted-tests.sh → Custom nuclei template
```

**Note**: Secret validation is handled by Trufflehog's built-in verification.

---

## Component 1: Cloud Resource Verification

### Script: `scripts/verify-cloud-exposure.sh <org>`

**Input**: KICS findings + IaC file parsing

**Purpose**: Test if cloud resources identified in IaC are actually exposed.

**Step 1**: Extract resource identifiers from IaC files

Parse Terraform/CloudFormation/K8s files for:
- S3 bucket names (from `aws_s3_bucket` resources)
- GCS bucket names (from `google_storage_bucket`)
- Azure container names
- Security group IDs with 0.0.0.0/0 rules
- Database hostnames
- API Gateway endpoints

**Step 2**: Test actual exposure

| Resource Type | Test Command | What Confirms Exposure |
|--------------|--------------|----------------------|
| S3 Bucket | `aws s3 ls s3://bucket --no-sign-request` | Returns listing |
| S3 Bucket | `curl -I https://bucket.s3.amazonaws.com` | Returns 200/403 (exists) vs 404 |
| GCS Bucket | `curl https://storage.googleapis.com/bucket` | Returns listing |
| Azure Blob | `curl https://account.blob.core.windows.net/container?restype=container&comp=list` | Returns listing |
| Open Port | `nc -zv host port` | Connection succeeds |
| Public API | `curl endpoint` | Returns data |

**Output format**:
```json
{
  "resource_type": "S3",
  "resource_name": "company-backup-bucket",
  "source_file": "terraform/s3.tf",
  "exposure_status": "PUBLIC_READ",
  "test_result": "Listed 1,247 objects",
  "sample_objects": ["backup-2024-01.sql.gz", "users.csv"],
  "impact": "CRITICAL - Database backups publicly accessible"
}
```

**Output file**: `findings/<org>/exposed-resources.json`

### Helper Script: `scripts/extract-cloud-resources.sh <org>`

Parses IaC files directly to extract resource names:

```bash
# Extract S3 bucket names from Terraform
grep -r 'bucket\s*=' *.tf | extract bucket names

# Extract from CloudFormation
parse YAML/JSON for AWS::S3::Bucket resources
```

---

## Component 2: Targeted Test Generation

### Script: `scripts/generate-targeted-tests.sh <org>`

**Input**: Semgrep findings with specific vulnerability patterns

**Purpose**: Generate custom nuclei templates that test the exact endpoints where semgrep found vulnerable patterns.

**Step 1**: Map semgrep rules to vulnerability types

| Semgrep Rule Pattern | Vuln Type | Test Strategy |
|---------------------|-----------|---------------|
| `*sql*injection*` | SQLi | Generate SQLi payloads |
| `*ssrf*`, `*url*fetch*` | SSRF | OOB callback test |
| `*command*injection*`, `*exec*` | RCE | Command injection payloads |
| `*deserialize*`, `*pickle*`, `*yaml.load*` | Deser | Gadget payloads |
| `*path*traversal*`, `*file*include*` | LFI/Path | `../` traversal |
| `*xss*`, `*innerhtml*`, `*v-html*` | XSS | XSS payloads |
| `*redirect*`, `*open-redirect*` | Open Redirect | Redirect payloads |

**Step 2**: Extract endpoint info from code context

From semgrep finding:
- `path`: The source file (e.g., `api/handlers/user.go`)
- `extra.lines`: The matched code

Parse the code to find:
- Route definition (e.g., `/api/users/{id}`)
- HTTP method
- Parameter names

**Step 3**: Generate nuclei template

```yaml
id: targeted-sqli-{{hash}}
info:
  name: SQLi in {{endpoint}} (from semgrep)
  severity: high
  description: |
    Semgrep found SQL injection pattern in {{file}}:{{line}}
    Matched code: {{code}}

http:
  - method: {{method}}
    path:
      - "{{endpoint}}"
    payloads:
      sqli:
        - "'"
        - "1' OR '1'='1"
        - "1; DROP TABLE users--"
    fuzzing:
      - part: query
        type: replace
        fuzz:
          - "{{sqli}}"
    matchers:
      - type: word
        words:
          - "SQL syntax"
          - "mysql_fetch"
          - "ORA-"
          - "PostgreSQL"
```

**Output**: `findings/<org>/custom-templates/`

### Challenge: Extracting endpoints from code

This is hard because:
- Different frameworks define routes differently
- May need to trace from handler function to route definition
- Could be in annotations, decorators, or separate route files

**Practical approach**:
1. For common frameworks (Express, Flask, Go chi/mux, Spring), write parsers
2. For unknown frameworks, output the file:line for manual endpoint identification
3. Let the user provide a mapping file: `endpoints.yaml`

---

## Directory Structure

```
scripts/
├── verify-cloud-exposure.sh     # Component 1
├── extract-cloud-resources.sh   # Component 1 helper
├── generate-targeted-tests.sh   # Component 2
└── lib/
    └── endpoint-parsers/        # Framework-specific parsers
        ├── express.sh
        ├── flask.sh
        └── go-chi.sh

templates/
└── nuclei-targeted.yaml.tmpl    # Template for generated nuclei files

findings/<org>/
├── exposed-resources.json       # Component 1 output
└── custom-templates/            # Component 2 output
    └── targeted-*.yaml
```

---

## Summary

| Component | Input | Output | ROI |
|-----------|-------|--------|-----|
| Cloud Verification | KICS + IaC files | Actually exposed resources | High - often missed |
| Targeted Tests | Semgrep findings | Custom nuclei templates | Medium - requires manual review |

**Total new files**: ~6-8 scripts

**Dependencies**:
- AWS CLI (for S3/cloud testing)
- `curl` (for API testing)
- `jq` (already have)
- `nc` (netcat, for port testing)

---

## Usage Examples

### Cloud Resource Verification

```bash
# Extract resources from IaC files
./scripts/extract-cloud-resources.sh acme-corp

# Test for actual exposure
./scripts/verify-cloud-exposure.sh acme-corp

# Review exposed resources
cat findings/acme-corp/exposed-resources.json | jq '.[] | select(.exposure_status == "PUBLIC_READ")'
```

### Targeted Test Generation

```bash
# Generate nuclei templates from semgrep findings
./scripts/generate-targeted-tests.sh acme-corp

# Run the generated templates
nuclei -t findings/acme-corp/custom-templates/ -l targets.txt
```
