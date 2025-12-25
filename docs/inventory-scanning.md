# Inventory Scanning

Language and dependency inventory for bug bounty targets, enabling prioritized rule development and CVE matching.

## Overview

Inventory scanning adds two tools to the hunt workflow:

| Tool | Purpose | Output |
|------|---------|--------|
| **scc** | Language/LOC analysis | Lines of code per language, complexity metrics |
| **syft** | SBOM generation | All dependencies with versions and package URLs |

## Prerequisites

```bash
# macOS
brew install scc syft

# Linux
go install github.com/boyter/scc/v3@latest
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
```

## Usage

### Automatic (Default)

Inventory runs automatically with `hunt.sh`:

```bash
./scripts/hunt.sh <org> <platform>              # Includes inventory
./scripts/hunt.sh <org> <platform> --skip-inventory  # Skip inventory
```

### Manual

```bash
./scripts/scan-inventory.sh <org>               # Run inventory only
./scripts/scan-inventory.sh <org> --repos-dir ./my-repos  # Custom repos location
```

## Output Structure

```
catalog/
└── languages.json           # Global language stats for ALL orgs

findings/<org>/inventory/
├── <repo>-sbom.json         # Per-repo SBOM (syft native format)
└── ...
```

**Why this structure:**
- **Languages**: Small data (~50-100 lines/repo), single file enables easy cross-org queries
- **SBOMs**: Large (10K+ packages/repo), per-repo files queried via DuckDB glob
- **Persistence**: `findings/` persists after `repos/` is archived/deleted

## Querying Inventory

### Language Statistics

```bash
# Summary by language
./scripts/extract-inventory.sh <org> languages

# Output:
# Language    | Files | Code LOC | Repos
# ------------|-------|----------|------
# Go          | 1,234 | 156,000  | 45
# TypeScript  |   890 |  98,000  | 32
# Python      |   456 |  45,000  | 18
```

### Dependency Search

```bash
# All packages
./scripts/extract-inventory.sh <org> packages

# Search for specific package
./scripts/extract-inventory.sh <org> packages | grep lodash

# CVE-ready format (name, version, purl)
./scripts/extract-inventory.sh <org> cve-ready
```

### DuckDB Direct Queries

```sql
-- Language distribution across all orgs
SELECT
    Language,
    SUM(Files) as total_files,
    SUM(Code) as total_loc
FROM read_json('findings/*/inventory/*-languages.json'),
UNNEST(Languages)
GROUP BY Language
ORDER BY total_loc DESC;

-- Find vulnerable package versions
SELECT
    name, version, type,
    regexp_extract(filename, 'findings/([^/]+)/', 1) as org
FROM read_json('findings/*/inventory/*-sbom.json', ignore_errors=true),
UNNEST(artifacts) as pkg
WHERE pkg.name ILIKE '%log4j%';

-- Repos using specific package
SELECT DISTINCT
    regexp_extract(filename, '/([^/]+)-sbom\.json', 1) as repo
FROM read_json('findings/<org>/inventory/*-sbom.json'),
UNNEST(artifacts) as pkg
WHERE pkg.name = 'lodash' AND pkg.version LIKE '4.17.%';
```

## Data Formats

### catalog/languages.json (Global)

Single file containing language stats for all orgs:

```json
{
  "orgs": {
    "hemi": {
      "last_scan": "2025-01-15T10:30:00Z",
      "repos": {
        "hemi-node": [
          {"Language": "Go", "Files": 150, "Lines": 25000, "Code": 20000, "Comments": 3000, "Blanks": 2000, "Complexity": 1500}
        ],
        "hemi-web": [
          {"Language": "TypeScript", "Files": 200, "Lines": 30000, "Code": 25000, "Comments": 2500, "Blanks": 2500}
        ]
      },
      "totals": {
        "Go": {"Files": 150, "Code": 20000, "Repos": 1},
        "TypeScript": {"Files": 200, "Code": 25000, "Repos": 1}
      }
    },
    "wise": {
      "last_scan": "2025-01-14T09:00:00Z",
      "repos": {...},
      "totals": {...}
    }
  }
}
```

### findings/<org>/inventory/<repo>-sbom.json (Per-Repo)

Uses syft's native JSON format (lossless). Key fields:

```json
{
  "artifacts": [
    {
      "name": "github.com/gin-gonic/gin",
      "version": "v1.9.1",
      "type": "go-module",
      "purl": "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
      "locations": [...],
      "licenses": [...]
    }
  ],
  "source": {
    "type": "directory",
    "target": "/path/to/repo"
  },
  "descriptor": {
    "name": "syft",
    "version": "1.0.0"
  }
}
```

## Use Cases

### 1. Prioritize Custom Rule Development

Query languages to focus on highest-value targets:

```bash
./scripts/extract-inventory.sh <org> languages
```

Focus custom Semgrep rules on languages with most code.

### 2. CVE Matching

Export dependencies for vulnerability database lookup:

```bash
./scripts/extract-inventory.sh <org> cve-ready > packages.txt
# Cross-reference with OSV.dev, NVD, or Snyk
```

### 3. Supply Chain Analysis

Identify shared dependencies across repos:

```sql
SELECT name, version, COUNT(*) as repo_count
FROM read_json('findings/<org>/inventory/*-sbom.json'),
UNNEST(artifacts) as pkg
GROUP BY name, version
HAVING repo_count > 3
ORDER BY repo_count DESC;
```

### 4. Attack Surface Estimation

Combine language stats with vulnerability density:

```bash
# High LOC + high semgrep findings = priority target
./scripts/extract-inventory.sh <org> languages
./scripts/extract-semgrep-findings.sh <org> count
```

## Troubleshooting

### scc not found

```bash
brew install scc
# or
go install github.com/boyter/scc/v3@latest
```

### syft not found

```bash
brew install syft
# or
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
```

### Inventory skipped (tools not installed)

If scc or syft are not installed, inventory scanning is skipped with a warning. Install the tools and re-run:

```bash
./scripts/scan-inventory.sh <org>
```

### Large repos slow to scan

syft can be slow on large monorepos. Use `--skip-inventory` for initial scans, then run inventory separately:

```bash
./scripts/hunt.sh <org> <platform> --skip-inventory
./scripts/scan-inventory.sh <org>  # Run later
```
