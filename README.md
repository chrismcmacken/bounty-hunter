# Bug Bounty Threat Hunting

Automated security scanning toolkit for bug bounty hunting. Combines static analysis (Semgrep, Trufflehog, KICS) with artifact detection to find vulnerabilities in open source repositories.

## Quick Start

```bash
# Hunt a target (track + clone + scan)
./scripts/hunt.sh <org-name> <platform>
./scripts/hunt.sh acme-corp hackerone

# Review findings
/review-all <org-name>
```

## Prerequisites

### Required Tools
| Tool | Purpose | Installation |
|------|---------|--------------|
| `git` | Repository cloning | Pre-installed on most systems |
| `semgrep` | Code vulnerability scanning | `brew install semgrep` |
| `trufflehog` | Secret detection | `brew install trufflehog` |
| `duckdb` | JSON query extraction | `brew install duckdb` |
| `jq` | JSON processing | `brew install jq` |

### Optional Tools
| Tool | Purpose | Installation |
|------|---------|--------------|
| `scc` | Language/LOC analysis (inventory) | `brew install scc` |
| `syft` | SBOM/dependency analysis (inventory) | `brew install syft` |
| `kics` | IaC misconfiguration scanning | `brew install kics` |
| `gh` | GitHub CLI (for platform queries) | `brew install gh` |

### Installation (macOS)

```bash
# Required
brew install semgrep trufflehog duckdb jq

# Optional - Inventory scanning
brew install scc
brew install syft

# Optional - IaC scanning
brew install kics

# Optional - GitHub CLI
brew install gh
```

### Installation (Linux)

```bash
# semgrep
pip install semgrep

# trufflehog
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# duckdb
# Download from https://duckdb.org/docs/installation/

# scc
go install github.com/boyter/scc/v3@latest

# syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# kics
# Download from https://docs.kics.io/latest/getting-started/
```

## Usage

### Full Workflow
```bash
./scripts/hunt.sh <org> <platform>              # Track, clone, and scan
./scripts/hunt.sh <org> <platform> --skip-kics  # Skip specific scanners
./scripts/hunt.sh <org> <platform> --skip-inventory  # Skip language/dependency inventory
```

### Individual Operations
```bash
./scripts/catalog-track.sh <org> <platform>     # Add org to tracking
./scripts/clone-org-repos.sh <org>              # Clone repositories
./scripts/catalog-scan.sh <org>                 # Run all scanners
./scripts/scan-inventory.sh <org>               # Run inventory only
```

### Query Results
```bash
./scripts/extract-semgrep-findings.sh <org> summary
./scripts/extract-trufflehog-findings.sh <org> verified
./scripts/extract-inventory.sh <org> languages
./scripts/extract-inventory.sh <org> packages
```

### Review Findings
```bash
/review-all <org>           # Comprehensive review
/review-semgrep <org>       # Code vulnerabilities
/review-trufflehog <org>    # Secrets
/review-artifacts <org>     # Archives, databases, backups
/review-kics <org>          # IaC misconfigurations
```

## Directory Structure

```
threat_hunting/
├── catalog/                 # Tracking data and platform scopes
│   ├── index.json          # Master index of tracked orgs
│   ├── platforms/          # HackerOne, Bugcrowd scope data
│   └── tracked/<org>/      # Per-org metadata and scan history
├── repos/<org>/            # Cloned repositories
├── findings/<org>/         # Scan results
│   ├── semgrep-results/
│   ├── trufflehog-results/
│   ├── artifact-results/
│   ├── kics-results/
│   ├── inventory/          # Language and dependency data
│   └── reports/            # Final reports
├── custom-rules/           # Custom Semgrep rules
│   ├── cve/               # CVE-based rules
│   └── open-semgrep-rules/ # Community rules
└── scripts/                # All tooling
```

## Platform Authentication

Configure tokens in `.env` (copy from `.env.example`):

```bash
# HackerOne
HACKERONE_TOKEN=your_token
HACKERONE_USERNAME=your_username

# Bugcrowd
BUGCROWD_TOKEN=your_session_token

# YesWeHack
YESWEHACK_TOKEN=your_token

# Intigriti
INTIGRITI_TOKEN=your_token
```

## Documentation

- [Catalog System](docs/catalog-system.md) - Tracking and scan management
- [CVE Rule Workflow](docs/cve-rule-workflow.md) - Creating rules from CVE patches
- [Static-Dynamic Bridge](docs/static-dynamic-bridge.md) - Validating static findings

## License

Private - Bug bounty research toolkit
