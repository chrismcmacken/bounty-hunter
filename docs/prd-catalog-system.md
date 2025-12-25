# PRD: Bug Bounty Target Catalog System

## Problem Statement

Currently, after scanning an organization's repositories, we delete them and keep only the findings. This creates several issues:

1. **No tracking of scanned orgs** - We may forget if we've scanned an organization before
2. **No change detection** - We miss new vulnerabilities when orgs add or modify code
3. **No cross-platform visibility** - Targets are scattered across HackerOne, Bugcrowd, and YesWeHack
4. **No historical context** - We can't correlate new findings with code changes

## Goals

1. Maintain a catalog of tracked organizations across all bug bounty platforms
2. Enable periodic rescanning with change detection
3. Use git's native diffing to track changes in scan results (no custom diff tooling)
4. Track code changes between scans to correlate with new findings
5. Keep all data in flat files accessible via CLI

## Non-Goals

1. Building a GUI or web interface
2. Real-time monitoring or notifications (future consideration)
3. Automated scanning scheduling (manual trigger for now)

---

## Dependencies

- **[bbscope](https://github.com/sw33tLie/bbscope)** - Target aggregation from bug bounty platforms
- **[DuckDB](https://duckdb.org/)** - SQL queries on JSON files
- **jq** - JSON formatting/sorting (still used for normalization)
- **git** - Version control and diffing

---

## Solution Overview

### Target Aggregation

Use [bbscope](https://github.com/sw33tLie/bbscope) to collect targets from:
- HackerOne
- Bugcrowd
- YesWeHack
- Intigriti (optional)

### Data Storage

All data stored as JSON/text files, version-controlled with git. Scan results stored as sorted, pretty-printed JSON for meaningful git diffs.

### Query Layer

Use [DuckDB](https://duckdb.org/) for querying JSON files with SQL syntax. DuckDB reads JSON files directly - no import step needed.

**Benefits over jq:**
- Familiar SQL syntax
- Native glob patterns (`read_json('catalog/tracked/*/scans/*/semgrep.json')`)
- Cross-file queries and aggregations
- Much faster for complex queries

**Example queries:**
```bash
# Orgs not scanned in 7 days
duckdb -c "SELECT name, last_scan FROM read_json('catalog/index.json').tracked_orgs
           WHERE strptime(last_scan, '%Y-%m-%d-%H%M') < current_date - 7"

# All high severity findings across all orgs
duckdb -c "SELECT * FROM read_json('catalog/tracked/*/scans/*/semgrep.json')
           WHERE extra.severity = 'ERROR'"
```

**Normalization for stable diffs:**
- Sort all object keys alphabetically (`jq --sort-keys`)
- Sort result arrays by stable keys:
  - Semgrep: sort by `path`, then `start.line`, then `check_id`
  - Trufflehog: sort by `SourceMetadata.Data.Filesystem.file`, then `DetectorName`
  - KICS: sort by `file_name`, then `query_name`
  - Artifacts: sort by `path`, then `type`

### Repository Management

- Cloned repos stored in gitignored `repos/` directory
- Repos kept between scans (not deleted)
- Commit SHAs recorded at scan time for change tracking

---

## Directory Structure

```
threat_hunting/
├── .gitignore                    # repos/, .env, *.tar.gz, etc.
├── catalog/
│   ├── platforms/                # bbscope output
│   │   ├── hackerone.json
│   │   ├── bugcrowd.json
│   │   ├── yeswehack.json
│   │   └── intigriti.json
│   ├── index.json                # Master list of tracked orgs
│   └── tracked/
│       └── <org>/
│           ├── meta.json         # Program info, platform, scope
│           └── scans/
│               └── <YYYY-MM-DD-HHMM>/
│                   ├── commits.json      # Repo SHAs at scan time
│                   ├── semgrep.json      # Sorted, pretty-printed results
│                   ├── trufflehog.json
│                   ├── kics.json
│                   └── artifacts.json
├── findings/                     # Confirmed reports & hunting targets
│   └── <org>/
│       ├── reports/              # Confirmed reportable findings
│       └── hunting/              # Future targets identified from scans
├── repos/                        # .gitignored - cloned target repos
│   └── <org>/
│       └── <repo>/
├── scripts/
└── docs/
```

---

## Data Schemas

### File Purposes

**catalog/platforms/*.json** (one per platform: hackerone.json, bugcrowd.json, yeswehack.json, intigriti.json)
- Raw bbscope output containing ALL programs from each platform
- The "discovery" layer - refresh periodically to find new programs
- Diff over time to spot newly added programs
- Source data when tracking a new org

**catalog/index.json**
- Master list of all tracked orgs with summary info
- Minimal fields for fast lookups
- Quick status checks across all tracked orgs

**catalog/tracked/<org>/meta.json**
- Detailed record for a single org including full scope, notes, and program details
- Extracted from bbscope platform data when org is tracked, plus additional fields (notes, added_date)
- Used when working with a specific target

**findings/<org>/** (reports/ and hunting/)
- `reports/` - Confirmed reportable findings ready for submission
- `hunting/` - Future targets identified from scans (endpoints to test, resources to verify, etc.)
- Separate from raw scan output in catalog/tracked/<org>/scans/
- Existing findings/ data should be migrated here

### catalog/index.json

```json
{
  "tracked_orgs": [
    {
      "name": "acme-corp",
      "platform": "hackerone",
      "program_url": "https://hackerone.com/acme",
      "added_date": "2025-01-10",
      "last_scan": "2025-01-15-1030",
      "scan_count": 3
    }
  ]
}
```

### catalog/tracked/<org>/meta.json

```json
{
  "name": "acme-corp",
  "platform": "hackerone",
  "program_url": "https://hackerone.com/acme",
  "scope": {
    "in_scope": ["*.acme.com", "github.com/acme-corp/*"],
    "out_of_scope": ["blog.acme.com"]
  },
  "added_date": "2025-01-10",
  "notes": ""
}
```

### catalog/tracked/<org>/scans/<YYYY-MM-DD-HHMM>/commits.json

```json
{
  "scan_time": "2025-01-15T10:30:00Z",
  "repos": {
    "api-server": "abc123def456",
    "frontend": "789xyz000111",
    "mobile-app": "fedcba654321"
  }
}
```

### catalog/platforms/hackerone.json

```json
{
  "refresh_time": "2025-01-15T08:00:00Z",
  "programs": [
    {
      "name": "acme-corp",
      "program_url": "https://hackerone.com/acme",
      "scope": ["*.acme.com"],
      "bounty_range": "$100 - $10,000"
    }
  ]
}
```

---

## Scripts to Implement

### catalog-refresh.sh

**Purpose**: Run bbscope to update platform target lists, handling auth tokens

**Usage**: `./scripts/catalog-refresh.sh [platform]`

**Behavior**:
1. Load auth tokens from `.env` file (unversioned)
2. Run bbscope for specified platform (or all if not specified)
3. Save output to `catalog/platforms/<platform>.json`

**Auth tokens** (loaded from `.env`):
```bash
HACKERONE_TOKEN=your_token
HACKERONE_USERNAME=your_username
BUGCROWD_TOKEN=your_token
YESWEHACK_TOKEN=your_token
```

`.env` must be added to `.gitignore` to prevent committing secrets.

New programs detected via `git diff catalog/platforms/` after refresh.

### catalog-track.sh

**Purpose**: Add an organization to tracked list

**Usage**: `./scripts/catalog-track.sh <org-name> <platform>`

**Behavior**:
1. Create `catalog/tracked/<org>/` directory
2. Create `meta.json` with program info (pulled from platform data if available)
3. Add entry to `catalog/index.json`

Note: Repos are cloned manually using `./scripts/clone-org-repos.sh` - scope parsing may require Claude to interpret which repos are in-scope.

### catalog-scan.sh

**Purpose**: Run all scans for a tracked org and record results

**Usage**: `./scripts/catalog-scan.sh <org-name>`

**Behavior**:
1. Verify org is in tracked list
2. Update repos: `git -C repos/<org>/<repo> pull` for each repo
3. Record current commit SHAs to `commits.json`
4. Run scan-all.sh (semgrep, trufflehog, kics, artifacts)
5. Copy results to `catalog/tracked/<org>/scans/<YYYY-MM-DD-HHMM>/` as sorted, pretty-printed JSON
6. Update `last_scan` in index.json
7. Interactive prompt asking whether to `git add` and commit the new scan

### catalog-diff.sh

**Purpose**: Show differences between scans

**Usage**: `./scripts/catalog-diff.sh <org-name> [scan-date-1] [scan-date-2]`

**Behavior**:
1. Default: compare latest scan to previous
2. Run `git diff` on scan result files
3. Optionally show code changes: `git diff <sha1>..<sha2>` for each repo

### catalog-status.sh

**Purpose**: Show status of all tracked orgs

**Usage**: `./scripts/catalog-status.sh`

**Behavior**:
1. List all tracked orgs with last scan date
2. Highlight orgs not scanned in >7 days
3. Show orgs with pending repo updates (new commits since last scan)

### catalog-untrack.sh

**Purpose**: Remove an org from tracking

**Usage**: `./scripts/catalog-untrack.sh <org-name> [--delete-repos]`

**Behavior**:
1. Remove from `catalog/index.json`
2. Optionally delete `repos/<org>/`
3. Keep `catalog/tracked/<org>/` for historical reference (or offer to delete)

---

## Workflow

### Initial Setup

```bash
# 1. Configure auth tokens in .env
echo "HACKERONE_TOKEN=your_token" >> .env
echo "HACKERONE_USERNAME=your_username" >> .env

# 2. Refresh platform targets
./scripts/catalog-refresh.sh

# 3. Browse available targets
duckdb -c "SELECT name FROM read_json('catalog/platforms/hackerone.json').programs"

# 4. Track an org
./scripts/catalog-track.sh acme-corp hackerone
```

### Regular Scanning

```bash
# 1. Scan a tracked org (prompts to commit when done)
./scripts/catalog-scan.sh acme-corp

# 2. Review changes from last scan
./scripts/catalog-diff.sh acme-corp

# 3. If new findings, investigate
/review-all acme-corp
```

### Periodic Maintenance

```bash
# Check what needs rescanning
./scripts/catalog-status.sh

# Refresh platform targets to find new programs
./scripts/catalog-refresh.sh

# Review new programs
git diff catalog/platforms/
```

---

## Integration with Existing Scripts

### scan-all.sh

Modify to:
- Accept optional `--output-dir` flag for catalog integration
- Output sorted, pretty-printed JSON for stable diffs:
  - Semgrep: `jq --sort-keys '.results |= sort_by(.path, .start.line, .check_id)'`
  - Trufflehog: `jq --sort-keys '.results |= sort_by(.SourceMetadata.Data.Filesystem.file, .DetectorName)'`
  - KICS: `jq --sort-keys '.results |= sort_by(.file_name, .query_name)'`
  - Artifacts: `jq --sort-keys '. |= sort_by(.path, .type)'`

### extract-*.sh scripts

No changes needed - they read from wherever results are stored.

### review-* skills

Update to optionally read from catalog scan directories.

---

## Git Configuration

### .gitignore additions

```
repos/
.env
*.tar.gz
*.zip
```

### .gitattributes (optional, for better JSON diffs)

```
*.json diff=json
```

With git config:
```bash
git config diff.json.textconv "jq --sort-keys ."
```

---

## Success Criteria

1. Can track 10+ orgs without manual bookkeeping
2. `catalog-diff.sh` shows new findings without custom code
3. Can correlate new vulnerabilities with specific code changes
4. All data readable via CLI tools (DuckDB, jq, grep, git diff)
5. Scanning workflow adds <2 minutes overhead vs current approach

---

## Future Considerations (Out of Scope)

- Slack/Discord notifications for new findings
- Scheduled scanning via cron
- Web dashboard for status overview
- Auto-detection of scope changes
- Integration with nuclei for dynamic scanning of new assets

---

## Decisions

1. **Private vs public programs**: No separate tracking - all programs treated the same
2. **Historical scan retention**: Keep forever, no pruning
3. **Commit behavior**: `catalog-scan.sh` prompts for commit but does not auto-commit without user confirmation
