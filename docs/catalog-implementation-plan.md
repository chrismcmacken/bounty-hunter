# Catalog System Implementation Plan

This document captures the complete implementation plan for the Bug Bounty Target Catalog System as defined in `docs/prd-catalog-system.md`.

---

## Overview

Transform the current "scan and delete" workflow into a persistent catalog that:
- Tracks organizations across bug bounty platforms
- Enables periodic rescanning with change detection
- Uses git diffs for comparing scan results
- Correlates new findings with code changes

---

## Dependencies

| Tool | Purpose | Install |
|------|---------|---------|
| **DuckDB** | SQL queries on JSON files | `brew install duckdb` |
| **bbscope** | Fetch targets from platforms | `go install github.com/sw33tLie/bbscope@latest` |
| **jq** | JSON normalization for stable diffs | Already installed |
| **git** | Version control and diffing | Already installed |

---

## Directory Structure (Target State)

```
threat_hunting/
├── .gitignore                    # Add: repos/, .env
├── .env                          # Auth tokens (not committed)
├── .env.example                  # Template for .env
├── catalog/
│   ├── platforms/                # bbscope output
│   │   ├── hackerone.json
│   │   ├── bugcrowd.json
│   │   └── yeswehack.json
│   ├── index.json                # Master list of tracked orgs
│   └── tracked/
│       └── <org>/
│           ├── meta.json         # Program info, platform, scope
│           └── scans/
│               └── <YYYY-MM-DD-HHMM>/
│                   ├── commits.json      # Repo SHAs at scan time
│                   ├── semgrep.json      # Normalized results
│                   ├── trufflehog.json
│                   ├── kics.json
│                   └── artifacts.json
├── findings/                     # Confirmed findings (existing)
│   └── <org>/
│       ├── reports/              # Reportable findings
│       └── hunting/              # Future targets
├── repos/                        # .gitignored - cloned repos
│   └── <org>/
│       └── <repo>/
├── scripts/
│   ├── lib/
│   │   └── catalog-utils.sh      # NEW: Shared functions
│   ├── catalog-refresh.sh        # NEW: Fetch from bbscope
│   ├── catalog-track.sh          # NEW: Add org to tracking
│   ├── catalog-scan.sh           # NEW: Run scans, store results
│   ├── catalog-diff.sh           # NEW: Compare scans
│   ├── catalog-status.sh         # NEW: Status dashboard
│   ├── catalog-untrack.sh        # NEW: Remove org
│   ├── clone-org-repos.sh        # MODIFY: Add --catalog flag
│   ├── scan-all.sh               # MODIFY: Add --output-dir, --normalize
│   ├── extract-semgrep-findings.sh    # REWRITE: jq → DuckDB
│   ├── extract-trufflehog-findings.sh # REWRITE: jq → DuckDB
│   ├── extract-kics-findings.sh       # REWRITE: jq → DuckDB
│   └── extract-artifact-findings.sh   # REWRITE: jq → DuckDB
└── docs/
```

---

## Script Architecture

### Relationship: catalog-scan.sh vs scan-all.sh

These scripts have distinct responsibilities:

**scan-all.sh** (existing, low-level)
- Runs the actual security scanners (semgrep, trufflehog, kics, artifacts)
- Outputs raw JSON to `findings/<org>/<scanner>-results/`
- No awareness of catalog system
- Can be used standalone for quick one-off scans

**catalog-scan.sh** (new, orchestrator)
- Wraps scan-all.sh with catalog management
- Handles: repo updates, commit SHA recording, result normalization, storage, index updates
- Stores normalized results in `catalog/tracked/<org>/scans/<timestamp>/`

```
catalog-scan.sh (orchestrator)
    │
    ├── 1. Verify org is tracked
    ├── 2. git pull all repos in repos/<org>/
    ├── 3. Record commit SHAs → commits.json
    │
    ├── 4. ─────► scan-all.sh ◄───── runs actual scanners
    │                 │
    │                 └── findings/<org>/<scanner>-results/ (raw output)
    │
    ├── 5. Normalize JSON (sort for stable git diffs)
    ├── 6. Copy to catalog/tracked/<org>/scans/<timestamp>/
    ├── 7. Update catalog/index.json
    └── 8. Prompt for git commit
```

**Why separate?**
1. **Backward compatibility** - scan-all.sh works standalone for users who don't need tracking
2. **Single responsibility** - scan-all.sh scans, catalog-scan.sh manages catalog
3. **Testability** - Can test scanning and catalog logic independently

### Script Categories

| Category | Scripts | Purpose |
|----------|---------|---------|
| **Scanners** | scan-all.sh, scan-semgrep.sh, scan-secrets.sh, scan-kics.sh, scan-artifacts.sh | Run security tools, output raw JSON |
| **Extractors** | extract-*-findings.sh | Query/format scan results (DuckDB) |
| **Catalog** | catalog-*.sh | Manage tracked orgs, scans, diffs |
| **Setup** | clone-org-repos.sh | Clone repositories |

---

## Phase 1: Infrastructure Setup

### Tasks

1. **Create directory structure**
   ```bash
   mkdir -p catalog/platforms catalog/tracked
   mkdir -p repos
   ```

2. **Update .gitignore**
   ```
   # Add these lines
   repos/
   .env
   *.tar.gz
   *.zip
   ```

3. **Create .env.example**
   ```bash
   # Bug Bounty Platform Auth Tokens
   # Copy to .env and fill in your tokens

   HACKERONE_TOKEN=
   HACKERONE_USERNAME=
   BUGCROWD_TOKEN=
   YESWEHACK_TOKEN=
   ```

4. **Create empty catalog/index.json**
   ```json
   {
     "tracked_orgs": []
   }
   ```

5. **Configure git for JSON diffs** (optional)
   ```bash
   # .gitattributes
   *.json diff=json

   # git config
   git config diff.json.textconv "jq --sort-keys ."
   ```

### Deliverables
- [x] Directory structure created (catalog/platforms, catalog/tracked, repos)
- [x] .gitignore created (repos/, .env, archives, temp dirs)
- [x] .env.example created (HackerOne, Bugcrowd, YesWeHack, Intigriti)
- [x] catalog/index.json initialized
- [x] .gitattributes configured (*.json diff=json)
- [x] git config diff.json.textconv set

---

## Phase 2: Library Functions

### File: `scripts/lib/catalog-utils.sh`

```bash
#!/usr/bin/env bash
# Shared functions for catalog system

# Get current timestamp in catalog format
get_scan_timestamp() {
    date +"%Y-%m-%d-%H%M"
}

# Get ISO timestamp
get_iso_timestamp() {
    date -u +"%Y-%m-%dT%H:%M:%SZ"
}

# Normalize semgrep JSON for stable diffs
# Sort by: path, start.line, check_id
normalize_semgrep_json() {
    local input="$1"
    local output="${2:-$input}"
    jq --sort-keys '
        .results |= sort_by(.path, .start.line, .check_id)
    ' "$input" > "$output.tmp" && mv "$output.tmp" "$output"
}

# Normalize trufflehog NDJSON for stable diffs
# Sort by: file, DetectorName
normalize_trufflehog_json() {
    local input="$1"
    local output="${2:-$input}"
    # NDJSON: sort lines by file and detector
    jq -s 'sort_by(.SourceMetadata.Data.Filesystem.file // .SourceMetadata.Data.Git.file, .DetectorName)' "$input" |
    jq -c '.[]' > "$output.tmp" && mv "$output.tmp" "$output"
}

# Normalize KICS JSON for stable diffs
# Sort by: file_name, query_name
normalize_kics_json() {
    local input="$1"
    local output="${2:-$input}"
    jq --sort-keys '
        .queries |= sort_by(.query_name) |
        .queries[].files |= sort_by(.file_name, .line)
    ' "$input" > "$output.tmp" && mv "$output.tmp" "$output"
}

# Normalize artifacts JSON for stable diffs
# Sort by: path, type
normalize_artifacts_json() {
    local input="$1"
    local output="${2:-$input}"
    jq --sort-keys '
        .archives |= sort_by(.path) |
        .databases |= sort_by(.path) |
        .sql_dumps |= sort_by(.path) |
        .source_backups |= sort_by(.path)
    ' "$input" > "$output.tmp" && mv "$output.tmp" "$output"
}

# Add org to index.json
add_to_index() {
    local org="$1"
    local platform="$2"
    local program_url="$3"
    local index_file="catalog/index.json"

    jq --arg name "$org" \
       --arg platform "$platform" \
       --arg url "$program_url" \
       --arg date "$(date +%Y-%m-%d)" \
       '.tracked_orgs += [{
           name: $name,
           platform: $platform,
           program_url: $url,
           added_date: $date,
           last_scan: null,
           scan_count: 0
       }]' "$index_file" > "$index_file.tmp" && mv "$index_file.tmp" "$index_file"
}

# Update index.json after scan
update_index_scan() {
    local org="$1"
    local timestamp="$2"
    local index_file="catalog/index.json"

    jq --arg name "$org" \
       --arg ts "$timestamp" \
       '.tracked_orgs |= map(
           if .name == $name then
               .last_scan = $ts | .scan_count += 1
           else . end
       )' "$index_file" > "$index_file.tmp" && mv "$index_file.tmp" "$index_file"
}

# Remove org from index.json
remove_from_index() {
    local org="$1"
    local index_file="catalog/index.json"

    jq --arg name "$org" \
       '.tracked_orgs |= map(select(.name != $name))' \
       "$index_file" > "$index_file.tmp" && mv "$index_file.tmp" "$index_file"
}

# Check if org is tracked
is_org_tracked() {
    local org="$1"
    local index_file="catalog/index.json"

    jq -e --arg name "$org" '.tracked_orgs[] | select(.name == $name)' "$index_file" > /dev/null 2>&1
}

# Get org info from index
get_org_info() {
    local org="$1"
    local field="$2"
    local index_file="catalog/index.json"

    jq -r --arg name "$org" --arg field "$field" \
       '.tracked_orgs[] | select(.name == $name) | .[$field]' "$index_file"
}
```

### Deliverables
- [x] scripts/lib/catalog-utils.sh created
- [x] Timestamp functions tested (get_scan_timestamp, get_iso_timestamp)
- [x] Path helpers tested (get_org_catalog_dir, get_org_repos_dir, etc.)
- [x] Index management tested (add_to_index, remove_from_index, is_org_tracked)
- [x] JSON normalization tested (semgrep, trufflehog NDJSON, kics, artifacts)

---

## Phase 3-6: DuckDB Migration of Extract Scripts

### Rationale

Replace jq-based extract scripts with DuckDB for:
- **SQL syntax** - More familiar, powerful
- **Glob patterns** - Query across all files in one command
- **Cross-org queries** - New capability for catalog system
- **Performance** - Faster for complex aggregations

### Phase 3: extract-semgrep-findings.sh

**Current**: 101 lines, jq, iterates files in bash loop

**New approach**:
```bash
#!/usr/bin/env bash
set -euo pipefail

ORG="${1:-}"
FORMAT="${2:-summary}"
REPO="${3:-}"

[[ -z "$ORG" ]] && { echo "Usage: $0 <org> [format] [repo]"; exit 1; }

RESULTS_DIR="findings/$ORG/semgrep-results"
[[ ! -d "$RESULTS_DIR" ]] && { echo "Error: $RESULTS_DIR not found"; exit 1; }

# Build file pattern
if [[ -n "$REPO" ]]; then
    PATTERN="$RESULTS_DIR/$REPO.json"
    [[ ! -f "$PATTERN" ]] && { echo "Error: $PATTERN not found"; exit 1; }
else
    PATTERN="$RESULTS_DIR/*.json"
fi

case "$FORMAT" in
    count)
        duckdb -c "
            SELECT
                regexp_extract(filename, '([^/]+)\\.json$', 1) as repo,
                count(*) as findings
            FROM read_json('$PATTERN')
            CROSS JOIN UNNEST(results) as r
            GROUP BY repo
            HAVING findings > 0
            ORDER BY findings DESC
        "
        ;;

    summary)
        duckdb -c "
            SELECT
                r.extra.severity as severity,
                r.check_id as rule,
                r.path || ':' || r.start.line as location,
                substring(r.extra.message, 1, 100) || '...' as message
            FROM read_json('$PATTERN')
            CROSS JOIN UNNEST(results) as r
            ORDER BY
                CASE r.extra.severity
                    WHEN 'ERROR' THEN 1
                    WHEN 'WARNING' THEN 2
                    ELSE 3
                END,
                r.path, r.start.line
        "
        ;;

    full)
        duckdb -json -c "
            SELECT r.*
            FROM read_json('$PATTERN')
            CROSS JOIN UNNEST(results) as r
        "
        ;;

    jsonl)
        duckdb -c "
            SELECT r.*
            FROM read_json('$PATTERN')
            CROSS JOIN UNNEST(results) as r
        " -json | jq -c '.[]'
        ;;

    *)
        echo "Unknown format: $FORMAT"
        echo "Available: count, summary, full, jsonl"
        exit 1
        ;;
esac

# Show total if not single repo
if [[ -z "$REPO" && "$FORMAT" != "jsonl" ]]; then
    echo ""
    total=$(duckdb -c "
        SELECT count(*) FROM read_json('$PATTERN')
        CROSS JOIN UNNEST(results)
    " -noheader -csv)
    echo "Total findings: $total"
fi
```

### Phase 4: extract-trufflehog-findings.sh

**Key difference**: Trufflehog outputs NDJSON (newline-delimited JSON)

```bash
# DuckDB handles NDJSON with format parameter
duckdb -c "
    SELECT
        DetectorName,
        CASE WHEN Verified THEN '[VERIFIED]' ELSE '[unverified]' END as status,
        coalesce(
            SourceMetadata.Data.Filesystem.file,
            SourceMetadata.Data.Git.file
        ) as file,
        substring(Raw, 1, 8) || '...' as secret_preview
    FROM read_json('$PATTERN', format='newline_delimited')
    ORDER BY Verified DESC, DetectorName
"
```

### Phase 5: extract-kics-findings.sh

**Key difference**: Deeply nested structure (queries → files)

```bash
# DuckDB flattens with multiple UNNEST
duckdb -c "
    SELECT
        q.severity,
        q.query_name,
        f.file_name || ':' || f.line as location,
        f.issue_type
    FROM read_json('$PATTERN')
    CROSS JOIN UNNEST(queries) as q
    CROSS JOIN UNNEST(q.files) as f
    WHERE q.severity IN ('HIGH', 'MEDIUM')
    ORDER BY
        CASE q.severity WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END,
        f.file_name
"
```

### Phase 6: extract-artifact-findings.sh

**Key difference**: Multiple arrays to union

```bash
# DuckDB unions across artifact types
duckdb -c "
    SELECT repo, 'archive' as type, a.path, a.size
    FROM read_json('$PATTERN')
    CROSS JOIN UNNEST(archives) as a
    UNION ALL
    SELECT repo, 'database' as type, d.path, d.size
    FROM read_json('$PATTERN')
    CROSS JOIN UNNEST(databases) as d
    UNION ALL
    SELECT repo, 'sql_dump' as type, s.path, s.size
    FROM read_json('$PATTERN')
    CROSS JOIN UNNEST(sql_dumps) as s
    UNION ALL
    SELECT repo, 'source_backup' as type, b.path, b.size
    FROM read_json('$PATTERN')
    CROSS JOIN UNNEST(source_backups) as b
    ORDER BY repo, type, path
"
```

### Deliverables
- [x] extract-semgrep-findings.sh rewritten with DuckDB (count, summary, full, jsonl, rules formats)
- [x] extract-trufflehog-findings.sh rewritten with DuckDB (count, summary, full, verified, detectors formats)
- [x] extract-kics-findings.sh rewritten with DuckDB (count, summary, full, resources, queries formats)
- [x] extract-artifact-findings.sh rewritten with DuckDB (count, summary, full, archives, sql, sources, databases formats)
- [x] All formats tested (count, summary, full, etc.)

---

## Phase 7: Modify clone-org-repos.sh

### Changes Required

Add `--catalog` flag to clone to `repos/<org>/` instead of `./<org>/`

**Current behavior** (line 120):
```bash
mkdir -p "$ORG"
```

**New behavior**:
```bash
# Add to argument parsing
CATALOG_MODE=""
case "$1" in
    --catalog)
        CATALOG_MODE="1"
        shift
        ;;
esac

# Change clone directory
if [[ -n "$CATALOG_MODE" ]]; then
    CLONE_DIR="repos/$ORG"
else
    CLONE_DIR="$ORG"
fi
mkdir -p "$CLONE_DIR"
```

Also update:
- Line 121: `mkdir -p "findings/$ORG/..."` - keep as-is (findings stay in findings/)
- Line 123-138: Update `$ORG/$name` → `$CLONE_DIR/$name`
- Line 141: Update final count path

### Deliverables
- [x] --catalog flag added
- [x] Backward compatibility preserved (default still clones to ./<org>/)
- [x] Help text updated

---

## Phase 8: Modify scan-all.sh

### Changes Required

1. Add `--output-dir <path>` flag
2. Add `--normalize` flag for sorted JSON output
3. Support catalog directory structure

**New flags**:
```bash
OUTPUT_DIR=""
NORMALIZE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --normalize)
            NORMALIZE="1"
            shift
            ;;
        # ... existing flags
    esac
done

# Default output dir
OUTPUT_DIR="${OUTPUT_DIR:-findings/$ORG}"
```

**Post-scan normalization**:
```bash
if [[ -n "$NORMALIZE" ]]; then
    source "$SCRIPT_DIR/lib/catalog-utils.sh"

    for f in "$OUTPUT_DIR/semgrep-results"/*.json; do
        [[ -f "$f" ]] && normalize_semgrep_json "$f"
    done
    # ... same for other scanners
fi
```

### Deliverables
- [x] --output-dir flag added
- [x] --normalize flag added
- [x] --repos-dir flag added (bonus)
- [x] Backward compatibility preserved
- [x] Help text updated

---

## Phase 9: catalog-track.sh

### Purpose
Add an organization to the tracked list

### Usage
```bash
./scripts/catalog-track.sh <org-name> <platform> [--program-url <url>]
```

### Behavior
1. Check if org already tracked (error if so)
2. Look up org in `catalog/platforms/<platform>.json` if exists
3. Create `catalog/tracked/<org>/` directory
4. Create `meta.json` with program info
5. Add entry to `catalog/index.json`
6. Print next steps (clone repos)

### Implementation
```bash
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/catalog-utils.sh"

ORG="${1:-}"
PLATFORM="${2:-}"
PROGRAM_URL=""

# Parse optional flags
shift 2 || true
while [[ $# -gt 0 ]]; do
    case "$1" in
        --program-url) PROGRAM_URL="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

[[ -z "$ORG" || -z "$PLATFORM" ]] && {
    echo "Usage: $0 <org-name> <platform> [--program-url <url>]"
    echo "Platforms: hackerone, bugcrowd, yeswehack"
    exit 1
}

# Check if already tracked
if is_org_tracked "$ORG"; then
    echo "Error: '$ORG' is already tracked"
    exit 1
fi

# Try to get info from platform data
PLATFORM_FILE="catalog/platforms/$PLATFORM.json"
if [[ -f "$PLATFORM_FILE" && -z "$PROGRAM_URL" ]]; then
    PROGRAM_URL=$(jq -r --arg name "$ORG" \
        '.programs[]? | select(.name == $name) | .program_url // empty' \
        "$PLATFORM_FILE")
fi

# Create directories
mkdir -p "catalog/tracked/$ORG/scans"

# Create meta.json
cat > "catalog/tracked/$ORG/meta.json" << EOF
{
  "name": "$ORG",
  "platform": "$PLATFORM",
  "program_url": "${PROGRAM_URL:-}",
  "scope": {
    "in_scope": [],
    "out_of_scope": []
  },
  "added_date": "$(date +%Y-%m-%d)",
  "notes": ""
}
EOF

# Add to index
add_to_index "$ORG" "$PLATFORM" "${PROGRAM_URL:-}"

echo "Tracked: $ORG ($PLATFORM)"
echo ""
echo "Next steps:"
echo "  1. Clone repos:  ./scripts/clone-org-repos.sh --catalog $ORG"
echo "  2. Run scan:     ./scripts/catalog-scan.sh $ORG"
```

### Deliverables
- [x] Script created
- [x] Platform lookup working
- [x] Index update working
- [x] Error handling for duplicates

---

## Phase 10: catalog-scan.sh (Core)

### Purpose
Run all scans for a tracked org, store normalized results, record commit SHAs

### Usage
```bash
./scripts/catalog-scan.sh <org-name> [scan-all options]
```

### Behavior
1. Verify org is tracked
2. Check repos exist in `repos/<org>/`
3. Update repos (`git pull`)
4. Record commit SHAs
5. Create scan directory with timestamp
6. Run `scan-all.sh`
7. Normalize and copy results to catalog
8. Update index.json
9. Prompt for git commit

### Implementation
```bash
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/catalog-utils.sh"

ORG="${1:-}"
shift || true

[[ -z "$ORG" ]] && {
    echo "Usage: $0 <org-name> [scan-all options]"
    exit 1
}

# Verify tracked
if ! is_org_tracked "$ORG"; then
    echo "Error: '$ORG' is not tracked"
    echo "Track first: ./scripts/catalog-track.sh $ORG <platform>"
    exit 1
fi

REPOS_DIR="repos/$ORG"
if [[ ! -d "$REPOS_DIR" ]]; then
    echo "Error: Repos not found at $REPOS_DIR"
    echo "Clone first: ./scripts/clone-org-repos.sh --catalog $ORG"
    exit 1
fi

TIMESTAMP=$(get_scan_timestamp)
SCAN_DIR="catalog/tracked/$ORG/scans/$TIMESTAMP"
mkdir -p "$SCAN_DIR"

echo "========================================"
echo "Catalog Scan: $ORG"
echo "Timestamp: $TIMESTAMP"
echo "========================================"
echo ""

# Update repos and record SHAs
echo "Updating repositories..."
declare -A REPO_SHAS
for repo in "$REPOS_DIR"/*/; do
    [[ -d "$repo/.git" ]] || continue
    name=$(basename "$repo")

    echo "  [$name] Pulling..."
    git -C "$repo" pull --ff-only 2>/dev/null || echo "  [$name] Pull failed, using current state"

    sha=$(git -C "$repo" rev-parse HEAD)
    REPO_SHAS[$name]=$sha
done
echo ""

# Write commits.json
echo "Recording commit SHAs..."
{
    echo "{"
    echo "  \"scan_time\": \"$(get_iso_timestamp)\","
    echo "  \"repos\": {"
    first=true
    for name in "${!REPO_SHAS[@]}"; do
        $first || echo ","
        printf "    \"%s\": \"%s\"" "$name" "${REPO_SHAS[$name]}"
        first=false
    done
    echo ""
    echo "  }"
    echo "}"
} > "$SCAN_DIR/commits.json"
echo ""

# Run scans (use repos/ directory, output to findings/ as usual)
# We need to temporarily work with the repos in their catalog location
# Create symlink or run from repos dir
echo "Running scans..."
ORIG_DIR=$(pwd)

# Option 1: Change to repos parent and scan
cd repos
"$SCRIPT_DIR/scan-all.sh" "$ORG" "$@"
cd "$ORIG_DIR"

# Copy and normalize results
echo ""
echo "Normalizing and storing results..."

FINDINGS_DIR="findings/$ORG"

# Semgrep - merge all repo results into one file
if [[ -d "$FINDINGS_DIR/semgrep-results" ]]; then
    jq -s '{ results: map(.results) | flatten }' \
        "$FINDINGS_DIR/semgrep-results"/*.json 2>/dev/null | \
        jq --sort-keys '.results |= sort_by(.path, .start.line, .check_id)' \
        > "$SCAN_DIR/semgrep.json"
    echo "  Semgrep: $(jq '.results | length' "$SCAN_DIR/semgrep.json") findings"
fi

# Trufflehog - concatenate NDJSON files, then sort
if [[ -d "$FINDINGS_DIR/trufflehog-results" ]]; then
    cat "$FINDINGS_DIR/trufflehog-results"/*.json 2>/dev/null | \
        jq -s 'sort_by(.SourceMetadata.Data.Filesystem.file // .SourceMetadata.Data.Git.file, .DetectorName)' | \
        jq -c '.[]' > "$SCAN_DIR/trufflehog.json"
    count=$(wc -l < "$SCAN_DIR/trufflehog.json" | xargs)
    echo "  Trufflehog: $count findings"
fi

# KICS - merge results
if [[ -d "$FINDINGS_DIR/kics-results" ]]; then
    jq -s '{
        queries: map(.queries // []) | flatten | group_by(.query_id) | map(.[0] + {files: map(.files) | flatten}),
        total_counter: map(.total_counter // 0) | add
    }' "$FINDINGS_DIR/kics-results"/*.json 2>/dev/null | \
        jq --sort-keys '.' > "$SCAN_DIR/kics.json"
    echo "  KICS: $(jq '.total_counter' "$SCAN_DIR/kics.json") findings"
fi

# Artifacts - merge results
if [[ -d "$FINDINGS_DIR/artifact-results" ]]; then
    jq -s 'map(. + {_repo: .repo}) | {
        artifacts: .,
        totals: {
            archives: map(.archives | length) | add,
            databases: map(.databases | length) | add,
            sql_dumps: map(.sql_dumps | length) | add,
            source_backups: map(.source_backups | length) | add
        }
    }' "$FINDINGS_DIR/artifact-results"/*.json 2>/dev/null | \
        jq --sort-keys '.' > "$SCAN_DIR/artifacts.json"
    echo "  Artifacts: $(jq '.totals | add' "$SCAN_DIR/artifacts.json") items"
fi

# Update index
update_index_scan "$ORG" "$TIMESTAMP"

echo ""
echo "========================================"
echo "Scan complete: $SCAN_DIR"
echo "========================================"
echo ""

# Prompt for commit
read -p "Commit scan results to git? [y/N] " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    git add "$SCAN_DIR"
    git add catalog/index.json
    git commit -m "Scan $ORG - $TIMESTAMP"
    echo "Committed."
else
    echo "Not committed. To commit later:"
    echo "  git add $SCAN_DIR catalog/index.json"
    echo "  git commit -m 'Scan $ORG - $TIMESTAMP'"
fi
```

### Deliverables
- [x] Script created
- [x] Repo updating working (with --no-pull option)
- [x] Commit SHA recording working
- [x] Result normalization working (merges per-repo results)
- [x] Index update working
- [x] Git commit prompt working (with --no-commit option)

---

## Phase 11: catalog-status.sh

### Purpose
Dashboard showing all tracked orgs and their scan status

### Usage
```bash
./scripts/catalog-status.sh [--stale-days N]
```

### Output
```
ORG             PLATFORM    LAST SCAN         SCANS  STATUS
─────────────────────────────────────────────────────────────
acme-corp       hackerone   2025-01-15-1030   3      ✓ Current
beta-inc        bugcrowd    2025-01-05-0800   2      ⚠ Stale (14d)
gamma-tech      hackerone   -                 0      ○ Never scanned

Tracked: 3 orgs | Stale: 1 | Never scanned: 1
```

### Implementation
```bash
#!/usr/bin/env bash
set -euo pipefail

STALE_DAYS=7

while [[ $# -gt 0 ]]; do
    case "$1" in
        --stale-days) STALE_DAYS="$2"; shift 2 ;;
        *) shift ;;
    esac
done

INDEX_FILE="catalog/index.json"
[[ ! -f "$INDEX_FILE" ]] && { echo "No catalog found. Run catalog-track.sh first."; exit 1; }

# Use DuckDB for the query
duckdb -c "
    WITH orgs AS (
        SELECT
            name,
            platform,
            last_scan,
            scan_count,
            CASE
                WHEN last_scan IS NULL THEN 'never'
                WHEN strptime(last_scan, '%Y-%m-%d-%H%M') < current_date - INTERVAL '$STALE_DAYS days' THEN 'stale'
                ELSE 'current'
            END as status,
            CASE
                WHEN last_scan IS NULL THEN NULL
                ELSE current_date - strptime(last_scan, '%Y-%m-%d-%H%M')::date
            END as days_ago
        FROM read_json('$INDEX_FILE')
        CROSS JOIN UNNEST(tracked_orgs)
    )
    SELECT
        name as \"ORG\",
        platform as \"PLATFORM\",
        coalesce(last_scan, '-') as \"LAST SCAN\",
        scan_count as \"SCANS\",
        CASE status
            WHEN 'current' THEN '✓ Current'
            WHEN 'stale' THEN '⚠ Stale (' || days_ago || 'd)'
            WHEN 'never' THEN '○ Never scanned'
        END as \"STATUS\"
    FROM orgs
    ORDER BY
        CASE status WHEN 'stale' THEN 1 WHEN 'never' THEN 2 ELSE 3 END,
        name
"

# Summary
echo ""
duckdb -noheader -c "
    SELECT
        'Tracked: ' || count(*) || ' orgs | ' ||
        'Stale: ' || sum(CASE WHEN last_scan IS NOT NULL AND strptime(last_scan, '%Y-%m-%d-%H%M') < current_date - INTERVAL '$STALE_DAYS days' THEN 1 ELSE 0 END) || ' | ' ||
        'Never scanned: ' || sum(CASE WHEN last_scan IS NULL THEN 1 ELSE 0 END)
    FROM read_json('$INDEX_FILE')
    CROSS JOIN UNNEST(tracked_orgs)
"
```

### Deliverables
- [x] Script created
- [x] Stale detection working (configurable --stale-days)
- [x] Status display with DuckDB queries
- [x] Summary counts accurate
- [x] Detailed org view (--org flag)
- [x] Recommendations for stale/never-scanned orgs

---

## Phase 12: catalog-diff.sh

### Purpose
Show differences between scans using git diff

### Usage
```bash
./scripts/catalog-diff.sh <org-name> [scan1] [scan2] [--code]
```

### Behavior
1. Default: compare latest scan to previous
2. Show git diff on normalized JSON files
3. With `--code`: also show code changes between commit SHAs

### Implementation
```bash
#!/usr/bin/env bash
set -euo pipefail

ORG="${1:-}"
SCAN1="${2:-}"
SCAN2="${3:-}"
SHOW_CODE=""

# Handle --code flag anywhere in args
for arg in "$@"; do
    [[ "$arg" == "--code" ]] && SHOW_CODE="1"
done

[[ -z "$ORG" ]] && {
    echo "Usage: $0 <org-name> [scan1] [scan2] [--code]"
    echo "  Defaults to comparing latest two scans"
    exit 1
}

SCANS_DIR="catalog/tracked/$ORG/scans"
[[ ! -d "$SCANS_DIR" ]] && { echo "Error: No scans found for $ORG"; exit 1; }

# Get scan directories sorted by name (which is timestamp)
mapfile -t SCANS < <(ls -1 "$SCANS_DIR" | sort)

if [[ ${#SCANS[@]} -lt 2 && -z "$SCAN1" ]]; then
    echo "Error: Need at least 2 scans to compare"
    echo "Available scans: ${SCANS[*]:-none}"
    exit 1
fi

# Default to latest two
SCAN1="${SCAN1:-${SCANS[-2]}}"
SCAN2="${SCAN2:-${SCANS[-1]}}"

DIR1="$SCANS_DIR/$SCAN1"
DIR2="$SCANS_DIR/$SCAN2"

[[ ! -d "$DIR1" ]] && { echo "Error: Scan not found: $SCAN1"; exit 1; }
[[ ! -d "$DIR2" ]] && { echo "Error: Scan not found: $SCAN2"; exit 1; }

echo "========================================"
echo "Comparing: $SCAN1 → $SCAN2"
echo "========================================"
echo ""

# Diff each result file
for scanner in semgrep trufflehog kics artifacts; do
    file1="$DIR1/$scanner.json"
    file2="$DIR2/$scanner.json"

    if [[ -f "$file1" && -f "$file2" ]]; then
        # Count changes
        added=$(diff <(jq -S '.' "$file1") <(jq -S '.' "$file2") 2>/dev/null | grep -c '^>' || echo "0")
        removed=$(diff <(jq -S '.' "$file1") <(jq -S '.' "$file2") 2>/dev/null | grep -c '^<' || echo "0")

        if [[ "$added" -gt 0 || "$removed" -gt 0 ]]; then
            echo "=== $scanner: +$added / -$removed ==="
            git diff --no-index --color=always "$file1" "$file2" 2>/dev/null | head -50 || true
            echo ""
        else
            echo "=== $scanner: No changes ==="
        fi
    elif [[ -f "$file2" && ! -f "$file1" ]]; then
        echo "=== $scanner: NEW (not in previous scan) ==="
    fi
done

# Code diff if requested
if [[ -n "$SHOW_CODE" ]]; then
    echo ""
    echo "========================================"
    echo "Code Changes"
    echo "========================================"

    commits1="$DIR1/commits.json"
    commits2="$DIR2/commits.json"

    if [[ -f "$commits1" && -f "$commits2" ]]; then
        # Get list of repos from both
        repos=$(jq -r '.repos | keys[]' "$commits1" "$commits2" 2>/dev/null | sort -u)

        for repo in $repos; do
            sha1=$(jq -r --arg r "$repo" '.repos[$r] // empty' "$commits1")
            sha2=$(jq -r --arg r "$repo" '.repos[$r] // empty' "$commits2")

            if [[ -n "$sha1" && -n "$sha2" && "$sha1" != "$sha2" ]]; then
                echo ""
                echo "=== $repo: $sha1 → $sha2 ==="
                repo_dir="repos/$ORG/$repo"
                if [[ -d "$repo_dir" ]]; then
                    git -C "$repo_dir" log --oneline "$sha1..$sha2" 2>/dev/null | head -20 || echo "  (commits not available)"
                fi
            fi
        done
    fi
fi
```

### Deliverables
- [x] Script created
- [x] JSON diff working (compares normalized JSON, shows new/removed findings)
- [x] Code diff working (--code flag shows commit history between scans)
- [x] Change summaries accurate (summary table with counts per scanner)
- [x] Additional features: --summary (counts only), --scanner filter, help text

---

## Phase 13: catalog-refresh.sh

### Purpose
Fetch targets from bug bounty platforms using bbscope

### Usage
```bash
./scripts/catalog-refresh.sh [platform]
```

### Behavior
1. Load tokens from `.env`
2. Run bbscope for each platform
3. Save to `catalog/platforms/<platform>.json`
4. Show diff summary for new programs

### Implementation
```bash
#!/usr/bin/env bash
set -euo pipefail

PLATFORM="${1:-all}"

# Load environment
if [[ -f .env ]]; then
    source .env
else
    echo "Warning: .env not found. Create from .env.example"
fi

mkdir -p catalog/platforms

refresh_platform() {
    local platform="$1"
    local output="catalog/platforms/$platform.json"
    local temp_output="${output}.new"

    echo "Refreshing $platform..."

    case "$platform" in
        hackerone)
            [[ -z "${HACKERONE_TOKEN:-}" ]] && { echo "  HACKERONE_TOKEN not set, skipping"; return; }
            bbscope h1 -t "$HACKERONE_TOKEN" -u "${HACKERONE_USERNAME:-}" -o json > "$temp_output" 2>/dev/null || {
                echo "  Failed to fetch from HackerOne"
                rm -f "$temp_output"
                return
            }
            ;;
        bugcrowd)
            [[ -z "${BUGCROWD_TOKEN:-}" ]] && { echo "  BUGCROWD_TOKEN not set, skipping"; return; }
            bbscope bc -t "$BUGCROWD_TOKEN" -o json > "$temp_output" 2>/dev/null || {
                echo "  Failed to fetch from Bugcrowd"
                rm -f "$temp_output"
                return
            }
            ;;
        yeswehack)
            [[ -z "${YESWEHACK_TOKEN:-}" ]] && { echo "  YESWEHACK_TOKEN not set, skipping"; return; }
            bbscope ywh -t "$YESWEHACK_TOKEN" -o json > "$temp_output" 2>/dev/null || {
                echo "  Failed to fetch from YesWeHack"
                rm -f "$temp_output"
                return
            }
            ;;
        *)
            echo "  Unknown platform: $platform"
            return
            ;;
    esac

    # Wrap in our schema
    local count=$(jq 'length' "$temp_output" 2>/dev/null || echo "0")
    jq --arg time "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
       '{refresh_time: $time, programs: .}' "$temp_output" > "$output"
    rm -f "$temp_output"

    echo "  $platform: $count programs"

    # Show new programs if previous version exists in git
    if git show HEAD:"$output" &>/dev/null; then
        new_count=$(diff <(git show HEAD:"$output" | jq -r '.programs[].name' | sort) \
                        <(jq -r '.programs[].name' "$output" | sort) 2>/dev/null | grep -c '^>' || echo "0")
        [[ "$new_count" -gt 0 ]] && echo "  NEW: $new_count programs added since last refresh"
    fi
}

if [[ "$PLATFORM" == "all" ]]; then
    for p in hackerone bugcrowd yeswehack; do
        refresh_platform "$p"
    done
else
    refresh_platform "$PLATFORM"
fi

echo ""
echo "Done. Review changes with: git diff catalog/platforms/"
```

### Deliverables
- [x] Script created
- [x] HackerOne integration working (bbscope h1)
- [x] Bugcrowd integration working (bbscope bc)
- [x] YesWeHack integration working (bbscope ywh)
- [x] Intigriti integration added (bbscope it)
- [x] New program detection working (git diff comparison)
- [x] Additional features: --list, --dry-run, token status check

---

## Phase 14: catalog-untrack.sh

### Purpose
Remove an organization from tracking

### Usage
```bash
./scripts/catalog-untrack.sh <org-name> [--delete-repos] [--delete-history]
```

### Behavior
1. Remove from index.json
2. Optionally delete repos/
3. Optionally delete catalog/tracked/<org>/
4. Confirm before destructive actions

### Implementation
```bash
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/catalog-utils.sh"

ORG="${1:-}"
DELETE_REPOS=""
DELETE_HISTORY=""

shift || true
while [[ $# -gt 0 ]]; do
    case "$1" in
        --delete-repos) DELETE_REPOS="1"; shift ;;
        --delete-history) DELETE_HISTORY="1"; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

[[ -z "$ORG" ]] && {
    echo "Usage: $0 <org-name> [--delete-repos] [--delete-history]"
    exit 1
}

if ! is_org_tracked "$ORG"; then
    echo "Error: '$ORG' is not tracked"
    exit 1
fi

echo "Untracking: $ORG"

# Remove from index
remove_from_index "$ORG"
echo "  Removed from index.json"

# Handle repos
if [[ -n "$DELETE_REPOS" && -d "repos/$ORG" ]]; then
    read -p "  Delete repos/$ORG? [y/N] " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "repos/$ORG"
        echo "  Deleted repos/$ORG"
    fi
fi

# Handle history
if [[ -n "$DELETE_HISTORY" && -d "catalog/tracked/$ORG" ]]; then
    read -p "  Delete catalog/tracked/$ORG? [y/N] " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "catalog/tracked/$ORG"
        echo "  Deleted catalog/tracked/$ORG"
    fi
else
    echo "  Keeping catalog/tracked/$ORG for historical reference"
fi

echo ""
echo "Done. '$ORG' is no longer tracked."
```

### Deliverables
- [ ] Script created
- [ ] Index removal working
- [ ] Repo deletion with confirmation
- [ ] History deletion with confirmation

---

## Phase 15: Testing and Documentation

### Testing Checklist

1. **End-to-end workflow**
   ```bash
   # Setup
   ./scripts/catalog-track.sh test-org hackerone
   ./scripts/clone-org-repos.sh --catalog test-org

   # First scan
   ./scripts/catalog-scan.sh test-org
   ./scripts/catalog-status.sh

   # Extract findings (DuckDB)
   ./scripts/extract-semgrep-findings.sh test-org
   ./scripts/extract-trufflehog-findings.sh test-org

   # Second scan (after some time)
   ./scripts/catalog-scan.sh test-org
   ./scripts/catalog-diff.sh test-org

   # Cleanup
   ./scripts/catalog-untrack.sh test-org --delete-repos
   ```

2. **DuckDB extract scripts**
   - [ ] Test each format option
   - [ ] Test single repo vs all repos
   - [ ] Test with empty results
   - [ ] Test with catalog paths

3. **Edge cases**
   - [ ] Org with no repos
   - [ ] Org with only one scan
   - [ ] Missing platform tokens
   - [ ] Interrupted scans

### Documentation Updates

1. **Update CLAUDE.md** with new workflow
2. **Update docs/prd-catalog-system.md** with any changes
3. **Create docs/catalog-queries.md** with useful DuckDB queries

### Deliverables
- [ ] All scripts tested
- [ ] Edge cases handled
- [ ] CLAUDE.md updated
- [ ] Example DuckDB queries documented

---

## Summary: Script Changes

| Script | Action | Phase |
|--------|--------|-------|
| `scripts/lib/catalog-utils.sh` | **CREATE** | 2 |
| `scripts/extract-semgrep-findings.sh` | **REWRITE** (DuckDB) | 3 |
| `scripts/extract-trufflehog-findings.sh` | **REWRITE** (DuckDB) | 4 |
| `scripts/extract-kics-findings.sh` | **REWRITE** (DuckDB) | 5 |
| `scripts/extract-artifact-findings.sh` | **REWRITE** (DuckDB) | 6 |
| `scripts/clone-org-repos.sh` | **MODIFY** (--catalog) | 7 |
| `scripts/scan-all.sh` | **MODIFY** (--output-dir) | 8 |
| `scripts/catalog-track.sh` | **CREATE** | 9 |
| `scripts/catalog-scan.sh` | **CREATE** | 10 |
| `scripts/catalog-status.sh` | **CREATE** | 11 |
| `scripts/catalog-diff.sh` | **CREATE** | 12 |
| `scripts/catalog-refresh.sh` | **CREATE** | 13 |
| `scripts/catalog-untrack.sh` | **CREATE** | 14 |

---

## Estimated Effort

| Phase | Description | Complexity |
|-------|-------------|------------|
| 1 | Infrastructure | Low |
| 2 | Library functions | Medium |
| 3-6 | DuckDB migration (4 scripts) | Medium each |
| 7-8 | Modify existing scripts | Low each |
| 9-14 | New catalog scripts (6 scripts) | Medium each |
| 15 | Testing and docs | Medium |

**Total new/modified scripts**: 14
**Total lines of code**: ~1,500-2,000 (estimated)
