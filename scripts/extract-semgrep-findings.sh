#!/usr/bin/env bash
# Extract semgrep findings from JSON result files using DuckDB
# Usage: ./scripts/extract-semgrep-findings.sh <org-name> [format] [repo-name]
#
# Examples:
#   ./scripts/extract-semgrep-findings.sh myorg              # All repos, summary format
#   ./scripts/extract-semgrep-findings.sh myorg full         # All repos, full format
#   ./scripts/extract-semgrep-findings.sh myorg summary repo # Specific repo

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/extract-common.sh
source "$SCRIPT_DIR/lib/extract-common.sh"

# Script-specific configuration (used by extract-common.sh)
# shellcheck disable=SC2034
RESULTS_TYPE="semgrep-results"
# shellcheck disable=SC2034
CATALOG_FILE="semgrep.json.gz"
# shellcheck disable=SC2034
SCANNER_CMD="scan-semgrep.sh"
# shellcheck disable=SC2034
DEFAULT_FORMAT="summary"
# shellcheck disable=SC2034
AVAILABLE_FORMATS="summary  - One line per finding with key details (default)
  full     - Full JSON for each finding
  count    - Just counts per repo
  jsonl    - One JSON object per line
  rules    - Top rules by finding count"

extract_init "$@"

# Build the read_json call
READ_JSON="$(read_json_opts)"

case "$FORMAT" in
    count)
        run_duckdb "
            SELECT
                regexp_extract(filename, '([^/]+)\\.json(\\.gz)?\$', 1) as repo,
                count(*) as findings
            FROM $READ_JSON,
            UNNEST(results)
            GROUP BY repo
            HAVING findings > 0
            ORDER BY findings DESC
        " || echo "No findings found."

        if [[ -z "$REPO" ]]; then
            total=$(duckdb_scalar "
                SELECT count(*)
                FROM $READ_JSON,
                UNNEST(results)
            ")
            print_total "findings" "${total:-0}"
        fi
        ;;

    summary)
        run_duckdb "
            SELECT
                regexp_extract(filename, '([^/]+)\\.json(\\.gz)?\$', 1) as repo,
                unnest.extra.severity as severity,
                unnest.check_id as rule,
                unnest.path || ':' || unnest.start.line as location,
                substring(unnest.extra.message, 1, 100) || '...' as message
            FROM $READ_JSON,
            UNNEST(results)
            ORDER BY
                CASE unnest.extra.severity
                    WHEN 'ERROR' THEN 1
                    WHEN 'WARNING' THEN 2
                    ELSE 3
                END,
                repo,
                unnest.path, unnest.start.line
        " || echo "No findings found."

        if [[ -z "$REPO" ]]; then
            total=$(duckdb_scalar "
                SELECT count(*)
                FROM $READ_JSON,
                UNNEST(results)
            ")
            print_total "findings" "${total:-0}"
        fi
        ;;

    full)
        duckdb -json -c "
            SELECT
                regexp_extract(filename, '([^/]+)\\.json(\\.gz)?\$', 1) as repo,
                unnest.check_id,
                unnest.path,
                unnest.start,
                unnest.\"end\",
                unnest.extra
            FROM $READ_JSON,
            UNNEST(results)
            ORDER BY repo, unnest.path, unnest.start.line
        " 2>/dev/null | jq '.'
        ;;

    jsonl)
        duckdb -json -c "
            SELECT
                regexp_extract(filename, '([^/]+)\\.json(\\.gz)?\$', 1) as repo,
                unnest.check_id,
                unnest.path,
                unnest.start,
                unnest.\"end\",
                unnest.extra
            FROM $READ_JSON,
            UNNEST(results)
            ORDER BY repo, unnest.path, unnest.start.line
        " 2>/dev/null | jq -c '.[]'
        ;;

    rules)
        echo "Top rules by finding count:"
        echo ""
        run_duckdb "
            SELECT
                unnest.check_id as rule,
                unnest.extra.severity as severity,
                count(*) as count
            FROM $READ_JSON,
            UNNEST(results)
            GROUP BY unnest.check_id, unnest.extra.severity
            ORDER BY count DESC
            LIMIT 20
        " || echo "No findings found."
        ;;

    *)
        unknown_format "$FORMAT"
        ;;
esac
