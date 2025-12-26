#!/usr/bin/env bash
# Extract artifact findings from JSON result files using DuckDB
# Usage: ./scripts/extract-artifact-findings.sh <org-name> [format] [repo-name]
#
# Examples:
#   ./scripts/extract-artifact-findings.sh myorg              # All repos, summary format
#   ./scripts/extract-artifact-findings.sh myorg archives     # List only archives
#   ./scripts/extract-artifact-findings.sh myorg summary repo # Specific repo

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/extract-common.sh
source "$SCRIPT_DIR/lib/extract-common.sh"

# Script-specific configuration (used by extract-common.sh)
# shellcheck disable=SC2034
RESULTS_TYPE="artifact-results"
# shellcheck disable=SC2034
CATALOG_FILE="artifacts.json.gz"
# shellcheck disable=SC2034
SCANNER_CMD="scan-artifacts.sh"
# shellcheck disable=SC2034
DEFAULT_FORMAT="summary"
# shellcheck disable=SC2034
AVAILABLE_FORMATS="summary   - Overview by category (default)
  count     - Just counts per repo
  archives  - List only archives needing extraction
  sql       - List only SQL dumps for PII review
  sources   - List only source code backups
  databases - List only binary databases
  full      - Full JSON output"

extract_init "$@"

# Build the read_json call
READ_JSON="$(read_json_opts)"

# For catalog mode, we need to UNNEST the repos array first
# Catalog format: {repos: [{repo, archives, ...}, ...], totals: {...}}
# Findings format: {repo, archives, databases, sql_dumps, source_backups} per file
if [[ -n "$CATALOG_MODE" ]]; then
    # Catalog mode: UNNEST the repos array with proper struct extraction
    BASE_QUERY="(SELECT r.repo, r.archives, r.databases, r.sql_dumps, r.source_backups FROM $READ_JSON, UNNEST(repos) as t(r))"
else
    # Findings mode: each file is already a repo object
    BASE_QUERY="$READ_JSON"
fi

case "$FORMAT" in
    count)
        run_duckdb "
            SELECT
                repo,
                COALESCE(len(archives), 0) as archives,
                COALESCE(len(databases), 0) as databases,
                COALESCE(len(sql_dumps), 0) as sql_dumps,
                COALESCE(len(source_backups), 0) as sources
            FROM $BASE_QUERY
            WHERE len(archives) > 0 OR len(databases) > 0 OR len(sql_dumps) > 0 OR len(source_backups) > 0
            ORDER BY archives DESC, databases DESC, sql_dumps DESC
        " || echo "No findings found."

        if [[ -z "$REPO" ]]; then
            totals=$(duckdb_scalar "
                SELECT
                    COALESCE(SUM(len(archives)), 0) || ',' ||
                    COALESCE(SUM(len(databases)), 0) || ',' ||
                    COALESCE(SUM(len(sql_dumps)), 0) || ',' ||
                    COALESCE(SUM(len(source_backups)), 0)
                FROM $BASE_QUERY
            ")
            archives=$(echo "$totals" | cut -d',' -f1)
            databases=$(echo "$totals" | cut -d',' -f2)
            sql=$(echo "$totals" | cut -d',' -f3)
            sources=$(echo "$totals" | cut -d',' -f4)
            echo ""
            echo "Totals: ${archives:-0} archives, ${databases:-0} databases, ${sql:-0} SQL dumps, ${sources:-0} source backups"
        fi
        ;;

    summary)
        run_duckdb "
            SELECT
                repo,
                'ARCHIVE' as type,
                unnest.path::VARCHAR as path,
                unnest.size::VARCHAR || ' bytes' as info
            FROM $BASE_QUERY,
            UNNEST(archives)
            WHERE len(archives) > 0

            UNION ALL

            SELECT
                repo,
                'DATABASE' as type,
                unnest.path::VARCHAR as path,
                '' as info
            FROM $BASE_QUERY,
            UNNEST(databases)
            WHERE len(databases) > 0

            UNION ALL

            SELECT
                repo,
                'SQL_DUMP' as type,
                unnest.path::VARCHAR as path,
                CASE WHEN unnest.has_data THEN '[CONTAINS DATA]' ELSE '' END as info
            FROM $BASE_QUERY,
            UNNEST(sql_dumps)
            WHERE len(sql_dumps) > 0

            UNION ALL

            SELECT
                repo,
                'SOURCE_BACKUP' as type,
                unnest.path::VARCHAR as path,
                '' as info
            FROM $BASE_QUERY,
            UNNEST(source_backups)
            WHERE len(source_backups) > 0

            ORDER BY repo, type, path
        " || echo "No findings found."

        if [[ -z "$REPO" ]]; then
            totals=$(duckdb_scalar "
                SELECT
                    COALESCE(SUM(len(archives)), 0) || ',' ||
                    COALESCE(SUM(len(databases)), 0) || ',' ||
                    COALESCE(SUM(len(sql_dumps)), 0) || ',' ||
                    COALESCE(SUM(len(source_backups)), 0)
                FROM $BASE_QUERY
            ")
            archives=$(echo "$totals" | cut -d',' -f1)
            databases=$(echo "$totals" | cut -d',' -f2)
            sql=$(echo "$totals" | cut -d',' -f3)
            sources=$(echo "$totals" | cut -d',' -f4)
            echo ""
            echo "Totals: ${archives:-0} archives, ${databases:-0} databases, ${sql:-0} SQL dumps, ${sources:-0} source backups"
            echo ""
            echo "Use 'archives' format to extract and scan with trufflehog."
        fi
        ;;

    archives)
        echo "Archives requiring extraction and scanning:"
        echo ""
        run_duckdb "
            SELECT
                repo,
                unnest.path as path,
                unnest.size as size_bytes
            FROM $BASE_QUERY,
            UNNEST(archives)
            ORDER BY repo, unnest.path
        " || echo "  (none)"

        count=$(duckdb_scalar "
            SELECT COALESCE(SUM(len(archives)), 0)
            FROM $BASE_QUERY
        ")
        if [[ "${count:-0}" != "0" ]]; then
            echo ""
            echo "Total: $count archives"
            echo "Run: ./scripts/extract-and-scan-archives.sh $ORG [repo]"
        fi
        ;;

    sql)
        echo "SQL dumps for PII review:"
        echo ""
        run_duckdb "
            SELECT
                repo,
                unnest.path as path,
                CASE WHEN unnest.has_data THEN '[CONTAINS DATA]' ELSE '[schema only]' END as status
            FROM $BASE_QUERY,
            UNNEST(sql_dumps)
            ORDER BY unnest.has_data DESC, repo, unnest.path
        " || echo "  (none)"

        counts=$(duckdb_scalar "
            SELECT
                COUNT(*) || ',' || SUM(CASE WHEN unnest.has_data THEN 1 ELSE 0 END)
            FROM $BASE_QUERY,
            UNNEST(sql_dumps)
        ")
        total=$(echo "$counts" | cut -d',' -f1)
        with_data=$(echo "$counts" | cut -d',' -f2)
        if [[ "${total:-0}" != "0" ]]; then
            echo ""
            echo "Total: $total SQL dumps (${with_data:-0} contain data)"
        fi
        ;;

    sources)
        echo "Source code backups (may contain old vulnerabilities):"
        echo ""
        run_duckdb "
            SELECT
                repo,
                unnest.path as path
            FROM $BASE_QUERY,
            UNNEST(source_backups)
            ORDER BY repo, unnest.path
        " || echo "  (none)"

        count=$(duckdb_scalar "
            SELECT COALESCE(SUM(len(source_backups)), 0)
            FROM $BASE_QUERY
        ")
        if [[ "${count:-0}" != "0" ]]; then
            print_total "source backups" "$count"
        fi
        ;;

    databases)
        echo "Binary databases (manual inspection needed):"
        echo ""
        run_duckdb "
            SELECT
                repo,
                unnest.path as path
            FROM $BASE_QUERY,
            UNNEST(databases)
            ORDER BY repo, unnest.path
        " || echo "  (none)"

        count=$(duckdb_scalar "
            SELECT COALESCE(SUM(len(databases)), 0)
            FROM $BASE_QUERY
        ")
        if [[ "${count:-0}" != "0" ]]; then
            print_total "binary databases" "$count"
        fi
        ;;

    full)
        duckdb -json -c "
            SELECT *
            FROM $BASE_QUERY
            ORDER BY repo
        " 2>/dev/null | jq '.'
        ;;

    *)
        unknown_format "$FORMAT"
        ;;
esac
