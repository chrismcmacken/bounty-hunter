#!/usr/bin/env bash
# Extract KICS IaC findings from JSON result files using DuckDB
# Usage: ./scripts/extract-kics-findings.sh <org-name> [format] [repo-name]
#
# Examples:
#   ./scripts/extract-kics-findings.sh myorg              # All repos, summary format
#   ./scripts/extract-kics-findings.sh myorg resources    # Extract resource identifiers
#   ./scripts/extract-kics-findings.sh myorg summary repo # Specific repo

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/extract-common.sh
source "$SCRIPT_DIR/lib/extract-common.sh"

# Script-specific configuration (used by extract-common.sh)
# shellcheck disable=SC2034
RESULTS_TYPE="kics-results"
# shellcheck disable=SC2034
CATALOG_FILE="kics.json.gz"
# shellcheck disable=SC2034
SCANNER_CMD="scan-kics.sh"
# shellcheck disable=SC2034
DEFAULT_FORMAT="summary"
# shellcheck disable=SC2034
AVAILABLE_FORMATS="summary   - Grouped by severity with file locations (default)
  count     - Just counts per repo by severity
  resources - Extract resource identifiers for verification
  full      - Full JSON for each finding
  queries   - Top queries by finding count"

extract_init "$@"

# Build the read_json call
READ_JSON="$(read_json_opts)"

case "$FORMAT" in
    count)
        duckdb -c "
            SELECT
                regexp_extract(filename, '([^/]+)\\.json(\\.gz)?\$', 1) as repo,
                COALESCE(total_counter, 0) as total,
                COALESCE(severity_counters.HIGH, 0) as high,
                COALESCE(severity_counters.MEDIUM, 0) as medium,
                COALESCE(severity_counters.LOW, 0) as low
            FROM $READ_JSON
            WHERE total_counter > 0
            ORDER BY high DESC, medium DESC, total DESC
        " 2>/dev/null || echo "No findings found."

        if [[ -z "$REPO" ]]; then
            totals=$(duckdb_scalar "
                SELECT
                    COALESCE(SUM(total_counter), 0) || ',' ||
                    COALESCE(SUM(severity_counters.HIGH), 0) || ',' ||
                    COALESCE(SUM(severity_counters.MEDIUM), 0) || ',' ||
                    COALESCE(SUM(severity_counters.LOW), 0)
                FROM $READ_JSON
            ")
            total=$(echo "$totals" | cut -d',' -f1)
            high=$(echo "$totals" | cut -d',' -f2)
            medium=$(echo "$totals" | cut -d',' -f3)
            low=$(echo "$totals" | cut -d',' -f4)
            echo ""
            echo "Total: ${total:-0} findings (HIGH: ${high:-0}, MEDIUM: ${medium:-0}, LOW: ${low:-0})"
            echo ""
            echo "IMPORTANT: IaC findings are reconnaissance, not vulnerabilities."
            echo "Use 'resources' format to extract identifiers for verification."
        fi
        ;;

    summary)
        duckdb -c "
            WITH query_data AS (
                SELECT
                    regexp_extract(filename, '([^/]+)\\.json(\\.gz)?\$', 1) as repo,
                    unnest.severity as severity,
                    unnest.query_name as query_name,
                    unnest.files as files
                FROM $READ_JSON,
                UNNEST(queries)
            )
            SELECT
                repo,
                severity,
                query_name as query,
                unnest.file_name as file,
                unnest.line as line,
                unnest.issue_type as issue
            FROM query_data,
            UNNEST(files)
            ORDER BY
                repo,
                CASE severity
                    WHEN 'HIGH' THEN 1
                    WHEN 'MEDIUM' THEN 2
                    WHEN 'LOW' THEN 3
                    ELSE 4
                END,
                query_name,
                unnest.file_name
        " 2>/dev/null || echo "No findings found."

        if [[ -z "$REPO" ]]; then
            totals=$(duckdb_scalar "
                SELECT
                    COALESCE(SUM(total_counter), 0) || ',' ||
                    COALESCE(SUM(severity_counters.HIGH), 0) || ',' ||
                    COALESCE(SUM(severity_counters.MEDIUM), 0) || ',' ||
                    COALESCE(SUM(severity_counters.LOW), 0)
                FROM $READ_JSON
            ")
            total=$(echo "$totals" | cut -d',' -f1)
            high=$(echo "$totals" | cut -d',' -f2)
            medium=$(echo "$totals" | cut -d',' -f3)
            low=$(echo "$totals" | cut -d',' -f4)
            echo ""
            echo "Total: ${total:-0} findings (HIGH: ${high:-0}, MEDIUM: ${medium:-0}, LOW: ${low:-0})"
        fi
        ;;

    resources)
        echo "Resource identifiers for verification:"
        echo ""

        # Storage resources (S3, GCS, Azure)
        echo "=== Storage Resources ==="
        duckdb -c "
            WITH query_data AS (
                SELECT
                    regexp_extract(filename, '([^/]+)\\.json(\\.gz)?\$', 1) as repo,
                    unnest.platform,
                    unnest.query_name,
                    unnest.files
                FROM $READ_JSON,
                UNNEST(queries)
            )
            SELECT DISTINCT
                repo,
                platform,
                unnest.file_name,
                unnest.line,
                COALESCE(unnest.search_value, unnest.search_key) as resource_ref
            FROM query_data,
            UNNEST(files)
            WHERE query_name ILIKE '%bucket%'
               OR query_name ILIKE '%storage%'
               OR query_name ILIKE '%s3%'
               OR query_name ILIKE '%blob%'
            ORDER BY repo, unnest.file_name
        " 2>/dev/null || echo "  (none)"
        echo ""

        # Security groups / network
        echo "=== Network / Security Groups ==="
        duckdb -c "
            WITH query_data AS (
                SELECT
                    regexp_extract(filename, '([^/]+)\\.json(\\.gz)?\$', 1) as repo,
                    unnest.query_name,
                    unnest.files
                FROM $READ_JSON,
                UNNEST(queries)
            )
            SELECT DISTINCT
                repo,
                query_name,
                unnest.file_name || ':' || unnest.line as location
            FROM query_data,
            UNNEST(files)
            WHERE query_name ILIKE '%security group%'
               OR query_name ILIKE '%ingress%'
               OR query_name ILIKE '%0.0.0.0%'
               OR query_name ILIKE '%firewall%'
            ORDER BY repo, unnest.file_name
        " 2>/dev/null || echo "  (none)"
        echo ""

        # IAM / RBAC
        echo "=== IAM / RBAC ==="
        duckdb -c "
            WITH query_data AS (
                SELECT
                    regexp_extract(filename, '([^/]+)\\.json(\\.gz)?\$', 1) as repo,
                    unnest.query_name,
                    unnest.files
                FROM $READ_JSON,
                UNNEST(queries)
            )
            SELECT DISTINCT
                repo,
                query_name,
                unnest.file_name || ':' || unnest.line as location
            FROM query_data,
            UNNEST(files)
            WHERE query_name ILIKE '%iam%'
               OR query_name ILIKE '%role%'
               OR query_name ILIKE '%policy%'
               OR query_name ILIKE '%rbac%'
               OR query_name ILIKE '%privilege%'
            ORDER BY repo, unnest.file_name
        " 2>/dev/null || echo "  (none)"
        echo ""

        # Kubernetes
        echo "=== Kubernetes / Container ==="
        duckdb -c "
            WITH query_data AS (
                SELECT
                    regexp_extract(filename, '([^/]+)\\.json(\\.gz)?\$', 1) as repo,
                    unnest.platform,
                    unnest.query_name,
                    unnest.files
                FROM $READ_JSON,
                UNNEST(queries)
            )
            SELECT DISTINCT
                repo,
                query_name,
                unnest.file_name || ':' || unnest.line as location
            FROM query_data,
            UNNEST(files)
            WHERE platform ILIKE '%kubernetes%'
               OR platform ILIKE '%helm%'
               OR platform ILIKE '%docker%'
            ORDER BY repo, query_name
        " 2>/dev/null || echo "  (none)"
        ;;

    full)
        duckdb -json -c "
            WITH query_data AS (
                SELECT
                    regexp_extract(filename, '([^/]+)\\.json(\\.gz)?\$', 1) as repo,
                    unnest.severity,
                    unnest.query_name,
                    unnest.platform,
                    unnest.category,
                    unnest.description,
                    unnest.files
                FROM $READ_JSON,
                UNNEST(queries)
            )
            SELECT
                repo,
                severity,
                query_name,
                platform,
                category,
                description,
                unnest.file_name,
                unnest.line,
                unnest.issue_type,
                unnest.search_key,
                unnest.search_value
            FROM query_data,
            UNNEST(files)
            ORDER BY
                repo,
                CASE severity WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END,
                query_name
        " 2>/dev/null | jq '.'
        ;;

    queries)
        echo "Top queries by finding count:"
        echo ""
        duckdb -c "
            WITH query_data AS (
                SELECT
                    unnest.severity,
                    unnest.query_name,
                    unnest.platform,
                    unnest.files
                FROM $READ_JSON,
                UNNEST(queries)
            )
            SELECT
                severity,
                query_name,
                platform,
                count(*) as count
            FROM query_data,
            UNNEST(files)
            GROUP BY severity, query_name, platform
            ORDER BY
                CASE severity WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END,
                count DESC
            LIMIT 30
        " 2>/dev/null || echo "No findings found."
        ;;

    *)
        unknown_format "$FORMAT"
        ;;
esac
