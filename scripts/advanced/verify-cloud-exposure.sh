#!/usr/bin/env bash
set -euo pipefail

# Verify cloud resource exposure
#
# Takes extracted cloud resources and tests if they are actually
# publicly accessible (not just misconfigured in code).
#
# Usage: ./scripts/verify-cloud-exposure.sh <org>
# Input: findings/<org>/cloud-resources.json
# Output: findings/<org>/exposed-resources.json

show_help() {
    cat << 'EOF'
Usage: ./scripts/verify-cloud-exposure.sh <org-name> [options]

Test cloud resources for actual public exposure.

Options:
  --timeout <sec>    Request timeout in seconds (default: 5)
  --skip-s3          Skip S3 bucket testing
  --skip-gcs         Skip GCS bucket testing
  --skip-azure       Skip Azure storage testing
  -h, --help         Show this help

Prerequisites:
  Run ./scripts/extract-cloud-resources.sh first to generate cloud-resources.json

What it tests:
  - S3 buckets: Anonymous listing and object access
  - GCS buckets: Public access
  - Azure storage: Anonymous container listing
  - Ingress hosts: HTTP(S) reachability

Output:
  findings/<org>/exposed-resources.json

Examples:
  ./scripts/verify-cloud-exposure.sh acme-corp
  ./scripts/verify-cloud-exposure.sh acme-corp --timeout 10
EOF
    exit 0
}

if [[ $# -lt 1 ]]; then
    show_help
fi

ORG="$1"
shift

# Defaults
TIMEOUT=5
SKIP_S3=""
SKIP_GCS=""
SKIP_AZURE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --timeout) TIMEOUT="$2"; shift 2 ;;
        --skip-s3) SKIP_S3="1"; shift ;;
        --skip-gcs) SKIP_GCS="1"; shift ;;
        --skip-azure) SKIP_AZURE="1"; shift ;;
        -h|--help) show_help ;;
        *) echo "Unknown option: $1"; show_help ;;
    esac
done

INPUT_FILE="$(pwd)/findings/$ORG/cloud-resources.json"
OUTPUT_FILE="$(pwd)/findings/$ORG/exposed-resources.json"

if [[ ! -f "$INPUT_FILE" ]]; then
    echo "Error: Cloud resources file not found: $INPUT_FILE"
    echo "Run ./scripts/extract-cloud-resources.sh $ORG first"
    exit 1
fi

RESOURCE_COUNT=$(jq '.resource_count // 0' "$INPUT_FILE")
if [[ "$RESOURCE_COUNT" -eq 0 ]]; then
    echo "No cloud resources found to test"
    exit 0
fi

echo "========================================"
echo "Cloud Exposure Verification: $ORG"
echo "========================================"
echo "Resources to test: $RESOURCE_COUNT"
echo "Timeout: ${TIMEOUT}s"
echo ""

# Initialize output
cat > "$OUTPUT_FILE" << EOF
{
  "verification_time": "$(date -Iseconds)",
  "tested_count": 0,
  "exposed_count": 0,
  "exposed_resources": []
}
EOF

TEMP_EXPOSED=$(mktemp)
echo "[]" > "$TEMP_EXPOSED"

tested=0
exposed=0

add_exposed() {
    local type="$1"
    local name="$2"
    local source_file="$3"
    local status="$4"
    local details="$5"
    local impact="$6"

    jq --arg type "$type" \
       --arg name "$name" \
       --arg file "$source_file" \
       --arg status "$status" \
       --arg details "$details" \
       --arg impact "$impact" \
       '. += [{
         "type": $type,
         "name": $name,
         "source_file": $file,
         "exposure_status": $status,
         "test_details": $details,
         "impact": $impact
       }]' "$TEMP_EXPOSED" > "${TEMP_EXPOSED}.tmp" && mv "${TEMP_EXPOSED}.tmp" "$TEMP_EXPOSED"
}

# Test S3 buckets
test_s3_bucket() {
    local bucket="$1"
    local source_file="$2"

    ((tested++))
    echo -n "  [S3] $bucket ... "

    # Test 1: Try anonymous listing
    local list_result
    list_result=$(aws s3 ls "s3://$bucket" --no-sign-request 2>&1 || true)

    if [[ "$list_result" != *"AccessDenied"* && "$list_result" != *"NoSuchBucket"* && -n "$list_result" ]]; then
        echo "PUBLIC_LIST"
        local object_count
        object_count=$(echo "$list_result" | wc -l | xargs)
        add_exposed "s3_bucket" "$bucket" "$source_file" "PUBLIC_LIST" \
            "Anonymous listing succeeded. $object_count objects visible." \
            "HIGH - Bucket contents publicly enumerable"
        ((exposed++))
        return
    fi

    # Test 2: Check if bucket exists (HEAD request)
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$TIMEOUT" \
        "https://$bucket.s3.amazonaws.com" 2>/dev/null || echo "000")

    case "$http_code" in
        200)
            echo "PUBLIC_READ"
            add_exposed "s3_bucket" "$bucket" "$source_file" "PUBLIC_READ" \
                "Bucket returns 200 on anonymous request" \
                "HIGH - Bucket publicly readable"
            ((exposed++))
            ;;
        403)
            echo "exists (private)"
            # Bucket exists but is private - not exposed, but confirmed real
            ;;
        404)
            echo "not found"
            ;;
        *)
            echo "unknown ($http_code)"
            ;;
    esac
}

# Test GCS buckets
test_gcs_bucket() {
    local bucket="$1"
    local source_file="$2"

    ((tested++))
    echo -n "  [GCS] $bucket ... "

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$TIMEOUT" \
        "https://storage.googleapis.com/$bucket" 2>/dev/null || echo "000")

    case "$http_code" in
        200)
            echo "PUBLIC"
            # Try to get listing
            local listing
            listing=$(curl -s --max-time "$TIMEOUT" "https://storage.googleapis.com/$bucket" 2>/dev/null | head -c 500)
            add_exposed "gcs_bucket" "$bucket" "$source_file" "PUBLIC" \
                "Bucket publicly accessible" \
                "HIGH - GCS bucket publicly readable"
            ((exposed++))
            ;;
        403)
            echo "exists (private)"
            ;;
        404)
            echo "not found"
            ;;
        *)
            echo "unknown ($http_code)"
            ;;
    esac
}

# Test Azure storage
test_azure_storage() {
    local account="$1"
    local source_file="$2"

    ((tested++))
    echo -n "  [Azure] $account ... "

    # Test blob service endpoint
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$TIMEOUT" \
        "https://$account.blob.core.windows.net/?comp=list" 2>/dev/null || echo "000")

    case "$http_code" in
        200)
            echo "PUBLIC_LIST"
            add_exposed "azure_storage" "$account" "$source_file" "PUBLIC_LIST" \
                "Container listing enabled" \
                "HIGH - Azure storage publicly enumerable"
            ((exposed++))
            ;;
        403|409)
            echo "exists (private)"
            ;;
        404|400)
            echo "not found"
            ;;
        *)
            echo "unknown ($http_code)"
            ;;
    esac
}

# Test ingress hosts
test_ingress_host() {
    local host="$1"
    local source_file="$2"

    ((tested++))
    echo -n "  [Host] $host ... "

    # Test HTTPS first, then HTTP
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$TIMEOUT" \
        -k "https://$host" 2>/dev/null || echo "000")

    if [[ "$http_code" == "000" ]]; then
        http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$TIMEOUT" \
            "http://$host" 2>/dev/null || echo "000")
    fi

    case "$http_code" in
        200|301|302|401|403)
            echo "REACHABLE ($http_code)"
            add_exposed "ingress_host" "$host" "$source_file" "REACHABLE" \
                "Host responds with HTTP $http_code" \
                "INFO - Host is publicly reachable (verify authorization)"
            ((exposed++))
            ;;
        000)
            echo "unreachable"
            ;;
        *)
            echo "responds ($http_code)"
            ;;
    esac
}

# Process resources by type
echo "Testing S3 buckets..."
if [[ -z "$SKIP_S3" ]]; then
    while IFS= read -r resource; do
        name=$(echo "$resource" | jq -r '.name')
        source_file=$(echo "$resource" | jq -r '.source_file')
        test_s3_bucket "$name" "$source_file"
    done < <(jq -c '.resources[] | select(.type == "s3_bucket")' "$INPUT_FILE")
else
    echo "  (skipped)"
fi

echo ""
echo "Testing GCS buckets..."
if [[ -z "$SKIP_GCS" ]]; then
    while IFS= read -r resource; do
        name=$(echo "$resource" | jq -r '.name')
        source_file=$(echo "$resource" | jq -r '.source_file')
        test_gcs_bucket "$name" "$source_file"
    done < <(jq -c '.resources[] | select(.type == "gcs_bucket")' "$INPUT_FILE")
else
    echo "  (skipped)"
fi

echo ""
echo "Testing Azure storage..."
if [[ -z "$SKIP_AZURE" ]]; then
    while IFS= read -r resource; do
        name=$(echo "$resource" | jq -r '.name')
        source_file=$(echo "$resource" | jq -r '.source_file')
        test_azure_storage "$name" "$source_file"
    done < <(jq -c '.resources[] | select(.type == "azure_storage")' "$INPUT_FILE")
else
    echo "  (skipped)"
fi

echo ""
echo "Testing ingress hosts..."
while IFS= read -r resource; do
    name=$(echo "$resource" | jq -r '.name')
    source_file=$(echo "$resource" | jq -r '.source_file')
    test_ingress_host "$name" "$source_file"
done < <(jq -c '.resources[] | select(.type == "k8s_ingress_host")' "$INPUT_FILE")

# Finalize output
jq --slurpfile exposed "$TEMP_EXPOSED" \
   --argjson tested "$tested" \
   --argjson exposed_count "$exposed" \
   '.tested_count = $tested | .exposed_count = $exposed_count | .exposed_resources = $exposed[0]' \
   "$OUTPUT_FILE" > "${OUTPUT_FILE}.tmp" && mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"

rm -f "$TEMP_EXPOSED"

echo ""
echo "========================================"
echo "Summary"
echo "========================================"
echo "Tested: $tested"
echo "Exposed: $exposed"

if [[ "$exposed" -gt 0 ]]; then
    echo ""
    echo "*** EXPOSED RESOURCES FOUND ***"
    echo ""
    jq -r '.exposed_resources[] | "[\(.exposure_status)] \(.type): \(.name)\n  Source: \(.source_file)\n  Impact: \(.impact)\n"' "$OUTPUT_FILE"
fi

echo ""
echo "Output: $OUTPUT_FILE"
