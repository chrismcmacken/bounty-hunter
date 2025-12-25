#!/usr/bin/env bash
set -euo pipefail

# Extract cloud resource identifiers from IaC files
#
# Parses Terraform, CloudFormation, and Kubernetes files to extract
# actual resource names (S3 buckets, GCS buckets, security groups, etc.)
# that can be tested for public exposure.
#
# Usage: ./scripts/extract-cloud-resources.sh <org> [repo]
# Output: findings/<org>/cloud-resources.json

show_help() {
    cat << 'EOF'
Usage: ./scripts/extract-cloud-resources.sh <org-name> [repo-name]

Extract cloud resource identifiers from Infrastructure-as-Code files.

Arguments:
  org-name    Organization name (must have cloned repos)
  repo-name   Optional: specific repo to scan

What it extracts:
  - S3 bucket names (Terraform, CloudFormation)
  - GCS bucket names (Terraform)
  - Azure storage accounts (Terraform)
  - Security groups with open rules
  - Database endpoints
  - API Gateway endpoints

Output:
  findings/<org>/cloud-resources.json

Examples:
  ./scripts/extract-cloud-resources.sh acme-corp
  ./scripts/extract-cloud-resources.sh acme-corp infrastructure-repo
EOF
    exit 0
}

if [[ $# -lt 1 ]]; then
    show_help
fi

ORG="$1"
REPO="${2:-}"

ORG_DIR="$(pwd)/$ORG"
OUTPUT_DIR="$(pwd)/findings/$ORG"
OUTPUT_FILE="$OUTPUT_DIR/cloud-resources.json"

mkdir -p "$OUTPUT_DIR"

if [[ ! -d "$ORG_DIR" ]]; then
    echo "Error: Organization directory not found: $ORG_DIR"
    exit 1
fi

echo "========================================"
echo "Cloud Resource Extraction: $ORG"
echo "========================================"

# Initialize output
echo '{"resources": [], "extraction_time": "'$(date -Iseconds)'"}' > "$OUTPUT_FILE"

# Temp file for collecting resources
TEMP_RESOURCES=$(mktemp)
echo "[]" > "$TEMP_RESOURCES"

add_resource() {
    local type="$1"
    local name="$2"
    local source_file="$3"
    local provider="$4"

    # Add to temp file using jq
    jq --arg type "$type" \
       --arg name "$name" \
       --arg file "$source_file" \
       --arg provider "$provider" \
       '. += [{"type": $type, "name": $name, "source_file": $file, "provider": $provider}]' \
       "$TEMP_RESOURCES" > "${TEMP_RESOURCES}.tmp" && mv "${TEMP_RESOURCES}.tmp" "$TEMP_RESOURCES"
}

# Determine which directories to scan
if [[ -n "$REPO" ]]; then
    SCAN_DIRS=("$ORG_DIR/$REPO")
else
    SCAN_DIRS=("$ORG_DIR"/*)
fi

for repo_dir in "${SCAN_DIRS[@]}"; do
    [[ -d "$repo_dir" ]] || continue
    repo_name=$(basename "$repo_dir")

    echo "[$repo_name] Scanning for IaC files..."

    # ========================================
    # Terraform (.tf files)
    # ========================================

    while IFS= read -r tf_file; do
        [[ -f "$tf_file" ]] || continue
        rel_path="${tf_file#$ORG_DIR/}"

        # S3 Buckets
        # Pattern: bucket = "bucket-name" or bucket = var.xxx
        grep -oP 'bucket\s*=\s*"[^"]+"' "$tf_file" 2>/dev/null | while read -r match; do
            bucket_name=$(echo "$match" | grep -oP '"[^"]+"' | tr -d '"')
            if [[ -n "$bucket_name" && ! "$bucket_name" =~ ^\$ ]]; then
                add_resource "s3_bucket" "$bucket_name" "$rel_path" "aws"
            fi
        done

        # GCS Buckets
        grep -oP 'name\s*=\s*"[^"]+"' "$tf_file" 2>/dev/null | while read -r match; do
            # Only if in google_storage_bucket context (rough heuristic)
            if grep -q 'google_storage_bucket' "$tf_file" 2>/dev/null; then
                bucket_name=$(echo "$match" | grep -oP '"[^"]+"' | tr -d '"')
                if [[ -n "$bucket_name" && ! "$bucket_name" =~ ^\$ && ${#bucket_name} -gt 3 ]]; then
                    add_resource "gcs_bucket" "$bucket_name" "$rel_path" "gcp"
                fi
            fi
        done

        # Azure Storage Accounts
        grep -oP 'storage_account_name\s*=\s*"[^"]+"' "$tf_file" 2>/dev/null | while read -r match; do
            account_name=$(echo "$match" | grep -oP '"[^"]+"' | tr -d '"')
            if [[ -n "$account_name" && ! "$account_name" =~ ^\$ ]]; then
                add_resource "azure_storage" "$account_name" "$rel_path" "azure"
            fi
        done

        # Security Groups with 0.0.0.0/0
        if grep -q '0\.0\.0\.0/0' "$tf_file" 2>/dev/null; then
            # Try to extract the security group name
            sg_name=$(grep -oP 'name\s*=\s*"[^"]+"' "$tf_file" 2>/dev/null | head -1 | grep -oP '"[^"]+"' | tr -d '"')
            if [[ -n "$sg_name" ]]; then
                add_resource "security_group_open" "$sg_name" "$rel_path" "aws"
            fi
        fi

    done < <(find "$repo_dir" -name "*.tf" -type f 2>/dev/null)

    # ========================================
    # CloudFormation (.yaml, .yml, .json)
    # ========================================

    while IFS= read -r cf_file; do
        [[ -f "$cf_file" ]] || continue
        rel_path="${cf_file#$ORG_DIR/}"

        # Check if it's a CloudFormation template
        if grep -q 'AWSTemplateFormatVersion\|AWS::' "$cf_file" 2>/dev/null; then

            # S3 Buckets - look for BucketName
            grep -oP 'BucketName:\s*[^\n]+' "$cf_file" 2>/dev/null | while read -r match; do
                bucket_name=$(echo "$match" | sed 's/BucketName:\s*//' | tr -d "'" | tr -d '"' | xargs)
                if [[ -n "$bucket_name" && ! "$bucket_name" =~ ^\! ]]; then
                    add_resource "s3_bucket" "$bucket_name" "$rel_path" "aws"
                fi
            done

        fi
    done < <(find "$repo_dir" \( -name "*.yaml" -o -name "*.yml" -o -name "*.json" \) -type f 2>/dev/null)

    # ========================================
    # Kubernetes / Helm
    # ========================================

    while IFS= read -r k8s_file; do
        [[ -f "$k8s_file" ]] || continue
        rel_path="${k8s_file#$ORG_DIR/}"

        # Look for external hostnames/endpoints
        grep -oP 'host:\s*[^\n]+' "$k8s_file" 2>/dev/null | while read -r match; do
            hostname=$(echo "$match" | sed 's/host:\s*//' | tr -d "'" | tr -d '"' | xargs)
            if [[ -n "$hostname" && "$hostname" =~ \. ]]; then
                add_resource "k8s_ingress_host" "$hostname" "$rel_path" "kubernetes"
            fi
        done

    done < <(find "$repo_dir" \( -name "*.yaml" -o -name "*.yml" \) -path "*/k8s/*" -o -path "*/kubernetes/*" -o -path "*/helm/*" -type f 2>/dev/null)

    # ========================================
    # Docker Compose (exposed ports)
    # ========================================

    while IFS= read -r compose_file; do
        [[ -f "$compose_file" ]] || continue
        rel_path="${compose_file#$ORG_DIR/}"

        # Look for exposed ports
        grep -oP 'ports:\s*\n\s*-\s*"[^"]+"' "$compose_file" 2>/dev/null | while read -r match; do
            port=$(echo "$match" | grep -oP '"[^"]+"' | tr -d '"')
            if [[ -n "$port" ]]; then
                add_resource "docker_exposed_port" "$port" "$rel_path" "docker"
            fi
        done

    done < <(find "$repo_dir" -name "docker-compose*.yml" -o -name "docker-compose*.yaml" -type f 2>/dev/null)

done

# Deduplicate and finalize output
jq -s '.[0] | unique_by(.type + .name)' "$TEMP_RESOURCES" > "${TEMP_RESOURCES}.dedup"

# Build final output
jq --slurpfile resources "${TEMP_RESOURCES}.dedup" \
   '.resources = $resources[0] | .resource_count = ($resources[0] | length)' \
   "$OUTPUT_FILE" > "${OUTPUT_FILE}.tmp" && mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"

rm -f "$TEMP_RESOURCES" "${TEMP_RESOURCES}.dedup"

# Summary
RESOURCE_COUNT=$(jq '.resource_count' "$OUTPUT_FILE")

echo ""
echo "========================================"
echo "Summary"
echo "========================================"
echo "Resources found: $RESOURCE_COUNT"

if [[ "$RESOURCE_COUNT" -gt 0 ]]; then
    echo ""
    echo "By type:"
    jq -r '.resources | group_by(.type) | .[] | "  \(.[0].type): \(length)"' "$OUTPUT_FILE"
    echo ""
    echo "By provider:"
    jq -r '.resources | group_by(.provider) | .[] | "  \(.[0].provider): \(length)"' "$OUTPUT_FILE"
fi

echo ""
echo "Output: $OUTPUT_FILE"
echo ""
echo "Next: Verify exposure with ./scripts/verify-cloud-exposure.sh $ORG"
