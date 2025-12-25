# OSV.dev API Reference

Quick reference for querying the OSV.dev vulnerability database.

## Base URL

```
https://api.osv.dev
```

No authentication required. No rate limits, but respect SLOs.

## Endpoints

### POST /v1/query - Single Package Query

Query vulnerabilities for a single package.

**Request:**
```bash
curl -s "https://api.osv.dev/v1/query" -d '{
  "package": {
    "name": "jinja2",
    "ecosystem": "PyPI"
  }
}'
```

**Or with PURL:**
```bash
curl -s "https://api.osv.dev/v1/query" -d '{
  "package": {
    "purl": "pkg:pypi/jinja2@3.0.0"
  }
}'
```

**Response:**
```json
{
  "vulns": [
    {
      "id": "CVE-2024-XXXXX",
      "summary": "...",
      "details": "...",
      "aliases": ["GHSA-xxxx-xxxx-xxxx"],
      "modified": "2024-12-20T00:00:00Z",
      "published": "2024-12-15T00:00:00Z",
      "references": [...],
      "affected": [...],
      "severity": [...]
    }
  ]
}
```

### POST /v1/querybatch - Batch Query

Query multiple packages at once (up to 1000 per request).

**Request:**
```bash
curl -s "https://api.osv.dev/v1/querybatch" -d '{
  "queries": [
    {"package": {"purl": "pkg:pypi/jinja2@3.0.0"}},
    {"package": {"purl": "pkg:pypi/flask@2.0.0"}},
    {"package": {"purl": "pkg:npm/lodash@4.17.15"}}
  ]
}'
```

**Response:**
```json
{
  "results": [
    {
      "vulns": [
        {"id": "CVE-2024-XXXXX", "modified": "2024-12-20T00:00:00Z"}
      ]
    },
    {
      "vulns": []
    },
    {
      "vulns": [
        {"id": "CVE-2024-YYYYY", "modified": "2024-12-18T00:00:00Z"}
      ]
    }
  ]
}
```

**Notes:**
- Results array order matches queries array order
- Batch response only includes `id` and `modified` - fetch full details separately
- Use `next_page_token` for pagination if > 1000 results

### GET /v1/vulns/{id} - Get Vulnerability Details

Fetch full details for a specific vulnerability.

**Request:**
```bash
curl -s "https://api.osv.dev/v1/vulns/CVE-2024-XXXXX"
```

**Response:**
```json
{
  "id": "CVE-2024-XXXXX",
  "summary": "Code injection in Jinja2 template rendering",
  "details": "Full description of the vulnerability...",
  "aliases": ["GHSA-xxxx-xxxx-xxxx", "PYSEC-2024-XXX"],
  "modified": "2024-12-20T00:00:00Z",
  "published": "2024-12-15T00:00:00Z",
  "references": [
    {
      "type": "ADVISORY",
      "url": "https://github.com/advisories/GHSA-xxxx-xxxx-xxxx"
    },
    {
      "type": "FIX",
      "url": "https://github.com/pallets/jinja/commit/abc123def456"
    },
    {
      "type": "WEB",
      "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-XXXXX"
    }
  ],
  "affected": [
    {
      "package": {
        "ecosystem": "PyPI",
        "name": "jinja2",
        "purl": "pkg:pypi/jinja2"
      },
      "ranges": [
        {
          "type": "ECOSYSTEM",
          "events": [
            {"introduced": "0"},
            {"fixed": "3.1.3"}
          ]
        }
      ],
      "versions": ["3.0.0", "3.0.1", "3.0.2", "3.1.0", "3.1.1", "3.1.2"]
    }
  ],
  "severity": [
    {
      "type": "CVSS_V3",
      "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    }
  ],
  "database_specific": {
    "cwe_ids": ["CWE-94"],
    "severity": "CRITICAL"
  }
}
```

## Key Response Fields

### Vulnerability Object

| Field | Description |
|-------|-------------|
| `id` | Primary identifier (CVE-XXXX-NNNNN or GHSA-xxxx-xxxx-xxxx) |
| `aliases` | Alternative identifiers |
| `summary` | Short description |
| `details` | Full description |
| `modified` | Last modification timestamp |
| `published` | Publication timestamp |
| `references` | Links to advisories, fixes, etc. |
| `affected` | Affected packages and versions |
| `severity` | CVSS scores |

### Reference Types

| Type | Description |
|------|-------------|
| `ADVISORY` | Security advisory |
| `FIX` | Fix commit or PR |
| `REPORT` | Bug report |
| `WEB` | General web link |
| `PACKAGE` | Package registry link |

### Affected Ranges

```json
{
  "type": "ECOSYSTEM",
  "events": [
    {"introduced": "0"},      // Vulnerable from version 0
    {"fixed": "3.1.3"}        // Fixed in version 3.1.3
  ]
}
```

Or with SEMVER:
```json
{
  "type": "SEMVER",
  "events": [
    {"introduced": "2.0.0"},
    {"fixed": "2.1.5"}
  ]
}
```

## Extracting Key Information

### Get CVSS Score

```bash
# From severity array
jq '.severity[] | select(.type == "CVSS_V3") | .score' response.json

# Parse CVSS string for numeric score
# CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8
```

### Get Fix Commit

```bash
# From references array
jq '.references[] | select(.type == "FIX") | .url' response.json
```

### Get CWE

```bash
# From database_specific
jq '.database_specific.cwe_ids[]' response.json
```

### Get Fixed Version

```bash
# From affected ranges
jq '.affected[0].ranges[0].events[] | select(.fixed) | .fixed' response.json
```

## SLOs (Service Level Objectives)

| Endpoint | P50 | P90 | P95 |
|----------|-----|-----|-----|
| GET /v1/vulns/{id} | 100ms | 200ms | 500ms |
| POST /v1/query | 300ms | 500ms | 1s |
| POST /v1/querybatch | 500ms | 4s | 6s |

## Best Practices

1. **Use batch queries** for multiple packages (more efficient)
2. **Add delays** between requests (100-200ms) to be respectful
3. **Cache results** - vulnerability details rarely change
4. **Handle pagination** for large result sets
5. **Use PURLs** when available (more precise than name+ecosystem)

## Example: Full Discovery Workflow

```bash
# 1. Query for recent Python vulnerabilities
curl -s "https://api.osv.dev/v1/query" -d '{
  "package": {"ecosystem": "PyPI"}
}' | jq '.vulns | length'

# 2. Get details for specific CVE
curl -s "https://api.osv.dev/v1/vulns/CVE-2024-XXXXX" > cve-details.json

# 3. Extract key fields
echo "Package: $(jq -r '.affected[0].package.name' cve-details.json)"
echo "Fixed in: $(jq -r '.affected[0].ranges[0].events[] | select(.fixed) | .fixed' cve-details.json)"
echo "Fix commit: $(jq -r '.references[] | select(.type == "FIX") | .url' cve-details.json)"
```
