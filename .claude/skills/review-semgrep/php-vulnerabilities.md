# PHP-Specific Vulnerabilities

Reference guide for PHP security patterns when reviewing semgrep findings.

## Parser Differential: parse_url() Bypass

### The Vulnerability

PHP's `parse_url()` returns `FALSE` for malformed URLs that other parsers (curl, browsers) accept:

```
http://evil.com:000443/path
                ^^^^^^ leading zeros in port

parse_url()     → returns FALSE (invalid URL)
curl/browsers   → parses as evil.com:443 (valid!)
```

### Attack Pattern (SSRF Bypass)

1. Application uses `parse_url()` to extract host for allowlist validation
2. Attacker provides URL with leading zeros in port: `http://evil.com:000443/`
3. `parse_url()` returns `false`, validation logic may be bypassed
4. Original URL passed to `curl`/`file_get_contents` which parses it correctly
5. SSRF to attacker-controlled host succeeds

### Vulnerable Code Patterns

```php
// VULNERABLE: No false check - will error or return null
$host = parse_url($url)['host'];

// VULNERABLE: Null coalesce falls back to original URL
$host = parse_url($url)['host'] ?? $url;

// VULNERABLE: Validation bypassed when parse_url returns false
$parsed = parse_url($url);
if ($parsed['host'] === 'allowed.com') {
    curl_init($url);  // Attacker bypasses allowlist!
}

// VULNERABLE: Empty host check doesn't catch false
$parsed = parse_url($url);
if (!empty($parsed['host'])) {
    // validation
}
// Original $url still used below...
```

### Safe Patterns

```php
// SAFE: Strict false check with rejection
if (parse_url($url) === false) {
    throw new InvalidArgumentException('Invalid URL');
}

// SAFE: Combined with filter_var
if (filter_var($url, FILTER_VALIDATE_URL) === false) {
    throw new InvalidArgumentException('Invalid URL');
}

// SAFE: Use parsed components for HTTP request, not original URL
$parsed = parse_url($url);
if ($parsed === false) {
    die('Invalid URL');
}
$safeUrl = $parsed['scheme'] . '://' . $parsed['host'] . $parsed['path'];
```

### Custom Semgrep Rule

We have `custom-rules/web-vulns/php-parse-url-bypass.yaml` to detect these patterns.

### References

- https://www.php.net/manual/en/function.parse-url.php ("Seriously malformed URLs, parse_url() may return false")
- https://blog.orange.tw/2017/07/how-i-chained-4-vulnerabilities-on.html

---

## Type Juggling Vulnerabilities

### The Vulnerability

PHP's loose comparison (`==`) has surprising behaviors:

```php
"0e123" == "0e456"   // TRUE (both parsed as scientific notation = 0)
"abc" == 0           // TRUE (string cast to int = 0)
[] == NULL           // TRUE
```

### Attack Pattern (Auth Bypass)

```php
// VULNERABLE: Magic hash collision
$hash = md5($password);
if ($hash == "0e462097431906509019562988736854") {
    // Authenticated!
}
// Attacker finds password that hashes to 0e... pattern
```

### Safe Pattern

```php
// SAFE: Strict comparison
if ($hash === $expected_hash) { ... }

// SAFE: hash_equals for timing-safe comparison
if (hash_equals($expected_hash, $hash)) { ... }
```

---

## strcmp() Bypass

### The Vulnerability

`strcmp()` returns `NULL` when comparing string to array:

```php
strcmp("password", [])  // Returns NULL
NULL == 0               // TRUE in loose comparison
```

### Attack Pattern

```php
// VULNERABLE: Array injection bypasses check
if (strcmp($_POST['password'], $correct_password) == 0) {
    // Authenticated!
}
// Attacker sends: password[]=anything
```

### Safe Pattern

```php
// SAFE: Strict comparison
if (strcmp($input, $expected) === 0) { ... }

// SAFER: hash_equals for passwords
if (hash_equals($expected, $input)) { ... }
```

---

## preg_match() Bypass

### Null Byte Truncation (older PHP)

```php
// VULNERABLE: Null byte truncates pattern matching
if (preg_match('/^[a-z]+$/', $input)) {
    include($input . '.php');
}
// Attacker: "valid\0../../etc/passwd"
```

### ReDoS (Regex Denial of Service)

Complex patterns with nested quantifiers can hang:

```php
// VULNERABLE: Catastrophic backtracking
preg_match('/^(a+)+$/', $user_input);
// Attacker: "aaaaaaaaaaaaaaaaaaaaaaaaaaaa!"
```

---

## unserialize() RCE

### The Vulnerability

`unserialize()` on user input allows object injection → RCE via gadget chains.

### Dangerous Patterns

```php
// CRITICAL: Direct user input
$obj = unserialize($_COOKIE['data']);

// CRITICAL: Base64 doesn't help
$obj = unserialize(base64_decode($_POST['data']));
```

### Safe Alternatives

```php
// SAFE: JSON instead
$data = json_decode($input, true);

// SAFER: Restrict allowed classes (PHP 7+)
$obj = unserialize($input, ['allowed_classes' => false]);
$obj = unserialize($input, ['allowed_classes' => ['SafeClass']]);
```

---

## Checklist for PHP Code Review

When reviewing PHP semgrep findings:

- [ ] **SSRF findings**: Check for `parse_url()` without `=== false` validation
- [ ] **Auth findings**: Look for `==` instead of `===` or `hash_equals()`
- [ ] **Input validation**: Check for `strcmp()` with loose comparison
- [ ] **Deserialization**: Any `unserialize()` on user input is critical
- [ ] **File inclusion**: Check for null byte injection (older PHP) or path traversal
- [ ] **SQL injection**: Verify parameterized queries, not string concatenation
