# Existing Custom Rules Summary

Summary of all rules in `custom-rules/` for reference when creating CVE-derived rules. Check this before writing new rules to avoid duplicating coverage.

**Total Rules: ~331**

---

## Directory Structure

```
custom-rules/
├── 0xdea-semgrep-rules/    # C/C++ memory safety (50 rules)
├── open-semgrep-rules/     # Multi-language security (200+ rules)
├── web-vulns/              # Taint-mode web vulns (7 rules)
├── custom/
│   ├── novel-vulns/        # Novel attack patterns (4 rules)
│   └── org-specific/       # Target-specific rules
└── cve/                    # CVE-derived rules (your new rules go here)
```

---

## Rules by Collection

### 1. 0xdea-semgrep-rules (Raptor)

**Language:** C/C++
**Focus:** Memory safety, undefined behavior, insecure APIs

| Category | Rules | Examples |
|----------|-------|----------|
| Memory Management | 8 | double-free, use-after-free, mismatched-memory-management |
| Buffer Operations | 10 | write-into-stack-buffer, off-by-one, incorrect-use-of-strncpy |
| Integer Issues | 5 | integer-wraparound, integer-truncation, signed-unsigned-conversion |
| Insecure APIs | 12 | gets, strcpy, sprintf, mktemp, rand, scanf |
| Unchecked Returns | 4 | malloc, setuid, scanf |
| Format Strings | 1 | format-string-bugs |
| Command Injection | 1 | command-injection |
| Other | 9 | typos, suspicious-assert, missing-return |

**Rule ID Prefix:** `raptor-*`

---

### 2. open-semgrep-rules

**Languages:** Python, Go, Java, Scala, C#, JavaScript
**Focus:** Injection, crypto, sensitive data, authentication

#### By Language

| Language | Rules | Categories |
|----------|-------|------------|
| Python | 70+ | crypto (21), exec (9), xml (8), deserialization (6), ssl (4) |
| Scala | 85+ | inject (16), crypto (13), cookie (8), xxe (6), endpoint (6) |
| Java | 50+ | crypto (15), inject (8), strings (4), xml (3), password (3) |
| Go | 30+ | filesystem (6), crypto (5), blocklist (4), injection (2) |
| C# | 15+ | injection (6), crypto (5), xss (2) |
| JavaScript | 10+ | buffer (2), xss (1), timing (1), eval (1) |

#### Key Rule Categories

**Crypto/Weak Algorithms:**
- MD5, SHA1, DES, RC4, Blowfish
- Weak key strength
- Insecure TLS settings
- Weak random sources

**Injection:**
- SQL injection (concatenation patterns)
- Template injection
- SSRF
- LDAP injection
- XPath injection

**Deserialization:**
- Python pickle
- Java object streams
- Ruby Marshal

**XML Processing:**
- XXE (external entities)
- XSLT injection
- XML bombs

---

### 3. web-vulns (Custom Taint Rules)

**Focus:** Bug bounty web vulnerabilities with multi-framework source coverage

| Rule File | Vulnerability | CWE | Languages |
|-----------|--------------|-----|-----------|
| `ssrf-taint.yaml` | Server-Side Request Forgery | CWE-918 | Python, JS, Java, Go, Ruby, PHP |
| `ssti-taint.yaml` | Template Injection | CWE-1336 | Python, PHP, JS, Java, Ruby, Go |
| `deserialization-taint.yaml` | Insecure Deserialization | CWE-502 | Python, Java, Ruby, PHP, JS, C# |
| `mongodb-nosql-injection.yaml` | NoSQL Injection | CWE-943 | Python, JS, Java, Go, Ruby |
| `xpath-injection.yaml` | XPath Injection | CWE-643 | Python, Java, PHP, C#, Ruby |
| `php-parse-url-bypass.yaml` | URL Validation Bypass | CWE-918 | PHP |
| `python-dynamic-import-lfi.yaml` | Local File Inclusion | CWE-98 | Python |

**CVE References in Rules:**
- CVE-2024-39338 (Axios SSRF)
- CVE-2024-22259 (Spring UriComponentsBuilder)
- CVE-2024-6386 (WPML Twig SSTI)

---

### 4. custom/novel-vulns

**Focus:** Novel attack patterns not in standard rulesets

| Rule | Vulnerability | Confidence |
|------|--------------|------------|
| `python-class-pollution.yaml` | Python Prototype Pollution Equivalent | HIGH |
| `python-pickle-ml-deserialization.yaml` | ML Model Deserialization (sklearn, torch) | HIGH |
| `python-unsafe-yaml-load.yaml` | YAML Deserialization | HIGH |
| `python-path-join-absolute-bypass.yaml` | Path Traversal via os.path.join | HIGH |

**Class Pollution Patterns:**
- `setattr()` with user-controlled attribute names
- Recursive merge functions with getattr/setattr
- `__globals__` traversal attacks
- `__dict__.update()` from untrusted input

---

## Coverage Gaps (Opportunities for New Rules)

Based on current coverage, these areas may need additional rules:

### Languages Underrepresented
- **Rust** - No rules currently
- **Kotlin** - No rules currently
- **Swift** - No rules currently
- **PHP** - Only 1 custom rule, relies on open-semgrep-rules

### Vulnerability Types
- **GraphQL injection** - Not covered
- **WebSocket vulnerabilities** - Not covered
- **JWT vulnerabilities** - Limited coverage
- **Race conditions** - Limited coverage
- **Business logic flaws** - Hard to generalize

### Framework-Specific
- **Next.js** - SSR-specific issues
- **FastAPI** - Beyond basic Flask patterns
- **Django REST Framework** - Serializer issues
- **gRPC** - Limited coverage

---

## Before Writing a New CVE Rule

### 1. Search Existing Rules

```bash
# Search by vulnerability type
grep -rn "CWE-89" custom-rules/                    # SQL injection
grep -rn "command.injection" custom-rules/         # Command injection

# Search by function/pattern
grep -rn "eval(" custom-rules/                     # eval usage
grep -rn "pickle" custom-rules/                    # pickle deserialization

# Search by CVE
grep -rn "CVE-2024" custom-rules/
```

### 2. Check Rule IDs

```bash
# List all existing rule IDs
grep -rh "^  - id:" custom-rules/ | sort | uniq
```

### 3. Avoid These Patterns (Already Covered)

**Python:**
- Basic SQL injection via string concatenation → `open-semgrep-rules/python/sql`
- pickle.load from user input → `custom/novel-vulns/python-pickle-ml-deserialization.yaml`
- yaml.load (unsafe) → `custom/novel-vulns/python-unsafe-yaml-load.yaml`
- SSRF via requests/urllib → `web-vulns/ssrf-taint.yaml`
- SSTI via Jinja2/Mako → `web-vulns/ssti-taint.yaml`

**Java:**
- XXE via DocumentBuilder → `open-semgrep-rules/java/xxe`
- Deserialization via ObjectInputStream → `web-vulns/deserialization-taint.yaml`
- SQL injection via Statement → `open-semgrep-rules/java/inject`
- Weak crypto (MD5, SHA1, DES) → `open-semgrep-rules/java/crypto`

**JavaScript:**
- eval() with user input → `open-semgrep-rules/javascript/eval`
- Command injection → Built into default rules
- Prototype pollution → Built into default rules

**C/C++:**
- Buffer overflows → `0xdea-semgrep-rules/rules/c/*`
- Format strings → `raptor-format-string-bugs`
- Use-after-free → `raptor-use-after-free`

---

## Naming Conventions

When adding CVE rules to `custom-rules/cve/`:

```
CVE-YYYY-NNNNN.yaml                    # Primary rule file
CVE-YYYY-NNNNN.py                      # Python test cases
CVE-YYYY-NNNNN.java                    # Java test cases (if applicable)
```

Rule ID format:
```
cve-YYYY-NNNNN-<vulnerability-type>[-<variant>]
```

Examples:
- `cve-2024-12345-sql-injection`
- `cve-2024-12345-path-traversal-django`
- `cve-2024-12345-deserialization-jackson`

---

## Updating This Summary

After adding significant rules, regenerate counts:

```bash
# Count rules by directory
find custom-rules -name "*.yaml" -o -name "*.yml" | grep -v ".github" | xargs dirname | sort | uniq -c | sort -rn

# List rule IDs
grep -rh "^  - id:" custom-rules/ --include="*.yaml" --include="*.yml" | sort | uniq | wc -l
```
