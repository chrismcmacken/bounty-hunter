# Pattern Classification Taxonomy

Behavioral patterns are organized by vulnerability class and specific pattern type.

## Directory Structure

```
custom-rules/patterns/
├── injection/
│   ├── sql-concatenation.yaml
│   ├── command-subprocess.yaml
│   ├── template-options.yaml
│   ├── template-string.yaml
│   ├── code-eval.yaml
│   └── ldap-query.yaml
├── ssrf/
│   ├── user-controlled-url.yaml
│   └── redirect-open.yaml
├── traversal/
│   ├── path-concatenation.yaml
│   └── zip-slip.yaml
├── deserialization/
│   ├── pickle-load.yaml
│   ├── yaml-unsafe.yaml
│   └── json-type-confusion.yaml
├── xxe/
│   ├── parser-external-entities.yaml
│   └── xslt-injection.yaml
├── crypto/
│   ├── weak-hash.yaml
│   ├── hardcoded-key.yaml
│   └── insecure-random.yaml
├── auth/
│   ├── missing-decorator.yaml
│   └── broken-comparison.yaml
└── xss/
    ├── dom-sink.yaml
    └── reflected-unescaped.yaml
```

## Pattern Classes

### injection/

Patterns where user input reaches code execution or query interpretation.

| Pattern | Description | Key Sinks |
|---------|-------------|-----------|
| `sql-concatenation` | User input concatenated into SQL | `execute()`, `query()`, raw SQL strings |
| `command-subprocess` | User input in shell commands | `subprocess.*`, `os.system()`, `exec()` |
| `template-options` | User objects to template config | `render(template, OPTIONS)` |
| `template-string` | User input as template content | `Template(USER_INPUT)` |
| `code-eval` | User input to code evaluation | `eval()`, `exec()`, `Function()` |
| `ldap-query` | User input in LDAP queries | LDAP filter construction |

### ssrf/

Patterns where user input controls server-side HTTP requests.

| Pattern | Description | Key Sinks |
|---------|-------------|-----------|
| `user-controlled-url` | User input as full URL | `requests.get()`, `fetch()`, `http.request()` |
| `redirect-open` | User input in redirect targets | `redirect()`, `Location` header |

### traversal/

Patterns where user input controls file system paths.

| Pattern | Description | Key Sinks |
|---------|-------------|-----------|
| `path-concatenation` | User input joined to paths | `open()`, `readFile()`, `os.path.join()` |
| `zip-slip` | Archive extraction without path validation | `extractall()`, `unzip` |

### deserialization/

Patterns where untrusted data is deserialized.

| Pattern | Description | Key Sinks |
|---------|-------------|-----------|
| `pickle-load` | User data to pickle deserializer | `pickle.loads()`, `cPickle.loads()` |
| `yaml-unsafe` | User YAML without safe loader | `yaml.load()` without `Loader=SafeLoader` |
| `json-type-confusion` | Type confusion via JSON | Magic method triggers |

### xxe/

Patterns enabling XML External Entity attacks.

| Pattern | Description | Key Sinks |
|---------|-------------|-----------|
| `parser-external-entities` | XML parser with entities enabled | `etree.parse()`, `DocumentBuilder` |
| `xslt-injection` | User input in XSLT processing | XSLT transformation functions |

### crypto/

Patterns involving cryptographic weaknesses.

| Pattern | Description | Key Sinks |
|---------|-------------|-----------|
| `weak-hash` | MD5/SHA1 for security purposes | `hashlib.md5()`, `crypto.createHash('md5')` |
| `hardcoded-key` | Encryption keys in source | AES/RSA key parameters |
| `insecure-random` | Weak RNG for security | `random.random()` for tokens |

### auth/

Patterns involving authentication/authorization bypasses.

| Pattern | Description | Key Sinks |
|---------|-------------|-----------|
| `missing-decorator` | Endpoints without auth checks | Route handlers without `@login_required` |
| `broken-comparison` | Timing-safe comparison missing | `==` for secrets instead of `compare_digest` |

### xss/

Patterns enabling Cross-Site Scripting.

| Pattern | Description | Key Sinks |
|---------|-------------|-----------|
| `dom-sink` | User input to DOM manipulation | `innerHTML`, `document.write()` |
| `reflected-unescaped` | User input reflected without escaping | Template rendering without autoescape |

## Pattern Naming Convention

Pattern file names follow this format:
```
<specific-behavior>-<context>.yaml
```

Examples:
- `sql-concatenation.yaml` - SQL injection via string concatenation
- `command-subprocess.yaml` - Command injection via subprocess
- `template-options.yaml` - Template injection via options object
- `path-concatenation.yaml` - Path traversal via string concatenation

## Rule ID Convention

Rule IDs follow this format:
```
<class>-<pattern>[-<variant>]
```

Examples:
- `injection-sql-concatenation`
- `injection-template-options`
- `ssrf-user-controlled-url`
- `traversal-path-concatenation`

## Adding New Patterns

When adding a new pattern:

1. Determine the pattern class (injection, ssrf, traversal, etc.)
2. Name the pattern by the specific behavior, not the CVE
3. Create file in appropriate directory
4. Use consistent rule ID format
5. Add CVE as `pattern_source` in metadata (reference only)
6. Add test file alongside rule

## Cross-Language Patterns

Many patterns exist across multiple languages. When a pattern applies to multiple languages:

1. Create one rule file per language family if sinks differ significantly
2. Or use `languages: [python, javascript, ...]` if patterns are similar
3. Document language-specific variants in the rule file

Example:
```yaml
# template-options.yaml
# Applies to JavaScript/TypeScript template engines
# For Python equivalent, see template-string.yaml
```
