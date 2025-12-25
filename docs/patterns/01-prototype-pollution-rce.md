# Prototype Pollution to RCE via hasOwnProperty Bypass

## Pattern Overview

| Attribute | Value |
|-----------|-------|
| **Pattern Class** | `injection/prototype-pollution-rce` |
| **Severity** | CRITICAL |
| **Score** | 10/10 |
| **CVSS** | 10.0 |
| **CWE** | CWE-1321 (Improperly Controlled Modification of Object Prototype Attributes) |
| **Languages** | JavaScript, TypeScript |
| **Source CVE** | CVE-2025-55182 (React2Shell) |
| **Status** | Actively exploited in the wild |

## Description

Server-side prototype pollution occurs when an application processes untrusted input through object operations that don't verify property ownership. When code accesses object properties without checking `hasOwnProperty()`, attackers can inject properties via `__proto__` that pollute `Object.prototype`. These poisoned properties then propagate to all objects in the application, potentially reaching dangerous sinks like `child_process.execSync()`.

This is distinct from client-side prototype pollution (which typically leads to XSS) because server-side exploitation can achieve **Remote Code Execution (RCE)**.

## Technical Details

### Root Cause

The vulnerability stems from accessing object properties without verifying that the property belongs to the object itself (not inherited from the prototype chain):

```javascript
// VULNERABLE: No ownership check
if (moduleExports[metadata[NAME]]) {
    // Attacker can set metadata[NAME] = "__proto__"
    // And control what moduleExports["__proto__"] returns
}

// SAFE: Uses hasOwnProperty check
if (hasOwnProperty.call(moduleExports, metadata[NAME])) {
    // Only accesses actual properties of moduleExports
}
```

### Attack Chain (CVE-2025-55182)

1. **Pollution Vector**: Attacker sends HTTP request with `__proto__` in JSON body
2. **Object Merge**: Application merges user input into objects without sanitization
3. **Prototype Poisoning**: `Object.prototype` gains attacker-controlled properties
4. **Sink Execution**: Subsequent code reads poisoned properties, triggering RCE

### Vulnerable Code Patterns

#### Pattern 1: Direct Property Access
```javascript
// Vulnerable
function getModule(exports, name) {
    return exports[name];  // name could be "__proto__"
}

// Safe
function getModule(exports, name) {
    if (Object.hasOwn(exports, name)) {  // ES2022+
        return exports[name];
    }
    return undefined;
}
```

#### Pattern 2: Object Spread/Merge
```javascript
// Vulnerable: Spreads user input directly
const config = { ...defaultConfig, ...req.body };

// Vulnerable: Object.assign with user input
Object.assign(target, req.body);

// Safer: Filter dangerous keys
const safeInput = Object.fromEntries(
    Object.entries(req.body).filter(([key]) =>
        !['__proto__', 'constructor', 'prototype'].includes(key)
    )
);
```

#### Pattern 3: Deep Merge Functions
```javascript
// Vulnerable deep merge (common in lodash.merge, etc.)
function deepMerge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object') {
            target[key] = deepMerge(target[key] || {}, source[key]);
        } else {
            target[key] = source[key];  // Can set __proto__ properties
        }
    }
    return target;
}

// Safe: Check ownership and block dangerous keys
function safeDeepMerge(target, source) {
    for (let key in source) {
        if (!source.hasOwnProperty(key)) continue;
        if (key === '__proto__' || key === 'constructor') continue;
        // ... rest of merge logic
    }
}
```

### Exploitation Example

```javascript
// Attacker sends POST request with body:
{
    "__proto__": {
        "shell": "/bin/sh",
        "env": { "NODE_OPTIONS": "--require /proc/self/cmdline" }
    }
}

// Or for React Server Components (CVE-2025-55182):
// Payload in RSC Flight protocol triggers RCE via process.mainModule.require
```

### RCE Sinks

Once `Object.prototype` is polluted, these sinks can be exploited:

```javascript
// child_process - most common
child_process.spawn(cmd, args, options);  // options.shell from prototype
child_process.exec(cmd, options);
child_process.execSync(cmd, options);

// Dynamic requires
require(pollutedPath);

// eval/Function
eval(pollutedString);
new Function(pollutedString);

// Template engines
ejs.render(template, { outputFunctionName: pollutedValue });
```

## Real-World Impact

### CVE-2025-55182 (React2Shell)

- **Affected**: React 19.0.0, 19.1.0, 19.1.1, 19.2.0 and Next.js 15.0.0-15.0.4
- **Impact**: Pre-authentication RCE on any server using React Server Components
- **Exploitation**: Active attacks observed within days of disclosure
- **Post-exploitation**: Cloud credential harvesting, cryptocurrency mining
- **Fix**: Added `hasOwnProperty.call()` checks before property access

### Observed Attack Patterns
- Scanning for Next.js 15 deployments
- Payload delivery via RSC Flight protocol
- Immediate pivot to IMDS for cloud credentials
- Cryptominer deployment

## Detection

### Semgrep Rule Approach

```yaml
rules:
  - id: prototype-pollution-property-access
    patterns:
      - pattern-either:
          # Direct bracket access with user input
          - pattern: $OBJ[$USER_INPUT]
          # for...in without hasOwnProperty
          - pattern: |
              for (let $KEY in $OBJ) {
                ...
                $OBJ[$KEY]
                ...
              }
      - pattern-not-inside: |
          if ($OBJ.hasOwnProperty($KEY)) { ... }
      - pattern-not-inside: |
          if (Object.hasOwn($OBJ, $KEY)) { ... }
      - pattern-not-inside: |
          if (hasOwnProperty.call($OBJ, $KEY)) { ... }
    message: "Property access without hasOwnProperty check - potential prototype pollution"
    languages: [javascript, typescript]
    severity: WARNING
```

### Runtime Detection

- Monitor for HTTP requests containing `__proto__`, `constructor`, or `prototype` in JSON bodies
- Watch for unexpected `child_process` spawns from Node.js web servers
- Alert on shell processes (bash, sh, dash) with Node.js parent

### WAF Rules

Block requests with these patterns in JSON bodies:
- `"__proto__"`
- `"constructor"`
- `"prototype"`

## Remediation

### Immediate Actions

1. **Update frameworks**: React 19.2.1+, Next.js 15.0.5+
2. **Add WAF rules** blocking `__proto__` in request bodies
3. **Audit object merge operations** in your codebase

### Code Fixes

```javascript
// 1. Always use hasOwnProperty checks
if (Object.hasOwn(obj, key)) { ... }  // ES2022+
if (Object.prototype.hasOwnProperty.call(obj, key)) { ... }  // Legacy

// 2. Use Object.create(null) for dictionaries
const safeDict = Object.create(null);  // No prototype chain

// 3. Freeze Object.prototype (breaks some libraries)
Object.freeze(Object.prototype);

// 4. Use Map instead of objects for user-controlled keys
const userMap = new Map();
userMap.set(userKey, userValue);  // Can't pollute prototype
```

### Library-Specific Mitigations

| Library | Mitigation |
|---------|------------|
| lodash | Use `lodash.merge` with `_.omit(input, ['__proto__', 'constructor'])` |
| Express | Use `express.json({ reviver: ... })` to filter keys |
| Next.js | Upgrade to 15.0.5+ |
| React | Upgrade to 19.2.1+ |

## References

- [Datadog: CVE-2025-55182 React2Shell Analysis](https://securitylabs.datadoghq.com/articles/cve-2025-55182-react2shell-remote-code-execution-react-server-components/)
- [Wiz: React2Shell Critical Vulnerability](https://www.wiz.io/blog/critical-vulnerability-in-react-cve-2025-55182)
- [React Security Advisory](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components)
- [CISA KEV Entry](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2025-55182)
- [AWS Threat Intelligence on React2Shell](https://aws.amazon.com/blogs/security/china-nexus-cyber-threat-groups-rapidly-exploit-react2shell-vulnerability-cve-2025-55182/)
- [Prototype Pollution Attack Research](https://portswigger.net/web-security/prototype-pollution)

## Semgrep Rule Evaluation

### Rule File
`custom-rules/patterns/injection/prototype-pollution-rce.yaml`

### Rules Created

| Rule ID | Confidence | Description |
|---------|------------|-------------|
| `prototype-pollution-object-assign` | HIGH | Direct spread/assign of HTTP input |
| `prototype-pollution-spread-http` | HIGH | Taint tracking: HTTP input → spread/assign |
| `prototype-pollution-to-child-process` | MEDIUM | Taint tracking: spread → child_process sinks |
| `prototype-pollution-lodash-merge-user-input` | MEDIUM | Lodash merge with user input |
| `prototype-pollution-deep-merge` | LOW (audit) | Generic for...in without hasOwnProperty |
| `prototype-pollution-query-parser` | LOW (audit) | Custom parsers using `{}` |

### Test Results

**OWASP Juice Shop** (intentionally vulnerable):
- **2 TRUE POSITIVES** in `routes/dataErasure.ts`:
  - Line 72: `res.render('dataErasureResult', { ...req.body })` - Template injection
  - Line 87: Same pattern, different code path
- **1 TRUE POSITIVE** in `oauth.component.ts`:
  - Line 73: `parseRedirectUrlParams()` - Client-side prototype pollution

**Nextcloud** (production code):
- 12,758 JS/TS files scanned
- **0 findings** - Demonstrates low FP rate on well-written code

### Metrics

| Metric | Value |
|--------|-------|
| True Positives (Juice Shop) | 3 |
| False Positives (excl. vendor) | 0 |
| Precision | 100% (on test set) |
| FP Rate | 0% (on production code) |

### Recommendations

1. **Use HIGH confidence rules for automated reporting**
2. **LOW confidence (audit) rules require manual review** - Check for hasOwnProperty guards
3. **Exclude vendor/test/bundle paths** via `.semgrepignore`:
   ```
   **/node_modules/
   **/vendor/
   **/assets/
   **/test/
   **/tests/
   **/dist/
   **/build/
   **/*.min.js
   **/*.bundle.js
   **/*.chunk.js
   **/*.chunk.mjs
   ```
4. **Increase timeout for large files**: `semgrep --timeout 60` (default is 30s)

### Performance Notes

Taint mode rules can timeout on bundled/minified JS files (500KB+). Exclude these patterns:
- `**/*-init.mjs` (Vite bundles)
- `**/dist/**`
- `**/*.min.js`

## Related Patterns

- `injection/prototype-pollution-xss` - Client-side variant leading to XSS
- `injection/template-options` - Similar object injection in template engines
- `deserialization/json-rce` - Unsafe JSON parsing leading to RCE
