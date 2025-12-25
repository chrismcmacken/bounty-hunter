# Windows Device Name Path Traversal

## Pattern Overview

| Attribute | Value |
|-----------|-------|
| **Pattern Class** | `traversal/windows-device-names` |
| **Severity** | HIGH |
| **Score** | 9/10 |
| **CVSS** | 8.1 |
| **CWE** | CWE-22 (Path Traversal), CWE-20 (Improper Input Validation) |
| **Languages** | JavaScript (Node.js), and any Windows application |
| **Source CVE** | CVE-2025-27210 (Node.js) |
| **Status** | Patched in Node.js 20.19.4, 22.17.1, 24.4.1 |

## Description

Windows reserves certain filenames as device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9). These names have special meaning to the OS and are handled differently than regular files. Path normalization functions like `path.join()` and `path.normalize()` may not properly handle these device names, allowing attackers to craft paths that bypass directory restrictions.

This is a bypass of an incomplete fix for CVE-2025-23084, demonstrating that Windows path handling continues to be a source of vulnerabilities.

## Technical Details

### Windows Reserved Device Names

| Device | Purpose |
|--------|---------|
| CON | Console (keyboard input/screen output) |
| PRN | Default printer |
| AUX | Auxiliary device (typically COM1) |
| NUL | Null device (discards all data) |
| COM1-COM9 | Serial ports |
| LPT1-LPT9 | Parallel printer ports |

These names are reserved regardless of:
- File extension (CON.txt is still CON)
- Directory location (/any/path/CON is still CON)
- Case (con, CON, Con all match)

### Root Cause

Node.js's `path.join()` and `path.normalize()` attempt to prevent path traversal by normalizing paths and ensuring they stay within a base directory. However, the fix for CVE-2025-23084 was incomplete - it didn't account for all variations of Windows device names in traversal sequences.

From the advisory:
> "A previous vulnerability (CVE-2025-23084) attempted to address path traversal via these APIs, but the fix was incomplete."

### Vulnerable Code Pattern

```javascript
const path = require('path');
const fs = require('fs');

// VULNERABLE: path.join doesn't properly handle device names
app.get('/files/:filename', (req, res) => {
    const baseDir = '/app/uploads';
    const filename = req.params.filename;

    // Developer thinks this is safe - path.join normalizes the path
    const filePath = path.join(baseDir, filename);

    // Check that resolved path is still under baseDir
    if (!filePath.startsWith(baseDir)) {
        return res.status(403).send('Access denied');
    }

    // But with filename = "..\\CON" or "AUX\\..\\..\\etc\\passwd"
    // the path may escape the intended directory
    fs.readFile(filePath, (err, data) => {
        res.send(data);
    });
});
```

### Attack Vectors

#### Vector 1: Device Name with Traversal

```javascript
// Attacker input
const maliciousPath = "..\\CON";

// path.join behavior on Windows
path.join('/uploads', '..\\CON');
// May resolve incorrectly, allowing escape

// Or with nested traversal
const maliciousPath2 = "AUX\\..\\..\\..\\Windows\\System32\\config\\SAM";
```

#### Vector 2: Device Name Variations

```javascript
// All of these refer to the same device
"CON"
"con"
"Con.txt"
"CON.anything"
"CON:stream"      // Alternate data stream syntax
"CON::$DATA"      // Default data stream
".\\CON"
"folder\\..\\CON"
```

#### Vector 3: UNC Path Combinations

```javascript
// Combining with UNC paths
"\\\\?\\C:\\Windows\\System32\\config\\SAM"
"\\\\localhost\\C$\\Windows\\System32\\config\\SAM"
```

### Exploitation Scenarios

#### Scenario 1: File Disclosure

```javascript
// Node.js file server
app.get('/download', (req, res) => {
    const file = req.query.file;
    const safePath = path.join('./public', file);
    res.sendFile(safePath);
});

// Attack: GET /download?file=..%5CCON%5C..%5C..%5Cetc%5Cpasswd
// On Windows: GET /download?file=..%5CAUX%5C..%5C..%5CWindows%5Cwin.ini
```

#### Scenario 2: File Write/Overwrite

```javascript
// Upload handler
app.post('/upload', (req, res) => {
    const filename = req.body.filename;
    const destPath = path.join('./uploads', filename);

    // Attacker can write outside uploads directory
    fs.writeFile(destPath, req.body.content, (err) => {
        res.send('Uploaded');
    });
});

// Attack: filename = "..\\CON\\..\\..\\app\\config.js"
```

#### Scenario 3: Path Validation Bypass

```javascript
// Custom path validator
function isPathSafe(userPath) {
    const resolved = path.resolve('./safe', userPath);
    return resolved.startsWith(path.resolve('./safe'));
}

// May return true for malicious paths involving device names
isPathSafe('..\\NUL\\..\\..\\sensitive');  // Could bypass
```

## Detection

### Semgrep Rule Approach

```yaml
rules:
  - id: windows-device-name-path-traversal
    patterns:
      - pattern-either:
          - pattern: path.join($BASE, $USER_INPUT)
          - pattern: path.normalize($USER_INPUT)
          - pattern: path.resolve($BASE, $USER_INPUT)
      - pattern-inside: |
          app.$METHOD($PATH, (req, res) => {
            ...
          })
    pattern-not-inside: |
      if ($USER_INPUT.match(/^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$/i)) { ... }
    message: >
      path.join/normalize with user input may be vulnerable to Windows device
      name path traversal. Validate input doesn't contain reserved device names.
    languages: [javascript, typescript]
    severity: WARNING

  - id: path-join-user-input-audit
    patterns:
      - pattern-either:
          - pattern: path.join(..., $REQ.params.$PARAM, ...)
          - pattern: path.join(..., $REQ.query.$PARAM, ...)
          - pattern: path.join(..., $REQ.body.$PARAM, ...)
    message: "User-controlled input in path.join - review for traversal"
    languages: [javascript, typescript]
    severity: INFO
```

### Manual Code Review

Look for:
1. `path.join()` or `path.normalize()` with user input
2. File operations on normalized paths
3. Path validation that only checks for `..` but not device names
4. Windows-deployed Node.js applications

### Testing

```bash
# Test variations
curl "https://target.com/files/..%5CCON"
curl "https://target.com/files/AUX%5C..%5C..%5Cconfig"
curl "https://target.com/files/..%5CPRN%5C..%5C..%5Csecret.txt"
curl "https://target.com/files/NUL%5C..%5C..%5C..%5CWindows%5Cwin.ini"
```

## Remediation

### Immediate Fix: Filter Device Names

```javascript
const WINDOWS_DEVICE_NAMES = /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|$)/i;

function sanitizePath(userPath) {
    // Split path into segments
    const segments = userPath.split(/[\/\\]/);

    // Check each segment for device names
    for (const segment of segments) {
        if (WINDOWS_DEVICE_NAMES.test(segment)) {
            throw new Error('Invalid path: contains reserved device name');
        }
    }

    // Also check for traversal
    if (userPath.includes('..')) {
        throw new Error('Invalid path: contains traversal sequence');
    }

    return userPath;
}
```

### Comprehensive Path Validation

```javascript
const path = require('path');

function safePathJoin(baseDir, userPath) {
    // 1. Reject null bytes
    if (userPath.includes('\0')) {
        throw new Error('Invalid path');
    }

    // 2. Reject Windows device names
    const DEVICE_NAMES = /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|:|$)/i;
    const segments = userPath.split(/[\/\\]/);
    for (const seg of segments) {
        if (DEVICE_NAMES.test(seg)) {
            throw new Error('Invalid path: reserved name');
        }
    }

    // 3. Normalize and resolve
    const resolved = path.resolve(baseDir, userPath);
    const normalizedBase = path.resolve(baseDir);

    // 4. Verify still under base directory
    if (!resolved.startsWith(normalizedBase + path.sep)) {
        throw new Error('Path traversal detected');
    }

    return resolved;
}
```

### Use Allowlist Instead of Blocklist

```javascript
// Better: Only allow specific characters
function validateFilename(filename) {
    // Allow only alphanumeric, dash, underscore, dot
    if (!/^[a-zA-Z0-9_\-\.]+$/.test(filename)) {
        throw new Error('Invalid filename');
    }

    // Ensure it has a valid extension
    if (!filename.match(/\.(txt|pdf|jpg|png)$/i)) {
        throw new Error('Invalid file type');
    }

    return filename;
}
```

### Node.js Version Upgrade

Upgrade to patched versions:
- Node.js 20.19.4+
- Node.js 22.17.1+
- Node.js 24.4.1+

### Platform-Aware Handling

```javascript
const isWindows = process.platform === 'win32';

function validatePath(userPath) {
    if (isWindows) {
        // Apply Windows-specific validation
        validateWindowsPath(userPath);
    }
    // Common validation for all platforms
    validateCommonPath(userPath);
}
```

## Testing

### Unit Tests

```javascript
describe('Path Traversal Prevention', () => {
    const testCases = [
        { input: '../etc/passwd', shouldReject: true },
        { input: '..\\Windows\\win.ini', shouldReject: true },
        { input: 'CON', shouldReject: true },
        { input: 'PRN.txt', shouldReject: true },
        { input: '..\\CON\\..\\secret', shouldReject: true },
        { input: 'AUX\\..\\..\\config', shouldReject: true },
        { input: 'normal-file.txt', shouldReject: false },
        { input: 'subdir/file.txt', shouldReject: false },
    ];

    testCases.forEach(({ input, shouldReject }) => {
        it(`should ${shouldReject ? 'reject' : 'accept'}: ${input}`, () => {
            if (shouldReject) {
                expect(() => safePathJoin('./uploads', input)).toThrow();
            } else {
                expect(() => safePathJoin('./uploads', input)).not.toThrow();
            }
        });
    });
});
```

### Integration Tests

```javascript
// Test actual file access
it('should not allow access to system files via device names', async () => {
    const response = await request(app)
        .get('/files/..%5CCON%5C..%5C..%5CWindows%5Cwin.ini');

    expect(response.status).toBe(400);
    expect(response.text).toContain('Invalid path');
});
```

## References

- [ZeroPath: CVE-2025-27210 Node.js Path Traversal](https://zeropath.com/blog/cve-2025-27210-nodejs-path-traversal-windows)
- [Node.js Security Release July 2025](https://nodejs.org/en/blog/vulnerability/july-2025-security-releases)
- [HeroDevs CVE-2025-27210 Analysis](https://www.herodevs.com/vulnerability-directory/cve-2025-27210)
- [Microsoft: Naming Files, Paths, and Namespaces](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)

## Related Patterns

- `traversal/path-join-bypass` - General path.join bypass techniques
- `traversal/symlink-follow` - Symlink-based traversal
- `traversal/null-byte-file` - Null byte in file paths
- `traversal/encoding-bypass` - URL/Unicode encoding bypasses
