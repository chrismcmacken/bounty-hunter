# Vulnerability Patterns (2025)

This directory contains documentation for behavioral vulnerability patterns discovered from 2025 CVEs. These patterns represent dangerous coding practices that developers recreate in custom code, making them excellent candidates for Semgrep rules.

## Pattern Index (by Priority)

| # | Pattern | Class | Severity | Score | Source CVE | Languages |
|---|---------|-------|----------|-------|------------|-----------|
| 1 | [Prototype Pollution RCE](01-prototype-pollution-rce.md) | `injection/prototype-pollution-rce` | CRITICAL | 10/10 | CVE-2025-55182 | JS/TS |
| 2 | [Symlink Path Traversal](02-symlink-path-traversal.md) | `traversal/symlink-follow` | HIGH | 8/10 | CVE-2025-8110 | Go, Python, JS |
| 3 | [Null Byte Hostname SSRF](03-null-byte-hostname-ssrf.md) | `ssrf/null-byte-hostname` | HIGH | 9/10 | CVE-2025-1220 | PHP |
| 4 | [Windows Device Name Traversal](04-windows-device-name-traversal.md) | `traversal/windows-device-names` | HIGH | 9/10 | CVE-2025-27210 | Node.js |
| 5 | [Batch File Command Injection](05-batch-file-command-injection.md) | `injection/batch-file-command` | HIGH | 8/10 | CVE-2025-61787 | JS/TS, Go, Rust, Python |
| 6 | [Pickle pip.main Bypass](06-pickle-pip-bypass.md) | `deserialization/pickle-pip-bypass` | MEDIUM-HIGH | 7/10 | CVE-2025-1716 | Python |

**Priority Rationale:**
- **#1-2**: Actively exploited in the wild with confirmed compromises
- **#3-4**: High score (9/10) with significant impact potential
- **#5-6**: Important patterns but lower immediate risk

## Discovery Date

All patterns discovered: **December 2025**

## Actively Exploited

The following patterns have confirmed in-the-wild exploitation:

- **CVE-2025-55182** (Prototype Pollution RCE) - React2Shell actively exploited for crypto mining and cloud credential theft
- **CVE-2025-8110** (Symlink Traversal) - Gogs zero-day with 700+ compromised instances

## Pattern Categories

### Injection Patterns
- [01 - Prototype Pollution RCE](01-prototype-pollution-rce.md) - Object property access without ownership checks
- [05 - Batch File Command Injection](05-batch-file-command-injection.md) - Windows cmd.exe metacharacter injection

### SSRF Patterns
- [03 - Null Byte Hostname SSRF](03-null-byte-hostname-ssrf.md) - Hostname truncation via null bytes

### Path Traversal Patterns
- [02 - Symlink Path Traversal](02-symlink-path-traversal.md) - Following symlinks to escape directories
- [04 - Windows Device Name Traversal](04-windows-device-name-traversal.md) - Reserved device names bypass path normalization

### Deserialization Patterns
- [06 - Pickle pip.main Bypass](06-pickle-pip-bypass.md) - Evading pickle security scanners

## Creating Rules from Patterns

Use the `/pattern-to-rule` skill to create Semgrep rules from these patterns:

```bash
/pattern-to-rule CVE-2025-55182   # Prototype pollution
/pattern-to-rule CVE-2025-27210   # Windows device names
/pattern-to-rule CVE-2025-8110    # Symlink following
```

## Hunting with Patterns

Scan bug bounty targets for these patterns:

```bash
# Scan with existing rules
semgrep --config custom-rules/patterns/ repos/<org>/

# Or use the full rule set
./scripts/scan-semgrep.sh <org>
```

## Contributing New Patterns

1. Use `/discover-patterns` to find new patterns from CVEs
2. Analyze the fix commit to extract the behavioral pattern
3. Document in this directory following the template
4. Create a Semgrep rule in `custom-rules/patterns/`

### Pattern Document Template

```markdown
# Pattern Name

## Pattern Overview
| Attribute | Value |
|-----------|-------|
| **Pattern Class** | `category/subcategory` |
| **Severity** | CRITICAL/HIGH/MEDIUM |
| **Score** | X/10 |
| **CWE** | CWE-XXX |
| **Languages** | Language1, Language2 |
| **Source CVE** | CVE-YYYY-XXXXX |

## Description
[What the pattern is and why it's dangerous]

## Technical Details
[Root cause, vulnerable code patterns, attack vectors]

## Detection
[Semgrep rule approach, manual review guidance]

## Remediation
[How to fix the vulnerable pattern]

## References
[Links to advisories, research, documentation]
```

## References

- [OSV.dev](https://osv.dev/) - Vulnerability database used for discovery
- [Semgrep Registry](https://semgrep.dev/r) - Existing rules to reference
- [MITRE CWE](https://cwe.mitre.org/) - Weakness enumeration
