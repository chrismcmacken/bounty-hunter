# Nextcloud - Low Priority Research Items

**Date**: 2025-12-24
**Platform**: HackerOne
**Status**: COMPLETED - All items reviewed as FALSE POSITIVES

---

## 1. GitHub Actions Shell Injection

**Location**: `server/.github/workflows/performance.yml:77`
**Rule**: GitHub Actions context injection pattern
**Status**: FALSE POSITIVE

**Analysis**:
The workflow uses `${{ github.event.pull_request.head.ref }}` in shell `run:` steps, which is typically dangerous. However:

1. **Fork check (lines 32-35)**: Workflow exits if PR is from a fork - only same-repo PRs proceed
2. **Single-quoted values**: Template values are wrapped in `'...'` preventing most shell injection
3. **Git branch restrictions**: Git doesn't allow `'` in branch names, so quote escape is impossible
4. **Already reviewed**: Has `# zizmor: ignore[template-injection]` annotation indicating prior security review

**Verdict**: Not exploitable. Requires repo write access + shell injection chars that git forbids.

---

## 2. parse_url() Host Extraction Bypass

**Locations**:
- `3rdparty/doctrine/dbal/src/Driver/Mysqli/Driver.php:34`
- `3rdparty/guzzlehttp/psr7/src/ServerRequest.php:191`

**Status**: FALSE POSITIVE (Out of Scope)

**Analysis**:
1. Both are in **vendored third-party code** (`3rdparty/`) - out of scope for Nextcloud bug bounty
2. The Guzzle code actually handles parse_url correctly:
   - Returns `[null, null]` when parse_url fails
   - Uses null coalescing (`??`) for missing keys
3. Would need to report to upstream Doctrine/Guzzle if there were real issues

**Verdict**: Out of scope + correctly handled.

---

## 3. Prototype Pollution in WebRTC Code

**Locations**: 6 instances in `spreed/src/utils/webrtc/`
**Status**: FALSE POSITIVE

**Analysis**:
All flagged instances use proper `hasOwn` protection:

```javascript
for (item in opts) {
    if (Object.hasOwn(opts, item)) {  // Blocks __proto__ and constructor
        this.config[item] = opts[item]
    }
}
```

The `Object.hasOwn()` check ensures only own properties are copied, blocking:
- `__proto__` pollution
- `constructor.prototype` pollution

**Verdict**: Protected code pattern, not exploitable.

---

## Summary

| Item | Status | Reason |
|------|--------|--------|
| GitHub Actions injection | FALSE POSITIVE | Fork restriction + single quotes + git char restrictions |
| parse_url() bypass | FALSE POSITIVE | Vendored code (out of scope) + correctly handled |
| Prototype pollution | FALSE POSITIVE | Uses Object.hasOwn() protection |

**Conclusion**: No actionable findings from these research items. All three were correctly identified as low-confidence by the initial triage and confirmed as false positives upon manual review.
