# ownCloud - Future Research Notes

**Date:** 2025-12-22
**Platform:** HackerOne
**Program URL:** https://hackerone.com/owncloud
**Status:** Program paused - revisit later

---

## Summary

Comprehensive scan of ~115 repositories completed. Zero high-confidence reportable findings, but 3 medium-severity findings in the **ocis** repository warrant investigation when the program reopens.

---

## Findings Requiring Investigation

All 3 findings are in **ocis** (ownCloud Infinite Scale) - explicitly in scope per program policy.

### 1. Hardcoded OAuth Client Secrets in Default Config

| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **File** | `services/idp/pkg/config/defaults/defaultconfig.go:90-109` |
| **Description** | Default OAuth client secrets for Desktop, Android, and iOS apps are hardcoded |
| **Secrets** | 3 base64-encoded client secrets for official apps |
| **Impact** | If unchanged in production, attackers could impersonate official clients |
| **Verification** | Test against production ownCloud/oCIS instances to check if defaults are used |

### 2. Template Injection in Email Notifications

| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **File** | `services/notifications/pkg/email/email.go:120-122` |
| **Code** | `template.HTML()` used on Greeting, MessageBody, CallToAction fields |
| **Impact** | If user-controlled, could lead to XSS in notification emails |
| **Verification** | Trace data flow to determine if fields accept user input |

### 3. Potential XSS in Error Responses

| Field | Value |
|-------|-------|
| **Severity** | Low |
| **File** | `services/activitylog/pkg/service/http.go:65` |
| **Code** | `w.Write([]byte(err.Error()))` - KQL parsing errors written to response |
| **Impact** | Potential reflected XSS if Content-Type is text/html |
| **Verification** | Test with malicious KQL queries containing XSS payloads |

---

## Scan Statistics

| Scanner | Total | Reportable | False Positives |
|---------|-------|------------|-----------------|
| Trufflehog | 177 | 0 | 177 |
| Semgrep | 3,085 | 0 (3 need investigation) | 3,082 |
| Artifacts | 77 | 0 | 77 |
| KICS | 1,738 | 0 | 1,738 |

---

## In-Scope Repositories (per HackerOne)

- ocis (next-gen server)
- core (legacy server)
- client (Desktop)
- android
- ios-app
- activity, customgroups, gallery, guests, notifications, oauth2, richdocuments, updater, user_ldap

**Note:** Test folders are out of scope - only code in final releases counts.

---

## Next Steps (When Program Reopens)

1. Set up local oCIS instance for testing
2. Verify OAuth client secrets against production deployments
3. Trace email template data flow for injection
4. Test KQL endpoint with XSS payloads
5. Re-scan for any new commits since 2025-12-22
