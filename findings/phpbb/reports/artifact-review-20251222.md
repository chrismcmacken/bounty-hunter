# phpBB Artifact Findings - Triage Report

## Executive Summary

Reviewed **49 archives** and **13 SQL dumps** from phpBB organization repositories. All archives were safely extracted and scanned for secrets. No high-confidence reportable vulnerabilities were identified. Most findings are false positives (vendored code, test data, or schema-only dumps).

---

## 1. CONFIRMED SENSITIVE DATA EXPOSURE

### 1.1 Developer Email in Local Database Dump ⚠️ LOW CONFIDENCE

**Files:**
- `/Users/chrism/threat_hunting/repos/phpbb/docs-system/support/docs/ug/new.sql`
- `/Users/chrism/threat_hunting/repos/phpbb/docs-system/support/docs/ug/updated_sql.sql`

**Repository:** `phpbb/docs-system`  
**Type:** SQL Dump with user data  
**Size:** ~392KB each (3,321 lines)

**Data Exposed:**
- Database: `phpbb_docs_local` (LOCAL development database)
- Generation Date: August 15, 2013
- User ID 2 (admin):
  - Email: `myrice@gmail.com`
  - Password Hash: `$H$9n8yPhewgpCwUK5SNqRXKbiN5PdeGP/` (phpBB hash format)
  - IP: 127.0.0.1
- Multiple bot accounts (Google, Bing, Baidu, etc.)

**Assessment:**
- **NOT REPORTABLE** - This is a 12-year-old local development database dump
- The email appears to be a developer's personal email from 2013
- Password is hashed (not plaintext), though old phpBB hashes may be weak
- Labeled as "local" database, not production
- No other real user data found (only bots and system accounts)

**Rationale for Not Reporting:**
1. Age: 2013 database dump (>10 years old)
2. Context: Clearly marked as `phpbb_docs_local` (development environment)
3. Limited exposure: Single email address
4. No exploitability: Cannot demonstrate current security impact
5. Bug bounty programs typically require current, exploitable issues

**Recommendation:**
- Consider mentioning to phpBB as good security hygiene (remove old dumps)
- Not worth a bug bounty report due to age and limited impact

---

## 2. ARCHIVES REQUIRING EXTRACTION AND SCANNING

### 2.1 Archive Scan Results ✅ COMPLETED

**Total Archives:** 49 (all in `phpbb/customisation-db` repository)

**Categories:**
1. **Language Packages (21 archives):** British English language packs for phpBB 3.2.x - 3.3.x
   - Location: `includes/language_packages/`
   - Size: ~200-220KB each
   - Status: ✅ Scanned - No secrets found

2. **phpBB Release Packages (28 archives):** Full phpBB releases 3.2.0 - 3.3.15
   - Location: `includes/phpbb_packages/`
   - Size: 7-8MB each
   - Status: ✅ Scanned - Found vendored code findings (see below)

### 2.2 Secrets Found in Archives

**Finding:** GitHub OAuth2 Token in Vendored Code  
**Detector:** GitHubOauth2  
**Token:** `0ee8433f5a9a779d08ef`  
**Verified:** ❌ No  
**Location:** `vendor/s9e/text-formatter/src/Plugins/MediaEmbed/Configurator/Collections/CachedDefinitionCollection.php`  
**Affected Versions:** phpBB 3.2.2 - 3.3.15 (28 releases)

**Assessment:**
- **NOT REPORTABLE** - This is in vendored third-party code (s9e/text-formatter library)
- Same token appears across all phpBB versions (likely test/example data)
- Unverified by Trufflehog (invalid or revoked)
- Bug bounty programs don't accept findings in vendored dependencies

**Recommendation:**
- Report upstream to s9e/text-formatter project (not phpBB)
- Check if s9e/text-formatter has a security policy or bug bounty program

---

## 3. FALSE POSITIVES FILTERED OUT

### 3.1 Schema-Only SQL Dumps ✅ SAFE

**Files:**
- `area51-phpbb3/phpBB/install/schemas/postgres_schema.sql` (2,152 bytes)
- `area51-phpbb3/phpBB/install/schemas/oracle_schema.sql` (923 bytes)
- `phpbb/phpBB/install/schemas/postgres_schema.sql` (2,152 bytes)
- `phpbb/phpBB/install/schemas/oracle_schema.sql` (923 bytes)
- `phpbb-app/install/schemas/postgres_schema.sql` (2,152 bytes)
- `phpbb-app/install/schemas/oracle_schema.sql` (923 bytes)

**Reason:** Schema definition only, no INSERT/COPY statements, no data

### 3.2 Default Installation Data ✅ SAFE

**Files:**
- `area51-phpbb3/phpBB/install/schemas/schema_data.sql` (84KB)
- `phpbb/phpBB/install/schemas/schema_data.sql` (84KB)
- `phpbb-app/install/schemas/schema_data.sql` (84KB)

**Content:** Default phpBB configuration settings (config_name, config_value pairs)

**Reason:** Default installation data, no user PII, just system configuration

### 3.3 Test/Demo Data ✅ SAFE

**File:** `converter-framework/phpBBgsoc.sql` (2,133 bytes)

**Content:**
```sql
CREATE TABLE `phpBB_user` (
  `uid` int(11) NOT NULL,
  `user_name` varchar(30) DEFAULT NULL,
  `age` int(11) DEFAULT NULL,
  `pass` varchar(20) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

INSERT INTO `phpBB_user` (`uid`, `user_name`, `age`, `pass`) VALUES
(1, 'bala', 19, '123456');
```

**Reason:** 
- Obviously fake test data (user "bala", plaintext password "123456")
- Database: `phpBBgsoc` (Google Summer of Code test database)
- Generated: May 17, 2017
- Single test user, not real PII

### 3.4 Documentation Metadata ✅ SAFE

**File:** `docs-system/docs_flash.sql` (1,862 bytes)

**Content:** Flash documentation files metadata (titles, filenames, user_id references)

**Reason:** No PII, just file metadata for documentation system

---

## 4. SUMMARY TABLE

| Finding Type | Count | Reportable | High Confidence | Notes |
|--------------|-------|------------|-----------------|-------|
| Archives (Language Packs) | 21 | ❌ | - | Clean |
| Archives (phpBB Releases) | 28 | ❌ | - | Vendored code findings only |
| SQL Schemas (no data) | 6 | ❌ | - | Schema definitions only |
| SQL Default Data | 3 | ❌ | - | Default installation config |
| SQL Test Data | 1 | ❌ | - | Obviously fake (bala/123456) |
| SQL Documentation Metadata | 1 | ❌ | - | File metadata only |
| SQL Developer Database Dump | 2 | ⚠️ | ❌ | 2013 local dev DB, 1 email |
| **Total** | **62** | **0** | **0** | **No reportable findings** |

---

## 5. VERIFICATION PERFORMED

### Extraction Safety
✅ All archives extracted using `safe-extract-archive.sh` with:
- Path traversal protection (zip-slip prevention)
- Symlink/hardlink attack protection
- Decompression bomb limits
- Size limits enforced

### Secret Scanning
✅ All extracted archives scanned with Trufflehog v3:
- 49 archives processed
- ~180,000+ files scanned
- 0 verified secrets found
- 1 unique unverified secret (vendored code)

### SQL Dump Analysis
✅ Manual review of all 13 SQL dumps:
- Checked for PII (email, passwords, phone, address)
- Reviewed table schemas and INSERT statements
- Verified data context (production vs test vs local)
- Assessed age and exploitability

---

## 6. RECOMMENDATIONS

### For Bug Bounty Hunting
1. **Do not report** any of these findings to phpBB bug bounty programs
2. **Consider reporting** the s9e/text-formatter GitHub OAuth2 token to the upstream project
3. **Optional low-priority mention** to phpBB security team about removing old 2013 database dumps

### For phpBB Security Team (Good Hygiene)
1. Remove old local database dumps from `docs-system` repository
2. Consider adding `.sql` to `.gitignore` to prevent future accidental commits
3. Audit git history to remove sensitive commits (email address)

### For Future Scans
1. Archived repositories detected in this scan may be out of scope - verify before reporting
2. Focus on active repositories with recent commits
3. Vendored dependencies should be reported upstream, not to phpBB

---

## 7. TECHNICAL DETAILS

### Scan Metadata
- **Organization:** phpbb
- **Scan Date:** 2025-12-22
- **Total Repositories:** 6
- **Artifact Files Found:** 62
- **Archives Extracted:** 49
- **SQL Dumps Analyzed:** 13
- **Databases Found:** 0 (SQLite/binary)
- **Source Backups Found:** 0

### Tools Used
- `extract-artifact-findings.sh` - DuckDB-based artifact cataloging
- `extract-and-scan-archives.sh` - Safe extraction + Trufflehog scanning
- `safe-extract-archive.sh` - Security-hardened archive extraction
- Manual SQL analysis - grep, file examination

### Files Reviewed
```
/Users/chrism/threat_hunting/findings/phpbb/artifact-results/
├── area51-phpbb3.json
├── converter-framework.json
├── customisation-db.json
├── docs-system.json
├── phpbb.json
└── phpbb-app.json

/Users/chrism/threat_hunting/findings/phpbb/trufflehog-results/
└── customisation-db-archives.json (1,188 lines)
```

---

## CONCLUSION

**No high-confidence, reportable bug bounty findings were identified** in the phpBB artifact scan results.

All findings fall into one of these categories:
1. **Vendored code** (report upstream, not to phpBB)
2. **Test/demo data** (obviously fake)
3. **Schema-only dumps** (no data exposure)
4. **Old local dev dumps** (>10 years old, minimal PII, not exploitable)

The scan successfully validated that phpBB's release packages and language packs do not contain embedded secrets or sensitive data beyond what's expected in vendored dependencies.

