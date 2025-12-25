# Vulnerable Test Repository Catalog

Curated list of intentionally vulnerable applications for testing Semgrep rules.

---

## Java Repositories

### OWASP WebGoat

**Best for:** SQL injection, XSS, XXE, authentication, access control

```bash
# Docker (recommended)
docker run -d -p 8080:8080 -p 9090:9090 webgoat/webgoat

# Clone
git clone https://github.com/WebGoat/WebGoat.git
cd WebGoat
./mvnw spring-boot:run
```

**Vulnerability locations:**
- SQLi: `src/main/java/org/owasp/webgoat/lessons/sql_injection/`
- XSS: `src/main/java/org/owasp/webgoat/lessons/xss/`
- XXE: `src/main/java/org/owasp/webgoat/lessons/xxe/`

---

### OWASP Benchmark

**Best for:** Standardized security testing metrics

```bash
# Clone and build
git clone https://github.com/OWASP/Benchmark.git
cd Benchmark
./mvnw compile

# Run Semgrep
semgrep --config your-rule.yaml src/main/java/
```

**Ground truth:** Benchmark provides expected results in `expectedresults-*.csv`

**Vulnerability types:** CWE-22, CWE-78, CWE-79, CWE-89, CWE-90, CWE-327, CWE-328, CWE-330, CWE-501, CWE-614, CWE-643

---

### Java-Sec-Code

**Best for:** Comprehensive Java vulnerability examples

```bash
git clone https://github.com/JoyChou93/java-sec-code.git
cd java-sec-code
mvn spring-boot:run
```

**Vulnerability categories:**
- Command injection
- Deserialization
- File operations
- SSRF
- SQL injection
- SSTI
- XXE

---

## PHP Repositories

### DVWA (Damn Vulnerable Web Application)

**Best for:** SQL injection, XSS, LFI, command injection, CSRF

```bash
# Docker (recommended)
docker run -d -p 80:80 vulnerables/web-dvwa

# Login: admin/password
# Set security level to "low" for testing
```

**Vulnerability files:**
- SQLi: `vulnerabilities/sqli/source/low.php`
- XSS: `vulnerabilities/xss_*/source/low.php`
- LFI: `vulnerabilities/fi/source/low.php`
- Command: `vulnerabilities/exec/source/low.php`

---

### bWAPP

**Best for:** 100+ vulnerability types

```bash
docker run -d -p 80:80 raesene/bwapp
# or
docker run -d -p 80:80 feltsecure/owasp-bwapp
```

**Notable categories:**
- A1: Injection (SQL, OS, LDAP, XPath)
- A2: Broken Auth
- A3: XSS (Reflected, Stored, DOM)
- A4: IDOR
- A5: Security Misconfig
- A8: Insecure Deserialization

---

## JavaScript/Node.js Repositories

### OWASP Juice Shop

**Best for:** Modern JavaScript, REST APIs, Angular

```bash
# Docker
docker run -d -p 3000:3000 bkimminich/juice-shop

# npm
git clone https://github.com/juice-shop/juice-shop.git
cd juice-shop
npm install
npm start
```

**Vulnerability locations:**
- SQLi: `routes/` (sequelize queries)
- XSS: `frontend/src/app/`
- NoSQLi: Various API routes
- JWT issues: `routes/login.ts`

---

### NodeGoat

**Best for:** OWASP Top 10 in Node.js/Express

```bash
git clone https://github.com/OWASP/NodeGoat.git
cd NodeGoat
npm install
npm start
```

**Vulnerability types:**
- A1: Injection
- A2: Broken Auth
- A3: XSS
- A5: Security Misconfig
- A6: Sensitive Data
- A7: Missing Access Control

---

### Damn Vulnerable NodeJS Application (DVNA)

**Best for:** Node.js-specific vulnerabilities

```bash
git clone https://github.com/appsecco/dvna.git
cd dvna
npm install
npm start
```

---

## Python Repositories

### Damn Vulnerable Python Web Application

**Best for:** Flask/Django vulnerabilities

```bash
git clone https://github.com/anxolerd/dvpwa.git
cd dvpwa
pip install -r requirements.txt
python run.py
```

---

### PyGoat

**Best for:** Python OWASP Top 10

```bash
git clone https://github.com/adeyosemanputra/pygoat.git
cd pygoat
pip install -r requirements.txt
python manage.py runserver
```

---

### VulnPy

**Best for:** Multiple Python frameworks

```bash
git clone https://github.com/fportantier/vulnpy.git
```

Includes vulnerable examples for:
- Django
- Flask
- Pyramid
- Falcon
- Bottle

---

## Ruby Repositories

### RailsGoat

**Best for:** Ruby on Rails vulnerabilities

```bash
git clone https://github.com/OWASP/railsgoat.git
cd railsgoat
bundle install
rails db:setup
rails server
```

**Vulnerability types:**
- SQL injection
- XSS
- Command injection
- Mass assignment
- Insecure direct object references

---

## Go Repositories

### Go Vulnerable

**Best for:** Go-specific vulnerabilities

```bash
git clone https://github.com/cokeBeer/go-vulnerable.git
```

**Includes:**
- Command injection
- SQL injection
- SSRF
- Path traversal

---

## Multi-Language

### VulnHub Applications

Various intentionally vulnerable VMs available at https://www.vulnhub.com/

### HackTheBox

Provides vulnerable machines at https://www.hackthebox.eu/

---

## Quick Reference Table

| Repository | Language | Docker | Best For |
|------------|----------|--------|----------|
| WebGoat | Java | `webgoat/webgoat` | SQLi, XSS, XXE |
| Benchmark | Java | N/A | Standardized metrics |
| DVWA | PHP | `vulnerables/web-dvwa` | Basic web vulns |
| bWAPP | PHP | `raesene/bwapp` | 100+ vuln types |
| Juice Shop | Node.js | `bkimminich/juice-shop` | Modern JS/REST |
| NodeGoat | Node.js | N/A | OWASP Top 10 |
| PyGoat | Python | N/A | Python Top 10 |
| RailsGoat | Ruby | N/A | Rails vulns |

---

## Testing Protocol

1. **Start vulnerable app** (Docker or local)
2. **Run Semgrep** against source code:
   ```bash
   semgrep --config rule.yaml /path/to/vulnerable-app/ --json > results.json
   ```
3. **Count findings**: `jq '.results | length' results.json`
4. **Verify against known locations** (check documentation above)
5. **Identify false positives** (findings in safe code)
6. **Calculate metrics** and adjust rule
