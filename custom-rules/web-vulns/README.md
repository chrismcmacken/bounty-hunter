# Web Vulnerability Detection Rules

Custom semgrep rules for detecting web application vulnerabilities commonly found in bug bounty programs. These rules supplement semgrep's `p/default` ruleset with additional coverage for edge cases, language-specific quirks, and patterns that standard rules miss.

## Rule Coverage

| Rule File | Vulnerability | CWE | Languages |
|-----------|--------------|-----|-----------|
| `deserialization-taint.yaml` | Insecure Deserialization | CWE-502 | Python, Java, Ruby, PHP, Node.js, C# |
| `ssrf-taint.yaml` | Server-Side Request Forgery | CWE-918 | Python, Node.js, Java, Go, Ruby, PHP |
| `ssti-taint.yaml` | Server-Side Template Injection | CWE-1336 | Python, PHP, Node.js, Java, Ruby, Go |
| `php-parse-url-bypass.yaml` | SSRF/Validation Bypass | CWE-918 | PHP |
| `mongodb-nosql-injection.yaml` | NoSQL Injection | CWE-943 | Python, Node.js, Java, Go, Ruby |
| `xpath-injection.yaml` | XPath Injection | CWE-643 | Python, Java, PHP, C#, Ruby |
| `python-dynamic-import-lfi.yaml` | Local File Inclusion | CWE-98 | Python |

---

## New Rules

### 1. MongoDB/NoSQL Injection (`mongodb-nosql-injection.yaml`)

**Vulnerability:** CWE-943 - Improper Neutralization of Special Elements in Data Query Logic

**Why This Rule Exists:**
Semgrep's `p/default` includes NoSQL injection rules for JavaScript (via njsscan) and Java, but **lacks Python pymongo coverage**. Python is widely used with MongoDB in web applications (Flask, Django, FastAPI), making this a significant gap.

**Attack Pattern:**
NoSQL injection occurs when user input is passed directly to MongoDB query operators like `$where`, `$regex`, or `$ne`. Unlike SQL injection, NoSQL injection exploits the document-based query structure.

**Vulnerable Code Examples:**

```python
# Python - Direct query construction
from flask import request
from pymongo import MongoClient

db = MongoClient().mydb

@app.route('/user')
def get_user():
    username = request.args.get('username')
    # VULNERABLE: User input directly in query
    user = db.users.find_one({'username': username})
    return user

@app.route('/search')
def search():
    query = request.json
    # VULNERABLE: Entire query object from user input
    results = db.products.find(query)
    return list(results)
```

```javascript
// Node.js - Operator injection
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    // VULNERABLE: Attacker can send {"$ne": ""} as password
    const user = await db.collection('users').findOne({
        username: username,
        password: password
    });
});
```

**Attack Payloads:**
```json
// Authentication bypass
{"username": "admin", "password": {"$ne": ""}}
{"username": "admin", "password": {"$gt": ""}}

// Data extraction via $regex
{"username": {"$regex": "^a"}}

// JavaScript injection via $where
{"$where": "this.password.length > 0"}
```

**Remediation:**
```python
# Safe: Validate input types
def get_user(username):
    if not isinstance(username, str):
        raise ValueError("Username must be a string")
    return db.users.find_one({'username': username})

# Safe: Use explicit field access, reject operators
def safe_query(user_input):
    if any(key.startswith('$') for key in user_input.keys()):
        raise ValueError("Query operators not allowed")
    return db.collection.find(user_input)
```

**References:**
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection
- https://book.hacktricks.xyz/pentesting-web/nosql-injection
- https://nullsweep.com/nosql-injection-cheatsheet/

---

### 2. XPath Injection (`xpath-injection.yaml`)

**Vulnerability:** CWE-643 - Improper Neutralization of Data within XPath Expressions

**Why This Rule Exists:**
Semgrep's `p/default` covers XPath injection for C# and partially for PHP, but **lacks coverage for Python (lxml, defusedxml) and Java (javax.xml.xpath)**. XPath injection is less common than SQLi but can be equally devastating when XML-based authentication or data storage is used.

**Attack Pattern:**
XPath injection occurs when user input is concatenated into XPath queries without proper escaping. Attackers can manipulate the query logic to bypass authentication, extract sensitive data, or enumerate the XML structure.

**Vulnerable Code Examples:**

```python
# Python lxml - Authentication bypass
from lxml import etree
from flask import request

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    tree = etree.parse('users.xml')
    # VULNERABLE: String concatenation in XPath
    query = f"//user[username='{username}' and password='{password}']"
    result = tree.xpath(query)

    if result:
        return "Login successful"
    return "Invalid credentials"
```

```java
// Java - Data extraction
import javax.xml.xpath.*;

public User findUser(String username) {
    XPath xpath = XPathFactory.newInstance().newXPath();
    // VULNERABLE: User input in XPath expression
    String expression = "//user[name='" + username + "']";
    Node result = (Node) xpath.evaluate(expression, doc, XPathConstants.NODE);
    return parseUser(result);
}
```

```php
// PHP - SimpleXML injection
$username = $_POST['username'];
$password = $_POST['password'];

$xml = simplexml_load_file('users.xml');
// VULNERABLE: Direct interpolation
$result = $xml->xpath("//user[username='$username' and password='$password']");
```

**Attack Payloads:**
```
# Authentication bypass
username: ' or '1'='1
password: ' or '1'='1

# Extract all users
username: '] | //user | //user['

# Boolean-based extraction
username: admin' and substring(password,1,1)='a' or '1'='2
```

**Remediation:**
```python
# Safe: Parameterized XPath (lxml supports this)
from lxml import etree

def safe_login(username, password):
    tree = etree.parse('users.xml')
    # Use XPath variables
    query = "//user[username=$username and password=$password]"
    result = tree.xpath(query, username=username, password=password)
    return bool(result)

# Safe: Input validation
import re
def validate_xpath_input(value):
    if not re.match(r'^[a-zA-Z0-9_]+$', value):
        raise ValueError("Invalid characters in input")
    return value
```

```java
// Safe: Use XPath variables (Java)
XPathExpression expr = xpath.compile("//user[name=$username]");
xpath.setXPathVariableResolver(new XPathVariableResolver() {
    public Object resolveVariable(QName var) {
        if (var.getLocalPart().equals("username")) {
            return sanitizedUsername;
        }
        return null;
    }
});
```

**References:**
- https://owasp.org/www-community/attacks/XPATH_Injection
- https://book.hacktricks.xyz/pentesting-web/xpath-injection
- https://cwe.mitre.org/data/definitions/643.html

---

### 3. Python Dynamic Import LFI (`python-dynamic-import-lfi.yaml`)

**Vulnerability:** CWE-98 - Improper Control of Filename for Include/Require Statement

**Why This Rule Exists:**
Python's dynamic import mechanisms (`importlib.import_module()`, `__import__()`, `exec()`) can be exploited for Local File Inclusion when user input controls the module path. This is **not covered by p/default** and is a Python-specific attack vector.

**Attack Pattern:**
When user input controls which module is imported, attackers can:
1. Import arbitrary modules to trigger side effects in `__init__.py`
2. Access sensitive modules (e.g., `os`, `subprocess`) if combined with attribute access
3. Cause denial of service by importing resource-intensive modules
4. In some cases, achieve code execution via specially crafted module files

**Vulnerable Code Examples:**

```python
# Flask - Plugin system vulnerability
from flask import request
import importlib

@app.route('/plugin/<name>')
def load_plugin(name):
    # VULNERABLE: User controls module name
    plugin = importlib.import_module(f'plugins.{name}')
    return plugin.run()

@app.route('/theme')
def set_theme():
    theme = request.args.get('theme')
    # VULNERABLE: Path traversal possible
    module = importlib.import_module(f'themes.{theme}')
    return module.apply()
```

```python
# Django - Dynamic view loading
from django.http import HttpRequest

def dynamic_view(request: HttpRequest):
    view_name = request.GET.get('view')
    # VULNERABLE: Arbitrary module import
    module = __import__(view_name)
    return module.handle(request)
```

```python
# FastAPI - Configuration loading
from fastapi import FastAPI, Query
import importlib

@app.get('/config')
def get_config(name: str = Query(...)):
    # VULNERABLE: User-controlled import
    config = importlib.import_module(name)
    return config.settings
```

**Attack Payloads:**
```
# Access system modules
/plugin/os
/plugin/subprocess
/plugin/..%2F..%2Fos  (path traversal attempt)

# Trigger side effects
/plugin/logging  (might expose configuration)
/plugin/unittest  (resource exhaustion)

# If attribute access follows import
/plugin/os&attr=system  (if code does getattr(module, attr))
```

**Remediation:**
```python
# Safe: Allowlist of permitted modules
ALLOWED_PLUGINS = {'analytics', 'export', 'notifications'}

def load_plugin(name):
    if name not in ALLOWED_PLUGINS:
        raise ValueError(f"Unknown plugin: {name}")
    return importlib.import_module(f'plugins.{name}')

# Safe: Validate module name format
import re

def safe_import(name):
    # Only allow alphanumeric and underscore
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', name):
        raise ValueError("Invalid module name")
    # Ensure it's within expected package
    if '..' in name or name.startswith('.'):
        raise ValueError("Path traversal attempt")
    return importlib.import_module(f'plugins.{name}')

# Safe: Use a registry pattern
PLUGIN_REGISTRY = {
    'analytics': 'myapp.plugins.analytics',
    'export': 'myapp.plugins.export',
}

def load_plugin(name):
    if name not in PLUGIN_REGISTRY:
        raise ValueError(f"Unknown plugin: {name}")
    return importlib.import_module(PLUGIN_REGISTRY[name])
```

**References:**
- https://cwe.mitre.org/data/definitions/98.html
- https://docs.python.org/3/library/importlib.html#importlib.import_module
- https://book.hacktricks.xyz/generic-methodologies-and-resources/python/bypass-python-sandboxes

---

## Usage

These rules are automatically included when running scans with `scan-semgrep.sh`:

```bash
# Full scan with custom rules (default)
./scripts/scan-semgrep.sh <org-name>

# Scan without custom rules
./scripts/scan-semgrep.sh <org-name> --no-custom-rules

# Test a specific rule
semgrep --config custom-rules/web-vulns/mongodb-nosql-injection.yaml /path/to/code
```

## Rule Design Principles

1. **Taint Mode First**: All rules use semgrep's taint mode (`mode: taint`) for accurate dataflow tracking from sources (user input) to sinks (dangerous functions).

2. **Framework-Aware Sources**: Each rule includes sources for common web frameworks:
   - Python: Flask, Django, FastAPI
   - JavaScript: Express, Koa, Hapi
   - Java: Spring, Servlets
   - PHP: Laravel, raw superglobals
   - Ruby: Rails
   - Go: Gin, net/http

3. **Sanitizer Recognition**: Rules include common sanitization patterns to reduce false positives.

4. **CVE References**: Where applicable, rules reference specific CVEs to help prioritize findings.

5. **High Confidence Focus**: Rules are tuned for bug bounty hunting - prioritizing true positives over comprehensive coverage.

## Contributing

When adding new rules:
1. Include taint mode with explicit sources and sinks
2. Add sanitizer patterns to reduce false positives
3. Test against real-world vulnerable code samples
4. Include references to CWE, OWASP, and relevant CVEs
5. Document attack patterns and remediation in this README
