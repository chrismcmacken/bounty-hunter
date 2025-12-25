# XPath Injection Vulnerabilities

Reference guide for XPath injection patterns when reviewing semgrep findings. Covers Python, Java, PHP, C#, and Ruby.

## Overview

**CWE-643**: Improper Neutralization of Data within XPath Expressions

XPath injection occurs when user input is concatenated into XPath queries without proper sanitization. Attackers can manipulate query logic to:
- Bypass authentication
- Extract sensitive data from XML documents
- Enumerate XML structure

## Attack Payloads

```
# Authentication bypass
' or '1'='1
' or ''='
admin' or '1'='1' or '1'='1

# Extract all users (union-style)
'] | //user | //user['

# Boolean-based extraction (character by character)
admin' and substring(password,1,1)='a' or '1'='2
admin' and string-length(password)>5 or '1'='2

# Error-based extraction
' and 1=2 or '
```

---

## Python: lxml / xml.etree

### The Vulnerability

Python's lxml library executes XPath queries that can be manipulated via string concatenation:

```python
from lxml import etree
from flask import request

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    tree = etree.parse('users.xml')
    # VULNERABLE: String interpolation in XPath
    query = f"//user[username='{username}' and password='{password}']"
    result = tree.xpath(query)

    if result:
        return "Login successful"
    return "Invalid credentials"
```

**Attack**: `username = "' or '1'='1"` bypasses authentication.

### Dangerous Patterns

```python
# CRITICAL: f-string/format in XPath
tree.xpath(f"//item[@id='{user_id}']")
tree.xpath("//user[name='{}']".format(name))
tree.xpath("//product[name='" + name + "']")

# CRITICAL: etree.XPath with user input
expr = etree.XPath(f"//user[@id='{user_id}']")

# CRITICAL: xml.etree.ElementTree (stdlib)
tree.find(f"./item[@name='{name}']")
tree.findall(f".//*[@category='{category}']")
```

### Safe Patterns

```python
# SAFE: Parameterized XPath (lxml supports this)
from lxml import etree

def safe_login(username, password):
    tree = etree.parse('users.xml')
    # Use XPath variables - lxml escapes them properly
    query = "//user[username=$username and password=$password]"
    result = tree.xpath(query, username=username, password=password)
    return bool(result)

# SAFE: Input validation with allowlist
import re
def safe_search(item_id):
    if not re.match(r'^[a-zA-Z0-9_-]+$', item_id):
        raise ValueError("Invalid item ID")
    tree = etree.parse('items.xml')
    return tree.xpath(f"//item[@id='{item_id}']")

# SAFE: Integer casting for numeric IDs
def get_item(item_id):
    safe_id = int(item_id)  # Throws on non-integer input
    tree = etree.parse('items.xml')
    return tree.xpath(f"//item[@id='{safe_id}']")
```

### Custom Semgrep Rule

We have `custom-rules/web-vulns/xpath-injection.yaml` with rule `python-xpath-injection` that detects:
- Flask/Django/FastAPI sources flowing to lxml xpath sinks
- etree.XPath() with tainted input
- xml.etree find/findall/iterfind with tainted input

---

## Java: javax.xml.xpath

### The Vulnerability

Java's XPath API is vulnerable when queries are built via string concatenation:

```java
import javax.xml.xpath.*;

@GetMapping("/user")
public User findUser(@RequestParam("username") String username) {
    XPath xpath = XPathFactory.newInstance().newXPath();
    // VULNERABLE: String concatenation
    String expression = "//user[name='" + username + "']";
    Node result = (Node) xpath.evaluate(expression, doc, XPathConstants.NODE);
    return parseUser(result);
}
```

### Dangerous Patterns

```java
// CRITICAL: String concatenation in evaluate()
xpath.evaluate("//user[name='" + username + "']", doc);
xpath.evaluate("//item[@id='" + id + "']", doc, XPathConstants.NODESET);

// CRITICAL: compile() with user input
XPathExpression expr = xpath.compile("//user[name='" + name + "']");

// CRITICAL: Servlet request parameters
String name = request.getParameter("name");
xpath.evaluate("//product[name='" + name + "']", doc);
```

### Safe Patterns

```java
// SAFE: XPath Variable Resolver
XPath xpath = XPathFactory.newInstance().newXPath();
xpath.setXPathVariableResolver(new XPathVariableResolver() {
    @Override
    public Object resolveVariable(QName variableName) {
        if (variableName.getLocalPart().equals("username")) {
            return sanitizedUsername;  // Return the safe value
        }
        return null;
    }
});

// Use variable reference in XPath
String expression = "//user[name=$username]";
Node result = (Node) xpath.evaluate(expression, doc, XPathConstants.NODE);

// SAFE: Input validation with regex
if (!username.matches("^[a-zA-Z0-9_]+$")) {
    throw new IllegalArgumentException("Invalid username");
}
xpath.evaluate("//user[name='" + username + "']", doc);

// SAFE: Numeric ID casting
int safeId = Integer.parseInt(userId);
xpath.evaluate("//item[@id='" + safeId + "']", doc);
```

### Custom Semgrep Rule

We have `custom-rules/web-vulns/xpath-injection.yaml` with rule `java-xpath-injection` that detects:
- Spring `@RequestParam`/`@PathVariable` sources
- Servlet `request.getParameter()` sources
- `XPath.evaluate()` and `XPath.compile()` sinks

---

## PHP: SimpleXML / DOMXPath

### The Vulnerability

PHP's SimpleXML and DOMXPath execute XPath queries vulnerable to injection:

```php
$username = $_POST['username'];
$password = $_POST['password'];

$xml = simplexml_load_file('users.xml');
// VULNERABLE: Variable interpolation in XPath
$result = $xml->xpath("//user[username='$username' and password='$password']");
```

### Dangerous Patterns

```php
// CRITICAL: SimpleXML with interpolation
$xml->xpath("//user[name='$name']");
$xml->xpath("//item[@id='" . $id . "']");

// CRITICAL: DOMXPath query/evaluate
$xpath = new DOMXPath($doc);
$xpath->query("//user[name='$name']");
$xpath->evaluate("//product[@category='$category']");

// CRITICAL: Laravel request input
$category = $request->input('category');
$xml->xpath("//product[@category='$category']");
```

### Safe Patterns

```php
// SAFE: Input validation with preg_match
if (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
    throw new InvalidArgumentException('Invalid username');
}
$xml->xpath("//user[name='$username']");

// SAFE: Type casting for numeric IDs
$safeId = (int) $_GET['id'];
$xml->xpath("//item[@id='$safeId']");

// SAFE: Allowlist validation
$allowed = ['electronics', 'clothing', 'food'];
if (!in_array($category, $allowed, true)) {
    throw new InvalidArgumentException('Invalid category');
}
$xml->xpath("//product[@category='$category']");

// SAFE: ctype validation
if (!ctype_alnum($code)) {
    throw new InvalidArgumentException('Invalid code');
}
```

### Custom Semgrep Rule

We have `custom-rules/web-vulns/xpath-injection.yaml` with rule `php-xpath-injection` that detects:
- `$_GET`/`$_POST`/`$_REQUEST` sources
- Laravel `$request->input()` sources
- SimpleXML `xpath()` and DOMXPath `query()`/`evaluate()` sinks

---

## C#: System.Xml.XPath

### The Vulnerability

.NET's XPath APIs are vulnerable to injection via string concatenation:

```csharp
string username = Request.Query["username"];

XmlDocument doc = new XmlDocument();
doc.Load("users.xml");

// VULNERABLE: String interpolation
XmlNodeList nodes = doc.SelectNodes($"//user[name='{username}']");
```

### Dangerous Patterns

```csharp
// CRITICAL: XmlDocument.SelectNodes/SelectSingleNode
doc.SelectNodes($"//user[name='{name}']");
doc.SelectSingleNode("//item[@id='" + id + "']");

// CRITICAL: XPathNavigator methods
navigator.Select($"//user[name='{name}']");
navigator.SelectSingleNode("//product[@id='" + id + "']");
navigator.Evaluate($"count(//user[role='{role}'])");

// CRITICAL: ASP.NET Core request sources
var name = Request.Query["name"];
var data = Request.Form["data"];
var id = HttpContext.Request.Query["id"];
```

### Safe Patterns

```csharp
// SAFE: Regex validation
if (!Regex.IsMatch(username, @"^[a-zA-Z0-9_]+$")) {
    throw new ArgumentException("Invalid username");
}
doc.SelectNodes($"//user[name='{username}']");

// SAFE: Type parsing for numeric IDs
if (!int.TryParse(id, out int safeId)) {
    throw new ArgumentException("Invalid ID");
}
doc.SelectNodes($"//item[@id='{safeId}']");

// SAFE: XsltContext with custom variable resolver
// (More complex - requires implementing IXsltContextVariable)
```

### Custom Semgrep Rule

We have `custom-rules/web-vulns/xpath-injection.yaml` with rule `csharp-xpath-injection` that detects:
- `Request.Query`/`Request.Form` sources
- `HttpContext.Request` sources
- `XmlDocument`/`XPathNavigator` sinks

---

## Ruby: Nokogiri / REXML

### The Vulnerability

Ruby's Nokogiri and REXML libraries execute XPath queries vulnerable to injection:

```ruby
username = params[:username]
password = params[:password]

doc = Nokogiri::XML(File.read('users.xml'))
# VULNERABLE: String interpolation
result = doc.xpath("//user[username='#{username}' and password='#{password}']")
```

### Dangerous Patterns

```ruby
# CRITICAL: Nokogiri with interpolation
doc.xpath("//item[@id='#{id}']")
doc.at_xpath("//user[name='#{name}']")

# CRITICAL: REXML XPath
REXML::XPath.first(doc, "//user[name='#{name}']")
REXML::XPath.each(doc, "//item[@category='#{cat}']")
REXML::XPath.match(doc, "//product[@id='#{id}']")

# CRITICAL: Rails params
name = params[:name]
doc.xpath("//user[name='#{name}']")
```

### Safe Patterns

```ruby
# SAFE: Regex validation
unless username.match?(/\A[a-zA-Z0-9_]+\z/)
  raise ArgumentError, 'Invalid username'
end
doc.xpath("//user[name='#{username}']")

# SAFE: Integer conversion for numeric IDs
safe_id = params[:id].to_i
doc.xpath("//item[@id='#{safe_id}']")

# SAFE: Allowlist validation
allowed = %w[electronics clothing food]
unless allowed.include?(category)
  raise ArgumentError, 'Invalid category'
end
```

### Custom Semgrep Rule

We have `custom-rules/web-vulns/xpath-injection.yaml` with rule `ruby-xpath-injection` that detects:
- Rails `params[]` sources
- Nokogiri `xpath()`/`at_xpath()` sinks
- REXML `XPath.first()`/`XPath.each()`/`XPath.match()` sinks

---

## Exploitability Assessment

When reviewing XPath injection findings, verify:

### Is Input User-Controlled?
- Direct from request parameters, form data, headers?
- From database that user can modify?
- From file that user can upload?

### Can Dangerous Characters Reach the Sink?
- Single quotes (`'`) - Required for most XPath injection
- Square brackets (`[`, `]`) - For predicate injection
- Pipe (`|`) - For union queries
- Parentheses - For function calls

**NOT Exploitable if:**
- Input is cast to integer (`int()`, `(int)`, `.to_i`)
- Input validated against strict alphanumeric regex
- Input from allowlist/enum

### Is There Authentication Context?
- Admin-only endpoints → Lower risk
- Public endpoints → Higher risk

---

## Checklist for XPath Injection Review

When reviewing semgrep XPath injection findings:

- [ ] **Trace data flow**: Does user input reach the XPath query?
- [ ] **Check for sanitization**: Is input validated before use?
- [ ] **Look for parameterization**: lxml supports XPath variables (`$varname`)
- [ ] **Verify character constraints**: Can quotes/brackets reach the sink?
- [ ] **Check type casting**: Integer casting prevents injection
- [ ] **Consider XML structure**: What data could be extracted?
- [ ] **Assess impact**: Authentication bypass? Data extraction?

---

## References

- https://owasp.org/www-community/attacks/XPATH_Injection
- https://book.hacktricks.xyz/pentesting-web/xpath-injection
- https://cwe.mitre.org/data/definitions/643.html
