# Data Flow Tracing Guide

Systematic approach to tracing user input from source to sink across different frameworks and languages.

## General Strategy

### Forward Tracing (Source → Sink)

1. **Start at entry point**
   - HTTP handler, CLI parser, file reader
2. **Follow the data**
   - Variable assignments, function calls, returns
3. **Note transformations**
   - Parsing, validation, sanitization
4. **End at dangerous operation**
   - Database, filesystem, command execution

### Backward Tracing (Sink → Source)

1. **Start at dangerous function**
   - `exec()`, `query()`, `readFile()`
2. **Trace parameters backward**
   - Where does this value come from?
3. **Find the origin**
   - Is it user-controlled?
4. **Check intermediate controls**
   - Was it validated/sanitized?

## Framework-Specific Entry Points

### Express.js (Node.js)

```javascript
// Direct access
req.query.param      // GET params (?param=value)
req.body.field       // POST body (needs body-parser)
req.params.id        // URL params (/user/:id)
req.headers['x-custom']  // Headers
req.cookies.session  // Cookies

// Common patterns
app.get('/path', (req, res) => {
    const userInput = req.query.input;  // SOURCE
});

// Middleware chain
app.use(express.json());  // Enables req.body
```

**Search patterns:**
```bash
grep -rn "req\.query\|req\.body\|req\.params" <repo>/
grep -rn "app\.get\|app\.post\|router\." <repo>/
```

### Django (Python)

```python
# Direct access
request.GET['param']      # GET params
request.POST['field']     # POST body
request.FILES['upload']   # File uploads
request.META['HTTP_*']    # Headers
request.COOKIES['name']   # Cookies
request.path              # URL path

# Common patterns
def view(request):
    user_input = request.GET.get('input')  # SOURCE

# URL params
path('user/<int:id>/', views.user_detail)
```

**Search patterns:**
```bash
grep -rn "request\.GET\|request\.POST\|request\.FILES" <repo>/
grep -rn "def.*request\)" <repo>/
```

### Flask (Python)

```python
# Direct access
request.args.get('param')    # GET params
request.form.get('field')    # POST form
request.json                  # JSON body
request.files['upload']       # File uploads
request.headers['X-Custom']   # Headers
request.cookies.get('name')   # Cookies

# Common patterns
@app.route('/path')
def handler():
    user_input = request.args.get('input')  # SOURCE
```

**Search patterns:**
```bash
grep -rn "request\.args\|request\.form\|request\.json" <repo>/
grep -rn "@app\.route\|@blueprint\.route" <repo>/
```

### Spring (Java)

```java
// Annotations for input
@RequestParam String param       // GET/POST params
@PathVariable String id          // URL params
@RequestBody Object body         // JSON body
@RequestHeader String header     // Headers
@CookieValue String cookie       // Cookies

// Common patterns
@GetMapping("/path")
public String handler(@RequestParam String input) {  // SOURCE
    return process(input);
}

// HttpServletRequest direct access
request.getParameter("param")
request.getHeader("header")
```

**Search patterns:**
```bash
grep -rn "@RequestParam\|@PathVariable\|@RequestBody" <repo>/
grep -rn "getParameter\|getHeader" <repo>/
```

### Laravel (PHP)

```php
// Direct access
$request->input('param')     // GET/POST params
$request->query('param')     // GET only
$request->post('field')      // POST only
$request->file('upload')     // File uploads
$request->header('X-Custom') // Headers
$request->cookie('name')     // Cookies

// Common patterns
public function show(Request $request) {
    $input = $request->input('data');  // SOURCE
}

// Route params
Route::get('/user/{id}', [Controller::class, 'show']);
```

**Search patterns:**
```bash
grep -rn "\$request->input\|\$request->query" <repo>/
grep -rn "Route::get\|Route::post" <repo>/
```

### Raw PHP

```php
// Superglobals (ALWAYS DANGEROUS)
$_GET['param']
$_POST['field']
$_REQUEST['any']
$_FILES['upload']
$_SERVER['HTTP_*']
$_COOKIE['name']

// Common patterns
$input = $_GET['input'];  // SOURCE - no framework protection
```

**Search patterns:**
```bash
grep -rn "\$_GET\|\$_POST\|\$_REQUEST\|\$_COOKIE" <repo>/
```

### Go (net/http)

```go
// Direct access
r.URL.Query().Get("param")    // GET params
r.FormValue("field")          // POST form
r.Header.Get("X-Custom")      // Headers
json.NewDecoder(r.Body)       // JSON body

// Common patterns
func handler(w http.ResponseWriter, r *http.Request) {
    input := r.URL.Query().Get("input")  // SOURCE
}

// Mux path params
mux.Vars(r)["id"]
```

**Search patterns:**
```bash
grep -rn "r\.URL\.Query\|r\.FormValue\|r\.Header" <repo>/
grep -rn "func.*http\.ResponseWriter" <repo>/
```

### Ruby on Rails

```ruby
# Direct access
params[:field]          # GET/POST params
request.headers['X-Custom']  # Headers
cookies[:name]          # Cookies
request.body.read       # Raw body

# Common patterns
def show
  @input = params[:input]  # SOURCE
end

# Strong params (partial sanitization)
params.require(:user).permit(:name, :email)
```

**Search patterns:**
```bash
grep -rn "params\[" <repo>/
grep -rn "def.*\n.*params" <repo>/
```

## Common Sinks by Vulnerability Type

### Command Injection

```python
# Python
os.system(cmd)
subprocess.run(cmd, shell=True)
subprocess.Popen(cmd, shell=True)
os.popen(cmd)
commands.getoutput(cmd)

# Node.js
child_process.exec(cmd)
child_process.execSync(cmd)
child_process.spawn(cmd, {shell: true})

# PHP
exec($cmd)
system($cmd)
shell_exec($cmd)
passthru($cmd)
popen($cmd)
`$cmd`

# Java
Runtime.getRuntime().exec(cmd)
ProcessBuilder(cmd)

# Ruby
system(cmd)
`cmd`
exec(cmd)
%x{cmd}
```

### SQL Injection

```python
# Python
cursor.execute(f"SELECT * FROM users WHERE id = {user_input}")
cursor.execute("SELECT * FROM users WHERE id = " + user_input)

# Node.js
connection.query("SELECT * FROM users WHERE id = " + userId)

# PHP
mysqli_query($conn, "SELECT * FROM users WHERE id = $id")
$pdo->query("SELECT * FROM users WHERE id = " . $id)

# Java
statement.executeQuery("SELECT * FROM users WHERE id = " + userId)

# Ruby
User.where("name = '#{params[:name]}'")
```

### Path Traversal

```python
# Python
open(user_path)
os.path.join(base, user_path)  # Still vulnerable!
pathlib.Path(base) / user_path

# Node.js
fs.readFile(userPath)
path.join(base, userPath)  # Still vulnerable!
fs.createReadStream(userPath)

# PHP
file_get_contents($path)
include($path)
require($path)
fopen($path)

# Java
new File(userPath)
new FileInputStream(userPath)
Paths.get(userPath)
```

### SSRF

```python
# Python
requests.get(user_url)
urllib.request.urlopen(user_url)
httpx.get(user_url)

# Node.js
fetch(userUrl)
axios.get(userUrl)
http.get(userUrl)

# PHP
file_get_contents($url)
curl_exec($ch)  // with CURLOPT_URL from user

# Java
new URL(userUrl).openConnection()
HttpClient.newHttpClient().send(...)
RestTemplate.getForObject(userUrl)
```

### Template Injection

```python
# Python (Jinja2)
Template(user_input).render()
render_template_string(user_input)

# Node.js (EJS)
ejs.render(userTemplate)
res.render(template, {settings: userInput})  # CVE-2022-29078

# Java (Freemarker)
Template t = new Template("name", new StringReader(userInput))
t.process(model, out)

# PHP (Twig)
$twig->createTemplate($userInput)->render()
```

### Deserialization

```python
# Python
pickle.loads(user_data)
yaml.load(user_data)  # Without Loader=SafeLoader
marshal.loads(user_data)

# Node.js
node-serialize.unserialize(userData)
js-yaml.load(userData)

# PHP
unserialize($userData)

# Java
new ObjectInputStream(userStream).readObject()

# Ruby
Marshal.load(user_data)
YAML.load(user_data)
```

## Tracing Techniques

### Static Analysis Commands

```bash
# Find all entry points
grep -rn "@app.route\|@router\|app.get\|app.post" <repo>/

# Find all dangerous sinks
grep -rn "exec\|system\|eval\|query\|readFile" <repo>/

# Find all user input access
grep -rn "request\.\|req\.\|params\[" <repo>/

# Find function definitions
grep -rn "def\s+vulnerable_function\|function vulnerable_function" <repo>/

# Find function calls
grep -rn "vulnerable_function(" <repo>/
```

### Call Graph Analysis

```bash
# Find what calls a function
grep -rn "dangerous_function(" <repo>/

# Find what a function calls
grep -A 50 "def dangerous_function" <repo>/<file>.py | head -60

# Find class methods
grep -rn "class.*:\|def.*self" <repo>/<file>.py
```

### IDE/LSP Features

```
# Go to definition - trace where function is defined
# Find all references - trace where function is called
# Show call hierarchy - see callers and callees
```

### Dynamic Tracing (if allowed)

```python
# Python debugging
import pdb; pdb.set_trace()

# Logging injection points
print(f"DEBUG: input = {user_input}")

# Request interception
# Use Burp Suite to see actual HTTP flow
```

## Red Flags to Watch For

### Immediate Concerns

| Pattern | Risk |
|---------|------|
| String concatenation in query | SQL Injection |
| `shell=True` with user input | Command Injection |
| `eval()` / `exec()` with user data | Code Execution |
| Path operations without validation | Path Traversal |
| URL building with user input | SSRF |
| Template with user content | SSTI |
| Deserialization of user data | RCE |

### Subtle Issues

| Pattern | Risk |
|---------|------|
| Validation AFTER transformation | Bypass possible |
| Client-side only validation | No server protection |
| Denylist instead of allowlist | Bypass possible |
| Type coercion in comparisons | Authentication bypass |
| Race conditions in checks | TOCTOU |
| Regex without anchors | Partial match bypass |

### Framework Misuse

| Pattern | Risk |
|---------|------|
| `render_template_string()` | SSTI (should use `render_template()`) |
| `cursor.execute(f"...")` | SQLi (should use parameterized) |
| `path.join()` without validation | Path traversal (path.join doesn't prevent ../) |
| Express without body-parser | req.body undefined, logic errors |
