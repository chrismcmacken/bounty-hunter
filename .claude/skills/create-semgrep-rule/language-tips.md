# Language-Specific Semgrep Tips

Quick reference for language-specific patterns, gotchas, and common sources/sinks.

## Python

### Common Sources (User Input)
```yaml
# Flask
- pattern: request.args[...]
- pattern: request.args.get(...)
- pattern: request.form[...]
- pattern: request.json[...]
- pattern: request.data
- pattern: request.cookies[...]
- pattern: request.headers[...]

# Django
- pattern: request.GET[...]
- pattern: request.GET.get(...)
- pattern: request.POST[...]
- pattern: request.POST.get(...)
- pattern: request.body

# FastAPI
- pattern: $PARAM  # Function parameters with type hints

# General
- pattern: input(...)
- pattern: sys.argv[...]
- pattern: os.environ[...]
```

### Common Sinks
```yaml
# Command Injection
- pattern: os.system($CMD)
- pattern: os.popen($CMD)
- pattern: subprocess.call($CMD, shell=True, ...)
- pattern: subprocess.Popen($CMD, shell=True, ...)
- pattern: subprocess.run($CMD, shell=True, ...)

# SQL Injection
- pattern: cursor.execute($Q)
- pattern: connection.execute($Q)
- pattern: $DB.execute($Q)
- pattern: engine.execute($Q)

# Code Execution
- pattern: eval(...)
- pattern: exec(...)
- pattern: compile(...)

# Deserialization
- pattern: pickle.loads(...)
- pattern: yaml.load(...) # Without Loader=SafeLoader
- pattern: marshal.loads(...)

# Path Traversal
- pattern: open($PATH, ...)
- pattern: os.path.join(..., $PATH, ...)
```

### Python Gotchas
- f-strings: Use `pattern: f"..."` to match f-strings
- Named arguments: `subprocess.run(cmd, shell=True)` - order matters for `shell=True`
- Decorators: Use `pattern-inside` to match decorated functions

---

## JavaScript / TypeScript

### Common Sources
```yaml
# Express.js
- pattern: req.params[...]
- pattern: req.params.$PARAM
- pattern: req.query[...]
- pattern: req.query.$PARAM
- pattern: req.body[...]
- pattern: req.body.$FIELD
- pattern: req.headers[...]
- pattern: req.cookies[...]

# Browser
- pattern: document.location
- pattern: window.location
- pattern: document.URL
- pattern: document.referrer
- pattern: $ELEM.innerHTML
- pattern: localStorage.getItem(...)
- pattern: sessionStorage.getItem(...)

# URL/Query parsing
- pattern: new URL(...).searchParams
- pattern: new URLSearchParams(...)
```

### Common Sinks
```yaml
# XSS
- pattern: $ELEM.innerHTML = $DATA
- pattern: document.write($DATA)
- pattern: $(...).html($DATA)  # jQuery
- pattern: dangerouslySetInnerHTML={{__html: $DATA}}  # React

# Command Injection (Node.js)
- pattern: child_process.exec($CMD, ...)
- pattern: child_process.execSync($CMD, ...)
- pattern: child_process.spawn($CMD, {shell: true}, ...)

# SQL Injection
- pattern: $DB.query($SQL, ...)
- pattern: $DB.raw($SQL)
- pattern: sequelize.query($SQL, ...)

# Code Execution
- pattern: eval($CODE)
- pattern: new Function($CODE)
- pattern: setTimeout($CODE, ...)  # When CODE is string
- pattern: setInterval($CODE, ...)

# Path Traversal
- pattern: fs.readFile($PATH, ...)
- pattern: fs.readFileSync($PATH, ...)
- pattern: path.join(..., $PATH, ...)
```

### JavaScript Gotchas
- Template literals: Use `pattern: \`...\`` with backticks
- Destructuring: `const {param} = req.query` - may need metavariable-pattern
- Optional chaining: `req.body?.field` - use `...` in pattern
- TypeScript types: Semgrep ignores type annotations, patterns work on runtime code

---

## Go

### Common Sources
```yaml
# net/http
- pattern: r.URL.Query().Get(...)
- pattern: r.FormValue(...)
- pattern: r.PostFormValue(...)
- pattern: r.Header.Get(...)
- pattern: r.Body

# Gin
- pattern: c.Query(...)
- pattern: c.PostForm(...)
- pattern: c.Param(...)
- pattern: c.GetHeader(...)

# Echo
- pattern: c.QueryParam(...)
- pattern: c.FormValue(...)
- pattern: c.Param(...)
```

### Common Sinks
```yaml
# Command Injection
- pattern: exec.Command($CMD, ...).Run()
- pattern: exec.Command($CMD, ...).Output()
- pattern: exec.Command($CMD, ...).CombinedOutput()

# SQL Injection
- pattern: db.Query($SQL, ...)
- pattern: db.Exec($SQL, ...)
- pattern: db.QueryRow($SQL, ...)
- pattern: tx.Query($SQL, ...)

# Path Traversal
- pattern: os.Open($PATH)
- pattern: os.ReadFile($PATH)
- pattern: ioutil.ReadFile($PATH)
- pattern: filepath.Join(..., $PATH, ...)

# SSRF
- pattern: http.Get($URL)
- pattern: http.Post($URL, ...)
- pattern: client.Get($URL)
```

### Go Gotchas
- Error handling: Patterns match regardless of `if err != nil` checks
- Use `pattern-not-inside` for safe patterns: `if err != nil { return }`
- Interfaces: Can't match interface implementations directly
- Multiple return values: Pattern on the specific value you care about

---

## Java

### Common Sources
```yaml
# Servlet
- pattern: request.getParameter(...)
- pattern: request.getParameterValues(...)
- pattern: request.getHeader(...)
- pattern: request.getCookies()
- pattern: request.getInputStream()

# Spring
- pattern: $PARAM  # @RequestParam annotated
- pattern: $BODY  # @RequestBody annotated

# JAX-RS
- pattern: $PARAM  # @QueryParam, @PathParam annotated
```

### Common Sinks
```yaml
# SQL Injection
- pattern: $STMT.executeQuery($SQL)
- pattern: $STMT.executeUpdate($SQL)
- pattern: $STMT.execute($SQL)
- pattern: $CONN.prepareStatement($SQL)

# Command Injection
- pattern: Runtime.getRuntime().exec($CMD)
- pattern: new ProcessBuilder($CMD).start()

# XXE
- pattern: $FACTORY.newDocumentBuilder().parse($INPUT)
- pattern: $READER.parse($INPUT)

# Deserialization
- pattern: new ObjectInputStream(...).readObject()
- pattern: $MAPPER.readValue($INPUT, ...)

# Path Traversal
- pattern: new File($PATH)
- pattern: new FileInputStream($PATH)
- pattern: Files.readAllBytes(Paths.get($PATH))

# SSRF
- pattern: new URL($URL).openConnection()
- pattern: new URL($URL).openStream()
```

### Java Gotchas
- Annotations: Can match with `@Annotation` in pattern
- Generics: Type parameters usually ignored
- Lambdas: Match the lambda body directly
- Static imports: Full class path may be needed

---

## PHP

### Common Sources
```yaml
- pattern: $_GET[...]
- pattern: $_POST[...]
- pattern: $_REQUEST[...]
- pattern: $_COOKIE[...]
- pattern: $_SERVER[...]
- pattern: $_FILES[...]
- pattern: file_get_contents("php://input")
```

### Common Sinks
```yaml
# Command Injection
- pattern: system($CMD)
- pattern: exec($CMD, ...)
- pattern: shell_exec($CMD)
- pattern: passthru($CMD)
- pattern: popen($CMD, ...)
- pattern: proc_open($CMD, ...)
- pattern: pcntl_exec($CMD, ...)

# SQL Injection
- pattern: mysqli_query($CONN, $SQL)
- pattern: $PDO->query($SQL)
- pattern: $PDO->exec($SQL)
- pattern: mysql_query($SQL)

# Code Execution
- pattern: eval($CODE)
- pattern: assert($CODE)
- pattern: create_function(..., $CODE)
- pattern: preg_replace($PATTERN, $CODE, ...)  # With /e modifier

# File Inclusion
- pattern: include($PATH)
- pattern: include_once($PATH)
- pattern: require($PATH)
- pattern: require_once($PATH)

# Deserialization
- pattern: unserialize($DATA)
```

### PHP Gotchas
- Variable variables: `$$var` - hard to track
- `parse_url()` bypass: Can be bypassed with malformed URLs (see php-vulnerabilities.md)
- Type juggling: `==` vs `===` matters for security
- Magic methods: `__wakeup`, `__destruct` for deserialization chains

---

## Ruby

### Common Sources
```yaml
# Rails
- pattern: params[...]
- pattern: params[:$KEY]
- pattern: request.headers[...]
- pattern: cookies[...]

# Sinatra
- pattern: params[...]
- pattern: request.env[...]
```

### Common Sinks
```yaml
# Command Injection
- pattern: system($CMD)
- pattern: exec($CMD)
- pattern: `$CMD`  # Backtick execution
- pattern: %x($CMD)
- pattern: IO.popen($CMD, ...)
- pattern: Open3.capture2($CMD, ...)

# SQL Injection
- pattern: $MODEL.where($SQL)
- pattern: $MODEL.find_by_sql($SQL)
- pattern: ActiveRecord::Base.connection.execute($SQL)

# Code Execution
- pattern: eval($CODE)
- pattern: instance_eval($CODE)
- pattern: class_eval($CODE)
- pattern: send($METHOD, ...)

# Deserialization
- pattern: Marshal.load($DATA)
- pattern: YAML.load($DATA)  # Use YAML.safe_load
```

### Ruby Gotchas
- Symbol vs String: `:symbol` vs `"string"` in params
- ERB templates: `<%= %>` for output, `<% %>` for logic
- Rails magic: Many implicit behaviors (mass assignment, etc.)
