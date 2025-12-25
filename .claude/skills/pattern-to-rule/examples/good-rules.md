# Good Rule Examples

High-quality Semgrep rules demonstrating best practices for CVE detection.

---

## Example 1: CVE-2024-6386 - WPML Twig SSTI

**What makes this good:**
- Taint mode tracks data flow accurately
- Multiple framework-specific sources
- Focus-metavariable narrows finding to vulnerable parameter
- CVE reference in metadata
- Clear remediation guidance

```yaml
rules:
  - id: cve-2024-6386-wpml-twig-ssti
    mode: taint
    languages: [php]
    severity: CRITICAL
    message: |
      User-controlled input passed to Twig createTemplate(). This allows
      Server-Side Template Injection (SSTI) leading to Remote Code Execution.

      CVE-2024-6386 affected WPML plugin < 4.6.13.

      Remediation: Use file-based templates with Twig. Never pass user input
      directly to createTemplate(). If dynamic templates are required, use
      a strict sandbox environment.

    metadata:
      cve: "CVE-2024-6386"
      cwe: "CWE-1336"
      cvss: "9.9"
      owasp: "A03:2021 - Injection"
      confidence: HIGH
      category: security
      references:
        - https://nvd.nist.gov/vuln/detail/CVE-2024-6386
        - https://blog.wpsec.com/the-full-story-of-cve-2024-6386-remote-code-execution-in-wpml/

    pattern-sources:
      # WordPress
      - pattern: $_GET[...]
      - pattern: $_POST[...]
      - pattern: $_REQUEST[...]
      # Laravel
      - pattern: $request->input(...)
      - pattern: $request->get(...)

    pattern-sinks:
      - pattern: $twig->createTemplate($TEMPLATE, ...)
        focus-metavariable: $TEMPLATE
      - pattern: $twig->createTemplate($TEMPLATE)
        focus-metavariable: $TEMPLATE

    pattern-sanitizers:
      # File-based templates are safe
      - pattern: $twig->render($FILE, ...)
      - pattern: $twig->load($FILE)
```

---

## Example 2: Python SQL Injection with Comprehensive Sanitizers

**What makes this good:**
- Covers multiple string construction methods
- Comprehensive sanitizer list reduces FPs
- Both pattern and taint mode available
- Test exclusions included

```yaml
rules:
  - id: python-sql-injection-taint
    mode: taint
    languages: [python]
    severity: ERROR
    message: |
      SQL injection vulnerability detected. User input flows to database
      query without proper parameterization.

      Remediation: Use parameterized queries with placeholders:
      cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

    metadata:
      cwe: "CWE-89"
      owasp: "A03:2021 - Injection"
      confidence: HIGH
      category: security

    pattern-sources:
      # Flask
      - pattern: request.args.get(...)
      - pattern: request.args[...]
      - pattern: request.form.get(...)
      - pattern: request.form[...]
      - pattern: request.json
      - pattern: request.json.get(...)
      - pattern: request.json[...]
      # Django
      - pattern: request.GET.get(...)
      - pattern: request.GET[...]
      - pattern: request.POST.get(...)
      - pattern: request.POST[...]

    pattern-sinks:
      - pattern: $CURSOR.execute($QUERY)
        focus-metavariable: $QUERY
      - pattern: $CURSOR.executemany($QUERY, ...)
        focus-metavariable: $QUERY
      - pattern: $ENGINE.execute($QUERY)
        focus-metavariable: $QUERY
      - pattern: $CONN.execute(text($QUERY))
        focus-metavariable: $QUERY

    pattern-sanitizers:
      # Parameterized queries
      - pattern: $CURSOR.execute("...", (...))
      - pattern: $CURSOR.execute("...", [...])
      - pattern: $CURSOR.execute($Q, params=...)

      # Type conversions
      - pattern: int(...)
      - pattern: float(...)
      - pattern: uuid.UUID(...)
      - pattern: bool(...)

      # Django ORM (safe by default)
      - pattern: $MODEL.objects.filter(...)
      - pattern: $MODEL.objects.get(...)
      - pattern: $MODEL.objects.exclude(...)
      - pattern: $MODEL.objects.create(...)

      # SQLAlchemy ORM
      - pattern: $SESSION.query(...).filter(...)
      - pattern: $SESSION.query(...).filter_by(...)
      - pattern: select(...).where(...)

    paths:
      exclude:
        - "**/test/**"
        - "**/tests/**"
        - "**/*_test.py"
        - "**/fixtures/**"
```

---

## Example 3: Command Injection with Safe Alternative Detection

**What makes this good:**
- Distinguishes shell=True (dangerous) from list args (safe)
- Excludes hardcoded commands
- Multiple sink variations covered

```yaml
rules:
  - id: python-command-injection
    mode: taint
    languages: [python]
    severity: CRITICAL
    message: |
      Command injection via subprocess with shell=True. User input flows
      to shell command execution.

      Remediation: Use subprocess with list arguments (no shell):
      subprocess.run(['ls', '-la', directory], shell=False)

    metadata:
      cwe: "CWE-78"
      confidence: HIGH
      category: security

    pattern-sources:
      - pattern: request.args.get(...)
      - pattern: request.form[...]
      - pattern: sys.argv[...]

    pattern-sinks:
      # subprocess with shell=True
      - pattern: subprocess.call($CMD, shell=True, ...)
        focus-metavariable: $CMD
      - pattern: subprocess.run($CMD, shell=True, ...)
        focus-metavariable: $CMD
      - pattern: subprocess.Popen($CMD, shell=True, ...)
        focus-metavariable: $CMD
      - pattern: subprocess.check_output($CMD, shell=True, ...)
        focus-metavariable: $CMD

      # os module
      - pattern: os.system($CMD)
        focus-metavariable: $CMD
      - pattern: os.popen($CMD)
        focus-metavariable: $CMD

    pattern-sanitizers:
      - pattern: shlex.quote(...)
      - pattern: shlex.split(...)

  # Separate rule for unsafe subprocess detection (no taint)
  - id: subprocess-shell-true-audit
    languages: [python]
    severity: WARNING
    message: |
      subprocess called with shell=True. Ensure command is not constructed
      from user input. Prefer list arguments with shell=False.

    metadata:
      cwe: "CWE-78"
      confidence: MEDIUM
      category: security

    patterns:
      - pattern: subprocess.$FUNC($CMD, shell=True, ...)
      # Exclude hardcoded safe commands
      - pattern-not: subprocess.$FUNC("...", shell=True, ...)
      # Exclude list form (less dangerous)
      - pattern-not: subprocess.$FUNC([...], shell=True, ...)
```

---

## Example 4: Deserialization with ML Focus

**What makes this good:**
- Covers often-overlooked ML model loading
- Framework-specific sinks (torch, joblib, sklearn)
- Clear explanation of attack vector

```yaml
rules:
  - id: python-ml-model-deserialization
    mode: taint
    languages: [python]
    severity: CRITICAL
    message: |
      Untrusted data passed to ML model loading function. Model files can
      contain pickled code that executes on load, leading to RCE.

      Attack: Attacker uploads malicious .pkl/.pt file → loaded by torch.load()
      or joblib.load() → arbitrary code executes.

      Remediation:
      - Only load models from trusted sources
      - Use weights_only=True for PyTorch when possible
      - Validate model file signatures/checksums

    metadata:
      cwe: "CWE-502"
      confidence: HIGH
      category: security

    pattern-sources:
      # File uploads
      - pattern: request.files[$KEY]
      - pattern: request.files[$KEY].save($PATH)
      # User-controlled paths
      - pattern: request.args.get(...)
      - pattern: request.json[...]

    pattern-sinks:
      # PyTorch
      - pattern: torch.load($PATH, ...)
        focus-metavariable: $PATH
      - pattern: torch.load($PATH)
        focus-metavariable: $PATH

      # Joblib
      - pattern: joblib.load($PATH)
        focus-metavariable: $PATH

      # Sklearn
      - pattern: sklearn.externals.joblib.load($PATH)
        focus-metavariable: $PATH

      # Keras (can load pickle)
      - pattern: keras.models.load_model($PATH)
        focus-metavariable: $PATH
      - pattern: tf.keras.models.load_model($PATH)
        focus-metavariable: $PATH

      # Standard pickle
      - pattern: pickle.load($FILE)
      - pattern: pickle.loads($DATA)

    pattern-sanitizers:
      # Safe loading flag
      - pattern: torch.load($PATH, weights_only=True)
      # NumPy with pickle disabled
      - pattern: numpy.load($PATH, allow_pickle=False)
```

---

## Example 5: SSRF with URL Bypass Detection

**What makes this good:**
- Comprehensive HTTP client coverage
- Documents common bypass techniques in message
- Provides concrete allowlist pattern

```yaml
rules:
  - id: python-ssrf-requests
    mode: taint
    languages: [python]
    severity: ERROR
    message: |
      User-controlled URL passed to HTTP request. This allows Server-Side
      Request Forgery (SSRF) attacks.

      Attack vectors:
      - http://169.254.169.254/ (AWS metadata)
      - http://localhost:6379/ (internal Redis)
      - http://127.0.0.1:8080/admin (internal admin)

      Bypass techniques attackers may use:
      - IP encoding: http://0x7f.0x0.0x0.0x1/ (hex)
      - DNS rebinding: attacker domain resolves to internal IP
      - URL parsing tricks: http://evil.com@safe.com

      Remediation: Validate URLs against an allowlist of permitted hosts:
      ```python
      from urllib.parse import urlparse
      ALLOWED_HOSTS = {'api.example.com', 'cdn.example.com'}
      parsed = urlparse(user_url)
      if parsed.hostname not in ALLOWED_HOSTS:
          raise ValueError("URL not in allowlist")
      ```

    metadata:
      cwe: "CWE-918"
      owasp: "A10:2021 - Server-Side Request Forgery"
      confidence: HIGH
      category: security

    pattern-sources:
      - pattern: request.args.get(...)
      - pattern: request.form[...]
      - pattern: request.json.get(...)
      - pattern: request.json[...]

    pattern-sinks:
      # requests library
      - pattern: requests.get($URL, ...)
        focus-metavariable: $URL
      - pattern: requests.post($URL, ...)
        focus-metavariable: $URL
      - pattern: requests.request($METHOD, $URL, ...)
        focus-metavariable: $URL
      - pattern: $SESSION.get($URL, ...)
        focus-metavariable: $URL

      # urllib
      - pattern: urllib.request.urlopen($URL, ...)
        focus-metavariable: $URL
      - pattern: urlopen($URL, ...)
        focus-metavariable: $URL

      # httpx
      - pattern: httpx.get($URL, ...)
        focus-metavariable: $URL
      - pattern: httpx.post($URL, ...)
        focus-metavariable: $URL

    pattern-sanitizers:
      # URL parsing followed by hostname check
      - pattern: |
          $PARSED = urlparse($URL)
          if $PARSED.hostname in $ALLOWED:
              ...
      - pattern: |
          $PARSED = urlparse($URL)
          if $PARSED.netloc in $ALLOWED:
              ...
```

---

## Key Takeaways

1. **Always use taint mode** for injection vulnerabilities - it tracks data flow accurately

2. **Include comprehensive sanitizers** - reduces false positives significantly

3. **Use focus-metavariable** - narrows finding to the specific vulnerable parameter

4. **Add CVE metadata** - helps prioritize findings

5. **Provide remediation** - developers need actionable fixes

6. **Exclude test paths** - reduces noise from intentionally vulnerable test code

7. **Cover variants** - multiple sinks for the same vulnerability type
