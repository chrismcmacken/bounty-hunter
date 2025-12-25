# Test cases for python-dynamic-import-lfi rule

from flask import Flask, request
import importlib
import importlib.util
import re

app = Flask(__name__)

# =============================================================================
# VULNERABLE PATTERNS - Should trigger
# =============================================================================

# Direct module name from request.form
@app.route('/load')
def load_module_vuln():
    module_name = request.form['module']
    # ruleid: python-dynamic-import-lfi
    module = importlib.import_module(module_name)
    return str(module)

# __import__ with request.json input
@app.route('/dynamic')
def dynamic_import_vuln():
    # ruleid: python-dynamic-import-lfi-fstring
    view_name = request.json.get('view')
    module = __import__(view_name)
    return module.handle()

# String concatenation with request.args
@app.route('/concat')
def concat_import_vuln():
    # ruleid: python-dynamic-import-lfi-concat
    name = request.args.get('name')
    module = importlib.import_module('myapp.plugins.' + name)
    return module.run()

# .format() with request.args
@app.route('/format')
def format_import_vuln():
    # ruleid: python-dynamic-import-lfi-concat
    name = request.args.get('name')
    module = importlib.import_module('myapp.plugins.{}'.format(name))
    return module.run()

# % formatting with request.args
@app.route('/percent')
def percent_import_vuln():
    # ruleid: python-dynamic-import-lfi-fstring
    name = request.args.get('name')
    module = importlib.import_module('myapp.plugins.%s' % name)
    return module.run()

# importlib.util.find_spec with request.args
@app.route('/util')
def util_import_vuln():
    # ruleid: python-dynamic-import-lfi-fstring
    name = request.args.get('name')
    spec = importlib.util.find_spec(name)
    return str(spec)


# =============================================================================
# SAFE PATTERNS - Should NOT trigger (ok:)
# =============================================================================

ALLOWED_PLUGINS = {'analytics', 'export', 'notifications'}
PLUGIN_REGISTRY = {
    'analytics': 'myapp.plugins.analytics',
    'export': 'myapp.plugins.export',
}

@app.route('/safe/allowlist')
def safe_allowlist():
    name = request.args.get('name')
    if name in ALLOWED_PLUGINS:
        # ok: python-dynamic-import-lfi
        plugin = importlib.import_module(f'plugins.{name}')
        return plugin.run()
    return "Not allowed", 403

@app.route('/safe/allowlist-negative')
def safe_allowlist_negative():
    name = request.args.get('name')
    if name not in ALLOWED_PLUGINS:
        raise ValueError(f"Unknown plugin: {name}")
    # ok: python-dynamic-import-lfi
    plugin = importlib.import_module(f'plugins.{name}')
    return plugin.run()

@app.route('/safe/registry')
def safe_registry():
    name = request.args.get('name')
    module_path = PLUGIN_REGISTRY.get(name)
    if module_path:
        # ok: python-dynamic-import-lfi
        plugin = importlib.import_module(module_path)
        return plugin.run()
    return "Not found", 404

@app.route('/safe/regex')
def safe_regex():
    name = request.args.get('name')
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', name):
        return "Invalid name", 400
    # ok: python-dynamic-import-lfi
    plugin = importlib.import_module(f'plugins.{name}')
    return plugin.run()

# ok: python-dynamic-import-lfi
def hardcoded_import():
    # Hardcoded module name, not user input
    module = importlib.import_module('myapp.utils')
    return module


# =============================================================================
# Django vulnerable patterns
# =============================================================================

def django_vuln_get(request):
    module_name = request.GET.get('module')
    # todoruleid: python-dynamic-import-lfi
    # NOTE: This pattern is difficult for taint tracking due to request.GET
    module = importlib.import_module(module_name)
    return module.handle(request)

def django_vuln_post(request):
    module_name = request.POST['module']
    # ruleid: python-dynamic-import-lfi
    module = __import__(module_name)
    return module.handle(request)


# =============================================================================
# exec/eval patterns
# =============================================================================

@app.route('/exec')
def exec_import_vuln():
    code = request.args.get('code')
    # ruleid: python-dynamic-import-lfi-exec
    exec(code)
    return "Done"

@app.route('/eval')
def eval_import_vuln():
    expr = request.form['expr']
    # ruleid: python-dynamic-import-lfi-exec
    result = eval(expr)
    return str(result)


# =============================================================================
# ADDITIONAL PATTERNS (may require manual review in real codebases)
# These patterns are harder for static analysis to detect reliably
# =============================================================================

# NOTE: Flask route parameters with f-strings are difficult to detect
# with semgrep pattern matching. Manual review recommended for:
# @app.route('/plugin/<name>')
# def load_plugin(name):
#     plugin = importlib.import_module(f'plugins.{name}')

# NOTE: f-string patterns with intermediate variables may require
# cross-function taint tracking to detect. Example:
# theme = request.args.get('theme')
# module = importlib.import_module(f'themes.{theme}')
