"""
Test cases for python-path-join-absolute-bypass semgrep rule.

The vulnerability: os.path.join() discards all preceding components when
any subsequent argument is an absolute path (starts with /).

Example:
    os.path.join("/safe/uploads", "/etc/passwd")  # Returns "/etc/passwd"
"""

import os
import os.path
import sys
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath
from flask import request
from werkzeug.utils import secure_filename

UPLOAD_DIR = "/var/www/uploads"

# ============================================================================
# VULNERABLE PATTERNS - Should be detected
# ============================================================================

# ruleid: python-path-join-absolute-bypass
def vulnerable_file_read():
    filename = request.args.get("file")
    path = os.path.join(UPLOAD_DIR, filename)
    return open(path).read()

# ruleid: python-path-join-absolute-bypass
def vulnerable_form_input():
    user_path = request.form["path"]
    full_path = os.path.join("/app/data", user_path)
    return send_file(full_path)

# ruleid: python-path-join-absolute-bypass
def vulnerable_json_input():
    data = request.json["filename"]
    return os.path.join("/uploads", data)

# ruleid: python-path-join-absolute-bypass
def vulnerable_file_upload():
    f = request.files["document"]
    save_path = os.path.join(UPLOAD_DIR, f.filename)
    f.save(save_path)

# ruleid: python-path-join-absolute-bypass
def vulnerable_pathlib():
    user_file = request.args.get("name")
    path = Path("/data") / user_file
    return path.read_text()

# ruleid: python-path-join-absolute-bypass
def vulnerable_pathlib_joinpath():
    user_file = request.args.get("name")
    path = Path("/data").joinpath(user_file)
    return path.read_text()

# ruleid: python-path-join-absolute-bypass
def vulnerable_purepath():
    """PurePath has the same behavior as Path"""
    user_file = request.args.get("name")
    path = PurePath("/data") / user_file
    return str(path)

# ruleid: python-path-join-absolute-bypass
def vulnerable_purepath_joinpath():
    user_file = request.args.get("name")
    path = PurePath("/data").joinpath(user_file)
    return str(path)

# ruleid: python-path-join-absolute-bypass
def vulnerable_pureposixpath():
    """PurePosixPath also has the same behavior"""
    user_file = request.args.get("name")
    path = PurePosixPath("/data").joinpath(user_file)
    return str(path)

# ruleid: python-path-join-absolute-bypass
def vulnerable_purewindowspath():
    """PureWindowsPath can be exploited with C:\\ or \\\\ on Windows"""
    user_file = request.args.get("name")
    path = PureWindowsPath("C:\\data").joinpath(user_file)
    return str(path)

# ruleid: python-path-join-absolute-bypass
def vulnerable_nested_join():
    subdir = request.args.get("dir")
    filename = request.args.get("file")
    # Both subdir and filename are tainted
    path = os.path.join("/base", subdir, filename)
    return path

# ruleid: python-path-join-user-input-first-arg
def vulnerable_user_controlled_base():
    base = request.args.get("base_dir")
    return os.path.join(base, "config.json")

# ruleid: python-path-join-absolute-bypass
def vulnerable_sys_argv():
    path = os.path.join("/app", sys.argv[1])
    return open(path).read()

# ruleid: python-path-join-absolute-bypass
def vulnerable_input():
    user_file = input("Enter filename: ")
    return os.path.join("/home/user", user_file)


# ============================================================================
# SAFE PATTERNS - Should NOT be detected
# ============================================================================

# ok: python-path-join-absolute-bypass
def safe_hardcoded_paths():
    # Hardcoded strings are not user-controlled
    path = os.path.join("/var/www", "static", "style.css")
    return path

# ok: python-path-join-absolute-bypass
def safe_basename():
    # os.path.basename strips directory components
    filename = request.args.get("file")
    safe_name = os.path.basename(filename)
    path = os.path.join(UPLOAD_DIR, safe_name)
    return path

# ok: python-path-join-absolute-bypass
def safe_secure_filename():
    # werkzeug.secure_filename sanitizes the input
    f = request.files["document"]
    safe_name = secure_filename(f.filename)
    save_path = os.path.join(UPLOAD_DIR, safe_name)
    f.save(save_path)

# ok: python-path-join-absolute-bypass
def safe_lstrip():
    # Stripping leading slashes prevents absolute path override
    filename = request.args.get("file")
    clean_name = filename.lstrip("/")
    path = os.path.join(UPLOAD_DIR, clean_name)
    return path

# ok: python-path-join-absolute-bypass
def safe_strip():
    filename = request.args.get("file")
    clean_name = filename.strip("/")
    path = os.path.join(UPLOAD_DIR, clean_name)
    return path

# todoruleid: python-path-join-absolute-bypass
# NOTE: This IS safe but semgrep can't do path-sensitive analysis for early returns.
# This will be a false positive requiring manual review.
def safe_check_startswith_fp():
    filename = request.args.get("file")
    if filename.startswith("/"):
        return "Invalid filename"
    path = os.path.join(UPLOAD_DIR, filename)
    return path

# ok: python-path-join-absolute-bypass
def safe_integer_id():
    # Integer conversion - can't be a path
    file_id = request.args.get("id")
    numeric_id = int(file_id)
    path = os.path.join(UPLOAD_DIR, str(numeric_id))
    return path

# ok: python-path-join-absolute-bypass
def safe_user_input_first_arg_only():
    # This is different - user input as first arg with hardcoded second
    # (Covered by separate rule if needed, but less directly exploitable
    # for reading arbitrary files - attacker controls base, not what's appended)
    base = "/uploads"
    hardcoded = "readme.txt"
    return os.path.join(base, hardcoded)


# ============================================================================
# EDGE CASES
# ============================================================================

# ruleid: python-path-join-absolute-bypass
def edge_case_multiple_user_inputs():
    # Multiple user inputs - should detect both
    dir_name = request.form.get("dir")
    file_name = request.form.get("file")
    return os.path.join("/base", dir_name, file_name)

# ok: python-path-join-absolute-bypass
def edge_case_removeprefix():
    # Python 3.9+ removeprefix
    filename = request.args.get("file")
    clean = filename.removeprefix("/")
    return os.path.join(UPLOAD_DIR, clean)
