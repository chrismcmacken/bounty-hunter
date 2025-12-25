# CVE-YYYY-NNNNN Test Cases
# ============================================================================
# Test file for cve-YYYY-NNNNN-vulnerability-type rule
#
# Based on: https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNNN
#
# Run tests: semgrep --test custom-rules/cve/
# ============================================================================

# Necessary imports for test cases
from flask import request
# import other_modules_as_needed

# ============================================================================
# TRUE POSITIVES - These MUST match (ruleid:)
# ============================================================================

# ruleid: cve-YYYY-NNNNN-vulnerability-type
def vulnerable_basic():
    """Basic vulnerable pattern from CVE"""
    user_input = request.args.get('input')
    dangerous_function(user_input)


# ruleid: cve-YYYY-NNNNN-vulnerability-type
def vulnerable_variant_1():
    """Variant: Different input source"""
    user_input = request.form['input']
    dangerous_function(user_input)


# ruleid: cve-YYYY-NNNNN-vulnerability-type
def vulnerable_variant_2():
    """Variant: String concatenation"""
    user_input = request.args.get('input')
    dangerous_function("prefix" + user_input)


# ruleid: cve-YYYY-NNNNN-vulnerability-type
def vulnerable_variant_3():
    """Variant: F-string construction"""
    user_input = request.args.get('input')
    dangerous_function(f"prefix {user_input}")


# ============================================================================
# TRUE NEGATIVES - These MUST NOT match (ok:)
# ============================================================================

# ok: cve-YYYY-NNNNN-vulnerability-type
def safe_hardcoded():
    """Safe: Hardcoded value, no user input"""
    dangerous_function("hardcoded_safe_value")


# ok: cve-YYYY-NNNNN-vulnerability-type
def safe_sanitized():
    """Safe: Input is sanitized before use"""
    user_input = request.args.get('input')
    safe_input = sanitize_function(user_input)
    dangerous_function(safe_input)


# ok: cve-YYYY-NNNNN-vulnerability-type
def safe_type_cast():
    """Safe: Input is type-cast to safe type"""
    user_input = request.args.get('id')
    safe_id = int(user_input)
    dangerous_function(safe_id)


# ok: cve-YYYY-NNNNN-vulnerability-type
def safe_allowlist():
    """Safe: Input validated against allowlist"""
    user_input = request.args.get('input')
    if user_input not in ALLOWED_VALUES:
        raise ValueError("Invalid input")
    dangerous_function(user_input)


# ok: cve-YYYY-NNNNN-vulnerability-type
def safe_constant():
    """Safe: Using constant, not user input"""
    CONSTANT_VALUE = "safe_constant"
    dangerous_function(CONSTANT_VALUE)


# ============================================================================
# EDGE CASES - Document known limitations
# ============================================================================

# todoruleid: cve-YYYY-NNNNN-vulnerability-type
# Known false negative: Cross-function flow not detected without --pro
def get_input():
    return request.args.get('input')

def vulnerable_cross_function():
    """FN: Requires interprocedural analysis"""
    user_input = get_input()
    dangerous_function(user_input)


# todook: cve-YYYY-NNNNN-vulnerability-type
# Known false positive: Custom sanitizer not recognized
def fp_custom_sanitizer():
    """FP: Company-specific sanitizer not in rule"""
    user_input = request.args.get('input')
    safe_input = company_specific_sanitizer(user_input)
    dangerous_function(safe_input)


# ============================================================================
# HELPER STUBS (for test execution)
# ============================================================================

def dangerous_function(x):
    """Stub for the dangerous function"""
    pass

def sanitize_function(x):
    """Stub for sanitization"""
    return x

def company_specific_sanitizer(x):
    """Stub for org-specific sanitizer"""
    return x

ALLOWED_VALUES = {'value1', 'value2', 'value3'}
