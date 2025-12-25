# Test cases for python-xpath-injection rule

from flask import request
from lxml import etree
import re

# =============================================================================
# TRUE POSITIVES - Should be detected
# =============================================================================

# ruleid: python-xpath-injection
@app.route('/login', methods=['POST'])
def login_vulnerable():
    username = request.form['username']
    password = request.form['password']
    tree = etree.parse('users.xml')
    query = f"//user[username='{username}' and password='{password}']"
    result = tree.xpath(query)
    return "OK" if result else "Fail"

# ruleid: python-xpath-injection
@app.route('/search')
def search_vulnerable():
    name = request.args.get('name')
    tree = etree.parse('data.xml')
    result = tree.xpath("//item[name='" + name + "']")
    return str(result)

# ruleid: python-xpath-injection
@app.route('/user')
def user_vulnerable():
    user_id = request.args['id']
    doc = etree.parse('users.xml')
    expr = etree.XPath(f"//user[@id='{user_id}']")
    return str(expr(doc))

# =============================================================================
# TRUE NEGATIVES - Should NOT be detected
# =============================================================================

# ok: python-xpath-injection
def static_query():
    # Safe: Hardcoded query, no user input
    tree = etree.parse('data.xml')
    result = tree.xpath("//user[@admin='true']")
    return result

# ok: python-xpath-injection
def hardcoded_value():
    # Safe: Query built from hardcoded strings only
    tree = etree.parse('config.xml')
    field = "status"
    value = "active"
    result = tree.xpath(f"//item[@{field}='{value}']")
    return result

# ok: python-xpath-injection
def integer_path_variable():
    # Safe: Path variable that's cast to int immediately, then used as int
    tree = etree.parse('data.xml')
    item_id = 42
    result = tree.xpath(f"//item[@id='{item_id}']")
    return result
