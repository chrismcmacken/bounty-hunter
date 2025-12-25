# Test cases for mongodb-nosql-injection rules
# Run: semgrep --config mongodb-nosql-injection.yaml --test .

from flask import request, jsonify
from pymongo import MongoClient
import json

db = MongoClient().mydb

# =============================================================================
# VULNERABLE PATTERNS - Should trigger rules
# =============================================================================

# ruleid: python-pymongo-nosql-injection
def vuln_find_one():
    username = request.args.get('username')
    user = db.users.find_one({'username': username})
    return user

# ruleid: python-pymongo-nosql-injection
def vuln_find_json():
    query = request.json
    results = db.products.find(query)
    return list(results)

# ruleid: python-pymongo-nosql-injection
def vuln_find_json_key():
    password = request.json['password']
    user = db.users.find_one({'password': password})
    return user

# ruleid: python-pymongo-nosql-injection
def vuln_update_one():
    filter_query = request.json.get('filter')
    db.users.update_one(filter_query, {'$set': {'active': True}})

# ruleid: python-pymongo-nosql-injection
def vuln_delete_many():
    query = request.form.get('query')
    parsed = json.loads(query)
    db.logs.delete_many(parsed)

# ruleid: python-pymongo-nosql-injection
def vuln_aggregate():
    pipeline = request.json
    results = db.orders.aggregate(pipeline)
    return list(results)

# ruleid: python-pymongo-nosql-injection
def vuln_count_documents():
    filter_data = request.get_json()
    count = db.items.count_documents(filter_data)
    return {'count': count}

# ruleid: python-pymongo-dangerous-operators
def vuln_where_operator():
    code = request.args.get('code')
    results = db.users.find({"$where": code})
    return list(results)

# ruleid: python-pymongo-dangerous-operators
def vuln_regex_operator():
    pattern = request.json['pattern']
    results = db.users.find({"username": {"$regex": pattern}})
    return list(results)

# =============================================================================
# SAFE PATTERNS - Should NOT trigger rules
# =============================================================================

# ok: python-pymongo-nosql-injection
def safe_hardcoded_query():
    # Hardcoded queries are safe
    users = db.users.find({'role': 'admin'})
    return list(users)

# todoruleid: python-pymongo-nosql-injection
# Note: isinstance() in conditional doesn't act as sanitizer in semgrep
# This is a known FP - semgrep doesn't do path-sensitive analysis
def safe_type_validated():
    username = request.args.get('username')
    if isinstance(username, str):
        # Type validation indicates awareness - but semgrep can't track this
        user = db.users.find_one({'username': username})
        return user
    return None

# ok: python-pymongo-nosql-injection
def safe_string_coercion():
    user_id = request.args.get('id')
    # Explicit string conversion prevents operator injection
    user = db.users.find_one({'_id': str(user_id)})
    return user

# ok: python-pymongo-nosql-injection
def safe_int_coercion():
    age = request.args.get('age')
    # Integer conversion prevents object injection
    users = db.users.find({'age': int(age)})
    return list(users)

# ok: python-pymongo-nosql-injection
def safe_objectid():
    from bson import ObjectId
    user_id = request.args.get('id')
    # ObjectId constructor validates format
    user = db.users.find_one({'_id': ObjectId(user_id)})
    return user

# ok: python-pymongo-nosql-injection
def safe_schema_validation():
    from pydantic import BaseModel

    class UserQuery(BaseModel):
        username: str

    data = request.json
    query = UserQuery.model_validate(data)
    user = db.users.find_one({'username': query.username})
    return user

# todoruleid: python-pymongo-nosql-injection
# Note: Early return pattern not tracked by semgrep (no path-sensitive analysis)
def safe_explicit_fields():
    # Building query with explicit field names from validated input
    username = request.args.get('username')
    if not isinstance(username, str) or len(username) > 50:
        return None
    # Only string value used, not the whole request object
    user = db.users.find_one({'username': username, 'active': True})
    return user
