# NoSQL/MongoDB Injection

Reference guide for NoSQL injection patterns when reviewing semgrep findings. Covers Python, Node.js, Java, Go, and Ruby.

## The Vulnerability

MongoDB and other NoSQL databases accept JSON/BSON query objects. When user input is passed directly to query methods, attackers can inject query operators to bypass authentication, extract data, or cause denial of service.

```javascript
// Node.js - VULNERABLE
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    // Attacker sends: {"username": "admin", "password": {"$ne": ""}}
    const user = await db.collection('users').findOne({
        username: username,
        password: password  // This could be {"$ne": ""} not a string!
    });
    if (user) return res.send("Logged in!");
});
```

## How It Works

MongoDB query operators start with `$`. When user input is an object instead of a string, these operators are interpreted:

| Operator | Payload | Effect |
|----------|---------|--------|
| `$ne` | `{"password": {"$ne": ""}}` | Matches any non-empty value → auth bypass |
| `$gt` | `{"password": {"$gt": ""}}` | Matches any value → auth bypass |
| `$regex` | `{"username": {"$regex": "^a"}}` | Pattern matching → data extraction |
| `$where` | `{"$where": "this.password.length > 0"}` | JavaScript execution |
| `$or` | `{"$or": [{...}, {...}]}` | Bypass conditions |

## Attack Payloads

```json
// Authentication bypass
{"username": "admin", "password": {"$ne": ""}}
{"username": "admin", "password": {"$gt": ""}}
{"username": {"$regex": "^admin"}, "password": {"$ne": ""}}

// Blind data extraction
{"username": "admin", "password": {"$regex": "^a"}}  // 200 = starts with 'a'
{"username": "admin", "password": {"$regex": "^b"}}  // 401 = doesn't

// JavaScript injection via $where
{"$where": "this.password.length > 5"}
{"$where": "sleep(5000)"}  // DoS
{"$where": "this.password == 'secret'"}  // Leak via timing

// Aggregate pipeline manipulation
[{"$match": {}}, {"$out": "public_collection"}]  // Write to another collection
```

---

## Language-Specific Patterns

### Python (pymongo, Motor, MongoEngine)

```python
# CRITICAL: Entire JSON body as query
query = request.json
results = db.products.find(query)

# CRITICAL: JSON field without type checking
password = request.json['password']  # Could be {"$ne": ""}
user = db.users.find_one({'password': password})

# CRITICAL: $where with user input
code = request.args.get('filter')
results = db.users.find({"$where": code})

# CRITICAL: MongoEngine __raw__
results = User.objects(__raw__=request.json)

# SAFE: Type validation
if not isinstance(password, str):
    raise ValueError("Invalid type")
user = db.users.find_one({'password': password})

# SAFE: Pydantic schema validation
class LoginRequest(BaseModel):
    username: str
    password: str

data = LoginRequest.model_validate(request.json)
```

### Node.js (mongodb driver, Mongoose)

```javascript
// CRITICAL: Direct body usage
const user = await User.findOne(req.body);

// CRITICAL: Destructured but still vulnerable
const { username, password } = req.body;
const user = await db.collection('users').findOne({ username, password });

// CRITICAL: Mongoose where()
const results = await User.where(req.query);

// SAFE: mongo-sanitize package
const sanitize = require('mongo-sanitize');
const user = await User.findOne({
    username: sanitize(req.body.username),
    password: sanitize(req.body.password)
});

// SAFE: Type coercion
const user = await User.findOne({
    username: String(req.body.username),
    password: String(req.body.password)
});

// SAFE: Mongoose schema (strict mode rejects unknown types by default)
const userSchema = new mongoose.Schema({
    username: { type: String, required: true },
    password: { type: String, required: true }
});
```

### Java (MongoDB Java Driver)

```java
// CRITICAL: Document.parse with user JSON
String jsonQuery = request.getParameter("query");
Document filter = Document.parse(jsonQuery);  // Operator injection
collection.find(filter);

// SAFE: Use Filters builder (typed, no operator injection)
import static com.mongodb.client.model.Filters.*;

String username = request.getParameter("username");
String password = request.getParameter("password");
collection.find(and(
    eq("username", username),  // Escaped as string value
    eq("password", password)
));
```

### Go (mongo-go-driver)

```go
// CRITICAL: Unmarshal user JSON directly to query
var filter bson.M
json.Unmarshal([]byte(userInput), &filter)
collection.Find(ctx, filter)

// SAFE: Explicit bson.M construction
filter := bson.M{
    "username": username,  // String variable, not unmarshaled object
    "password": password,
}
collection.Find(ctx, filter)

// SAFE: Use bson.D for ordered, typed queries
filter := bson.D{
    {"username", username},
    {"password", password},
}
```

### Ruby (Mongoid, mongo-ruby-driver)

```ruby
# CRITICAL: Params directly in query
User.where(params[:query])

# CRITICAL: JSON.parse to query
query = JSON.parse(request.body.read)
collection.find(query)

# SAFE: Strong parameters with type enforcement
def user_params
  params.require(:user).permit(:username, :password)
end
# Then validate types before query

# SAFE: Explicit field assignment
User.where(username: params[:username].to_s, password: params[:password].to_s)
```

---

## Detection Tips

When reviewing semgrep findings:

1. **Check input source**: Is data from `request.json`, `req.body`, `params`, etc.?
2. **Verify types**: Can input be an object/dict, or is it guaranteed to be a string?
3. **Look for validation**: Schema validation, type checks, sanitization functions
4. **Watch for $where**: Any user input reaching `$where` is JavaScript injection
5. **Check aggregation**: User-controlled pipelines can do anything

## False Positive Indicators

- Hardcoded queries (no user input)
- Schema validation (Pydantic, Mongoose schema, etc.)
- Explicit type conversion (`str()`, `String()`, `.to_s`)
- `ObjectId` validation for `_id` fields
- Query builder APIs (`Filters.eq()` in Java)
- Admin-only endpoints

## Semgrep Limitations

**Known false positives** (require manual triage):
- Conditional type checks (`if isinstance(x, str):`) - semgrep doesn't track control flow
- Early return patterns after validation - same limitation

---

## Custom Semgrep Rules

Rule file: `custom-rules/web-vulns/mongodb-nosql-injection.yaml`

| Rule ID | Language | Detection Pattern |
|---------|----------|-------------------|
| `python-pymongo-nosql-injection` | Python | Taint: web input → pymongo/Motor/MongoEngine |
| `python-pymongo-dangerous-operators` | Python | `$where` and `$regex` operator usage |
| `nodejs-mongodb-nosql-injection` | JS/TS | Native driver + Mongoose methods |
| `java-mongodb-nosql-injection` | Java | MongoDB Java Driver, Document.parse() |
| `go-mongodb-nosql-injection` | Go | mongo-go-driver collection methods |
| `ruby-mongodb-nosql-injection` | Ruby | Mongoid + mongo-ruby-driver |
| `mongodb-raw-query-string-audit` | Multi | String interpolation in queries |

---

## References

- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection
- https://book.hacktricks.xyz/pentesting-web/nosql-injection
- https://nullsweep.com/nosql-injection-cheatsheet/
- https://blog.websecurify.com/2014/08/hacking-nodejs-and-mongodb
- CWE-943: Improper Neutralization of Special Elements in Data Query Logic
