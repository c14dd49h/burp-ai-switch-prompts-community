# IDOR Detection

## Objective

Detect IDOR vulnerabilities that allow accessing resources belonging to other users by manipulating identifiers.

## Typical injection points

- Numeric IDs: `/api/users/123`, `?user_id=123`
- UUIDs: `/documents/550e8400-e29b-41d4-a716-446655440000`
- Filenames: `/files/report.pdf`, `?file=user_data.json`
- Encoded references: `?ref=dXNlcl8xMjM=` (base64)

## Test steps

### 1. Identify object references

Search in:
- URLs: `/api/orders/456`
- Parameters: `?invoice_id=789`
- Request body: `{"document_id": 123}`
- Headers: `X-User-Id: 456`

### 2. Understand the identification pattern

**Sequential IDs:**
```
/users/1, /users/2, /users/3...
```

**Predictable IDs:**
```
user_123, user_124...
invoice_2024_001, invoice_2024_002...
```

**UUIDs (more difficult):**
```
Look for UUID leaks elsewhere (logs, emails, API responses)
```

### 3. Test horizontal access

With account A, try to access B's resources:

```
-- Your resource
GET /api/documents/100  -> 200 OK

-- Another user's resource
GET /api/documents/101  -> 200 OK = IDOR!
GET /api/documents/99   -> 200 OK = IDOR!
```

### 4. Test vertical access

Try to access admin resources:

```
-- User resources
GET /api/users/me -> {"role": "user"}

-- Admin resources
GET /api/admin/users -> 200 OK = Privilege escalation!
GET /api/users/1 -> Admin user data = IDOR!
```

### 5. Test CRUD operations

**Read (GET):**
```
GET /api/orders/OTHER_USER_ORDER_ID
```

**Update (PUT/PATCH):**
```
PUT /api/profile/OTHER_USER_ID
{"email": "attacker@evil.com"}
```

**Delete (DELETE):**
```
DELETE /api/documents/OTHER_USER_DOC_ID
```

### 6. Bypasses

**HTTP method change:**
```
GET /api/users/123 -> 403
POST /api/users/123 -> 200 OK
```

**Wrapping in an array:**
```
{"id": 123} -> 403
{"id": [123]} -> 200 OK
```

**Parameter pollution:**
```
/api/users?id=ME&id=VICTIM
```

**Encoding:**
```
/api/users/123 -> 403
/api/users/123%00 -> 200 OK
```

### 7. Document the finding

If vulnerable:
```
1. burp_cvss_calculate(...) to get the vector
2. burp_create_finding(
     title: "IDOR on [endpoint]",
     cvss_vector: "<from calculator>",
     description: "...",
     references: ["CWE-639"]
   )
```

## Vulnerability indicators

- 200 response with another user's data
- No server-side verification (client trust)
- Predictable/sequential IDs

## Protection indicators

- Server-side ownership verification
- Non-predictable UUIDs
- Session-based access control
- 403/404 response for unauthorized resources
