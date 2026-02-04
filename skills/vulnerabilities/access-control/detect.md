# Access Control Vulnerability Detection Skill

## Objective
Identify broken access control vulnerabilities including IDOR, privilege escalation, and authorization bypass.

## Instructions

### 1. Identify Access Control Points
Look for:
- User-specific resources (profiles, orders, documents)
- Admin/privileged functions
- Role-based features
- Multi-tenant boundaries
- API endpoints with authorization

### 2. IDOR (Insecure Direct Object Reference)

**Numeric ID manipulation:**
```
/api/users/123 → /api/users/124
/order/1001 → /order/1002
/document/456 → /document/457
```

**UUID/GUID manipulation:**
```
/profile/550e8400-e29b-41d4-a716-446655440000
→ /profile/550e8400-e29b-41d4-a716-446655440001
```

**Encoded ID manipulation:**
```
# Base64
/user/MTIz → decode(MTIz)=123 → encode(124)=MTI0 → /user/MTI0

# Hex
/file/7b → 123 → 124 → /file/7c
```

**Hash-based IDs:**
- Collect multiple IDs to identify patterns
- Check if hash is predictable (MD5 of sequential numbers)

### 3. Horizontal Privilege Escalation

**Test across users:**
1. Login as User A, note resource IDs
2. Login as User B
3. Try to access User A's resources as User B

**Common IDOR parameters:**
```
id, user_id, account_id, order_id, doc_id, file_id,
profile_id, customer_id, record_id, invoice_id, uid,
guid, ref, reference, key, token, number, no
```

### 4. Vertical Privilege Escalation

**Access admin functions as regular user:**
```
/admin/users
/api/admin/settings
/dashboard/admin
/manage/users
```

**Role parameter manipulation:**
```json
{"username":"user","role":"admin"}
{"user":"test","isAdmin":true}
{"permissions":["read","write","delete","admin"]}
```

**Cookie/token manipulation:**
```
role=user → role=admin
admin=0 → admin=1
isAdmin=false → isAdmin=true
```

### 5. HTTP Method Bypass

**Test different methods:**
```http
GET /admin/users → 403 Forbidden
POST /admin/users → 200 OK?
PUT /admin/users → 200 OK?
PATCH /admin/users → 200 OK?
DELETE /admin/users → 200 OK?
```

**Method override headers:**
```
X-HTTP-Method-Override: PUT
X-Method-Override: DELETE
X-HTTP-Method: PATCH
```

### 6. Path Traversal for Authorization Bypass

**URL manipulation:**
```
/admin/dashboard → 403
/admin/./dashboard → 200?
/Admin/dashboard → 200?
/ADMIN/dashboard → 200?
/admin%2fdashboard → 200?
```

### 7. Parameter Pollution

**HTTP Parameter Pollution:**
```
/api/user?id=123&id=456
/api/user?id[]=123&id[]=456
/api/user?id=123,456
```

### 8. JWT/Token Manipulation

**For JWT-based auth:**
- Modify claims (role, user_id)
- Test algorithm confusion
- Use `jwt_decode` tool for analysis

**Session token tests:**
- Swap tokens between users
- Reuse tokens after logout
- Predict token patterns

### 9. Referer/Origin Bypass

**Missing Referer check:**
```http
GET /admin/sensitive HTTP/1.1
Host: target.com
# Remove Referer header
```

**Spoofed Referer:**
```http
Referer: https://target.com/admin/
```

### 10. API Authorization Testing

**Enumerate API endpoints:**
```
GET /api/v1/users/123
POST /api/v1/users
PUT /api/v1/users/123
DELETE /api/v1/users/123
GET /api/v1/admin/users
```

**Test with different auth levels:**
- No authentication
- Low-privilege token
- Different user's token

### 11. Multi-Tenant Bypass

**Test tenant isolation:**
```
X-Tenant-ID: tenant1 → X-Tenant-ID: tenant2
/api/tenant1/data → /api/tenant2/data
```

**Subdomain switching:**
```
customer1.app.com → customer2.app.com
```

### 12. Function-Level Access Control

**Hidden functionality discovery:**
- Check JavaScript for hidden endpoints
- Review API documentation
- Test common admin paths:
```
/admin, /administrator, /manage, /console
/api/admin, /api/management, /internal
/_admin, /backend, /dashboard
```

### 13. Workflow Bypass

**Skip steps in multi-step process:**
```
Step 1: /checkout/cart
Step 2: /checkout/shipping
Step 3: /checkout/payment
Step 4: /checkout/confirm

Try: Direct access to Step 4 without completing Step 1-3
```

### 14. Mass Assignment

**Add extra parameters:**
```json
// Original
{"name":"John","email":"john@example.com"}

// Tampered
{"name":"John","email":"john@example.com","role":"admin","verified":true}
```

### 15. Confirm and Document
If confirmed, create finding with:
- Vulnerable endpoint
- Access control weakness type
- PoC showing unauthorized access
- Evidence (unauthorized data/action)
- Impact assessment

## MCP Tools to Use
- `params_extract`: Identify resource identifiers
- `http1_request` / `http2_request`: Test access
- `jwt_decode`: Analyze tokens
- `repeater_tab_with_payload`: Manual testing
- `intruder_prepare`: Enumerate IDs
- `issue_create`: Report confirmed finding

## Keywords
idor, broken access control, privilege escalation, bac, authorization bypass

## References
- PayloadsAllTheThings/Insecure Direct Object References
- OWASP Broken Access Control
- PortSwigger Access Control Labs
