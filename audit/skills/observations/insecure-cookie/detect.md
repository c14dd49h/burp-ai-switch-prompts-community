# Insecure Cookie Configuration Detection

## Objective
Identify cookies missing security attributes (Secure, HttpOnly, SameSite) that could lead to session hijacking or other attacks.

## Instructions

### 1. Essential Cookie Attributes

**Security attributes to check:**

| Attribute | Purpose |
|-----------|---------|
| Secure | Only send over HTTPS |
| HttpOnly | Prevent JavaScript access |
| SameSite | CSRF protection |
| Path | Scope restriction |
| Domain | Domain restriction |
| Expires/Max-Age | Lifetime control |

### 2. Secure Flag

**Missing Secure flag:**
```http
Set-Cookie: session=abc123
# Should be:
Set-Cookie: session=abc123; Secure
```

**Impact:**
- Cookie sent over HTTP
- Man-in-the-middle can intercept
- Session hijacking possible

**Check:**
- All sensitive cookies on HTTPS sites
- Especially session tokens
- Authentication cookies

### 3. HttpOnly Flag

**Missing HttpOnly:**
```http
Set-Cookie: session=abc123
# Should be:
Set-Cookie: session=abc123; HttpOnly
```

**Impact:**
- JavaScript can read cookie
- XSS can steal session
- document.cookie exposure

**Verify with:**
```javascript
document.cookie  // Should not show HttpOnly cookies
```

### 4. SameSite Attribute

**Values and behavior:**
```http
SameSite=Strict  # Never sent cross-site
SameSite=Lax     # Sent on top-level navigation
SameSite=None    # Always sent (requires Secure)
```

**Missing SameSite:**
```http
Set-Cookie: session=abc123
# Defaults vary by browser (Lax in modern browsers)
```

**Issues:**
- SameSite=None without Secure (invalid)
- Missing when CSRF protection needed
- Overly permissive for sensitive operations

### 5. Path Attribute

**Overly broad path:**
```http
Set-Cookie: admin_token=xxx; Path=/
# Should be restricted:
Set-Cookie: admin_token=xxx; Path=/admin
```

**Impact:**
- Cookie sent to unnecessary paths
- Larger attack surface
- Potential for cookie theft via subdirectories

### 6. Domain Attribute

**Overly broad domain:**
```http
Set-Cookie: session=xxx; Domain=.example.com
```

**Issues:**
- Shared with all subdomains
- Subdomain compromise affects main domain
- Consider subdomain security

### 7. Cookie Lifetime

**Permanent session cookies:**
```http
Set-Cookie: session=xxx; Max-Age=31536000  # 1 year
```

**Issues:**
- Sessions never expire
- Increased theft window
- Consider session timeout

**Missing expiration:**
```http
Set-Cookie: session=xxx  # Session cookie (expires on browser close)
```

### 8. Cookie Name Prefixes

**Secure prefixes (modern browsers):**
```http
Set-Cookie: __Secure-session=xxx; Secure
Set-Cookie: __Host-session=xxx; Secure; Path=/
```

**Benefits:**
- Browser-enforced security requirements
- `__Secure-` requires Secure flag
- `__Host-` requires Secure, no Domain, Path=/

### 9. Sensitive Cookies to Check

**Priority cookies:**
- Session identifiers
- Authentication tokens
- CSRF tokens
- Remember-me tokens
- User preference cookies with sensitive data

### 10. Testing Methodology

**Manual testing:**
1. Log in and capture Set-Cookie headers
2. Check each attribute
3. Verify behavior over HTTP (should not work)
4. Test JavaScript access (should fail for HttpOnly)
5. Test cross-site requests (SameSite behavior)

### 11. Document the Finding

**Create OBSERVATION finding with:**
- Cookie name
- Missing attribute(s)
- Current Set-Cookie header
- Recommended configuration
- Risk assessment

## Remediation Guidance

**Recommended cookie configuration:**
```http
Set-Cookie: session=xxx; Secure; HttpOnly; SameSite=Strict; Path=/
```

**For CSRF tokens (need JS access):**
```http
Set-Cookie: csrf_token=xxx; Secure; SameSite=Strict; Path=/
```

**Framework examples:**

**Express.js:**
```javascript
res.cookie('session', value, {
  secure: true,
  httpOnly: true,
  sameSite: 'strict'
});
```

**Django:**
```python
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
```

**PHP:**
```php
session_set_cookie_params([
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Strict'
]);
```

## MCP Tools to Use

### BurpSuite
- `http1_request` / `http2_request`: Capture Set-Cookie headers
- `repeater_tab_with_payload`: Test cookie behavior

### Chrome
- `evaluate_script`: Test document.cookie access
- `list_network_requests`: Analyze cookie headers

## Keywords
cookie security, httponly, secure flag, samesite, session cookie

## References
- OWASP Session Management Cheat Sheet
- RFC 6265 - HTTP State Management Mechanism
- MDN Set-Cookie documentation
