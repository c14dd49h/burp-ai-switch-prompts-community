# Missing Security Headers Detection

## Objective
Identify missing or improperly configured HTTP security headers that reduce the application's defense-in-depth.

## Instructions

### 1. Check Required Security Headers

**Essential headers to verify:**

| Header | Purpose |
|--------|---------|
| Strict-Transport-Security | HTTPS enforcement |
| X-Content-Type-Options | MIME sniffing prevention |
| X-Frame-Options | Clickjacking prevention |
| Content-Security-Policy | XSS/injection mitigation |
| X-XSS-Protection | Legacy XSS filter (deprecated but check) |
| Referrer-Policy | Referer leakage control |
| Permissions-Policy | Feature restrictions |

### 2. Strict-Transport-Security (HSTS)

**Missing HSTS:**
```http
# Should have:
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

**Issues to check:**
- Absent on HTTPS responses
- Short max-age (< 1 year)
- Missing includeSubDomains when subdomains use HTTPS
- Not on HSTS preload list for critical sites

### 3. X-Content-Type-Options

**Should be present:**
```http
X-Content-Type-Options: nosniff
```

**Impact of missing:**
- MIME sniffing attacks
- Content-type confusion

### 4. X-Frame-Options

**Check for:**
```http
X-Frame-Options: DENY
# or
X-Frame-Options: SAMEORIGIN
```

**Issues:**
- Missing entirely
- ALLOW-FROM with weak restrictions
- Should be replaced by CSP frame-ancestors

### 5. Content-Security-Policy

**Check for CSP presence and strength:**
```http
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'
```

**Weak CSP indicators:**
```
'unsafe-inline'
'unsafe-eval'
data:
*
```

**Missing directives:**
- default-src
- script-src
- object-src
- base-uri
- form-action
- frame-ancestors

### 6. Referrer-Policy

**Should restrict referer leakage:**
```http
Referrer-Policy: strict-origin-when-cross-origin
# or
Referrer-Policy: no-referrer
```

**Weak values:**
- unsafe-url
- no-referrer-when-downgrade (default, leaks to HTTP)

### 7. Permissions-Policy (Feature-Policy)

**Restrict browser features:**
```http
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

**Features to restrict:**
- geolocation
- camera
- microphone
- payment
- usb

### 8. Cache-Control for Sensitive Pages

**For authenticated/sensitive pages:**
```http
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
```

**Issues:**
- Missing on login pages
- Missing on pages with sensitive data
- Allows caching of authenticated responses

### 9. Additional Headers

**Cross-Origin headers:**
```http
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
```

**Cookie security (check Set-Cookie):**
```http
Set-Cookie: session=xxx; Secure; HttpOnly; SameSite=Strict
```

### 10. Scoring Matrix

| Header | Severity if Missing |
|--------|-------------------|
| HSTS | Medium |
| X-Content-Type-Options | Low |
| X-Frame-Options / CSP frame-ancestors | Medium |
| CSP | Medium-High |
| Referrer-Policy | Low |
| Permissions-Policy | Low |

### 11. Document the Finding

**Create OBSERVATION finding with:**
- Missing header(s)
- Affected URL(s)
- Current header configuration (if partial)
- Recommended header value
- Impact explanation

## MCP Tools to Use

### BurpSuite
- `http1_request` / `http2_request`: Retrieve and analyze headers
- `repeater_tab_with_payload`: Test header presence across endpoints

## Keywords
security headers, hsts, csp, content security policy, x-frame-options

## References
- OWASP Secure Headers Project
- https://securityheaders.com
- MDN Web Docs HTTP Headers
