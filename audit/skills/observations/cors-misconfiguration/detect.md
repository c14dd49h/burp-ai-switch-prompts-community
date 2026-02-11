# CORS Misconfiguration Observation

## Objective
Identify CORS configurations that, while not directly exploitable, represent security weaknesses or deviations from best practices.

## Note
This skill is for OBSERVATION-level findings. For exploitable CORS vulnerabilities (with credentials), use the CORS vulnerability detection skill.

## Instructions

### 1. Overly Permissive Wildcard

**Wildcard without credentials:**
```http
Access-Control-Allow-Origin: *
```

**When this is an observation (not vulnerability):**
- No `Access-Control-Allow-Credentials: true`
- Only public, non-sensitive data accessible
- Still worth noting for defense-in-depth

### 2. Broad Subdomain Trust

**Trusting all subdomains:**
```http
Origin: https://any.example.com
→ Access-Control-Allow-Origin: https://any.example.com
```

**Why noteworthy:**
- Subdomain takeover could escalate
- Compromised subdomain affects main domain
- Increases attack surface

### 3. Development Origins in Production

**Localhost allowed:**
```http
Origin: http://localhost:3000
→ Access-Control-Allow-Origin: http://localhost:3000
```

**Issues:**
- Development oversight
- Could indicate other dev artifacts
- Potential for local exploitation

### 4. HTTP Origins on HTTPS

**Protocol mismatch:**
```http
# On HTTPS site
Origin: http://example.com
→ Access-Control-Allow-Origin: http://example.com
```

**Why noteworthy:**
- Downgrades security
- MitM could intercept cross-origin requests
- Mixed content issues

### 5. Regex Pattern Issues

**Partial domain matching:**
```http
# If checking contains "example.com"
Origin: https://example.com.attacker.com
→ Access-Control-Allow-Origin: https://example.com.attacker.com
```

**When observation (not vuln):**
- No credentials allowed
- Limited data exposure

### 6. Missing Vary Header

**Cache poisoning risk:**
```http
Access-Control-Allow-Origin: https://trusted.com
# Missing: Vary: Origin
```

**Impact:**
- Cached responses may serve wrong CORS headers
- Potential for cache poisoning
- CDN/proxy issues

### 7. Exposed Headers

**Excessive header exposure:**
```http
Access-Control-Expose-Headers: Authorization, X-Custom-Secret, X-Internal-Data
```

**Issues:**
- Exposes internal header names
- May leak sensitive data
- Information disclosure

### 8. Long Preflight Cache

**Extended preflight caching:**
```http
Access-Control-Max-Age: 86400  # 24 hours
```

**Considerations:**
- Policy changes take time to propagate
- May be acceptable but worth noting

### 9. Allowed Methods

**Overly permissive methods:**
```http
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, PATCH, OPTIONS, TRACE
```

**Issues:**
- TRACE rarely needed
- Excessive permissions
- Review necessity

### 10. Allowed Headers

**Broad header allowance:**
```http
Access-Control-Allow-Headers: *
```

**Issues:**
- Allows any custom header
- May bypass some security controls
- Less restrictive than necessary

### 11. Documentation Requirements

**For OBSERVATION finding, document:**
- Current CORS configuration
- Specific weakness identified
- Potential escalation scenarios
- Recommended restrictive configuration
- Priority (usually Low-Medium)

### 12. Risk Assessment

**Low Risk Observations:**
- Wildcard without credentials
- Missing Vary header
- Overly long preflight cache

**Medium Risk Observations:**
- Broad subdomain trust
- HTTP origins allowed
- Development origins in production

## Remediation Guidance

**Best practices:**
```http
Access-Control-Allow-Origin: https://specific-trusted-origin.com
Access-Control-Allow-Credentials: true (only if needed)
Access-Control-Allow-Methods: GET, POST (minimum required)
Access-Control-Allow-Headers: Content-Type, Authorization (specific headers)
Access-Control-Max-Age: 600 (reasonable cache)
Vary: Origin
```

**Implement origin allowlist:**
```javascript
const allowedOrigins = [
  'https://app.example.com',
  'https://admin.example.com'
];

if (allowedOrigins.includes(origin)) {
  res.setHeader('Access-Control-Allow-Origin', origin);
}
```

## MCP Tools to Use

### BurpSuite
- `http1_request` / `http2_request`: Test various origins
- `repeater_tab_with_payload`: Manual CORS testing

## Keywords
cors configuration, cross-origin, access-control-allow-origin

## References
- MDN CORS Documentation
- OWASP CORS Security
- Web Security Academy CORS
