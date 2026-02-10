---
name: XSS Reflected Detection
version: 1.0
author: community
description: Detect reflected XSS vulnerabilities
tags: [xss, injection, owasp-a03, client-side]
requires_selection: true
---

# XSS Reflected Detection

## Objectif

Detect Cross-Site Scripting (XSS) reflected vulnerabilities where user input is returned in the response without proper sanitization.

## Etapes de test

### 1. Identify injection points

Search in the request:
- GET/POST parameters
- Headers (User-Agent, Referer, X-Forwarded-For)
- URL fragments
- Cookies

### 2. Verify reflection

Send a unique value (canary) and check if it appears in the response:
```
Canary: burpxss12345
```

If reflected, note the context:
- In raw HTML
- In an HTML attribute
- In JavaScript
- In CSS
- In a comment

### 3. Context-specific detection payloads

**HTML context:**
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

**Attribute context:**
```html
" onmouseover="alert(1)
' onfocus='alert(1)' autofocus='
```

**JavaScript context:**
```javascript
';alert(1)//
</script><script>alert(1)</script>
```

**Encoding bypasses:**
```
%3Cscript%3Ealert(1)%3C/script%3E
&#60;script&#62;alert(1)&#60;/script&#62;
\u003cscript\u003ealert(1)\u003c/script\u003e
```

### 4. Check protections

- Content-Security-Policy header
- X-XSS-Protection header
- Special character encoding
- Server-side filtering

### 5. Document the finding

If vulnerable:
```
burp_create_finding(
  title: "Reflected XSS on [endpoint]",
  type: "VULNERABILITY",
  severity: "MEDIUM",
  confidence: "CERTAIN" or "FIRM",
  category: "XSS",
  description: "Detailed description...",
  remediation: "Encode outputs, implement CSP...",
  references: ["CWE-79", "https://owasp.org/www-community/xss-filter-evasion-cheatsheet"]
)
```

If protected:
```
burp_create_finding(
  title: "XSS Protection verified on [endpoint]",
  type: "COVERED",
  severity: "INFO",
  category: "XSS",
  description: "Input sanitization and CSP in place..."
)
```

## Vulnerability indicators

- Input reflected without modification
- Characters `< > " ' /` not encoded
- No CSP or permissive CSP
- X-XSS-Protection: 0

## Protection indicators

- Special characters encoded (HTML entities)
- Restrictive CSP with nonces
- HttpOnly on sensitive cookies
- X-Content-Type-Options: nosniff
