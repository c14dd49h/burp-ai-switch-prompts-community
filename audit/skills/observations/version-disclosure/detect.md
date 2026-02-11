# Version Disclosure Detection

## Objective
Identify exposed server, framework, or application version information that aids attackers in targeting known vulnerabilities.

## Instructions

### 1. Check Response Headers

**Common version-disclosing headers:**
```http
Server: Apache/2.4.41 (Ubuntu)
Server: nginx/1.18.0
X-Powered-By: PHP/7.4.3
X-Powered-By: ASP.NET
X-AspNet-Version: 4.0.30319
X-AspNetMvc-Version: 5.2
X-Generator: Drupal 8
X-Drupal-Cache: HIT
```

**Framework-specific headers:**
```http
X-Runtime: 0.003141  (Ruby on Rails)
X-Request-Id: xxx    (Rails)
X-Django-Debug: true (Django)
X-Struts: xxx        (Apache Struts)
```

### 2. Check Error Pages

**Default error pages reveal:**
- Apache default 404/500 pages
- Nginx default error pages
- IIS detailed error messages
- Tomcat stack traces
- Framework-specific error templates

**Test URLs:**
```
/nonexistent-page-12345
/%00
/..%00
/;.css
```

### 3. Check Meta Tags and Comments

**HTML source analysis:**
```html
<meta name="generator" content="WordPress 5.8">
<meta name="generator" content="Drupal 8">
<!-- Built with Next.js 12.0 -->
<!-- Powered by Angular 13 -->
```

### 4. Check JavaScript Files

**Look for version info in:**
```javascript
// jQuery v3.6.0
// React v18.0
// Vue.js v3.2
window.APP_VERSION = "2.1.0";
```

### 5. Check API Responses

**Version in API responses:**
```json
{
  "version": "1.2.3",
  "api_version": "v2",
  "server": "Express/4.17.1"
}
```

### 6. Check Specific Endpoints

**Common version endpoints:**
```
/version
/api/version
/about
/info
/status
/.version
/build.json
/package.json (if exposed)
/composer.json (if exposed)
```

### 7. Fingerprinting Techniques

**File hash fingerprinting:**
Compare static file hashes against known versions.

**Behavior-based fingerprinting:**
Test specific features present in certain versions.

### 8. Impact Assessment

**Why version disclosure matters:**
- Enables targeted CVE exploitation
- Reveals technology stack
- Assists in crafting specific payloads
- Reduces attacker reconnaissance time

### 9. Document the Finding

**Create OBSERVATION finding with:**
- Location of disclosure (header, page, file)
- Exact version disclosed
- Technology/component identified
- Recommendation to remove/mask version

## Remediation Guidance

**Apache:**
```apache
ServerTokens Prod
ServerSignature Off
```

**Nginx:**
```nginx
server_tokens off;
```

**PHP:**
```ini
expose_php = Off
```

**Remove X-Powered-By:**
Application-level configuration to suppress headers.

## MCP Tools to Use

### BurpSuite
- `http1_request` / `http2_request`: Check response headers
- `find_reflected`: Search for version strings in responses
- `params_extract`: Identify version parameters

## Keywords
server version, version disclosure, fingerprint, banner grabbing

## References
- OWASP Information Gathering
- CIS Benchmarks for Web Servers
