# Technology Fingerprinting Skill

## Objective
Identify web technologies, frameworks, servers, and components used by the target application for informed vulnerability assessment.

## Instructions

### 1. HTTP Header Analysis

**Server header:**
```
Server: Apache/2.4.41 (Ubuntu)
Server: nginx/1.18.0
Server: Microsoft-IIS/10.0
```

**X-Powered-By:**
```
X-Powered-By: PHP/7.4.3
X-Powered-By: ASP.NET
X-Powered-By: Express
```

**Other revealing headers:**
```
X-AspNet-Version: 4.0.30319
X-AspNetMvc-Version: 5.2
X-Generator: Drupal 9
X-Drupal-Cache: HIT
X-Varnish: 123456
X-Cache: HIT from squid
X-Powered-CMS: WordPress
Via: 1.1 varnish
```

### 2. Cookie Analysis

**Framework-specific cookies:**
```
PHPSESSID - PHP
JSESSIONID - Java (Tomcat, JBoss)
ASP.NET_SessionId - ASP.NET
CFID/CFTOKEN - ColdFusion
connect.sid - Express.js
laravel_session - Laravel
_rails_session - Ruby on Rails
wp-settings-* - WordPress
```

### 3. HTML/JavaScript Analysis

**Meta tags:**
```html
<meta name="generator" content="WordPress 5.8">
<meta name="generator" content="Drupal 9">
<meta name="generator" content="Joomla">
```

**JavaScript libraries:**
```javascript
// Check for global objects
jQuery, $         - jQuery
angular           - AngularJS
React             - React
Vue               - Vue.js
Backbone          - Backbone.js
```

**Common file patterns:**
```
/wp-content/      - WordPress
/wp-includes/     - WordPress
/administrator/   - Joomla
/sites/default/   - Drupal
/static/admin/    - Django
/assets/          - Rails Asset Pipeline
```

### 4. Error Page Analysis

**Default error pages reveal:**
```
Apache: Apache/2.4.41 Server at example.com Port 80
Nginx: nginx error page
IIS: Microsoft .NET Framework Version
Tomcat: Apache Tomcat/9.0.41
Django: Debug = True error page
Rails: Action Controller Exception
PHP: Fatal error... in /var/www/...
```

### 5. URL Structure Analysis

**Framework patterns:**
```
/index.php?id=1           - PHP
/controller/action        - MVC framework
/api/v1/resource          - REST API
/graphql                  - GraphQL
/admin.asp                - Classic ASP
/page.aspx                - ASP.NET
/servlet/                 - Java Servlet
/cgi-bin/                 - CGI scripts
```

### 6. Common Files to Request

**Technology indicators:**
```
/robots.txt              - May reveal paths
/sitemap.xml             - Site structure
/.git/HEAD               - Git repository
/.svn/entries            - SVN repository
/web.config              - ASP.NET config
/wp-config.php           - WordPress
/configuration.php       - Joomla
/composer.json           - PHP Composer
/package.json            - Node.js
/Gemfile                 - Ruby
/requirements.txt        - Python
```

### 7. API Endpoint Discovery

**Common API paths:**
```
/api/
/api/v1/
/rest/
/graphql
/swagger.json
/openapi.json
/api-docs
/.well-known/
```

### 8. WAF/CDN Detection

**Common indicators:**
```
# Headers
Server: cloudflare
X-CDN: Imperva
X-Sucuri-ID: xxx
X-Akamai-Request-ID: xxx

# Behavior
403 on payloads - WAF blocking
Challenge pages - Bot protection
```

### 9. CMS Detection

**WordPress:**
```
/wp-content/
/wp-includes/
/wp-admin/
/wp-login.php
/readme.html
```

**Drupal:**
```
/sites/default/
/node/1
/user/login
/CHANGELOG.txt
```

**Joomla:**
```
/administrator/
/components/
/modules/
/README.txt
```

### 10. Version Detection

**Try accessing:**
```
/VERSION
/version.txt
/CHANGELOG
/CHANGELOG.md
/readme.html
```

### 11. Document Findings

Create summary with:
- Web server and version
- Backend language/framework
- Frontend frameworks/libraries
- CMS if applicable
- CDN/WAF detected
- API technologies
- Known vulnerabilities for versions

## MCP Tools to Use
- `http1_request` / `http2_request`: Request indicator files
- `proxy_history`: Analyze captured traffic
- `site_map`: Review discovered paths
- `params_extract`: Identify technology-specific parameters

## References
- PayloadsAllTheThings/Methodology and Resources
- Wappalyzer Technology Database
- WhatWeb fingerprints
