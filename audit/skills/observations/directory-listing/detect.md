# Directory Listing Detection

## Objective
Identify exposed directory listings that reveal file structure and potentially sensitive files.

## Instructions

### 1. Identify Directory Listing

**Visual indicators:**
```
Index of /uploads/
Index of /backup/
Directory listing for /var/www/
Apache/2.4.41 Server at example.com Port 80
```

**Common HTML patterns:**
```html
<title>Index of /</title>
<h1>Index of /uploads</h1>
[DIR] parent directory
[TXT] readme.txt
```

### 2. Common Vulnerable Directories

**Test these paths:**
```
/uploads/
/backup/
/backups/
/images/
/files/
/docs/
/documents/
/assets/
/static/
/media/
/temp/
/tmp/
/logs/
/data/
/export/
/includes/
/lib/
/vendor/
/node_modules/
```

### 3. Sensitive Files to Look For

**Configuration files:**
```
.htaccess
.htpasswd
web.config
config.php
settings.py
.env
.git/
.svn/
```

**Backup files:**
```
*.bak
*.backup
*.old
*.orig
*.sql
*.tar.gz
*.zip
database.sql
```

**Source code:**
```
*.php~
*.py~
*.java
*.cs
```

**Logs:**
```
*.log
access.log
error.log
debug.log
```

### 4. Server-Specific Listings

**Apache:**
```html
<title>Index of /path</title>
<address>Apache/x.x.x Server</address>
```

**Nginx:**
```html
<title>Index of /path/</title>
<hr><center>nginx</center>
```

**IIS:**
```
Directory listing enabled in web.config
```

**Tomcat:**
```html
<title>Directory Listing For /path</title>
```

### 5. Automation Techniques

**Directory brute forcing:**
```
/admin/
/administrator/
/api/
/app/
/application/
/assets/
/backup/
/config/
/data/
/debug/
/dev/
/files/
/includes/
/internal/
/logs/
/private/
/scripts/
/server/
/src/
/test/
/tmp/
/upload/
```

### 6. Information Gathered

**From directory listings:**
- Application structure
- Backup file locations
- Configuration file names
- Hidden or administrative paths
- File naming conventions
- Technology indicators

### 7. Risk Assessment

**High Risk:**
- Exposed backup files
- Configuration files visible
- Source code accessible
- Credentials in file names

**Medium Risk:**
- Application structure revealed
- Internal paths exposed
- File naming patterns visible

**Low Risk:**
- Static asset directories
- Public media directories

### 8. Document the Finding

**Create OBSERVATION finding with:**
- Directory URL with listing enabled
- Sensitive files found (if any)
- Server type/version if disclosed
- Screenshot of listing
- Recommendation to disable

## Remediation Guidance

**Apache (.htaccess):**
```apache
Options -Indexes
```

**Nginx:**
```nginx
autoindex off;
```

**IIS (web.config):**
```xml
<directoryBrowse enabled="false" />
```

**Tomcat (web.xml):**
```xml
<init-param>
    <param-name>listings</param-name>
    <param-value>false</param-value>
</init-param>
```

## MCP Tools to Use

### BurpSuite
- `http1_request` / `http2_request`: Check directories
- `sitemap_json`: Discover accessible paths
- `intruder_prepare`: Directory enumeration

### Chrome
- `navigate_page`: Browse directory listings
- `take_screenshot`: Capture evidence

## Keywords
directory listing, index of, directory browsing, file enumeration

## References
- OWASP Directory Listing
- CWE-548: Information Exposure Through Directory Listing
