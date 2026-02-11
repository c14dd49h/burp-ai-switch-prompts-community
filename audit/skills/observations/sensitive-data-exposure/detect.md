# Sensitive Data Exposure Detection

## Objective
Identify exposure of sensitive information in application responses, logs, or error messages.

## Instructions

### 1. Types of Sensitive Data

**Personal Identifiable Information (PII):**
- Full names
- Email addresses
- Phone numbers
- Physical addresses
- Social Security Numbers
- National ID numbers
- Date of birth

**Financial Data:**
- Credit card numbers
- Bank account numbers
- Transaction details
- Financial statements

**Authentication Data:**
- Passwords (plaintext or hashed)
- API keys
- Session tokens
- JWT tokens
- OAuth tokens

**System Information:**
- Internal IP addresses
- Server paths
- Database connection strings
- Configuration details

### 2. Common Exposure Points

**Response bodies:**
```json
{
  "user": {
    "email": "user@example.com",
    "password_hash": "$2a$10$xxx",
    "ssn": "123-45-6789",
    "credit_card": "4111111111111111"
  }
}
```

**URL parameters:**
```
/profile?ssn=123-45-6789
/reset?token=secret_token_value
/download?file=/etc/passwd
```

**Response headers:**
```http
X-User-Email: user@example.com
Set-Cookie: user_data={"email":"user@example.com","admin":true}
```

### 3. Data Patterns to Search

**Credit card patterns:**
```regex
\b4[0-9]{12}(?:[0-9]{3})?\b     # Visa
\b5[1-5][0-9]{14}\b              # MasterCard
\b3[47][0-9]{13}\b               # Amex
```

**SSN pattern:**
```regex
\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b
```

**Email pattern:**
```regex
[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}
```

**API key patterns:**
```regex
(api[_-]?key|apikey)["\s:=]+["\']?([a-zA-Z0-9]{20,})["\']?
AKIA[0-9A-Z]{16}  # AWS Access Key
sk_live_[a-zA-Z0-9]{24}  # Stripe
```

### 4. Check API Responses

**Over-exposed fields:**
- Internal IDs when UUIDs expected
- Password hashes in user objects
- Admin flags in public responses
- Other users' data in responses

**Mass assignment indicators:**
```json
{
  "id": 1,
  "username": "user",
  "email": "user@example.com",
  "password_hash": "xxx",
  "role": "admin",
  "internal_notes": "VIP customer"
}
```

### 5. Check Error Messages

**Sensitive data in errors:**
```
Error connecting to database: mysql://user:password@localhost/db
Failed to validate credit card: 4111111111111111
User not found: admin@internal.company.com
```

### 6. Check Client-Side Storage

**Browser storage exposure:**
```javascript
localStorage.getItem('user_token')
sessionStorage.getItem('api_key')
document.cookie
```

### 7. Check Source Code

**Embedded secrets:**
```html
<!-- API Key: abc123 -->
<script>var apiKey = "secret_key_here";</script>
```

### 8. Check Logs and Debug Output

**Sensitive data logged:**
```
[INFO] User login: username=admin, password=secret123
[DEBUG] API request: headers={Authorization: Bearer xxx}
```

### 9. Mass Assignment Testing

**Test for over-posting:**
```json
POST /api/users
{
  "username": "test",
  "role": "admin",
  "is_verified": true
}
```

### 10. IDOR Leading to Data Exposure

**Test sequential IDs:**
```
/api/users/1
/api/users/2
/api/documents/123
/api/documents/124
```

### 11. Document the Finding

**Create OBSERVATION finding with:**
- Type of sensitive data exposed
- Location (endpoint, header, body)
- Sample data (redacted if necessary)
- Impact assessment
- Affected users (if determinable)
- Recommendation for remediation

## Remediation Guidance

**General:**
- Implement proper data classification
- Use DTOs/view models to control exposed fields
- Encrypt sensitive data at rest and in transit
- Mask/redact sensitive data in logs
- Implement proper access controls
- Regular security audits

## MCP Tools to Use

### BurpSuite
- `http1_request` / `http2_request`: Analyze responses
- `find_reflected`: Search for patterns in responses
- `sitemap_json`: Audit all captured responses

### Chrome
- `evaluate_script`: Check client-side storage
- `list_console_messages`: Look for logged sensitive data

## Keywords
data exposure, sensitive data, pii, information leakage

## References
- OWASP Sensitive Data Exposure
- GDPR Data Protection Requirements
- PCI DSS Compliance
