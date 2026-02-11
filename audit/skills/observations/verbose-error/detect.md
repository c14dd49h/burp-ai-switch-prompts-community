# Verbose Error Message Detection

## Objective
Identify verbose error messages, stack traces, and debug information that leak sensitive details about the application's internals.

## Instructions

### 1. Trigger Error Conditions

**Common error triggers:**
```
- Invalid input types (string vs integer)
- Missing required parameters
- Malformed JSON/XML
- Invalid file paths
- Division by zero
- Null/undefined references
- Database connection errors
- Authentication failures
```

**Test payloads:**
```
?id=test (when expecting integer)
?id=-1
?id=9999999999999
?file=../../../nonexistent
?param[]=array
```

### 2. Stack Trace Indicators

**Look for exposed stack traces:**
```
at com.example.Class.method(Class.java:123)
File "/app/models/user.py", line 42
in /var/www/html/includes/db.php on line 156
Microsoft.NET Framework Version:2.0.50727.9500
```

**Framework-specific errors:**
```
# Java
java.lang.NullPointerException
java.sql.SQLException

# PHP
Fatal error: Uncaught exception
Warning: mysqli_query()

# Python
Traceback (most recent call last):

# .NET
System.NullReferenceException
Server Error in '/' Application

# Node.js
TypeError: Cannot read property
```

### 3. Database Error Messages

**SQL errors revealing schema:**
```
You have an error in your SQL syntax near 'users'
ORA-00942: table or view does not exist
Unknown column 'password' in 'field list'
```

**Connection strings:**
```
Server=localhost;Database=mydb;User=root
mongodb://user:pass@localhost:27017/db
```

### 4. Path Disclosure

**File paths in errors:**
```
C:\inetpub\wwwroot\app\config.php
/var/www/html/includes/database.php
/home/webapp/src/controllers/UserController.php
```

### 5. Configuration Exposure

**Exposed settings:**
```
DEBUG = True
APP_KEY = base64:xxx
database_password = xxx
API_SECRET = xxx
```

### 6. Framework Debug Pages

**Development mode indicators:**
- Django debug page (yellow error page)
- Laravel Whoops page
- Spring Boot error page with stack trace
- Express.js detailed errors
- ASP.NET yellow screen of death

### 7. API Error Responses

**Verbose API errors:**
```json
{
  "error": {
    "message": "Query failed",
    "sql": "SELECT * FROM users WHERE id = 'test'",
    "file": "/app/db.js",
    "line": 42
  }
}
```

### 8. Information Leaked

**Sensitive details to document:**
- Internal file paths
- Database structure/queries
- Framework versions
- Library versions
- Server configuration
- Internal IP addresses
- Usernames/credentials
- API keys

### 9. Testing Methodology

**Systematic error testing:**
1. Test all input parameters with invalid data
2. Test boundary conditions
3. Test authentication/authorization failures
4. Test file operations with invalid paths
5. Test API endpoints with malformed requests
6. Check custom error pages

### 10. Document the Finding

**Create OBSERVATION finding with:**
- Error type and location
- Sensitive information disclosed
- Full error message (sanitized if contains real secrets)
- Trigger condition
- Recommendation for proper error handling

## Remediation Guidance

**General recommendations:**
- Disable debug mode in production
- Implement custom error pages
- Log errors server-side, show generic messages to users
- Sanitize error responses
- Use error monitoring tools (Sentry, Rollbar)

## MCP Tools to Use

### BurpSuite
- `http1_request` / `http2_request`: Send error-triggering requests
- `find_reflected`: Search for path/version strings
- `repeater_tab_with_payload`: Manual error testing

## Keywords
stack trace, error message, debug, information leakage

## References
- OWASP Improper Error Handling
- CWE-209: Information Exposure Through Error Message
