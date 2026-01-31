# SQL Injection Detection Skill

## Objective
Identify and confirm SQL injection vulnerabilities in web applications.

## Instructions

### 1. Identify Injection Points
- Query string parameters
- POST body parameters
- HTTP headers (User-Agent, Referer, Cookie)
- JSON/XML data fields

### 2. Test for SQL Injection
Use the following test payloads:
- Single quote: `'`
- Double quote: `"`
- Numeric manipulation: `1 OR 1=1`
- Time-based: `' OR SLEEP(5)--`
- Error-based: `' AND 1=CONVERT(int, @@version)--`

### 3. Confirm Vulnerability
- Look for error messages containing SQL syntax
- Check for different responses with true/false conditions
- Measure response time for time-based injection
- Use out-of-band techniques with Collaborator

### 4. Document Finding
If confirmed, create a Burp issue with:
- Vulnerable parameter
- Proof of concept payload
- Evidence (response diff, time delay, error message)

## MCP Tools to use
- http1_request: Send test requests
- params_extract: List all parameters
- find_reflected: Check reflections
- collaborator_generate / collaborator_poll: OOB verification
- issue_create: Report confirmed finding
