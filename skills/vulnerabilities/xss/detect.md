# XSS Detection Skill

## Objective
Identify and confirm Cross-Site Scripting (XSS) vulnerabilities.

## Instructions

### 1. Find Reflection Points
Use find_reflected tool to identify where user input is reflected in responses.

### 2. Determine Context
- HTML body context
- HTML attribute context
- JavaScript context
- URL context

### 3. Test for XSS
Context-appropriate payloads:
- HTML: `<script>alert(1)</script>`
- Attribute: `" onmouseover="alert(1)`
- JavaScript: `';alert(1)//`
- Event handlers: `<img src=x onerror=alert(1)>`

### 4. Bypass Filters
- Case variation: `<ScRiPt>`
- Encoding: `&#x3c;script&#x3e;`
- Alternative tags: `<svg onload=alert(1)>`

### 5. Confirm and Report
- Verify payload executes in browser
- Document the reflection context
- Create Burp issue with PoC

## MCP Tools to use
- find_reflected: Identify reflections
- http1_request: Test payloads
- url_encode: Encode payloads
- issue_create: Report confirmed XSS
