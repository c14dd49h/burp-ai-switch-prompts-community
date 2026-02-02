# Burp AI Switch - Community Prompts

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)
![Burp Suite](https://img.shields.io/badge/Burp%20Suite-2025.x-orange.svg)

Community-maintained AI prompts for the [Burp AI Switch](https://github.com/c14dd49h/burp-ai-switch) extension.

## Overview

This repository contains a curated collection of AI prompts designed to enhance automated security testing within Burp Suite. The prompts work with the Burp AI Switch extension to enable LLM-powered vulnerability detection, analysis, and professional reporting.

**Supported LLM Providers:**
- Claude Code (Anthropic)
- Codex CLI (OpenAI)
- Ollama (Local, privacy-first)

## Features

- **Dual-Mode System**: Auditor mode for security testing, Reporter mode for professional documentation
- **Modular Skills Architecture**: Reusable prompts organized by vulnerability type
- **MCP Tool Integration**: Direct access to 60+ Burp Suite tools through Model Context Protocol
- **Extensible Framework**: Easy to add new vulnerability detection skills
- **Professional Reporting**: Structured templates following industry standards

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/c14dd49h/burp-ai-switch-prompts-community.git
```

### 2. Configure in Burp AI Switch

Point the Burp AI Switch extension to use this prompt directory in the extension settings.

### 3. Start Testing

1. Right-click on a request in Burp Suite (Repeater, Proxy, etc.)
2. Select "Send to AI Switch"
3. Choose a skill (e.g., SQL Injection Detection)
4. Let the AI analyze and test the target

## Project Structure

```
burp-ai-switch-prompts-community/
├── auditor/                          # Auditor mode system prompts
│   └── default.md                    # Security Research Agent
├── reporter/                         # Reporter mode system prompts
│   └── default.md                    # Finding Documentation Writer
├── templates/                        # Output templates
│   └── default.md                    # Vulnerability Report Template
└── skills/                           # Reusable skill prompts
    ├── recon/                        # TYPE: Reconnaissance
    │   └── fingerprinting/           # CATEGORY
    │       └── detect.md             # SKILL
    ├── analysis/                     # TYPE: Analysis
    │   └── request/
    │       └── analyze.md
    ├── vulnerabilities/              # TYPE: Vulnerability Detection
    │   ├── sql-injection/
    │   │   └── detect.md
    │   ├── xss/
    │   │   └── detect.md
    │   └── [22 more categories]      # Community contributions welcome
    └── payloads/                     # TYPE: Payload Generation
        └── generation/
            └── generate.md
```

**Hierarchy Explained:**
- **TYPE**: Top-level category (recon, analysis, vulnerabilities, payloads)
- **CATEGORY**: Specific area within a type (e.g., sql-injection, xss)
- **SKILL**: Individual `.md` file with instructions (e.g., detect.md)

## Available Prompts

### System Prompts

| File | Purpose | Description |
|------|---------|-------------|
| `auditor/default.md` | Security Research Agent | Defines AI behavior for vulnerability testing: methodical approach, scope checking, evidence-based reporting |
| `reporter/default.md` | Finding Writer | Guidelines for professional security documentation: OWASP standards, CVSS scoring, actionable remediation |

### Skills

| Type | Category | Skill | Objective |
|------|----------|-------|-----------|
| **Recon** | fingerprinting | `detect.md` | Identify technologies, frameworks, and server configurations |
| **Analysis** | request | `analyze.md` | Deep HTTP request/response analysis for security issues |
| **Vulnerabilities** | sql-injection | `detect.md` | Identify and confirm SQL injection vulnerabilities |
| **Vulnerabilities** | xss | `detect.md` | Identify and confirm Cross-Site Scripting vulnerabilities |
| **Payloads** | generation | `generate.md` | Generate and mutate payloads for various vulnerability types |

### Planned Vulnerability Categories

The following categories have placeholder directories ready for community contributions:

| Category | Description |
|----------|-------------|
| `access-control` | Broken access control, IDOR, privilege escalation |
| `business-logic` | Application logic flaws |
| `cache-poisoning` | Web cache poisoning attacks |
| `clickjacking` | UI redress attacks |
| `command-injection` | OS command injection |
| `cors` | CORS misconfigurations |
| `crlf` | CRLF injection |
| `csrf` | Cross-Site Request Forgery |
| `deserialization` | Insecure deserialization |
| `file-upload` | Unrestricted file upload |
| `info-disclosure` | Information disclosure |
| `jwt` | JWT vulnerabilities |
| `nosql-injection` | NoSQL injection |
| `oauth` | OAuth/OIDC misconfigurations |
| `open-redirect` | Open redirect vulnerabilities |
| `path-traversal` | Directory traversal |
| `race-conditions` | Race condition vulnerabilities |
| `request-smuggling` | HTTP request smuggling |
| `session` | Session management flaws |
| `ssrf` | Server-Side Request Forgery |
| `ssti` | Server-Side Template Injection |
| `xxe` | XML External Entity injection |

### Templates

| File | Purpose |
|------|---------|
| `templates/default.md` | Standard vulnerability report format with Title, Severity, Description, Steps to Reproduce, PoC, Impact, and Remediation sections |

## Creating Custom Skills

### Skill File Format

Every skill should follow this structure:

```markdown
# [Skill Name]

## Objective
[Clear description of what this skill accomplishes]

## Instructions
1. [Step 1]
2. [Step 2]
3. [Step 3]
...

## MCP Tools to use
- tool_name: Purpose of the tool
- another_tool: Why it's needed
```

### Example: Creating a CSRF Detection Skill

1. Create the file: `skills/vulnerabilities/csrf/detect.md`

2. Add the content:

```markdown
# CSRF Detection Skill

## Objective
Identify and confirm Cross-Site Request Forgery vulnerabilities in state-changing requests.

## Instructions

### 1. Identify State-Changing Requests
- POST, PUT, DELETE methods
- Actions that modify data or settings
- Authentication-related endpoints

### 2. Check for CSRF Protections
- Look for CSRF tokens in forms/headers
- Check SameSite cookie attributes
- Verify Origin/Referer validation

### 3. Test Token Validation
- Remove the CSRF token
- Use an invalid/expired token
- Reuse tokens across sessions

### 4. Confirm Vulnerability
- Create a PoC HTML page
- Verify the action executes without valid token

## MCP Tools to use
- http1_request: Send modified requests
- params_extract: Identify CSRF tokens
- issue_create: Report confirmed CSRF
```

## MCP Tools Reference

Skills can reference these MCP tools that the AI has access to through Burp AI Switch:

### Passive Tools (Read-only)

| Tool | Description |
|------|-------------|
| `params_extract` | Extract all parameters from a request |
| `find_reflected` | Find where input is reflected in responses |
| `site_map` | Access Burp's site map |
| `proxy_http_history` | Browse proxy history |
| `request_parse` | Parse HTTP request structure |
| `response_parse` | Parse HTTP response structure |
| `jwt_decode` | Decode JWT tokens |
| `base64_encode/decode` | Base64 encoding operations |
| `url_encode/decode` | URL encoding operations |
| `hash_compute` | Compute various hashes |
| `scope_check` | Verify if URL is in scope |

### Active Tools (Interact with target)

| Tool | Description |
|------|-------------|
| `http1_request` | Send HTTP/1.1 requests |
| `http2_request` | Send HTTP/2 requests |
| `collaborator_generate` | Generate Collaborator payloads |
| `collaborator_poll` | Poll for Collaborator interactions |
| `issue_create` | Create Burp Suite issues |
| `scan_audit_start` | Start active scanning |

## Contributing

We welcome contributions! Here's how to add your prompts:

### 1. Fork the Repository

```bash
git clone https://github.com/YOUR_USERNAME/burp-ai-switch-prompts-community.git
```

### 2. Create Your Prompt

Follow the structure and conventions described above.

### 3. Test Your Prompt

Use Burp AI Switch to verify your prompt works as expected.

### 4. Submit a Pull Request

- Use a descriptive commit message
- Explain what your prompt does in the PR description
- Include example use cases if helpful

### Contribution Guidelines

- **Be specific**: Prompts should have clear, actionable instructions
- **Test thoroughly**: Verify the prompt produces accurate results
- **Document tools**: List all MCP tools the skill uses
- **Follow conventions**: Use lowercase directory names with hyphens
- **No false positives**: Skills should prioritize accuracy over quantity

## Workflow Overview

```
┌─────────────────────────────────────────┐
│         AUDITOR MODE                    │
│   (Security Research Agent)             │
│                                         │
│   1. Scope Check (scope_check)          │
│   2. Reconnaissance (fingerprinting)    │
│   3. Analysis (request analysis)        │
│   4. Vulnerability Testing (skills)     │
│   5. Issue Creation (issue_create)      │
└──────────────────┬──────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────┐
│         REPORTER MODE                   │
│   (Finding Documentation Writer)        │
│                                         │
│   1. Review findings                    │
│   2. Professional documentation         │
│   3. CVSS scoring                       │
│   4. Remediation guidance               │
└──────────────────┬──────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────┐
│         OUTPUT                          │
│   (Using templates/default.md)          │
│                                         │
│   - Title                               │
│   - Severity                            │
│   - Description                         │
│   - Steps to Reproduce                  │
│   - Proof of Concept                    │
│   - Impact                              │
│   - Remediation                         │
│   - References                          │
└─────────────────────────────────────────┘
```

## Related Projects

- [Burp AI Switch](https://github.com/c14dd49h/burp-ai-switch) - The main Burp Suite extension that uses these prompts
- [Model Context Protocol](https://modelcontextprotocol.io/) - The protocol enabling AI-tool communication

## License

MIT License - See [LICENSE](LICENSE) for details.

---

**Made with security in mind by the community.**
