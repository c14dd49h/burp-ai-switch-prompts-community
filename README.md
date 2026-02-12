# Burp AI Switch - Community Prompts

Community-driven prompt repository for [Burp AI Switch](https://github.com/c14dd49h/burp-ai-switch) extension.

## Overview

This repository contains agents and skills that guide AI behavior during security testing with Burp Suite.

```
burp-ai-switch-prompts-community/
├── agent.md                    <- Master agent (entry point)
├── taxonomy.yaml               <- Vulnerability/observation types (source of truth)
├── audit/
│   ├── agent.md                <- Security audit agent
│   └── skills/
│       └── vulnerabilities/    <- Vulnerability detection skills
│           ├── xss/
│           ├── sql-injection/
│           ├── ssrf/
│           └── ...
└── report/
    ├── finding/
    │   ├── agent.md            <- Finding writer
    │   └── templates/          <- Finding templates (configurable)
    │       └── default.md
    └── exec-summary/
        ├── agent.md            <- Executive summary generator
        └── templates/
            └── default.md
```

## Installation

1. Clone this repository:
```bash
git clone https://github.com/c14dd49h/burp-ai-switch-prompts-community.git
```

2. In Burp AI Switch settings, add the path to this repository

3. Click "Refresh" to load the prompts

## Usage

### Security Audit

1. Select a request in Burp Suite
2. Right-click → "Send to AI Switch"
3. Ask: "Test this request for vulnerabilities"
4. The AI loads `audit/agent.md` and uses appropriate skills

### Report Generation

1. After audit, ask: "Write the findings"
2. The AI loads `report/finding/agent.md`
3. DRAFT findings become WRITTEN with professional descriptions

### Executive Summary

Ask: "Generate executive summary" to get a high-level report.

## Skills Hierarchy

Skills follow a 3-level hierarchy:

```
skills/
├── TYPE/           # recon, analysis, vulnerabilities, payloads
│   └── CATEGORY/   # xss, sql-injection, ssrf, etc.
│       └── ACTION.md # detect.md, bypass.md, exploit.md
```

### Available Skills

| Category | Path | Description |
|----------|------|-------------|
| XSS | `vulnerabilities/xss/detect.md` | Cross-Site Scripting detection |
| SQL Injection | `vulnerabilities/sql-injection/detect.md` | UNION-based SQLi |
| SSRF | `vulnerabilities/ssrf/detect.md` | Server-Side Request Forgery |
| Access Control | `vulnerabilities/access-control/detect.md` | IDOR, AuthZ bypass |
| Path Traversal | `vulnerabilities/path-traversal/detect.md` | Directory traversal, LFI |
| Command Injection | `vulnerabilities/command-injection/detect.md` | OS command injection |

## Contributing

### Adding a new skill

1. Create file at `audit/skills/TYPE/CATEGORY/ACTION.md`
2. Use YAML frontmatter:
```yaml
---
name: Skill Name
version: 1.0
author: your-name
description: What this skill does
tags: [tag1, tag2]
requires_selection: true
---
```
3. Include sections:
   - **Objective**: What the skill detects
   - **Test steps**: Numbered methodology
   - **Payloads**: Detection payloads
   - **Document the finding**: How to report

### Skill guidelines

- Be specific and actionable
- Include both detection AND bypass techniques
- Reference CWE and OWASP where applicable
- Test with real targets before submitting

## File Format

All files use YAML frontmatter + Markdown:

```markdown
---
name: Agent/Skill Name
version: 1.0
author: community
description: Brief description
tags: [tag1, tag2]
---

# Title

Content here...
```

## Taxonomy

The `taxonomy.yaml` file defines standard vulnerability and observation types used across all skills:

**Vulnerabilities:**
| ID | Name | CWE |
|----|------|-----|
| `xss` | Cross-Site Scripting | CWE-79 |
| `sql-injection` | SQL Injection | CWE-89 |
| `ssrf` | Server-Side Request Forgery | CWE-918 |
| `idor` | Insecure Direct Object Reference | CWE-639 |
| `path-traversal` | Path Traversal | CWE-22 |
| `command-injection` | Command Injection | CWE-78 |

**Observations:**
| ID | Name |
|----|------|
| `version-disclosure` | Version Disclosure |
| `missing-security-header` | Missing Security Header |
| `verbose-error` | Verbose Error Message |

Use these `vuln_type` values when creating findings for consistency.

## MCP Tools Reference

Skills can use these Burp AI Switch MCP tools:

### Passive (Read-only)
- `burp_get_current_selection` - Get selected request
- `burp_get_proxy_history` - Browse captured traffic
- `burp_list_skills` - List available skills
- `burp_list_findings` - List existing findings
- `burp_check_scope` - Check if URL is in scope
- `burp_get_audit_settings` - Get audit settings
- `burp_get_finding_template` - Get configured finding template
- `burp_get_executive_summary` - Get current executive summary
- `burp_get_executive_summary_template` - Get configured executive summary template

### Active (Modify)
- `burp_create_finding` - Create finding with `vuln_type` for categorization
- `burp_update_finding` - Update finding status/content
- `burp_export_findings` - Export to JSON/Markdown
- `burp_set_executive_summary` - Save executive summary

### HTTP (Send requests)
- `burp_send_request` - Send HTTP request through Burp

## License

MIT License - See [LICENSE](LICENSE)
