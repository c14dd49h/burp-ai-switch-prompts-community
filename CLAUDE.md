# CLAUDE.md

Instructions for Claude Code when working on this repository.

## Project Overview

This is a **prompt-only repository** for the [Burp AI Switch](https://github.com/c14dd49h/burp-ai-switch) extension. It contains markdown files that define AI behavior and instructions for security testing tasks within Burp Suite.

**Key Points:**
- No executable code - only markdown prompt files
- Prompts are loaded dynamically by the Burp AI Switch extension
- Changes to prompts affect AI behavior in security testing workflows

## Repository Structure

```
burp-ai-switch-prompts-community/
├── auditor/          # System prompts for Auditor mode (security testing)
│   └── default.md
├── reporter/         # System prompts for Reporter mode (documentation)
│   └── default.md
├── templates/        # Output templates for reports
│   └── default.md
└── skills/           # Modular skill prompts (TYPE/CATEGORY/action.md)
    ├── recon/
    ├── analysis/
    ├── vulnerabilities/
    └── payloads/
```

## Key Files

| File | Purpose |
|------|---------|
| `auditor/default.md` | Defines Security Research Agent behavior: scope checking, methodical testing, evidence-based reporting |
| `reporter/default.md` | Defines Finding Writer behavior: OWASP standards, CVSS scoring, professional documentation |
| `templates/default.md` | Vulnerability report structure: Title, Severity, Description, PoC, Impact, Remediation |

## Skill File Format

All skills must follow this structure:

```markdown
# [Skill Name]

## Objective
[What this skill accomplishes]

## Instructions
[Step-by-step testing guide]

## MCP Tools to use
[List of MCP tools with their purpose]
```

**Required Sections:**
1. `# Title` - Name of the skill
2. `## Objective` - Clear goal description
3. `## Instructions` - Numbered steps or subsections
4. `## MCP Tools to use` - Tools the AI should leverage

## MCP Tools Reference

These tools are available to the AI through Burp AI Switch:

### Passive (Read-only)
- `params_extract` - Extract request parameters
- `find_reflected` - Find input reflections in responses
- `site_map` - Access Burp's site map
- `proxy_http_history` - Browse captured traffic
- `request_parse` / `response_parse` - Parse HTTP structures
- `jwt_decode` - Decode JWT tokens
- `base64_encode/decode`, `url_encode/decode` - Encoding utilities
- `hash_compute` - Hash computation
- `scope_check` - Verify target is in scope

### Active (Interact with target)
- `http1_request` / `http2_request` - Send HTTP requests
- `collaborator_generate` / `collaborator_poll` - OOB testing
- `issue_create` - Create Burp Suite issues
- `scan_audit_start` - Start active scanning

## Naming Conventions

- **Directories**: lowercase with hyphens (`sql-injection`, not `SQLInjection`)
- **Skill files**: action-based naming (`detect.md`, `analyze.md`, `generate.md`)
- **Empty categories**: use `.gitkeep` placeholder

## Skills Hierarchy

```
skills/
├── TYPE/           # Level 1: recon, analysis, vulnerabilities, payloads
│   └── CATEGORY/   # Level 2: specific area (e.g., sql-injection, xss)
│       └── SKILL.md # Level 3: action file (e.g., detect.md)
```

## Common Tasks

### Adding a New Vulnerability Skill

1. Create file: `skills/vulnerabilities/{vuln-type}/detect.md`
2. Follow the skill file format above
3. List relevant MCP tools
4. Test with Burp AI Switch

### Modifying a System Prompt

1. Edit `auditor/default.md` or `reporter/default.md`
2. Keep prompts concise and action-oriented
3. Maintain the Role/Behavior/Response Format structure

### Adding a New Category

1. Create directory: `skills/{type}/{new-category}/`
2. Add `.gitkeep` if no skills yet
3. Create skill files as needed

## Testing Changes

1. Load the prompt directory in Burp AI Switch
2. Send a request to the AI with the relevant skill
3. Verify the AI follows the updated instructions
4. Check for accurate vulnerability detection (no false positives)

## Quality Guidelines

- **Clarity**: Instructions should be unambiguous
- **Accuracy**: Skills should minimize false positives
- **Completeness**: Include all necessary steps
- **Tool awareness**: Reference appropriate MCP tools
- **Scope respect**: Always encourage scope checking before testing
