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
├── agent.md                    <- MASTER AGENT (entry point)
├── audit/
│   ├── agent.md                <- Sub-agent for security auditing
│   └── skills/
│       └── vulnerabilities/    <- TYPE level
│           ├── xss/            <- CATEGORY level
│           │   └── detect.md   <- ACTION level
│           ├── sql-injection/
│           ├── ssrf/
│           ├── access-control/
│           ├── path-traversal/
│           └── command-injection/
└── report/
    ├── agent.md                <- Report orchestrator
    ├── finding/
    │   └── agent.md            <- Finding writer agent
    └── exec-summary/
        └── agent.md            <- Executive summary agent
```

## Key Files

| File | Purpose |
|------|---------|
| `agent.md` | Master agent - routes to sub-agents based on user intent |
| `audit/agent.md` | Security testing agent - methodical vulnerability research |
| `report/agent.md` | Report orchestrator - coordinates finding + summary agents |
| `report/finding/agent.md` | Writes professional finding descriptions |
| `report/exec-summary/agent.md` | Generates executive summaries |

## Skills Hierarchy (3 Levels)

```
skills/
├── TYPE/           # Level 1: recon, analysis, vulnerabilities, payloads
│   └── CATEGORY/   # Level 2: xss, sql-injection, ssrf, jwt...
│       └── ACTION.md # Level 3: detect.md, bypass.md, exploit.md
```

**Current skills:**
- `vulnerabilities/xss/detect.md` - XSS detection
- `vulnerabilities/sql-injection/detect.md` - SQL injection
- `vulnerabilities/ssrf/detect.md` - SSRF
- `vulnerabilities/access-control/detect.md` - IDOR
- `vulnerabilities/path-traversal/detect.md` - Path traversal
- `vulnerabilities/command-injection/detect.md` - Command injection

## File Format

All agents and skills use YAML frontmatter + Markdown:

```markdown
---
name: Skill Name
version: 1.0
author: community
description: What this does
tags: [tag1, tag2]
requires_selection: true  # Optional: needs selected request
requires: findings        # Optional: needs existing findings
---

# Title

## Objective
[Goal of this agent/skill]

## Instructions / Test steps
[Detailed methodology]

## MCP Tools to use
[List of Burp AI Switch tools]
```

**Required sections:**
1. `# Title` - Name of the agent/skill
2. `## Objective` or `## Instructions` - Clear goal description
3. Step-by-step methodology
4. Tool references (for skills)

## MCP Tools Reference

These tools are available through Burp AI Switch:

### Passive (Read-only)
- `burp_get_current_selection` - Get selected request/response
- `burp_get_proxy_history` - Browse captured traffic
- `burp_list_skills` - List available agents and skills
- `burp_get_skill` - Load skill content
- `burp_list_findings` - List findings with filters
- `burp_get_finding` - Get finding details

### Active (Modify state)
- `burp_create_finding` - Create VULNERABILITY or COVERED finding
- `burp_update_finding` - Update finding content/status
- `burp_delete_finding` - Remove a finding
- `burp_export_findings` - Export to JSON or Markdown
- `burp_import_findings` - Import findings

### HTTP (Send requests)
- `burp_http_request` - Send HTTP request through Burp

## Naming Conventions

- **Directories**: lowercase with hyphens (`sql-injection`, not `SQLInjection`)
- **Skill files**: action-based naming (`detect.md`, `bypass.md`, `exploit.md`)
- **Agent files**: always named `agent.md` in their directory

## Common Tasks

### Adding a New Vulnerability Skill

1. Create directory: `audit/skills/vulnerabilities/{vuln-type}/`
2. Create file: `detect.md` (and optionally `bypass.md`, `exploit.md`)
3. Follow the skill template with YAML frontmatter
4. Include: Objective, Test steps, Payloads, Documentation guidance
5. Reference CWE and OWASP

### Modifying an Agent

1. Edit the `agent.md` file in the appropriate directory
2. Keep the YAML frontmatter up to date
3. Maintain the workflow/routing tables
4. Test with Burp AI Switch

### Adding a New Category

1. Create directory: `audit/skills/TYPE/NEW-CATEGORY/`
2. Add at least `detect.md`
3. Update `audit/agent.md` skills table if needed

## Quality Guidelines

- **Clarity**: Instructions should be unambiguous
- **Accuracy**: Skills should minimize false positives
- **Completeness**: Include all necessary steps
- **Tool awareness**: Reference appropriate MCP tools
- **Scope respect**: Always encourage scope checking before testing

## Testing Changes

1. Configure the prompt repository path in Burp AI Switch settings
2. Click "Refresh" to reload prompts
3. Send a request to AI with relevant context
4. Verify the AI follows updated instructions
5. Check for accurate vulnerability detection

## Finding Types

| Type | Usage |
|------|-------|
| `VULNERABILITY` | Confirmed security flaw |
| `COVERED` | Security control verified as working |

## Finding Status Flow

```
DRAFT → WRITTEN → REVIEWED → EXPORTED
```

- `DRAFT`: Raw finding from audit
- `WRITTEN`: Professionally written by report agent
- `REVIEWED`: Validated by user
- `EXPORTED`: Included in final report
