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
├── taxonomy.yaml               <- SOURCE OF TRUTH (vuln/obs types, CWE, OWASP)
├── audit/
│   ├── agent.md                <- Agent for security auditing (entry point)
│   └── skills/
│       ├── vulnerabilities/
│       │   ├── injection/              <- CATEGORY
│       │   │   ├── xss/detect.md
│       │   │   ├── sql/detect.md
│       │   │   ├── nosql/detect.md
│       │   │   ├── command/detect.md
│       │   │   ├── ssti/detect.md
│       │   │   └── crlf/detect.md
│       │   ├── access-control/         <- CATEGORY
│       │   │   ├── idor/detect.md
│       │   │   └── authz-bypass/detect.md
│       │   ├── authentication/         <- CATEGORY
│       │   │   ├── jwt/detect.md
│       │   │   └── oauth/detect.md
│       │   └── [standalone]/           <- No category
│       │       ├── ssrf/detect.md
│       │       ├── path-traversal/detect.md
│       │       ├── xxe/detect.md
│       │       ├── csrf/detect.md
│       │       ├── cors/detect.md
│       │       ├── open-redirect/detect.md
│       │       ├── request-smuggling/detect.md
│       │       ├── deserialization/detect.md
│       │       └── file-upload/detect.md
│       └── observations/
│           ├── version-disclosure/detect.md
│           ├── missing-security-header/detect.md
│           ├── verbose-error/detect.md
│           ├── debug-mode/detect.md
│           ├── directory-listing/detect.md
│           ├── sensitive-data-exposure/detect.md
│           ├── insecure-cookie/detect.md
│           └── cors-misconfiguration/detect.md
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
| `taxonomy.yaml` | Source of truth for vulnerability/observation types |
| `audit/agent.md` | Security testing agent (entry point) - methodical vulnerability research |
| `report/agent.md` | Report orchestrator - coordinates finding + summary agents |
| `report/finding/agent.md` | Writes professional finding descriptions |
| `report/exec-summary/agent.md` | Generates executive summaries |

## Skills Hierarchy

Skills are organized with optional categories:

```
skills/
├── vulnerabilities/
│   ├── {category}/     # Optional grouping (injection, access-control, authentication)
│   │   └── {id}/
│   │       └── detect.md
│   └── {id}/           # Standalone (no category)
│       └── detect.md
└── observations/
    └── {id}/
        └── detect.md
```

### Categorized Skills

| Category | Skills |
|----------|--------|
| `injection` | xss, sql, nosql, command, ssti, crlf |
| `access-control` | idor, authz-bypass |
| `authentication` | jwt, oauth |

### Standalone Skills

| Type | Skills |
|------|--------|
| Vulnerabilities | ssrf, path-traversal, xxe, csrf, cors, open-redirect, request-smuggling, deserialization, file-upload |
| Observations | version-disclosure, missing-security-header, verbose-error, debug-mode, directory-listing, sensitive-data-exposure, insecure-cookie, cors-misconfiguration |

## Taxonomy (Source of Truth)

The `taxonomy.yaml` file is the single source of truth for vulnerability and observation types:

```yaml
# taxonomy.yaml
vulnerabilities:
  - id: xss
    name: Cross-Site Scripting
    category: injection         # NEW: optional category field
    description: Detect XSS vulnerabilities
    cwe: CWE-79
    owasp: A03:2021
    references:
      - https://owasp.org/xss
    remediation_template: |
      Encode output. Use CSP.

observations:
  - id: version-disclosure
    name: Version Disclosure
    description: Server version exposed in headers
```

**Path derivation:**
- `vulnerabilities/injection/xss/detect.md` → id: `xss`, category: `injection`
- `vulnerabilities/ssrf/detect.md` → id: `ssrf`, category: `null`

## File Format

### Agents (with YAML frontmatter)

```markdown
---
name: Agent Name
version: 1.0
author: community
description: What this does
---

# Title

## Objective
[Goal of this agent]

## Workflow
[Routing and delegation logic]
```

### Skills (pure Markdown, no frontmatter)

Skills use pure markdown - metadata comes from taxonomy.yaml:

```markdown
# XSS Detection

## Objective
Detect Cross-Site Scripting vulnerabilities...

## Instructions
1. Identify injection points
2. Test with payloads
3. Document findings

## MCP Tools to use
- `burp_get_current_selection`
- `burp_create_finding`
```

**Required sections:**
1. `# Title` - Name of the skill
2. `## Objective` or `## Instructions` - Clear goal description
3. Step-by-step methodology
4. Tool references

## MCP Tools Reference

These tools are available through Burp AI Switch:

### Passive (Read-only)
- `burp_get_current_selection` - Get selected request/response
- `burp_get_proxy_history` - Browse captured traffic
- `burp_list_agents` - List available agents
- `burp_get_agent` - Load an agent by ID
- `burp_list_skills` - List available detection skills
- `burp_get_skill` - Load a detection skill by path
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

- **Directories**: lowercase with hyphens (`access-control`, not `AccessControl`)
- **Skill IDs**: short names (`sql`, not `sql-injection`)
- **Skill files**: action-based naming (`detect.md`, `bypass.md`, `exploit.md`)
- **Agent files**: always named `agent.md` in their directory

## Common Tasks

### Adding a New Categorized Vulnerability Skill

1. Add entry to `taxonomy.yaml` with `category` field:
   ```yaml
   - id: new-vuln
     name: New Vulnerability Type
     category: injection       # or access-control, authentication
     description: Description for this vuln type
     cwe: CWE-XXX
     owasp: A0X:2021
   ```
2. Create directory: `audit/skills/vulnerabilities/{category}/{id}/`
3. Create file: `detect.md` (pure markdown, no frontmatter)
4. Include: Objective, Test steps, Payloads, Documentation guidance

### Adding a New Standalone Vulnerability Skill

1. Add entry to `taxonomy.yaml` WITHOUT `category` field:
   ```yaml
   - id: new-standalone
     name: New Standalone Vuln
     description: Description
     cwe: CWE-XXX
   ```
2. Create directory: `audit/skills/vulnerabilities/{id}/`
3. Create file: `detect.md`

### Adding a New Observation Skill

1. Add entry to `taxonomy.yaml` under `observations:`
2. Create directory: `audit/skills/observations/{id}/`
3. Create file: `detect.md` (pure markdown)

### Modifying an Agent

1. Edit the `agent.md` file in the appropriate directory
2. Keep the YAML frontmatter up to date
3. Maintain the workflow/routing tables
4. Test with Burp AI Switch

### Adding to Taxonomy

Edit `taxonomy.yaml` to add new types. Fields:
- `id` (required): Unique identifier matching directory name
- `name` (required): Display name
- `description` (required): Short description
- `category` (optional): Category for grouping (injection, access-control, authentication)
- `cwe`: CWE reference
- `owasp`: OWASP Top 10 reference
- `references`: List of URLs
- `remediation_template`: Multi-line remediation guidance

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
| `VULNERABILITY` | Confirmed security flaw (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL) |
| `COVERED` | Security control verified as working |
| `OBSERVATION` | Informational note (not a vulnerability, not a control) |

### vuln_type Parameter

Always specify `vuln_type` when creating findings:
- Matches taxonomy IDs: `xss`, `sql`, `idor`, `version-disclosure`, etc.
- Enables deduplication by host+type
- Provides CWE/OWASP references automatically

## Finding Status Flow

```
DRAFT → WRITTEN → REVIEWED → EXPORTED
```

- `DRAFT`: Raw finding from audit
- `WRITTEN`: Professionally written by report agent
- `REVIEWED`: Validated by user
- `EXPORTED`: Included in final report
