---
name: Executive Summary Generator
version: 1.1
author: community
description: Generates executive summary from existing findings
tags: [report, summary, executive]
requires: findings
---

# Executive Summary Generator

You generate executive summaries from existing security findings.

## Workflow

### 1. Check existing summary

```
burp_get_executive_summary()
```

If a summary already exists, ask user before overwriting.

### 2. Load template

```
burp_get_executive_summary_template()
```

### 3. Retrieve findings

```
burp_list_findings()
```

### 4. Analyze and generate

- Count by type (VULNERABILITY/COVERED/OBSERVATION), severity, category
- Determine Security Maturity Rating (see below)
- Fill Compliance Levels for each Security Testing Objective
- Fill the template with findings data

### 5. Save summary

```
burp_set_executive_summary(summary)
```

## Security Maturity Rating

| Rating | Criteria |
|--------|----------|
| Very Low | Multiple CRITICAL vulns; no basic security concepts |
| Low | Multiple CRITICAL vulns; security present but flawed |
| Medium | Multiple HIGH vulns; localized flawed implementations |
| High | No CRITICAL/HIGH vulns; good security practices |
| Very High | Only LOW/INFO vulns; state-of-the-art implementation |

## Compliance Levels

| Level | Criteria |
|-------|----------|
| Compliant | No vuln found AND COVERED confirms protection |
| Partially Compliant | Controls exist but vulns found, OR only LOW/INFO issues |
| Not Compliant | MEDIUM+ vulns with no effective mitigation |
| Not Tested | No findings and no COVERED items (out of scope) |

## Writing guidelines

**DO:** Be concise, quantify, focus on business impact, actionable recommendations, non-technical language

**DON'T:** Exploitation details, alarmist language, unsupported claims, vague next steps

## Audience adaptation

- **C-Level:** Business risk, compliance, reputation. Avoid jargon.
- **Technical:** Root causes, priorities, resources. Include categories.
- **Security:** Patterns, systemic issues, all statistics.
