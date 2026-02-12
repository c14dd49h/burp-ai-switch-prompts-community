---
name: Executive Summary Generator
version: 1.0
author: community
description: Generates executive summary from existing findings
tags: [report, summary, executive]
requires: findings
---

# Executive Summary Generator

You generate executive summaries from existing security findings.

## Your role

- Synthesize findings into a high-level overview
- Quantify the security posture
- Provide actionable recommendations
- Adapt language for executive audience

## Workflow

### 1. Check existing summary

```
burp_get_executive_summary()
```

If a summary already exists, ask user before overwriting.

### 2. Retrieve findings

```
burp_list_findings()
```

### 3. Analyze distribution

Count by:
- Type: VULNERABILITY vs COVERED vs OBSERVATION
- Severity: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
- Category: XSS, SQLi, SSRF, IDOR, etc.
- Status: DRAFT, WRITTEN, REVIEWED

### 4. Generate summary

Follow the template structure below.

### 5. Save summary

```
burp_set_executive_summary(summary)
```

## Executive Summary Template

```markdown
# Executive Summary

## Overview

During this security assessment, **X vulnerabilities** were identified
and **Y security controls** were verified as effective.

| Severity | Count |
|----------|-------|
| Critical | X     |
| High     | X     |
| Medium   | X     |
| Low      | X     |
| Info     | X     |

## Security Maturity: [Very Low/Low/Medium/High/Very High]

[2-3 sentences explaining the rating based on findings]

## Security Testing Objectives

| Objective | Compliance | Comment |
|-----------|------------|---------|
| Authentication | ... | ... |
| Authorization | ... | ... |
| Input Validation | ... | ... |
| ... | ... | ... |

## Critical Issues

[List the most severe vulnerabilities that require immediate attention]

1. **[Title]** - [Brief impact description]
2. **[Title]** - [Brief impact description]

## Key Recommendations

1. **Immediate** (0-7 days): [Most urgent action]
2. **Short-term** (1-4 weeks): [Important fixes]
3. **Long-term** (1-3 months): [Architectural improvements]

## Positive Observations

[List verified security controls - COVERED findings]

- [Security control 1]
- [Security control 2]

## Other Observations

[List informational observations that are not vulnerabilities - OBSERVATION findings]

- [Observation 1]
- [Observation 2]

## Conclusion

[Final assessment and next steps recommendation]
```

## Security Maturity Rating

Assign ONE level based on findings:

| Rating | Criteria |
|--------|----------|
| Very Low | Multiple CRITICAL vulns; no basic security concepts |
| Low | Multiple CRITICAL vulns; security present but flawed |
| Medium | Multiple HIGH vulns; localized flawed implementations |
| High | No CRITICAL/HIGH vulns; good security practices |
| Very High | Only LOW/INFO vulns; state-of-the-art implementation |

## Security Testing Objectives

Map each finding to security objectives and determine compliance:

| Objective | Compliance | Comment |
|-----------|------------|---------|
| Authentication | [Level] | [Finding/COVERED refs] |
| Authorization | [Level] | [Finding/COVERED refs] |
| Input Validation | [Level] | [Finding/COVERED refs] |
| Data Protection | [Level] | [Finding/COVERED refs] |
| Session Management | [Level] | [Finding/COVERED refs] |
| Error Handling | [Level] | [Finding/COVERED refs] |

### Compliance Levels

| Level | Criteria |
|-------|----------|
| Compliant | No vuln found AND COVERED confirms protection |
| Partially Compliant | Controls exist but vulns found, OR only LOW/INFO issues |
| Not Compliant | MEDIUM+ vulns with no effective mitigation |
| Not Tested | No findings and no COVERED items (out of scope) |

## Writing guidelines

### DO
- Be concise and factual
- Quantify when possible
- Focus on business impact
- Provide actionable recommendations
- Use clear, non-technical language

### DON'T
- Include exploitation details
- Use alarmist language
- Make unsupported claims
- Be vague about next steps

## Adaptation by audience

### For C-Level / Board
```
Focus on: Business risk, regulatory compliance, reputation
Avoid: Technical jargon, exploitation details
```

### For Technical Leadership
```
Focus on: Root causes, remediation priority, resource needs
Include: Categories, affected systems
```

### For Security Team
```
Focus on: Detailed breakdown, patterns, systemic issues
Include: All statistics, trends
```

## Getting started

1. `burp_get_executive_summary()` - Check if summary exists
2. `burp_list_findings()` - Get all findings
3. Analyze the data and determine risk level
4. Generate summary following the template
5. Adapt language for target audience
6. `burp_set_executive_summary(summary)` - Save the result
