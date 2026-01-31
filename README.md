# Burp AI Switch - Community Prompts

Community-maintained prompts for [Burp AI Switch](https://github.com/c14dd49h/burp-ai-switch) extension.

## Structure

```
├── agent/                          # Agent system prompts
│   └── default.md
├── skills/                         # Skills organized by TYPE/CATEGORY
│   ├── recon/                      # TYPE: Reconnaissance
│   │   └── fingerprinting/         # CATEGORY
│   │       └── detect.md           # SKILL
│   ├── analysis/                   # TYPE: Analysis
│   │   └── request/                # CATEGORY
│   │       └── analyze.md          # SKILL
│   ├── vulnerabilities/            # TYPE: Vulnerability detection
│   │   ├── sql-injection/          # CATEGORY
│   │   │   └── detect.md           # SKILL
│   │   ├── xss/                    # CATEGORY
│   │   │   └── detect.md           # SKILL
│   │   └── ...                     # Other OWASP categories
│   └── payloads/                   # TYPE: Payload generation
│       └── generation/             # CATEGORY
│           └── generate.md         # SKILL
└── templates/                      # Report templates
    └── default.md
```

**Hierarchy:**
- **TYPE** = Level 1 folder in skills/ (recon, analysis, vulnerabilities, payloads)
- **CATEGORY** = Level 2 folder within each type
- **SKILL** = .md file within a category

## Contributing

1. Fork this repository
2. Add your prompts following the structure above
3. Submit a Pull Request

## License

MIT License
