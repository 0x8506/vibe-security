# Vibe Security Assets

AI coding assistant configurations for security-focused development across multiple platforms.

## Structure

```
assets/
├── .agent/
│   └── workflows/
│       └── vibe-security.md          # Antigravity Agent workflow
├── .claude/
│   └── skills/
│       └── vibe-security/
│           ├── SKILL.md              # Claude skill definition
│           ├── data/                 # Security knowledge base
│           │   ├── vulnerabilities.csv
│           │   ├── patterns.csv
│           │   ├── rules.csv
│           │   └── frameworks.csv
│           └── scripts/              # Python utilities
│               ├── core.py
│               └── search.py
├── .cursor/
│   └── commands/
│       └── vibe-security.md          # Cursor command
├── .github/
│   └── prompts/
│       └── vibe-security.prompt.md   # GitHub Copilot prompt
└── .windsurf/
    └── workflows/
        └── vibe-security.md          # Windsurf workflow
```

## Usage

### For Antigravity Agent

Copy `.agent/workflows/` to your project's `.agent/` directory.

### For Claude

Copy `.claude/skills/` to your project's `.claude/` directory, then use:

```bash
python3 .claude/skills/vibe-security/scripts/search.py "sql" --domain vulnerability
```

### For Cursor

Copy `.cursor/commands/` to your project's `.cursor/` directory.

### For GitHub Copilot

Copy `.github/prompts/` to your project's `.github/` directory.

### For Windsurf

Copy `.windsurf/workflows/` to your project's `.windsurf/` directory.

## Security Knowledge Base

The `.claude/skills/vibe-security/data/` directory contains CSV files with security intelligence:

- **vulnerabilities.csv**: Common vulnerability types with examples and remediations
- **patterns.csv**: Language-specific code patterns that indicate security issues
- **rules.csv**: Security rules mapped to OWASP and CWE standards
- **frameworks.csv**: Framework-specific security best practices

## Search Tool

The Python search tool provides quick access to security knowledge:

```bash
# Search for vulnerabilities
python3 scripts/search.py "sql" --domain vulnerability

# Search for language-specific patterns
python3 scripts/search.py "javascript" --domain pattern

# Search for security rules
python3 scripts/search.py "authentication" --domain rule

# Get framework-specific guidance
python3 scripts/search.py "express" --domain framework

# Filter by severity
python3 scripts/search.py "javascript" --domain pattern --severity critical
```

## Supported Languages

- JavaScript/TypeScript
- Python
- PHP
- Java
- Ruby
- Go
- C#

## Supported Frameworks

- Express.js (Node.js)
- Django (Python)
- Flask (Python)
- Laravel (PHP)
- Spring (Java)
- Rails (Ruby)
- ASP.NET (C#)
- Next.js (React)

## Security Categories

- SQL Injection
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Authentication Issues
- Authorization Issues
- Cryptographic Failures
- Command Injection
- Path Traversal
- Deserialization Vulnerabilities
- Security Misconfiguration
- Dependency Vulnerabilities

## Contributing

To add new security patterns or rules:

1. Edit the appropriate CSV file in `.claude/skills/vibe-security/data/`
2. Test with the search tool
3. Update all AI assistant configuration files to include new patterns

## Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [SANS Top 25](https://www.sans.org/top25-software-errors/)
