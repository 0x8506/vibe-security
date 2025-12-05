# Vibe Security

An AI-powered security scanner and fixer for Vibe Coder that finds, verifies, and automatically fixes security vulnerabilities in your code.

<p align="center">
  <img src="https://img.shields.io/badge/Security-First-red?style=for-the-badge" alt="Security First">
  <img src="https://img.shields.io/badge/OWASP-Top%2010-orange?style=for-the-badge" alt="OWASP Top 10">
  <img src="https://img.shields.io/badge/CWE-Compliant-blue?style=for-the-badge" alt="CWE Compliant">
</p>

## Overview

Vibe Security is a comprehensive security analysis tool designed specifically for AI-assisted development with Vibe Coder. It automatically scans your codebase for security vulnerabilities, provides detailed explanations, and can automatically fix many common security issues.

## Features

### 🔍 **Security Scanner**

- **30+ Security Rules** covering OWASP Top 10
- **Multi-Language Support** - JavaScript, TypeScript, Python, Java, PHP, C#, Ruby, Go, Rust
- **Real-time Analysis** - Scan your entire codebase in seconds
- **Detailed Reports** - Comprehensive vulnerability reports with severity ratings

### 🛡️ **Vulnerability Detection**

- SQL Injection, XSS, Command Injection, Path Traversal
- CSRF, Weak Cryptography, Hardcoded Secrets
- Authentication/Authorization Issues, SSRF, XXE
- And many more security vulnerabilities

### 🔧 **Auto-Fix**

- Automatically fix common security issues
- Safe, tested remediation strategies
- Preserves functionality while improving security

### ✅ **Verification**

- Security posture verification
- Compliance reporting
- Best practices assessment

### 🤖 **AI Integration**

- Security guidelines for Claude, Cursor, Windsurf, Copilot, Antigravity
- Security-first code generation
- Automated security reviews

## Installation

### Using npm (Recommended)

```bash
# Install globally
npm install -g vibe-security

# Or using bun
bun install -g vibe-security
```

### Quick Start

```bash
# Scan your project
vibesec scan

# Scan and auto-fix issues
vibesec scan --fix

# Verify security posture
vibesec verify

# Install security guidelines for AI assistant
vibesec init --ai claude    # For Claude
vibesec init --ai cursor    # For Cursor
vibesec init --ai windsurf  # For Windsurf
vibesec init --ai copilot   # For GitHub Copilot
vibesec init --ai antigravity # For Antigravity
vibesec init --ai all       # For all assistants
```

## Usage

### Scan Command

```bash
# Scan current directory
vibesec scan

# Scan specific path
vibesec scan --path /path/to/project

# Auto-fix issues
vibesec scan --fix

# Filter by severity
vibesec scan --severity critical high

# Filter by category
vibesec scan --category injection authentication

# Exclude directories
vibesec scan --exclude node_modules dist build

# JSON output for CI/CD
vibesec scan --format json
```

### Verify Command

```bash
# Run security verification
vibesec verify

# Strict mode (fail on any issues)
vibesec verify --strict

# Set severity threshold
vibesec verify --threshold critical
```

### Example Output

```
🔒 Vibe Security Scanner
Scanning: /Users/yourname/project

✓ Scanned 245 files in 1234ms

Security Issues Found:

  CRITICAL  3
  HIGH      12
  MEDIUM    8
  LOW       5

────────────────────────────────────────────────────────────────────────────

src/api/users.ts
  CRITICAL  Line 45
  │ SQL Injection - String Concatenation
  │ SQL query built using string concatenation with user input
  │ const query = `SELECT * FROM users WHERE id = '${userId}'`;
  └ CWE-89 • A03:2021 - Injection
```

### Security Categories Covered

- SQL Injection (CWE-89)
- XSS (CWE-79)
- Command Injection (CWE-78)
- Path Traversal (CWE-22)
- CSRF (CWE-352)
- Weak Cryptography (CWE-327)
- Hardcoded Secrets (CWE-798)
- Authentication Issues (CWE-287)
- Authorization Flaws (CWE-285)
- And 20+ more vulnerability types

## Supported Languages

- JavaScript (.js, .jsx, .mjs, .cjs)
- TypeScript (.ts, .tsx)
- Python (.py)
- Java (.java)
- C# (.cs)
- PHP (.php)
- Ruby (.rb)
- Go (.go)
- Rust (.rs)

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install Vibe Security
        run: npm install -g vibe-security
      - name: Run Security Scan
        run: vibesec scan --format json
```

## Quick Fix Examples

### SQL Injection

**Before:** `db.query(\`SELECT _ FROM users WHERE id = '${userId}'\`)` 
**After:**`db.query('SELECT _ FROM users WHERE id = ?', [userId])`

### XSS Prevention

**Before:** `element.innerHTML = userInput`  
**After:** `element.innerHTML = DOMPurify.sanitize(userInput)`

### Weak Cryptography

**Before:** `crypto.createHash('md5').update(password).digest('hex')`  
**After:** `await bcrypt.hash(password, 12)`

## License

This work is licensed under [CC BY-NC 4.0](https://creativecommons.org/licenses/by-nc/4.0/).

- **Free for personal use** - Use, modify, and share for non-commercial purposes
- **Attribution required** - Credit "Vibe Security" when sharing
- **No commercial use** - Cannot be used for commercial purposes without permission

---

<p align="center">
  Made with ❤️ for secure code generation with Vibe Coder
</p>

<p align="center">
  <strong>🔒 Security First. Always.</strong>
</p>
