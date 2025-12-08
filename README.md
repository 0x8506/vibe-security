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
# Install security guidelines for AI assistant
vibesec init --ai claude    # For Claude
vibesec init --ai cursor    # For Cursor
vibesec init --ai windsurf  # For Windsurf
vibesec init --ai copilot   # For GitHub Copilot
vibesec init --ai antigravity # For Antigravity
vibesec init --ai all       # For all assistants

# Version Management
vibesec versions              # List available versions
vibesec update                # Update to latest version
vibesec init --version v1.0.0 # Install specific version
```

## Usage

### Claude Code

The skill activates automatically when you request security scanning or code review. Just chat naturally:

```
Scan my code for security vulnerabilities
Fix the SQL injection issues in my project
Check my authentication implementation for security issues
```

### Cursor / Windsurf / Antigravity

Use the slash command to invoke the skill:

```
/vibe-security Scan my code for security vulnerabilities
/vibe-security Fix the SQL injection issues in my project
/vibe-security Check my authentication implementation for security issues
```

### GitHub Copilot

In VS Code with Copilot, type `/` in chat to see available prompts, then select vibe-security:

```
/vibe-security Scan my code for security vulnerabilities
/vibe-security Fix the SQL injection issues in my project
/vibe-security Check my authentication implementation for security issues
```

### Example Prompts

- **Scan my code for security vulnerabilities**
- **Fix hardcoded secrets in my project**
- **Check for SQL injection vulnerabilities**
- **Review my authentication implementation**
- **Find and fix XSS vulnerabilities**
- **Verify security best practices**
- **Install security guidelines for Claude**

## Recommended AI Models

### For Best Security Analysis

We recommend using these AI models with Vibe Security for optimal security vulnerability detection and code fixing:

#### **Claude Opus 4.5** (Recommended)

- Most advanced model for comprehensive security analysis
- Superior reasoning capabilities for complex vulnerability detection
- Exceptional at identifying subtle security flaws and attack vectors
- Best for critical security audits, enterprise codebases, and production deployments
- Provides the most thorough security remediation strategies

#### **Claude Sonnet 4.5**

- Excellent balance of speed and security analysis depth
- Great at understanding security context and identifying vulnerabilities
- Provides safe remediation strategies with detailed explanations
- Ideal for daily development and most security workflows

#### **Claude Opus 4**

- Powerful for complex security audits and enterprise codebases
- Deep reasoning capabilities for advanced vulnerability analysis
- Best for critical security reviews and compliance requirements
- Recommended for production deployments and sensitive applications

#### **GPT-4o**

- Fast and efficient for security-aware code generation
- Good alternative with quick response times
- Excellent for CI/CD integration and automated scanning
- Cost-effective for large-scale projects

#### **Claude Sonnet 4**

- Faster alternative for quick security scans
- Good balance of speed and accuracy
- Suitable for rapid iteration during development

#### **o1-preview**

- Specialized for complex security architecture reviews
- Advanced reasoning for intricate vulnerability chains
- Best for security research and deep code audits

#### **GPT-4o-mini**

- Quick checks and preliminary scans
- Most cost-effective option
- Good for learning and educational use cases

### Model Selection Guide

| Use Case                       | Best Model        | Alternative       |
| ------------------------------ | ----------------- | ----------------- |
| **Quick Security Scan**        | Claude Sonnet 4.5 | GPT-4o            |
| **Deep Security Audit**        | Claude Opus 4.5   | Claude Opus 4     |
| **Auto-Fix Vulnerabilities**   | Claude Opus 4.5   | Claude Sonnet 4.5 |
| **Enterprise Compliance**      | Claude Opus 4.5   | Claude Opus 4     |
| **Critical Production Review** | Claude Opus 4.5   | o1-preview        |
| **Learning Security Concepts** | Claude Sonnet 4.5 | GPT-4o            |

### Performance Tips

- **For large codebases (1000+ files):** Use Claude Sonnet 4 or GPT-4o for faster scans
- **For critical security reviews:** Use Claude Opus 4.5 with `--strict` mode for maximum thoroughness
- **For production deployments:** Claude Opus 4.5 provides unmatched security depth
- **For daily development:** Claude Sonnet 4.5 provides the best speed/quality balance
- **For cost optimization:** Use GPT-4o-mini for quick checks, escalate to full models for fixes

### From Source

If you've downloaded or cloned the source code:

```bash
# Navigate to the cli directory
cd vibe-security/cli

# Install dependencies
npm install
# Or using bun
bun install

# Build the project
npm run build
# Or using bun
bun run build

# Link globally (optional)
npm link
# Or using bun
bun link

# Now you can use vibesec command globally
vibesec --help
```

**Next Step:** After installation, follow the [Quick Start](#quick-start) guide above to install security guidelines for your AI assistant and start scanning.

<!-- ### Scan Command

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
``` -->

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

<!-- ## CI/CD Integration

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
``` -->

<!-- ## Quick Fix Examples

### SQL Injection

**Before:** `db.query(\`SELECT _ FROM users WHERE id = '${userId}'\`)`
**After:**`db.query('SELECT _ FROM users WHERE id = ?', [userId])`

### XSS Prevention

**Before:** `element.innerHTML = userInput`
**After:** `element.innerHTML = DOMPurify.sanitize(userInput)`

### Weak Cryptography

**Before:** `crypto.createHash('md5').update(password).digest('hex')`
**After:** `await bcrypt.hash(password, 12)` -->

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
