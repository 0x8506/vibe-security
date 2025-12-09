# Vibe Security CLI - User Guide

## Installation

```bash
npm install -g vibe-security
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

> **Note**: If you're not using one of the recommended models above, consider upgrading for better security analysis results. Lower-tier models may miss subtle vulnerabilities or provide less accurate fix suggestions.

## Quick Start

### 1. Scan Your Code

```bash
vibesec scan
```

This will scan your entire project for security vulnerabilities.

### 2. Auto-Fix Issues

```bash
vibesec scan --fix
```

Automatically fix common security issues where possible.

### 3. Verify Security

```bash
vibesec verify
```

Run a comprehensive security verification checklist.

### 4. Install AI Guidelines

```bash
vibesec init --ai claude
```

Install security guidelines for your AI coding assistant.

## Command Reference

### `vibesec scan [options]`

Scan your codebase for security vulnerabilities.

**Options:**

- `-p, --path <path>` - Path to scan (default: current directory)
- `-f, --fix` - Automatically fix issues where possible
- `-s, --severity <levels...>` - Filter by severity: critical, high, medium, low
- `-c, --category <categories...>` - Filter by category
- `-e, --exclude <patterns...>` - Exclude files/directories
- `--format <format>` - Output format: text, json, sarif (default: text)

**Examples:**

```bash
# Scan current directory
vibesec scan

# Scan specific path
vibesec scan --path ./src

# Show only critical and high severity issues
vibesec scan --severity critical high

# Scan and fix
vibesec scan --fix

# Exclude test files
vibesec scan --exclude test tests __tests__ spec

# Output as JSON
vibesec scan --format json > security-report.json
```

### `vibesec verify [options]`

Verify the security posture of your codebase.

**Options:**

- `-p, --path <path>` - Path to verify (default: current directory)
- `--strict` - Fail on any security issues
- `--threshold <level>` - Severity threshold: critical, high, medium, low (default: high)

**Examples:**

```bash
# Run verification
vibesec verify

# Strict mode (exit with error if issues found)
vibesec verify --strict

# Only fail on critical issues
vibesec verify --threshold critical
```

### `vibesec init [options]`

Install security guidelines for AI coding assistants.

**Options:**

- `-a, --ai <type>` - AI assistant type: claude, cursor, windsurf, copilot, antigravity, all
- `-f, --force` - Overwrite existing files

**Examples:**

```bash
# Install for Claude
vibesec init --ai claude

# Install for all AI assistants
vibesec init --ai all

# Force overwrite
vibesec init --ai cursor --force
```

## Security Categories

Vibe Security detects 30+ types of vulnerabilities:

### Critical Severity

- **SQL Injection** (CWE-89) - Unparameterized database queries
- **Command Injection** (CWE-78) - Unvalidated system commands
- **Path Traversal** (CWE-22) - Unvalidated file paths
- **Hardcoded Secrets** (CWE-798) - API keys, passwords in code
- **eval() Usage** (CWE-95) - Code injection via eval
- **Insecure Deserialization** (CWE-502) - Unsafe data deserialization

### High Severity

- **XSS** (CWE-79) - Unescaped user input in HTML
- **Weak Cryptography** (CWE-327) - MD5, SHA1, DES usage
- **Weak Passwords** (CWE-521) - Insufficient password requirements
- **Auth Bypass** (CWE-347) - JWT verification disabled
- **CSRF** (CWE-352) - Missing CSRF protection
- **SSRF** (CWE-918) - User-controlled URLs
- **XXE** (CWE-611) - Unsafe XML parsing
- **Prototype Pollution** (CWE-1321) - Object prototype manipulation

### Medium Severity

- **Insecure Random** (CWE-338) - Math.random() for security
- **CORS Misconfiguration** (CWE-942) - Allow all origins
- **Information Disclosure** (CWE-532) - Logging sensitive data
- **Open Redirect** (CWE-601) - Unvalidated redirects
- **Insecure Protocol** (CWE-319) - HTTP instead of HTTPS
- **Race Conditions** (CWE-367) - TOCTOU vulnerabilities

### Low Severity

- **Missing Security Headers** (CWE-693) - No CSP, HSTS
- **Type Confusion** (CWE-697) - Loose equality (==)
- **Stack Trace Exposure** (CWE-209) - Error details to users

## Code Fix Examples

### Example 1: SQL Injection

**❌ Vulnerable Code:**

```javascript
const query = `SELECT * FROM users WHERE id = '${userId}'`;
const result = await db.query(query);
```

**✅ Fixed Code:**

```javascript
const query = "SELECT * FROM users WHERE id = ?";
const result = await db.query(query, [userId]);
```

### Example 2: XSS Prevention

**❌ Vulnerable Code:**

```javascript
element.innerHTML = userInput;
```

**✅ Fixed Code:**

```javascript
import DOMPurify from "dompurify";
element.innerHTML = DOMPurify.sanitize(userInput);
// Or for plain text:
element.textContent = userInput;
```

### Example 3: Weak Cryptography

**❌ Vulnerable Code:**

```javascript
const hash = crypto.createHash("md5").update(password).digest("hex");
```

**✅ Fixed Code:**

```javascript
const bcrypt = require("bcrypt");
const hash = await bcrypt.hash(password, 12);
```

### Example 4: Hardcoded Secrets

**❌ Vulnerable Code:**

```javascript
const apiKey = "sk-1234567890abcdef";
```

**✅ Fixed Code:**

```javascript
const apiKey = process.env.API_KEY;
if (!apiKey) throw new Error("API_KEY not configured");
```

### Example 5: Command Injection

**❌ Vulnerable Code:**

```javascript
exec(`git clone ${userUrl}`);
```

**✅ Fixed Code:**

```javascript
const { execFile } = require("child_process");
execFile("git", ["clone", userUrl]);
```

### Example 6: Path Traversal

**❌ Vulnerable Code:**

```javascript
fs.readFile(req.query.file, callback);
```

**✅ Fixed Code:**

```javascript
const path = require("path");
const safePath = path.normalize(userPath).replace(/^(\.\.(\/|\\|$))+/, "");
const fullPath = path.join(baseDir, safePath);
if (!fullPath.startsWith(baseDir)) {
  throw new Error("Invalid path");
}
fs.readFile(fullPath, callback);
```

## CI/CD Integration

### GitHub Actions

Create `.github/workflows/security.yml`:

```yaml
name: Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v3

      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: "18"

      - name: Install Vibe Security
        run: npm install -g vibe-security

      - name: Run Security Scan
        run: vibesec scan --format json > security-report.json

      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: security-report.json

      - name: Verify Security (Fail on High/Critical)
        run: vibesec verify --threshold high
```

### GitLab CI

Create `.gitlab-ci.yml`:

```yaml
security_scan:
  stage: test
  image: node:18
  script:
    - npm install -g vibe-security
    - vibesec scan --format json > security-report.json
  artifacts:
    reports:
      security: security-report.json
    when: always
  allow_failure: false
```

## Configuration File

Create `.vibesec.json` in your project root:

```json
{
  "exclude": [
    "node_modules",
    "dist",
    "build",
    "coverage",
    "test",
    "tests",
    "__tests__",
    "*.test.js",
    "*.spec.js"
  ],
  "severity": ["critical", "high", "medium", "low"],
  "categories": [
    "injection",
    "xss",
    "authentication",
    "authorization",
    "cryptography",
    "path-traversal",
    "csrf",
    "cors",
    "information-disclosure"
  ],
  "autoFix": false,
  "failOnSeverity": "high",
  "maxIssues": 0
}
```

## Best Practices

1. **Run Regularly**: Integrate into your development workflow
2. **Start Early**: Catch vulnerabilities during development
3. **Review Fixes**: Always review auto-fixes before committing
4. **Keep Updated**: Update regularly for new security rules
5. **Educate Team**: Use reports to improve security awareness
6. **Monitor CI/CD**: Fail builds on critical/high severity issues
7. **Track Progress**: Monitor reduction in vulnerabilities over time

## AI Assistant Integration

After running `vibesec init --ai <assistant>`, security guidelines are installed:

- **Claude**: `.claude/security-instructions.md`
- **Cursor**: `.cursor/security-rules.md`
- **Windsurf**: `.windsurf/security-rules.md`
- **Copilot**: `.github/copilot-instructions.md`
- **Antigravity**: `.agent/security-rules.md`
- **Shared**: `.shared/security-guidelines.md`

These files provide:

- Security best practices
- Safe vs unsafe code examples
- OWASP Top 10 coverage
- CWE references
- Language-specific guidelines

## Troubleshooting

### Issue: Too many false positives

**Solution**: Use the exclude option or configuration file to exclude test files and third-party code.

```bash
vibesec scan --exclude test tests node_modules
```

### Issue: Need to scan only specific files

**Solution**: Use the path option to scan a specific directory.

```bash
vibesec scan --path ./src/api
```

### Issue: Want to see only critical issues

**Solution**: Filter by severity.

```bash
vibesec scan --severity critical
```

## Support

- Issues: [GitHub Issues](https://github.com/yourusername/vibe-security/issues)
- Documentation: [Wiki](https://github.com/yourusername/vibe-security/wiki)

## OWASP Top 10 Mapping

Vibe Security covers all OWASP Top 10 (2021) risks:

1. **A01:2021 - Broken Access Control**: CSRF, authorization checks
2. **A02:2021 - Cryptographic Failures**: Weak algorithms, hardcoded secrets
3. **A03:2021 - Injection**: SQL, Command, XSS, XXE
4. **A04:2021 - Insecure Design**: Race conditions, security patterns
5. **A05:2021 - Security Misconfiguration**: Headers, CORS, error handling
6. **A06:2021 - Vulnerable Components**: (Use npm audit separately)
7. **A07:2021 - Auth Failures**: Weak passwords, JWT issues
8. **A08:2021 - Data Integrity**: Deserialization, prototype pollution
9. **A09:2021 - Logging Failures**: Sensitive data logging
10. **A10:2021 - SSRF**: User-controlled URLs

---

**🔒 Security First. Always.**
