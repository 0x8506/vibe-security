---
description: Analyze and fix security vulnerabilities
auto_execution_mode: 3
---

# Vibe Security - Security Intelligence

Comprehensive security scanner and code analyzer for identifying vulnerabilities across multiple languages and frameworks.

## Prerequisites

Check if Node.js is installed:

```bash
node --version
```

If Node.js is not installed, install it based on user's OS:

**macOS:**

```bash
brew install node
```

**Ubuntu/Debian:**

```bash
sudo apt update && sudo apt install nodejs npm
```

**Windows:**

```powershell
winget install OpenJS.NodeJS
```

---

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

---

## How to Use This Workflow

When user requests security work (scan, analyze, fix, audit, check, review vulnerabilities), follow this workflow:

### Step 1: Analyze Security Context

Extract key information from user request:

- **Language**: JavaScript, Python, Java, PHP, etc.
- **Framework**: Express, Django, Spring, Laravel, etc.
- **Vulnerability type**: SQL injection, XSS, CSRF, authentication, etc.
- **Scope**: Single file, directory, or full project

### Step 2: Run Security Scans

**Advanced Analysis:**

```bash
# AST-based semantic analysis
python3 .agent/scripts/ast_analyzer.py <file>

# Data flow analysis
python3 .agent/scripts/dataflow_analyzer.py <file>

# CVE & dependency scanning
python3 .agent/scripts/cve_integration.py .

# Supply chain security
python3 .agent/scripts/cve_integration.py . --ecosystem npm
```

**CLI Scanning:**

```bash
# Scan current directory
npx vibe-security scan

# Scan specific file
npx vibe-security scan --file path/to/file.js

# Scan with specific rules
npx vibe-security scan --rules sql-injection,xss,auth

# Infrastructure scanning
grep -r "publicly_accessible.*=.*true" . --include="*.tf"
grep -r "privileged:.*true" . --include="*.yaml"
```

### Step 3: Analyze Vulnerabilities

Review scan results by severity:

- **Critical**: Immediate security risk (SQL injection, RCE, auth bypass)
- **High**: Significant vulnerability (XSS, CSRF, insecure crypto)
- **Medium**: Security weakness (weak validation, info disclosure)
- **Low**: Best practice violation (missing headers, weak passwords)

### Step 4: Get Fix Suggestions

**ML-Based Recommendations:**

```bash
# Get intelligent fix suggestions
python3 .agent/scripts/fix_engine.py \
  --type sql-injection \
  --language javascript \
  --code "db.query(\`SELECT * FROM users WHERE id = \${userId}\`)"
```

### Step 5: Apply Fixes with Rollback

**Automated Fix Engine:**

```bash
# Apply fix with backup
python3 .agent/scripts/autofix_engine.py apply \
  --file app.js --line 45 --type sql-injection \
  --original "db.query(\`SELECT...\`)" \
  --fixed "db.query('SELECT...', [userId])"

# Batch apply fixes
python3 .agent/scripts/autofix_engine.py batch --file fixes.json

# Rollback if needed
python3 .agent/scripts/autofix_engine.py rollback
```

**Manual Fixes:**

1. **Critical first** - Fix critical vulnerabilities immediately
2. **Validate inputs** - Add input validation and sanitization
3. **Secure outputs** - Add output encoding/escaping
4. **Test fixes** - Verify fixes don't break functionality
5. **Re-scan** - Run security scan again to confirm fixes

### Step 6: Generate Reports

**Multiple Formats:**

```bash
# HTML with charts and statistics
python3 .agent/scripts/reporter.py results.json --format html -o report.html

# SARIF for CI/CD integration
python3 .agent/scripts/reporter.py results.json --format sarif -o results.sarif

# JSON for automation
python3 .agent/scripts/reporter.py results.json --format json -o report.json
```

---

## Security Domains

### Available Security Checks

| Domain           | Checks For                          | Common Issues                                       |
| ---------------- | ----------------------------------- | --------------------------------------------------- |
| `injection`      | SQL, NoSQL, Command, LDAP injection | Unsanitized queries, string concatenation           |
| `xss`            | Cross-Site Scripting                | Unescaped output, innerHTML usage                   |
| `auth`           | Authentication weaknesses           | Weak passwords, missing MFA, insecure sessions      |
| `authz`          | Authorization issues                | Missing access controls, privilege escalation       |
| `crypto`         | Cryptographic failures              | Weak algorithms, hardcoded secrets, insecure random |
| `sensitive-data` | Data exposure                       | Logging secrets, exposing PII                       |
| `security-misc`  | Misconfiguration                    | CORS, CSP, headers, error handling                  |
| `dependencies`   | Vulnerable packages                 | Outdated/vulnerable npm/pip packages                |

---

## Example Workflow

**User request:** "Scan my Express API for security issues"

**AI should:**

```bash
# 1. Check if Vibe Security is installed
npx vibe-security --version

# 2. Run comprehensive security scan
npx vibe-security scan

# 3. If vulnerabilities found, analyze by severity
# Critical: SQL injection in user.controller.js line 45
# High: XSS vulnerability in comment.controller.js line 23
# Medium: Missing rate limiting on /api/login

# 4. Fix critical issues first
# - Replace string concatenation with parameterized queries
# - Add input validation with validator library
# - Sanitize output with proper encoding

# 5. Fix high severity issues
# - Escape user input before rendering
# - Use textContent instead of innerHTML
# - Implement CSP headers

# 6. Fix medium severity issues
# - Add express-rate-limit middleware
# - Implement account lockout
# - Add security headers with helmet

# 7. Re-scan to verify fixes
npx vibe-security scan --verify
```

---

## Security Rules by Language

### JavaScript/Node.js

```javascript
// ✅ Secure: Parameterized query
const user = await db.query("SELECT * FROM users WHERE id = $1", [userId]);

// ❌ Vulnerable: SQL injection
const user = await db.query(`SELECT * FROM users WHERE id = ${userId}`);

// ✅ Secure: Escape output
element.textContent = userInput;

// ❌ Vulnerable: XSS
element.innerHTML = userInput;
```

### Python

```python
# ✅ Secure: Parameterized query
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# ❌ Vulnerable: SQL injection
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# ✅ Secure: Hash passwords
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# ❌ Vulnerable: Plain text password
user.password = password
```

### PHP

```php
// ✅ Secure: Prepared statement
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$userId]);

// ❌ Vulnerable: SQL injection
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = $userId");

// ✅ Secure: Escape output
echo htmlspecialchars($userInput, ENT_QUOTES, 'UTF-8');

// ❌ Vulnerable: XSS
echo $userInput;
```

---

## Tips for Better Security

1. **Scan regularly** - Run security scans before every commit
2. **Fix by severity** - Address critical vulnerabilities first
3. **Validate all inputs** - Never trust user input
4. **Encode all outputs** - Escape data before rendering
5. **Use security libraries** - Don't roll your own crypto
6. **Keep dependencies updated** - Patch known vulnerabilities
7. **Implement defense in depth** - Multiple layers of security
8. **Log security events** - Monitor for suspicious activity

---

## Integration with CI/CD

Add Vibe Security to your CI/CD pipeline:

**GitHub Actions:**

```yaml
- name: Security Scan
  run: npx vibe-security scan --fail-on critical
```

**GitLab CI:**

```yaml
security:
  script:
    - npx vibe-security scan --fail-on critical
```

---

## Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [Security Checklist](../../SECURITY_CHECKLIST.md)
