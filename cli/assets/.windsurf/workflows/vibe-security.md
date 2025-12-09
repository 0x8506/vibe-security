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

## How to Use This Workflow

When user requests security work (scan, analyze, fix, audit, check, review vulnerabilities), follow this workflow:

### Step 1: Analyze Security Context

Extract key information from user request:

- **Language**: JavaScript, Python, Java, PHP, etc.
- **Framework**: Express, Django, Spring, Laravel, etc.
- **Vulnerability type**: SQL injection, XSS, CSRF, authentication, etc.
- **Scope**: Single file, directory, or full project

### Step 2: Run Security Scans

**Advanced Analysis (Recommended):**

```bash
# AST-based semantic analysis (most accurate)
python3 .windsurf/scripts/ast_analyzer.py <file>

# Data flow analysis (tracks tainted data)
python3 .windsurf/scripts/dataflow_analyzer.py <file>

# CVE & dependency scanning
python3 .windsurf/scripts/cve_integration.py .

# Supply chain security
python3 .windsurf/scripts/cve_integration.py . --ecosystem npm
```

**Quick Scanning:**

```bash
# CLI tool (if available)
npx vibe-security scan
npx vibe-security scan --file path/to/file.js

# Manual pattern scanning
grep -r "db\\.query.*\${" . --include="*.js"    # SQL injection
grep -r "\\.innerHTML\\s*=" . --include="*.js"  # XSS
grep -r "eval(" . --include="*.js"              # Code injection
grep -r "dangerouslySetInnerHTML" . --include="*.jsx" # React XSS

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

**ML-Based Fix Engine:**

```bash
# Get intelligent fix recommendations
python3 .windsurf/scripts/fix_engine.py \
  --type sql-injection \
  --language javascript \
  --code "db.query(\`SELECT * FROM users WHERE id = \${userId}\`)"

# Outputs: Fixed code, explanation, test, recommendations, confidence
```

### Step 5: Apply Fixes with Rollback

**Auto-Fix Engine:**

```bash
# Apply fix with automatic backup
python3 .windsurf/scripts/autofix_engine.py apply \
  --file app.js --line 45 --type sql-injection \
  --original "db.query(\`SELECT...\`)" \
  --fixed "db.query('SELECT * FROM users WHERE id = $1', [userId])"

# Test changes
npm test

# Rollback if needed
python3 .windsurf/scripts/autofix_engine.py rollback

# View history
python3 .windsurf/scripts/autofix_engine.py history
```

**Manual Fixes:**

1. **Critical first** - Fix critical vulnerabilities immediately
2. **Validate inputs** - Add input validation and sanitization
3. **Secure outputs** - Add output encoding/escaping
4. **Test fixes** - Verify fixes don't break functionality
5. **Re-scan** - Run security scan again to confirm fixes

### Step 6: Generate Reports

```bash
# HTML report with charts
python3 .windsurf/scripts/reporter.py results.json --format html -o report.html

# SARIF for GitHub Code Scanning
python3 .windsurf/scripts/reporter.py results.json --format sarif -o results.sarif

# CSV for analysis
python3 .windsurf/scripts/reporter.py results.json --format csv -o vulns.csv
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

## Quick Security Scans

### JavaScript/Node.js

```bash
grep -r "db\\.query.*\${" . --include="*.js"
grep -r "\\.innerHTML\\s*=" . --include="*.js"
grep -r "eval(" . --include="*.js"
grep -r "createHash.*md5" . --include="*.js"
```

### Python

```bash
grep -r "execute.*f\"" . --include="*.py"
grep -r "os\\.system" . --include="*.py"
grep -r "pickle\\.loads" . --include="*.py"
grep -r "hashlib\\.md5" . --include="*.py"
```

### PHP

```bash
grep -r "mysqli_query.*\\$" . --include="*.php"
grep -r "\$_(GET|POST|REQUEST)" . --include="*.php"
grep -r "unserialize" . --include="*.php"
grep -r "md5(" . --include="*.php"
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
