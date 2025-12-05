---
name: vibe-security
description: "Security intelligence for code analysis. Detects SQL injection, XSS, CSRF, authentication issues, crypto failures, and more. Actions: scan, analyze, fix, audit, check, review, secure, validate, sanitize, protect. Languages: JavaScript, TypeScript, Python, PHP, Java, Go, Ruby. Frameworks: Express, Django, Flask, Laravel, Spring, Rails. Vulnerabilities: SQL injection, XSS, CSRF, authentication bypass, authorization issues, command injection, path traversal, insecure deserialization, weak crypto, sensitive data exposure. Topics: input validation, output encoding, parameterized queries, password hashing, session management, CORS, CSP, security headers, rate limiting, dependency scanning."
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

## How to Use This Skill

When user requests security work (scan, analyze, fix, audit, check, review vulnerabilities), follow this workflow:

### Step 1: Analyze Security Context

Extract key information from user request:

- **Language**: JavaScript, Python, Java, PHP, etc.
- **Framework**: Express, Django, Spring, Laravel, etc.
- **Vulnerability type**: SQL injection, XSS, CSRF, authentication, etc.
- **Scope**: Single file, directory, or full project

### Step 2: Run Security Analysis

Use security scanning scripts to analyze code:

```bash
# Basic security scan
python3 .claude/skills/vibe-security/scripts/scan.py "<file_or_directory>"

# Scan for specific vulnerability types
python3 .claude/skills/vibe-security/scripts/scan.py "<file>" --check sql-injection,xss,auth

# Generate security report
python3 .claude/skills/vibe-security/scripts/report.py "<directory>"
```

### Step 3: Analyze Vulnerabilities by Severity

**Critical** (Fix immediately):

- SQL Injection
- Remote Code Execution
- Authentication Bypass
- Hardcoded Secrets

**High** (Fix soon):

- XSS (Cross-Site Scripting)
- CSRF
- Insecure Cryptography
- Authorization Issues

**Medium** (Fix in sprint):

- Missing Input Validation
- Information Disclosure
- Weak Password Policy
- Missing Security Headers

**Low** (Technical debt):

- Code Quality Issues
- Best Practice Violations
- Performance Concerns

### Step 4: Apply Security Fixes

Follow this systematic approach:

1. **Critical vulnerabilities first**
2. **Add input validation** - Whitelist, type checking, length limits
3. **Secure outputs** - Escape, encode, sanitize
4. **Fix authentication/authorization** - Strong passwords, MFA, RBAC
5. **Update cryptography** - Modern algorithms, secure random
6. **Test thoroughly** - Verify fixes don't break functionality
7. **Re-scan** - Confirm all vulnerabilities are resolved

---

## Security Check Reference

### Available Vulnerability Checks

| Check Type          | Detects                | Example Issues                                      |
| ------------------- | ---------------------- | --------------------------------------------------- |
| `sql-injection`     | SQL/NoSQL injection    | String concatenation in queries, unsanitized input  |
| `xss`               | Cross-Site Scripting   | innerHTML usage, unescaped output, DOM manipulation |
| `command-injection` | OS command injection   | shell=True, exec with user input                    |
| `path-traversal`    | Directory traversal    | Unsanitized file paths, ../.. in paths              |
| `auth-issues`       | Authentication flaws   | Weak passwords, missing MFA, insecure sessions      |
| `authz-issues`      | Authorization flaws    | Missing access controls, IDOR, privilege escalation |
| `crypto-failures`   | Cryptographic issues   | MD5/SHA1 usage, weak keys, insecure random          |
| `sensitive-data`    | Data exposure          | Logging passwords, exposing PII, hardcoded secrets  |
| `deserialization`   | Unsafe deserialization | pickle, eval, unserialize on user input             |
| `security-config`   | Misconfiguration       | CORS, CSP, headers, error messages                  |
| `dependencies`      | Vulnerable packages    | CVEs in npm/pip/composer packages                   |

---

## Language-Specific Security Patterns

### JavaScript/TypeScript

```javascript
// ✅ SECURE: Parameterized query
const user = await db.query("SELECT * FROM users WHERE id = $1", [userId]);

// ❌ VULNERABLE: SQL injection
const user = await db.query(`SELECT * FROM users WHERE id = ${userId}`);

// ✅ SECURE: Escape output
element.textContent = userInput;
const clean = DOMPurify.sanitize(htmlContent);

// ❌ VULNERABLE: XSS
element.innerHTML = userInput;

// ✅ SECURE: Input validation
const email = validator.isEmail(input) ? input : null;

// ❌ VULNERABLE: No validation
const email = req.body.email;
```

### Python

```python
# ✅ SECURE: Parameterized query
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# ❌ VULNERABLE: SQL injection
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# ✅ SECURE: Password hashing
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# ❌ VULNERABLE: Plain text
user.password = password

# ✅ SECURE: Safe subprocess
subprocess.run(['ls', '-la', sanitized_dir])

# ❌ VULNERABLE: Command injection
os.system(f'ls -la {user_dir}')
```

### PHP

```php
// ✅ SECURE: Prepared statement
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$userId]);

// ❌ VULNERABLE: SQL injection
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = $userId");

// ✅ SECURE: Output escaping
echo htmlspecialchars($input, ENT_QUOTES, 'UTF-8');

// ❌ VULNERABLE: XSS
echo $userInput;

// ✅ SECURE: Password hashing
$hash = password_hash($password, PASSWORD_ARGON2ID);

// ❌ VULNERABLE: MD5
$hash = md5($password);
```

---

## Example Workflow

**User request:** "Check my Express app for security vulnerabilities"

**AI should:**

```bash
# 1. Run security scan on the project
python3 .claude/skills/vibe-security/scripts/scan.py "./src" --language javascript

# 2. Analyze results by severity
# Output might show:
# CRITICAL: SQL Injection in src/controllers/user.js:45
# HIGH: XSS in src/views/profile.ejs:12
# MEDIUM: Missing rate limiting on /api/login
# LOW: Console.log contains sensitive data

# 3. Fix critical issues first
# - Review src/controllers/user.js:45
# - Replace string concatenation with parameterized query
# - Add input validation using validator library

# 4. Fix high severity issues
# - Review src/views/profile.ejs:12
# - Use <%- for HTML escaping or DOMPurify for rich content
# - Implement Content Security Policy

# 5. Fix medium severity issues
# - Install express-rate-limit middleware
# - Configure rate limiting on authentication endpoints
# - Add helmet for security headers

# 6. Fix low severity issues
# - Remove or redact sensitive console.log statements
# - Use proper logging library with log levels

# 7. Generate security report
python3 .claude/skills/vibe-security/scripts/report.py "./src"
```

---

## Tips for Secure Development

1. **Validate all inputs** - Use allowlists, not denylists
2. **Encode all outputs** - Context-appropriate escaping
3. **Use parameterized queries** - Never concatenate SQL
4. **Hash passwords properly** - bcrypt, Argon2, scrypt
5. **Implement MFA** - Add second factor authentication
6. **Use HTTPS everywhere** - Encrypt data in transit
7. **Keep dependencies updated** - Patch known vulnerabilities
8. **Follow principle of least privilege** - Minimal necessary permissions
9. **Log security events** - Monitor for attacks
10. **Regular security audits** - Scan before every release

---

## Integration Examples

### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit
python3 .claude/skills/vibe-security/scripts/scan.py "." --fail-on critical
```

### CI/CD Pipeline

**GitHub Actions:**

```yaml
- name: Security Scan
  run: |
    python3 .claude/skills/vibe-security/scripts/scan.py "." --format json
```

**GitLab CI:**

```yaml
security_scan:
  script:
    - python3 .claude/skills/vibe-security/scripts/scan.py "."
```

---

## Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [SANS Top 25](https://www.sans.org/top25-software-errors/)
- [Security Checklist](../../../SECURITY_CHECKLIST.md)
