---
name: vibe-security
description: "Security intelligence for code analysis with vulnerability detection across multiple languages and frameworks"
agent: "agent"
---

# vibe-security

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

## How to Use This Prompt

When user requests security work (scan, analyze, fix, audit, check, review vulnerabilities), follow this workflow:

### Step 1: Analyze Security Context

Extract key information from user request:

- **Language**: JavaScript, Python, Java, PHP, etc.
- **Framework**: Express, Django, Spring, Laravel, etc.
- **Vulnerability type**: SQL injection, XSS, CSRF, authentication, etc.
- **Scope**: Single file, directory, or full project

### Step 2: Run Security Scans

Use grep or specialized tools to scan for vulnerabilities:

```bash
# JavaScript/Node.js vulnerabilities
grep -r "db\\.query.*\${" . --include="*.js"        # SQL injection
grep -r "\\.innerHTML\\s*=" . --include="*.js"      # XSS
grep -r "eval(" . --include="*.js"                  # Code injection

# Python vulnerabilities
grep -r "execute.*f\"" . --include="*.py"           # SQL injection
grep -r "os\\.system" . --include="*.py"            # Command injection
grep -r "pickle\\.loads" . --include="*.py"         # Deserialization

# PHP vulnerabilities
grep -r "mysqli_query.*\\$" . --include="*.php"     # SQL injection
grep -r "\$_(GET|POST)" . --include="*.php"         # Unsanitized input
```

### Step 3: Analyze Vulnerabilities by Severity

Prioritize fixes based on severity:

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

### Step 4: Apply Security Fixes

Systematically fix vulnerabilities:

1. **Critical first** - Address immediate security risks
2. **Validate inputs** - Add validation and sanitization
3. **Secure outputs** - Add proper escaping/encoding
4. **Fix authentication** - Strengthen passwords, add MFA
5. **Update cryptography** - Use modern algorithms
6. **Test thoroughly** - Verify fixes work correctly
7. **Re-scan** - Confirm all issues are resolved

---

## Security Patterns by Language

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

**User request:** "Scan my Node.js API for security issues"

**Agent should:**

```bash
# 1. Scan for SQL injection
grep -r "db\\.query.*\${" . --include="*.js"

# 2. Scan for XSS vulnerabilities
grep -r "\\.innerHTML\\s*=" . --include="*.js"

# 3. Scan for command injection
grep -r "exec(.*\${" . --include="*.js"

# 4. Check for weak crypto
grep -r "createHash.*md5" . --include="*.js"

# 5. Check for hardcoded secrets
grep -r "API_KEY\\s*=\\s*['\"]" . --include="*.js"

# 6. Analyze results and prioritize by severity

# 7. Apply fixes systematically:
#    - Replace string concatenation with parameterized queries
#    - Use textContent instead of innerHTML
#    - Use execFile instead of exec
#    - Replace MD5 with SHA-256
#    - Move secrets to environment variables

# 8. Re-scan to verify all issues resolved
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

## Integration with CI/CD

Add security scanning to your pipeline:

**GitHub Actions:**

```yaml
- name: Security Scan
  run: |
    grep -r "db\\.query.*\${" . --include="*.js" && exit 1 || true
```

**GitLab CI:**

```yaml
security_scan:
  script:
    - bash security-scan.sh
  allow_failure: false
```

---

## Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [SANS Top 25](https://www.sans.org/top25-software-errors/)
- [Security Checklist](../../SECURITY_CHECKLIST.md)
