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

## How to Use This Command

When user requests security work (scan, analyze, fix, audit, check, review vulnerabilities), follow this workflow:

### Step 1: Analyze Security Context

Extract key information from user request:

- **Language**: JavaScript, Python, Java, PHP, etc.
- **Framework**: Express, Django, Spring, Laravel, etc.
- **Vulnerability type**: SQL injection, XSS, CSRF, authentication, etc.
- **Scope**: Single file, directory, or full project

### Step 2: Run Security Scans

Scan for common vulnerabilities:

```bash
# Scan current directory
grep -r "db.query.*\${" . --include="*.js"
grep -r "\.innerHTML\s*=" . --include="*.js"
grep -r "eval(" . --include="*.js"

# Scan Python files
grep -r "execute.*f\"" . --include="*.py"
grep -r "os.system(" . --include="*.py"

# Scan PHP files
grep -r "mysqli_query.*\$" . --include="*.php"
grep -r "\$_(GET|POST|REQUEST)" . --include="*.php"
```

### Step 3: Analyze Vulnerabilities by Severity

**Critical** (Fix immediately):

- SQL Injection - Unsanitized database queries
- Remote Code Execution - eval(), exec() with user input
- Authentication Bypass - Missing or broken auth
- Hardcoded Secrets - API keys, passwords in code

**High** (Fix soon):

- XSS (Cross-Site Scripting) - Unescaped output
- CSRF - Missing CSRF tokens
- Insecure Cryptography - MD5, weak keys
- Authorization Issues - Missing access controls

**Medium** (Fix in sprint):

- Missing Input Validation
- Information Disclosure
- Weak Password Policy
- Missing Security Headers

**Low** (Technical debt):

- Code Quality Issues
- Best Practice Violations

---

## Quick Security Checks

### JavaScript/Node.js

```bash
# Check for SQL injection
grep -r "db\\.query.*\${" . --include="*.js"
grep -r "db\\.query.*\\+" . --include="*.js"

# Check for XSS
grep -r "\\.innerHTML\\s*=" . --include="*.js"
grep -r "dangerouslySetInnerHTML" . --include="*.jsx"

# Check for command injection
grep -r "exec(.*\${" . --include="*.js"

# Check for weak crypto
grep -r "createHash.*md5" . --include="*.js"
grep -r "Math\\.random" . --include="*.js"
```

### Python

```bash
# Check for SQL injection
grep -r "execute.*f\"" . --include="*.py"
grep -r "execute.*%" . --include="*.py"

# Check for command injection
grep -r "os\\.system" . --include="*.py"
grep -r "subprocess.*shell=True" . --include="*.py"

# Check for deserialization
grep -r "pickle\\.loads" . --include="*.py"

# Check for weak crypto
grep -r "hashlib\\.md5" . --include="*.py"
```

### PHP

```bash
# Check for SQL injection
grep -r "mysqli_query.*\\$" . --include="*.php"
grep -r "\\$conn->query.*\\$" . --include="*.php"

# Check for XSS
grep -r "echo.*\\$_(GET|POST)" . --include="*.php"

# Check for deserialization
grep -r "unserialize" . --include="*.php"

# Check for weak crypto
grep -r "md5(" . --include="*.php"
```

---

## Security Fixes by Category

### SQL Injection

**JavaScript:**

```javascript
// ✅ Secure
const user = await db.query("SELECT * FROM users WHERE id = $1", [userId]);

// ❌ Vulnerable
const user = await db.query(`SELECT * FROM users WHERE id = ${userId}`);
```

**Python:**

```python
# ✅ Secure
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# ❌ Vulnerable
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
```

### XSS Prevention

**JavaScript:**

```javascript
// ✅ Secure
element.textContent = userInput;
const clean = DOMPurify.sanitize(htmlContent);

// ❌ Vulnerable
element.innerHTML = userInput;
```

### Authentication

**Node.js:**

```javascript
// ✅ Secure
const bcrypt = require("bcrypt");
const hash = await bcrypt.hash(password, 12);

// ❌ Vulnerable
user.password = password;
```

---

## Tips for Secure Development

1. **Validate all inputs** - Never trust user input
2. **Encode all outputs** - Escape before rendering
3. **Use parameterized queries** - Never concatenate SQL
4. **Hash passwords properly** - bcrypt, Argon2, scrypt
5. **Implement MFA** - Add second factor
6. **Use HTTPS** - Encrypt data in transit
7. **Keep dependencies updated** - Patch vulnerabilities
8. **Follow least privilege** - Minimal permissions
9. **Log security events** - Monitor for attacks
10. **Regular security audits** - Scan before release

---

## Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [Security Checklist](../../../SECURITY_CHECKLIST.md)
