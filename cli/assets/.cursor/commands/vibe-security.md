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

**Advanced Analysis:**

```bash
# AST-based semantic analysis
python3 .cursor/scripts/ast_analyzer.py <file>

# Data flow tracking
python3 .cursor/scripts/dataflow_analyzer.py <file>

# CVE scanning
python3 .cursor/scripts/cve_integration.py .
```

**Quick Pattern Scanning:**

```bash
# JavaScript/Node.js
grep -r "db.query.*\${" . --include="*.js"           # SQL injection
grep -r "\.innerHTML\s*=" . --include="*.js"        # XSS
grep -r "eval(" . --include="*.js"                   # Code injection
grep -r "dangerouslySetInnerHTML" . --include="*.jsx" # React XSS

# Python
grep -r "execute.*f\"" . --include="*.py"           # SQL injection
grep -r "os.system(" . --include="*.py"              # Command injection
grep -r "pickle.loads" . --include="*.py"            # Deserialization

# PHP
grep -r "mysqli_query.*\$" . --include="*.php"       # SQL injection
grep -r "\$_(GET|POST|REQUEST)" . --include="*.php" # Unsanitized input

# Infrastructure
grep -r "publicly_accessible.*=.*true" . --include="*.tf"  # Terraform
grep -r "privileged:.*true" . --include="*.yaml"    # Kubernetes
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

### Step 4: Get Fix Suggestions

```bash
# ML-based fix recommendations
python3 .cursor/scripts/fix_engine.py \
  --type sql-injection \
  --language javascript \
  --code "db.query(\`SELECT * FROM users WHERE id = \${id}\`)"
```

### Step 5: Apply Fixes with Rollback

```bash
# Auto-fix with backup
python3 .cursor/scripts/autofix_engine.py apply \
  --file app.js --line 42 --type sql-injection \
  --original "db.query(\`SELECT...\`)" \
  --fixed "db.query('SELECT...', [id])"

# Rollback if needed
python3 .cursor/scripts/autofix_engine.py rollback
```

### Step 6: Generate Reports

```bash
# HTML report
python3 .cursor/scripts/reporter.py results.json --format html -o report.html

# SARIF for Code Scanning
python3 .cursor/scripts/reporter.py results.json --format sarif -o results.sarif
```

---

## Advanced Features

### Compliance Mapping

- OWASP Top 10 2021
- CWE IDs
- MITRE ATT&CK
- NIST Controls
- PCI-DSS

### Supported Languages (18+)

- JavaScript, TypeScript, Python, PHP, Java, Go, Ruby, C#
- Kotlin, Swift, Rust, Scala, Elixir, Solidity
- Terraform, Kubernetes, Docker, CloudFormation

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
