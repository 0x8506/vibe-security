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

**Advanced Analysis (Recommended):**

```bash
# AST-based semantic analysis (most accurate)
python3 .github/scripts/ast_analyzer.py <file>

# Data flow analysis (tracks tainted data)
python3 .github/scripts/dataflow_analyzer.py <file>

# CVE/dependency scanning
python3 .github/scripts/cve_integration.py .

# IaC security scanning
python3 .github/scripts/iac_scanner.py .
```

**Quick Pattern Scanning:**

```bash
# JavaScript/Node.js vulnerabilities
grep -r "db\\.query.*\${" . --include="*.js"        # SQL injection
grep -r "\\.innerHTML\\s*=" . --include="*.js"      # XSS
grep -r "eval(" . --include="*.js"                  # Code injection
grep -r "dangerouslySetInnerHTML" . --include="*.jsx" # React XSS

# Python vulnerabilities
grep -r "execute.*f\"" . --include="*.py"           # SQL injection
grep -r "os\\.system" . --include="*.py"            # Command injection
grep -r "pickle\\.loads" . --include="*.py"         # Deserialization
grep -r "yaml\\.load\\(" . --include="*.py"         # Unsafe YAML

# PHP vulnerabilities
grep -r "mysqli_query.*\\$" . --include="*.php"     # SQL injection
grep -r "\$_(GET|POST)" . --include="*.php"         # Unsanitized input

# Go vulnerabilities
grep -r "exec\\.Command.*\\+" . --include="*.go"    # Command injection
grep -r "sql\\.Query.*\\+" . --include="*.go"       # SQL injection

# Infrastructure (Terraform, K8s, Docker)
grep -r "publicly_accessible.*=.*true" . --include="*.tf"  # Public resources
grep -r "privileged:.*true" . --include="*.yaml"    # Privileged containers
grep -r "USER root" . --include="Dockerfile"        # Root user
```

### Step 3: Analyze Vulnerabilities by Severity

**Use ML-Based Fix Suggestions:**

```bash
# Get intelligent fix recommendations
python3 .github/scripts/fix_engine.py \
  --type sql-injection \
  --language javascript \
  --code "db.query(\`SELECT * FROM users WHERE id = \${id}\`)"
```

**Prioritize by Severity & Compliance:**

**Critical** (Fix immediately - OWASP A03, PCI-DSS 6.5.1):

- SQL Injection (CWE-89)
- Remote Code Execution (CWE-94)
- Authentication Bypass (CWE-287)
- Hardcoded Secrets (CWE-798)
- Deserialization (CWE-502)

**High** (Fix soon - OWASP A02, A07):

- XSS (CWE-79)
- CSRF (CWE-352)
- Insecure Cryptography (CWE-327)
- Authorization Issues (CWE-285)
- Command Injection (CWE-78)

**Medium** (Fix in sprint):

- Missing Input Validation
- Information Disclosure (CWE-200)
- Weak Password Policy
- Missing Security Headers
- Path Traversal (CWE-22)

**Low** (Technical debt):

- Code Quality Issues
- Best Practice Violations

### Step 4: Apply Security Fixes

**Automated Fixes with Rollback:**

```bash
# Apply fix with automatic backup
python3 .github/scripts/autofix_engine.py apply \
  --file app.js \
  --line 42 \
  --type sql-injection \
  --original "db.query(\`SELECT * FROM users WHERE id = \${id}\`)" \
  --fixed "db.query('SELECT * FROM users WHERE id = $1', [id])"

# Test the fix
npm test

# Rollback if tests fail
python3 .github/scripts/autofix_engine.py rollback --fix-id 0
```

**Systematic Manual Fixes:**

1. **Critical first** - Address immediate security risks
2. **Validate inputs** - Add validation and sanitization
3. **Secure outputs** - Add proper escaping/encoding
4. **Fix authentication** - Strengthen passwords, add MFA
5. **Update cryptography** - Use modern algorithms
6. **Test thoroughly** - Verify fixes work correctly
7. **Re-scan** - Confirm all issues are resolved

### Step 5: Generate Security Reports

**Multiple Report Formats:**

```bash
# HTML report with charts and statistics
python3 .github/scripts/reporter.py scan-results.json --format html -o security-report.html

# SARIF for GitHub Code Scanning
python3 .github/scripts/reporter.py scan-results.json --format sarif -o results.sarif

# CSV for spreadsheet analysis
python3 .github/scripts/reporter.py scan-results.json --format csv -o vulnerabilities.csv

# JSON for CI/CD integration
python3 .github/scripts/reporter.py scan-results.json --format json -o report.json
```

---

## Advanced Features

### Data Flow Analysis

Track tainted data from user input to dangerous operations:

```bash
# Identify data flow vulnerabilities
python3 .github/scripts/dataflow_analyzer.py src/
```

### Supply Chain Security

Detect malicious dependencies and typosquatting:

```bash
# Scan for malicious packages
python3 .github/scripts/cve_integration.py . --ecosystem npm
```

### Compliance Mapping

Map vulnerabilities to standards (OWASP, CWE, MITRE ATT&CK, NIST, PCI-DSS):

```bash
# View compliance mappings
cat .github/data/compliance-mapping.csv | grep sql-injection
```

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
