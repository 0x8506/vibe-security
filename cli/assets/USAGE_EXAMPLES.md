# Vibe Security - Usage Examples

Comprehensive examples for using Vibe Security AI assistant features.

## Table of Contents

1. [Basic Security Scanning](#basic-security-scanning)
2. [Advanced Analysis](#advanced-analysis)
3. [Fix Workflows](#fix-workflows)
4. [CI/CD Integration](#cicd-integration)
5. [Reporting](#reporting)
6. [Language-Specific Examples](#language-specific-examples)

---

## Basic Security Scanning

### Quick Pattern Scan

```bash
# Scan JavaScript files for SQL injection
grep -r "db\.query.*\${" . --include="*.js"

# Scan Python files for command injection
grep -r "os\.system" . --include="*.py"

# Scan PHP files for XSS
grep -r "\$_(GET|POST)" . --include="*.php"

# Scan all files for hardcoded secrets
grep -rE "(api_key|password|secret).*=.*['\"][A-Za-z0-9]{20,}" .
```

### AST-Based Scanning

```bash
# Analyze single file
python3 .claude/skills/vibe-security/scripts/ast_analyzer.py src/app.js

# Analyze entire directory
find src/ -name "*.py" -exec python3 .claude/skills/vibe-security/scripts/ast_analyzer.py {} \;

# Save results to JSON
python3 .claude/skills/vibe-security/scripts/ast_analyzer.py src/ > scan-results.json
```

---

## Advanced Analysis

### Data Flow Analysis

```bash
# Analyze Python file for tainted data
python3 .claude/skills/vibe-security/scripts/dataflow_analyzer.py auth.py

# Expected output shows:
# - Tainted variables (user inputs)
# - Data flow paths
# - Vulnerable sinks where tainted data reaches dangerous operations
```

### CVE & Dependency Scanning

```bash
# Scan all dependencies
python3 .claude/skills/vibe-security/scripts/cve_integration.py .

# Scan specific ecosystem
python3 .claude/skills/vibe-security/scripts/cve_integration.py . --ecosystem npm
python3 .claude/skills/vibe-security/scripts/cve_integration.py . --ecosystem python

# Get JSON output for automation
python3 .claude/skills/vibe-security/scripts/cve_integration.py . --json > cve-report.json
```

### Supply Chain Security

```bash
# Check for typosquatting in package.json
python3 .claude/skills/vibe-security/scripts/cve_integration.py . --ecosystem npm

# Output includes:
# - Known CVE vulnerabilities
# - Typosquatting detection
# - Malicious install scripts
# - Dependency confusion risks
```

---

## Fix Workflows

### Get Fix Suggestions

```bash
# SQL injection fix
python3 .claude/skills/vibe-security/scripts/fix_engine.py \
  --type sql-injection \
  --language javascript \
  --code "db.query(\`SELECT * FROM users WHERE id = \${userId}\`)"

# Output includes:
# ✅ Fixed code: db.query('SELECT * FROM users WHERE id = $1', [userId])
# 📖 Explanation: Use parameterized queries...
# 🧪 Test code: test('should prevent SQL injection', ...)
# 💡 Recommendations: Use ORM, validate inputs...
# 🎯 Confidence: 85%
```

```bash
# XSS fix
python3 .claude/skills/vibe-security/scripts/fix_engine.py \
  --type xss \
  --language javascript \
  --code "element.innerHTML = userInput"

# Command injection fix
python3 .claude/skills/vibe-security/scripts/fix_engine.py \
  --type command-injection \
  --language python \
  --code "os.system(f'ls {user_dir}')"
```

### Apply Fixes with Rollback

```bash
# Step 1: Apply fix (automatically creates backup)
python3 .claude/skills/vibe-security/scripts/autofix_engine.py apply \
  --file src/database.js \
  --line 45 \
  --type sql-injection \
  --original "db.query(\`SELECT * FROM users WHERE id = \${userId}\`)" \
  --fixed "db.query('SELECT * FROM users WHERE id = $1', [userId])"

# Output: ✅ Fix applied, backup created at .vibe-security/backups/...

# Step 2: Test your changes
npm test

# Step 3: If tests fail, rollback
if [ $? -ne 0 ]; then
  python3 .claude/skills/vibe-security/scripts/autofix_engine.py rollback
  echo "❌ Tests failed, changes rolled back"
else
  echo "✅ Tests passed, fix successful"
fi
```

### Batch Apply Fixes

```bash
# Create fixes.json with multiple fixes
cat > fixes.json << 'EOF'
{
  "fixes": [
    {
      "file": "src/auth.js",
      "line": 23,
      "type": "weak-crypto",
      "original": "crypto.createHash('md5')",
      "fixed": "crypto.createHash('sha256')"
    },
    {
      "file": "src/database.js",
      "line": 45,
      "type": "sql-injection",
      "original": "db.query(`SELECT...`)",
      "fixed": "db.query('SELECT...', [id])"
    }
  ]
}
EOF

# Apply all fixes
python3 .claude/skills/vibe-security/scripts/autofix_engine.py batch --file fixes.json

# View fix history
python3 .claude/skills/vibe-security/scripts/autofix_engine.py history

# Rollback all fixes if needed
python3 .claude/skills/vibe-security/scripts/autofix_engine.py rollback-all
```

---

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/security.yml
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
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: "3.10"

      - name: AST Security Analysis
        run: |
          python3 .claude/skills/vibe-security/scripts/ast_analyzer.py src/ \
            --json > ast-results.json

      - name: Data Flow Analysis
        run: |
          python3 .claude/skills/vibe-security/scripts/dataflow_analyzer.py src/ \
            --json > dataflow-results.json

      - name: CVE Scanning
        run: |
          python3 .claude/skills/vibe-security/scripts/cve_integration.py . \
            --json > cve-results.json

      - name: Generate SARIF Report
        run: |
          python3 .claude/skills/vibe-security/scripts/reporter.py \
            ast-results.json \
            --format sarif \
            --output results.sarif

      - name: Upload to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif

      - name: Generate HTML Report
        run: |
          python3 .claude/skills/vibe-security/scripts/reporter.py \
            ast-results.json \
            --format html \
            --output security-report.html

      - name: Upload Report Artifact
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: security-report.html

      - name: Fail on Critical Vulnerabilities
        run: |
          CRITICAL_COUNT=$(jq '.vulnerabilities | map(select(.severity == "critical")) | length' ast-results.json)
          if [ "$CRITICAL_COUNT" -gt 0 ]; then
            echo "❌ Found $CRITICAL_COUNT critical vulnerabilities"
            exit 1
          fi
```

### GitLab CI

```yaml
# .gitlab-ci.yml
security_scan:
  stage: test
  image: python:3.10

  script:
    # AST Analysis
    - python3 .claude/skills/vibe-security/scripts/ast_analyzer.py src/ --json > ast-results.json

    # CVE Scanning
    - python3 .claude/skills/vibe-security/scripts/cve_integration.py . --json > cve-results.json

    # Generate Report
    - python3 .claude/skills/vibe-security/scripts/reporter.py ast-results.json --format html -o security-report.html

    # Fail on critical issues
    - |
      CRITICAL=$(jq '.vulnerabilities | map(select(.severity == "critical")) | length' ast-results.json)
      if [ "$CRITICAL" -gt 0 ]; then
        echo "Found $CRITICAL critical vulnerabilities"
        exit 1
      fi

  artifacts:
    reports:
      sast: ast-results.json
    paths:
      - security-report.html
    expire_in: 1 week
```

### Pre-commit Hook

```bash
# .git/hooks/pre-commit
#!/bin/bash

echo "🔍 Running security scan..."

# Get list of staged files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(js|py|php|go)$')

if [ -z "$STAGED_FILES" ]; then
  echo "✅ No code files to scan"
  exit 0
fi

# Run AST analysis on staged files
for file in $STAGED_FILES; do
  echo "Scanning: $file"
  python3 .claude/skills/vibe-security/scripts/ast_analyzer.py "$file" --json > /tmp/scan-result.json

  # Check for critical vulnerabilities
  CRITICAL=$(jq '.issues | map(select(.severity == "critical")) | length' /tmp/scan-result.json 2>/dev/null || echo "0")

  if [ "$CRITICAL" -gt 0 ]; then
    echo "❌ Critical vulnerability found in $file"
    jq '.issues[] | select(.severity == "critical")' /tmp/scan-result.json
    exit 1
  fi
done

echo "✅ Security scan passed"
exit 0
```

---

## Reporting

### HTML Report with Charts

```bash
# Generate comprehensive HTML report
python3 .claude/skills/vibe-security/scripts/reporter.py scan-results.json \
  --format html \
  --output security-report.html

# Open in browser
open security-report.html
```

### SARIF for GitHub Code Scanning

```bash
# Generate SARIF format
python3 .claude/skills/vibe-security/scripts/reporter.py scan-results.json \
  --format sarif \
  --output results.sarif

# Upload to GitHub (in CI)
# See GitHub Actions example above
```

### CSV for Analysis

```bash
# Generate CSV for spreadsheet analysis
python3 .claude/skills/vibe-security/scripts/reporter.py scan-results.json \
  --format csv \
  --output vulnerabilities.csv

# Open in Excel/Google Sheets
open vulnerabilities.csv
```

### JSON for Automation

```bash
# Generate JSON for programmatic use
python3 .claude/skills/vibe-security/scripts/reporter.py scan-results.json \
  --format json \
  --output security-report.json

# Parse with jq
jq '.statistics.by_severity' security-report.json
jq '.vulnerabilities[] | select(.severity == "critical")' security-report.json
```

---

## Language-Specific Examples

### JavaScript/TypeScript

```bash
# Scan for common Node.js vulnerabilities
python3 .claude/skills/vibe-security/scripts/ast_analyzer.py src/server.js

# Common issues detected:
# - SQL injection (template literals in queries)
# - XSS (innerHTML, dangerouslySetInnerHTML)
# - Command injection (exec with user input)
# - Weak crypto (MD5, Math.random)
# - Hardcoded secrets

# Get fix for SQL injection
python3 .claude/skills/vibe-security/scripts/fix_engine.py \
  --type sql-injection \
  --language javascript \
  --code "pool.query(\`SELECT * FROM users WHERE email = '\${email}'\`)"
```

### Python

```bash
# Scan Python application
python3 .claude/skills/vibe-security/scripts/ast_analyzer.py app.py

# Data flow analysis for Django/Flask
python3 .claude/skills/vibe-security/scripts/dataflow_analyzer.py views.py

# Common issues:
# - SQL injection (f-strings in queries)
# - Command injection (os.system, subprocess with shell=True)
# - Deserialization (pickle.loads, yaml.load)
# - Path traversal (open with user input)

# Get fix for command injection
python3 .claude/skills/vibe-security/scripts/fix_engine.py \
  --type command-injection \
  --language python \
  --code "os.system(f'ls -la {user_directory}')"
```

### PHP

```bash
# Scan PHP application
grep -r "\$_(GET|POST)" . --include="*.php" | head -20

# Check for SQL injection
grep -r "mysqli_query.*\$" . --include="*.php"

# Check for weak crypto
grep -r "md5(" . --include="*.php"
```

### Go

```bash
# Scan Go files
grep -r "exec.Command.*\+" . --include="*.go"
grep -r "sql.Query.*\+" . --include="*.go"
```

### Infrastructure (Terraform)

```bash
# Scan Terraform files
grep -r "publicly_accessible.*=.*true" . --include="*.tf"
grep -r "ingress.*cidr_blocks.*=.*\[.*0\.0\.0\.0/0" . --include="*.tf"

# Common issues:
# - Public S3 buckets
# - Open security groups (0.0.0.0/0)
# - Unencrypted storage
# - Weak IAM policies
```

### Kubernetes

```bash
# Scan Kubernetes manifests
grep -r "privileged:.*true" . --include="*.yaml"
grep -r "hostNetwork:.*true" . --include="*.yaml"
grep -r "runAsUser:.*0" . --include="*.yaml"

# Common issues:
# - Privileged containers
# - Host network access
# - Running as root
# - Missing resource limits
```

---

## Complete Workflow Example

Here's a complete security audit workflow:

```bash
#!/bin/bash
# complete-security-audit.sh

echo "🔒 Starting Vibe Security Complete Audit..."
echo "============================================="

# 1. AST Analysis
echo "📊 Step 1/6: AST-based semantic analysis..."
python3 .claude/skills/vibe-security/scripts/ast_analyzer.py src/ --json > ast-results.json
echo "✅ AST analysis complete"

# 2. Data Flow Analysis
echo "🌊 Step 2/6: Data flow analysis..."
python3 .claude/skills/vibe-security/scripts/dataflow_analyzer.py src/ --json > dataflow-results.json
echo "✅ Data flow analysis complete"

# 3. CVE Scanning
echo "🔍 Step 3/6: CVE & dependency scanning..."
python3 .claude/skills/vibe-security/scripts/cve_integration.py . --json > cve-results.json
echo "✅ CVE scanning complete"

# 4. Get Fix Suggestions
echo "💡 Step 4/6: Generating fix suggestions..."
CRITICAL_VULNS=$(jq -r '.vulnerabilities[] | select(.severity == "critical") | .type' ast-results.json | head -5)
for vuln_type in $CRITICAL_VULNS; do
  echo "  - Generating fix for: $vuln_type"
  # Generate fixes (would need actual code snippets in real scenario)
done
echo "✅ Fix suggestions generated"

# 5. Generate Reports
echo "📄 Step 5/6: Generating reports..."
python3 .claude/skills/vibe-security/scripts/reporter.py ast-results.json --format html -o security-report.html
python3 .claude/skills/vibe-security/scripts/reporter.py ast-results.json --format sarif -o results.sarif
python3 .claude/skills/vibe-security/scripts/reporter.py ast-results.json --format csv -o vulnerabilities.csv
echo "✅ Reports generated"

# 6. Summary
echo "📊 Step 6/6: Security Audit Summary"
echo "============================================="
TOTAL=$(jq '.vulnerabilities | length' ast-results.json)
CRITICAL=$(jq '.vulnerabilities | map(select(.severity == "critical")) | length' ast-results.json)
HIGH=$(jq '.vulnerabilities | map(select(.severity == "high")) | length' ast-results.json)
MEDIUM=$(jq '.vulnerabilities | map(select(.severity == "medium")) | length' ast-results.json)
LOW=$(jq '.vulnerabilities | map(select(.severity == "low")) | length' ast-results.json)

echo "Total Vulnerabilities: $TOTAL"
echo "  🔴 Critical: $CRITICAL"
echo "  🟠 High: $HIGH"
echo "  🟡 Medium: $MEDIUM"
echo "  🟢 Low: $LOW"
echo ""
echo "📁 Reports saved:"
echo "  - security-report.html (Open in browser)"
echo "  - results.sarif (Upload to GitHub)"
echo "  - vulnerabilities.csv (Open in Excel)"
echo ""

# Exit with error if critical vulnerabilities found
if [ "$CRITICAL" -gt 0 ]; then
  echo "❌ FAILED: Critical vulnerabilities must be fixed before deployment"
  exit 1
else
  echo "✅ PASSED: No critical vulnerabilities found"
  exit 0
fi
```

Run it:

```bash
chmod +x complete-security-audit.sh
./complete-security-audit.sh
```

---

## Tips & Best Practices

1. **Run scans regularly**: Before every commit or PR
2. **Use data flow analysis**: For high-value authentication/authorization code
3. **Enable auto-fix cautiously**: Always test after automated fixes
4. **Keep CVE database updated**: Run dependency scans weekly
5. **Generate reports**: Track security posture over time
6. **Map to compliance**: Align with your regulatory requirements
7. **Use rollback fearlessly**: Don't be afraid to experiment with fixes
8. **Scan IaC before deployment**: Catch cloud misconfigurations early
9. **Check supply chain**: Audit all new dependencies
10. **Continuous learning**: Review false positives to improve detection

---

For more information, see:

- [ENHANCEMENTS.md](ENHANCEMENTS.md) - Detailed feature documentation
- [README.md](README.md) - Main documentation
- [SECURITY_CHECKLIST.md](../../SECURITY_CHECKLIST.md) - Security best practices
