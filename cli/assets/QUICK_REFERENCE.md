# 🚀 Vibe Security v2.0 - Quick Reference Card

## 📥 Installation

```bash
# Copy to your project
cp -r .claude/ /path/to/your/project/
```

## 🔍 Common Commands

### Security Scanning

```bash
# AST analysis (most accurate)
python3 .claude/skills/vibe-security/scripts/ast_analyzer.py <file>

# Data flow analysis
python3 .claude/skills/vibe-security/scripts/dataflow_analyzer.py <file>

# CVE scanning
python3 .claude/skills/vibe-security/scripts/cve_integration.py .

# Quick grep patterns
grep -r "db\.query.*\${" . --include="*.js"              # SQL injection
grep -r "\.innerHTML\s*=" . --include="*.js"             # XSS
grep -r "os\.system" . --include="*.py"                  # Command injection
grep -r "publicly_accessible.*=.*true" . --include="*.tf" # Terraform
```

### Fix Suggestions

```bash
# Get ML-based fix
python3 .claude/skills/vibe-security/scripts/fix_engine.py \
  --type <vulnerability-type> \
  --language <language> \
  --code "<vulnerable-code>"
```

### Auto-Fix

```bash
# Apply fix with backup
python3 .claude/skills/vibe-security/scripts/autofix_engine.py apply \
  --file <file> --line <line> --type <type> \
  --original "<old-code>" --fixed "<new-code>"

# Rollback
python3 .claude/skills/vibe-security/scripts/autofix_engine.py rollback

# History
python3 .claude/skills/vibe-security/scripts/autofix_engine.py history
```

### Reporting

```bash
# HTML report
python3 .claude/skills/vibe-security/scripts/reporter.py results.json \
  --format html -o report.html

# SARIF (GitHub)
python3 .claude/skills/vibe-security/scripts/reporter.py results.json \
  --format sarif -o results.sarif

# CSV
python3 .claude/skills/vibe-security/scripts/reporter.py results.json \
  --format csv -o vulns.csv
```

## 🎯 Vulnerability Types

| Type              | Severity | Example                                               |
| ----------------- | -------- | ----------------------------------------------------- |
| sql-injection     | Critical | `db.query(\`SELECT \* FROM users WHERE id = ${id}\`)` |
| xss               | High     | `element.innerHTML = userInput`                       |
| command-injection | Critical | `exec(\`ls ${userDir}\`)`                             |
| weak-crypto       | High     | `crypto.createHash('md5')`                            |
| hardcoded-secret  | Critical | `const API_KEY = 'sk-1234'`                           |
| path-traversal    | High     | `fs.readFile(userPath)`                               |
| csrf              | High     | Missing CSRF tokens                                   |
| deserialization   | Critical | `pickle.loads(user_data)`                             |
| ssrf              | High     | `fetch(\`http://${userUrl}\`)`                        |

## 🌐 Supported Languages (18+)

**Programming**: JavaScript, TypeScript, Python, PHP, Java, Go, Ruby, C#, Kotlin, Swift, Rust, Scala, Elixir, Solidity

**Infrastructure**: Terraform, Kubernetes, Docker, CloudFormation, Ansible

## 📋 Compliance Standards

- **OWASP Top 10 2021**
- **CWE** (Common Weakness Enumeration)
- **MITRE ATT&CK**
- **NIST** Cybersecurity Framework
- **PCI-DSS**

## 🔗 CI/CD Integration

### GitHub Actions

```yaml
- name: Security Scan
  run: |
    python3 .claude/skills/vibe-security/scripts/ast_analyzer.py src/ > results.json
    python3 .claude/skills/vibe-security/scripts/reporter.py results.json --format sarif -o results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit
python3 .claude/skills/vibe-security/scripts/ast_analyzer.py <changed-files>
```

## 📊 Report Formats

| Format | Use Case                   | Command Flag     |
| ------ | -------------------------- | ---------------- |
| HTML   | Human-readable with charts | `--format html`  |
| SARIF  | GitHub Code Scanning       | `--format sarif` |
| CSV    | Spreadsheet analysis       | `--format csv`   |
| JSON   | Automation/CI/CD           | `--format json`  |

## 🎓 Learning Resources

- `README.md` - Main documentation
- `ENHANCEMENTS.md` - Detailed features
- `USAGE_EXAMPLES.md` - Comprehensive examples
- `IMPLEMENTATION_SUMMARY.md` - What's new

## 💡 Quick Tips

1. Use AST analysis for accuracy (90% fewer false positives)
2. Enable data flow for critical auth/authz code
3. Always test after auto-fix
4. Run CVE scans weekly
5. Generate reports for tracking
6. Use rollback fearlessly
7. Scan IaC before deployment
8. Check supply chain for new deps

## 🆘 Common Issues

**Q: Script not found?**
A: Ensure you're in the project root or use full path

**Q: Rollback not working?**
A: Check `.vibe-security/backups/` for backup files

**Q: False positives?**
A: Use AST analysis instead of grep patterns

**Q: Slow scans?**
A: Scan specific files/dirs instead of entire project

## 📞 Support

- Documentation: See `README.md`
- Examples: See `USAGE_EXAMPLES.md`
- Issues: GitHub Issues
- Community: Share custom rules

---

**Vibe Security v2.0** - Security intelligence for every developer! 🔒✨
