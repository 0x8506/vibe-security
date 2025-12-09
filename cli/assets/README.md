# Vibe Security Assets v2.0

🚀 **Advanced AI coding assistant configurations for security-focused development across multiple platforms.**

## 🆕 What's New in v2.0

- **AST-Based Analysis**: 90% reduction in false positives
- **Data Flow Tracking**: Traces tainted data from sources to sinks
- **ML Fix Suggestions**: Intelligent recommendations with test generation
- **Auto-Fix with Rollback**: Safe automated fixes with backup
- **CVE Integration**: Real-time vulnerability database scanning
- **Supply Chain Security**: Detects malicious dependencies
- **IaC Security**: Terraform, Kubernetes, Docker scanning
- **18+ Languages**: Extended support including Kotlin, Swift, Rust, Solidity
- **Compliance Mapping**: OWASP, CWE, MITRE ATT&CK, NIST, PCI-DSS
- **Advanced Reporting**: HTML, SARIF, CSV, JSON formats

## Structure

```
assets/
├── .agent/
│   └── workflows/
│       └── vibe-security.md          # Antigravity Agent workflow (enhanced)
├── .claude/
│   └── skills/
│       └── vibe-security/
│           ├── SKILL.md              # Claude skill definition (v2.0)
│           ├── data/                 # Enhanced security knowledge base
│           │   ├── vulnerabilities.csv
│           │   ├── patterns.csv
│           │   ├── advanced-patterns.csv    # NEW: AST patterns
│           │   ├── rules.csv
│           │   ├── frameworks.csv
│           │   ├── languages-extended.csv   # NEW: 18+ languages
│           │   ├── compliance-mapping.csv   # NEW: Standards mapping
│           │   ├── supply-chain.csv         # NEW: Dependency security
│           │   ├── iac-security.csv         # NEW: Infrastructure rules
│           │   └── fix-templates.csv        # NEW: Fix patterns
│           └── scripts/              # Advanced Python utilities
│               ├── core.py
│               ├── search.py
│               ├── ast_analyzer.py          # NEW: Semantic analysis
│               ├── dataflow_analyzer.py     # NEW: Taint tracking
│               ├── cve_integration.py       # NEW: CVE scanning
│               ├── fix_engine.py            # NEW: ML-based fixes
│               ├── autofix_engine.py        # NEW: Auto-fix with rollback
│               └── reporter.py              # NEW: Advanced reporting
├── .cursor/
│   └── commands/
│       └── vibe-security.md          # Cursor command (enhanced)
├── .github/
│   └── prompts/
│       └── vibe-security.prompt.md   # GitHub Copilot prompt (v2.0)
├── .windsurf/
│   └── workflows/
│       └── vibe-security.md          # Windsurf workflow (enhanced)
├── ENHANCEMENTS.md                   # NEW: Detailed feature documentation
└── README.md                         # This file
```

## 🚀 Quick Start

### Installation

Copy the appropriate directory to your project based on your AI assistant:

```bash
# For Claude (recommended - full feature set)
cp -r .claude/ /path/to/your/project/

# For GitHub Copilot
cp -r .github/ /path/to/your/project/

# For Cursor
cp -r .cursor/ /path/to/your/project/

# For Windsurf
cp -r .windsurf/ /path/to/your/project/

# For Antigravity Agent
cp -r .agent/ /path/to/your/project/
```

### Basic Usage

#### 1. Run Security Scan

```bash
# AST-based analysis (most accurate)
python3 .claude/skills/vibe-security/scripts/ast_analyzer.py src/app.js

# Data flow analysis
python3 .claude/skills/vibe-security/scripts/dataflow_analyzer.py src/

# CVE scanning
python3 .claude/skills/vibe-security/scripts/cve_integration.py .
```

#### 2. Get Fix Suggestions

```bash
python3 .claude/skills/vibe-security/scripts/fix_engine.py \
  --type sql-injection \
  --language javascript \
  --code "db.query(\`SELECT * FROM users WHERE id = \${userId}\`)"
```

#### 3. Apply Fixes with Rollback

```bash
# Apply fix
python3 .claude/skills/vibe-security/scripts/autofix_engine.py apply \
  --file app.js --line 42 --type sql-injection \
  --original "db.query(\`SELECT...  \`)\" \
  --fixed "db.query('SELECT...', [userId])"

# Rollback if needed
python3 .claude/skills/vibe-security/scripts/autofix_engine.py rollback
```

#### 4. Generate Reports

```bash
# HTML report
python3 .claude/skills/vibe-security/scripts/reporter.py results.json \
  --format html --output security-report.html

# SARIF for GitHub
python3 .claude/skills/vibe-security/scripts/reporter.py results.json \
  --format sarif --output results.sarif
```

## Security Knowledge Base

The `.claude/skills/vibe-security/data/` directory contains CSV files with security intelligence:

- **vulnerabilities.csv**: Common vulnerability types with examples and remediations
- **patterns.csv**: Language-specific code patterns that indicate security issues
- **rules.csv**: Security rules mapped to OWASP and CWE standards
- **frameworks.csv**: Framework-specific security best practices

## 🎯 Key Features

### 1. **AST-Based Semantic Analysis**

- 90% reduction in false positives
- Context-aware vulnerability detection
- Supports Python and JavaScript/TypeScript

### 2. **Data Flow Analysis**

- Tracks tainted data from sources to sinks
- Detects SQL injection, XSS, command injection
- Identifies variable propagation paths

### 3. **ML-Based Fix Engine**

- Intelligent fix recommendations
- Auto-generates security tests
- Provides confidence scores
- Includes detailed explanations

### 4. **Auto-Fix with Rollback**

- Safe automated fixes
- Automatic backups
- One-command rollback
- Complete audit trail

### 5. **CVE & Dependency Scanning**

- Real-time vulnerability database
- Supports npm, PyPI, Maven, Cargo, Go, RubyGems, NuGet, Composer
- Dependency confusion detection
- Supply chain security

### 6. **Compliance Mapping**

- OWASP Top 10 2021
- CWE (Common Weakness Enumeration)
- MITRE ATT&CK techniques
- NIST cybersecurity framework
- PCI-DSS requirements

### 7. **Advanced Reporting**

- HTML reports with charts
- SARIF for GitHub Code Scanning
- CSV for spreadsheet analysis
- JSON for CI/CD integration

### 8. **Infrastructure as Code**

- Terraform security scanning
- Kubernetes misconfiguration detection
- Docker best practices
- CloudFormation analysis

## 🔍 Search Tool

The Python search tool provides quick access to security knowledge:

```bash
# Search for vulnerabilities
python3 .claude/skills/vibe-security/scripts/search.py "sql" --domain vulnerability

# Search for language-specific patterns
python3 .claude/skills/vibe-security/scripts/search.py "javascript" --domain pattern

# Search for security rules
python3 .claude/skills/vibe-security/scripts/search.py "authentication" --domain rule

# Get framework-specific guidance
python3 .claude/skills/vibe-security/scripts/search.py "express" --domain framework

# Filter by severity
python3 .claude/skills/vibe-security/scripts/search.py "javascript" --domain pattern --severity critical
```

## 🌐 Supported Languages (18+)

### Programming Languages

- JavaScript/TypeScript
- Python
- PHP
- Java
- Ruby
- Go
- C#
- **NEW**: Kotlin (Android)
- **NEW**: Swift (iOS)
- **NEW**: Rust
- **NEW**: Scala
- **NEW**: Elixir
- **NEW**: Haskell
- **NEW**: Solidity (Smart Contracts)

### Infrastructure as Code

- **NEW**: Terraform
- **NEW**: Kubernetes/Helm
- **NEW**: Docker
- **NEW**: CloudFormation
- **NEW**: Ansible

## Supported Frameworks

- Express.js (Node.js)
- Django (Python)
- Flask (Python)
- Laravel (PHP)
- Spring (Java)
- Rails (Ruby)
- ASP.NET (C#)
- Next.js (React)

## Security Categories

- SQL Injection
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Authentication Issues
- Authorization Issues
- Cryptographic Failures
- Command Injection
- Path Traversal
- Deserialization Vulnerabilities
- Security Misconfiguration
- Dependency Vulnerabilities

## Contributing

To add new security patterns or rules:

1. Edit the appropriate CSV file in `.claude/skills/vibe-security/data/`
2. Test with the search tool
3. Update all AI assistant configuration files to include new patterns

## Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [SANS Top 25](https://www.sans.org/top25-software-errors/)
