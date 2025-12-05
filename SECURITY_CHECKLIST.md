# Security Checklist for Vibe Coder

## Pre-Development

- [ ] Security requirements defined
- [ ] Threat model created
- [ ] Security testing plan established
- [ ] AI assistant security guidelines installed (`vibesec init`)

## During Development

### Input Validation

- [ ] All user inputs validated
- [ ] Input type checking implemented
- [ ] Length limits enforced
- [ ] Allowlists used where possible
- [ ] Input sanitization applied

### Authentication

- [ ] Strong password requirements (12+ characters, complexity)
- [ ] Password hashing with bcrypt/Argon2 (12+ rounds)
- [ ] Multi-factor authentication (MFA) supported
- [ ] Session management secure
- [ ] Account lockout after failed attempts
- [ ] Password reset secure

### Authorization

- [ ] Role-based access control (RBAC) implemented
- [ ] Permissions checked on every request
- [ ] Principle of least privilege applied
- [ ] Resource ownership validated
- [ ] Access attempts logged

### Data Protection

- [ ] Sensitive data encrypted at rest
- [ ] Sensitive data encrypted in transit (HTTPS/TLS)
- [ ] PII properly handled
- [ ] No sensitive data in logs
- [ ] No sensitive data in URLs
- [ ] Secure data deletion implemented

### Cryptography

- [ ] AES-256-GCM for symmetric encryption
- [ ] RSA-2048+ for asymmetric encryption
- [ ] SHA-256+ for hashing
- [ ] crypto.randomBytes() for tokens
- [ ] No MD5, SHA1, or DES
- [ ] Keys stored securely

### Database Security

- [ ] Parameterized queries used
- [ ] ORM properly configured
- [ ] No dynamic SQL with user input
- [ ] Database credentials secured
- [ ] Principle of least privilege for DB accounts
- [ ] Database backups encrypted

### API Security

- [ ] Authentication required
- [ ] Authorization enforced
- [ ] Rate limiting implemented
- [ ] Input validation on all endpoints
- [ ] CORS properly configured
- [ ] CSRF protection enabled
- [ ] API versioning in place

### Error Handling

- [ ] Generic error messages for users
- [ ] Detailed errors logged securely
- [ ] No stack traces exposed
- [ ] No sensitive data in errors
- [ ] Proper HTTP status codes used

### Logging & Monitoring

- [ ] Security events logged
- [ ] Authentication attempts logged
- [ ] Authorization failures logged
- [ ] No sensitive data in logs
- [ ] Log tampering prevented
- [ ] Anomaly detection in place

### Dependencies

- [ ] Dependencies up to date
- [ ] No known vulnerabilities (`npm audit`)
- [ ] Unused dependencies removed
- [ ] Lock files used
- [ ] Supply chain security considered

### Code Security

- [ ] No hardcoded secrets
- [ ] No eval() or similar dangerous functions
- [ ] No command injection points
- [ ] No path traversal vulnerabilities
- [ ] No SQL injection points
- [ ] No XSS vulnerabilities
- [ ] Secure random number generation

## Testing

### Security Testing

- [ ] Static analysis (SAST) completed (`vibesec scan`)
- [ ] Dynamic analysis (DAST) planned
- [ ] Dependency scanning completed
- [ ] Security unit tests written
- [ ] Penetration testing scheduled
- [ ] Security code review completed

### Specific Tests

- [ ] SQL injection tests
- [ ] XSS tests
- [ ] CSRF tests
- [ ] Authentication bypass tests
- [ ] Authorization tests
- [ ] Path traversal tests
- [ ] Command injection tests

## Deployment

### Infrastructure

- [ ] HTTPS/TLS enforced (TLS 1.2+)
- [ ] Security headers configured
- [ ] HSTS enabled
- [ ] CSP configured
- [ ] Firewall configured
- [ ] Intrusion detection enabled

### Configuration

- [ ] Debug mode disabled
- [ ] Secrets in environment variables
- [ ] Secret management system used
- [ ] Secure defaults configured
- [ ] Unnecessary services disabled
- [ ] Security updates automated

### Monitoring

- [ ] Security monitoring enabled
- [ ] Log aggregation configured
- [ ] Alerts for security events
- [ ] Incident response plan ready
- [ ] Backup and recovery tested

## Post-Deployment

### Maintenance

- [ ] Regular security scans (`vibesec verify`)
- [ ] Dependency updates scheduled
- [ ] Security patches applied promptly
- [ ] Security logs reviewed regularly
- [ ] Penetration testing scheduled annually
- [ ] Incident response plan updated

### Compliance

- [ ] GDPR compliance (if applicable)
- [ ] HIPAA compliance (if applicable)
- [ ] PCI-DSS compliance (if applicable)
- [ ] SOC 2 compliance (if applicable)
- [ ] ISO 27001 (if applicable)

## OWASP Top 10 Coverage

- [ ] **A01:2021 - Broken Access Control**: Authorization implemented
- [ ] **A02:2021 - Cryptographic Failures**: Strong crypto used
- [ ] **A03:2021 - Injection**: Parameterized queries, input validation
- [ ] **A04:2021 - Insecure Design**: Security patterns followed
- [ ] **A05:2021 - Security Misconfiguration**: Secure defaults
- [ ] **A06:2021 - Vulnerable Components**: Dependencies updated
- [ ] **A07:2021 - Auth Failures**: Strong authentication
- [ ] **A08:2021 - Data Integrity**: Secure serialization
- [ ] **A09:2021 - Logging Failures**: Proper logging
- [ ] **A10:2021 - SSRF**: URL validation

## Quick Commands

```bash
# Scan for vulnerabilities
vibesec scan

# Auto-fix issues
vibesec scan --fix

# Verify security posture
vibesec verify

# Install AI guidelines
vibesec init --ai all
```

## Severity Priorities

### Must Fix Immediately (Critical)

- SQL Injection
- Command Injection
- Path Traversal
- Hardcoded secrets
- Authentication bypass
- Insecure deserialization

### Fix Soon (High)

- XSS vulnerabilities
- Weak cryptography
- CSRF issues
- SSRF vulnerabilities
- XXE vulnerabilities
- Weak password policies

### Fix in Sprint (Medium)

- CORS misconfiguration
- Information disclosure
- Open redirect
- Insecure random
- Race conditions

### Fix When Possible (Low)

- Missing security headers
- Type confusion
- Minor info disclosure

---

Use this checklist throughout your development lifecycle to ensure comprehensive security coverage.

**🔒 Remember: Security is not a feature, it's a requirement.**
