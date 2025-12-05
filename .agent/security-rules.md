# Vibe Security for Antigravity

Security-focused code generation for Antigravity Agent.

## Security Rules

### 1. Input Validation

Validate all inputs before processing:

- Use type checking
- Implement length limits
- Use allowlists when possible
- Sanitize all user input

### 2. Injection Prevention

**SQL Injection:**

```javascript
// ✅ Safe
const user = await pool.query("SELECT * FROM users WHERE id = $1", [userId]);

// ❌ Unsafe
const user = await pool.query(`SELECT * FROM users WHERE id = ${userId}`);
```

**Command Injection:**

```javascript
// ✅ Safe
const { execFile } = require("child_process");
execFile("ls", ["-la", sanitizedDir]);

// ❌ Unsafe
exec(`ls -la ${dir}`);
```

### 3. Authentication

- Use bcrypt or Argon2 for passwords
- Implement MFA
- Enforce strong password policies
- Use secure session management

### 4. Authorization

- Implement RBAC
- Check permissions on every request
- Use principle of least privilege
- Validate resource ownership

### 5. Cryptography

- Use AES-256-GCM
- SHA-256 or better
- No MD5, SHA1, DES
- Use crypto.randomBytes()

### 6. Secrets

- Environment variables only
- Never commit secrets
- Use secret managers
- Rotate regularly

### 7. HTTPS/TLS

- HTTPS only
- TLS 1.2+
- HSTS headers
- Secure cookies

### 8. Headers

```javascript
app.use(helmet());
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
    },
  })
);
```

### 9. Error Handling

- Generic error messages
- Don't expose stack traces
- Log errors securely
- Don't log sensitive data

### 10. Dependencies

- Keep updated
- Run audits
- Remove unused
- Use lock files

## OWASP Top 10

1. Broken Access Control
2. Cryptographic Failures
3. Injection
4. Insecure Design
5. Security Misconfiguration
6. Vulnerable Components
7. Authentication Failures
8. Data Integrity Failures
9. Logging Failures
10. SSRF

## Security Checklist

✓ Input validation
✓ Output encoding
✓ Parameterized queries
✓ Strong authentication
✓ Proper authorization
✓ Secure cryptography
✓ HTTPS/TLS
✓ Security headers
✓ CSRF protection
✓ No secrets in code
