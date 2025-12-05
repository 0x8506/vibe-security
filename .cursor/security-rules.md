# Vibe Security Rules for Cursor

## Security-First Development

Apply these security rules to all code generation:

### Input Validation

- Validate all user inputs
- Use allowlists over denylists
- Sanitize data before processing
- Reject invalid inputs early

### SQL Injection Prevention

```typescript
// ✅ Use parameterized queries
const result = await db.query("SELECT * FROM users WHERE id = $1", [userId]);

// ❌ Never concatenate
const result = await db.query(`SELECT * FROM users WHERE id = '${userId}'`);
```

### XSS Prevention

```typescript
// ✅ Use textContent or sanitization
element.textContent = userInput;
const clean = DOMPurify.sanitize(userInput);

// ❌ Never direct innerHTML
element.innerHTML = userInput;
```

### Authentication

- Implement MFA when possible
- Use bcrypt/argon2 for password hashing
- Enforce strong password policies (12+ chars)
- Implement account lockout after failed attempts

### Cryptography

- Use AES-256-GCM for encryption
- Use SHA-256 or better for hashing
- Never use MD5, SHA1, or DES
- Use crypto.randomBytes() not Math.random()

### Authorization

- Implement role-based access control (RBAC)
- Check permissions on every request
- Use principle of least privilege
- Validate ownership of resources

### Error Handling

```typescript
// ✅ Generic error messages
res.status(401).json({ error: "Authentication failed" });

// ❌ Detailed error exposure
res.status(401).json({ error: `User ${username} not found in database` });
```

### Secrets Management

- Store secrets in environment variables
- Use secret management services (Vault, AWS Secrets Manager)
- Never commit secrets to version control
- Rotate secrets regularly

### HTTPS/TLS

- Use HTTPS for all communications
- Enforce TLS 1.2 or higher
- Implement HSTS headers
- Use secure cookies (httpOnly, secure, sameSite)

### Dependencies

- Keep dependencies updated
- Run security audits regularly
- Remove unused dependencies
- Use lock files

## Quick Security Checklist

- [ ] Input validation
- [ ] Output encoding
- [ ] Parameterized queries
- [ ] Strong authentication
- [ ] Proper authorization
- [ ] Secure cryptography
- [ ] HTTPS/TLS
- [ ] Security headers
- [ ] CSRF protection
- [ ] No hardcoded secrets
