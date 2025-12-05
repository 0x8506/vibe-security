# Vibe Security Rules for Windsurf

Security-first code generation guidelines for Windsurf AI.

## Core Security Principles

1. **Validate Input**: Never trust user input
2. **Encode Output**: Escape data before rendering
3. **Authenticate**: Verify identity properly
4. **Authorize**: Check permissions always
5. **Encrypt**: Use strong cryptography
6. **Audit**: Log security events

## Critical Vulnerabilities to Prevent

### SQL Injection

```javascript
// ✅ Secure
db.query("SELECT * FROM products WHERE id = ?", [productId]);

// ❌ Vulnerable
db.query(`SELECT * FROM products WHERE id = ${productId}`);
```

### XSS (Cross-Site Scripting)

```javascript
// ✅ Secure
element.textContent = userInput;
div.innerHTML = DOMPurify.sanitize(htmlContent);

// ❌ Vulnerable
div.innerHTML = userInput;
eval(userInput);
```

### Command Injection

```javascript
// ✅ Secure
execFile("git", ["clone", sanitizedUrl]);

// ❌ Vulnerable
exec(`git clone ${url}`);
```

### Path Traversal

```javascript
// ✅ Secure
const safePath = path.join(baseDir, path.normalize(userPath));
if (!safePath.startsWith(baseDir)) throw new Error("Invalid path");

// ❌ Vulnerable
fs.readFile(req.query.file);
```

## Authentication Best Practices

- Hash passwords with bcrypt (12+ rounds)
- Implement JWT with proper verification
- Use secure session management
- Enforce MFA for sensitive operations
- Implement rate limiting

## Authorization Best Practices

- Check permissions on every request
- Use RBAC or ABAC models
- Validate resource ownership
- Implement least privilege
- Audit access attempts

## Cryptography Requirements

- AES-256 for symmetric encryption
- RSA-2048+ for asymmetric encryption
- SHA-256+ for hashing
- crypto.randomBytes() for tokens
- No MD5, SHA1, or DES

## Security Headers

```javascript
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
    },
  })
);
```

## OWASP Top 10 Compliance

All generated code must address OWASP Top 10 risks.

## Testing

- Implement security unit tests
- Use SAST tools
- Scan dependencies
- Perform code reviews
