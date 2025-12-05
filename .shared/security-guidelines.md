# Vibe Security - Security Guidelines for AI Code Generation

## Overview

This knowledge base provides comprehensive security guidelines for AI-assisted code generation. Use these rules to ensure all generated code follows security best practices.

## Critical Security Rules

### 1. Input Validation & Sanitization

**ALWAYS validate and sanitize user input before processing**

✅ **DO:**

```javascript
// Validate input
const sanitizeInput = (input) => {
  return validator.escape(input.trim());
};

// Use parameterized queries
const user = await db.query("SELECT * FROM users WHERE id = ?", [userId]);
```

❌ **DON'T:**

```javascript
// Direct string concatenation with user input
const query = `SELECT * FROM users WHERE id = '${userId}'`;
```

### 2. SQL Injection Prevention

**ALWAYS use parameterized queries or ORMs**

✅ **DO:**

```javascript
// Parameterized query
await db.execute("SELECT * FROM users WHERE email = ?", [email]);

// ORM
await User.findOne({ where: { email } });
```

❌ **DON'T:**

```javascript
await db.query(`SELECT * FROM users WHERE email = '${email}'`);
```

### 3. XSS (Cross-Site Scripting) Prevention

**ALWAYS sanitize output and use secure rendering methods**

✅ **DO:**

```javascript
import DOMPurify from "dompurify";

// Sanitize before rendering
const clean = DOMPurify.sanitize(userInput);
element.innerHTML = clean;

// Use textContent for plain text
element.textContent = userInput;
```

❌ **DON'T:**

```javascript
element.innerHTML = userInput;
eval(userInput);
```

### 4. Authentication & Authorization

**ALWAYS implement proper authentication and authorization**

✅ **DO:**

```javascript
// Strong password requirements
const passwordRegex =
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$/;

// Hash passwords
const hashedPassword = await bcrypt.hash(password, 12);

// Verify JWT properly
const verified = jwt.verify(token, process.env.JWT_SECRET);
```

❌ **DON'T:**

```javascript
// Weak password validation
if (password.length < 6) throw new Error("Too short");

// Plain text passwords
const user = { password: password };

// Disabled verification
const decoded = jwt.decode(token); // No signature verification!
```

### 5. Cryptography

**ALWAYS use strong, modern cryptographic algorithms**

✅ **DO:**

```javascript
const crypto = require("crypto");

// Use SHA-256 or better
const hash = crypto.createHash("sha256").update(data).digest("hex");

// Use AES-256
const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

// Secure random generation
const token = crypto.randomBytes(32).toString("hex");
```

❌ **DON'T:**

```javascript
// Weak algorithms
const hash = crypto.createHash("md5").update(data).digest("hex");
const hash = crypto.createHash("sha1").update(data).digest("hex");

// Insecure random
const token = Math.random().toString(36);
```

### 6. Command Injection Prevention

**NEVER execute commands with user input**

✅ **DO:**

```javascript
// Use safe alternatives
const { execFile } = require("child_process");
execFile("ls", ["-l", sanitizedPath], callback);

// Whitelist allowed values
const allowedCommands = ["start", "stop", "restart"];
if (!allowedCommands.includes(command)) throw new Error("Invalid command");
```

❌ **DON'T:**

```javascript
exec(`ls -l ${userInput}`);
spawn(`git ${userCommand}`);
```

### 7. Path Traversal Prevention

**ALWAYS validate and sanitize file paths**

✅ **DO:**

```javascript
const path = require("path");

// Validate and normalize paths
const safePath = path.normalize(userPath).replace(/^(\.\.(\/|\\|$))+/, "");
const fullPath = path.join(basePath, safePath);

// Ensure path is within allowed directory
if (!fullPath.startsWith(basePath)) {
  throw new Error("Invalid path");
}
```

❌ **DON'T:**

```javascript
fs.readFile(req.query.file, callback);
fs.readFile(`./uploads/${req.body.filename}`, callback);
```

### 8. CSRF Protection

**ALWAYS implement CSRF protection for state-changing operations**

✅ **DO:**

```javascript
const csrf = require("csurf");
const csrfProtection = csrf({ cookie: true });

app.post("/api/transfer", csrfProtection, async (req, res) => {
  // Process request
});
```

❌ **DON'T:**

```javascript
app.post("/api/transfer", async (req, res) => {
  // No CSRF protection!
});
```

### 9. Secure Headers

**ALWAYS set security headers**

✅ **DO:**

```javascript
const helmet = require("helmet");
app.use(helmet());

// Or manually
app.use((req, res, next) => {
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader(
    "Strict-Transport-Security",
    "max-age=31536000; includeSubDomains"
  );
  res.setHeader("Content-Security-Policy", "default-src 'self'");
  next();
});
```

### 10. Secrets Management

**NEVER hardcode secrets in code**

✅ **DO:**

```javascript
// Use environment variables
const apiKey = process.env.API_KEY;
const dbPassword = process.env.DB_PASSWORD;

// Use secret management services
const { SecretManagerServiceClient } = require("@google-cloud/secret-manager");
const client = new SecretManagerServiceClient();
const [secret] = await client.accessSecretVersion({ name: secretName });
```

❌ **DON'T:**

```javascript
const apiKey = "sk-1234567890abcdef";
const password = "MyPassword123!";
```

## Security Checklist

Before generating any code, ensure:

- [ ] Input validation is implemented
- [ ] Output encoding/escaping is used
- [ ] Parameterized queries for database operations
- [ ] Strong authentication mechanisms
- [ ] Proper authorization checks
- [ ] Secure cryptographic functions
- [ ] HTTPS/TLS for all communications
- [ ] Security headers are set
- [ ] CSRF protection for state changes
- [ ] No hardcoded secrets
- [ ] Error messages don't leak sensitive info
- [ ] Logging doesn't include sensitive data
- [ ] Dependencies are up to date
- [ ] Least privilege principle applied

## OWASP Top 10 (2021)

1. **A01:2021 - Broken Access Control**
2. **A02:2021 - Cryptographic Failures**
3. **A03:2021 - Injection**
4. **A04:2021 - Insecure Design**
5. **A05:2021 - Security Misconfiguration**
6. **A06:2021 - Vulnerable and Outdated Components**
7. **A07:2021 - Identification and Authentication Failures**
8. **A08:2021 - Software and Data Integrity Failures**
9. **A09:2021 - Security Logging and Monitoring Failures**
10. **A10:2021 - Server-Side Request Forgery (SSRF)**

## Language-Specific Guidelines

### JavaScript/TypeScript

- Use strict mode: `'use strict';`
- Avoid `eval()`, `Function()`, `setTimeout(string)`, `setInterval(string)`
- Use `===` instead of `==`
- Validate all inputs
- Use Content Security Policy (CSP)

### Python

- Never use `pickle.loads()` on untrusted data
- Use parameterized queries with DB-API
- Validate file uploads
- Use `secrets` module for cryptographic randomness
- Avoid `eval()`, `exec()`, `compile()`

### Java

- Use PreparedStatement for SQL queries
- Validate all inputs
- Avoid native serialization for untrusted data
- Use secure random: `SecureRandom`
- Enable security manager

### PHP

- Use prepared statements (PDO/MySQLi)
- Enable `htmlspecialchars()` with ENT_QUOTES
- Avoid `eval()`, `system()`, `exec()`
- Use password_hash() for passwords
- Set `session.cookie_httponly = 1`

## Common CWE (Common Weakness Enumeration)

- **CWE-79**: XSS
- **CWE-89**: SQL Injection
- **CWE-78**: OS Command Injection
- **CWE-22**: Path Traversal
- **CWE-352**: CSRF
- **CWE-798**: Hardcoded Credentials
- **CWE-327**: Weak Cryptography
- **CWE-502**: Deserialization
- **CWE-918**: SSRF
- **CWE-601**: Open Redirect

## Additional Resources

- OWASP: https://owasp.org/
- CWE: https://cwe.mitre.org/
- NIST: https://nvd.nist.gov/
- Security Headers: https://securityheaders.com/
