# Vibe Security for Copilot

## Security Guidelines for GitHub Copilot

### Input Validation

Always validate and sanitize user input:

```python
# ✅ Good
email = validator.validate_email(request.form['email'])
if not email:
    raise ValueError("Invalid email")

# ❌ Bad
email = request.form['email']
```

### SQL Injection Prevention

Use parameterized queries:

```python
# ✅ Good
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# ❌ Bad
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
```

### XSS Prevention

Escape output properly:

```python
# ✅ Good
from markupsafe import escape
return f"<h1>{escape(username)}</h1>"

# ❌ Bad
return f"<h1>{username}</h1>"
```

### Authentication

Use strong password hashing:

```python
# ✅ Good
from werkzeug.security import generate_password_hash, check_password_hash
password_hash = generate_password_hash(password, method='pbkdf2:sha256')

# ❌ Bad
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()
```

### Secrets Management

Never hardcode secrets:

```python
# ✅ Good
import os
api_key = os.environ.get('API_KEY')

# ❌ Bad
api_key = 'sk-1234567890abcdef'
```

### File Operations

Validate file paths:

```python
# ✅ Good
import os
safe_path = os.path.normpath(user_path)
if not safe_path.startswith(base_dir):
    raise ValueError("Invalid path")

# ❌ Bad
with open(request.args.get('file'), 'r') as f:
    content = f.read()
```

### Security Checklist

- [ ] Input validation implemented
- [ ] Parameterized queries used
- [ ] Output properly escaped
- [ ] Strong authentication in place
- [ ] Authorization checks present
- [ ] Secrets in environment variables
- [ ] HTTPS enforced
- [ ] Security headers set
- [ ] CSRF protection enabled
- [ ] Dependencies up to date

### References

- OWASP Top 10: https://owasp.org/www-project-top-ten/
- CWE: https://cwe.mitre.org/
