import type { SecurityRule } from "../types/index.js";

export const SECURITY_RULES: SecurityRule[] = [
  // SQL Injection
  {
    id: "sql-injection-001",
    name: "SQL Injection - String Concatenation",
    severity: "critical",
    category: "injection",
    description: "SQL query built using string concatenation with user input",
    pattern:
      /(query|execute|exec)\s*\([^)]*[\+\$\`]\s*(?:req\.|params\.|body\.|query\.|input|user)/gi,
    languages: ["javascript", "typescript", "python", "php", "java", "csharp"],
    cwe: "CWE-89",
    owasp: "A03:2021 - Injection",
  },
  {
    id: "sql-injection-002",
    name: "SQL Injection - Template Literals",
    severity: "critical",
    category: "injection",
    description: "SQL query using template literals with user input",
    pattern:
      /`[^`]*SELECT[^`]*\$\{[^}]*(?:req\.|params\.|body\.|query\.|input|user)[^}]*\}[^`]*`/gi,
    languages: ["javascript", "typescript"],
    cwe: "CWE-89",
    owasp: "A03:2021 - Injection",
  },

  // XSS (Cross-Site Scripting)
  {
    id: "xss-001",
    name: "XSS - Direct innerHTML Assignment",
    severity: "high",
    category: "xss",
    description:
      "Direct assignment to innerHTML with potentially unsafe content",
    pattern: /\.innerHTML\s*=\s*(?!['"`])[^;]+/gi,
    languages: ["javascript", "typescript"],
    cwe: "CWE-79",
    owasp: "A03:2021 - Injection",
  },
  {
    id: "xss-002",
    name: "XSS - dangerouslySetInnerHTML",
    severity: "high",
    category: "xss",
    description: "React dangerouslySetInnerHTML without sanitization",
    pattern: /dangerouslySetInnerHTML\s*=\s*\{\{\s*__html:\s*(?!DOMPurify)/gi,
    languages: ["javascript", "typescript"],
    cwe: "CWE-79",
    owasp: "A03:2021 - Injection",
  },
  {
    id: "xss-003",
    name: "XSS - eval() Usage",
    severity: "critical",
    category: "xss",
    description: "Use of eval() with user input",
    pattern: /eval\s*\([^)]*(?:req\.|params\.|body\.|query\.|input|user)/gi,
    languages: ["javascript", "typescript", "python"],
    cwe: "CWE-95",
    owasp: "A03:2021 - Injection",
  },

  // Authentication & Authorization
  {
    id: "auth-001",
    name: "Weak Password Policy",
    severity: "high",
    category: "authentication",
    description: "Password validation allows weak passwords",
    pattern: /password\.length\s*[<>=!]+\s*[1-7](?!\d)/gi,
    languages: ["javascript", "typescript", "python", "java", "csharp"],
    cwe: "CWE-521",
    owasp: "A07:2021 - Identification and Authentication Failures",
  },
  {
    id: "auth-002",
    name: "Hardcoded Credentials",
    severity: "critical",
    category: "authentication",
    description: "Hardcoded passwords or API keys in source code",
    pattern:
      /(password|api_key|apikey|secret|token|auth)\s*[=:]\s*['"][^'"]+['"]/gi,
    languages: [
      "javascript",
      "typescript",
      "python",
      "java",
      "csharp",
      "php",
      "ruby",
    ],
    cwe: "CWE-798",
    owasp: "A07:2021 - Identification and Authentication Failures",
  },
  {
    id: "auth-003",
    name: "Missing JWT Signature Verification",
    severity: "critical",
    category: "authentication",
    description: "JWT verification disabled or bypassed",
    pattern: /jwt\.verify\([^)]*,\s*null\s*\)|jwt\.decode\(/gi,
    languages: ["javascript", "typescript"],
    cwe: "CWE-347",
    owasp: "A02:2021 - Cryptographic Failures",
  },

  // Cryptography
  {
    id: "crypto-001",
    name: "Weak Hashing Algorithm",
    severity: "high",
    category: "cryptography",
    description: "Use of weak cryptographic hash functions (MD5, SHA1)",
    pattern: /(md5|sha1|SHA1|MD5)\s*\(/gi,
    languages: ["javascript", "typescript", "python", "java", "csharp", "php"],
    cwe: "CWE-327",
    owasp: "A02:2021 - Cryptographic Failures",
  },
  {
    id: "crypto-002",
    name: "Insecure Random Number Generation",
    severity: "medium",
    category: "cryptography",
    description: "Use of Math.random() for security-sensitive operations",
    pattern: /Math\.random\(\)/gi,
    languages: ["javascript", "typescript"],
    cwe: "CWE-338",
    owasp: "A02:2021 - Cryptographic Failures",
  },
  {
    id: "crypto-003",
    name: "Weak Encryption Algorithm",
    severity: "high",
    category: "cryptography",
    description: "Use of DES or other weak encryption algorithms",
    pattern: /(createCipher\s*\(\s*['"]des|algorithm\s*[:=]\s*['"]des)/gi,
    languages: ["javascript", "typescript", "python"],
    cwe: "CWE-327",
    owasp: "A02:2021 - Cryptographic Failures",
  },

  // Path Traversal
  {
    id: "path-001",
    name: "Path Traversal",
    severity: "critical",
    category: "path-traversal",
    description: "Potential path traversal vulnerability",
    pattern:
      /(readFile|readFileSync|writeFile|createReadStream)\s*\([^)]*(?:req\.|params\.|body\.|query\.)[^)]*\)/gi,
    languages: ["javascript", "typescript", "python"],
    cwe: "CWE-22",
    owasp: "A01:2021 - Broken Access Control",
  },

  // Command Injection
  {
    id: "cmd-001",
    name: "Command Injection",
    severity: "critical",
    category: "injection",
    description: "Potential command injection via exec/system calls",
    pattern:
      /(exec|spawn|execSync|system)\s*\([^)]*(?:req\.|params\.|body\.|query\.|input|user)/gi,
    languages: ["javascript", "typescript", "python", "php"],
    cwe: "CWE-78",
    owasp: "A03:2021 - Injection",
  },

  // CSRF
  {
    id: "csrf-001",
    name: "Missing CSRF Protection",
    severity: "high",
    category: "csrf",
    description: "State-changing operation without CSRF protection",
    pattern: /router\.(post|put|delete|patch)\s*\([^)]*\)\s*,\s*(?!.*csrf)/gi,
    languages: ["javascript", "typescript"],
    cwe: "CWE-352",
    owasp: "A01:2021 - Broken Access Control",
  },

  // CORS
  {
    id: "cors-001",
    name: "Insecure CORS Configuration",
    severity: "medium",
    category: "cors",
    description: "CORS configured to allow all origins",
    pattern: /Access-Control-Allow-Origin['"]?\s*[:=]\s*['"]?\*/gi,
    languages: ["javascript", "typescript", "python", "java", "csharp"],
    cwe: "CWE-942",
    owasp: "A05:2021 - Security Misconfiguration",
  },

  // Information Disclosure
  {
    id: "info-001",
    name: "Sensitive Data in Logs",
    severity: "medium",
    category: "information-disclosure",
    description: "Logging sensitive information",
    pattern:
      /console\.(log|info|debug|error)\([^)]*(?:password|token|secret|apikey|credit_card)/gi,
    languages: ["javascript", "typescript"],
    cwe: "CWE-532",
    owasp: "A09:2021 - Security Logging and Monitoring Failures",
  },
  {
    id: "info-002",
    name: "Stack Trace Exposure",
    severity: "medium",
    category: "information-disclosure",
    description: "Exposing stack traces to users",
    pattern: /res\.send\([^)]*error\.stack|response\([^)]*error\.stack/gi,
    languages: ["javascript", "typescript"],
    cwe: "CWE-209",
    owasp: "A05:2021 - Security Misconfiguration",
  },

  // XML External Entity (XXE)
  {
    id: "xxe-001",
    name: "XXE - Unsafe XML Parsing",
    severity: "high",
    category: "injection",
    description: "XML parser configured without entity restriction",
    pattern: /new\s+DOMParser\(\)|parseString\(|parseXML\(/gi,
    languages: ["javascript", "typescript", "java", "python"],
    cwe: "CWE-611",
    owasp: "A05:2021 - Security Misconfiguration",
  },

  // Deserialization
  {
    id: "deser-001",
    name: "Insecure Deserialization",
    severity: "critical",
    category: "deserialization",
    description: "Unsafe deserialization of user input",
    pattern:
      /(pickle\.loads|yaml\.load|unserialize|ObjectInputStream)\s*\([^)]*(?:req\.|params\.|body\.|query\.)/gi,
    languages: ["python", "javascript", "typescript", "java", "php"],
    cwe: "CWE-502",
    owasp: "A08:2021 - Software and Data Integrity Failures",
  },

  // SSRF
  {
    id: "ssrf-001",
    name: "Server-Side Request Forgery",
    severity: "high",
    category: "ssrf",
    description: "HTTP request with user-controlled URL",
    pattern:
      /(fetch|axios\.get|request|http\.get)\s*\([^)]*(?:req\.|params\.|body\.|query\.)/gi,
    languages: ["javascript", "typescript", "python"],
    cwe: "CWE-918",
    owasp: "A10:2021 - Server-Side Request Forgery",
  },

  // Regex DoS
  {
    id: "redos-001",
    name: "Regular Expression DoS",
    severity: "medium",
    category: "dos",
    description: "Potentially vulnerable regex pattern",
    pattern: /new\s+RegExp\s*\([^)]*\([^)]*\+[^)]*\)\*/gi,
    languages: ["javascript", "typescript", "python", "java"],
    cwe: "CWE-1333",
    owasp: "A05:2021 - Security Misconfiguration",
  },

  // Open Redirect
  {
    id: "redirect-001",
    name: "Open Redirect",
    severity: "medium",
    category: "redirect",
    description: "Redirect to user-controlled URL",
    pattern: /(redirect|location)\s*\([^)]*(?:req\.|params\.|body\.|query\.)/gi,
    languages: ["javascript", "typescript", "python", "php"],
    cwe: "CWE-601",
    owasp: "A01:2021 - Broken Access Control",
  },

  // Race Condition
  {
    id: "race-001",
    name: "Time-of-Check Time-of-Use",
    severity: "medium",
    category: "race-condition",
    description: "Potential TOCTOU race condition",
    pattern: /if\s*\([^)]*exists[^)]*\)[^{]*\{[^}]*(?:write|create|delete)/gi,
    languages: ["javascript", "typescript", "python", "java"],
    cwe: "CWE-367",
    owasp: "A04:2021 - Insecure Design",
  },

  // Missing Security Headers
  {
    id: "headers-001",
    name: "Missing Security Headers",
    severity: "low",
    category: "headers",
    description: "Response missing important security headers",
    pattern:
      /res\.send\((?!.*helmet|X-Frame-Options|Content-Security-Policy)/gi,
    languages: ["javascript", "typescript"],
    cwe: "CWE-693",
    owasp: "A05:2021 - Security Misconfiguration",
  },

  // Insecure Dependencies
  {
    id: "dep-001",
    name: "Insecure Protocol",
    severity: "medium",
    category: "network",
    description: "Use of insecure HTTP instead of HTTPS",
    pattern: /['"]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/gi,
    languages: ["javascript", "typescript", "python", "java", "csharp"],
    cwe: "CWE-319",
    owasp: "A02:2021 - Cryptographic Failures",
  },

  // Type Confusion
  {
    id: "type-001",
    name: "Type Confusion - Loose Equality",
    severity: "low",
    category: "type-safety",
    description: "Use of loose equality (==) instead of strict (===)",
    pattern: /(?<!=[=!])[!=]=(?![=])/g,
    languages: ["javascript", "typescript"],
    cwe: "CWE-697",
    owasp: "A04:2021 - Insecure Design",
  },

  // Prototype Pollution
  {
    id: "proto-001",
    name: "Prototype Pollution",
    severity: "high",
    category: "prototype-pollution",
    description: "Potential prototype pollution vulnerability",
    pattern: /\[(?:req\.|params\.|body\.|query\.)[^\]]*\]\s*=/gi,
    languages: ["javascript", "typescript"],
    cwe: "CWE-1321",
    owasp: "A08:2021 - Software and Data Integrity Failures",
  },
];

export function getRulesByLanguage(language: string): SecurityRule[] {
  return SECURITY_RULES.filter((rule) =>
    rule.languages.includes(language.toLowerCase())
  );
}

export function getRulesBySeverity(severity: string): SecurityRule[] {
  return SECURITY_RULES.filter((rule) => rule.severity === severity);
}

export function getRulesByCategory(category: string): SecurityRule[] {
  return SECURITY_RULES.filter((rule) => rule.category === category);
}
