// Example file with security vulnerabilities for testing

const express = require("express");
const mysql = require("mysql");
const crypto = require("crypto");
const { exec } = require("child_process");

const app = express();

// Hardcoded credentials - CRITICAL
const API_KEY = "sk-1234567890abcdef";
const password = "MyPassword123!";

// SQL Injection vulnerability - CRITICAL
app.get("/user", (req, res) => {
  const userId = req.query.id;
  const query = `SELECT * FROM users WHERE id = '${userId}'`;
  db.query(query, (err, result) => {
    res.json(result);
  });
});

// XSS vulnerability - HIGH
app.get("/profile", (req, res) => {
  const username = req.query.name;
  res.send(`<h1>Welcome ${username}</h1>`);
});

// Command Injection - CRITICAL
app.post("/backup", (req, res) => {
  const filename = req.body.file;
  exec(`tar -czf backup.tar.gz ${filename}`, (err, stdout) => {
    res.send("Backup created");
  });
});

// Weak cryptography - HIGH
function hashPassword(pass) {
  return crypto.createHash("md5").update(pass).digest("hex");
}

// Weak password validation - HIGH
function validatePassword(password) {
  if (password.length < 5) {
    return false;
  }
  return true;
}

// Path Traversal - CRITICAL
app.get("/download", (req, res) => {
  const file = req.query.file;
  res.sendFile(file);
});

// eval usage - CRITICAL
app.post("/calculate", (req, res) => {
  const expression = req.body.expr;
  const result = eval(expression);
  res.json({ result });
});

// Insecure random - MEDIUM
function generateToken() {
  return Math.random().toString(36);
}

// CORS misconfiguration - MEDIUM
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  next();
});

// Logging sensitive data - MEDIUM
app.post("/login", (req, res) => {
  console.log("Login attempt:", req.body.email, req.body.password);
  // ... authentication logic
});

// Missing CSRF protection - HIGH
app.post("/transfer", (req, res) => {
  // No CSRF token validation
  const amount = req.body.amount;
  const to = req.body.to;
  // ... transfer money
});

// Loose equality - LOW
if (req.query.admin == 1) {
  // Admin access
}

app.listen(3000);
