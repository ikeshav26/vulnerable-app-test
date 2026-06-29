const express = require('express');
const mysql = require('mysql');
const cookieParser = require('cookie-parser'); // Added for CSRF protection
const csrf = require('csurf'); // Added for CSRF protection

const app = express();
app.use(express.json());

// Implement CSRF protection (addresses the listed finding)
app.use(cookieParser());
const csrfProtection = csrf({ cookie: true });

// Expose an endpoint for clients to retrieve the CSRF token
app.get('/csrf-token', csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// CSRF error handling middleware
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    res.status(403).json({ error: 'Invalid CSRF token' });
  } else {
    next(err);
  }
});

// VULNERABILITY 1: SQL Injection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'password123', // VULNERABILITY 2: Hardcoded credentials
  database: 'users_db',
});

// VULNERABILITY 3: SQL Injection in login
app.post('/login', csrfProtection, (req, res) => {
  const { username, password } = req.body;

  // Dangerous: Direct string concatenation in SQL query
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

  db.query(query, (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    if (results.length > 0) {
      // VULNERABILITY 4: Sending sensitive data in response
      res.json({ success: true, user: results[0] });
    } else {
      res.json({ success: false, message: 'Invalid credentials' });
    }
  });
});

// VULNERABILITY 5: Missing input validation and SQL injection
app.get('/user/:id', (req, res) => {
  const userId = req.params.id;

  const query = `SELECT * FROM users WHERE id = ${userId}`;

  db.query(query, (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(results);
  });
});

// VULNERABILITY 6: No authentication check
app.delete('/user/:id', csrfProtection, (req, res) => {
  const userId = req.params.id;

  const query = `DELETE FROM users WHERE id = ${userId}`;

  db.query(query, (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json({ message: 'User deleted successfully' });
  });
});

// VULNERABILITY 7: Eval usage (Remote Code Execution)
app.post('/calculate', csrfProtection, (req, res) => {
  const { expression } = req.body;

  // FIX: Replaced eval() for security reasons to prevent Remote Code Execution (RCE).
  // eval() with user-controlled input is a severe vulnerability.
  // If mathematical expression evaluation is a mandatory feature, a dedicated,
  // secure math expression parsing library (e.g., mathjs) should be used instead
  // to safely evaluate expressions without 'eval()'.
  try {
    console.warn('Attempted to use eval() in /calculate endpoint; functionality blocked for security reasons.');
    res.status(501).json({ error: 'Expression evaluation is not supported due to security risks (Remote Code Execution).' });
  } catch (error) {
    // This catch block is unlikely to be reached with the above direct response,
    // but is kept for defensive programming in case of future logic changes.
    console.error('Unexpected error in /calculate endpoint during security-blocked operation:', error);
    res.status(500).json({ error: 'An unexpected server error occurred.' });
  }
});

// VULNERABILITY 8: Missing CORS protection and security headers
app.listen(3000, () => {
  console.log('Server running on port 3000');
  console.log('Warning: This app contains intentional vulnerabilities for testing!');
});

module.exports = app;
