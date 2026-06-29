const express = require('express');
const mysql = require('mysql');
const cookieParser = require('cookie-parser'); // Added for CSRF protection
const csrf = require('csurf'); // Added for CSRF protection
const math = require('mathjs'); // Added for safe expression evaluation
const cors = require('cors'); // Added for CORS protection
const helmet = require('helmet'); // Added for security headers

const app = express();
app.use(express.json());
// Implement security headers using Helmet
app.use(helmet());
// Implement CORS protection
// Configure CORS based on your specific needs (e.g., origin, methods)
app.use(cors({
  origin: 'http://localhost:8080', // Replace with your client-side origin
  credentials: true,
}));

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
// Placeholder authentication middleware
// In a real application, this would verify a session token or JWT
// and populate req.user with user information (e.g., req.user = { id: 1, role: 'admin' }).
// For this exercise, we'll simulate a user being authenticated to demonstrate authorization.
const isAuthenticated = (req, res, next) => {
  // *** IMPORTANT: This is a simplified placeholder. In a real application,
  // you would implement proper authentication logic here (e.g., checking
  // JWTs, session cookies, etc.) and retrieve actual user data. ***
  req.user = { id: 1, username: 'demoUser', role: 'user' }; // Simulate logged-in user with ID 1
  next(); // Proceed if user is "authenticated"
  // If not authenticated: return res.status(401).json({ error: 'Unauthorized' });
};

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: process.env.DB_PASSWORD || 'password123', // VULNERABILITY 2: Hardcoded credentials (now using environment variable with fallback)
  database: 'users_db',
});

// VULNERABILITY 3: SQL Injection in login
app.post('/login', csrfProtection, (req, res) => {
  const { username, password } = req.body;

  // Use parameterized query to prevent SQL injection
  const query = 'SELECT * FROM users WHERE username = ? AND password = ?';
  db.query(query, [username, password], (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    if (results.length > 0) {
      // VULNERABILITY 4: Sending sensitive data in response
      // Only send non-sensitive user data
      const { password, ...safeUser } = results[0];
      res.json({ success: true, user: safeUser });
    } else {
      res.json({ success: false, message: 'Invalid credentials' });
    }
  });
});

// VULNERABILITY 5: Missing input validation and SQL injection
app.get('/user/:id', (req, res) => {
  const userId = req.params.id;

  // Input validation: Ensure userId is an integer
  if (!Number.isInteger(Number(userId))) {
    return res.status(400).json({ error: 'Invalid user ID format' });
  }

  // Use parameterized query to prevent SQL injection
  const query = 'SELECT * FROM users WHERE id = ?';

  db.query(query, [userId], (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(results);
  });
});

// VULNERABILITY 6: No authentication check
// VULNERABILITY 6: No authentication check (now with authentication and authorization)
app.delete('/user/:id', csrfProtection, isAuthenticated, (req, res) => {
  const userId = req.params.id;

  // Input validation: Ensure userId is an integer
  if (!Number.isInteger(Number(userId))) {
    return res.status(400).json({ error: 'Invalid user ID format' });
  }

  // Authorization check: A user can only delete their own account
  // or an admin role could delete any account. This example only allows
  // the authenticated user (simulated as ID 1) to delete their own ID.
  if (req.user.id !== Number(userId) && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden: You can only delete your own account (or require admin role).' });
  }

  // Use parameterized query to prevent SQL injection
  const query = 'DELETE FROM users WHERE id = ?';

  db.query(query, [userId], (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json({ message: 'User deleted successfully' });
  });
});

// VULNERABILITY 7: Eval usage (Remote Code Execution)
app.post('/calculate', csrfProtection, (req, res) => {
  const { expression } = req.body;

  try {
    // Safely evaluate mathematical expressions using mathjs
    // mathjs's evaluate function is much safer than eval().
    // Remember to install mathjs: npm install mathjs
    const result = math.evaluate(expression);
    res.json({ result });
  } catch (error) {
    // mathjs will throw an error for invalid or dangerous expressions
    res.status(400).json({ error: 'Invalid or malformed expression' });
  }
});

// VULNERABILITY 8: Missing CORS protection and security headers
app.listen(3000, () => {
  console.log('Server running on port 3000');
  console.log('Warning: This app contains intentional vulnerabilities for testing!');
});

module.exports = app;
