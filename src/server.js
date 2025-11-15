const express = require('express');
const mysql = require('mysql');

const app = express();
app.use(express.json());

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: process.env.DB_PASSWORD, // FIXED: Replaced hardcoded password with environment variable
  database: 'users_db',
});

// Fixed: SQL Injection in login, sensitive data in response, and added input validation
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Input validation: Ensure username and password are provided
  if (!username || typeof username !== 'string' || username.trim().length === 0) {
    return res.status(400).json({ error: 'Valid username is required' });
  }
  if (!password || typeof password !== 'string' || password.trim().length === 0) {
    return res.status(400).json({ error: 'Valid password is required' });
  }

  // Use parameterized query to prevent SQL injection
  // In a real application, passwords should be hashed and salted (e.g., using bcrypt)
  // and compared securely, not stored/compared in plaintext.
  const query = `SELECT id, username FROM users WHERE username = ? AND password = ?`;
  db.query(query, [username, password], (err, results) => {
    if (err) {
      console.error('Database error during login:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    if (results.length > 0) {
      // Fixed: Only send non-sensitive user data in response
      res.json({ success: true, user: { id: results[0].id, username: results[0].username } });
    } else {
      res.status(401).json({ success: false, message: 'Invalid credentials' }); // Use 401 for unauthorized
    }
  });
});

// Fixed: Missing input validation and SQL injection
app.get('/user/:id', (req, res) => {
  const userId = req.params.id;

  // Input validation: Ensure userId is a positive integer
  const parsedUserId = parseInt(userId, 10);
  if (isNaN(parsedUserId) || parsedUserId <= 0) {
    return res.status(400).json({ error: 'Invalid user ID. Must be a positive integer.' });
  }

  // Use parameterized query to prevent SQL injection
  // Fixed: Only select non-sensitive fields
  const query = `SELECT id, username FROM users WHERE id = ?`;
  db.query(query, [parsedUserId], (err, results) => {
    if (err) {
      console.error('Database error fetching user:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    if (results.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(results[0]); // Return the single user object
  });
});

// Fixed: Missing input validation and SQL injection (authentication check remains unaddressed as per issue type)
app.delete('/user/:id', (req, res) => {
  const userId = req.params.id;

  // Input validation: Ensure userId is a positive integer
  const parsedUserId = parseInt(userId, 10);
  if (isNaN(parsedUserId) || parsedUserId <= 0) {
    return res.status(400).json({ error: 'Invalid user ID. Must be a positive integer.' });
  }

  // NOTE: In a real application, proper authentication and authorization checks
  // would be required here to ensure only authorized users can delete accounts.

  // Use parameterized query to prevent SQL injection
  const query = `DELETE FROM users WHERE id = ?`;
  db.query(query, [parsedUserId], (err, results) => {
    if (err) {
      console.error('Database error deleting user:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    if (results.affectedRows === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json({ message: 'User deleted successfully' });
  });
});

// Fixed: Eval usage removed and input validated to prevent Remote Code Execution
app.post('/calculate', (req, res) => {
  const { expression } = req.body;

  // Input validation: Ensure expression is a string representing a simple number.
  // eval() is removed to prevent remote code execution. For complex calculations,
  // a dedicated and secure mathematical expression parser library should be used.
  if (typeof expression !== 'string' || !/^-?\d+(\.\d+)?$/.test(expression.trim())) {
    return res.status(400).json({ error: 'Invalid expression. Only simple numeric values are supported for calculation.' });
  }

  try {
    // Safely parse the number string without using eval()
    const result = parseFloat(expression);
    if (isNaN(result)) {
        return res.status(400).json({ error: 'Invalid numeric expression' });
    }
    res.json({ result });
  } catch (error) {
    console.error('Error during calculation parsing:', error);
    res.status(400).json({ error: 'Error processing calculation' });
  }
});

// VULNERABILITY: Missing CORS protection and security headers (not addressed by current issue type)
app.listen(3000, () => {
  console.log('Server running on port 3000');
  console.log('Warning: This app contained intentional vulnerabilities for testing, now some are fixed!');
});

module.exports = app;