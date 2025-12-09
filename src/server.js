const express = require('express');
const mysql = require('mysql');
const cors = require('cors'); // Add for CORS protection
const helmet = require('helmet'); // Add for security headers

const app = express();
app.use(express.json());
app.use(cors()); // Enable CORS for all origins by default (can be configured)
app.use(helmet()); // Add various security headers

const db = mysql.createConnection({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE || 'users_db',
});

// Connect to MySQL
db.connect(err => {
  if (err) {
    console.error('Database connection failed:', err.stack);
    return;
  }
  console.log('Connected to database as id ' + db.threadId);
});

// Fix for SQL Injection in login and input validation
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Input Validation
  if (!username || typeof username !== 'string' || username.length < 3 || username.length > 50) {
    return res.status(400).json({ error: 'Invalid username format or length.' });
  }
  if (!password || typeof password !== 'string' || password.length < 8 || password.length > 100) { // Example: password length validation
    return res.status(400).json({ error: 'Invalid password format or length.' });
  }

  // Use parameterized queries to prevent SQL Injection
  // In a real application, passwords should be hashed and compared securely.
  const query = `SELECT id, username FROM users WHERE username = ? AND password = ?`;
  db.query(query, [username, password], (err, results) => {
    if (err) {
      console.error('Login database error:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    if (results.length > 0) {
      // VULNERABILITY 4: Sending sensitive data in response (FIXED: only return id and username)
      res.json({ success: true, user: results[0] });
    } else {
      res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
  });
});

// Fix for missing input validation and SQL injection
app.get('/user/:id', (req, res) => {
  const userId = req.params.id;

  // Input Validation: Ensure userId is a valid integer
  if (!userId || !Number.isInteger(parseInt(userId, 10))) {
    return res.status(400).json({ error: 'Invalid user ID. Must be an integer.' });
  }
  const parsedUserId = parseInt(userId, 10); // Sanitize to integer

  // Use parameterized queries to prevent SQL Injection
  // Only select necessary user information
  const query = `SELECT id, username FROM users WHERE id = ?`;
  db.query(query, [parsedUserId], (err, results) => {
    if (err) {
      console.error('Database error retrieving user:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    if (results.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(results[0]); // Return the first (and only) user found
  });
});

// Fix for SQL injection and input validation for deletion
app.delete('/user/:id', (req, res) => {
  // NOTE: This endpoint still lacks proper authentication/authorization.
  // In a real application, a user should only be able to delete their own account
  // or an admin should be explicitly authorized.

  const userId = req.params.id;

  // Input Validation: Ensure userId is a valid integer
  if (!userId || !Number.isInteger(parseInt(userId, 10))) {
    return res.status(400).json({ error: 'Invalid user ID. Must be an integer.' });
  }
  const parsedUserId = parseInt(userId, 10); // Sanitize to integer

  // Use parameterized queries to prevent SQL Injection
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

// Fix for Eval usage (Remote Code Execution) and add input validation
app.post('/calculate', (req, res) => {
  const { num1, operator, num2 } = req.body;

  // Input Validation: Ensure inputs are numbers and operator is valid
  if (typeof num1 !== 'number' || typeof num2 !== 'number' || isNaN(num1) || isNaN(num2)) {
    return res.status(400).json({ error: 'Both num1 and num2 must be valid numbers.' });
  }
  if (!['+', '-', '*', '/'].includes(operator)) {
    return res.status(400).json({ error: 'Invalid operator. Only +, -, *, / are allowed.' });
  }

  let result;
  try {
    switch (operator) {
      case '+': result = num1 + num2; break;
      case '-': result = num1 - num2; break;
      case '*': result = num1 * num2; break;
      case '/':
        if (num2 === 0) {
          return res.status(400).json({ error: 'Cannot divide by zero.' });
        }
        result = num1 / num2;
        break;
      default:
        // This case should ideally not be reached due to the earlier validation
        return res.status(400).json({ error: 'Unknown error with operator.' });
    }
    res.json({ result });
  } catch (error) {
    console.error('Calculation error:', error);
    res.status(500).json({ error: 'An unexpected calculation error occurred.' });
  }
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
  console.log('Warning: This app contained intentional vulnerabilities for testing, now fixed!');
});

module.exports = app;