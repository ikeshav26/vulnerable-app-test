const express = require('express');
const mysql = require('mysql');

const app = express();
app.use(express.json());

// VULNERABILITY 1: SQL Injection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'password123', // VULNERABILITY 2: Hardcoded credentials
  database: 'users_db',
});

// VULNERABILITY 3: SQL Injection in login
app.post('/login', (req, res) => {
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
app.delete('/user/:id', (req, res) => {
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
app.post('/calculate', (req, res) => {
  const { expression } = req.body;

  try {
    const result = eval(expression); // Dangerous!
    res.json({ result });
  } catch (error) {
    res.status(400).json({ error: 'Invalid expression' });
  }
});

// VULNERABILITY 8: Missing CORS protection and security headers
app.listen(3000, () => {
  console.log('Server running on port 3000');
  console.log('Warning: This app contains intentional vulnerabilities for testing!');
});

module.exports = app;
