const express = require('express');
const mysql = require('mysql');
const dotenv = require('dotenv');
const cors = require('cors');
const helmet = require('helmet');

// Load environment variables from .env file
dotenv.config();

const app = express();

// Apply security middlewares
app.use(helmet());
app.use(cors());
app.use(express.json());

// Database connection using environment variables for all sensitive configuration
const db = mysql.createConnection({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'users_db',
});

// Connect to MySQL
db.connect((err) => {
  if (err) {
    console.error('Database connection failed: ' + err.stack);
    return;
  }
  console.log('Connected to database as id ' + db.threadId);
});

// Dummy authentication middleware (placeholder)
// In a real application, this would verify a token/session/cookie
const authenticate = (req, res, next) => {
  // For demonstration, we'll proceed. In a real app, this would check
  // for a valid authentication token and return 401 if unauthorized.
  console.log('Authentication placeholder: In a real app, verify user identity here.');
  // Example: if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
  next();
};

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Input Validation: Check for presence and type
  if (!username || typeof username !== 'string' || username.trim() === '') {
    return res.status(400).json({ error: 'Username is required and must be a non-empty string.' });
  }
  if (!password || typeof password !== 'string' || password.trim() === '') {
    return res.status(400).json({ error: 'Password is required and must be a non-empty string.' });
  }

  // Use parameterized queries to prevent SQL Injection
  // ONLY select non-sensitive fields to return in the response
  const query = `SELECT id, username FROM users WHERE username = ? AND password = ?`;
  db.query(query, [username, password], (err, results) => {
    if (err) {
      console.error('Login database error:', err);
      return res.status(500).json({ error: 'Database error during login.' });
    }

    if (results.length > 0) {
      // Authentication successful, return minimal user data
      res.json({ success: true, user: results[0] });
    } else {
      res.status(401).json({ success: false, message: 'Invalid credentials.' });
    }
  });
});

app.get('/user/:id', authenticate, (req, res) => {
  const userId = req.params.id;

  // Input Validation: Ensure userId is a positive integer
  const parsedUserId = parseInt(userId, 10);
  if (isNaN(parsedUserId) || parsedUserId <= 0) {
    return res.status(400).json({ error: 'Invalid user ID. Must be a positive integer.' });
  }

  // Use parameterized query to prevent SQL Injection
  // ONLY select non-sensitive fields
  const query = `SELECT id, username FROM users WHERE id = ?`;
  db.query(query, [parsedUserId], (err, results) => {
    if (err) {
      console.error('Fetch user database error:', err);
      return res.status(500).json({ error: 'Database error fetching user.' });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: 'User not found.' });
    }
    res.json(results[0]);
  });
});

app.delete('/user/:id', authenticate, (req, res) => {
  const userId = req.params.id;

  // Input Validation: Ensure userId is a positive integer
  const parsedUserId = parseInt(userId, 10);
  if (isNaN(parsedUserId) || parsedUserId <= 0) {
    return res.status(400).json({ error: 'Invalid user ID. Must be a positive integer.' });
  }

  // Use parameterized query to prevent SQL Injection
  const query = `DELETE FROM users WHERE id = ?`;
  db.query(query, [parsedUserId], (err, results) => {
    if (err) {
      console.error('Delete user database error:', err);
      return res.status(500).json({ error: 'Database error deleting user.' });
    }
    if (results.affectedRows === 0) {
      return res.status(404).json({ message: 'User not found or already deleted.' });
    }
    res.json({ message: 'User deleted successfully.' });
  });
});

app.post('/calculate', (req, res) => {
  const { expression } = req.body;

  // Input Validation: Check for presence and type
  if (!expression || typeof expression !== 'string' || expression.trim() === '') {
    return res.status(400).json({ error: 'Expression is required and must be a non-empty string.' });
  }

  // --- SAFE ARITHMETIC EVALUATOR (simple example) ---
  // This is a minimal example replacing eval(). For complex expressions,
  // consider using a dedicated, secure math evaluation library (e.g., mathjs with sandbox).
  // This example only handles two numbers and one basic operator (+, -, *, /).
  const operators = ['+', '-', '*', '/'];
  let result = null;
  let foundOperator = false;

  for (const op of operators) {
    if (expression.includes(op)) {
      const parts = expression.split(op);
      if (parts.length === 2) {
        const num1 = parseFloat(parts[0].trim());
        const num2 = parseFloat(parts[1].trim());

        if (!isNaN(num1) && !isNaN(num2)) {
          foundOperator = true;
          switch (op) {
            case '+': result = num1 + num2; break;
            case '-': result = num1 - num2; break;
            case '*': result = num1 * num2; break;
            case '/':
              if (num2 === 0) {
                return res.status(400).json({ error: 'Division by zero is not allowed.' });
              }
              result = num1 / num2;
              break;
          }
          break; // Exit loop after finding and processing the first valid operator
        }
      }
    }
  }

  if (foundOperator && result !== null) {
    res.json({ result });
  } else {
    // If it's just a single number, return it
    const singleNumber = parseFloat(expression.trim());
    if (!isNaN(singleNumber)) {
        res.json({ result: singleNumber });
    } else {
        res.status(400).json({ error: 'Invalid or unsupported mathematical expression. Please use a simple format like "1+1" or a single number.' });
    }
  }
  // --- END SAFE ARITHMETIC EVALUATOR ---
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log('Security fixes applied. Remember to review and test thoroughly.');
});

module.exports = app;