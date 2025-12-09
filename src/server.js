const express = require('express');
const mysql = require('mysql');
const Joi = require('joi'); // For robust input validation

const app = express();
app.use(express.json());

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
});

db.connect(err => {
  if (err) {
    console.error('Database connection failed: ' + err.stack);
    process.exit(1); // Exit if DB connection fails
  }
  console.log('Connected to database as id ' + db.threadId);
});

// Input validation schema for login
const loginSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(30).required(),
  password: Joi.string().min(6).max(100).required() // Password validation for format, not strength. Passwords should be hashed.
});

app.post('/login', (req, res) => {
  const { error, value } = loginSchema.validate(req.body);
  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }

  const { username, password } = value; // Use validated values

  // IMPORTANT: Passwords should always be hashed (e.g., bcrypt) and compared securely.
  // Storing and comparing plaintext passwords is a severe security vulnerability.
  // This fix primarily addresses SQL injection using parameterized queries.
  const query = 'SELECT id, username FROM users WHERE username = ? AND password = ?';
  db.query(query, [username, password], (err, results) => {
    if (err) {
      console.error('Login database error:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    if (results.length > 0) {
      // Only return non-sensitive user data (e.g., id, username, but NOT password hash if it were stored)
      res.json({ success: true, user: { id: results[0].id, username: results[0].username } });
    } else {
      res.json({ success: false, message: 'Invalid credentials' });
    }
  });
});

app.get('/user/:id', (req, res) => {
  // Input validation for userId: ensure it's a positive integer
  const schema = Joi.number().integer().positive().required();
  const { error, value: userId } = schema.validate(req.params.id);

  if (error) {
    return res.status(400).json({ error: 'Invalid user ID. Must be a positive integer.' });
  }

  // Use parameterized query to prevent SQL injection
  const query = 'SELECT id, username FROM users WHERE id = ?'; // Select specific fields to avoid leaking unnecessary data
  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error('Retrieve user database error:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    if (results.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(results[0]);
  });
});

app.delete('/user/:id', (req, res) => {
  // In a production application, robust authentication and authorization checks would be required here.
  // E.g., verify user's identity and permissions before allowing deletion.

  // Input validation for userId: ensure it's a positive integer
  const schema = Joi.number().integer().positive().required();
  const { error, value: userId } = schema.validate(req.params.id);

  if (error) {
    return res.status(400).json({ error: 'Invalid user ID. Must be a positive integer.' });
  }

  // Use parameterized query to prevent SQL injection
  const query = 'DELETE FROM users WHERE id = ?';
  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error('Delete user database error:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    if (results.affectedRows === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json({ message: 'User deleted successfully' });
  });
});

app.post('/calculate', (req, res) => {
  // IMPORTANT: `eval()` is inherently unsafe and should never be used with user input.
  // For security reasons, arbitrary code/expression evaluation is not allowed.
  // If specific mathematical operations are required, implement them explicitly and safely,
  // or use a dedicated, sandboxed library. `JSON.parse()` is only suitable for JSON strings.
  return res.status(403).json({ error: 'Arbitrary expression evaluation is not allowed for security reasons.' });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});

module.exports = app;