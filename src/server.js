const express = require('express');
const mysql = require('mysql');
require('dotenv').config();

const app = express();
app.use(express.json());

const db = mysql.createConnection({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE || 'users_db',
});

db.connect(err => {
  if (err) {
    return;
  }
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || typeof username !== 'string' || username.length < 3 || username.length > 50) {
    return res.status(400).json({ error: 'Invalid username. Must be 3-50 characters.' });
  }
  if (!password || typeof password !== 'string' || password.length < 6 || password.length > 100) {
    return res.status(400).json({ error: 'Invalid password. Must be 6-100 characters.' });
  }

  const query = `SELECT id, username FROM users WHERE username = ? AND password = ?`;
  db.query(query, [username, password], (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Database error during login' });
    }

    if (results.length > 0) {
      res.json({ success: true, user: results[0] });
    } else {
      res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
  });
});

app.get('/user/:id', (req, res) => {
  const userId = parseInt(req.params.id, 10);

  if (isNaN(userId) || userId <= 0) {
    return res.status(400).json({ error: 'Invalid user ID. Must be a positive integer.' });
  }

  const query = `SELECT id, username FROM users WHERE id = ?`;
  db.query(query, [userId], (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Database error fetching user' });
    }
    if (results.length === 0) {
        return res.status(404).json({ message: 'User not found' });
    }
    res.json(results[0]);
  });
});

app.delete('/user/:id', (req, res) => {
  const userId = parseInt(req.params.id, 10);

  if (isNaN(userId) || userId <= 0) {
    return res.status(400).json({ error: 'Invalid user ID. Must be a positive integer.' });
  }

  const query = `DELETE FROM users WHERE id = ?`;
  db.query(query, [userId], (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Database error deleting user' });
    }
    if (results.affectedRows === 0) {
        return res.status(404).json({ message: 'User not found' });
    }
    res.json({ message: 'User deleted successfully' });
  });
});

app.post('/calculate', (req, res) => {
  res.status(501).json({ error: 'Mathematical expression evaluation is not securely supported.' });
});

app.listen(3000, () => {
});

module.exports = app;