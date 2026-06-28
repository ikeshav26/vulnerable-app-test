const crypto = require('crypto');
const bcrypt = require('bcrypt'); // Added for secure password hashing

// VULNERABILITY 9: Weak hashing algorithm - FIXED: Using bcrypt for secure hashing
const SALT_ROUNDS = 10; // Recommended number of salt rounds for bcrypt

function hashPassword(password) {
  // bcrypt automatically handles salting and is designed for password hashing
  return bcrypt.hashSync(password, SALT_ROUNDS);
}

// VULNERABILITY 10: Using deprecated and insecure crypto
function encrypt(text, password) {
  const cipher = crypto.createCipher('des', password); // DES is weak!
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

// VULNERABILITY 11: Predictable random values
function generateToken() {
  return Math.random().toString(36).substring(2); // Not cryptographically secure
}

// VULNERABILITY 12: No rate limiting on sensitive operation
function resetPassword(userId) {
  const token = generateToken();
  console.log(`Password reset token for user ${userId}: ${token}`);
  return token;
}

module.exports = {
  hashPassword,
  encrypt,
  generateToken,
  resetPassword,
};
