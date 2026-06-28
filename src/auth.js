const crypto = require('crypto');
const bcrypt = require('bcrypt');

// VULNERABILITY 9: Weak hashing algorithm - FIXED: Using bcrypt for secure password hashing
function hashPassword(password) {
  const saltRounds = 10; // Recommended number of salt rounds
  return bcrypt.hashSync(password, saltRounds);
}

// VULNERABILITY 10: Using deprecated and insecure crypto
function encrypt(text, password) {
  const algorithm = 'aes-256-cbc';
  const key = crypto.scryptSync(password, 'salt', 32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
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
