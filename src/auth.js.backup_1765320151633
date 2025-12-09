const crypto = require('crypto');

// VULNERABILITY 9: Weak hashing algorithm
function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
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
