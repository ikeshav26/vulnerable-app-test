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
    // DES is weak and should be replaced with a modern algorithm like AES-256-GCM.
  // This fix primarily addresses the 'no-iv' and 'deprecated function' warning.

  // Derive an 8-byte key for DES from the password using SHA256 hash.
  // Note: Direct password to key derivation is generally discouraged for secure applications.
  // A proper KDF like PBKDF2 should be used, typically with a random salt.
  const key = crypto.createHash('sha256').update(password).digest().slice(0, 8); // DES key length is 8 bytes

  // Generate a cryptographically secure, random 8-byte IV for DES.
  // The IV must be unique for each encryption operation and stored/transmitted with the ciphertext.
  const iv = crypto.randomBytes(8); // DES IV length is 8 bytes

  const cipher = crypto.createCipheriv('des', key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  // Return the IV along with the ciphertext, separated by a colon.
  // The IV is essential for decryption and must be known.
  return `${iv.toString('hex')}:${encrypted}`;
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
