const crypto = require('crypto');

// VULNERABILITY 9: Weak hashing algorithm
function hashPassword(password) {
  // Fix: Replaced MD5 with SHA-256 as a stronger hashing algorithm.
  // For password storage, bcrypt or PBKDF2 with a salt would be even more secure.
  return crypto.createHash('sha256').update(password).digest('hex');
}

// VULNERABILITY 10: Using deprecated and insecure crypto
// Fix: Replaced DES with AES-256-CBC, a stronger algorithm, and used createCipheriv.
// Securely derive key and IV from password using PBKDF2 and use a random IV.
// The salt and IV are returned alongside the encrypted text for decryption.
function encrypt(text, password) {
  const salt = crypto.randomBytes(16); // Generate a random salt for key derivation
  const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha512'); // 32 bytes for AES-256 key
  const iv = crypto.randomBytes(16); // 16 bytes for AES-256-CBC IV

  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  // Return an object containing all necessary components for decryption
  return {
    encryptedData: encrypted,
    iv: iv.toString('hex'),
    salt: salt.toString('hex')
  };
}

// VULNERABILITY 11: Predictable random values
function generateToken() {
  // Fix: Replaced Math.random with crypto.randomBytes for cryptographically secure token generation.
  return crypto.randomBytes(20).toString('hex'); // Generates a 40-character hex string token
}

// VULNERABILITY 12: No rate limiting on sensitive operation
// This issue is not directly related to WEAK_CRYPTO and is left as is per instructions.
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