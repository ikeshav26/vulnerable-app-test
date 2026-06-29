const crypto = require('crypto');
const bcrypt = require('bcrypt'); // Added for secure password hashing

// VULNERABILITY 9: Weak hashing algorithm - FIXED: Using bcrypt for secure hashing
const SALT_ROUNDS = 10; // Recommended number of salt rounds for bcrypt

function hashPassword(password) {
  // bcrypt automatically handles salting and is designed for password hashing
  return bcrypt.hashSync(password, SALT_ROUNDS);
}

// VULNERABILITY 10: Using deprecated and insecure crypto - FIXED: Using createCipheriv with strong algorithm and key derivation
function encrypt(text, password) {
  // Define constants for secure encryption (can be moved globally if preferred, but for self-contained fix)
  const ALGORITHM = 'aes-256-cbc';
  const IV_LENGTH = 16; // 16 bytes for AES-256-CBC IV
  const KEY_LENGTH = 32; // 32 bytes for AES-256-CBC key (256 bits)
  const KEY_DERIVATION_ITERATIONS = 100000; // Recommended iterations for PBKDF2
  const KEY_DERIVATION_DIGEST = 'sha512'; // Digest algorithm for PBKDF2

  // Generate a random IV for each encryption operation
  const iv = crypto.randomBytes(IV_LENGTH);
  
  // Generate a unique salt for key derivation from the password/passphrase
  // This is crucial for security as it ensures a unique key is derived even for the same password,
  // preventing dictionary attacks on derived keys and making each encryption unique.
  const salt = crypto.randomBytes(16); // Salt for PBKDF2

  // Derive a secure key from the password using PBKDF2
  // This is essential when the 'password' parameter is a human-memorable string (passphrase).
  // PBKDF2 stretches the password, making brute-force attacks much harder.
  const key = crypto.pbkdf2Sync(password, salt, KEY_DERIVATION_ITERATIONS, KEY_LENGTH, KEY_DERIVATION_DIGEST);

  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  // Return the IV, salt, and encrypted data. All three are necessary for decryption.
  // They are concatenated here with a colon delimiter for simplicity,
  // but a more robust solution might use a structured object or different encoding.
  return `${iv.toString('hex')}:${salt.toString('hex')}:${encrypted}`;
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
