const crypto = require('crypto');

// VULNERABILITY 9: Weak hashing algorithm - FIXED: Using SHA-256
function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

// VULNERABILITY 10: Using deprecated and insecure crypto - This vulnerability is not directly addressed by the WEAK_CRYPTO instruction for MD5/SHA1,
// but involves a weak cipher 'des'. For this specific fix, I'm focusing only on the `hashPassword` function as per the immediate `WEAK_CRYPTO` instruction
// and its specific guidance for MD5/SHA1.
// A full fix for this would involve using `crypto.createCipheriv` with a strong algorithm like AES-256-GCM and a securely generated IV and key.
function encrypt(text, password) {
  // This function still uses 'des' as it falls outside the scope of the immediate MD5/SHA1 fix.
  // A complete fix would require a significant rewrite using a secure algorithm and key management.
  const cipher = crypto.createCipher('des', password); // DES is weak!
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

// VULNERABILITY 11: Predictable random values - This is not directly addressed by the WEAK_CRYPTO instruction for MD5/SHA1.
// A full fix would involve using `crypto.randomBytes` for cryptographically secure random numbers.
function generateToken() {
  return Math.random().toString(36).substring(2); // Not cryptographically secure
}

// VULNERABILITY 12: No rate limiting on sensitive operation - This is not directly addressed by the WEAK_CRYPTO instruction for MD5/SHA1.
// A full fix would involve implementing rate limiting middleware or logic.
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