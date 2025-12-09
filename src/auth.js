const crypto = require('crypto');

const HASH_SALT_LENGTH = 16;
const HASH_KEY_LENGTH = 64;
const HASH_ITERATIONS = 100000;
const HASH_DIGEST = 'sha512';

const ENCRYPTION_ALGORITHM = 'aes-256-cbc';
const ENCRYPTION_IV_LENGTH = 16;
const ENCRYPTION_KEY_DERIVATION_ITERATIONS = 10000;
const ENCRYPTION_KEY_DERIVATION_SALT = Buffer.from('a_unique_and_non_secret_salt_for_key_derivation', 'utf8'); // This salt helps with key derivation, does not need to be secret but should be unique to the app
const ENCRYPTION_KEY_LENGTH = 32;

const TOKEN_LENGTH = 32;

function hashPassword(password) {
  const salt = crypto.randomBytes(HASH_SALT_LENGTH).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, HASH_ITERATIONS, HASH_KEY_LENGTH, HASH_DIGEST).toString('hex');
  return `${salt}:${hash}`;
}

function encrypt(text, secret) {
  const key = crypto.pbkdf2Sync(secret, ENCRYPTION_KEY_DERIVATION_SALT, ENCRYPTION_KEY_DERIVATION_ITERATIONS, ENCRYPTION_KEY_LENGTH, HASH_DIGEST);
  const iv = crypto.randomBytes(ENCRYPTION_IV_LENGTH);
  const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

function generateToken() {
  return crypto.randomBytes(TOKEN_LENGTH).toString('hex');
}

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