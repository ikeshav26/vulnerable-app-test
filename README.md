# Vulnerable Test Application

⚠️ **WARNING: This application contains intentional security vulnerabilities for testing purposes only!**

## Purpose

This is a test repository to demonstrate the AI-powered security remediation service. It contains various common security vulnerabilities that the AI service should detect and fix.

## Known Vulnerabilities

### 1. SQL Injection (src/server.js)
- Lines 16-30: Login endpoint vulnerable to SQL injection
- Lines 34-45: User lookup endpoint with SQL injection
- Lines 48-59: Delete endpoint with SQL injection

### 2. Hardcoded Credentials (src/server.js)
- Line 10: Database password hardcoded in source

### 3. Remote Code Execution (src/server.js)
- Lines 62-71: Using `eval()` on user input

### 4. Weak Cryptography (src/auth.js)
- Line 5: Using MD5 for password hashing
- Line 11: Using deprecated DES encryption
- Line 20: Using Math.random() for tokens

### 5. Missing Security Controls
- No authentication/authorization checks
- No input validation
- No rate limiting
- No CORS protection
- No security headers

## Testing the AI Service

1. Install your GitHub App on this repository
2. The AI service should detect all vulnerabilities
3. Generate fixes for each vulnerability
4. Create a PR with the fixes

## Expected Fixes

The AI should suggest:
- Using parameterized queries for SQL
- Moving credentials to environment variables
- Removing eval() usage
- Upgrading to bcrypt for password hashing
- Using crypto.randomBytes() for tokens
- Adding helmet.js for security headers
- Implementing authentication middleware
- Adding input validation

## DO NOT deploy this application!

This is for testing only. Never deploy applications with known vulnerabilities.
