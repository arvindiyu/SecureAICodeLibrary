# Secure Coding Prompt: Secure-Coding Mentor Bot

## Purpose

This prompt guides you in creating educational content, assessments, and feedback to help developers learn secure coding practices. Use this prompt to generate learning materials, code reviews with a security focus, and interactive learning scenarios for your team.

## Secure-Coding Mentor Bot Prompt

```
As a secure coding mentor, help me [LEARNING OBJECTIVE] for [LANGUAGE/FRAMEWORK] development with a security focus.

Learning context:
1. Skill level: [Beginner, intermediate, advanced]
2. Programming language: [Language]
3. Framework or environment: [Framework/environment]
4. Security focus areas: [Authentication, authorization, input validation, etc.]
5. Time available: [Time for learning session]
6. Learning format: [Tutorial, code review, quiz, interactive exercise, etc.]

Create educational content that:
1. Explains relevant security concepts clearly
2. Provides secure coding examples with explanations
3. Highlights common security mistakes to avoid
4. Includes practical exercises or challenges
5. References industry best practices and standards
6. Builds security awareness and defensive thinking
7. Relates security principles to practical scenarios
8. Explains the security impact of coding choices
9. Offers remediation strategies for common vulnerabilities
10. Includes knowledge checks or quizzes where appropriate

If reviewing code, highlight:
1. Security vulnerabilities and risks
2. Secure alternatives to risky code
3. Potential attack vectors
4. Security best practices that apply
5. Security testing approaches for the code
```

## Learning Content Structure

### 1. Concept Introduction

Start with clear explanations of security concepts:
- Core security principles relevant to the topic
- Impact and risks of security vulnerabilities
- Security terminology and frameworks
- Real-world examples of security failures
- Industry standards and compliance requirements

### 2. Secure Implementation Examples

Provide practical, secure code examples:
- Well-commented secure code patterns
- Security control implementations
- Framework-specific security features
- Security library usage examples
- Configuration examples for security settings

### 3. Common Vulnerabilities and Fixes

Highlight typical security issues:
- Code patterns that create vulnerabilities
- Side-by-side comparison of vulnerable vs. secure code
- Security anti-patterns to avoid
- Common developer mistakes
- Language/framework-specific security pitfalls

### 4. Interactive Learning Exercises

Create engagement through practical application:
- Code completion challenges
- Security code review exercises
- Vulnerability identification quizzes
- Security refactoring tasks
- Capture-the-flag style security exercises

### 5. Best Practices and References

Consolidate learning with guidelines:
- Security checklists for the specific technology
- Recommended security tools and libraries
- Documentation and reference links
- Community resources for ongoing learning
- Security testing approaches

## Example Implementation: Web API Security in Node.js

### Learning Module: API Authentication & Authorization

#### 1. Concept Introduction

**API Security Fundamentals**

API security is critical for protecting backend services from unauthorized access and data breaches. Modern APIs face numerous threats including:

1. **Unauthorized Access**: Attackers attempting to access resources without proper authentication
2. **Privilege Escalation**: Authenticated users accessing resources beyond their permissions
3. **Token Theft**: Interception or theft of authentication tokens
4. **Replay Attacks**: Reusing captured request data for malicious purposes
5. **Injection Attacks**: Exploiting APIs with malicious input

Proper API security requires a defense-in-depth approach with multiple security layers:

- **Authentication**: Verifying user identity
- **Authorization**: Controlling access to resources
- **Input Validation**: Preventing malicious data
- **Rate Limiting**: Protecting against abuse
- **Encryption**: Protecting data in transit
- **Logging & Monitoring**: Detecting security incidents

In this module, we'll focus on implementing secure authentication and authorization for Node.js APIs using industry best practices.

#### 2. Secure Implementation Examples

**JWT Authentication Implementation**

Here's a secure implementation of JWT authentication in an Express.js API:

```javascript
// Required packages
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

const app = express();
app.use(express.json());

// Security configuration
const JWT_SECRET = process.env.JWT_SECRET; // Store in environment variables
const JWT_EXPIRY = '15m'; // Short-lived tokens
const REFRESH_TOKEN_EXPIRY = '7d';
const BCRYPT_ROUNDS = 12;

// In-memory token blacklist (use Redis in production)
const tokenBlacklist = new Set();

// User authentication
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Input validation
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }
    
    // Retrieve user from database (pseudocode)
    const user = await findUserByUsername(username);
    
    if (!user) {
      // Use consistent response time to prevent timing attacks
      await bcrypt.compare(password, '$2b$12$K3JNi5oQGMk.LLcLQzyr.eBmQFhfI8np/ueX7NUTLc9by7ivJg1PG');
      return res.status(401).json({ error: 'Authentication failed' });
    }
    
    // Verify password with bcrypt
    const passwordMatch = await bcrypt.compare(password, user.passwordHash);
    
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Authentication failed' });
    }
    
    // Check account lockout status
    if (user.isLocked) {
      return res.status(401).json({ error: 'Account locked' });
    }
    
    // Generate secure tokens
    const accessToken = jwt.sign(
      { 
        userId: user.id,
        username: user.username,
        roles: user.roles 
      },
      JWT_SECRET,
      { 
        expiresIn: JWT_EXPIRY,
        algorithm: 'HS256',  // Specify algorithm explicitly
        jwtid: crypto.randomBytes(16).toString('hex') // Unique token ID
      }
    );
    
    const refreshToken = crypto.randomBytes(40).toString('hex');
    
    // Store refresh token in database (pseudocode)
    await storeRefreshToken(user.id, refreshToken, REFRESH_TOKEN_EXPIRY);
    
    // Set cookies with secure attributes
    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000 // 15 minutes
    });
    
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/api/auth/refresh', // Restrict to refresh endpoint
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });
    
    // Log successful authentication
    logger.info('User authenticated successfully', { 
      userId: user.id,
      username: user.username,
      timestamp: new Date().toISOString()
    });
    
    return res.json({ 
      message: 'Authentication successful',
      user: {
        id: user.id,
        username: user.username,
        // Don't include sensitive information
      }
    });
  } catch (error) {
    logger.error('Authentication error', { error: error.message });
    return res.status(500).json({ error: 'Authentication failed' });
  }
});

// JWT verification middleware
const authenticateToken = (req, res, next) => {
  // Get token from Authorization header or cookie
  const authHeader = req.headers['authorization'];
  const tokenFromHeader = authHeader && authHeader.split(' ')[1];
  const tokenFromCookie = req.cookies.accessToken;
  
  const token = tokenFromHeader || tokenFromCookie;
  
  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }
  
  // Check if token is blacklisted
  if (tokenBlacklist.has(token)) {
    return res.status(401).json({ error: 'Token has been revoked' });
  }
  
  try {
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET, {
      algorithms: ['HS256'] // Restrict to specific algorithm
    });
    
    // Attach user to request object
    req.user = decoded;
    
    next();
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      return res.status(401).json({ error: 'Token expired' });
    }
    
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// Role-based authorization middleware
const authorize = (requiredRoles) => {
  return (req, res, next) => {
    // Check if user exists and has roles
    if (!req.user || !req.user.roles) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    // Check if user has required role
    const hasRequiredRole = req.user.roles.some(role => 
      requiredRoles.includes(role)
    );
    
    if (!hasRequiredRole) {
      // Log authorization failure
      logger.warn('Authorization failure', {
        userId: req.user.userId,
        requiredRoles,
        userRoles: req.user.roles,
        endpoint: req.originalUrl,
        method: req.method
      });
      
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    
    next();
  };
};

// Protected route example
app.get('/api/users/profile', authenticateToken, (req, res) => {
  // User information is available in req.user
  res.json({ 
    user: {
      id: req.user.userId,
      username: req.user.username,
      roles: req.user.roles
    } 
  });
});

// Admin-only route example
app.get('/api/admin/users', 
  authenticateToken, 
  authorize(['admin']), 
  async (req, res) => {
    // Only admins can access this route
    const users = await getAllUsers();
    res.json({ users });
});

// Token refresh endpoint
app.post('/api/auth/refresh', async (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  
  if (!refreshToken) {
    return res.status(401).json({ error: 'Refresh token required' });
  }
  
  try {
    // Verify refresh token from database (pseudocode)
    const tokenData = await verifyRefreshToken(refreshToken);
    
    if (!tokenData || tokenData.expired) {
      return res.status(401).json({ error: 'Invalid refresh token' });
    }
    
    // Get user data
    const user = await getUserById(tokenData.userId);
    
    // Generate new access token
    const accessToken = jwt.sign(
      { 
        userId: user.id,
        username: user.username,
        roles: user.roles 
      },
      JWT_SECRET,
      { 
        expiresIn: JWT_EXPIRY,
        algorithm: 'HS256',
        jwtid: crypto.randomBytes(16).toString('hex')
      }
    );
    
    // Set new access token cookie
    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000
    });
    
    return res.json({ message: 'Token refreshed successfully' });
  } catch (error) {
    logger.error('Token refresh error', { error: error.message });
    return res.status(500).json({ error: 'Token refresh failed' });
  }
});

// Logout endpoint
app.post('/api/auth/logout', authenticateToken, (req, res) => {
  try {
    // Add current token to blacklist
    const authHeader = req.headers['authorization'];
    const tokenFromHeader = authHeader && authHeader.split(' ')[1];
    const tokenFromCookie = req.cookies.accessToken;
    const token = tokenFromHeader || tokenFromCookie;
    
    if (token) {
      // Add to blacklist with expiry
      tokenBlacklist.add(token);
      
      // In production, use Redis with expiry matching token expiry
      // redisClient.set(`bl_${token}`, '1', 'EX', 15 * 60);
    }
    
    // Invalidate refresh token (pseudocode)
    const refreshToken = req.cookies.refreshToken;
    if (refreshToken) {
      invalidateRefreshToken(refreshToken);
    }
    
    // Clear cookies
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken', { path: '/api/auth/refresh' });
    
    return res.json({ message: 'Logged out successfully' });
  } catch (error) {
    logger.error('Logout error', { error: error.message });
    return res.status(500).json({ error: 'Logout failed' });
  }
});
```

**Secure Password Management**

```javascript
const bcrypt = require('bcrypt');
const crypto = require('crypto');

// User registration with secure password handling
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    // Input validation
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    // Password strength validation
    if (!isPasswordStrong(password)) {
      return res.status(400).json({ 
        error: 'Password must be at least 10 characters and include uppercase, lowercase, number, and special character' 
      });
    }
    
    // Check if user exists
    const existingUser = await findUserByUsernameOrEmail(username, email);
    if (existingUser) {
      return res.status(409).json({ error: 'Username or email already exists' });
    }
    
    // Generate password hash with bcrypt
    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    
    // Generate email verification token
    const verificationToken = crypto.randomBytes(32).toString('hex');
    
    // Create user (pseudocode)
    const user = await createUser({
      username,
      email,
      passwordHash,
      verificationToken,
      isVerified: false,
      roles: ['user']
    });
    
    // Send verification email (pseudocode)
    await sendVerificationEmail(email, verificationToken);
    
    return res.status(201).json({ 
      message: 'User registered successfully. Please verify your email.' 
    });
  } catch (error) {
    logger.error('Registration error', { error: error.message });
    return res.status(500).json({ error: 'Registration failed' });
  }
});

// Password reset request
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }
    
    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
    
    // Store reset token with expiry (pseudocode)
    await storeResetToken(email, resetTokenHash, '1h');
    
    // Send reset email with token (pseudocode)
    // Note: Send the unhashed token to the user, but store the hash
    await sendPasswordResetEmail(email, resetToken);
    
    // Always return success to prevent email enumeration
    return res.json({ message: 'If the email exists, a password reset link has been sent' });
  } catch (error) {
    logger.error('Password reset request error', { error: error.message });
    return res.status(500).json({ error: 'Password reset request failed' });
  }
});
```

#### 3. Common Vulnerabilities and Fixes

**Vulnerability: Insecure JWT Implementation**

❌ **Vulnerable Code:**

```javascript
// VULNERABLE: Insecure JWT implementation
const generateToken = (userId) => {
  // No expiration, no algorithm specified
  return jwt.sign({ userId }, 'hardcoded-secret');
};

// VULNERABLE: No verification of algorithm
const verifyToken = (token) => {
  try {
    return jwt.verify(token, 'hardcoded-secret');
  } catch (error) {
    return null;
  }
};
```

✅ **Secure Fix:**

```javascript
// SECURE: Proper JWT implementation
const generateToken = (userId) => {
  // Environment variable for secret, proper expiration
  return jwt.sign(
    { userId },
    process.env.JWT_SECRET,
    { 
      expiresIn: '15m', 
      algorithm: 'HS256',
      jwtid: crypto.randomBytes(16).toString('hex')
    }
  );
};

// SECURE: Proper verification with algorithm specification
const verifyToken = (token) => {
  try {
    return jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['HS256'] // Explicitly specify algorithm
    });
  } catch (error) {
    // Proper error handling
    logger.error('Token verification failed', { error: error.name });
    return null;
  }
};
```

**Vulnerability: Missing Authorization Checks**

❌ **Vulnerable Code:**

```javascript
// VULNERABLE: No authorization check
app.get('/api/users/:id', authenticateToken, async (req, res) => {
  const userId = req.params.id;
  const user = await getUserById(userId);
  
  // Any authenticated user can access any user's data
  res.json({ user });
});
```

✅ **Secure Fix:**

```javascript
// SECURE: Proper authorization check
app.get('/api/users/:id', authenticateToken, async (req, res) => {
  const userId = req.params.id;
  const requestedById = req.user.userId;
  
  // Check if user is requesting their own data or is an admin
  if (userId !== requestedById && !req.user.roles.includes('admin')) {
    logger.warn('Unauthorized access attempt', {
      requestedId: userId,
      requesterId: requestedById
    });
    return res.status(403).json({ error: 'Access denied' });
  }
  
  const user = await getUserById(userId);
  res.json({ user });
});
```

**Vulnerability: Improper Password Storage**

❌ **Vulnerable Code:**

```javascript
// VULNERABLE: Insecure password storage
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  
  // Store password as plain text or with weak hashing
  const user = {
    username,
    password: md5(password) // MD5 is cryptographically broken
  };
  
  await saveUser(user);
  res.json({ message: 'User registered' });
});
```

✅ **Secure Fix:**

```javascript
// SECURE: Proper password hashing with bcrypt
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  
  // Validate password strength
  if (password.length < 10) {
    return res.status(400).json({ error: 'Password too short' });
  }
  
  // Hash password with bcrypt (work factor of 12)
  const passwordHash = await bcrypt.hash(password, 12);
  
  const user = {
    username,
    passwordHash // Store hash, not the password
  };
  
  await saveUser(user);
  res.json({ message: 'User registered' });
});
```

#### 4. Interactive Learning Exercises

**Exercise 1: Identify the Security Issues**

Review the following code and identify all security issues:

```javascript
// Authentication endpoint with security issues
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  // Find user
  const user = users.find(u => u.username === username);
  
  // Check password
  if (user && user.password === password) {
    // Generate token
    const token = jwt.sign({ userId: user.id }, 'secret-key');
    
    // Send response
    res.json({ token });
  } else {
    res.status(401).json({ message: 'Invalid username or password' });
  }
});

// Protected endpoint
app.get('/api/profile/:id', (req, res) => {
  // Get token
  const token = req.headers.authorization;
  
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }
  
  try {
    // Verify token
    const decoded = jwt.verify(token, 'secret-key');
    const userId = req.params.id;
    
    // Get user data
    const userData = getUserData(userId);
    
    // Return user data
    res.json(userData);
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
});
```

**Security Issues to Identify:**
1. Passwords stored and compared in plain text
2. Hardcoded secret key for JWT
3. No JWT expiration specified
4. No algorithm specified for JWT signing or verification
5. Authorization not checked (any authenticated user can access any profile)
6. Token format not properly validated (should use Bearer scheme)
7. No input validation
8. No rate limiting for login attempts
9. Inconsistent error messages could enable username enumeration
10. No secure cookie settings or CSRF protection

**Exercise 2: Secure the Code**

Implement proper security controls to fix the issues identified in Exercise 1.

**Exercise 3: Implement Rate Limiting**

Create a rate-limiting middleware to protect authentication endpoints from brute force attacks.

#### 5. Best Practices and References

**API Security Best Practices Checklist**

1. **Authentication**
   - Use modern authentication frameworks and libraries
   - Implement proper password hashing (bcrypt, Argon2)
   - Set reasonable token expiration times
   - Implement refresh token rotation
   - Store tokens securely (httpOnly cookies)
   - Implement MFA for sensitive operations

2. **Authorization**
   - Implement role-based access control
   - Apply principle of least privilege
   - Check authorization on every request
   - Validate user permissions server-side
   - Implement proper resource ownership checks

3. **Input Validation**
   - Validate all input parameters
   - Use schema validation libraries (Joi, Zod)
   - Implement content-type validation
   - Validate file uploads (size, type, content)
   - Sanitize outputs to prevent XSS

4. **Rate Limiting & Abuse Prevention**
   - Implement rate limiting for all endpoints
   - Add specific protection for authentication endpoints
   - Implement CAPTCHA for sensitive operations
   - Monitor for suspicious patterns
   - Implement IP-based blocking for abuse

5. **Error Handling & Logging**
   - Use generic error messages for clients
   - Log detailed errors server-side
   - Implement proper exception handling
   - Avoid exposing stack traces
   - Use structured logging

**Security Tools and Libraries**

1. **Authentication & Authorization**
   - Passport.js - Authentication middleware
   - jsonwebtoken - JWT implementation
   - bcrypt - Password hashing
   - express-rate-limit - Rate limiting
   - helmet - HTTP security headers

2. **Validation & Sanitization**
   - Joi or Zod - Schema validation
   - express-validator - Request validation
   - content-type - Content type validation
   - validator.js - String validation library

3. **Security Testing**
   - OWASP ZAP - Security testing tool
   - JWT Debugger - JWT inspection tool
   - npm audit - Dependency scanning
   - Snyk - Vulnerability scanning

**References and Resources**

1. OWASP API Security Top 10: https://owasp.org/www-project-api-security/
2. OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
3. OWASP JWT Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html
4. Node.js Security Best Practices: https://nodejs.org/en/docs/guides/security/

## Security Testing for Learning Materials

### Knowledge Check Quiz

1. **Which of the following is the most secure way to store passwords?**
   - a) MD5 hashing
   - b) SHA-256 hashing
   - c) bcrypt with sufficient rounds
   - d) Base64 encoding
   - **Answer: c) bcrypt with sufficient rounds**

2. **Why is it important to specify the algorithm when verifying JWTs?**
   - a) To improve performance
   - b) To prevent algorithm confusion attacks
   - c) It's optional and doesn't affect security
   - d) To ensure compatibility across platforms
   - **Answer: b) To prevent algorithm confusion attacks**

3. **Which of these practices helps prevent Cross-Site Request Forgery (CSRF)?**
   - a) Using httpOnly cookies
   - b) Implementing proper Content-Security-Policy
   - c) Using anti-CSRF tokens
   - d) Implementing rate limiting
   - **Answer: c) Using anti-CSRF tokens**

4. **What is the principle of least privilege?**
   - a) Using minimal dependencies in your application
   - b) Granting users only the permissions they need
   - c) Running services with minimal CPU usage
   - d) Using the simplest authentication method
   - **Answer: b) Granting users only the permissions they need**

5. **Why should authentication failure messages be generic?**
   - a) To improve user experience
   - b) To reduce server load
   - c) To prevent username enumeration
   - d) It's an industry standard
   - **Answer: c) To prevent username enumeration**

## References

- OWASP API Security Top 10: https://owasp.org/www-project-api-security/
- NIST Special Publication 800-63B (Digital Identity Guidelines): https://pages.nist.gov/800-63-3/sp800-63b.html
- OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- JWT Best Practices: https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/
