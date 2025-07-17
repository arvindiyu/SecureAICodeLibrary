# Secure Coding Prompt: Node.js (JavaScript/TypeScript)

## Purpose

This prompt guides you in implementing secure coding practices for Node.js applications using JavaScript or TypeScript. Use this prompt to generate code that follows security best practices and avoids common vulnerabilities.

## Secure Node.js Development Prompt

```
As a secure Node.js developer, help me implement [FEATURE/FUNCTIONALITY] with security as a priority. 

Consider these security aspects in your implementation:
1. Input validation and sanitization
2. Authentication and authorization
3. Secure session management
4. Protection against common web vulnerabilities (XSS, CSRF, injection)
5. Secure dependency management
6. Error handling that doesn't leak sensitive information
7. Secure configuration management
8. Proper logging (without sensitive data)
9. Rate limiting and resource protection
10. Data encryption where needed

Technical requirements:
- Framework: [Express.js, NestJS, etc.]
- Authentication method: [JWT, session-based, OAuth, etc.]
- Database: [MongoDB, PostgreSQL, MySQL, etc.]
- Environment: [Production, Development, etc.]

Follow these Node.js/TypeScript security best practices:
- Use proper input validation with libraries like joi, zod, or class-validator
- Implement parameterized queries for database operations
- Use security middleware like helmet, csurf, and rate-limiters
- Apply the principle of least privilege for all operations
- Follow secure coding patterns specific to Node.js
- Use TypeScript types and interfaces for better code safety
- Implement proper error handling and logging
```

## Security Considerations for Node.js

### Authentication & Authorization

- **JWT Security**: Proper signing algorithm (RS256 preferred over HS256), reasonable expiration time, secure storage
- **Session Security**: Secure cookies, proper session expiration, session fixation protection
- **OAuth Implementation**: Secure client validation, proper state parameter, PKCE when appropriate

### Input Validation

- **Request Body Validation**: Using libraries like Joi, Zod, class-validator
- **Parameter Validation**: Type checking, range validation, pattern matching
- **File Upload Security**: Virus scanning, size limits, type validation

### Database Security

- **Query Security**: Using ORMs or prepared statements
- **NoSQL Injection Prevention**: Proper MongoDB query construction
- **Connection Security**: TLS connections, least privilege accounts

### API Security

- **Rate Limiting**: Using libraries like express-rate-limit
- **CORS Configuration**: Properly restricted origins
- **Security Headers**: Using Helmet.js for secure HTTP headers

### Dependency Management

- **Package Auditing**: Regular npm audit checks
- **Version Pinning**: Exact versions in package.json
- **Supply Chain Security**: Using lockfiles, considering npm organizations

### Error Handling

- **Secure Error Responses**: Avoiding stack traces in production
- **Centralized Error Handling**: Consistent error formatting
- **Graceful Failure**: Failing securely without exposing internals

### Logging

- **Secure Logging**: Avoiding sensitive data in logs
- **Structured Logging**: Using Winston or Pino with proper redaction
- **Log Security**: Protecting log files and streams

### Configuration Management

- **Environment Variables**: Secure loading and validation
- **Secrets Management**: Using dedicated services like Vault or cloud key management
- **Configuration Validation**: Ensuring secure defaults

## Example Implementations

### Secure Express Middleware Setup

```typescript
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { body, validationResult } from 'express-validator';

const app = express();

// Security middleware
app.use(helmet()); // Set security-related HTTP headers
app.use(express.json({ limit: '100kb' })); // Limit request size

// Configure CORS properly
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || 'https://yourdomain.com',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  maxAge: 86400 // 24 hours
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many requests, please try again later.'
});
app.use('/api/', limiter); // Apply to all API endpoints

// Input validation example
app.post('/api/users',
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 }).escape(),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  },
  userController.createUser
);

// Centralized error handling
app.use((err, req, res, next) => {
  const errorId = uuidv4(); // For error tracking
  
  // Log detailed error for debugging (but not sensitive data)
  logger.error({
    id: errorId,
    method: req.method,
    path: req.path,
    error: err.message,
    stack: process.env.NODE_ENV === 'production' ? undefined : err.stack
  });
  
  // Send sanitized response to client
  res.status(err.statusCode || 500).json({
    error: process.env.NODE_ENV === 'production' ? 'Internal server error' : err.message,
    errorId // For customer support reference
  });
});
```

### Secure MongoDB Connection

```typescript
import mongoose from 'mongoose';
import { config } from './config';

async function connectToDatabase() {
  try {
    // Use environment variables for sensitive connection info
    const uri = config.get('mongodb.uri');
    
    await mongoose.connect(uri, {
      // Connection pool settings
      maxPoolSize: 10,
      minPoolSize: 5,
      
      // Secure settings
      ssl: true,
      sslValidate: true,
      sslCA: config.get('mongodb.sslCA'),
      
      // Timeout settings
      serverSelectionTimeoutMS: 5000,
      connectTimeoutMS: 10000,
      
      // Retry logic
      retryWrites: true,
      retryReads: true
    });
    
    console.log('Connected to MongoDB');
  } catch (error) {
    console.error('Failed to connect to MongoDB', error.message);
    // Don't log the full error object as it may contain credentials
    process.exit(1);
  }
}
```

### Secure JWT Authentication

```typescript
import jwt from 'jsonwebtoken';
import fs from 'fs';
import { promisify } from 'util';
import { config } from './config';

// Promisify JWT functions
const sign = promisify(jwt.sign);
const verify = promisify(jwt.verify);

// Load keys securely (from secure location, not in code repository)
const privateKey = fs.readFileSync(config.get('jwt.privateKeyPath'));
const publicKey = fs.readFileSync(config.get('jwt.publicKeyPath'));

export async function generateToken(payload) {
  // Use strong algorithm and reasonable expiration
  return await sign(payload, privateKey, {
    algorithm: 'RS256', // Asymmetric algorithm preferred
    expiresIn: '1h',    // Short-lived tokens
    audience: config.get('jwt.audience'),
    issuer: config.get('jwt.issuer'),
    jwtid: crypto.randomUUID() // Unique JWT ID
  });
}

export async function verifyToken(token) {
  try {
    return await verify(token, publicKey, {
      algorithms: ['RS256'], // Restrict allowed algorithms
      audience: config.get('jwt.audience'),
      issuer: config.get('jwt.issuer'),
      complete: true // Return decoded header + payload + signature
    });
  } catch (error) {
    // Log error type but not the token itself
    console.error(`Token verification failed: ${error.name}`);
    return null;
  }
}

// Middleware to protect routes
export function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authorization token required' });
  }
  
  const token = authHeader.split(' ')[1];
  
  verifyToken(token)
    .then(decoded => {
      if (!decoded) {
        return res.status(401).json({ error: 'Invalid token' });
      }
      
      // Add user info to request for downstream use
      req.user = decoded.payload;
      next();
    })
    .catch(err => {
      return res.status(401).json({ error: 'Invalid token' });
    });
}
```

## Security Testing Guidance

When implementing Node.js security features, validate with:

1. **Static Analysis**: Use tools like ESLint with security plugins, SonarQube
2. **Dependency Scanning**: Regular npm audit, Snyk, or Dependabot
3. **Security Headers**: Test with https://securityheaders.com
4. **Vulnerability Scanning**: OWASP ZAP, Burp Suite
5. **Penetration Testing**: Focus on API endpoints, authentication mechanisms

## Additional Resources

- [OWASP Node.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
- [Node.js Security Best Practices](https://github.com/goldbergyoni/nodebestpractices#6-security-best-practices)
- [Express.js Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html)
- [TypeScript Security Best Practices](https://docs.microsoft.com/en-us/javascript/typescript-handbook/typescript-in-5-minutes)
