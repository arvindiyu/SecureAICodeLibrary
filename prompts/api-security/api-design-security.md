# API Security Design Guidelines

## Prompt

As a Secure API Design Specialist, help me design or review API endpoints with security as a priority. Follow these best practices:

### Authentication & Authorization
- Implement proper authentication mechanisms (OAuth 2.0, JWT, API keys)
- Use rate limiting to prevent abuse and DoS attacks
- Implement proper authorization checks for each endpoint
- Apply the principle of least privilege

### Input Validation & Output Encoding
- Validate and sanitize all input parameters (query, path, body)
- Use proper data types and validation constraints
- Implement parameterized queries for database operations
- Apply output encoding appropriate to the context

### API-Specific Controls
- Use HTTPS for all API communication
- Implement proper CORS policies
- Add security headers (Content-Security-Policy, X-Content-Type-Options, etc.)
- Use appropriate HTTP methods and status codes

### API Documentation & Security Testing
- Document security requirements and controls
- Include authentication and authorization details in API documentation
- Implement security testing (fuzzing, penetration testing)
- Use tools like OWASP ZAP or Burp Suite for API testing

## Example Implementation

### API Endpoint Security Review

```typescript
// INSECURE: No input validation, no rate limiting, insecure authentication
app.post('/api/users', (req, res) => {
  const user = req.body;
  db.query(`INSERT INTO users VALUES ('${user.username}', '${user.password}')`);
  res.status(201).send({ success: true });
});

// SECURE: With proper security controls
app.post('/api/users', 
  rateLimiter({ windowMs: 15 * 60 * 1000, max: 5 }), // Rate limiting
  authenticate, // Authentication middleware
  authorize(['admin']), // Authorization middleware
  [
    body('username').isAlphanumeric().isLength({ min: 5, max: 20 }).trim().escape(),
    body('password').isStrongPassword().trim(),
  ],
  async (req, res) => {
    // Validate request body
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    // Use parameterized query
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    
    try {
      await db.query('INSERT INTO users(username, password) VALUES($1, $2)', 
        [username, hashedPassword]);
      
      // Log the event (audit trail)
      logger.info(`User created: ${username} by ${req.user.id}`);
      
      return res.status(201)
        .set({
          'Content-Security-Policy': "default-src 'self'",
          'X-Content-Type-Options': 'nosniff'
        })
        .json({ success: true });
    } catch (error) {
      // Avoid leaking error details
      logger.error(`User creation error: ${error.message}`);
      return res.status(500).json({ error: 'An error occurred during user creation' });
    }
  }
);
```

### Secure API Design in Python (FastAPI)

```python
from fastapi import FastAPI, Depends, HTTPException, Security
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader
from pydantic import BaseModel, Field, validator
import bcrypt
from typing import List
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address

app = FastAPI(title="Secure API")
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(429, _rate_limit_exceeded_handler)

api_key_header = APIKeyHeader(name="X-API-Key")

class UserCreate(BaseModel):
    username: str = Field(..., min_length=5, max_length=20, regex=r'^[a-zA-Z0-9]+$')
    password: str = Field(..., min_length=8)
    
    @validator('password')
    def password_strength(cls, v):
        # Check for password complexity
        if not any(char.isdigit() for char in v):
            raise ValueError('Password must contain at least one digit')
        if not any(char.isupper() for char in v):
            raise ValueError('Password must contain at least one uppercase letter')
        return v

def verify_api_key(api_key: str = Security(api_key_header)):
    if api_key != "valid_api_key":  # In production, use secure key storage
        raise HTTPException(status_code=403, detail="Invalid API key")
    return api_key

@app.post("/api/users/")
@limiter.limit("5/minute")  # Rate limiting
async def create_user(user: UserCreate, api_key: str = Depends(verify_api_key)):
    # Password hashing
    hashed_password = bcrypt.hashpw(user.password.encode(), bcrypt.gensalt())
    
    # In a real app, use parameterized queries for database operations
    # db.execute("INSERT INTO users (username, password) VALUES (%s, %s)", 
    #           (user.username, hashed_password.decode()))
    
    # Audit logging
    # logger.info(f"User created: {user.username}")
    
    return {"status": "user created"}
```

### Java Spring Boot Secure API Example

```java
@RestController
@RequestMapping("/api")
public class UserController {

    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private PasswordEncoder passwordEncoder;

    // Rate limiting using bucket4j
    private final Bucket bucket = Bucket4j.builder()
            .addLimit(Bandwidth.classic(5, Refill.greedy(5, Duration.ofMinutes(1))))
            .build();

    @PostMapping("/users")
    public ResponseEntity<?> createUser(
            @Valid @RequestBody UserCreateDTO userDTO,
            @RequestHeader("X-API-Key") String apiKey) {
        
        // Rate limiting check
        if (!bucket.tryConsume(1)) {
            return ResponseEntity
                    .status(HttpStatus.TOO_MANY_REQUESTS)
                    .body("Rate limit exceeded");
        }
        
        // API Key validation (in production use proper API key management)
        if (!"valid_api_key".equals(apiKey)) {
            return ResponseEntity
                    .status(HttpStatus.FORBIDDEN)
                    .body("Invalid API key");
        }
        
        // Password hashing before storing
        User user = new User();
        user.setUsername(userDTO.getUsername());
        user.setPassword(passwordEncoder.encode(userDTO.getPassword()));
        
        // Secure database operation
        userRepository.save(user);
        
        // Audit logging
        // logger.info("User created: {}", userDTO.getUsername());
        
        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Security-Policy", "default-src 'self'");
        headers.add("X-Content-Type-Options", "nosniff");
        
        return new ResponseEntity<>(
                Map.of("status", "user created"), 
                headers,
                HttpStatus.CREATED);
    }
}

// Data validation using Bean Validation
public class UserCreateDTO {
    @NotBlank
    @Size(min = 5, max = 20)
    @Pattern(regexp = "^[a-zA-Z0-9]+$")
    private String username;
    
    @NotBlank
    @Size(min = 8)
    @Pattern(regexp = "^(?=.*[0-9])(?=.*[A-Z]).*$", 
             message = "Password must contain at least one digit and one uppercase letter")
    private String password;
    
    // Getters and setters omitted for brevity
}
```

## Security Testing Guidelines

1. **Input Validation Testing**
   - Test with boundary values, invalid inputs, and special characters
   - Attempt SQL injection, XSS, command injection

2. **Authentication Testing**
   - Test credential handling and session management
   - Test for improper token handling and expiry

3. **Authorization Testing**
   - Test vertical privilege escalation (elevating privileges)
   - Test horizontal privilege escalation (accessing other users' data)

4. **Rate Limiting & DoS Protection**
   - Test API rate limits with automated tools
   - Verify proper handling of concurrent requests

5. **API-Specific Testing**
   - Test CORS implementation
   - Verify proper use of HTTP methods and status codes
   - Check for sensitive information in responses

## Common API Security Vulnerabilities

1. **Broken Object Level Authorization**
   - API endpoints fail to enforce proper object-level permissions

2. **Broken User Authentication**
   - Weak or improper implementation of authentication mechanisms

3. **Excessive Data Exposure**
   - API returns more data than necessary, leaking sensitive information

4. **Lack of Resources & Rate Limiting**
   - Absence of proper throttling leading to DoS vulnerability

5. **Security Misconfiguration**
   - Default configurations, incomplete setups, open cloud storage

6. **Injection Flaws**
   - SQL, NoSQL, command injection due to unsanitized inputs

7. **Improper Assets Management**
   - Unpatched systems, deprecated API versions, unprotected files

8. **Mass Assignment**
   - Client-provided data binding to data models without proper filtering

9. **Improper Inventory Management**
   - Outdated documentation, unprotected API endpoints

10. **Insufficient Logging & Monitoring**
    - Lack of proper logging for security events and suspicious activities
