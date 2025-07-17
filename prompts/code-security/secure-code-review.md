# Secure Code Review Prompt

## Overview

This prompt helps you perform systematic and thorough security code reviews to identify vulnerabilities, security anti-patterns, and potential weaknesses before they reach production. Use this prompt to guide Copilot in analyzing code for security issues across various languages and frameworks.

## How to Use This Prompt

1. Provide the code snippet or file that needs security review
2. Specify the programming language and framework context
3. Include any additional application context (e.g., is this code handling authentication, payment processing, etc.)
4. Request specific security focus areas if needed

## Example Prompts

```
Perform a secure code review on this Java authentication module. Focus on potential SQL injection and improper session management issues.

[CODE BLOCK]
public class AuthenticationService {
    private final UserRepository userRepository;
    
    public AuthenticationService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }
    
    public User authenticate(String username, String password) {
        String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
        return userRepository.findByQuery(query);
    }
    
    public String generateSessionToken(User user) {
        return user.getUsername() + ":" + System.currentTimeMillis();
    }
}
[/CODE BLOCK]
```

```
Review this Node.js API endpoint for security vulnerabilities, focusing on input validation, authorization checks, and potential information leakage.

[CODE BLOCK]
app.post('/api/users/:id/update', (req, res) => {
  const userId = req.params.id;
  const updates = req.body;
  
  db.query(`UPDATE users SET ? WHERE id = ${userId}`, [updates], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: err.message });
    }
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    res.json({ success: true, message: 'User updated' });
  });
});
[/CODE BLOCK]
```

## Security Focus Areas

When reviewing code, Copilot will analyze for these common security issues:

1. **Injection Vulnerabilities**
   - SQL Injection
   - Command Injection
   - Cross-Site Scripting (XSS)
   - LDAP Injection
   - XML Injection/XXE
   - Template Injection

2. **Authentication & Authorization**
   - Missing authentication
   - Weak authentication mechanisms
   - Improper authorization checks
   - Insecure credential storage
   - Session management flaws

3. **Data Protection**
   - Sensitive data exposure
   - Missing encryption
   - Weak cryptographic implementations
   - Insecure key management
   - Unprotected PII/PHI

4. **Input Validation**
   - Missing/insufficient validation
   - Client-side only validation
   - Type confusion issues
   - Unchecked file uploads
   - Untrusted data handling

5. **Output Encoding**
   - Missing HTML encoding
   - Improper JSON serialization
   - Content-Type issues
   - Missing HTTP headers

6. **Error Handling**
   - Information disclosure in errors
   - Stack traces in responses
   - Inconsistent error messages
   - Missing error handling
   - Security control bypasses

7. **Security Misconfiguration**
   - Hardcoded secrets
   - Default configurations
   - Unnecessary features enabled
   - Overly permissive settings
   - Missing security headers

8. **Race Conditions**
   - TOCTOU issues
   - Concurrency problems
   - Resource contention
   - Deadlock vulnerabilities

9. **Business Logic Flaws**
   - Broken access control
   - Mass assignment
   - Insecure direct object references
   - Logic bypass opportunities
   - Privilege escalation paths

10. **Third-Party Components**
    - Vulnerable dependencies
    - Insecure integrations
    - Outdated libraries
    - Supply chain risks

## Expected Output Format

```markdown
# Security Code Review Results

## Summary of Findings
- [HIGH] SQL Injection vulnerability in authenticate method
- [MEDIUM] Weak session token generation
- [LOW] Missing input validation

## Detailed Analysis

### [HIGH] SQL Injection vulnerability
**Location**: `authenticate()` method
**Issue**: String concatenation in SQL query allows attacker to inject arbitrary SQL
**Impact**: Complete database compromise, unauthorized access
**Recommendation**: Use parameterized queries:
```java
String query = "SELECT * FROM users WHERE username = ? AND password = ?";
return userRepository.findByQueryWithParams(query, username, password);
```

### [MEDIUM] Weak session token generation
**Location**: `generateSessionToken()` method
**Issue**: Session token is predictable and lacks entropy
**Impact**: Session hijacking, authentication bypass
**Recommendation**: Use a cryptographically secure random generator:
```java
public String generateSessionToken(User user) {
    byte[] randomBytes = new byte[32];
    new SecureRandom().nextBytes(randomBytes);
    return Base64.getEncoder().encodeToString(randomBytes);
}
```

### [LOW] Missing input validation
**Location**: `authenticate()` method
**Issue**: No validation on username and password inputs
**Impact**: Potential for injection attacks beyond SQL
**Recommendation**: Add input validation before processing:
```java
public User authenticate(String username, String password) {
    if (username == null || username.isEmpty() || password == null) {
        throw new IllegalArgumentException("Invalid credentials");
    }
    // Existing code with parameterized query
}
```

## Risk Assessment
Overall risk: HIGH - Critical vulnerabilities identified requiring immediate remediation.

## Secure Coding References
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
```
