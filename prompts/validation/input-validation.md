# Input Validation Prompt

## Overview

This prompt guides you in implementing comprehensive input validation strategies to prevent security vulnerabilities related to improper or missing validation. Proper input validation is a fundamental security control that helps prevent injection attacks, buffer overflows, and other security issues.

## How to Use This Prompt

1. Provide the code snippet or function that handles user inputs
2. Specify the programming language and framework context
3. Describe what the inputs represent (user data, API parameters, file uploads, etc.)
4. Ask for specific validation requirements (format, range, size, etc.)

## Example Prompts

```
Implement input validation for this Node.js Express route that processes user registration data. The route accepts username, email, password, and age. Ensure all fields are properly validated for security.

[CODE BLOCK]
router.post('/register', (req, res) => {
  const { username, email, password, age } = req.body;
  
  // TODO: Add input validation
  
  // Process registration
  const user = new User({ username, email, password, age });
  user.save()
    .then(() => res.status(201).json({ message: 'User registered successfully' }))
    .catch(err => res.status(500).json({ error: err.message }));
});
[/CODE BLOCK]
```

```
Create a Python function to validate file uploads in a Flask application. The function should verify file type (only PDFs and images allowed), file size (max 5MB), and scan for malicious content.
```

## Validation Strategies by Data Type

### Text Input Validation
- **Length Constraints**: Enforce minimum and maximum length limits
- **Format Validation**: Use regular expressions for expected patterns
- **Character Set Restrictions**: Limit to allowed characters
- **Content Filtering**: Filter/sanitize dangerous sequences

### Numeric Input Validation
- **Range Checking**: Enforce minimum and maximum values
- **Type Verification**: Ensure input is numeric
- **Precision Handling**: Verify decimal places if applicable
- **Zero/Negative Handling**: Check if zero or negative values are acceptable

### Date/Time Input Validation
- **Format Verification**: Ensure date matches expected format
- **Range Checking**: Verify date is within valid range
- **Logical Validation**: Check if date makes sense (e.g., birth date in past)
- **Timezone Handling**: Process timezone information correctly

### File Upload Validation
- **Type Verification**: Validate MIME type and extension match
- **Size Limits**: Enforce maximum file size
- **Content Analysis**: Scan file content for malicious patterns
- **Metadata Cleaning**: Strip potentially dangerous metadata

### Structured Data Validation
- **Schema Validation**: Verify structure matches expected schema
- **Required Fields**: Check all required fields are present
- **Cross-field Validation**: Verify logical relationships between fields
- **Nested Validation**: Apply validation rules to nested structures

## Implementation Examples

### JavaScript/TypeScript (Express) Input Validation

```javascript
// Using express-validator
const { body, validationResult } = require('express-validator');

router.post('/register', [
  // Username validation
  body('username')
    .trim()
    .isLength({ min: 3, max: 30 }).withMessage('Username must be 3-30 characters')
    .matches(/^[A-Za-z0-9_-]+$/).withMessage('Username can only contain letters, numbers, underscores and hyphens')
    .escape(),
  
  // Email validation
  body('email')
    .trim()
    .isEmail().withMessage('Invalid email address')
    .normalizeEmail(),
  
  // Password validation
  body('password')
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
      .withMessage('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'),
  
  // Age validation
  body('age')
    .isInt({ min: 18, max: 120 }).withMessage('Age must be between 18 and 120'),
], (req, res) => {
  // Check for validation errors
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  
  // Process validated input
  const { username, email, password, age } = req.body;
  // Continue with registration...
});
```

### Python (Flask) File Upload Validation

```python
import os
import magic
from flask import Flask, request
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

def validate_file_upload(file):
    """
    Validates uploaded file for security.
    
    Args:
        file: The file from request.files
        
    Returns:
        tuple: (is_valid, error_message)
    """
    # Check if file exists
    if not file:
        return False, "No file provided"
        
    # Check filename
    filename = secure_filename(file.filename)
    if not filename:
        return False, "Invalid filename"
        
    # Check file extension
    ext = os.path.splitext(filename)[1].lower()[1:]
    if ext not in ALLOWED_EXTENSIONS:
        return False, f"File type not allowed. Allowed types: {', '.join(ALLOWED_EXTENSIONS)}"
    
    # Check file size
    file_content = file.read()
    file.seek(0)  # Reset file pointer after reading
    
    if len(file_content) > MAX_FILE_SIZE:
        return False, f"File too large. Maximum size: {MAX_FILE_SIZE / 1024 / 1024}MB"
    
    # Check actual content type with python-magic
    mime = magic.Magic(mime=True)
    content_type = mime.from_buffer(file_content)
    
    if ext == 'pdf' and content_type != 'application/pdf':
        return False, "File content doesn't match extension"
    
    if ext in ['png', 'jpg', 'jpeg', 'gif'] and not content_type.startswith('image/'):
        return False, "File content doesn't match extension"
        
    # Additional checks could be added here (virus scanning, etc.)
    
    return True, "File is valid"


app = Flask(__name__)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return {"error": "No file part"}, 400
        
    file = request.files['file']
    
    is_valid, message = validate_file_upload(file)
    if not is_valid:
        return {"error": message}, 400
        
    # Process the valid file
    filename = secure_filename(file.filename)
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    
    return {"message": "File uploaded successfully"}, 201
```

### Java Input Validation for REST API

```java
import javax.validation.Valid;
import javax.validation.constraints.*;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

// Data Transfer Object with built-in validation
public class UserRegistrationDto {
    
    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 30, message = "Username must be between 3 and 30 characters")
    @Pattern(regexp = "^[A-Za-z0-9_-]+$", 
             message = "Username can only contain letters, numbers, underscores and hyphens")
    private String username;
    
    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    private String email;
    
    @NotBlank(message = "Password is required")
    @Size(min = 8, message = "Password must be at least 8 characters")
    @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]+$",
             message = "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character")
    private String password;
    
    @NotNull(message = "Age is required")
    @Min(value = 18, message = "Age must be at least 18")
    @Max(value = 120, message = "Age must not exceed 120")
    private Integer age;
    
    // Getters and setters
}

@RestController
@RequestMapping("/api/users")
public class UserController {

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody UserRegistrationDto registrationDto) {
        // If we get here, all validation has passed
        // Process the registration
        try {
            // User creation logic
            return ResponseEntity.status(201).body("User registered successfully");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Registration failed: " + e.getMessage());
        }
    }
}
```

## Security Considerations

1. **Defense in Depth**
   - Implement validation at all layers (client, API, service)
   - Combine different validation approaches for critical inputs

2. **Failure Handling**
   - Fail securely when validation errors occur
   - Provide appropriate user feedback without exposing system details
   - Log validation failures for security monitoring

3. **Canonicalization**
   - Normalize inputs before validation to prevent bypass techniques
   - Watch for encoding tricks that can bypass validation

4. **Performance**
   - Balance thorough validation with performance requirements
   - Consider asynchronous validation for complex checks

5. **Customization**
   - Adapt validation rules based on risk profile of the application
   - Implement stricter validation for higher-risk features

## Common Pitfalls to Avoid

1. Client-side only validation
2. Bypassing validation for internal requests
3. Inconsistent validation across different entry points
4. Over-reliance on blacklisting instead of whitelisting
5. Incomplete validation of nested or complex data structures
6. Insufficient validation for file uploads and binary data
7. Not handling internationalization and character encoding issues

## Best Practices

1. **Centralize Validation Logic**
   - Create reusable validation libraries
   - Ensure consistent validation across application

2. **Use Framework Validation**
   - Leverage built-in validation capabilities of frameworks
   - Use well-tested validation libraries

3. **Input Normalization**
   - Normalize inputs before validation (trim whitespace, etc.)
   - Handle character encoding consistently

4. **Positive Validation**
   - Prefer allowlist (whitelist) over denylist (blacklist) approaches
   - Define exactly what is allowed, not what is forbidden

5. **Structured Data Validation**
   - Use schema validation for JSON/XML (JSON Schema, XML Schema)
   - Validate before parsing complex structures

6. **Contextual Validation**
   - Apply business-context validation beyond basic format checks
   - Implement domain-specific validation rules
