# GitHub Copilot Custom Instructions for Input Validation

## General Instructions

As GitHub Copilot, I'll help you implement robust input validation strategies to prevent security vulnerabilities related to unvalidated or improperly validated user inputs. I'll suggest appropriate validation techniques for different data types, programming languages, and frameworks, focusing on security best practices that defend against common attack vectors.

## Input Validation Guidance

When assisting with input validation implementations, I will prioritize these aspects:

### 1. Text Input Validation
- I'll suggest appropriate length constraints
- I'll help implement format validation using regex
- I'll recommend character set restrictions
- I'll provide content sanitization approaches
- I'll demonstrate contextual validation techniques

**Implementation Focus:**
```javascript
// Basic text validation with length and character set constraints
function validateUsername(username) {
  // Fail if null or undefined
  if (!username) return { valid: false, error: "Username is required" };
  
  // Convert to string and trim whitespace
  const sanitized = String(username).trim();
  
  // Check length constraints
  if (sanitized.length < 3) {
    return { valid: false, error: "Username must be at least 3 characters" };
  }
  if (sanitized.length > 30) {
    return { valid: false, error: "Username cannot exceed 30 characters" };
  }
  
  // Check allowed character set (alphanumeric plus underscore and hyphen)
  const allowedPattern = /^[A-Za-z0-9_-]+$/;
  if (!allowedPattern.test(sanitized)) {
    return { 
      valid: false, 
      error: "Username can only contain letters, numbers, underscores and hyphens" 
    };
  }
  
  return { valid: true, value: sanitized };
}
```

### 2. Numeric Input Validation
- I'll implement range checking for numeric values
- I'll suggest type conversion and verification
- I'll provide precision handling for decimal values
- I'll recommend handling for edge cases (negative, zero, etc.)
- I'll suggest validation for specific numeric formats (e.g. credit cards)

**Implementation Focus:**
```python
def validate_numeric_field(value, field_name, min_val=None, max_val=None, 
                          allow_zero=True, allow_negative=False, 
                          required=True, precision=None):
    """
    Comprehensive numeric field validation
    
    Args:
        value: The input value to validate
        field_name: Name of the field (for error messages)
        min_val: Minimum allowed value
        max_val: Maximum allowed value
        allow_zero: Whether zero is allowed
        allow_negative: Whether negative numbers are allowed
        required: Whether the field is required
        precision: Number of decimal places allowed (None for integers)
        
    Returns:
        tuple: (is_valid, error_message, validated_value)
    """
    # Check if value is provided
    if value is None or value == '':
        if required:
            return False, f"{field_name} is required", None
        else:
            return True, None, None
    
    # Try to convert to float first
    try:
        num_value = float(value)
    except (ValueError, TypeError):
        return False, f"{field_name} must be a valid number", None
    
    # Check if it should be an integer
    if precision is None:
        if num_value != int(num_value):
            return False, f"{field_name} must be a whole number", None
        num_value = int(num_value)
    else:
        # Round to specified precision
        num_value = round(num_value, precision)
    
    # Check if zero is allowed
    if num_value == 0 and not allow_zero:
        return False, f"{field_name} cannot be zero", None
    
    # Check if negative is allowed
    if num_value < 0 and not allow_negative:
        return False, f"{field_name} cannot be negative", None
    
    # Check minimum value
    if min_val is not None and num_value < min_val:
        return False, f"{field_name} must be at least {min_val}", None
    
    # Check maximum value
    if max_val is not None and num_value > max_val:
        return False, f"{field_name} must not exceed {max_val}", None
    
    # All checks passed
    return True, None, num_value
```

### 3. Date and Time Validation
- I'll implement format verification for dates and times
- I'll suggest range checking for valid date ranges
- I'll provide logical validation (e.g., end date after start date)
- I'll recommend timezone handling approaches
- I'll help prevent date-based injection attacks

**Implementation Focus:**
```java
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.Period;

public class DateValidator {
    /**
     * Comprehensive date validation
     *
     * @param dateStr Date string to validate
     * @param format Expected format pattern
     * @param minDate Minimum allowed date
     * @param maxDate Maximum allowed date
     * @param minAge Minimum age (for birth dates)
     * @return ValidationResult with status and message
     */
    public static ValidationResult validateDate(String dateStr, String format, 
                                               LocalDate minDate, LocalDate maxDate,
                                               Integer minAge) {
        if (dateStr == null || dateStr.trim().isEmpty()) {
            return new ValidationResult(false, "Date is required");
        }
        
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern(format);
        LocalDate date;
        
        try {
            date = LocalDate.parse(dateStr.trim(), formatter);
        } catch (DateTimeParseException e) {
            return new ValidationResult(false, 
                "Invalid date format. Please use format: " + format);
        }
        
        // Check minimum date
        if (minDate != null && date.isBefore(minDate)) {
            return new ValidationResult(false, 
                "Date cannot be before " + minDate.format(formatter));
        }
        
        // Check maximum date
        if (maxDate != null && date.isAfter(maxDate)) {
            return new ValidationResult(false, 
                "Date cannot be after " + maxDate.format(formatter));
        }
        
        // Check minimum age if applicable (for birth dates)
        if (minAge != null) {
            LocalDate ageThreshold = LocalDate.now().minusYears(minAge);
            if (date.isAfter(ageThreshold)) {
                return new ValidationResult(false, 
                    "Must be at least " + minAge + " years old");
            }
        }
        
        return new ValidationResult(true, null, date);
    }
    
    // Validation result class
    public static class ValidationResult {
        private final boolean valid;
        private final String errorMessage;
        private final LocalDate value;
        
        public ValidationResult(boolean valid, String errorMessage) {
            this(valid, errorMessage, null);
        }
        
        public ValidationResult(boolean valid, String errorMessage, LocalDate value) {
            this.valid = valid;
            this.errorMessage = errorMessage;
            this.value = value;
        }
        
        // Getters
        public boolean isValid() { return valid; }
        public String getErrorMessage() { return errorMessage; }
        public LocalDate getValue() { return value; }
    }
}
```

### 4. File Upload Validation
- I'll implement comprehensive file type verification
- I'll suggest secure size limit enforcement
- I'll provide content analysis approaches
- I'll recommend metadata stripping techniques
- I'll help prevent file upload vulnerabilities

**Implementation Focus:**
```javascript
const fs = require('fs');
const path = require('path');
const fileType = require('file-type');
const crypto = require('crypto');

/**
 * Validate and sanitize file uploads
 * @param {Object} file - The uploaded file object (e.g., from multer)
 * @param {Object} options - Validation options
 * @returns {Promise<Object>} Validation result
 */
async function validateFileUpload(file, options = {}) {
  // Default options
  const config = {
    maxSize: options.maxSize || 5 * 1024 * 1024, // 5MB default
    allowedMimeTypes: options.allowedMimeTypes || ['image/jpeg', 'image/png', 'image/gif', 'application/pdf'],
    allowedExtensions: options.allowedExtensions || ['jpg', 'jpeg', 'png', 'gif', 'pdf'],
    sanitizeFilename: options.sanitizeFilename !== false,
    checkContent: options.checkContent !== false,
  };
  
  const result = {
    valid: true,
    errors: [],
    sanitizedFile: null
  };
  
  // Check if file exists
  if (!file) {
    result.valid = false;
    result.errors.push('No file provided');
    return result;
  }
  
  // Check file size
  if (file.size > config.maxSize) {
    result.valid = false;
    result.errors.push(`File too large. Maximum size: ${config.maxSize / 1024 / 1024}MB`);
  }
  
  // Check file extension
  const ext = path.extname(file.originalname).toLowerCase().substring(1);
  if (!config.allowedExtensions.includes(ext)) {
    result.valid = false;
    result.errors.push(`File extension not allowed. Allowed extensions: ${config.allowedExtensions.join(', ')}`);
  }
  
  // Check MIME type based on content
  if (config.checkContent) {
    try {
      const buffer = file.buffer || await fs.promises.readFile(file.path);
      const detectedType = await fileType.fromBuffer(buffer);
      
      if (!detectedType || !config.allowedMimeTypes.includes(detectedType.mime)) {
        result.valid = false;
        result.errors.push('File content does not match allowed types');
      }
      
      // Check if extension matches detected MIME
      const expectedExts = {
        'image/jpeg': ['jpg', 'jpeg'],
        'image/png': ['png'],
        'image/gif': ['gif'],
        'application/pdf': ['pdf']
      };
      
      if (detectedType && expectedExts[detectedType.mime] && 
          !expectedExts[detectedType.mime].includes(ext)) {
        result.valid = false;
        result.errors.push('File extension does not match content');
      }
    } catch (err) {
      result.valid = false;
      result.errors.push('Error analyzing file content');
    }
  }
  
  // Sanitize filename
  if (config.sanitizeFilename) {
    const sanitizedName = sanitizeFilename(file.originalname);
    const uniqueName = `${Date.now()}-${crypto.randomBytes(8).toString('hex')}${path.extname(sanitizedName)}`;
    
    result.sanitizedFile = {
      ...file,
      originalname: sanitizedName,
      filename: uniqueName
    };
  } else {
    result.sanitizedFile = file;
  }
  
  return result;
}

// Helper function to sanitize filenames
function sanitizeFilename(filename) {
  // Remove potentially dangerous characters
  let sanitized = filename.replace(/[^\w\s.-]/g, '');
  // Replace spaces with underscores
  sanitized = sanitized.replace(/\s+/g, '_');
  return sanitized;
}
```

### 5. Structured Data Validation
- I'll implement schema-based validation approaches
- I'll suggest field-level and cross-field validation
- I'll provide nested data structure validation techniques
- I'll recommend handling for complex data types
- I'll help prevent deserialization vulnerabilities

**Implementation Focus:**
```python
from marshmallow import Schema, fields, validate, validates, validates_schema, ValidationError
from marshmallow.validate import Length, Range, OneOf, Regexp
import re

class AddressSchema(Schema):
    """Nested schema for address validation"""
    street = fields.String(required=True, validate=Length(min=1, max=100))
    city = fields.String(required=True, validate=Length(min=1, max=50))
    state = fields.String(required=True, validate=Length(equal=2))
    zip_code = fields.String(required=True, validate=Regexp(r'^\d{5}(-\d{4})?$'))
    country = fields.String(required=True, validate=Length(min=2, max=50))

class UserSchema(Schema):
    """Schema for comprehensive user data validation"""
    id = fields.UUID(dump_only=True)  # Read-only field
    
    username = fields.String(required=True, validate=[
        Length(min=3, max=30),
        Regexp(r'^[A-Za-z0-9_-]+$', error="Username can only contain letters, numbers, underscores and hyphens")
    ])
    
    email = fields.Email(required=True)
    
    password = fields.String(required=True, validate=[
        Length(min=8),
        Regexp(
            r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$',
            error="Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character"
        )
    ], load_only=True)  # Password is write-only
    
    age = fields.Integer(required=True, validate=Range(min=18, max=120))
    
    role = fields.String(validate=OneOf(['user', 'admin', 'moderator']))
    
    address = fields.Nested(AddressSchema, required=False)
    
    preferences = fields.Dict(keys=fields.String(), values=fields.Raw(), required=False)
    
    created_at = fields.DateTime(dump_only=True)  # Read-only field
    
    # Custom field-level validation
    @validates('email')
    def validate_email(self, email):
        if email.split('@')[1] == 'forbidden-domain.com':
            raise ValidationError("This email domain is not allowed")
    
    # Cross-field validation
    @validates_schema
    def validate_role_permissions(self, data, **kwargs):
        if data.get('role') == 'admin' and data.get('age', 0) < 21:
            raise ValidationError("Admin users must be at least 21 years old")
        
        if data.get('role') == 'admin' and not self._is_secure_password(data.get('password', '')):
            raise ValidationError("Admin accounts require stronger passwords")
    
    def _is_secure_password(self, password):
        """Additional password security checks for sensitive roles"""
        if len(password) < 12:
            return False
            
        # Check for common password patterns
        common_patterns = [
            r'password', r'123', r'qwerty', r'admin', 
            r'welcome', r'letmein', r'abc'
        ]
        for pattern in common_patterns:
            if re.search(pattern, password.lower()):
                return False
                
        return True
        
# Example usage
def validate_user_data(user_data):
    """
    Validates user data against schema
    
    Args:
        user_data: Dictionary containing user data
        
    Returns:
        tuple: (is_valid, errors_or_data)
    """
    schema = UserSchema()
    try:
        # Validate and deserialize input
        validated_data = schema.load(user_data)
        return True, validated_data
    except ValidationError as err:
        return False, err.messages
```

### 6. API Parameter Validation
- I'll implement query and path parameter validation
- I'll suggest header and cookie validation approaches
- I'll provide content negotiation validation
- I'll recommend API versioning validation
- I'll help prevent parameter pollution attacks

**Implementation Focus:**
```typescript
// Express API validation using express-validator
import { Request, Response, NextFunction } from 'express';
import { body, query, param, header, validationResult, ValidationChain } from 'express-validator';

// Validation chains for different API endpoint parameters
export const createUserValidation = [
  body('username')
    .trim()
    .isLength({ min: 3, max: 30 })
    .withMessage('Username must be 3-30 characters')
    .matches(/^[A-Za-z0-9_-]+$/)
    .withMessage('Username can only contain letters, numbers, underscores and hyphens')
    .escape(),
  
  body('email')
    .trim()
    .isEmail()
    .withMessage('Invalid email address')
    .normalizeEmail(),
  
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/)
    .withMessage('Password must include uppercase, lowercase, number and special character'),
    
  body('age')
    .isInt({ min: 18, max: 120 })
    .withMessage('Age must be between 18 and 120'),
];

export const getUserValidation = [
  param('id')
    .isUUID(4)
    .withMessage('Invalid user ID format'),
    
  query('fields')
    .optional()
    .isString()
    .withMessage('Fields parameter must be a string')
    .customSanitizer(value => value.split(','))
    .custom(fields => {
      const allowedFields = ['username', 'email', 'profile', 'status'];
      return fields.every(field => allowedFields.includes(field));
    })
    .withMessage('Invalid fields requested'),
    
  header('authorization')
    .matches(/^Bearer [A-Za-z0-9-_.]+$/)
    .withMessage('Invalid authorization header format'),
];

export const searchUsersValidation = [
  query('q')
    .optional()
    .isString()
    .withMessage('Search query must be a string')
    .isLength({ min: 2, max: 50 })
    .withMessage('Search query must be 2-50 characters'),
    
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be a positive integer')
    .toInt(),
    
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100')
    .toInt(),
    
  query('sort')
    .optional()
    .isIn(['username', 'email', 'created_at', 'updated_at'])
    .withMessage('Invalid sort field'),
    
  query('order')
    .optional()
    .isIn(['asc', 'desc'])
    .withMessage('Order must be asc or desc'),
];

// Generic validation middleware to be used with any validation chain
export const validate = (validations: ValidationChain[]) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    // Execute all validations
    await Promise.all(validations.map(validation => validation.run(req)));
    
    // Check for validation errors
    const errors = validationResult(req);
    if (errors.isEmpty()) {
      return next();
    }
    
    // Return validation errors
    return res.status(400).json({
      status: 'error',
      message: 'Validation failed',
      errors: errors.array()
    });
  };
};

// Example usage in routes
// router.post('/users', validate(createUserValidation), userController.createUser);
// router.get('/users/:id', validate(getUserValidation), userController.getUser);
// router.get('/users', validate(searchUsersValidation), userController.searchUsers);
```

### 7. Security Considerations for Input Validation
- I'll suggest defense in depth validation strategies
- I'll recommend secure failure handling approaches
- I'll provide canonicalization techniques
- I'll help balance security with performance
- I'll suggest customized validation based on risk

**Implementation Focus:**
```csharp
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using System.Security.Cryptography;

public class SecurityInputValidator
{
    // Defense-in-depth approach with multiple validation layers
    public ValidationResult ValidateSecuritySensitiveInput(string input, InputType inputType)
    {
        // Null check (fail fast)
        if (input == null)
        {
            return ValidationResult.Invalid("Input cannot be null");
        }
        
        // Size validation (prevent DoS)
        if (input.Length > GetMaximumLengthForInputType(inputType))
        {
            return ValidationResult.Invalid("Input exceeds maximum allowed length");
        }
        
        // Canonicalize input before further validation
        string canonicalized = CanonicalizeInput(input, inputType);
        
        // Format validation with appropriate validation strategy
        bool isValidFormat = ValidateFormatByInputType(canonicalized, inputType, out string formatError);
        if (!isValidFormat)
        {
            return ValidationResult.Invalid(formatError);
        }
        
        // Content security validation
        bool isSecure = ValidateContentSecurity(canonicalized, inputType, out string securityError);
        if (!isSecure)
        {
            return ValidationResult.Invalid(securityError);
        }
        
        // Pass content hash for integrity verification
        string contentHash = ComputeContentHash(canonicalized);
        
        // Input passed all validation checks
        return ValidationResult.Valid(canonicalized, contentHash);
    }
    
    // Determine maximum allowed length based on input type
    private int GetMaximumLengthForInputType(InputType inputType)
    {
        switch (inputType)
        {
            case InputType.Username:
                return 50;
            case InputType.Password:
                return 128;
            case InputType.Email:
                return 254; // RFC 5321 limit
            case InputType.CreditCard:
                return 19;  // With separators
            case InputType.Comment:
                return 1000;
            case InputType.Search:
                return 200;
            default:
                return 100;  // Default limit
        }
    }
    
    // Canonicalize input to a standard form before validation
    private string CanonicalizeInput(string input, InputType inputType)
    {
        // Trim whitespace for all inputs
        string result = input.Trim();
        
        // Type-specific canonicalization
        switch (inputType)
        {
            case InputType.Email:
                // Convert to lowercase
                result = result.ToLowerInvariant();
                break;
                
            case InputType.CreditCard:
                // Remove non-numeric characters
                result = Regex.Replace(result, @"\D", "");
                break;
                
            case InputType.Search:
                // Remove multiple spaces
                result = Regex.Replace(result, @"\s+", " ");
                break;
                
            case InputType.Username:
                // Convert to lowercase for case-insensitive comparisons
                result = result.ToLowerInvariant();
                break;
        }
        
        return result;
    }
    
    // Format validation based on input type
    private bool ValidateFormatByInputType(string input, InputType inputType, out string error)
    {
        error = string.Empty;
        
        switch (inputType)
        {
            case InputType.Email:
                // Use strict email validation
                if (!IsValidEmail(input))
                {
                    error = "Invalid email format";
                    return false;
                }
                break;
                
            case InputType.Username:
                // Alphanumeric plus limited symbols
                if (!Regex.IsMatch(input, @"^[a-z0-9_\-\.]+$"))
                {
                    error = "Username can only contain letters, numbers, underscores, periods, and hyphens";
                    return false;
                }
                break;
                
            case InputType.Password:
                // Password strength checks
                if (!IsStrongPassword(input))
                {
                    error = "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character";
                    return false;
                }
                break;
                
            case InputType.CreditCard:
                // Check using Luhn algorithm and length
                if (!IsValidCreditCard(input))
                {
                    error = "Invalid credit card number";
                    return false;
                }
                break;
        }
        
        return true;
    }
    
    // Security content validation
    private bool ValidateContentSecurity(string input, InputType inputType, out string error)
    {
        error = string.Empty;
        
        switch (inputType)
        {
            case InputType.Comment:
            case InputType.Search:
                // Check for common attack patterns
                if (ContainsSuspiciousPatterns(input))
                {
                    error = "Input contains potentially malicious content";
                    return false;
                }
                break;
        }
        
        return true;
    }
    
    // Helper methods for specific validations
    
    private bool IsValidEmail(string email)
    {
        try
        {
            // First, simple regex check
            if (!Regex.IsMatch(email, @"^[^@\s]+@[^@\s]+\.[^@\s]+$"))
            {
                return false;
            }
            
            // More detailed validation
            var addr = new System.Net.Mail.MailAddress(email);
            return addr.Address == email;
        }
        catch
        {
            return false;
        }
    }
    
    private bool IsStrongPassword(string password)
    {
        // At least 8 chars with uppercase, lowercase, number and special char
        return password.Length >= 8 &&
               Regex.IsMatch(password, "[A-Z]") &&
               Regex.IsMatch(password, "[a-z]") &&
               Regex.IsMatch(password, "[0-9]") &&
               Regex.IsMatch(password, "[^a-zA-Z0-9]");
    }
    
    private bool IsValidCreditCard(string ccNumber)
    {
        // Check length
        if (ccNumber.Length < 13 || ccNumber.Length > 19)
        {
            return false;
        }
        
        // Luhn algorithm (mod 10 check)
        int sum = 0;
        bool alternate = false;
        
        for (int i = ccNumber.Length - 1; i >= 0; i--)
        {
            int digit = ccNumber[i] - '0';
            
            if (alternate)
            {
                digit *= 2;
                if (digit > 9)
                {
                    digit -= 9;
                }
            }
            
            sum += digit;
            alternate = !alternate;
        }
        
        return sum % 10 == 0;
    }
    
    private bool ContainsSuspiciousPatterns(string input)
    {
        // Check for common attack vectors (very basic check - would be more comprehensive in production)
        string[] suspiciousPatterns = {
            "<script", "javascript:", "onerror=", "onload=", "onclick=", 
            "eval(", "document.cookie", "alert(", "prompt(", 
            "SELECT.*FROM", "UNION.*SELECT", "DROP.*TABLE",
            "--", "/*", "*/", "';", "';--", "';#"
        };
        
        foreach (var pattern in suspiciousPatterns)
        {
            if (input.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return true;
            }
        }
        
        return false;
    }
    
    private string ComputeContentHash(string input)
    {
        using (SHA256 sha256 = SHA256.Create())
        {
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            byte[] hashBytes = sha256.ComputeHash(inputBytes);
            
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < hashBytes.Length; i++)
            {
                builder.Append(hashBytes[i].ToString("x2"));
            }
            
            return builder.ToString();
        }
    }
}

public enum InputType
{
    Username,
    Password,
    Email,
    CreditCard,
    Comment,
    Search
}

public class ValidationResult
{
    public bool IsValid { get; private set; }
    public string ValidationMessage { get; private set; }
    public string SanitizedValue { get; private set; }
    public string ContentHash { get; private set; }
    
    private ValidationResult(bool isValid, string message, string sanitized = null, string hash = null)
    {
        IsValid = isValid;
        ValidationMessage = message;
        SanitizedValue = sanitized;
        ContentHash = hash;
    }
    
    public static ValidationResult Valid(string sanitized, string hash = null)
    {
        return new ValidationResult(true, "Validation passed", sanitized, hash);
    }
    
    public static ValidationResult Invalid(string message)
    {
        return new ValidationResult(false, message);
    }
}
```

## Output Format

When suggesting input validation implementations, I will provide:

1. **Analysis of Input Types** - Identify what types of input need validation and their security requirements
2. **Language-Specific Approaches** - Suggest validation techniques appropriate for the programming language and framework
3. **Comprehensive Validation Strategy** - Consider defense in depth across multiple application layers
4. **Example Implementation** - Provide working code examples with proper error handling
5. **Security Considerations** - Highlight specific security concerns for the validation context

**Example Structure:**
```markdown
## Input Validation Analysis

The user registration endpoint needs validation for these inputs:
- Username (text input with character restrictions)
- Email (format validation)
- Password (strength requirements)
- Age (numeric range validation)

## Validation Strategy

I recommend implementing validation at multiple layers:
1. **Client-side validation** for immediate user feedback
2. **API endpoint validation** as the primary security control
3. **Service-layer validation** for defense in depth

## Implementation Approach

For Express.js applications, express-validator is the recommended approach:

```javascript
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
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/)
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
  // ...
});
```

## Security Considerations

- **Validation Bypass Protection**: All input parameters are normalized and canonicalized before validation
- **Failure Handling**: Validation failures return 400 Bad Request with specific error messages
- **Error Messages**: Detailed enough for legitimate users but don't reveal system details
- **Sanitization**: User-controlled text is escaped to prevent XSS attacks

## Additional Recommendations

1. Consider adding rate limiting for registration attempts
2. Store validation errors in logs for security monitoring
3. Implement CAPTCHA for registration to prevent automated attacks
```
