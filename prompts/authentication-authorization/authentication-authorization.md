# Authentication and Authorization Prompt

## Overview

This prompt guides you in implementing secure authentication and authorization mechanisms for your applications. Proper implementation of these security controls is fundamental to protecting user data, preventing unauthorized access, and maintaining the integrity of your systems.

## How to Use This Prompt

1. Provide details about your application type (web app, API, mobile app, etc.)
2. Specify your tech stack/programming language
3. Describe your authentication requirements (e.g., MFA, SSO, passwordless)
4. Mention any authorization needs (RBAC, ABAC, etc.)
5. Include compliance requirements if applicable (GDPR, HIPAA, etc.)

## Example Prompts

```
Create a secure authentication system for a Node.js/Express application using JWT tokens. Include user registration, login, password reset, and MFA functionality. Implementation should follow OWASP security best practices.
```

```
Implement RBAC (Role-Based Access Control) for a Python FastAPI backend that serves a healthcare application. The system needs to support multiple user types: Patients, Doctors, Nurses, and Administrators. Include code for middleware that enforces authorization checks on API endpoints.
```

## Core Authentication Principles

### 1. Authentication Factors
- **Something you know**: Passwords, PINs, security questions
- **Something you have**: Mobile device, hardware token, smart card
- **Something you are**: Biometrics (fingerprint, face, voice)
- **Somewhere you are**: Geolocation
- **Something you do**: Behavior patterns, typing rhythm

### 2. Password Security
- Use secure password hashing (bcrypt, Argon2, PBKDF2)
- Implement robust password policies
- Avoid composition rules that lead to predictable patterns
- Enforce minimum password length (12+ characters recommended)
- Check passwords against breach databases

### 3. Multi-Factor Authentication (MFA)
- Implement TOTP (Time-based One-Time Passwords)
- Support hardware security keys (FIDO2/WebAuthn)
- Provide backup authentication methods
- Apply MFA selectively based on risk assessment
- Secure the MFA enrollment process

### 4. Session Management
- Generate strong session identifiers
- Implement secure cookie attributes (Secure, HttpOnly, SameSite)
- Set appropriate session timeout periods
- Provide session termination functionality
- Track concurrent sessions
- Implement session binding to prevent hijacking

### 5. Authentication Workflows
- Secure user registration process
- Implement account recovery securely
- Apply rate limiting on authentication attempts
- Use secure notification for security events
- Implement progressive authentication for sensitive operations

## Core Authorization Principles

### 1. Authorization Models
- **RBAC**: Role-Based Access Control
- **ABAC**: Attribute-Based Access Control
- **PBAC**: Policy-Based Access Control
- **ReBAC**: Relationship-Based Access Control
- **CBAC**: Context-Based Access Control

### 2. Authorization Design
- Apply principle of least privilege
- Implement defense in depth
- Centralize authorization logic
- Use declarative over imperative permissions
- Consider authorization granularity needs

### 3. Access Control Implementation
- Validate authorization on server-side
- Implement proper access control checks
- Apply API endpoint protections
- Protect sensitive operations with step-up authentication
- Implement proper object-level authorization

### 4. Authorization Context
- Consider environmental factors (time, location)
- Implement dynamic authorization rules
- Apply contextual integrity principles
- Handle delegation of authority securely
- Support temporary elevated privileges

## Implementation Examples

### Node.js/Express Authentication with JWT

```javascript
// Required packages
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');

const app = express();
app.use(express.json());

// Mock database
const users = [];

// Rate limiting middleware
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: {
    status: 'error',
    message: 'Too many login attempts. Please try again later.'
  }
});

// User registration
app.post('/register', [
  // Input validation
  body('email').isEmail().normalizeEmail(),
  body('password')
    .isLength({ min: 12 })
    .withMessage('Password must be at least 12 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must include lowercase, uppercase, number, and special character'),
  body('name').trim().notEmpty()
], async (req, res) => {
  // Check for validation errors
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ status: 'error', errors: errors.array() });
  }

  const { email, password, name } = req.body;

  // Check if user exists
  const userExists = users.find(u => u.email === email);
  if (userExists) {
    return res.status(400).json({
      status: 'error',
      message: 'User already exists'
    });
  }

  // Hash password
  const salt = await bcrypt.genSalt(12);
  const hashedPassword = await bcrypt.hash(password, salt);

  // Create MFA secret
  const mfaSecret = speakeasy.generateSecret({
    name: `MyApp:${email}`
  });

  // Create user
  const user = {
    id: Date.now().toString(),
    name,
    email,
    password: hashedPassword,
    mfaSecret: mfaSecret.base32,
    mfaEnabled: false,
    roles: ['user'],
    createdAt: new Date()
  };

  users.push(user);

  // Generate QR code for MFA setup
  const qrCodeUrl = await qrcode.toDataURL(mfaSecret.otpauth_url);

  res.status(201).json({
    status: 'success',
    message: 'User registered successfully',
    data: {
      userId: user.id,
      email: user.email,
      name: user.name,
      mfaQrCode: qrCodeUrl
    }
  });
});

// MFA setup completion
app.post('/setup-mfa', authenticateToken, async (req, res) => {
  const { token } = req.body;
  const userId = req.user.id;
  
  // Find user
  const user = users.find(u => u.id === userId);
  
  // Verify token
  const verified = speakeasy.totp.verify({
    secret: user.mfaSecret,
    encoding: 'base32',
    token
  });
  
  if (!verified) {
    return res.status(400).json({
      status: 'error',
      message: 'Invalid MFA token'
    });
  }
  
  // Enable MFA
  user.mfaEnabled = true;
  
  res.json({
    status: 'success',
    message: 'MFA setup completed successfully'
  });
});

// User login
app.post('/login', authLimiter, async (req, res) => {
  const { email, password, mfaToken } = req.body;
  
  // Find user
  const user = users.find(u => u.email === email);
  if (!user) {
    // Use consistent response time to prevent timing attacks
    await bcrypt.hash('dummy-password', 12);
    return res.status(401).json({
      status: 'error',
      message: 'Invalid credentials'
    });
  }
  
  // Validate password
  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) {
    return res.status(401).json({
      status: 'error',
      message: 'Invalid credentials'
    });
  }
  
  // Check MFA if enabled
  if (user.mfaEnabled) {
    if (!mfaToken) {
      return res.status(401).json({
        status: 'error',
        message: 'MFA token required',
        requireMfa: true
      });
    }
    
    const verified = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: 'base32',
      token: mfaToken,
      window: 1 // Allow 30 seconds before/after
    });
    
    if (!verified) {
      return res.status(401).json({
        status: 'error',
        message: 'Invalid MFA token'
      });
    }
  }
  
  // Generate JWT token
  const token = jwt.sign(
    { id: user.id, email: user.email, roles: user.roles },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );
  
  // Generate refresh token with longer expiry
  const refreshToken = jwt.sign(
    { id: user.id },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: '7d' }
  );
  
  // Log successful login
  console.log(`User ${user.email} logged in at ${new Date().toISOString()}`);
  
  res.json({
    status: 'success',
    message: 'Login successful',
    data: {
      token,
      refreshToken,
      expiresIn: 3600, // 1 hour in seconds
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        roles: user.roles
      }
    }
  });
});

// Token refresh endpoint
app.post('/refresh-token', (req, res) => {
  const { refreshToken } = req.body;
  
  if (!refreshToken) {
    return res.status(401).json({
      status: 'error',
      message: 'Refresh token required'
    });
  }
  
  try {
    // Verify refresh token
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    
    // Find user
    const user = users.find(u => u.id === decoded.id);
    if (!user) {
      return res.status(401).json({
        status: 'error',
        message: 'Invalid refresh token'
      });
    }
    
    // Generate new access token
    const token = jwt.sign(
      { id: user.id, email: user.email, roles: user.roles },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    
    res.json({
      status: 'success',
      message: 'Token refreshed',
      data: {
        token,
        expiresIn: 3600
      }
    });
  } catch (error) {
    return res.status(401).json({
      status: 'error',
      message: 'Invalid refresh token'
    });
  }
});

// Password reset request
app.post('/reset-password-request', async (req, res) => {
  const { email } = req.body;
  
  // Find user
  const user = users.find(u => u.email === email);
  
  // Always return success even if email doesn't exist (prevent email enumeration)
  if (user) {
    // Generate reset token (in a real app, store this securely with an expiry)
    const resetToken = jwt.sign(
      { id: user.id },
      process.env.JWT_RESET_SECRET,
      { expiresIn: '15m' }
    );
    
    // In a real app, send email with reset link
    console.log(`Reset token for ${email}: ${resetToken}`);
  }
  
  res.json({
    status: 'success',
    message: 'If your email exists in our system, you will receive a password reset link'
  });
});

// Password reset completion
app.post('/reset-password', [
  body('token').notEmpty(),
  body('password')
    .isLength({ min: 12 })
    .withMessage('Password must be at least 12 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must include lowercase, uppercase, number, and special character')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ status: 'error', errors: errors.array() });
  }
  
  const { token, password } = req.body;
  
  try {
    // Verify reset token
    const decoded = jwt.verify(token, process.env.JWT_RESET_SECRET);
    
    // Find user
    const user = users.find(u => u.id === decoded.id);
    if (!user) {
      return res.status(400).json({
        status: 'error',
        message: 'Invalid or expired token'
      });
    }
    
    // Hash new password
    const salt = await bcrypt.genSalt(12);
    user.password = await bcrypt.hash(password, salt);
    
    // In a real app, invalidate all existing sessions
    
    res.json({
      status: 'success',
      message: 'Password reset successful'
    });
  } catch (error) {
    res.status(400).json({
      status: 'error',
      message: 'Invalid or expired token'
    });
  }
});

// Middleware to authenticate token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({
      status: 'error',
      message: 'Authentication required'
    });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({
      status: 'error',
      message: 'Invalid or expired token'
    });
  }
}

// Middleware for role-based authorization
function authorize(roles = []) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        status: 'error',
        message: 'Authentication required'
      });
    }
    
    const userRoles = req.user.roles || [];
    const hasAuthorizedRole = roles.some(role => userRoles.includes(role));
    
    if (!hasAuthorizedRole) {
      return res.status(403).json({
        status: 'error',
        message: 'Insufficient permissions'
      });
    }
    
    next();
  };
}

// Protected route example with role-based authorization
app.get('/admin/users', authenticateToken, authorize(['admin']), (req, res) => {
  // Only accessible to users with admin role
  const usersList = users.map(u => ({
    id: u.id,
    name: u.name,
    email: u.email,
    roles: u.roles,
    mfaEnabled: u.mfaEnabled,
    createdAt: u.createdAt
  }));
  
  res.json({
    status: 'success',
    data: usersList
  });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
```

### Python FastAPI RBAC Implementation

```python
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
import secrets
from enum import Enum

# Database models and session management would be defined here
# For simplicity, we'll use in-memory data structures

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT configuration
SECRET_KEY = secrets.token_urlsafe(32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI(title="Healthcare API with RBAC")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Role enum
class Role(str, Enum):
    ADMIN = "admin"
    DOCTOR = "doctor"
    NURSE = "nurse"
    PATIENT = "patient"

# User model
class User(BaseModel):
    id: int
    username: str
    email: str
    full_name: str
    hashed_password: str
    disabled: bool = False
    roles: List[Role]

# Token model
class Token(BaseModel):
    access_token: str
    token_type: str

# Token data model
class TokenData(BaseModel):
    username: Optional[str] = None
    roles: Optional[List[Role]] = None

# Mock database
fake_users_db = {
    "admin": {
        "id": 1,
        "username": "admin",
        "email": "admin@example.com",
        "full_name": "Admin User",
        "hashed_password": pwd_context.hash("adminpassword"),
        "roles": [Role.ADMIN]
    },
    "doctor": {
        "id": 2,
        "username": "doctor",
        "email": "doctor@example.com",
        "full_name": "Doctor Smith",
        "hashed_password": pwd_context.hash("doctorpassword"),
        "roles": [Role.DOCTOR]
    },
    "nurse": {
        "id": 3,
        "username": "nurse",
        "email": "nurse@example.com",
        "full_name": "Nurse Johnson",
        "hashed_password": pwd_context.hash("nursepassword"),
        "roles": [Role.NURSE]
    },
    "patient": {
        "id": 4,
        "username": "patient",
        "email": "patient@example.com",
        "full_name": "Patient Doe",
        "hashed_password": pwd_context.hash("patientpassword"),
        "roles": [Role.PATIENT]
    }
}

# Patient record model
class PatientRecord(BaseModel):
    id: int
    patient_id: int
    doctor_id: int
    diagnosis: str
    notes: str
    created_at: datetime

# Mock patient records
fake_patient_records = [
    {
        "id": 1,
        "patient_id": 4,
        "doctor_id": 2,
        "diagnosis": "Common cold",
        "notes": "Rest and fluids recommended",
        "created_at": datetime.now() - timedelta(days=5)
    },
    {
        "id": 2,
        "patient_id": 4,
        "doctor_id": 2,
        "diagnosis": "Annual checkup",
        "notes": "All tests normal",
        "created_at": datetime.now() - timedelta(days=1)
    }
]

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_user(username: str):
    if username in fake_users_db:
        user_dict = fake_users_db[username]
        return User(**user_dict)
    return None

def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        role_values = payload.get("roles", [])
        roles = [Role(role) for role in role_values]
        token_data = TokenData(username=username, roles=roles)
    except JWTError:
        raise credentials_exception
    user = get_user(token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

# Role-based authorization dependency
def RoleChecker(allowed_roles: List[Role]):
    async def check_role(current_user: User = Depends(get_current_active_user)):
        if not any(role in allowed_roles for role in current_user.roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation not permitted. Required roles: {allowed_roles}"
            )
        return current_user
    return check_role

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    role_values = [role.value for role in user.roles]
    access_token = create_access_token(
        data={"sub": user.username, "roles": role_values},
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    # Remove sensitive fields for response
    user_dict = current_user.dict()
    user_dict.pop("hashed_password", None)
    return user_dict

@app.get("/admin/users")
async def admin_get_users(
    current_user: User = Depends(RoleChecker([Role.ADMIN]))
):
    # Only accessible to admins
    users = []
    for username, user_data in fake_users_db.items():
        user = dict(user_data)
        user.pop("hashed_password", None)  # Remove sensitive info
        users.append(user)
    return users

@app.get("/patients")
async def get_patients(
    current_user: User = Depends(RoleChecker([Role.DOCTOR, Role.NURSE, Role.ADMIN]))
):
    # Only accessible to medical staff and admins
    patients = []
    for username, user_data in fake_users_db.items():
        if Role.PATIENT in user_data["roles"]:
            patient = dict(user_data)
            patient.pop("hashed_password", None)  # Remove sensitive info
            patients.append(patient)
    return patients

@app.get("/patient-records")
async def get_all_patient_records(
    current_user: User = Depends(RoleChecker([Role.ADMIN]))
):
    # Only accessible to admins
    return fake_patient_records

@app.get("/patient-records/{patient_id}")
async def get_patient_records(
    patient_id: int,
    current_user: User = Depends(get_current_active_user)
):
    # Custom authorization logic
    if Role.PATIENT in current_user.roles:
        # Patients can only view their own records
        if current_user.id != patient_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only access your own records"
            )
    elif not any(role in [Role.DOCTOR, Role.NURSE, Role.ADMIN] for role in current_user.roles):
        # Only medical staff or the patient themselves can access records
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to access patient records"
        )
    
    # Filter records for the specified patient
    records = [r for r in fake_patient_records if r["patient_id"] == patient_id]
    return records

@app.post("/patient-records")
async def create_patient_record(
    record: PatientRecord,
    current_user: User = Depends(RoleChecker([Role.DOCTOR, Role.ADMIN]))
):
    # Only doctors and admins can create records
    # In a real app, we would save to database
    fake_patient_records.append(record.dict())
    return {"status": "success", "message": "Record created"}

@app.put("/patient-records/{record_id}")
async def update_patient_record(
    record_id: int,
    record_data: dict,
    current_user: User = Depends(RoleChecker([Role.DOCTOR, Role.ADMIN]))
):
    # Only doctors and admins can update records
    for record in fake_patient_records:
        if record["id"] == record_id:
            # If doctor, check if they are the original author
            if Role.DOCTOR in current_user.roles and Role.ADMIN not in current_user.roles:
                if record["doctor_id"] != current_user.id:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="You can only modify your own records"
                    )
            # Update record fields
            for key, value in record_data.items():
                if key != "id":  # Prevent changing the ID
                    record[key] = value
            return {"status": "success", "message": "Record updated"}
    
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Record with ID {record_id} not found"
    )

@app.delete("/patient-records/{record_id}")
async def delete_patient_record(
    record_id: int,
    current_user: User = Depends(RoleChecker([Role.ADMIN]))
):
    # Only admins can delete records
    for i, record in enumerate(fake_patient_records):
        if record["id"] == record_id:
            del fake_patient_records[i]
            return {"status": "success", "message": "Record deleted"}
    
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Record with ID {record_id} not found"
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

### Java Spring Boot Role and Permission Based Authorization

```java
// User entity
@Entity
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false, unique = true)
    private String email;

    private boolean enabled = true;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
        name = "user_roles",
        joinColumns = @JoinColumn(name = "user_id"),
        inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Role> roles = new HashSet<>();

    // Getters and setters
}

// Role entity
@Entity
@Table(name = "roles")
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, unique = true)
    private ERole name;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
        name = "role_permissions",
        joinColumns = @JoinColumn(name = "role_id"),
        inverseJoinColumns = @JoinColumn(name = "permission_id")
    )
    private Set<Permission> permissions = new HashSet<>();

    // Getters and setters
}

// Permission entity
@Entity
@Table(name = "permissions")
public class Permission {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String name;

    // Getters and setters
}

// Role enum
public enum ERole {
    ROLE_USER,
    ROLE_MODERATOR,
    ROLE_ADMIN
}

// Custom security expression
@Component
public class CustomSecurityExpression {
    
    public boolean hasPermission(Authentication authentication, String permission) {
        if (authentication == null || !(authentication.getPrincipal() instanceof UserDetailsImpl)) {
            return false;
        }
        
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        
        return userDetails.getAuthorities().stream()
            .filter(auth -> auth instanceof GrantedAuthority)
            .map(GrantedAuthority::getAuthority)
            .anyMatch(auth -> auth.equals(permission));
    }
}

// Security configuration
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(
    prePostEnabled = true,
    securedEnabled = true,
    jsr250Enabled = true
)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter() {
        return new AuthTokenFilter();
    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors().and().csrf().disable()
            .exceptionHandling().authenticationEntryPoint(unauthorizedHandler).and()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
            .authorizeRequests()
                .antMatchers("/api/auth/**").permitAll()
                .antMatchers("/api/public/**").permitAll()
                .antMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated();
        
        http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);
    }
}

// JWT utilities
@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${app.jwtSecret}")
    private String jwtSecret;

    @Value("${app.jwtExpirationMs}")
    private int jwtExpirationMs;

    public String generateJwtToken(Authentication authentication) {
        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();

        return Jwts.builder()
                .setSubject(userPrincipal.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }

    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
    }

    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }

        return false;
    }
}

// Example controller with fine-grained authorization
@RestController
@RequestMapping("/api/resources")
public class ResourceController {

    @GetMapping
    @PreAuthorize("hasRole('ROLE_USER')")
    public ResponseEntity<List<Resource>> getAllResources() {
        // All authenticated users can view resources
        return ResponseEntity.ok(resourceService.findAll());
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ROLE_USER')")
    public ResponseEntity<Resource> getResource(@PathVariable Long id) {
        return ResponseEntity.ok(resourceService.findById(id));
    }

    @PostMapping
    @PreAuthorize("hasPermission(#resource, 'CREATE_RESOURCE')")
    public ResponseEntity<Resource> createResource(@RequestBody Resource resource) {
        return ResponseEntity.status(HttpStatus.CREATED).body(resourceService.save(resource));
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasPermission(#resource, 'EDIT_RESOURCE')")
    public ResponseEntity<Resource> updateResource(@PathVariable Long id, @RequestBody Resource resource) {
        return ResponseEntity.ok(resourceService.update(id, resource));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<Void> deleteResource(@PathVariable Long id) {
        // Only admins can delete resources
        resourceService.delete(id);
        return ResponseEntity.noContent().build();
    }

    // Custom permission check with data-based authorization
    @PatchMapping("/{id}/status")
    @PreAuthorize("hasRole('ROLE_MODERATOR') or @customSecurityExpression.hasPermission(authentication, 'APPROVE_RESOURCE')")
    public ResponseEntity<Resource> updateResourceStatus(
            @PathVariable Long id, 
            @RequestParam String status) {
        Resource resource = resourceService.findById(id);
        
        // Additional data-based authorization
        if ("PUBLISHED".equals(status) && !SecurityUtils.isAdmin()) {
            // Check if current user owns this resource
            if (!SecurityUtils.getCurrentUserId().equals(resource.getOwnerId())) {
                throw new AccessDeniedException("You can only publish your own resources");
            }
        }
        
        resource = resourceService.updateStatus(id, status);
        return ResponseEntity.ok(resource);
    }
}
```

## Security Considerations

### Authentication Security
- **Protect Against Brute Force**: Implement rate limiting, account lockout
- **Secure Credential Storage**: Hash passwords with strong algorithms, never store plaintext 
- **Manage Sessions Securely**: Use secure cookies, proper expiration, rotation
- **Secure Account Recovery**: Avoid security questions, implement secure reset flows
- **Defend Against Common Attacks**: CSRF, session fixation, clickjacking

### Authorization Security
- **Validate on Server-Side**: Never trust client-side authorization checks
- **Fail Securely**: Default to deny access when authorization fails
- **Defense in Depth**: Apply authorization at multiple layers
- **Complete Mediation**: Verify authorization for every request
- **Least Privilege**: Limit permissions to what's strictly necessary

### Additional Security Measures
- **Secure Headers**: Use HTTP security headers (Content-Security-Policy, etc.)
- **Audit Logging**: Record authentication and authorization events
- **Intrusion Detection**: Monitor for suspicious authentication patterns
- **Secure Defaults**: Deny access by default, require explicit grants
- **Regular Testing**: Conduct security reviews and penetration testing

## Best Practices

1. **Never Store Plaintext Passwords**
   - Always use secure hashing algorithms with proper salting
   - Consider using specialized libraries like Argon2, bcrypt, or PBKDF2

2. **Implement Multi-Factor Authentication**
   - Offer MFA as a security enhancement
   - Consider making it mandatory for privileged accounts
   - Support multiple second factor options

3. **Use Strong Session Management**
   - Generate cryptographically secure session identifiers
   - Set proper cookie security attributes
   - Implement absolute and idle timeouts
   - Provide session termination functionality

4. **Apply the Principle of Least Privilege**
   - Grant minimal permissions necessary for the user's role
   - Use time-limited and context-aware permissions when possible
   - Implement just-in-time privilege escalation for sensitive operations

5. **Implement Proper Error Messages**
   - Use generic error messages for authentication failures
   - Avoid information disclosure through error messages
   - Provide detailed error logs for administrators

6. **Secure Communications**
   - Use HTTPS for all authentication and authorization traffic
   - Implement HSTS to prevent downgrade attacks
   - Consider certificate pinning for mobile applications

7. **Regular Security Updates**
   - Keep authentication libraries and frameworks updated
   - Monitor for security vulnerabilities in dependencies
   - Have a process for emergency security updates

8. **Test Authentication and Authorization**
   - Conduct regular security testing
   - Include authentication bypass scenarios in tests
   - Test for common authorization flaws like IDOR
