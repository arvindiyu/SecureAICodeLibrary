# Secure Coding Prompt: FastAPI (Python)

## Purpose

This prompt guides you in implementing secure coding practices for FastAPI applications. Use this prompt to generate code that follows security best practices and avoids common vulnerabilities in FastAPI projects.

## Secure FastAPI Development Prompt

```
As a secure FastAPI developer, help me implement [FEATURE/FUNCTIONALITY] with security as a priority. 

Consider these security aspects in your implementation:
1. Input validation and data parsing
2. Authentication and authorization
3. Dependency injection for secure services
4. Protection against common API vulnerabilities (injection, BOLA, broken authentication)
5. Secure dependency management
6. Error handling that doesn't leak sensitive information
7. Security headers and CORS configuration
8. Proper logging (without sensitive data)
9. Rate limiting and resource protection
10. Data encryption where needed

Technical requirements:
- FastAPI version: [version]
- Authentication method: [OAuth2 with JWT, OAuth2 with Password flow, API keys, etc.]
- Database ORM: [SQLAlchemy, Tortoise-ORM, etc.]
- Environment: [Production, Development, etc.]

Follow these FastAPI security best practices:
- Use Pydantic models for strict input validation and type checking
- Implement proper dependency injection for security components
- Use parameterized queries with SQLAlchemy to prevent SQL injection
- Configure proper CORS policies to prevent cross-origin attacks
- Apply OAuth2 security scopes to control access to endpoints
- Implement proper error handling with HTTPException
- Use secure password hashing with Passlib and bcrypt
```

## Security Considerations for FastAPI

### Authentication & Authorization

- **OAuth2 with JWT**: Properly configure JWT security with secure algorithms, reasonable expiration times
- **Password Hashing**: Use Passlib with bcrypt for secure password storage
- **Dependency Injection**: Use FastAPI's dependency system for authorization checks
- **Scopes and Permissions**: Implement fine-grained permission control with OAuth2 scopes

### Input Validation

- **Pydantic Models**: Use strict Pydantic models with field validation
- **Request Body Parsing**: Validate and sanitize all input data
- **Path and Query Parameters**: Apply constraints and validation

### Dependency Management

- **Requirements Pinning**: Pin dependency versions in requirements.txt
- **Vulnerability Scanning**: Regular scanning of dependencies with safety or pip-audit
- **Minimal Dependencies**: Include only necessary packages

### API Security

- **Security Headers**: Configure proper security headers using middleware
- **CORS Configuration**: Implement strict CORS policies
- **Rate Limiting**: Implement rate limiting with FastAPI middleware or external tools
- **Request Validation**: Validate all incoming requests thoroughly

### Database Security

- **ORM Usage**: Use SQLAlchemy with parameterized queries
- **Connection Pooling**: Configure proper connection pooling
- **Least Privilege**: Use database accounts with minimal privileges
- **Query Sanitization**: Avoid raw SQL, use ORM methods or parameterized queries

## Example Implementation: Secure User Authentication

```python
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import Optional
import os

# Models
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class User(BaseModel):
    username: str
    email: str
    full_name: Optional[str] = None
    disabled: Optional[bool] = False

class UserInDB(User):
    hashed_password: str

# Security utilities
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Configuration - in production, use environment variables or a secure vault
SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

# User functions
def get_user(db, username: str):
    # In real implementation, query the database
    # This is just a demonstration
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)
    return None

def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

# Token functions
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Dependency for getting current user
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
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
        
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

# FastAPI app
app = FastAPI()

# Authentication endpoint
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Protected endpoint
@app.get("/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user
```

## Security Testing for FastAPI

### Automated Testing

- Use `pytest` with FastAPI TestClient
- Implement security-focused tests for authentication, authorization, input validation
- Test rate limiting and CORS configurations

### Common Vulnerabilities to Test

- **SQL Injection**: Test parameterized queries with edge cases
- **Broken Authentication**: Test token expiration, validation, revocation
- **Excessive Data Exposure**: Verify response models are properly defined
- **Broken Access Control**: Test role-based access controls
- **Security Misconfiguration**: Test proper HTTP security headers

## References

- FastAPI Security Documentation: https://fastapi.tiangolo.com/tutorial/security/
- OWASP API Security Top 10: https://owasp.org/www-project-api-security/
- Pydantic Documentation: https://docs.pydantic.dev/latest/
- SQLAlchemy ORM Documentation: https://docs.sqlalchemy.org/en/20/orm/
