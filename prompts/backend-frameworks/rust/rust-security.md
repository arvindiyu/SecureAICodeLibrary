# Rust Security Best Practices

## Prompt

As a Rust Security Specialist, help me implement secure Rust code that leverages the language's safety features while also addressing security concerns that the compiler cannot protect against. I need guidance on memory safety, concurrency, dependency management, cryptography, error handling, and secure API design in Rust.

### Memory Safety & Ownership
- Avoid unsafe code blocks unless absolutely necessary
- Use proper ownership and borrowing patterns
- Implement proper lifetime annotations
- Use references over raw pointers
- Leverage Rust's type system for safety guarantees

### Concurrency & Threading
- Use message-passing concurrency with channels
- Avoid data races by respecting Rust's ownership rules
- Use thread-safe data structures from std::sync
- Implement proper synchronization mechanisms
- Be cautious with Mutex and RwLock to prevent deadlocks

### Dependency Management
- Audit dependencies regularly with `cargo audit`
- Pin dependency versions to prevent supply chain attacks
- Minimize dependencies to reduce attack surface
- Use well-maintained crates from trusted sources
- Check for security advisories before adding dependencies

### Cryptography
- Use established cryptography crates (ring, RustCrypto)
- Never implement your own cryptographic algorithms
- Use secure random number generators
- Implement proper key management
- Follow cryptographic best practices for your use case

### Error Handling
- Use Result and Option types for error handling
- Avoid unwrap() and expect() in production code
- Implement proper error propagation with the ? operator
- Create custom error types for better error handling
- Ensure errors don't leak sensitive information

### API Security
- Implement proper input validation
- Use strong typing to prevent injection attacks
- Implement proper authentication and authorization
- Follow the principle of least privilege
- Use HTTPS for all API endpoints
- Implement rate limiting to prevent abuse

## Example Implementations

### Secure Memory Management

```rust
// INSECURE: Using unsafe code unnecessarily
fn insecure_example() {
    let mut data = vec![1, 2, 3, 4];
    let ptr = data.as_mut_ptr();
    
    unsafe {
        // Direct pointer manipulation can lead to memory safety issues
        *ptr.offset(2) = 10;
    }
}

// SECURE: Using Rust's safe abstractions
fn secure_example() {
    let mut data = vec![1, 2, 3, 4];
    
    // Use safe indexing with bounds checking
    if data.len() > 2 {
        data[2] = 10;
    }
}
```

### Secure Concurrency

```rust
use std::sync::{Arc, Mutex};
use std::thread;

// INSECURE: Potential for deadlocks and unclear ownership
fn insecure_concurrency() {
    let counter = Mutex::new(0);
    
    let handle = thread::spawn(move || {
        let mut num = counter.lock().unwrap();
        *num += 1;
        
        // Lock is still held here, potential deadlock if another lock is acquired
        let mut other_lock = other_resource.lock().unwrap();
    });
    
    handle.join().unwrap();
}

// SECURE: Proper concurrency with clear ownership and lock management
fn secure_concurrency() {
    let counter = Arc::new(Mutex::new(0));
    let counter_clone = Arc::clone(&counter);
    
    let handle = thread::spawn(move || {
        // Scope the lock to minimize the duration it's held
        {
            let mut num = counter_clone.lock().unwrap();
            *num += 1;
        } // Lock is released here
        
        // Perform other operations without holding the lock
    });
    
    handle.join().unwrap();
}
```

### Secure API Implementation with Actix-Web

```rust
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use actix_web::middleware::{Logger, DefaultHeaders};
use serde::{Deserialize, Serialize};
use validator::Validate;

// Use strong typing and validation for request data
#[derive(Debug, Deserialize, Validate)]
struct UserRequest {
    #[validate(length(min = 3, max = 50))]
    username: String,
    
    #[validate(email)]
    email: String,
}

#[derive(Serialize)]
struct UserResponse {
    id: u64,
    username: String,
}

async fn create_user(
    // Use extractors for automatic validation
    user: web::Json<UserRequest>,
    // Use dependency injection for services
    db: web::Data<DbPool>,
) -> impl Responder {
    // Validate input data
    if let Err(errors) = user.validate() {
        return HttpResponse::BadRequest().json(errors);
    }
    
    // Use parameterized queries to prevent SQL injection
    let result = db
        .execute(
            "INSERT INTO users (username, email) VALUES ($1, $2) RETURNING id",
            &[&user.username, &user.email]
        )
        .await;
    
    match result {
        Ok(row) => {
            let id: u64 = row.get(0);
            let response = UserResponse {
                id,
                username: user.username.clone(),
            };
            HttpResponse::Created().json(response)
        },
        Err(err) => {
            // Log error details internally
            log::error!("Database error: {:?}", err);
            
            // Return a generic error to the user
            HttpResponse::InternalServerError()
                .json(json!({"error": "Failed to create user"}))
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize secure logger
    env_logger::init();
    
    // Connect to database securely
    let db_pool = create_db_pool().await.expect("Failed to create database pool");
    
    HttpServer::new(move || {
        App::new()
            // Provide database connection pool to handlers
            .app_data(web::Data::new(db_pool.clone()))
            // Add security headers
            .wrap(
                DefaultHeaders::new()
                    .add(("X-Content-Type-Options", "nosniff"))
                    .add(("X-Frame-Options", "DENY"))
                    .add(("Content-Security-Policy", "default-src 'self'"))
            )
            // Enable logging
            .wrap(Logger::default())
            // Rate limiting middleware
            .wrap(RateLimiter::new(
                SimpleRateLimiterStore::new(),
                SimpleRateLimiterConfig {
                    max_requests: 100,
                    interval: std::time::Duration::from_secs(60),
                }
            ))
            // Secure routes with proper HTTP methods
            .service(
                web::resource("/api/users")
                    .route(web::post().to(create_user))
            )
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
```

### Secure Cryptography

```rust
use ring::{rand, signature};
use data_encoding::HEXLOWER;

fn secure_cryptography_example() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a secure random key pair
    let rng = rand::SystemRandom::new();
    let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng)?;
    let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())?;
    
    // Sign a message
    let msg = b"Important message that needs authentication";
    let sig = key_pair.sign(msg);
    
    // Get the public key for verification
    let public_key = key_pair.public_key();
    
    // Verify the signature
    let public_key_bytes = public_key.as_ref();
    let peer_public_key = signature::UnparsedPublicKey::new(
        &signature::ED25519,
        public_key_bytes,
    );
    
    // Verify will return an error if the signature is invalid
    peer_public_key.verify(msg, sig.as_ref())?;
    
    println!("Signature verified successfully!");
    
    Ok(())
}
```

### Error Handling Best Practices

```rust
use thiserror::Error;

// Custom error type
#[derive(Error, Debug)]
enum AppError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    
    #[error("Validation error: {0}")]
    ValidationError(String),
    
    #[error("Authentication error")]
    AuthError,
    
    #[error("Internal server error")]
    InternalError,
}

// Public-facing error that doesn't leak implementation details
#[derive(Serialize)]
struct ApiError {
    code: String,
    message: String,
}

impl From<AppError> for ApiError {
    fn from(error: AppError) -> Self {
        match error {
            AppError::ValidationError(details) => ApiError {
                code: "VALIDATION_ERROR".into(),
                message: format!("Input validation failed: {}", details),
            },
            AppError::AuthError => ApiError {
                code: "UNAUTHORIZED".into(),
                message: "Authentication required".into(),
            },
            // Hide implementation details for other errors
            _ => ApiError {
                code: "INTERNAL_ERROR".into(),
                message: "An internal error occurred".into(),
            },
        }
    }
}

fn process_user_input(input: &str) -> Result<(), AppError> {
    if input.is_empty() {
        return Err(AppError::ValidationError("Input cannot be empty".into()));
    }
    
    // Use the ? operator for clean error propagation
    let user = db_get_user(input)?;
    
    if !is_authorized(&user) {
        return Err(AppError::AuthError);
    }
    
    // Process the authenticated and validated input
    Ok(())
}

// Handler function that converts internal errors to API errors
async fn api_handler(req: Request) -> Response {
    match process_request(req).await {
        Ok(data) => Response::ok().json(data),
        Err(err) => {
            // Log the detailed error internally
            log::error!("Request failed: {:?}", err);
            
            // Return a sanitized error to the client
            let api_error: ApiError = err.into();
            Response::error().json(api_error)
        }
    }
}
```

## Security Testing in Rust

1. **Static Analysis**
   - Use `cargo clippy` for linting and catching common mistakes
   - Implement `#[deny(unsafe_code)]` in critical modules
   - Use `cargo audit` to check for vulnerable dependencies

2. **Fuzzing**
   - Use `cargo-fuzz` or `afl.rs` for fuzzing your code
   - Target input parsing and serialization/deserialization code
   - Create specific fuzz targets for complex algorithms

3. **Property-Based Testing**
   - Use `proptest` or `quickcheck` for property-based tests
   - Test invariants that should always hold true
   - Test edge cases automatically

4. **Memory Safety Testing**
   - Run tests with Address Sanitizer (ASAN) enabled
   - Use Miri to detect undefined behavior
   - Test with different optimization levels

## Common Rust Security Pitfalls

1. **Unsafe Code**
   - Using `unsafe` blocks without thorough review
   - Not maintaining safety invariants around unsafe code
   - Insufficient documentation of safety requirements

2. **Serialization/Deserialization**
   - Deserializing untrusted input without validation
   - Type confusion in generic deserialization
   - Not handling malformed inputs gracefully

3. **Concurrency Issues**
   - Incorrect use of `Send` and `Sync` traits
   - Deadlocks from improper lock ordering
   - Race conditions in complex concurrent code

4. **Error Handling**
   - Using `unwrap()` or `expect()` in production code
   - Leaking sensitive information in error messages
   - Not handling all error cases properly

5. **Dependency Management**
   - Not auditing dependencies for security issues
   - Using outdated dependencies with known vulnerabilities
   - Too many dependencies increasing attack surface

6. **Resource Management**
   - Not implementing proper timeouts for operations
   - Resource exhaustion from unbounded collections
   - Not limiting memory usage appropriately
