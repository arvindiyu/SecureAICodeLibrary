# Mobile Security Prompts

This directory contains prompts for implementing secure mobile applications. These prompts are organized to help developers implement secure mobile applications across different platforms and technologies.

## Directory Structure

The mobile security content is organized to separate platform-agnostic principles from platform-specific implementation details:

- **[common/](./common/)** - Platform-agnostic mobile security principles that apply to all mobile platforms
- **[android/](./android/)** - Android-specific security prompts and examples (Java/Kotlin)
- **[ios/](./ios/)** - iOS-specific security prompts and examples (Swift/SwiftUI/Objective-C)

## Organization Philosophy

The content is organized following these principles:

1. **Separation of Concerns** - Common security principles are separated from platform-specific implementations
2. **Implementation Focus** - Platform-specific content focuses on practical implementation details
3. **Consistency** - Similar security controls are addressed across all platforms
4. **Completeness** - Each section aims to cover all major security aspects for the platform

## Using the Mobile Security Prompts

Each section contains:

1. **Security Best Practices** - Platform-specific and general mobile security guidance
2. **Code Examples** - Practical implementations of security controls
3. **Testing Guidelines** - How to verify security implementations
4. **OWASP Mobile References** - Mapping to OWASP Mobile Top 10 risks and MASVS requirements

### Standard Operating Procedure (SOP)

For the most effective use of these prompts, follow this procedure:

1. **Start with common guidance** - Review the mobile security common principles first
   - Understand the fundamental security concerns for mobile applications
   - Identify which security controls are relevant to your application

2. **Apply platform-specific controls** - Use the Android or iOS specific guidance based on your platform
   - Follow the implementation examples for your specific platform
   - Adapt the examples to your application's architecture

3. **Implement comprehensive security** - Address all relevant security aspects:
   - Secure data storage and protection at rest
   - Secure network communication
   - Authentication and authorization
   - Code protection and anti-tampering
   - Input validation and output encoding
   - Privacy controls and permission handling

4. **Verify implementation** - Use the testing guidelines to validate your implementation
   - Apply both static and dynamic security testing
   - Verify against the OWASP Mobile Application Security Verification Standard (MASVS)

## Mobile Security Principles

These prompts focus on the following key security principles:

1. **Secure Data Storage** - Protecting sensitive data at rest
   - Keychain Services (iOS) / EncryptedSharedPreferences (Android)
   - Data Protection API (iOS) / Android Keystore System
   - Database encryption and secure configuration
   - Secure file storage with proper permissions

2. **Secure Communication** - Ensuring data in transit is protected
   - Certificate pinning implementation
   - Proper TLS configuration and validation
   - Network Security Config (Android)
   - App Transport Security (iOS)
   - API request/response security

3. **Authentication & Authorization** - Implementing secure user authentication
   - Biometric authentication
   - OAuth 2.0 / OpenID Connect implementation
   - Multi-factor authentication
   - Secure token handling
   - Session management

4. **Code Protection** - Preventing reverse engineering and tampering
   - Obfuscation techniques
   - Root/jailbreak detection
   - Anti-debugging measures
   - Integrity checks
   - Tampering detection

5. **Privacy & Permissions** - Implementing proper privacy controls
   - Runtime permission handling
   - Data minimization practices
   - Secure data sharing mechanisms
   - GDPR/CCPA compliance guidelines
   - Privacy-by-design implementation

6. **Security Testing** - Validating security implementations
   - OWASP Mobile Security Testing Guide (MSTG) practices
   - Static analysis tools and configurations
   - Dynamic analysis and penetration testing
   - Security verification processes
   - Continuous security testing in CI/CD
