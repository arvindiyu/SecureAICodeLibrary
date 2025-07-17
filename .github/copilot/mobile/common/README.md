# Common Mobile Security Instructions for GitHub Copilot

This directory contains platform-agnostic GitHub Copilot custom instructions for secure mobile development. These instructions guide Copilot to provide security-focused code suggestions that apply across all mobile platforms, regardless of the specific technology stack.

## Available Instructions

1. [Mobile Security Common Instructions](./mobile-security-common.md) - Core mobile security instructions applicable across all platforms

## Purpose and Philosophy

The common mobile security instructions serve as:

1. **Foundation Layer** - Providing fundamental mobile security principles that apply universally
2. **Common Patterns** - Establishing consistent security approaches across different platforms
3. **Baseline Security** - Setting a minimum security standard for all mobile development
4. **Platform-Independent Guidance** - Focusing on concepts rather than specific implementations

## Key Security Areas

The common mobile security instructions cover these key areas:

1. **Data Storage Security**
   - Secure storage principles and considerations
   - Encryption fundamentals for data at rest
   - Secure key management principles
   - Data minimization strategies
   - Secure deletion and memory management

2. **Network Communication Security**
   - TLS configuration best practices
   - Certificate validation principles
   - API security fundamentals
   - Secure data transmission patterns
   - Defense against common network attacks

3. **Authentication & Authorization**
   - Secure authentication design patterns
   - Token-based authentication principles
   - Multi-factor authentication concepts
   - Authorization models and patterns
   - Session management security

4. **Input Validation & Output Encoding**
   - Input validation principles
   - Output encoding for security
   - Defense against injection attacks
   - Parameter validation approaches
   - Content security strategies

5. **Application Security Architecture**
   - Security by design principles
   - Threat modeling approaches
   - Layered security implementation
   - Security controls selection
   - Defense-in-depth strategies

6. **Security Testing & Verification**
   - Mobile security testing principles
   - OWASP Mobile testing approaches
   - Common mobile vulnerability categories
   - Security verification methodology
   - Continuous security validation

## Usage Instructions

### How to Use These Instructions

1. **Standalone Basic Security**:
   - For projects where platform-specific guidance is less important
   - Add the entire contents of [mobile-security-common.md](./mobile-security-common.md) to Copilot instructions

2. **Foundation for Platform-Specific Instructions**:
   - Start with these common instructions as a foundation
   - Add platform-specific instructions from [Android](../android/android-security.md) or [iOS](../ios/ios-security.md) directories
   - This layered approach provides comprehensive security guidance

3. **Custom Combinations**:
   - Select relevant sections based on your project's security requirements
   - Combine with other security instructions as needed
   - Add your organization's specific security policies or compliance requirements

### Example Integration Pattern

For a complete mobile security instruction set:

1. Start with common mobile security instructions
2. Add platform-specific instructions (Android or iOS)
3. Add any application-specific security requirements
4. Add compliance-specific requirements if applicable

This layered approach ensures comprehensive security guidance while maintaining clarity and focus.

These instructions provide a foundation for secure mobile development regardless of platform. Use these instructions as a starting point, then add platform-specific instructions based on your target platform.
