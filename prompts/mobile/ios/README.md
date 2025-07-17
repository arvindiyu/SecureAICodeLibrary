# iOS Security Prompts

This directory contains security prompts specific to iOS application development. These prompts focus on iOS-specific security concerns, best practices, and implementation examples using Swift, SwiftUI, and Objective-C.

## Available Prompts

1. [iOS Security Best Practices](./ios-security.md) - Comprehensive iOS security guidelines and code examples

## Key iOS Security Areas

The iOS security prompts cover these key areas:

1. **Secure Data Storage**
   - Keychain Services API implementation
   - Data Protection API usage and protection classes
   - Secure CoreData configuration
   - Encrypted SQLite databases
   - Secure file handling with proper attributes
   - NSSecureCoding for object serialization

2. **Network Security**
   - App Transport Security (ATS) configuration
   - Certificate pinning with URLSession
   - URLSession security best practices
   - Secure API client implementation
   - Preventing common network vulnerabilities
   - Network extension security

3. **Authentication & Authorization**
   - LocalAuthentication framework implementation
   - Face ID and Touch ID integration
   - Secure token management
   - Secure authentication flows
   - Multi-factor authentication
   - Secure app groups access control

4. **App Security**
   - Code signing and validation
   - Provisioning profile security
   - Jailbreak detection techniques
   - App Attest API implementation
   - DeviceCheck API usage
   - Anti-debugging measures
   - Runtime integrity checks

5. **Privacy & Permissions**
   - Permission request best practices
   - Privacy preserving API usage
   - App privacy report preparation
   - Privacy manifests implementation
   - Secure inter-app communication
   - App extensions security

6. **iOS Specific Protections**
   - Secure Swift/SwiftUI coding patterns
   - Pointer authentication (PAC)
   - Secure enclave usage
   - App sandbox security
   - Memory protection mechanisms
   - Swift type safety leveraging

7. **Security Testing**
   - iOS-specific security testing approaches
   - Static analysis tools configuration
   - Dynamic testing techniques
   - Security verification procedures
   - Continuous security testing in CI/CD

## Usage Instructions

### For Developers

1. **Review Platform-Agnostic Principles First**
   - Start by reviewing the [common mobile security principles](../common/mobile-security-common.md)
   - Understand the fundamental security concerns for mobile applications

2. **Apply iOS-Specific Implementations**
   - Use the [iOS Security Best Practices](./ios-security.md) guide for implementation details
   - Adapt the code examples to your application architecture
   - Follow the iOS-specific security recommendations
   - Leverage iOS platform security features

3. **Integration with Development Process**
   - Incorporate security checks into your development workflow
   - Use the provided code examples as templates for your implementation
   - Apply the security testing guidelines during development and testing
   - Use Swift's type safety features to prevent common vulnerabilities

### For Security Reviewers

1. **Security Assessment**
   - Use the security guidelines as a checklist for security reviews
   - Verify that iOS-specific security controls are properly implemented
   - Check for proper usage of iOS security APIs and frameworks
   - Validate secure coding patterns specific to Swift/Objective-C

2. **Threat Modeling**
   - Consider iOS-specific attack vectors during threat modeling
   - Use the security areas as categories for threat identification
   - Map identified threats to recommended security controls
   - Account for iOS platform security guarantees and limitations

## Related Resources

1. [Apple Platform Security Guide](https://support.apple.com/guide/security/welcome/web)
2. [OWASP Mobile Security Testing Guide - iOS](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x06a-Platform-Overview.md)
3. [iOS App Security Guidelines](https://developer.apple.com/documentation/security)
4. [Swift Security Best Practices](https://developer.apple.com/swift/)
