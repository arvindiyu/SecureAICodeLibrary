# Android Security Prompts

This directory contains security prompts specific to Android application development. These prompts focus on Android-specific security concerns, best practices, and implementation examples using Java and Kotlin.

## Available Prompts

1. [Android Security Best Practices](./android-security.md) - Comprehensive Android security guidelines and code examples

## Key Android Security Areas

The Android security prompts cover these key areas:

1. **Secure Data Storage**
   - EncryptedSharedPreferences implementation
   - Room database with SQLCipher encryption
   - Android Keystore System for cryptographic key management
   - Secure file storage with proper permissions
   - Secure backup strategies

2. **Network Security**
   - Network Security Config implementation
   - Certificate pinning with OkHttp and standard APIs
   - TLS configuration best practices
   - Secure HTTP clients with proper error handling
   - Protection against common network vulnerabilities

3. **Authentication & Authorization**
   - BiometricPrompt API for secure biometric authentication
   - Secure token storage and management
   - Runtime permission handling and best practices
   - Authentication flows with proper security controls
   - Multi-factor authentication implementation

4. **Secure IPC Mechanisms**
   - Intent security and filtering
   - ContentProvider security with proper permissions
   - BroadcastReceiver protections
   - Service security considerations
   - Deep link security

5. **Platform Security**
   - SafetyNet Attestation API implementation
   - Root detection techniques
   - App signing verification
   - StrictMode policy configuration
   - Security provider updates

6. **Code Protection**
   - ProGuard and R8 configuration for obfuscation
   - Anti-debugging techniques
   - Anti-tampering implementations
   - Secure coding patterns for Android
   - Protection against injection attacks

7. **Security Testing**
   - Android-specific security testing approaches
   - Dynamic analysis with Android tools
   - Static analysis configuration
   - Security scanning integration
   - Automated security testing in CI/CD

## Usage Instructions

### For Developers

1. **Review Platform-Agnostic Principles First**
   - Start by reviewing the [common mobile security principles](../common/mobile-security-common.md)
   - Understand the fundamental security concerns for mobile applications

2. **Apply Android-Specific Implementations**
   - Use the [Android Security Best Practices](./android-security.md) guide for implementation details
   - Adapt the code examples to your application architecture
   - Follow the Android-specific security recommendations

3. **Integration with Development Process**
   - Incorporate security checks into your development workflow
   - Use the provided code examples as templates for your implementation
   - Apply the security testing guidelines during development and testing

### For Security Reviewers

1. **Security Assessment**
   - Use the security guidelines as a checklist for security reviews
   - Verify that Android-specific security controls are properly implemented
   - Check for proper usage of Android security APIs and frameworks

2. **Threat Modeling**
   - Consider Android-specific attack vectors during threat modeling
   - Use the security areas as categories for threat identification
   - Map identified threats to recommended security controls

## Related Resources

1. [Android Platform Security Guide](https://source.android.com/security)
2. [OWASP Mobile Security Testing Guide - Android](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05a-Platform-Overview.md)
3. [Android Security Bulletins](https://source.android.com/security/bulletin)
4. [CWE for Mobile](https://cwe.mitre.org/data/definitions/1028.html)
