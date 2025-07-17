# Mobile Security Copilot Instructions

This directory contains GitHub Copilot custom instructions for secure mobile development. These instructions are organized to help Copilot provide security-focused suggestions for mobile application development across different platforms and frameworks.

## Directory Structure

The mobile security Copilot instructions follow a clear organization that separates platform-agnostic guidance from platform-specific implementation details:

- **[common/](./common/)** - Platform-agnostic mobile security instructions applicable to all mobile platforms
- **[android/](./android/)** - Android-specific security instructions for Java and Kotlin development
- **[ios/](./ios/)** - iOS-specific security instructions for Swift, SwiftUI, and Objective-C development

## Using the Mobile Security Instructions

These instructions are designed to guide GitHub Copilot in providing security-focused code suggestions. To use them effectively:

### Standard Operating Procedure for Copilot Custom Instructions

1. **Start with common instructions** - Add the common mobile security instructions as a base
   - Copy the contents of [mobile-security-common.md](./common/mobile-security-common.md) to your Copilot custom instructions
   - These provide fundamental mobile security guidance regardless of platform

2. **Add platform-specific instructions** - Include platform-specific instructions based on your project
   - For Android projects: Add [android-security.md](./android/android-security.md) instructions
   - For iOS projects: Add [ios-security.md](./ios/ios-security.md) instructions
   - For multi-platform projects: Include instructions for all relevant platforms

3. **Customize for your project context** - Tailor the instructions for your specific needs
   - Add project-specific security requirements or compliance standards
   - Specify which security controls are most important for your application
   - Include any organization-specific security policies or guidelines

4. **Use in combination with prompts** - For best results when working with Copilot:
   - Reference specific security requirements in your prompts
   - Ask Copilot to follow the security instructions when generating code
   - Request security reviews of generated code

## Key Security Focus Areas

These instructions guide Copilot to focus on these key security areas:

1. **Secure Data Storage**
   - Platform-appropriate encryption mechanisms
   - Secure storage locations (Keychain, EncryptedSharedPreferences)
   - Proper key management practices
   - Data minimization principles

2. **Network Security**
   - Certificate pinning implementation
   - TLS configuration best practices
   - Secure API client patterns
   - Request/response security

3. **Authentication & Authorization**
   - Biometric authentication implementation
   - Secure token storage and handling
   - Multi-factor authentication patterns
   - OAuth 2.0 and OpenID Connect implementations

4. **Input Validation & Output Encoding**
   - Input validation patterns
   - Output encoding for various contexts
   - Protection against injection attacks
   - Request parameter validation

5. **Platform Security**
   - Platform-specific security features
   - Security configuration best practices
   - Permission handling
   - OS security integration

6. **Code Protection**
   - Obfuscation techniques
   - Anti-debugging measures
   - Root/jailbreak detection
   - Application integrity checks

7. **Privacy Controls**
   - Permission request patterns
   - Privacy-preserving code examples
   - Data minimization techniques
   - Compliance with privacy regulations

## Benefits of Using These Instructions

1. **Security by Default** - Copilot will prioritize secure implementation patterns
2. **Consistency** - Ensures consistent security approaches across your codebase
3. **Best Practices** - Incorporates industry standards and platform vendor recommendations
4. **Learning** - Helps developers learn secure coding techniques as they work with Copilot
